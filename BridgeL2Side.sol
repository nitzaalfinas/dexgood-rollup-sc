// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ERC20MintBurnFreeze {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;
    address public admin;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => bool) public frozen;

    // --- Permit (EIP-2612) ---
    mapping(address => uint256) public nonces;
    bytes32 public immutable DOMAIN_SEPARATOR;
    // keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)")
    bytes32 public constant PERMIT_TYPEHASH = 0xd505accf6fb6f7c9c1b6c3e0b979bfa6a6c7e2e7e1e7e736d9193c2ac8b10b5d;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Mint(address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);
    event Freeze(address indexed addr);
    event Unfreeze(address indexed addr);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier notFrozen(address addr) {
        require(!frozen[addr], "Address frozen");
        _;
    }

    constructor(string memory _name, string memory _symbol, address _admin) {
        name = _name;
        symbol = _symbol;
        admin = _admin;

        uint256 chainId;
        assembly {
            chainId := chainid()
        }
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(_name)),
                keccak256(bytes("1")),
                chainId,
                address(this)
            )
        );
    }

    function transfer(address to, uint256 value) external notFrozen(msg.sender) notFrozen(to) returns (bool) {
        require(balanceOf[msg.sender] >= value, "Insufficient balance");
        require(!frozen[msg.sender], "Address frozen");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external notFrozen(msg.sender) notFrozen(spender) returns (bool) {
        require(!frozen[msg.sender] && !frozen[spender], "Address frozen");
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external notFrozen(msg.sender) notFrozen(from) notFrozen(to) returns (bool) {
        require(balanceOf[from] >= value, "Insufficient balance");
        require(allowance[from][msg.sender] >= value, "Allowance exceeded");
        require(!frozen[from] && !frozen[to], "Address frozen");
        balanceOf[from] -= value;
        balanceOf[to] += value;
        allowance[from][msg.sender] -= value;
        emit Transfer(from, to, value);
        return true;
    }

    function mint(address to, uint256 value) external onlyAdmin {
        balanceOf[to] += value;
        totalSupply += value;
        emit Mint(to, value);
        emit Transfer(address(0), to, value);
    }

    function burnFrom(address from, uint256 value) external onlyAdmin {
        require(balanceOf[from] >= value, "Insufficient balance");
        balanceOf[from] -= value;
        totalSupply -= value;
        emit Burn(from, value);
        emit Transfer(from, address(0), value);
    }

    function freeze(address addr) external onlyAdmin {
        frozen[addr] = true;
        emit Freeze(addr);
    }

    function unfreeze(address addr) external onlyAdmin {
        frozen[addr] = false;
        emit Unfreeze(addr);
    }

    // --- Permit (EIP-2612) ---
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(deadline == 0 || block.timestamp <= deadline, "Permit: expired deadline");
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        PERMIT_TYPEHASH,
                        owner,
                        spender,
                        value,
                        nonces[owner]++,
                        deadline
                    )
                )
            )
        );
        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0) && recovered == owner, "Permit: invalid signature");
        allowance[owner][spender] = value;
        emit Approval(owner, spender, value);
    }

    // Optional: for wallet compatibility
    function version() external pure returns (string memory) {
        return "1";
    }
}

contract BridgeL2Side {
    address public admin;

    mapping(address => address) public tokens;
    mapping(uint256 => bool) public done;

    event DepositERC20(address indexed user, address indexed token, uint256 amount, uint256 timestamp);
    event DepositETH(address indexed user, uint256 amount, uint256 timestamp);
    event ReleaseERC20(uint256 indexed layerOneId, address to, address token, uint256 amount, uint256 timestamp);
    event ReleaseETH(address indexed to, uint256 amount, uint256 timestamp);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    // Deposit ERC20 token (burn on L2)
    function depositERC20(address token, uint256 amount) external {
        ERC20MintBurnFreeze(token).burnFrom(msg.sender, amount);
        emit DepositERC20(msg.sender, token, amount, block.timestamp);
    }

    // Deposit native ETH (burn pattern: send to address(0))
    function depositETH() external payable {
        require(msg.value > 0, "No ETH sent");
        // ETH "burn" di L2 biasanya dengan lock di contract, atau bisa juga dihapus dari supply L2
        emit DepositETH(msg.sender, msg.value, block.timestamp);
    }

    // Release ERC20 token (mint on L2, admin only)
    function releaseERC20(uint256 layerOneId, address layerOneToken, address to, uint256 amount, string memory name, string memory symbol) external onlyAdmin {
        require(!done[layerOneId], "Already done");
        if(tokens[layerOneToken] != address(0)) {
            // minting mapped token
            // minting to tokens[layerOneToken]
            ERC20MintBurnFreeze(tokens[layerOneToken]).mint(to, amount);
        }
        else {
            // create a new token mapping if not exists
            tokens[layerOneToken] = address(new ERC20MintBurnFreeze(name, symbol, msg.sender));

            // minting to the new token
            ERC20MintBurnFreeze(tokens[layerOneToken]).mint(to, amount);
        }
        done[layerOneId] = true;
        emit ReleaseERC20(layerOneId, to, tokens[layerOneToken], amount, block.timestamp);
    }

    // Release native ETH (admin only)
    function releaseETH(address to, uint256 amount) external onlyAdmin {
        require(address(this).balance >= amount, "Insufficient ETH");
        (bool sent, ) = to.call{value: amount}("");
        require(sent, "ETH transfer failed");
        emit ReleaseETH(to, amount, block.timestamp);
    }

    // Fungsi receive agar kontrak bisa menerima ETH
    receive() external payable {}
}