// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/Address.sol";

contract ERC20MintBurnFreeze is ReentrancyGuard, Pausable {
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
    bytes32 public constant PERMIT_TYPEHASH = 0xd505accf6fb6f7c9c1b6c3e0b979bfa6a6c7e2e7e1e7e736d9193c2ac8b10b5d;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Mint(address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);
    event Freeze(address indexed addr);
    event Unfreeze(address indexed addr);
    event OwnershipTransferred(address indexed previousAdmin, address indexed newAdmin);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier notFrozen(address addr) {
        require(!frozen[addr], "Address frozen");
        _;
    }

    constructor(string memory _name, string memory _symbol, address _admin) {
        require(_admin != address(0), "Invalid admin");
        name = _name;
        symbol = _symbol;
        admin = _admin;

        uint256 chainId = block.chainid;
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

    function transfer(address to, uint256 value) external nonReentrant whenNotPaused notFrozen(msg.sender) notFrozen(to) returns (bool) {
        require(balanceOf[msg.sender] >= value, "Insufficient balance");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external nonReentrant whenNotPaused notFrozen(msg.sender) notFrozen(spender) returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external nonReentrant whenNotPaused notFrozen(msg.sender) notFrozen(from) notFrozen(to) returns (bool) {
        require(balanceOf[from] >= value, "Insufficient balance");
        require(allowance[from][msg.sender] >= value, "Allowance exceeded");
        balanceOf[from] -= value;
        balanceOf[to] += value;
        allowance[from][msg.sender] -= value;
        emit Transfer(from, to, value);
        return true;
    }

    function mint(address to, uint256 value) external onlyAdmin whenNotPaused {
        balanceOf[to] += value;
        totalSupply += value;
        emit Mint(to, value);
        emit Transfer(address(0), to, value);
    }

    function burnFrom(address from, uint256 value) external onlyAdmin whenNotPaused {
        require(balanceOf[from] >= value, "Insufficient balance");
        balanceOf[from] -= value;
        totalSupply -= value;
        emit Burn(from, value);
        emit Transfer(from, address(0), value);
    }

    function freeze(address addr) external onlyAdmin {
        require(addr != address(0), "Invalid address");
        frozen[addr] = true;
        emit Freeze(addr);
    }

    function unfreeze(address addr) external onlyAdmin {
        require(addr != address(0), "Invalid address");
        frozen[addr] = false;
        emit Unfreeze(addr);
    }

    function transferOwnership(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "New admin cannot be zero address");
        require(newAdmin != admin, "New admin cannot be current admin");
        address previousAdmin = admin;
        admin = newAdmin;
        emit OwnershipTransferred(previousAdmin, newAdmin);
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

    function version() external pure returns (string memory) {
        return "1";
    }

    function pauseToken() external onlyAdmin {
        _pause();
    }

    function unpauseToken() external onlyAdmin {
        _unpause();
    }
}

/**
 * @title BridgeL2Side - Cross-Chain Bridge L2 Contract  
 * @notice Secure bridge contract for L2 side operations: minting/burning wrapped tokens
 * @dev Uses OpenZeppelin security patterns: ReentrancyGuard, Ownable2Step, Pausable
 * @dev Manages wrapped tokens creation and L1↔L2 token mapping
 */
contract BridgeL2Side is ReentrancyGuard, Ownable2Step, Pausable {
    using Address for address payable;

    // ========== COUNTERS ==========
    uint256 public withdrawCounter;
    uint256 public depositCounter;
    uint256 public batchCounter;
    
    // ========== TOKEN MAPPINGS ==========
    mapping(address => address) public tokens;         // L1 token => L2 wrapped token
    mapping(address => address) public tokensReverse;  // L2 wrapped token => L1 token
    address[] public createdTokens;                    // Array of all created L2 tokens
    
    // ========== SECURITY TRACKING ==========
    mapping(uint256 => bool) public done;             // Track processed L1 deposits
    mapping(address => uint256) public userNonce;     // Prevent front-running attacks
    mapping(address => uint256) public lastWithdrawTime;   // Rate limiting per user for withdraws
    mapping(address => uint256) public dailyWithdrawAmount; // Daily withdraw tracking
    mapping(address => uint256) public dailyWithdrawReset;  // Daily reset timestamp
    mapping(address => uint256) public lastDepositTime;    // Rate limiting for deposits (admin)
    mapping(address => uint256) public withdrawMinimums; // Track which tokens have minimum withdraw enforced
    
    // ========== TIME TRACKING ==========
    uint256 public lastBatchTime;
    uint256 public lastEmergencyTime;
    uint256 public dailyDepositVolume;     // Track daily deposit volume
    uint256 public lastDepositVolumeReset; // Daily volume reset timestamp
    uint256 public dailyWithdrawVolume;    // Track daily withdraw volume
    uint256 public lastWithdrawVolumeReset; // Daily withdraw volume reset timestamp

    bool public sampaiA;
    bool public sampaiB;
    bool public sampaiC;
    bool public sampaiD;
    bool public sampaiE;
    bool public sampaiF;
    bool public sampaiG;
    bool public sampaiH;
    bool public sampaiI;
    bool public sampaiJ;
    bool public sampaiK;
    bool public sampaiL;
    bool public sampaiM;
    bool public sampaiZ;

    // ========== LIMITS & DELAYS ==========
    uint256 public constant MAX_BATCH_SIZE = 25;
    uint256 public constant MIN_BATCH_DELAY = 1 hours;
    uint256 public constant EMERGENCY_DELAY = 24 hours;
    uint256 public constant WITHDRAW_COOLDOWN = 30 seconds;     // Anti-spam for withdraws
    uint256 public constant DEPOSIT_COOLDOWN = 10 seconds;      // Anti-spam for deposits (admin)
    uint256 public constant MIN_WITHDRAW_AMOUNT = 0.001 ether;  // Minimum withdraw
    uint256 public constant MAX_WITHDRAW_AMOUNT = 10000 ether;  // Maximum withdraw
    uint256 public constant DAILY_WITHDRAW_LIMIT = 50000 ether; // Per user daily limit
    uint256 public constant EMERGENCY_TIMELOCK = 48 hours;     // Emergency timelock
    uint256 public emergencyUnlockTime;                        // Emergency unlock timestamp
    uint256 public constant MAX_DAILY_DEPOSIT_VOLUME = 1000000 ether; // Max daily deposit volume
    uint256 public constant MAX_SINGLE_DEPOSIT = 100000 ether; // Max single deposit amount
    uint256 public constant MAX_DAILY_WITHDRAW_VOLUME = 2000000 ether; // Max daily withdraw volume
    uint256 public constant MAX_SINGLE_WITHDRAW = 50000 ether; // Max single withdraw amount
    
    // ========== FEE SYSTEM REMOVED ==========
    // Following industry standard: Major bridges (Arbitrum, Optimism, zkSync) don't charge fees
    // Revenue model: Gas fees and rollup economics

    // ========== EVENTS ==========
    event WithdrawERC20(uint256 indexed withdrawId, address indexed user, address indexed l2Token, address l1Token, uint256 amount, uint256 nonce, uint256 timestamp);
    event WithdrawETH(uint256 indexed withdrawId, address indexed user, uint256 amount, uint256 nonce, uint256 timestamp);
    event DepositERC20(uint256 indexed depositId, uint256 indexed l1DepositId, address indexed to, address l1Token, address l2Token, uint256 amount, uint256 timestamp);
    event DepositETH(uint256 indexed depositId, address indexed to, uint256 amount, uint256 timestamp);
    event TokenCreated(address indexed l1Token, address indexed l2Token, string name, string symbol);
    event BatchComplete(uint256 indexed batchId, uint256 itemCount, uint256 totalAmount);
    event EmergencyWithdrawal(address indexed token, address indexed to, uint256 amount);
    event TokenOwnershipUpdateFailed(address indexed token, string reason);
    event EmergencyUnlockRequested(uint256 unlockTime);
    event EmergencyUnlockCancelled();
    event MinimumWithdrawUpdated(address indexed token, uint256 oldMinimum, uint256 newMinimum);

    // ========== MODIFIERS ==========
    
    modifier validWithdrawAmount(uint256 amount) {
        require(amount >= MIN_WITHDRAW_AMOUNT, "Amount too small");
        require(amount <= MAX_WITHDRAW_AMOUNT, "Amount too large");
        _;
    }

    modifier validWithdrawAmountErc20(uint256 amount, address l2Token) {
        require(amount >= withdrawMinimums[l2Token], "Amount too small");
        _;
    }
    
    modifier withdrawRateLimited() {
        require(
            block.timestamp >= lastWithdrawTime[msg.sender] + WITHDRAW_COOLDOWN,
            "Withdraw too frequent"
        );
        _checkDailyWithdrawLimit();
        lastWithdrawTime[msg.sender] = block.timestamp;
        _;
    }
    
    modifier depositRateLimited() {
        require(
            block.timestamp >= lastDepositTime[msg.sender] + DEPOSIT_COOLDOWN,
            "Deposit too frequent"
        );
        lastDepositTime[msg.sender] = block.timestamp;
        _;
    }
    
    modifier batchCooldown() {
        require(block.timestamp >= lastBatchTime + MIN_BATCH_DELAY, "Batch cooldown active");
        _;
    }

    modifier emergencyCooldown() {
        require(block.timestamp >= lastEmergencyTime + EMERGENCY_DELAY, "Emergency cooldown active");
        _;
    }
    
    modifier emergencyUnlocked() {
        require(emergencyUnlockTime > 0 && block.timestamp >= emergencyUnlockTime, "Emergency functions locked");
        _;
    }

    // ========== CONSTRUCTOR ==========
    constructor() Ownable(msg.sender) {
        lastBatchTime = block.timestamp;
        lastEmergencyTime = block.timestamp;
        emergencyUnlockTime = 0;
        lastDepositVolumeReset = block.timestamp;
        dailyDepositVolume = 0;
        lastWithdrawVolumeReset = block.timestamp;
        dailyWithdrawVolume = 0;
    }

    // ========== INTERNAL HELPER FUNCTIONS ==========
    
    /**
     * @notice Check and update daily withdraw limit
     */
    function _checkDailyWithdrawLimit() internal {
        if (block.timestamp >= dailyWithdrawReset[msg.sender] + 1 days) {
            dailyWithdrawAmount[msg.sender] = 0;
            dailyWithdrawReset[msg.sender] = block.timestamp;
        }
    }

    /**
     * @notice Set minimum withdraw amount for specific token
     * @param l2Token L2 token address
     * @param minimumAmount Minimum withdraw amount in token's native decimals
     */
    function setTokenMinimumWithdraw(address l2Token, uint256 minimumAmount) external onlyOwner {
        require(l2Token != address(0), "Invalid token address");
        require(tokensReverse[l2Token] != address(0), "Token not found");
        uint256 oldMinimum = withdrawMinimums[l2Token];
        withdrawMinimums[l2Token] = minimumAmount;
        emit MinimumWithdrawUpdated(l2Token, oldMinimum, minimumAmount);
    }
    

    
    /**
     * @notice Update daily withdraw tracking
     * @param amount Withdraw amount
     */
    function _updateDailyWithdraw(uint256 amount) internal {
        dailyWithdrawAmount[msg.sender] += amount;
        require(
            dailyWithdrawAmount[msg.sender] <= DAILY_WITHDRAW_LIMIT,
            "Daily withdraw limit exceeded"
        );
    }
    
    /**
     * @notice Check and update daily deposit volume limits
     * @param amount Deposit amount to add
     */
    function _checkDailyDepositVolume(uint256 amount) internal {
        // Reset daily volume if a day has passed
        if (block.timestamp >= lastDepositVolumeReset + 1 days) {
            dailyDepositVolume = 0;
            lastDepositVolumeReset = block.timestamp;
        }
        
        require(amount <= MAX_SINGLE_DEPOSIT, "Single deposit too large");
        dailyDepositVolume += amount;
        require(dailyDepositVolume <= MAX_DAILY_DEPOSIT_VOLUME, "Daily deposit volume exceeded");
    }
    
    /**
     * @notice Check and update daily withdraw volume limits
     * @param amount Withdraw amount to add
     */
    function _checkDailyWithdrawVolume(uint256 amount) internal {
        // Reset daily volume if a day has passed
        if (block.timestamp >= lastWithdrawVolumeReset + 1 days) {
            dailyWithdrawVolume = 0;
            lastWithdrawVolumeReset = block.timestamp;
        }
        
        require(amount <= MAX_SINGLE_WITHDRAW, "Single withdraw too large");
        dailyWithdrawVolume += amount;
        require(dailyWithdrawVolume <= MAX_DAILY_WITHDRAW_VOLUME, "Daily withdraw volume exceeded");
    }

    // ========== WITHDRAW FUNCTIONS (L2 → L1) ==========
    
    /**
     * @notice Withdraw ERC20 tokens from L2 to L1 (burn L2 wrapped tokens)
     * @param l2Token L2 wrapped token address to burn
     * @param amount Amount to withdraw
     * @dev This burns L2 wrapped tokens, relayer will unlock L1 tokens
     */
    function withdrawERC20(address l2Token, uint256 amount) 
        external 
        nonReentrant
        whenNotPaused
        validWithdrawAmountErc20(amount, l2Token)
        withdrawRateLimited
    {
        sampaiA = true;
        require(l2Token != address(0), "Invalid token address");
        sampaiB = true;
        require(tokensReverse[l2Token] != address(0), "Token not mapped to L1");
        sampaiC = true;
        
        // Security checks for token and user
        ERC20MintBurnFreeze token = ERC20MintBurnFreeze(l2Token);
        sampaiD = true;
        require(!token.frozen(msg.sender), "User is frozen");
        sampaiE = true;
        require(!token.frozen(l2Token), "Token is frozen");
        sampaiF = true;
        require(token.balanceOf(msg.sender) >= amount, "Insufficient balance");
        sampaiG = true;
        
        // Get L1 token address
        address l1Token = tokensReverse[l2Token];
        sampaiH = true;
        
        // Update tracking BEFORE burning (prevent reentrancy issues)
        uint256 nonce = ++userNonce[msg.sender];
        sampaiI = true;
        uint256 withdrawId = ++withdrawCounter;
        sampaiJ = true;
        _updateDailyWithdraw(amount);
        sampaiK = true;
        _checkDailyWithdrawVolume(amount);
        sampaiL = true;
        
        // Burn L2 wrapped tokens - this will revert if insufficient balance/allowance
        token.burnFrom(msg.sender, amount);
        sampaiM = true;
        
        // Emit event AFTER successful burn
        emit WithdrawERC20(withdrawId, msg.sender, l2Token, l1Token, amount, nonce, block.timestamp);
    }

    /**
     * @notice Withdraw ETH from L2 to L1 (burn/lock user's ETH)
     * @dev User sends ETH with transaction, ETH gets locked in bridge
     * @dev Relayer will unlock equivalent ETH on L1 side
     */
    function withdrawETH() 
        external 
        payable
        nonReentrant
        whenNotPaused
        validWithdrawAmount(msg.value)
        withdrawRateLimited
    {
        require(msg.value > 0, "Must send ETH to withdraw");
        
        // Update tracking AFTER receiving ETH
        uint256 nonce = ++userNonce[msg.sender];
        uint256 withdrawId = ++withdrawCounter;
        _updateDailyWithdraw(msg.value);
        _checkDailyWithdrawVolume(msg.value);
        
        // ETH is now locked in this contract
        // Relayer will process this event and unlock ETH on L1
        
        emit WithdrawETH(withdrawId, msg.sender, msg.value, nonce, block.timestamp);
    }

    // ========== DEPOSIT FUNCTIONS (L1 → L2) ==========

    /**
     * @notice Deposit ERC20 tokens from L1 to L2 (mint L2 wrapped tokens)
     * @param l1DepositId L1 deposit ID
     * @param l1Token L1 token address
     * @param to Recipient address
     * @param amount Amount to deposit
     * @param name Token name (for new tokens)
     * @param symbol Token symbol (for new tokens)
     * @dev Only admin can call this based on L1 deposit events
     */
    function depositERC20(
        uint256 l1DepositId, 
        address l1Token, 
        address to, 
        uint256 amount, 
        string memory name, 
        string memory symbol
    ) external onlyOwner nonReentrant depositRateLimited {
        require(!done[l1DepositId], "Already processed");
        require(l1Token != address(0), "Invalid L1 token");
        require(to != address(0), "Invalid recipient");
        require(amount > 0, "Invalid amount");
        require(amount <= MAX_WITHDRAW_AMOUNT, "Amount too large"); // Prevent massive minting
        require(bytes(name).length > 0 && bytes(name).length <= 50, "Invalid name");
        
        // Check daily deposit volume limits
        _checkDailyDepositVolume(amount);
        require(bytes(symbol).length > 0 && bytes(symbol).length <= 10, "Invalid symbol");
        
        address l2Token;
        uint256 depositId = ++depositCounter;
        
        // Check if L2 wrapped token exists
        if(tokens[l1Token] != address(0)) {
            l2Token = tokens[l1Token];
            // Verify token metadata consistency for existing tokens
            require(
                keccak256(bytes(ERC20MintBurnFreeze(l2Token).name())) == keccak256(bytes(name)) &&
                keccak256(bytes(ERC20MintBurnFreeze(l2Token).symbol())) == keccak256(bytes(symbol)),
                "Token metadata mismatch"
            );
            ERC20MintBurnFreeze(l2Token).mint(to, amount);
        } else {
            // Create new L2 wrapped token with security checks
            require(createdTokens.length < 10000, "Too many tokens created"); // Prevent DoS
            l2Token = address(new ERC20MintBurnFreeze(name, symbol, address(this)));
            tokens[l1Token] = l2Token;
            tokensReverse[l2Token] = l1Token;
            createdTokens.push(l2Token);

            // Set minimum withdraw amount for new tokens
            withdrawMinimums[l2Token] = 5 * (10 ** 18); // 5 tokens in wei

            ERC20MintBurnFreeze(l2Token).mint(to, amount);
            emit TokenCreated(l1Token, l2Token, name, symbol);
        }
        
        done[l1DepositId] = true;
        emit DepositERC20(depositId, l1DepositId, to, l1Token, l2Token, amount, block.timestamp);
    }

    /**
     * @notice Deposit ETH from L1 to L2 (release ETH on L2)
     * @param l1DepositId L1 deposit ID (must be unique)
     * @param to Recipient address
     * @param amount Amount to deposit
     * @dev Only admin can call this based on L1 deposit events
     * @dev CRITICAL: Admin must verify L1 event before calling this
     */
    function depositETH(uint256 l1DepositId, address to, uint256 amount) 
        external 
        onlyOwner 
        nonReentrant 
        depositRateLimited 
    {
        require(!done[l1DepositId], "Already processed");
        require(to != address(0), "Invalid recipient");
        require(amount > 0, "Invalid amount");
        require(address(this).balance >= amount, "Insufficient ETH");
        
        // Check daily deposit volume limits
        _checkDailyDepositVolume(amount);
        
        uint256 depositId = ++depositCounter;
        done[l1DepositId] = true;
        
        (bool success, ) = payable(to).call{value: amount}("");
        require(success, "ETH transfer failed");
        emit DepositETH(depositId, to, amount, block.timestamp);
    }

    // ========== BATCH OPERATIONS ==========
    
    /**
     * @notice Batch deposit ERC20 tokens (up to 25 at once)
     */
    function batchDepositERC20(
        uint256[] calldata l1DepositIds,
        address[] calldata l1Tokens,
        address[] calldata recipients,
        uint256[] calldata amounts,
        string[] calldata names,
        string[] calldata symbols
    ) external onlyOwner batchCooldown nonReentrant depositRateLimited {
        uint256 length = l1DepositIds.length;
        require(
            length == l1Tokens.length && 
            length == recipients.length && 
            length == amounts.length &&
            length == names.length &&
            length == symbols.length, 
            "Array length mismatch"
        );
        require(length > 0 && length <= MAX_BATCH_SIZE, "Invalid batch size");
        
        // Validate all deposits first (prevent front-running)
        _validateBatchDeposits(l1DepositIds);
        
        // Execute batch deposits
        uint256 totalAmount = _executeBatchDeposits(
            l1DepositIds,
            l1Tokens, 
            recipients,
            amounts,
            names,
            symbols
        );
        
        batchCounter++;
        lastBatchTime = block.timestamp;
        emit BatchComplete(batchCounter, length, totalAmount);
    }
    
    /**
     * @notice Internal function to validate batch deposits
     * @param l1DepositIds Array of L1 deposit IDs to validate
     */
    function _validateBatchDeposits(uint256[] calldata l1DepositIds) internal view {
        for (uint256 i = 0; i < l1DepositIds.length; i++) {
            require(!done[l1DepositIds[i]], "Already processed");
        }
    }
    
    /**
     * @notice Internal function to execute batch deposits
     * @param l1DepositIds Array of L1 deposit IDs
     * @param l1Tokens Array of L1 token addresses
     * @param recipients Array of recipient addresses
     * @param amounts Array of amounts
     * @param names Array of token names
     * @param symbols Array of token symbols
     * @return totalAmount Total amount processed
     */
    function _executeBatchDeposits(
        uint256[] calldata l1DepositIds,
        address[] calldata l1Tokens,
        address[] calldata recipients,
        uint256[] calldata amounts,
        string[] calldata names,
        string[] calldata symbols
    ) internal returns (uint256 totalAmount) {
        uint256 length = l1DepositIds.length;
        totalAmount = 0;
        
        for (uint256 i = 0; i < length; i++) {
            // Validate single deposit
            require(recipients[i] != address(0), "Invalid recipient");
            require(amounts[i] > 0, "Invalid amount");
            require(amounts[i] <= MAX_WITHDRAW_AMOUNT, "Amount too large");
            require(bytes(names[i]).length > 0 && bytes(names[i]).length <= 50, "Invalid name");
            require(bytes(symbols[i]).length > 0 && bytes(symbols[i]).length <= 10, "Invalid symbol");
            require(totalAmount <= type(uint256).max - amounts[i], "Overflow protection");
            
            totalAmount += amounts[i];
            require(totalAmount <= MAX_WITHDRAW_AMOUNT * MAX_BATCH_SIZE, "Total amount too large");
            
            // Process single deposit
            _processSingleBatchDeposit(
                l1DepositIds[i],
                l1Tokens[i],
                recipients[i],
                amounts[i],
                names[i],
                symbols[i]
            );
        }
    }
    
    /**
     * @notice Internal function to process single deposit in batch
     * @param l1DepositId L1 deposit ID
     * @param l1Token L1 token address
     * @param recipient Recipient address
     * @param amount Amount to deposit
     * @param name Token name
     * @param symbol Token symbol
     */
    function _processSingleBatchDeposit(
        uint256 l1DepositId,
        address l1Token,
        address recipient,
        uint256 amount,
        string calldata name,
        string calldata symbol
    ) internal {
        uint256 depositId = ++depositCounter;
        address l2Token;
        
        // Check if L2 wrapped token exists
        address cachedL2Token = tokens[l1Token];
        if (cachedL2Token != address(0)) {
            l2Token = cachedL2Token;
            // Verify token metadata consistency
            require(
                keccak256(bytes(ERC20MintBurnFreeze(l2Token).name())) == keccak256(bytes(name)) &&
                keccak256(bytes(ERC20MintBurnFreeze(l2Token).symbol())) == keccak256(bytes(symbol)),
                "Token metadata mismatch"
            );
            ERC20MintBurnFreeze(l2Token).mint(recipient, amount);
        } else {
            // Create new L2 wrapped token
            require(createdTokens.length < 10000, "Too many tokens created");
            l2Token = address(new ERC20MintBurnFreeze(name, symbol, address(this)));
            tokens[l1Token] = l2Token;
            tokensReverse[l2Token] = l1Token;
            createdTokens.push(l2Token);
            
            ERC20MintBurnFreeze(l2Token).mint(recipient, amount);
            emit TokenCreated(l1Token, l2Token, name, symbol);
        }
        
        done[l1DepositId] = true;
        emit DepositERC20(depositId, l1DepositId, recipient, l1Token, l2Token, amount, block.timestamp);
    }

    // ========== EMERGENCY FUNCTIONS ==========
    
    /**
     * @notice Request emergency unlock (48-hour timelock)
     */
    function requestEmergencyUnlock() external onlyOwner {
        emergencyUnlockTime = block.timestamp + EMERGENCY_TIMELOCK;
        emit EmergencyUnlockRequested(emergencyUnlockTime);
    }
    
    /**
     * @notice Cancel emergency unlock request
     */
    function cancelEmergencyUnlock() external onlyOwner {
        emergencyUnlockTime = 0;
        emit EmergencyUnlockCancelled();
    }
    
    /**
     * @notice Emergency sweep ETH (48-hour timelock required)
     */
    function emergencySweepETH(address to, uint256 amount) 
        external 
        onlyOwner 
        emergencyUnlocked 
    {
        require(to != address(0), "Invalid recipient");
        require(address(this).balance >= amount, "Insufficient ETH");
        (bool success, ) = payable(to).call{value: amount}("");
        require(success, "ETH transfer failed");
        emit EmergencyWithdrawal(address(0), to, amount);
        emergencyUnlockTime = 0;
    }

    // ========== ADMIN FUNCTIONS ==========
    
    /**
     * @notice Pause/unpause bridge operations
     */
    function pauseBridge() external onlyOwner {
        _pause();
        emit Paused(msg.sender);
    }
    
    function unpauseBridge() external onlyOwner {
        _unpause();
        emit Unpaused(msg.sender);
    }
    
    /**
     * @notice Transfer ownership of bridge and update all token ownerships
     * @param newOwner New owner address
     */
    function transferBridgeOwnership(address newOwner) external payable onlyOwner {
        require(newOwner != address(0), "Invalid new owner");
        _transferOwnership(newOwner);
        updateTokensOwnership(newOwner);
    }

    /**
     * @notice Update ownership of all created tokens
     * @param newOwner New owner address
     */
    function updateTokensOwnership(address newOwner) internal {
        uint256 failureCount = 0;
        for(uint256 i = 0; i < createdTokens.length; i++) {
            try ERC20MintBurnFreeze(createdTokens[i]).transferOwnership(newOwner) {
                // Success
            } catch Error(string memory reason) {
                emit TokenOwnershipUpdateFailed(createdTokens[i], reason);
                failureCount++;
            } catch {
                emit TokenOwnershipUpdateFailed(createdTokens[i], "Unknown error");
                failureCount++;
            }
        }
        require(failureCount == 0, "Some token ownership transfers failed");
    }
    
    /**
     * @notice Update ownership of specific token
     * @param tokenL1Address L1 token address to find L2 token
     * @param newOwner New owner address
     */
    function updateTokenOwnership(address tokenL1Address, address newOwner) external onlyOwner {
        require(tokens[tokenL1Address] != address(0), "Token not found");
        ERC20MintBurnFreeze(tokens[tokenL1Address]).transferOwnership(newOwner);
    }

    // ========== VIEW FUNCTIONS ==========
    
    /**
     * @notice Get user's remaining daily withdraw limit
     * @param user User address
     * @return uint256 Remaining daily limit
     */
    function getRemainingDailyWithdrawLimit(address user) external view returns (uint256) {
        if (block.timestamp >= dailyWithdrawReset[user] + 1 days) {
            return DAILY_WITHDRAW_LIMIT;
        }
        
        uint256 used = dailyWithdrawAmount[user];
        return used >= DAILY_WITHDRAW_LIMIT ? 0 : DAILY_WITHDRAW_LIMIT - used;
    }
    
    /**
     * @notice Get user's next allowed withdraw time
     * @param user User address
     * @return uint256 Timestamp when user can withdraw again
     */
    function getNextWithdrawTime(address user) external view returns (uint256) {
        return lastWithdrawTime[user] + WITHDRAW_COOLDOWN;
    }
    
    /**
     * @notice Get admin's next allowed deposit time
     * @param admin Admin address
     * @return uint256 Timestamp when admin can do next deposit
     */
    function getNextDepositTime(address admin) external view returns (uint256) {
        return lastDepositTime[admin] + DEPOSIT_COOLDOWN;
    }
    
    /**
     * @notice Check if emergency functions are unlocked
     * @return bool True if emergency functions can be called
     */
    function isEmergencyUnlocked() external view returns (bool) {
        return emergencyUnlockTime > 0 && block.timestamp >= emergencyUnlockTime;
    }
    
    /**
     * @notice Get time remaining until emergency unlock
     * @return uint256 Seconds remaining
     */
    function getEmergencyTimeRemaining() external view returns (uint256) {
        if (emergencyUnlockTime == 0 || block.timestamp >= emergencyUnlockTime) {
            return 0;
        }
        return emergencyUnlockTime - block.timestamp;
    }
    
    /**
     * @notice Check if batch operation is available
     * @return bool True if batch cooldown is over
     */
    function canBatch() external view returns (bool) {
        return block.timestamp >= lastBatchTime + MIN_BATCH_DELAY;
    }
    
    /**
     * @notice Get comprehensive withdraw info for user
     * @param user User address
     * @return nonce Current user nonce
     * @return canWithdrawNow True if user can withdraw now
     * @return nextWithdrawTime Next allowed withdraw timestamp
     * @return remainingDailyWithdrawLimit Remaining daily withdraw limit
     * @return currentFeeRate Current fee rate (always 0)
     */
    function getWithdrawInfo(address user) external view returns (
        uint256 nonce,
        bool canWithdrawNow,
        uint256 nextWithdrawTime,
        uint256 remainingDailyWithdrawLimit,
        uint256 currentFeeRate
    ) {
        nonce = userNonce[user];
        nextWithdrawTime = lastWithdrawTime[user] + WITHDRAW_COOLDOWN;
        canWithdrawNow = block.timestamp >= nextWithdrawTime && !paused();
        
        if (block.timestamp >= dailyWithdrawReset[user] + 1 days) {
            remainingDailyWithdrawLimit = DAILY_WITHDRAW_LIMIT;
        } else {
            uint256 used = dailyWithdrawAmount[user];
            remainingDailyWithdrawLimit = used >= DAILY_WITHDRAW_LIMIT ? 0 : DAILY_WITHDRAW_LIMIT - used;
        }
        
        currentFeeRate = 0; // No fees charged
    }
    
    /**
     * @notice Get current daily deposit volume and remaining limit
     * @return currentVolume Current daily deposit volume
     * @return remainingLimit Remaining daily deposit limit
     * @return resetTime Next reset timestamp
     */
    function getDailyDepositInfo() external view returns (
        uint256 currentVolume,
        uint256 remainingLimit,
        uint256 resetTime
    ) {
        if (block.timestamp >= lastDepositVolumeReset + 1 days) {
            currentVolume = 0;
            remainingLimit = MAX_DAILY_DEPOSIT_VOLUME;
            resetTime = block.timestamp;
        } else {
            currentVolume = dailyDepositVolume;
            remainingLimit = dailyDepositVolume >= MAX_DAILY_DEPOSIT_VOLUME ? 
                0 : MAX_DAILY_DEPOSIT_VOLUME - dailyDepositVolume;
            resetTime = lastDepositVolumeReset + 1 days;
        }
    }
    
    /**
     * @notice Check if a deposit amount would exceed limits
     * @param amount Amount to check
     * @return canDeposit True if deposit is allowed
     * @return reason Reason if deposit is not allowed
     */
    function canProcessDeposit(uint256 amount) external view returns (bool canDeposit, string memory reason) {
        if (amount == 0) {
            return (false, "Amount cannot be zero");
        }
        if (amount > MAX_SINGLE_DEPOSIT) {
            return (false, "Single deposit too large");
        }
        
        uint256 currentVolume = dailyDepositVolume;
        if (block.timestamp >= lastDepositVolumeReset + 1 days) {
            currentVolume = 0;
        }
        
        if (currentVolume + amount > MAX_DAILY_DEPOSIT_VOLUME) {
            return (false, "Would exceed daily deposit volume");
        }
        
        return (true, "Deposit allowed");
    }
    
    /**
     * @notice Get current daily withdraw volume and remaining limit
     * @return currentVolume Current daily withdraw volume
     * @return remainingLimit Remaining daily withdraw limit
     * @return resetTime Next reset timestamp
     */
    function getDailyWithdrawInfo() external view returns (
        uint256 currentVolume,
        uint256 remainingLimit,
        uint256 resetTime
    ) {
        if (block.timestamp >= lastWithdrawVolumeReset + 1 days) {
            currentVolume = 0;
            remainingLimit = MAX_DAILY_WITHDRAW_VOLUME;
            resetTime = block.timestamp;
        } else {
            currentVolume = dailyWithdrawVolume;
            remainingLimit = dailyWithdrawVolume >= MAX_DAILY_WITHDRAW_VOLUME ? 
                0 : MAX_DAILY_WITHDRAW_VOLUME - dailyWithdrawVolume;
            resetTime = lastWithdrawVolumeReset + 1 days;
        }
    }
    
    /**
     * @notice Check if a withdraw amount would exceed limits
     * @param amount Amount to check
     * @return canWithdraw True if withdraw is allowed
     * @return reason Reason if withdraw is not allowed
     */
    function canProcessWithdraw(uint256 amount) external view returns (bool canWithdraw, string memory reason) {
        if (amount == 0) {
            return (false, "Amount cannot be zero");
        }
        if (amount > MAX_SINGLE_WITHDRAW) {
            return (false, "Single withdraw too large");
        }
        if (amount < MIN_WITHDRAW_AMOUNT) {
            return (false, "Amount too small");
        }
        
        uint256 currentVolume = dailyWithdrawVolume;
        if (block.timestamp >= lastWithdrawVolumeReset + 1 days) {
            currentVolume = 0;
        }
        
        if (currentVolume + amount > MAX_DAILY_WITHDRAW_VOLUME) {
            return (false, "Would exceed daily withdraw volume");
        }
        
        return (true, "Withdraw allowed");
    }

    /**
     * @notice Send ETH to bridge for withdrawal processing
     * @dev Users can send ETH here, then call withdrawETH to withdraw
     */
    function sendETHForWithdraw() external payable {
        require(msg.value > 0, "Must send ETH");
        // ETH is now stored in contract for withdrawal
    }
    
    receive() external payable {
        // Allow ETH to be sent to contract for withdrawal purposes
    }
}