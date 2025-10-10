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
    bytes32 public constant PERMIT_TYPEHASH = keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

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

    // ========= CUSTOM ERRORS (reduce bytecode size) =========
    error ErrInvalidAddress();
    error ErrAlreadyProcessed();
    error ErrAmountZero();
    error ErrAmountTooSmall();
    error ErrAmountTooLarge();
    error ErrCooldown();
    error ErrEmergencyLocked();
    error ErrTokenNotMapped();
    error ErrScaleNotInit();
    error ErrInvalidScaledAmount();
    error ErrFrozenUser();
    error ErrInsufficientBalance();
    error ErrNameInvalid();
    error ErrSymbolInvalid();
    error ErrDecimalsTooHigh();
    error ErrDecimalsMismatch();
    error ErrMetadataMismatch();
    error ErrFailedCall();

    // ========== COUNTERS ==========
    uint256 public withdrawCounter;
    uint256 public depositCounter;
    uint256 public batchCounter;
    
    // ========== TOKEN MAPPINGS ==========
    address public ethg; // ETHg token address on L2

    mapping(address => address) public tokens;         // L1 token => L2 wrapped token
    mapping(address => address) public tokensReverse;  // L2 wrapped token => L1 token
    address[] public createdTokens;                    // Array of all created L2 tokens
    // L1 token decimals and scaling (to normalize to 18 decimals on L2)
    mapping(address => uint8) public l1TokenDecimals;   // L1 token => decimals on L1 (0..18)
    mapping(address => uint256) public l1TokenScale;     // L1 token => scale factor 10**(18 - decimals), or 1 for 18
    
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
    uint256 public dailyWithdrawVolume;    // Track daily withdraw volume
    uint256 public lastWithdrawVolumeReset; // Daily withdraw volume reset timestamp

    // ========== LIMITS & DELAYS ==========
    uint256 public constant MAX_BATCH_SIZE = 25;
    uint256 public constant MIN_BATCH_DELAY = 1 hours;
    uint256 public constant EMERGENCY_DELAY = 24 hours;
    uint256 public constant WITHDRAW_COOLDOWN = 30 seconds;     // Anti-spam for withdraws
    uint256 public constant DEPOSIT_COOLDOWN = 10 seconds;      // Anti-spam for deposits (admin)
    uint256 public constant MIN_WITHDRAW_AMOUNT = 0.001 * 10 ** 18;  // Minimum withdraw
    uint256 public constant MAX_WITHDRAW_AMOUNT = 10000 * 10 ** 18;  // Maximum withdraw
    uint256 public constant DAILY_WITHDRAW_LIMIT = 50000 * 10 ** 18; // Per user daily limit
    uint256 public constant EMERGENCY_TIMELOCK = 48 hours;     // Emergency timelock
    uint256 public emergencyUnlockTime;                        // Emergency unlock timestamp
    uint256 public constant MAX_DAILY_WITHDRAW_VOLUME = 2000000 * 10 ** 18; // Max daily withdraw volume
    uint256 public constant MAX_SINGLE_WITHDRAW = 50000 * 10 ** 18; // Max single withdraw amount

    // ========== EVENTS ==========
    event WithdrawERC20(
        uint256 indexed withdrawId,
        address indexed user,
        address indexed l2Token,
        address l1Token,
        uint256 amountScaled,
        uint256 rawAmount,
        uint256 nonce,
        uint256 timestamp
    );
    event WithdrawETHg(uint256 indexed withdrawId, address indexed user, address indexed l2Token, uint256 amount, uint256 nonce, uint256 timestamp);
    event DepositERC20(uint256 indexed depositId, uint256 indexed l1DepositId, address indexed to, address l1Token, address l2Token, uint256 amount, uint256 timestamp);
    event DepositETHg(uint256 indexed depositId, uint256 indexed l1DepositId, address indexed to, uint256 amount, uint256 timestamp);
    event TokenCreated(address indexed l1Token, address indexed l2Token, string name, string symbol, uint8 decimals);
    event BatchComplete(uint256 indexed batchId, uint256 itemCount, uint256 totalAmount);
    event EmergencyWithdrawal(address indexed token, address indexed to, uint256 amount);
    event TokenOwnershipUpdateFailed(address indexed token, string reason);
    event EmergencyUnlockRequested(uint256 unlockTime);
    event EmergencyUnlockCancelled();
    event MinimumWithdrawUpdated(address indexed token, uint256 oldMinimum, uint256 newMinimum);

    // ========== STRUCTS FOR BATCH OPERATIONS ==========
    struct BatchDepositData {
        uint256 l1DepositId;
        address l1Token;
        address recipient;
        uint256 amount; // raw amount in L1 token decimals
    }

    // ========== MODIFIERS ==========
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
        lastWithdrawVolumeReset = block.timestamp;
        dailyWithdrawVolume = 0;

        ethg = address(new ERC20MintBurnFreeze("Ethereum g", "ETHg", address(this)));
        withdrawMinimums[ethg] = 0.001 * (10 ** 18);
    }

    // ========== INTERNAL HELPER FUNCTIONS ==========

    function manualTokenMapping(address l1Token, address l2Token) external onlyOwner {
        if (l1Token == address(0)) revert ErrInvalidAddress();
        if (l2Token == address(0)) revert ErrInvalidAddress();
        if (tokens[l1Token] != address(0)) revert ErrAlreadyProcessed();
        if (tokensReverse[l2Token] != address(0)) revert ErrAlreadyProcessed();
        if (ERC20MintBurnFreeze(l2Token).admin() != address(this)) revert ErrMetadataMismatch();
        tokens[l1Token] = l2Token;
        tokensReverse[l2Token] = l1Token;
        withdrawMinimums[l2Token] = 5 * (10 ** 18); // 5 tokens in wei
    }
    
    function _checkDailyWithdrawLimit() internal {
        if (block.timestamp >= dailyWithdrawReset[msg.sender] + 1 days) {
            dailyWithdrawAmount[msg.sender] = 0;
            dailyWithdrawReset[msg.sender] = block.timestamp;
        }
    }

    function setTokenMinimumWithdraw(address l2Token, uint256 minimumAmount) external onlyOwner {
        if (l2Token == address(0)) revert ErrInvalidAddress();
        if (tokensReverse[l2Token] == address(0)) revert ErrTokenNotMapped();
        uint256 oldMinimum = withdrawMinimums[l2Token];
        withdrawMinimums[l2Token] = minimumAmount;
        emit MinimumWithdrawUpdated(l2Token, oldMinimum, minimumAmount);
    }

    function setETHgMinimumWithdraw(uint256 minimumAmount) external onlyOwner {
        uint256 oldMinimum = withdrawMinimums[ethg];
        withdrawMinimums[ethg] = minimumAmount;
        emit MinimumWithdrawUpdated(ethg, oldMinimum, minimumAmount);
    }
    
    function _updateDailyWithdraw(uint256 amount) internal {
        dailyWithdrawAmount[msg.sender] += amount;
        if (dailyWithdrawAmount[msg.sender] > DAILY_WITHDRAW_LIMIT) revert ErrAmountTooLarge();
    }
    
    function _checkDailyWithdrawVolume(uint256 amount) internal {
        if (block.timestamp >= lastWithdrawVolumeReset + 1 days) {
            dailyWithdrawVolume = 0;
            lastWithdrawVolumeReset = block.timestamp;
        }
        if (amount > MAX_SINGLE_WITHDRAW) revert ErrAmountTooLarge();
        dailyWithdrawVolume += amount;
        if (dailyWithdrawVolume > MAX_DAILY_WITHDRAW_VOLUME) revert ErrAmountTooLarge();
    }

    // ========== WITHDRAW FUNCTIONS (L2 → L1) ==========
    
    function withdrawERC20(address l2Token, uint256 amount) 
        external 
        nonReentrant
        whenNotPaused
        validWithdrawAmountErc20(amount, l2Token)
        withdrawRateLimited
    {
        if (l2Token == ethg) revert ErrInvalidAddress();
        if (l2Token == address(0)) revert ErrInvalidAddress();
        if (tokensReverse[l2Token] == address(0)) revert ErrTokenNotMapped();
        
        ERC20MintBurnFreeze token = ERC20MintBurnFreeze(l2Token);
        if (token.frozen(msg.sender)) revert ErrFrozenUser();
        if (token.balanceOf(msg.sender) < amount) revert ErrInsufficientBalance();
        
        address l1Token = tokensReverse[l2Token];
        uint256 scale = l1TokenScale[l1Token];
        if (scale == 0) revert ErrScaleNotInit();
        if (amount % scale != 0) revert ErrInvalidScaledAmount();
        uint256 rawAmount = amount / scale;
        
        uint256 nonce = ++userNonce[msg.sender];
        uint256 withdrawId = ++withdrawCounter;
        _updateDailyWithdraw(amount);
        _checkDailyWithdrawVolume(amount);
        
        token.burnFrom(msg.sender, amount);
        
        emit WithdrawERC20(
            withdrawId, 
            msg.sender, 
            l2Token, 
            l1Token, 
            amount,      // amountScaled (burned on L2)
            rawAmount,   // rawAmount (to release on L1)
            nonce, 
            block.timestamp
        );
    }

    // Pada code ini kita hanya menarik ETHg sehingga gak perlu skala dan cek token lain
    function withdrawETHg(uint256 amount) 
        external 
        nonReentrant
        whenNotPaused
        withdrawRateLimited
    {
        if (amount == 0) revert ErrAmountZero();
        if (amount < MIN_WITHDRAW_AMOUNT) revert ErrAmountTooSmall();
        
        if (amount < withdrawMinimums[ethg]) revert ErrAmountTooSmall();
        
        if (ERC20MintBurnFreeze(ethg).frozen(msg.sender)) revert ErrFrozenUser();
        if (ERC20MintBurnFreeze(ethg).balanceOf(msg.sender) < amount) revert ErrInsufficientBalance();

        uint256 nonce = ++userNonce[msg.sender];
        uint256 withdrawId = ++withdrawCounter;
        
        _updateDailyWithdraw(amount);
        _checkDailyWithdrawVolume(amount);

        ERC20MintBurnFreeze(ethg).burnFrom(msg.sender, amount);

        emit WithdrawETHg(withdrawId, msg.sender, ethg, amount, nonce, block.timestamp);
    }

    // ========== DEPOSIT FUNCTIONS (L1 → L2) ==========

    function registerERC20(
        address l1Token,
        string memory name,
        string memory symbol,
        uint8 decimals
    ) external onlyOwner {
        if (l1Token == address(0)) revert ErrInvalidAddress();
        if (tokens[l1Token] != address(0)) revert ErrAlreadyProcessed();
        if (bytes(name).length == 0 || bytes(name).length > 50) revert ErrNameInvalid();
        if (bytes(symbol).length == 0 || bytes(symbol).length > 10) revert ErrSymbolInvalid();
        if (decimals > 18) revert ErrDecimalsTooHigh();

        address l2Token = address(new ERC20MintBurnFreeze(name, symbol, address(this)));
        tokens[l1Token] = l2Token;
        tokensReverse[l2Token] = l1Token;
        createdTokens.push(l2Token);
        withdrawMinimums[l2Token] = 5 * (10 ** 18);
        
        l1TokenDecimals[l1Token] = decimals;
        uint256 scale = (decimals == 18) ? 1 : (10 ** (18 - decimals));
        l1TokenScale[l1Token] = scale;
        
        emit TokenCreated(l1Token, l2Token, name, symbol, decimals);
    }

    function depositERC20(
        uint256 l1DepositId, 
        address l1Token, 
        address to, 
        uint256 amount
    ) external onlyOwner nonReentrant depositRateLimited {
        if (done[l1DepositId]) revert ErrAlreadyProcessed();
        if (l1Token == address(0) || to == address(0)) revert ErrInvalidAddress();
        if (amount == 0) revert ErrAmountZero();

        address l2Token = tokens[l1Token];
        if (l2Token == address(0)) revert ErrTokenNotMapped();

        uint256 scale = l1TokenScale[l1Token];
        if (scale == 0) revert ErrScaleNotInit();
        if (amount > type(uint256).max / scale) revert ErrAmountTooLarge();

        uint256 mintAmount = amount * scale;
        ERC20MintBurnFreeze(l2Token).mint(to, mintAmount);

        uint256 depositId = ++depositCounter;
        done[l1DepositId] = true;
        emit DepositERC20(depositId, l1DepositId, to, l1Token, l2Token, amount, block.timestamp);
    }

    function depositETHg(
        uint256 l1DepositId, 
        address to, 
        uint256 amount
    ) external onlyOwner nonReentrant depositRateLimited {
        if (done[l1DepositId]) revert ErrAlreadyProcessed();
        if (to == address(0)) revert ErrInvalidAddress();
        if (amount == 0) revert ErrAmountZero();

        if (amount > type(uint256).max / 1) revert ErrAmountTooLarge(); // Prevent overflow
        
        uint256 depositId = ++depositCounter;

        ERC20MintBurnFreeze(ethg).mint(to, amount);

        done[l1DepositId] = true;
        emit DepositETHg(depositId, l1DepositId, to, amount, block.timestamp);
    }

    // ========== FIXED BATCH OPERATIONS ==========

    /**
     * @notice Batch deposit ERC20 tokens (no metadata required)
     * @dev Each item requires: l1DepositId, l1Token, recipient, amount (raw, in L1 decimals)
     *      The function checks that each l1Token is already mapped, then mints
     *      amount * scale(l1Token) to the recipient. Marks each l1DepositId as done.
     */
    function batchDepositERC20(
        BatchDepositData[] calldata deposits
    ) external onlyOwner batchCooldown nonReentrant depositRateLimited {
        uint256 length = deposits.length;
        if (length == 0 || length > MAX_BATCH_SIZE) revert ErrAmountTooLarge();
        
        // Validate all deposits first
        for (uint256 i = 0; i < length; ) {
            if (done[deposits[i].l1DepositId]) revert ErrAlreadyProcessed();
            unchecked { ++i; }
        }

        uint256 totalAmount = 0;
        
        // Process each deposit
        for (uint256 i = 0; i < length; ) {
            totalAmount += _processBatchDeposit(deposits[i]);
            unchecked { ++i; }
        }

        batchCounter++;
        lastBatchTime = block.timestamp;
        emit BatchComplete(batchCounter, length, totalAmount);
    }
    
    /**
     * @notice Internal function to process single batch deposit (FIXED)
     */
    function _processBatchDeposit(
        BatchDepositData calldata deposit
    ) internal returns (uint256) {
        if (deposit.recipient == address(0)) revert ErrInvalidAddress();
        if (deposit.amount == 0) revert ErrAmountZero();

        if (tokens[deposit.l1Token] == address(0)) revert ErrTokenNotMapped();
        
        uint256 depositId = ++depositCounter;
        address l2Token;
        
        l2Token = tokens[deposit.l1Token];
        ERC20MintBurnFreeze tokenContract = ERC20MintBurnFreeze(l2Token);
        uint256 scale = l1TokenScale[deposit.l1Token];
        if (scale == 0) revert ErrScaleNotInit();
        if (deposit.amount > type(uint256).max / scale) revert ErrAmountTooLarge();
        tokenContract.mint(deposit.recipient, deposit.amount * scale);
        
        done[deposit.l1DepositId] = true;
        emit DepositERC20(depositId, deposit.l1DepositId, deposit.recipient, deposit.l1Token, l2Token, deposit.amount, block.timestamp);
        
        return deposit.amount;
    }

    // ========== EMERGENCY FUNCTIONS ==========
    
    function requestEmergencyUnlock() external onlyOwner {
        emergencyUnlockTime = block.timestamp + EMERGENCY_TIMELOCK;
        emit EmergencyUnlockRequested(emergencyUnlockTime);
    }
    
    function cancelEmergencyUnlock() external onlyOwner {
        emergencyUnlockTime = 0;
        emit EmergencyUnlockCancelled();
    }
    
    function emergencySweepETH(address to, uint256 amount) 
        external 
        onlyOwner 
        emergencyUnlocked 
    {
        if (to == address(0)) revert ErrInvalidAddress();
        if (address(this).balance < amount) revert ErrInsufficientBalance();
        (bool success, ) = payable(to).call{value: amount}("");
        if (!success) revert ErrFailedCall();
        emit EmergencyWithdrawal(address(0), to, amount);
        emergencyUnlockTime = 0;
    }

    // ========== ADMIN FUNCTIONS ==========
    
    function pauseBridge() external onlyOwner {
        _pause();
    }
    
    function unpauseBridge() external onlyOwner {
        _unpause();
    }
    
    function transferBridgeOwnership(address newOwner) external payable onlyOwner {
        require(newOwner != address(0), "Invalid new owner");
        transferOwnership(newOwner);
        _updateTokensOwnership(newOwner);
    }

    function _updateTokensOwnership(address newOwner) internal {
        uint256 failureCount = 0;
        uint256 length = createdTokens.length;
        for(uint256 i = 0; i < length; i++) {
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
    
    function updateTokenOwnership(address tokenL1Address, address newOwner) external onlyOwner {
        require(tokens[tokenL1Address] != address(0), "Token not found");
        ERC20MintBurnFreeze(tokens[tokenL1Address]).transferOwnership(newOwner);
    }

    // ========== VIEW FUNCTIONS ==========
    
    function getRemainingDailyWithdrawLimit(address user) external view returns (uint256) {
        if (block.timestamp >= dailyWithdrawReset[user] + 1 days) {
            return DAILY_WITHDRAW_LIMIT;
        }
        
        uint256 used = dailyWithdrawAmount[user];
        return used >= DAILY_WITHDRAW_LIMIT ? 0 : DAILY_WITHDRAW_LIMIT - used;
    }
    
    function getNextWithdrawTime(address user) external view returns (uint256) {
        return lastWithdrawTime[user] + WITHDRAW_COOLDOWN;
    }
    
    function getNextDepositTime(address admin) external view returns (uint256) {
        return lastDepositTime[admin] + DEPOSIT_COOLDOWN;
    }
    
    function isEmergencyUnlocked() external view returns (bool) {
        return emergencyUnlockTime > 0 && block.timestamp >= emergencyUnlockTime;
    }
    
    function getEmergencyTimeRemaining() external view returns (uint256) {
        if (emergencyUnlockTime == 0 || block.timestamp >= emergencyUnlockTime) {
            return 0;
        }
        return emergencyUnlockTime - block.timestamp;
    }
    
    function canBatch() external view returns (bool) {
        return block.timestamp >= lastBatchTime + MIN_BATCH_DELAY;
    }
    
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
        
        currentFeeRate = 0;
    }
    
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

    receive() external payable {
        revert("Direct ETH not accepted");
    }
}