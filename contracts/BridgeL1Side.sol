// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title BridgeL1Side - Cross-Chain Bridge L1 Contract
 * @notice Secure bridge contract for deposits and releases of ETH and ERC20 tokens
 * @dev Uses OpenZeppelin security patterns: ReentrancyGuard, SafeERC20, Ownable2Step
 * @dev Pausable only affects deposits - release functions remain available when paused
 * @dev Emergency functions require 48-hour timelock for additional security
 */
contract BridgeL1Side is ReentrancyGuard, Ownable2Step, Pausable {
    using SafeERC20 for IERC20;
    using Address for address payable;

    // ========== COUNTERS ==========
    uint256 public depositCounter;
    uint256 public batchCounter;
    
    // ========== SECURITY TRACKING ==========
    mapping(uint256 => bool) public isReleased;           // Track released deposits
    mapping(uint256 => bool) public isWithdrawProcessed;  // Track processed L2 withdraws
    mapping(address => uint256) public userNonce;         // Prevent front-running attacks
    mapping(address => uint256) public lastDepositTime;   // Rate limiting per user
    mapping(address => uint256) public dailyDepositAmount; // Daily deposit tracking
    mapping(address => uint256) public dailyDepositReset;  // Daily reset timestamp
    mapping(address => uint256) public dailyReleaseAmount; // Daily release tracking
    mapping(address => uint256) public dailyReleaseReset;  // Daily release timestamp
    
    // ========== TIME TRACKING ==========
    uint256 public lastBatchTime;
    uint256 public lastEmergencyTime;
    
    // ========== LIMITS & DELAYS ==========
    uint256 public constant MAX_BATCH_SIZE = 50;
    uint256 public constant MIN_BATCH_DELAY = 1 hours;
    uint256 public constant EMERGENCY_DELAY = 24 hours;
    uint256 public constant MIN_DEPOSIT = 0.001 ether;
    uint256 public constant MAX_DEPOSIT = 1000 ether;
    uint256 public constant MIN_DEPOSIT_INTERVAL = 30 seconds; // Anti-spam
    uint256 public constant DAILY_DEPOSIT_LIMIT = 10000 ether; // Per user daily limit
    uint256 public constant DAILY_RELEASE_LIMIT = 50000 ether; // Per user daily release limit
    uint256 public constant MAX_SINGLE_RELEASE = 10000 ether; // Max single release amount
    // Fee system removed - following industry standard (Arbitrum, Optimism, etc.)
    // Revenue model: Gas fees and potential sequencer/validator rewards
    uint256 public constant EMERGENCY_TIMELOCK = 48 hours; // Timelock for emergency functions
    uint256 public emergencyUnlockTime; // When emergency functions become available

    // ========== EVENTS ==========
    event DepositERC20(uint256 indexed depositId, address indexed user, address indexed token, uint256 amount, uint256 nonce, uint256 timestamp);
    event DepositETH(uint256 indexed depositId, address indexed user, uint256 amount, uint256 nonce, uint256 timestamp);
    event ReleaseERC20(uint256 indexed depositId, uint256 indexed l2WithdrawId, address indexed to, address token, uint256 amount, uint256 nonce);
    event ReleaseETH(uint256 indexed depositId, uint256 indexed l2WithdrawId, address indexed to, uint256 amount, uint256 nonce);
    event BatchComplete(uint256 indexed batchId, uint256 itemCount, uint256 totalAmount);
    event EmergencyWithdrawal(address indexed token, address indexed to, uint256 amount);
    // Fee-related events removed - following industry standard
    event EmergencyUnlockRequested(uint256 unlockTime);
    event EmergencyUnlockCancelled();

    // ========== MODIFIERS ==========
    modifier validDepositAmount(uint256 amount) {
        require(amount >= MIN_DEPOSIT, "Amount too small");
        require(amount <= MAX_DEPOSIT, "Amount too large");
        _;
    }
    
    modifier rateLimited() {
        require(
            block.timestamp >= lastDepositTime[msg.sender] + MIN_DEPOSIT_INTERVAL,
            "Deposit too frequent"
        );
        _checkDailyLimit();
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
        emergencyUnlockTime = 0; // Emergency functions locked by default
    }

    // ========== INTERNAL HELPER FUNCTIONS ==========
    
    /**
     * @notice Check and update daily deposit limit
     */
    function _checkDailyLimit() internal {
        // Reset daily limit if 24 hours passed
        if (block.timestamp >= dailyDepositReset[msg.sender] + 1 days) {
            dailyDepositAmount[msg.sender] = 0;
            dailyDepositReset[msg.sender] = block.timestamp;
        }
    }
    
    /**
     * @notice Bridge fee removed - following industry standard
     * @dev Major bridges (Arbitrum, Optimism, zkSync) don't charge deposit fees
     * @dev Revenue model: Gas fees and sequencer/validator economics
     */
    function _removed_calculateFee() internal pure {
        // Fee system removed for competitive user experience
    }
    
    /**
     * @notice Update daily deposit tracking
     * @param amount Deposit amount
     */
    function _updateDailyDeposit(uint256 amount) internal {
        dailyDepositAmount[msg.sender] += amount;
        require(
            dailyDepositAmount[msg.sender] <= DAILY_DEPOSIT_LIMIT,
            "Daily deposit limit exceeded"
        );
    }
    
    /**
     * @notice Check and update daily release limit for a user
     * @param user User address receiving release
     * @param amount Release amount
     */
    function _updateDailyRelease(address user, uint256 amount) internal {
        // Reset daily limit if 24 hours passed
        if (block.timestamp >= dailyReleaseReset[user] + 1 days) {
            dailyReleaseAmount[user] = 0;
            dailyReleaseReset[user] = block.timestamp;
        }
        
        require(amount <= MAX_SINGLE_RELEASE, "Single release too large");
        dailyReleaseAmount[user] += amount;
        require(
            dailyReleaseAmount[user] <= DAILY_RELEASE_LIMIT,
            "Daily release limit exceeded"
        );
    }
    
    /**
     * @notice Check for duplicate deposit IDs in batch
     * @param depositIds Array of deposit IDs to check
     */
    function _checkNoDuplicateIds(uint256[] calldata depositIds) internal pure {
        for (uint256 i = 0; i < depositIds.length; i++) {
            for (uint256 j = i + 1; j < depositIds.length; j++) {
                require(depositIds[i] != depositIds[j], "Duplicate deposit ID");
            }
        }
    }

    // ========== DEPOSIT FUNCTIONS ==========
    
    /**
     * @notice Deposit ERC20 tokens to bridge
     * @param token ERC20 token address
     * @param amount Amount to deposit
     */
    function depositERC20(address token, uint256 amount) 
        external 
        nonReentrant 
        whenNotPaused
        validDepositAmount(amount)
        rateLimited
    {
        require(token != address(0), "Invalid token address");
        
        // No fees charged - following industry standard (Arbitrum, Optimism)
        
        // Update tracking
        uint256 nonce = ++userNonce[msg.sender];
        uint256 depositId = ++depositCounter;
        _updateDailyDeposit(amount);
        
        // Transfer full amount to bridge
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        
        emit DepositERC20(depositId, msg.sender, token, amount, nonce, block.timestamp);
    }

    /**
     * @notice Deposit ETH to bridge
     */
    function depositETH() 
        external 
        payable 
        nonReentrant 
        whenNotPaused
        validDepositAmount(msg.value)
        rateLimited
    {
        // No fees charged - following industry standard
        
        // Update tracking
        uint256 nonce = ++userNonce[msg.sender];
        uint256 depositId = ++depositCounter;
        _updateDailyDeposit(msg.value);
        
        emit DepositETH(depositId, msg.sender, msg.value, nonce, block.timestamp);
    }

    // ========== RELEASE FUNCTIONS ==========

    /**
     * @notice Release ERC20 tokens to user based on L2 withdraw
     * @param l2WithdrawId L2 withdraw ID (from L2 WithdrawERC20 event)
     * @param token Token address
     * @param to Recipient address (must match L2 withdraw user)
     * @param amount Amount to release (must match L2 withdraw amount)
     * @param withdrawNonce User nonce from L2 withdraw event
     * @dev CRITICAL: Admin must verify L2 withdraw event matches all parameters
     */
    function releaseERC20(
        uint256 l2WithdrawId, 
        address token, 
        address to, 
        uint256 amount, 
        uint256 withdrawNonce
    ) external onlyOwner nonReentrant {
        require(!isWithdrawProcessed[l2WithdrawId], "L2 withdraw already processed");
        require(to != address(0), "Invalid recipient");
        require(amount > 0, "Invalid amount");
        require(token != address(0), "Invalid token");
        require(withdrawNonce > 0, "Invalid nonce");
        
        // Check daily release limits
        _updateDailyRelease(to, amount);
        
        // Mark L2 withdraw as processed
        isWithdrawProcessed[l2WithdrawId] = true;
        
        // Generate L1 release ID for tracking
        uint256 releaseId = ++depositCounter;
        
        // Transfer tokens to user
        IERC20(token).safeTransfer(to, amount);
        
        emit ReleaseERC20(releaseId, l2WithdrawId, to, token, amount, withdrawNonce);
    }

    /**
     * @notice Release ETH to user based on L2 withdraw
     * @param l2WithdrawId L2 withdraw ID (from L2 WithdrawETH event)
     * @param to Recipient address (must match L2 withdraw user)
     * @param amount Amount to release (must match L2 withdraw amount)
     * @param withdrawNonce User nonce from L2 withdraw event
     * @dev CRITICAL: Admin must verify L2 withdraw event matches all parameters
     */
    function releaseETH(
        uint256 l2WithdrawId, 
        address to, 
        uint256 amount, 
        uint256 withdrawNonce
    ) external onlyOwner nonReentrant {
        require(!isWithdrawProcessed[l2WithdrawId], "L2 withdraw already processed");
        require(to != address(0), "Invalid recipient");
        require(amount > 0, "Invalid amount");
        require(address(this).balance >= amount, "Insufficient ETH");
        require(withdrawNonce > 0, "Invalid nonce");
        
        // Check daily release limits
        _updateDailyRelease(to, amount);
        
        // Mark L2 withdraw as processed
        isWithdrawProcessed[l2WithdrawId] = true;
        
        // Generate L1 release ID for tracking
        uint256 releaseId = ++depositCounter;
        
        // Transfer ETH to user
        payable(to).sendValue(amount);
        
        emit ReleaseETH(releaseId, l2WithdrawId, to, amount, withdrawNonce);
    }

    // ========== BATCH RELEASE FUNCTIONS ==========

    /**
     * @notice Batch release ERC20 tokens (up to 50 at once)
     * @param token Token address
     * @param recipients Array of recipient addresses
     * @param amounts Array of amounts to release
     * @param depositIds Array of deposit IDs
     */
    function batchReleaseERC20(
        address token,
        address[] calldata recipients,
        uint256[] calldata amounts,
        uint256[] calldata depositIds
    ) external onlyOwner batchCooldown nonReentrant {
        uint256 length = recipients.length;
        require(length == amounts.length && length == depositIds.length, "Array length mismatch");
        require(length > 0 && length <= MAX_BATCH_SIZE, "Invalid batch size");
        
        // Check for duplicate deposit IDs
        _checkNoDuplicateIds(depositIds);
        
        uint256 totalAmount = 0;
        
        // Pre-validation
        for (uint256 i = 0; i < length; i++) {
            require(!isReleased[depositIds[i]], "Deposit already released");
            require(recipients[i] != address(0), "Invalid recipient");
            require(amounts[i] > 0, "Invalid amount");
            totalAmount += amounts[i];
        }
        
        require(IERC20(token).balanceOf(address(this)) >= totalAmount, "Insufficient balance");
        
        // Execute batch
        for (uint256 i = 0; i < length; i++) {
            isReleased[depositIds[i]] = true;
            IERC20(token).safeTransfer(recipients[i], amounts[i]);
            emit ReleaseERC20(depositIds[i], 0, recipients[i], token, amounts[i], 0); // Legacy deposit release
        }
        
        batchCounter++;
        lastBatchTime = block.timestamp;
        emit BatchComplete(batchCounter, length, totalAmount);
    }

    /**
     * @notice Batch release ETH (up to 50 at once)
     * @param recipients Array of recipient addresses
     * @param amounts Array of amounts to release
     * @param depositIds Array of deposit IDs
     */
    function batchReleaseETH(
        address[] calldata recipients,
        uint256[] calldata amounts,
        uint256[] calldata depositIds
    ) external onlyOwner batchCooldown nonReentrant {
        uint256 length = recipients.length;
        require(length == amounts.length && length == depositIds.length, "Array length mismatch");
        require(length > 0 && length <= MAX_BATCH_SIZE, "Invalid batch size");
        
        // Check for duplicate deposit IDs
        _checkNoDuplicateIds(depositIds);
        
        uint256 totalAmount = 0;
        
        // Pre-validation
        for (uint256 i = 0; i < length; i++) {
            require(!isReleased[depositIds[i]], "Deposit already released");
            require(recipients[i] != address(0), "Invalid recipient");
            require(amounts[i] > 0, "Invalid amount");
            totalAmount += amounts[i];
        }
        
        require(address(this).balance >= totalAmount, "Insufficient ETH");
        
        // Execute batch
        for (uint256 i = 0; i < length; i++) {
            isReleased[depositIds[i]] = true;
            payable(recipients[i]).sendValue(amounts[i]);
            emit ReleaseETH(depositIds[i], 0, recipients[i], amounts[i], 0); // Legacy deposit release
        }
        
        batchCounter++;
        lastBatchTime = block.timestamp;
        emit BatchComplete(batchCounter, length, totalAmount);
    }

    // ========== EMERGENCY FUNCTIONS ==========

    /**
     * @notice Emergency batch release ERC20 (max 10, 24h cooldown)
     * @param token Token address
     * @param recipients Array of recipient addresses
     * @param amounts Array of amounts to release
     * @param depositIds Array of deposit IDs
     */
    function emergencyBatchReleaseERC20(
        address token,
        address[] calldata recipients,
        uint256[] calldata amounts,
        uint256[] calldata depositIds
    ) external onlyOwner emergencyCooldown nonReentrant {
        uint256 length = recipients.length;
        require(length > 0 && length <= 10, "Emergency batch max 10");
        require(length == amounts.length && length == depositIds.length, "Array length mismatch");
        
        uint256 totalAmount = 0;
        for (uint256 i = 0; i < length; i++) {
            require(!isReleased[depositIds[i]], "Already released");
            require(recipients[i] != address(0), "Invalid recipient");
            require(amounts[i] > 0, "Invalid amount");
            totalAmount += amounts[i];
        }
        
        require(IERC20(token).balanceOf(address(this)) >= totalAmount, "Insufficient balance");
        
        for (uint256 i = 0; i < length; i++) {
            isReleased[depositIds[i]] = true;
            IERC20(token).safeTransfer(recipients[i], amounts[i]);
            emit ReleaseERC20(depositIds[i], 0, recipients[i], token, amounts[i], 0); // Emergency deposit release
        }
        
        batchCounter++;
        lastEmergencyTime = block.timestamp;
        emit BatchComplete(batchCounter, length, totalAmount);
    }

    /**
     * @notice Emergency batch release ETH (max 10, 24h cooldown)
     * @param recipients Array of recipient addresses
     * @param amounts Array of amounts to release
     * @param depositIds Array of deposit IDs
     */
    function emergencyBatchReleaseETH(
        address[] calldata recipients,
        uint256[] calldata amounts,
        uint256[] calldata depositIds
    ) external onlyOwner emergencyCooldown nonReentrant {
        uint256 length = recipients.length;
        require(length > 0 && length <= 10, "Emergency batch max 10");
        require(length == amounts.length && length == depositIds.length, "Array length mismatch");
        
        uint256 totalAmount = 0;
        for (uint256 i = 0; i < length; i++) {
            require(!isReleased[depositIds[i]], "Already released");
            require(recipients[i] != address(0), "Invalid recipient");
            require(amounts[i] > 0, "Invalid amount");
            totalAmount += amounts[i];
        }
        
        require(address(this).balance >= totalAmount, "Insufficient ETH");
        
        for (uint256 i = 0; i < length; i++) {
            isReleased[depositIds[i]] = true;
            payable(recipients[i]).sendValue(amounts[i]);
            emit ReleaseETH(depositIds[i], 0, recipients[i], amounts[i], 0); // Emergency deposit release
        }
        
        batchCounter++;
        lastEmergencyTime = block.timestamp;
        emit BatchComplete(batchCounter, length, totalAmount);
    }

    // ========== EMERGENCY RECOVERY ==========
    
    /**
     * @notice Request emergency unlock (48-hour timelock)
     * @dev Owner must call this first, then wait 48 hours before emergency functions work
     */
    function requestEmergencyUnlock() external onlyOwner {
        emergencyUnlockTime = block.timestamp + EMERGENCY_TIMELOCK;
        emit EmergencyUnlockRequested(emergencyUnlockTime);
    }
    
    /**
     * @notice Cancel emergency unlock request
     * @dev Can be called to cancel pending emergency unlock
     */
    function cancelEmergencyUnlock() external onlyOwner {
        emergencyUnlockTime = 0;
        emit EmergencyUnlockCancelled();
    }

    /**
     * @notice Emergency sweep ERC20 tokens (48-hour timelock required)
     * @param token Token address
     * @param to Recipient address
     * @param amount Amount to sweep
     * @dev Requires requestEmergencyUnlock() called 48 hours prior
     */
    function emergencySweepERC20(address token, address to, uint256 amount) 
        external 
        onlyOwner 
        emergencyUnlocked 
    {
        require(to != address(0), "Invalid recipient");
        IERC20(token).safeTransfer(to, amount);
        emit EmergencyWithdrawal(token, to, amount);
        
        // Reset emergency unlock after use
        emergencyUnlockTime = 0;
    }

    /**
     * @notice Emergency sweep ETH (48-hour timelock required)
     * @param to Recipient address
     * @param amount Amount to sweep
     * @dev Requires requestEmergencyUnlock() called 48 hours prior
     */
    function emergencySweepETH(address to, uint256 amount) 
        external 
        onlyOwner 
        emergencyUnlocked 
    {
        require(to != address(0), "Invalid recipient");
        require(address(this).balance >= amount, "Insufficient ETH");
        payable(to).sendValue(amount);
        emit EmergencyWithdrawal(address(0), to, amount);
        
        // Reset emergency unlock after use
        emergencyUnlockTime = 0;
    }

    // ========== ADMIN FUNCTIONS ==========
    
    /**
     * @notice Fee system removed - following industry standard
     * @dev Major bridges don't charge deposit fees for better UX
     */
    // function setDepositFeeRate() - REMOVED
    
    /**
     * @notice Pause/unpause deposits
     */
    function pauseDeposits() external onlyOwner {
        _pause();
    }
    
    function unpauseDeposits() external onlyOwner {
        _unpause();
    }
    
    /**
     * @notice Fee collection removed - no fees charged
     * @dev Following industry standard: Arbitrum, Optimism, zkSync don't charge fees
     */
    // function collectFees() - REMOVED (no fees to collect)

    // ========== VIEW FUNCTIONS ==========

    /**
     * @notice Check if deposit has been released
     * @param depositId Deposit ID to check
     * @return bool True if released
     */
    function checkReleaseStatus(uint256 depositId) external view returns (bool) {
        return isReleased[depositId];
    }
    
    /**
     * @notice Get user's remaining daily deposit limit
     * @param user User address
     * @return uint256 Remaining daily limit
     */
    function getRemainingDailyLimit(address user) external view returns (uint256) {
        // Check if daily limit should be reset
        if (block.timestamp >= dailyDepositReset[user] + 1 days) {
            return DAILY_DEPOSIT_LIMIT;
        }
        
        uint256 used = dailyDepositAmount[user];
        return used >= DAILY_DEPOSIT_LIMIT ? 0 : DAILY_DEPOSIT_LIMIT - used;
    }
    
    /**
     * @notice Get user's next allowed deposit time
     * @param user User address
     * @return uint256 Timestamp when user can deposit again
     */
    function getNextDepositTime(address user) external view returns (uint256) {
        return lastDepositTime[user] + MIN_DEPOSIT_INTERVAL;
    }
    
    /**
     * @notice Fee calculation removed - no fees charged
     * @dev Following industry standard for better user experience
     * @return uint256 Always returns 0 (no fees)
     */
    function calculateDepositFee(uint256) external pure returns (uint256) {
        return 0; // No fees charged
    }
    
    /**
     * @notice Fee rate removed - always 0
     * @return uint256 Always returns 0 (no fees)
     */
    function getDepositFeeRate() external pure returns (uint256) {
        return 0; // No fees charged
    }
    
    /**
     * @notice Get user's current nonce
     * @param user User address
     * @return uint256 Current nonce
     */
    function getUserNonce(address user) external view returns (uint256) {
        return userNonce[user];
    }
    
    /**
     * @notice Get contract ETH balance
     * @return uint256 ETH balance
     */
    function getETHBalance() external view returns (uint256) {
        return address(this).balance;
    }
    
    /**
     * @notice Get contract ERC20 token balance
     * @param token Token address
     * @return uint256 Token balance
     */
    function getTokenBalance(address token) external view returns (uint256) {
        return IERC20(token).balanceOf(address(this));
    }
    
    /**
     * @notice Check if batch operation is available
     * @return bool True if batch cooldown is over
     */
    function canBatch() external view returns (bool) {
        return block.timestamp >= lastBatchTime + MIN_BATCH_DELAY;
    }

    /**
     * @notice Check if emergency operation is available
     * @return bool True if emergency cooldown is over
     */
    function canEmergency() external view returns (bool) {
        return block.timestamp >= lastEmergencyTime + EMERGENCY_DELAY;
    }

    /**
     * @notice Get time since last batch operation
     * @return uint256 Seconds since last batch
     */
    function getTimeSinceLastBatch() external view returns (uint256) {
        return block.timestamp - lastBatchTime;
    }

    /**
     * @notice Get time since last emergency operation
     * @return uint256 Seconds since last emergency
     */
    function getTimeSinceLastEmergency() external view returns (uint256) {
        return block.timestamp - lastEmergencyTime;
    }
    
    /**
     * @notice Check if emergency functions are currently unlocked
     * @return bool True if emergency functions can be called
     */
    function isEmergencyUnlocked() external view returns (bool) {
        return emergencyUnlockTime > 0 && block.timestamp >= emergencyUnlockTime;
    }
    
    /**
     * @notice Get emergency unlock timestamp
     * @return uint256 Timestamp when emergency functions become available (0 if not requested)
     */
    function getEmergencyUnlockTime() external view returns (uint256) {
        return emergencyUnlockTime;
    }
    
    /**
     * @notice Get time remaining until emergency unlock
     * @return uint256 Seconds remaining (0 if already unlocked or not requested)
     */
    function getEmergencyTimeRemaining() external view returns (uint256) {
        if (emergencyUnlockTime == 0 || block.timestamp >= emergencyUnlockTime) {
            return 0;
        }
        return emergencyUnlockTime - block.timestamp;
    }
    
    /**
     * @notice Get comprehensive deposit info for user
     * @param user User address
     * @return nonce Current user nonce
     * @return canDepositNow True if user can deposit now
     * @return nextDepositTime Next allowed deposit timestamp
     * @return remainingDailyLimit Remaining daily deposit limit
     * @return currentFeeRate Current fee rate in basis points
     */
    function getDepositInfo(address user) external view returns (
        uint256 nonce,
        bool canDepositNow,
        uint256 nextDepositTime,
        uint256 remainingDailyLimit,
        uint256 currentFeeRate
    ) {
        nonce = userNonce[user];
        nextDepositTime = lastDepositTime[user] + MIN_DEPOSIT_INTERVAL;
        canDepositNow = block.timestamp >= nextDepositTime && !paused();
        
        // Calculate remaining daily limit
        if (block.timestamp >= dailyDepositReset[user] + 1 days) {
            remainingDailyLimit = DAILY_DEPOSIT_LIMIT;
        } else {
            uint256 used = dailyDepositAmount[user];
            remainingDailyLimit = used >= DAILY_DEPOSIT_LIMIT ? 0 : DAILY_DEPOSIT_LIMIT - used;
        }
        
        currentFeeRate = 0; // No fees charged
    }
    
    /**
     * @notice Check if L2 withdraw has been processed
     * @param l2WithdrawId L2 withdraw ID to check
     * @return bool True if processed
     */
    function isL2WithdrawProcessed(uint256 l2WithdrawId) external view returns (bool) {
        return isWithdrawProcessed[l2WithdrawId];
    }
    
    /**
     * @notice Get user's remaining daily release limit
     * @param user User address
     * @return uint256 Remaining daily release limit
     */
    function getRemainingDailyReleaseLimit(address user) external view returns (uint256) {
        // Check if daily limit should be reset
        if (block.timestamp >= dailyReleaseReset[user] + 1 days) {
            return DAILY_RELEASE_LIMIT;
        }
        
        uint256 used = dailyReleaseAmount[user];
        return used >= DAILY_RELEASE_LIMIT ? 0 : DAILY_RELEASE_LIMIT - used;
    }
    
    /**
     * @notice Check if a release amount would exceed user's daily limit
     * @param user User address
     * @param amount Amount to check
     * @return canRelease True if release is allowed
     * @return reason Reason if release is not allowed
     */
    function canProcessRelease(address user, uint256 amount) external view returns (bool canRelease, string memory reason) {
        if (amount == 0) {
            return (false, "Amount cannot be zero");
        }
        if (amount > MAX_SINGLE_RELEASE) {
            return (false, "Single release too large");
        }
        
        // Check daily limit
        uint256 currentUsed = dailyReleaseAmount[user];
        if (block.timestamp >= dailyReleaseReset[user] + 1 days) {
            currentUsed = 0;
        }
        
        if (currentUsed + amount > DAILY_RELEASE_LIMIT) {
            return (false, "Would exceed daily release limit");
        }
        
        return (true, "Release allowed");
    }

    // ========== FALLBACK ==========
    
    /**
     * @notice Receive ETH and auto-deposit
     * @dev Creates deposit entry for direct ETH transfers
     * @dev Uses same validation as depositETH() including rate limiting
     */
    receive() external payable {
        require(!paused(), "Contract is paused");
        require(msg.value >= MIN_DEPOSIT && msg.value <= MAX_DEPOSIT, "Invalid ETH amount");
        
        // Rate limiting check (same as rateLimited modifier)
        require(
            block.timestamp >= lastDepositTime[msg.sender] + MIN_DEPOSIT_INTERVAL,
            "Deposit too frequent"
        );
        
        // Daily limit check and update
        _checkDailyLimit();
        _updateDailyDeposit(msg.value);
        
        // No fees charged - industry standard practice
        
        // Update tracking
        uint256 nonce = ++userNonce[msg.sender];
        uint256 depositId = ++depositCounter;
        lastDepositTime[msg.sender] = block.timestamp;
        
        emit DepositETH(depositId, msg.sender, msg.value, nonce, block.timestamp);
    }
}