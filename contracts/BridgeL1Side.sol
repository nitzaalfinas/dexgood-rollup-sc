// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
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

    mapping(address => bool) public tokens; // tracking tokens is ever deposited or not
    address[] public tokenList; // list of all deposited tokens
    
    // ========== SECURITY TRACKING ==========
    mapping(uint256 => bool) public isReleased;           // Track released deposits
    mapping(uint256 => bool) public isWithdrawProcessed;  // Track processed L2 withdraws
    mapping(address => uint256) public userNonce;         // Prevent front-running attacks
    mapping(address => uint256) public lastDepositTime;   // Rate limiting per user
    
    // ========== TIME TRACKING ==========
    uint256 public lastBatchTime;
    uint256 public lastEmergencyTime;
    
    // ========== LIMITS & DELAYS ==========
    uint256 public constant MAX_BATCH_SIZE = 50;
    uint256 public constant MIN_BATCH_DELAY = 1 hours;
    uint256 public constant EMERGENCY_DELAY = 24 hours;
    uint256 public constant MIN_DEPOSIT_INTERVAL = 30 seconds; // Anti-spam
    uint256 public constant EMERGENCY_TIMELOCK = 48 hours; // Timelock for emergency functions
    uint256 public emergencyUnlockTime; // When emergency functions become available

    // ========== EVENTS ==========
    event DepositERC20(
        uint256 indexed depositId, 
        address indexed user, 
        address indexed token, 
        uint256 amountReceived,
        uint256 nonce, 
        uint256 timestamp
    );
    event DepositETH(uint256 indexed depositId, address indexed user, uint256 amount, uint256 nonce, uint256 timestamp);
    event ReleaseERC20(uint256 indexed depositId, uint256 indexed l2WithdrawId, address indexed to, address token, uint256 amount, uint256 nonce);
    event ReleaseETH(uint256 indexed depositId, uint256 indexed l2WithdrawId, address indexed to, uint256 amount, uint256 nonce);
    event BatchComplete(uint256 indexed batchId, uint256 itemCount, uint256 totalAmount);
    event EmergencyWithdrawal(address indexed token, address indexed to, uint256 amount);
    event EmergencyUnlockRequested(uint256 unlockTime);
    event EmergencyUnlockCancelled();
    event NewERC20(address indexed token, string name, string symbol, uint8 decimals);

    // ========== MODIFIERS ==========
    modifier rateLimited() {
        require(
            block.timestamp >= lastDepositTime[msg.sender] + MIN_DEPOSIT_INTERVAL,
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
        emergencyUnlockTime = 0; // Emergency functions locked by default
    }

    // ========== INTERNAL HELPER FUNCTIONS ==========
    function _checkNoDuplicateIds(uint256[] calldata depositIds) internal pure {
        for (uint256 i = 0; i < depositIds.length; i++) {
            for (uint256 j = i + 1; j < depositIds.length; j++) {
                require(depositIds[i] != depositIds[j], "Duplicate deposit ID");
            }
        }
    }

    // ========== DEPOSIT FUNCTIONS ==========
    function depositERC20(address token, uint256 amount) 
        external 
        nonReentrant 
        whenNotPaused
        rateLimited
    {
        require(token != address(0), "Invalid token address");
        require(amount > 0, "Amount must be greater than 0");

        // ✅ CHECK IF NEW TOKEN - Emit registration event
        if(tokens[token] == false){
            tokenList.push(token);
            tokens[token] = true;

            uint8 dec = IERC20Metadata(token).decimals();
            require(dec <= 18, "Decimals > 18 not supported");

            // 🎯 EMIT TOKEN REGISTRATION EVENT (separate from deposit)
            emit NewERC20(token, IERC20Metadata(token).name(), IERC20Metadata(token).symbol(), dec);
        }
        
        uint256 nonce = ++userNonce[msg.sender];
        uint256 depositId = ++depositCounter;
        
        uint256 beforeBal = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        uint256 received = IERC20(token).balanceOf(address(this)) - beforeBal;
        require(received > 0, "No tokens received");
        
        // ✅ CLEAN DEPOSIT EVENT - No metadata needed
        emit DepositERC20(depositId, msg.sender, token, received, nonce, block.timestamp);
    }

    function depositETH() 
        external 
        payable 
        nonReentrant 
        whenNotPaused
        rateLimited
    {
        require(msg.value > 0, "Amount must be greater than 0");
        
        uint256 nonce = ++userNonce[msg.sender];
        uint256 depositId = ++depositCounter;
        
        emit DepositETH(depositId, msg.sender, msg.value, nonce, block.timestamp);
    }

    // ========== RELEASE FUNCTIONS ==========

    function releaseERC20(
        uint256 l2WithdrawId,
        address token,
        address to,
        uint256 amountRaw,      // Amount to release (from L2 event rawAmount)
        uint256 withdrawNonce
    ) external onlyOwner nonReentrant {
        require(!isWithdrawProcessed[l2WithdrawId], "L2 withdraw already processed");
        require(to != address(0), "Invalid recipient");
        require(amountRaw > 0, "Invalid amount");
        require(token != address(0), "Invalid token");
        require(withdrawNonce > 0, "Invalid nonce");

        isWithdrawProcessed[l2WithdrawId] = true;
        uint256 releaseId = ++depositCounter;

        IERC20(token).safeTransfer(to, amountRaw);
        emit ReleaseERC20(releaseId, l2WithdrawId, to, token, amountRaw, withdrawNonce);
    }

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
        
        isWithdrawProcessed[l2WithdrawId] = true;
        uint256 releaseId = ++depositCounter;
        
        payable(to).sendValue(amount);
        emit ReleaseETH(releaseId, l2WithdrawId, to, amount, withdrawNonce);
    }

    // ========== BATCH RELEASE FUNCTIONS ==========
    function batchReleaseERC20(
        address token,
        address[] calldata recipients,
        uint256[] calldata amounts,
        uint256[] calldata depositIds
    ) external onlyOwner batchCooldown nonReentrant {
        uint256 length = recipients.length;
        require(length == amounts.length && length == depositIds.length, "Array length mismatch");
        require(length > 0 && length <= MAX_BATCH_SIZE, "Invalid batch size");
        
        _checkNoDuplicateIds(depositIds);
        
        uint256 totalAmount = 0;
        for (uint256 i = 0; i < length; i++) {
            require(!isReleased[depositIds[i]], "Deposit already released");
            require(recipients[i] != address(0), "Invalid recipient");
            require(amounts[i] > 0, "Invalid amount");
            totalAmount += amounts[i];
        }
        
        require(IERC20(token).balanceOf(address(this)) >= totalAmount, "Insufficient balance");
        
        for (uint256 i = 0; i < length; i++) {
            isReleased[depositIds[i]] = true;
            IERC20(token).safeTransfer(recipients[i], amounts[i]);
            emit ReleaseERC20(depositIds[i], 0, recipients[i], token, amounts[i], 0);
        }
        
        batchCounter++;
        lastBatchTime = block.timestamp;
        emit BatchComplete(batchCounter, length, totalAmount);
    }

    function batchReleaseETH(
        address[] calldata recipients,
        uint256[] calldata amounts,
        uint256[] calldata depositIds
    ) external onlyOwner batchCooldown nonReentrant {
        uint256 length = recipients.length;
        require(length == amounts.length && length == depositIds.length, "Array length mismatch");
        require(length > 0 && length <= MAX_BATCH_SIZE, "Invalid batch size");
        
        _checkNoDuplicateIds(depositIds);
        
        uint256 totalAmount = 0;
        for (uint256 i = 0; i < length; i++) {
            require(!isReleased[depositIds[i]], "Deposit already released");
            require(recipients[i] != address(0), "Invalid recipient");
            require(amounts[i] > 0, "Invalid amount");
            totalAmount += amounts[i];
        }
        
        require(address(this).balance >= totalAmount, "Insufficient ETH");
        
        for (uint256 i = 0; i < length; i++) {
            isReleased[depositIds[i]] = true;
            payable(recipients[i]).sendValue(amounts[i]);
            emit ReleaseETH(depositIds[i], 0, recipients[i], amounts[i], 0);
        }
        
        batchCounter++;
        lastBatchTime = block.timestamp;
        emit BatchComplete(batchCounter, length, totalAmount);
    }

    // ========== EMERGENCY FUNCTIONS ==========
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
            emit ReleaseERC20(depositIds[i], 0, recipients[i], token, amounts[i], 0);
        }
        
        batchCounter++;
        lastEmergencyTime = block.timestamp;
        emit BatchComplete(batchCounter, length, totalAmount);
    }

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
            emit ReleaseETH(depositIds[i], 0, recipients[i], amounts[i], 0);
        }
        
        batchCounter++;
        lastEmergencyTime = block.timestamp;
        emit BatchComplete(batchCounter, length, totalAmount);
    }

    // ========== EMERGENCY RECOVERY ==========
    function requestEmergencyUnlock() external onlyOwner {
        emergencyUnlockTime = block.timestamp + EMERGENCY_TIMELOCK;
        emit EmergencyUnlockRequested(emergencyUnlockTime);
    }
    
    function cancelEmergencyUnlock() external onlyOwner {
        emergencyUnlockTime = 0;
        emit EmergencyUnlockCancelled();
    }

    function emergencySweepERC20(address token, address to, uint256 amount) 
        external 
        onlyOwner 
        emergencyUnlocked 
    {
        require(to != address(0), "Invalid recipient");
        IERC20(token).safeTransfer(to, amount);
        emit EmergencyWithdrawal(token, to, amount);
        emergencyUnlockTime = 0;
    }

    function emergencySweepETH(address to, uint256 amount) 
        external 
        onlyOwner 
        emergencyUnlocked 
    {
        require(to != address(0), "Invalid recipient");
        require(address(this).balance >= amount, "Insufficient ETH");
        payable(to).sendValue(amount);
        emit EmergencyWithdrawal(address(0), to, amount);
        emergencyUnlockTime = 0;
    }

    // ========== ADMIN FUNCTIONS ==========
    function pauseDeposits() external onlyOwner {
        _pause();
    }
    
    function unpauseDeposits() external onlyOwner {
        _unpause();
    }

    // ========== ESSENTIAL VIEW FUNCTIONS ONLY ==========
    
    /**
     * @notice Check if L2 withdraw has been processed (ESSENTIAL for preventing double-spending)
     */
    function isL2WithdrawProcessed(uint256 l2WithdrawId) external view returns (bool) {
        return isWithdrawProcessed[l2WithdrawId];
    }

    /**
     * @notice Get user's current nonce (ESSENTIAL for front-end integration)
     */
    function getUserNonce(address user) external view returns (uint256) {
        return userNonce[user];
    }

    /**
     * @notice Check if deposit has been released (ESSENTIAL for tracking)
     */
    function checkReleaseStatus(uint256 depositId) external view returns (bool) {
        return isReleased[depositId];
    }

    // ========== FALLBACK ==========
    receive() external payable {
        require(!paused(), "Contract is paused");
        require(msg.value > 0, "Amount must be greater than 0");
        require(
            block.timestamp >= lastDepositTime[msg.sender] + MIN_DEPOSIT_INTERVAL,
            "Deposit too frequent"
        );
        
        uint256 nonce = ++userNonce[msg.sender];
        uint256 depositId = ++depositCounter;
        lastDepositTime[msg.sender] = block.timestamp;
        
        emit DepositETH(depositId, msg.sender, msg.value, nonce, block.timestamp);
    }
}