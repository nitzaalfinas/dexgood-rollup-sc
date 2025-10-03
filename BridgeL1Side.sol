// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract BridgeL1Side {
    address public admin;
    uint256 public depositCounter;

    event DepositERC20(uint256 indexed depositId, address indexed user, address indexed token, uint256 amount, uint256 timestamp);
    event DepositETH(uint256 indexed depositId, address indexed user, uint256 amount, uint256 timestamp);
    event ReleaseERC20(uint256 indexed depositId, address indexed to, address indexed token, uint256 amount, uint256 timestamp);
    event ReleaseETH(uint256 indexed depositId, address indexed to, uint256 amount, uint256 timestamp);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    // Deposit ERC20 token
    function depositERC20(address token, uint256 amount) external {
        require(IERC20(token).transferFrom(msg.sender, address(this), amount), "Transfer failed");
        depositCounter++;
        emit DepositERC20(depositCounter, msg.sender, token, amount, block.timestamp);
    }

    // Deposit native ETH
    function depositETH() external payable {
        require(msg.value > 0, "No ETH sent");
        depositCounter++;
        emit DepositETH(depositCounter, msg.sender, msg.value, block.timestamp);
    }

    // Release ERC20 token (admin only)
    function releaseERC20(uint256 depositId, address token, address to, uint256 amount) external onlyAdmin {
        require(IERC20(token).transfer(to, amount), "Transfer failed");
        emit ReleaseERC20(depositId, to, token, amount, block.timestamp);
    }

    // Release native ETH (admin only)
    function releaseETH(uint256 depositId, address to, uint256 amount) external onlyAdmin {
        require(address(this).balance >= amount, "Insufficient ETH");
        (bool sent, ) = to.call{value: amount}("");
        require(sent, "ETH transfer failed");
        emit ReleaseETH(depositId, to, amount, block.timestamp);
    }

    // Batch release ERC20 tokens (admin only)
    function batchReleaseERC20(address token, address[] calldata recipients, uint256[] calldata amounts, uint256[] calldata depositIds) external onlyAdmin {
        require(recipients.length == amounts.length && recipients.length == depositIds.length, "Length mismatch");
        for (uint256 i = 0; i < recipients.length; i++) {
            require(IERC20(token).transfer(recipients[i], amounts[i]), "Transfer failed");
            emit ReleaseERC20(depositIds[i], recipients[i], token, amounts[i], block.timestamp);
        }
    }

    // Batch release native ETH (admin only)
    function batchReleaseETH(address[] calldata recipients, uint256[] calldata amounts, uint256[] calldata depositIds) external onlyAdmin {
        require(recipients.length == amounts.length && recipients.length == depositIds.length, "Length mismatch");
        for (uint256 i = 0; i < recipients.length; i++) {
            require(address(this).balance >= amounts[i], "Insufficient ETH");
            (bool sent, ) = recipients[i].call{value: amounts[i]}("");
            require(sent, "ETH transfer failed");
            emit ReleaseETH(depositIds[i], recipients[i], amounts[i], block.timestamp);
        }
    }
}