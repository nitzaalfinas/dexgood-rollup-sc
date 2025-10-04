// Helper functions for ExchangeNewOptimized tests
const { ethers } = require("hardhat");


async function deployMyCustomDecimalsToken(initialSupply, decimals) {
    const MyCustomDecimalsToken = await ethers.getContractFactory("MyCustomDecimalsToken");
    const token = await MyCustomDecimalsToken.deploy(initialSupply, decimals);
    await token.waitForDeployment();
    return token;
}

module.exports = {
    deployMyCustomDecimalsToken
};