require("dotenv").config();
require("@nomicfoundation/hardhat-toolbox");
require("hardhat-gas-reporter");

module.exports = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200
      },
      viaIR: true
    }
  },
  networks: {
    hardhat: {
      allowUnlimitedContractSize: true
    }
  },
  gasReporter: {
    enabled: true,
    currency: 'USD',
    token: 'BNB',
    coinmarketcap: process.env.CMC_API_KEY,
    gasPrice: 3, // dalam satuan gwei, semua diambil dari rata-rata. misal 30 gwei untuk ETH, 3 gwei untuk BNB, 30 untuk MATIC
  },
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts"
  },
  etherscan: {
    apiKey: process.env.ETHERSCAN_API_KEY
  }
};