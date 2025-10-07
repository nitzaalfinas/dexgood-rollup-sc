require('dotenv').config();
require('@nomicfoundation/hardhat-toolbox');

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.20",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  networks: {
    hardhat: {
      chainId: 1337,
    },
    // L1 Testnet (Sepolia)
    sepolia: {
      url: process.env.SEPOLIA_RPC_URL || 'https://ethereum-sepolia-rpc.publicnode.com',
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
      chainId: 11155111,
      gasPrice: 20000000000, // 20 gwei
      gas: 6000000,
      timeout: 60000,
      confirmations: 2,
    },
    // L2 Testnet (Dexgood)
    dexgood: {
      url: process.env.DEXGOOD_RPC_URL || 'https://testnet-scan.dexgood.com/rpc',
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
      chainId: 98765432103,
      gasPrice: 1000000000, // 1 gwei
      gas: 10000000,
      timeout: 60000,
      confirmations: 1,
    },
    // L1 Mainnet (Future)
    ethereum: {
      url: process.env.ETHEREUM_RPC_URL || '',
      accounts: process.env.MAINNET_PRIVATE_KEY ? [process.env.MAINNET_PRIVATE_KEY] : [],
      chainId: 1,
      gasPrice: 'auto',
      gas: 'auto',
    },
    // L2 Mainnet (Future)
    dexgoodMainnet: {
      url: process.env.DEXGOOD_MAINNET_RPC_URL || '',
      accounts: process.env.MAINNET_PRIVATE_KEY ? [process.env.MAINNET_PRIVATE_KEY] : [],
      chainId: 0, // Will be updated when mainnet launches
      gasPrice: 'auto',
      gas: 'auto',
    },
  },
  gasReporter: {
    enabled: process.env.REPORT_GAS === 'true',
    currency: 'USD',
    gasPrice: 20,
    coinmarketcap: process.env.COINMARKETCAP_API_KEY,
  },
  etherscan: {
    apiKey: {
      sepolia: process.env.ETHERSCAN_API_KEY || "",
      mainnet: process.env.ETHERSCAN_API_KEY || "",
    },
  },
  mocha: {
    timeout: 300000, // 5 minutes
  },
};