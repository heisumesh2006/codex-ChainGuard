import { defineConfig } from "hardhat/config";
import { loadProjectEnv } from "./scripts/load-env.js";

loadProjectEnv();

const selectedNetwork = (process.env.CHAINGUARD_NETWORK ?? "hardhat").toLowerCase();
if (!new Set(["hardhat", "sepolia"]).has(selectedNetwork)) {
  throw new Error("CHAINGUARD_NETWORK must be either 'hardhat' or 'sepolia'");
}

const networks = {
  localhost: {
    type: "http",
    chainType: "l1",
    url: "http://127.0.0.1:8545",
  },
};

if (selectedNetwork === "sepolia") {
  if (!process.env.SEPOLIA_RPC_URL) {
    throw new Error("SEPOLIA_RPC_URL is not configured");
  }
  if (!process.env.SEPOLIA_PRIVATE_KEY) {
    throw new Error("SEPOLIA_PRIVATE_KEY is not configured");
  }
  if (!/^0x[0-9a-fA-F]{64}$/u.test(process.env.SEPOLIA_PRIVATE_KEY)) {
    throw new Error("SEPOLIA_PRIVATE_KEY must be a 0x-prefixed 32-byte hexadecimal key");
  }
  networks.sepolia = {
    type: "http",
    chainType: "l1",
    url: process.env.SEPOLIA_RPC_URL,
    accounts: [process.env.SEPOLIA_PRIVATE_KEY],
  };
}

export default defineConfig({
  solidity: {
    version: "0.8.28",
    settings: { optimizer: { enabled: true, runs: 200 } },
  },
  networks,
});
