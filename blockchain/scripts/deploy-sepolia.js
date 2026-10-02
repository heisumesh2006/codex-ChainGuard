import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ContractFactory, JsonRpcProvider, Wallet, formatEther } from "ethers";
import { loadProjectEnv } from "./load-env.js";

loadProjectEnv();

const EXPECTED_CHAIN_ID = 11155111n;
const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const artifactPath = path.join(projectRoot, "blockchain", "artifacts", "contracts", "AgentTrustRegistry.sol", "AgentTrustRegistry.json");
const metadataPath = path.join(projectRoot, "blockchain", "deployments", "sepolia.json");

function requiredEnv(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is not configured`);
  return value;
}

function printMetadata(metadata, existing = false) {
  console.log(`Network: Ethereum Sepolia${existing ? " (existing deployment)" : ""}`);
  console.log(`Chain ID: ${metadata.chain_id}`);
  console.log(`Contract address: ${metadata.contract_address}`);
  console.log(`Deployment transaction hash: ${metadata.deployment_tx_hash}`);
  console.log(`Block number: ${metadata.deployment_block}`);
  console.log(`Deployed at: ${metadata.deployed_at}`);
}

async function main() {
  const network = (process.env.CHAINGUARD_NETWORK ?? "").trim().toLowerCase();
  if (network !== "sepolia") throw new Error("Set CHAINGUARD_NETWORK=sepolia explicitly before deployment");
  const rpcUrl = requiredEnv("SEPOLIA_RPC_URL");
  const privateKey = requiredEnv("SEPOLIA_PRIVATE_KEY");
  if (!/^0x[0-9a-fA-F]{64}$/u.test(privateKey)) {
    throw new Error("SEPOLIA_PRIVATE_KEY must be a 0x-prefixed 32-byte hexadecimal key");
  }
  const provider = new JsonRpcProvider(rpcUrl);
  const chainId = (await provider.getNetwork()).chainId;
  if (chainId !== EXPECTED_CHAIN_ID) {
    throw new Error(`Sepolia chain ID mismatch: expected 11155111, received ${chainId}`);
  }

  try {
    const existing = JSON.parse(await readFile(metadataPath, "utf8"));
    if (existing.chain_id === Number(EXPECTED_CHAIN_ID) && (await provider.getCode(existing.contract_address)) !== "0x") {
      printMetadata(existing, true);
      return;
    }
    throw new Error("Existing Sepolia deployment metadata is stale; archive it before deploying again");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }

  const wallet = new Wallet(privateKey, provider);
  const balance = await provider.getBalance(wallet.address);
  if (balance === 0n) throw new Error("Root wallet has no Sepolia test ETH; fund it from a Sepolia faucet first");
  const artifact = JSON.parse(await readFile(artifactPath, "utf8"));
  const factory = new ContractFactory(artifact.abi, artifact.bytecode, wallet);
  const deploymentTransaction = await factory.getDeployTransaction();
  const gasLimit = await provider.estimateGas({ ...deploymentTransaction, from: wallet.address });
  const feeData = await provider.getFeeData();
  const feePerGas = feeData.maxFeePerGas ?? feeData.gasPrice;
  if (feePerGas === null) throw new Error("Could not estimate Sepolia transaction fees");
  const estimatedCost = gasLimit * feePerGas;
  if (balance < estimatedCost) {
    throw new Error(`Insufficient Sepolia test ETH for estimated deployment gas (balance ${formatEther(balance)} ETH)`);
  }

  const contract = await factory.deploy({ gasLimit });
  const transactionHash = contract.deploymentTransaction().hash;
  const receipt = await contract.deploymentTransaction().wait(2, 120_000);
  if (!receipt || receipt.status !== 1 || !receipt.contractAddress) {
    throw new Error("Sepolia deployment did not receive a successful confirmation");
  }
  const block = await provider.getBlock(receipt.blockNumber);
  const metadata = {
    network: "Ethereum Sepolia",
    chain_id: Number(EXPECTED_CHAIN_ID),
    contract_address: receipt.contractAddress,
    deployment_tx_hash: transactionHash,
    deployment_block: receipt.blockNumber,
    deployed_at: new Date(Number(block.timestamp) * 1000).toISOString(),
    root_authorizer: wallet.address,
  };
  const registry = await contract.getAddress();
  if ((await provider.getCode(registry)) === "0x") throw new Error("No contract code found after Sepolia deployment");
  await mkdir(path.dirname(metadataPath), { recursive: true });
  await writeFile(metadataPath, `${JSON.stringify(metadata, null, 2)}\n`, { encoding: "utf8", flag: "wx" });
  printMetadata(metadata);
}

main().catch((error) => {
  const message = String(error?.message ?? "");
  const safeMessage = /SEPOLIA_|CHAINGUARD_NETWORK|chain ID mismatch|test ETH|insufficient Sepolia/iu.test(message)
    ? message
    : /timeout|timed out/iu.test(message)
      ? "Sepolia transaction confirmation timed out; check transaction status before retrying."
      : "Deployment failed; check Sepolia RPC availability, wallet balance, and deployment metadata.";
  console.error(`Sepolia deployment failed: ${safeMessage}`);
  process.exitCode = 1;
});
