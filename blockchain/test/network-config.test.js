import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";

const blockchainRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const configImport = "import('./hardhat.config.js')";

function loadConfig(overrides = {}) {
  const env = { ...process.env, ...overrides };
  return spawnSync(process.execPath, ["--input-type=module", "-e", configImport], {
    cwd: blockchainRoot,
    env,
    encoding: "utf8",
  });
}

test("Hardhat network config loads with the default local profile", () => {
  const result = loadConfig({ CHAINGUARD_NETWORK: "hardhat", SEPOLIA_RPC_URL: "", SEPOLIA_PRIVATE_KEY: "" });
  assert.equal(result.status, 0, result.stderr);
});

test("Sepolia config fails clearly when the RPC URL is missing", () => {
  const result = loadConfig({ CHAINGUARD_NETWORK: "sepolia", SEPOLIA_RPC_URL: "", SEPOLIA_PRIVATE_KEY: "" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /SEPOLIA_RPC_URL is not configured/u);
  assert.doesNotMatch(result.stderr, /[0-9a-f]{64}/iu);
});

test("Sepolia config parses with environment credentials without printing them", () => {
  const privateKey = `0x${"11".repeat(32)}`;
  const result = loadConfig({
    CHAINGUARD_NETWORK: "sepolia",
    SEPOLIA_RPC_URL: "https://rpc.example.invalid/secret-marker",
    SEPOLIA_PRIVATE_KEY: privateKey,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.doesNotMatch(result.stdout + result.stderr, /secret-marker/u);
  assert.equal((result.stdout + result.stderr).includes(privateKey), false);
});

test("Sepolia config rejects a malformed key without echoing its value", () => {
  const malformed = "this-is-not-a-key";
  const result = loadConfig({
    CHAINGUARD_NETWORK: "sepolia",
    SEPOLIA_RPC_URL: "https://rpc.example.invalid",
    SEPOLIA_PRIVATE_KEY: malformed,
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /SEPOLIA_PRIVATE_KEY must be a 0x-prefixed/u);
  assert.equal((result.stdout + result.stderr).includes(malformed), false);
});
