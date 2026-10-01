import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const port = Number(process.env.CHAINGUARD_HARDHAT_PORT ?? "8545");
const hardhatCli = fileURLToPath(new URL("../node_modules/hardhat/dist/src/cli.js", import.meta.url));
const child = spawn(
  process.execPath,
  [hardhatCli, "node", "--hostname", "127.0.0.1", "--port", String(port)],
  { stdio: "ignore", cwd: fileURLToPath(new URL("..", import.meta.url)) },
);

const stop = () => child.kill("SIGTERM");
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
child.on("exit", (code) => process.exit(code ?? 1));

let connected = false;
for (let attempt = 0; attempt < 300 && !connected; attempt++) {
  if (child.exitCode !== null) break;
  try {
    const response = await fetch(`http://127.0.0.1:${port}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] }),
    });
    connected = response.ok;
  } catch {
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}
if (!connected) {
  stop();
  throw new Error("Hardhat node did not become ready");
}
console.log(`Hardhat JSON-RPC ready at http://127.0.0.1:${port}`);
await new Promise(() => {});
