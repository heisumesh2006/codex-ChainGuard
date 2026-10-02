# ChainGuard-AI

Blockchain-backed trust and governance for autonomous agents. The finished system has a FastAPI adapter, six core security subsystems, a Solidity registry on local Hardhat, and a React dashboard.

## Repository layout

| Path | Responsibility |
| --- | --- |
| `backend/api/` | FastAPI, WebSocket demo, API tests |
| `backend/core/authorization/` | Agents, permissions, delegation, action log |
| `backend/core/blockchain/` | Web3 anchoring, identities, credentials, proofs |
| `backend/core/tracing/` | Rooted delegation tracing |
| `backend/core/drift_detection/` | Saved Isolation Forest, data, metrics |
| `backend/core/revocation/` | Public verifier, audit, revocation evidence |
| `backend/core/governance/` | Pipeline, canonical deployment, final report |
| `blockchain/` | AgentTrustRegistry Solidity contract and Hardhat tests |
| `frontend/` | React dashboard |

## Start the local stack (Windows PowerShell)

From the repository root, create a fresh environment for a new clone:

```powershell
py -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt
```

Start Hardhat in one terminal:

```powershell
cd blockchain
npm install
npm run compile
npm run node
```

From the repository root, start the API in a second terminal when the saved canonical contract is present on this Hardhat chain:

```powershell
.venv/Scripts/python.exe -m uvicorn backend.api.main:app --host 127.0.0.1 --port 8000
```

Hardhat resets its chain on restart. If the saved deployment is no longer on chain, use the existing disposable demo server instead. It creates a fresh registry without overwriting saved evidence and serves port 8001:

```powershell
.venv/Scripts/python.exe -m backend.api.demo_server
```

Start the frontend in a third terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. The frontend defaults to port 8000; set `VITE_API_BASE_URL=http://127.0.0.1:8001` for the disposable server. See [API notes](backend/api/README.md), [blockchain notes](backend/core/blockchain/README.md), and [architecture](docs/architecture.md).

## Sepolia public test deployment

Hardhat remains the default local development profile (chain ID 31337). For a public demo, configure the separate Ethereum Sepolia profile (chain ID 11155111). Sepolia uses test ETH and is **not Ethereum Mainnet**. Get test ETH for a dedicated root-authorizer wallet from one of the faucets listed by [ethereum.org](https://ethereum.org/developers/docs/networks/) or use the [Alchemy Sepolia faucet](https://www.alchemy.com/faucets/ethereum-sepolia). The Alchemy page currently describes a 0.1 SepoliaETH daily drip; faucet limits can change.

Copy `.env.example` to `.env`, then fill in `SEPOLIA_RPC_URL` and `SEPOLIA_PRIVATE_KEY` locally. Never commit `.env` or paste its values into source control. The private key stays in the API/deployment process and is not returned to the frontend. Compile and deploy explicitly:

```powershell
cd blockchain
npm run compile
$env:CHAINGUARD_NETWORK = "sepolia"
npm run deploy:sepolia
cd ..
.venv/Scripts/python.exe -m backend.core.governance.bootstrap
.venv/Scripts/python.exe -m uvicorn backend.api.main:app --host 127.0.0.1 --port 8000
```

The deployment command verifies chain ID 11155111, waits for two confirmations, and saves only public deployment metadata to `blockchain/deployments/sepolia.json`. The Python bootstrap reuses that contract, replays the current trust evidence into the isolated Sepolia data profile, and leaves the local Hardhat evidence intact. The API and Blockchain Audit page then produce Sepolia Etherscan links for the contract, batch transactions, and blocks. Sepolia deployment is never automatic.

## Verification

From the repository root, compile the backend with `.venv/Scripts/python.exe -m compileall -q backend`. The Hardhat checks are `npm run compile` and `npm run test:contract` from `blockchain/`; the frontend check is `npm run build` from `frontend/`. The Python suites live beside their subsystems in `backend/core/*/tests/` and `backend/api/tests/`.

## Scope and limitations

The four-agent deployment and its behavior dataset are a reproducible prototype. Hardhat is a local Ethereum network, the drift data is synthetic, and evaluation metrics do not establish production performance. Revocation currently decommissions a full agent rather than selecting individual permissions. Historical saved deployment files refer to the chain on which they were created; use the disposable demo API after a Hardhat restart.
