# ChainGuard-AI

Blockchain-backed trust and governance for autonomous agents. The system has a FastAPI adapter, six core security subsystems, a Solidity registry used on local Hardhat and Ethereum Sepolia, and a React dashboard.

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

## Public Ethereum Sepolia Demo

The verified public demo uses the **existing** `AgentTrustRegistry` deployment on Ethereum Sepolia (chain ID `11155111`), not Ethereum Mainnet. Viewing this demo does not require another deployment.

| Public evidence | Value |
| --- | --- |
| Registry | [0x61c74D0525f4f5A1a7b20f2eA561e485E71dd243](https://sepolia.etherscan.io/address/0x61c74D0525f4f5A1a7b20f2eA561e485E71dd243) |
| Deployment | [Transaction](https://sepolia.etherscan.io/tx/0xf5660aab74ae2ca7da6aea1f6c5895c3816517f64450ef37aa986df8b703e460) · [block 11830349](https://sepolia.etherscan.io/block/11830349) |
| Audit batch | `batch:0xee6028db0fb103cc0c5e1685e586b24d9213515a806aa9717f3ed0b54341006c` |
| Merkle root | `0xee6028db0fb103cc0c5e1685e586b24d9213515a806aa9717f3ed0b54341006c` |
| Batch anchor | [Transaction](https://sepolia.etherscan.io/tx/0xae52c353001ff8754625054d8873eeda0b74b1702af775da3e6a4cd4d33b75c2) · [block 11834006](https://sepolia.etherscan.io/block/11834006) |

The hybrid trust model sends **critical authority events** (agent registration, credential issuance, delegation, and revocation) to the contract immediately. During this controlled run, trust setup accounted for 5 registration, 5 credential, 2 delegation, and 1 revocation transactions. These 13 transactions are separate from ordinary action auditing and from the earlier deployment transaction.

For **ordinary governed actions**, the governance pipeline writes complete `AuditRecord`s to an append-only off-chain JSONL store. Canonical record bytes are hashed with Ethereum Keccak-256; the ordered hashes form a Merkle tree, and only its root and compact batch metadata go on-chain. The observed run produced **5 actions → 5 off-chain AuditRecords → 1 Merkle root → 1 Sepolia batch-root transaction**, with **0 legacy per-action audit commitments** for those actions. Legacy individual action commitments remain in the historical bootstrap compatibility path.

| Governed scenario | Verdict |
| --- | --- |
| Normal | ALLOW |
| Self Escalation | BLOCK |
| Unauthorized Delegation | BLOCK |
| Scope Creep | REVIEW |
| Post-Decommission | BLOCK |

The scope-creep audit action `audit:d1eb93fcc6b6452bb5a92b7bcd7bb728` verified from its canonical Keccak-256 leaf through a Merkle inclusion proof to the root read from the Sepolia registry. The original record returned **VERIFIED**; changing a copy in memory returned **TAMPERED** without modifying stored evidence. The chain proves the batch commitment; an individual action proof also needs its off-chain record and Merkle siblings.

### View the existing demo without sending transactions

Install the Python requirements and frontend packages as described above, and compile the contract to make its ABI available (`cd blockchain; npm run compile`). Configure the environment variable names `CHAINGUARD_NETWORK` (select `sepolia`) and `SEPOLIA_RPC_URL` in your ignored local environment. A private key is **not required for read-only status and proof checks**; it is required only for transactions. To view the recorded action proofs in the dashboard, keep the existing Sepolia runtime deployment files under `backend/core/blockchain/data/sepolia/` and `backend/core/governance/data/sepolia/`, plus the off-chain audit and batch files under the latter directory. These runtime files are ignored by Git. A fresh clone can inspect the public registry and batch transaction through the links above, but cannot reconstruct an individual AuditRecord proof without that off-chain evidence.

From the repository root, start the API, then start the frontend in another terminal:

```powershell
.venv/Scripts/python.exe -m uvicorn backend.api.main:app --host 127.0.0.1 --port 8000
```

```powershell
cd frontend
npm run dev
```

Open `http://localhost:5173/blockchain-audit`. The frontend's `VITE_API_BASE_URL`, if set locally, must point to the API on port 8000. The page shows the batch and lets you verify the action ID above; `/api/audit/status` exposes the current network and contract status. These viewing steps do not run governance scenarios or submit transactions.

## Sepolia deployment tooling (operator-only)

Hardhat remains the default local development profile (chain ID 31337). The commands below are for deployment/bootstrap operators, **not** for viewing the verified demo. With the committed `blockchain/deployments/sepolia.json` manifest and live contract, `npm run deploy:sepolia` detects and reports the existing deployment; it does not redeploy. If that manifest is absent on a separate installation, the command can deploy a new registry. The Python bootstrap can then send trust and historical individual action-hash transactions, and refuses to overwrite existing canonical runtime state. Sepolia uses test ETH and is **not Ethereum Mainnet**. Get test ETH for a dedicated root-authorizer wallet from one of the faucets listed by [ethereum.org](https://ethereum.org/developers/docs/networks/) or use the [Alchemy Sepolia faucet](https://www.alchemy.com/faucets/ethereum-sepolia). The Alchemy page currently describes a 0.1 SepoliaETH daily drip; faucet limits can change.

For operator actions, copy `.env.example` to `.env`, then fill in `SEPOLIA_RPC_URL` and `SEPOLIA_PRIVATE_KEY` locally. Never commit `.env` or paste its values into source control. The private key stays in the API/deployment process and is not returned to the frontend. The explicit operator commands are:

```powershell
cd blockchain
npm run compile
$env:CHAINGUARD_NETWORK = "sepolia"
npm run deploy:sepolia
cd ..
.venv/Scripts/python.exe -m backend.core.governance.bootstrap
.venv/Scripts/python.exe -m uvicorn backend.api.main:app --host 127.0.0.1 --port 8000
```

The deployment command verifies chain ID 11155111, waits for two confirmations, and saves only public deployment metadata to `blockchain/deployments/sepolia.json`. The Python bootstrap reuses that contract, replays trust evidence (including historical individual action-hash commitments) into the isolated Sepolia data profile, and leaves the local Hardhat evidence intact. The API and Blockchain Audit page then produce Sepolia Etherscan links for the contract, batch transactions, and blocks. Sepolia deployment is never automatic.

## Verification

From the repository root, compile the backend with `.venv/Scripts/python.exe -m compileall -q backend`. The Hardhat checks are `npm run compile` and `npm run test:contract` from `blockchain/`; the frontend check is `npm run build` from `frontend/`. The Python suites live beside their subsystems in `backend/core/*/tests/` and `backend/api/tests/`.

## Scope and limitations

The four-agent deployment and its behavior dataset are a reproducible prototype. Hardhat is a local Ethereum network, the drift data is synthetic, and evaluation metrics do not establish production performance. Revocation currently decommissions a full agent rather than selecting individual permissions. Historical saved deployment files refer to the chain on which they were created; use the disposable demo API after a Hardhat restart.
