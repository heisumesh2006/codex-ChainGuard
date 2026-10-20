# ChainGuard-AI
## Blockchain-Anchored Trust and Delegation Framework for Autonomous AI Agents

**ChainGuard-AI checks an agent's identity, permissions, delegated authority, unusual behavior and recorded audit evidence.** It combines cryptographically signed requests, scope-bound delegation, cascading revocation, Isolation Forest anomaly detection and Ethereum-compatible Merkle-batched commitments.

An autonomous agent is software that can choose and perform operations rather than only answer questions. In an online shop, a coordinator can delegate order creation to a purchasing agent. A payment agent must not gain administrator rights by claiming to be the coordinator. ChainGuard evaluates such operations, returns **ALLOW**, **REVIEW** or **BLOCK**, and records evidence that can later be checked against an anchored commitment.

This is an implemented engineering and research prototype with a supported **disposable local Hardhat demonstration**. It is not a production identity provider or a guarantee of perfect security.

**New user:** follow [Quick start](#quick-start--run-chainguard-ai-locally).

**Student/developer:** read the [complete technical handbook](docs/COMPLETE_PROJECT_EXPLANATION.md) for algorithms, source navigation, worked examples, experiments and viva preparation.

## Contents

1. [Features and six modules](#1-features-and-six-modules)
2. [Technology stack](#2-technology-stack)
3. [Requirements](#3-requirements)
4. [Clone](#4-clone-the-repository)
5. [Quick start: three terminals](#quick-start--run-chainguard-ai-locally)
6. [Backend modes](#5-backend-installation-and-startup-modes)
7. [Blockchain lifecycle](#6-blockchain-lifecycle)
8. [Frontend](#7-frontend-configuration)
9. [Nine-page walkthrough](#8-local-demo-walkthrough)
10. [Signed requests](#9-signed-request-demonstration)
11. [Audit demonstration](#10-blockchain-audit-demonstration)
12. [Sepolia](#11-public-sepolia-mode)
13. [Tests](#12-testing)
14. [Troubleshooting](#13-troubleshooting)
15. [Structure](#14-project-structure)
16. [Research and limitations](#15-research-limitations-and-references)
17. [Validation record](#16-documentation-validation)

## 1. Features and six modules

| Module | Actual functionality | Purpose |
|---|---|---|
| Authorization | Registered identities; EIP-191 operation/payload signatures; persistent nonces; scoped root/delegated grants and expiry | A privileged name is not identity, and identity is not permission |
| Blockchain trust registry | Root-controlled identity, credential, delegation, revocation and batch commitments; receipt/event verification | Separately queryable trust and audit evidence |
| Delegation tracing | Required credential, issuer, scope and time checks; multi-hop paths, alternatives and cycle rejection | Explains where authority came from |
| Policy drift detection | Saved normal-trained Isolation Forest with four categorical and ten numeric features | Flags unusual behavior within nominal permissions |
| Revocation | Full-agent decommissioning and downstream grant invalidation, preserving independent valid paths | Stops authority derived from revoked grants |
| Governance | Mandatory authority/evidence checks combined with anomaly signals | Explainable ALLOW, REVIEW or BLOCK decisions |

Supporting features include canonical Keccak-256 hashing, ordered Merkle proofs, deterministic batch sealing, durable anchor claims, bounded transaction recovery, cross-process file coordination, safe provider diagnostics, REST/WebSocket APIs, nine dashboard pages and five scenarios.

**Deployment boundary:** `AgentTrustRegistry.sol` is used locally and in existing Sepolia evidence. The optional `GrantAuthority.sol` ancestry extension has been tested on isolated **local Hardhat only**. It is not deployed on public Sepolia, and the normal demo does not automatically deploy it. Current Python signed-grant/cascading enforcement is not a retroactive upgrade of historical public evidence.

## 2. Technology stack

Versions distinguish declared ranges from observed installations. Python dependencies are not fully frozen.

| Technology | Purpose | Verified declaration/version |
|---|---|---|
| Python | Backend, policy, inference, experiments | Tested 3.14.0 |
| FastAPI / Pydantic | REST and validation | FastAPI `>=0.115,<1`; validation 0.150.0 / Pydantic 2.14.1 |
| Uvicorn | HTTP/WebSocket server | `>=0.30,<1`; validation 0.54.0 |
| HTTPX / unittest | API tests / regressions | HTTPX `>=0.27,<1`, validation 0.28.1; unittest is standard library |
| Web3.py | RPC, contracts, receipts, hashes | `>=7,<9`; validation 8.0.0 |
| eth-account | EIP-191 signing/recovery | Transitive Web3 dependency; validation 0.14.0 |
| Keccak-256 / Merkle trees | Canonical commitments and inclusion proofs | Web3 Keccak plus project code; not NIST SHA3-256 |
| scikit-learn / joblib | Isolation Forest and saved model | `>=1.9,<2` / `>=1.6,<2`; validation 1.9.1 / 1.6.0 |
| NumPy / SciPy | Numerical processing | Transitive; validation 2.5.4 / 1.18.1 |
| React / JavaScript | Dashboard | React lockfile 19.3.0; ES modules |
| Vite | Development server/build | Lockfile 6.4.3 |
| React Router | Navigation | Lockfile 7.18.4 |
| React Flow / Recharts | Trust graph / charts | Lockfile 11.11.4 / 2.15.4 |
| Framer Motion / Lucide / Tailwind CSS | Transitions / icons / styles | Declared major versions 12 / 0.460 / 4 |
| Solidity / Hardhat | Contracts / local chain | solc 0.8.28, optimizer 200 runs; Hardhat lockfile 3.18.0 |
| ethers / Node test runner | Contract tests | ethers lockfile 6.17.0; Node built-in runner |
| Playwright | Browser regression | Lockfile 1.64.0; supplied configs select Microsoft Edge |
| JSON / JSONL files | Durable policy, nonce, audit and batch storage | No SQL database, MongoDB or Redis required |
| matplotlib | Optional research figures | Separate research requirements; not normal startup |

Sources: [root requirements](requirements.txt), [API requirements](backend/api/requirements.txt), [blockchain requirements](backend/core/blockchain/requirements.txt), [ML requirements](backend/core/drift_detection/requirements.txt), [frontend package](frontend/package.json), [blockchain package](blockchain/package.json), and npm lockfiles.

## 3. Requirements

Install Git, Python 3.14 with pip/Windows launcher, Node.js with npm, and a modern browser. VS Code is optional. The observed environment is **Windows 11 build 26200, Python 3.14.0, Node 24.15.0, npm 11.12.1**. Older combinations are not established by this guide.

```powershell
git --version
py -3.14 --version
py -3.14 -m pip --version
node --version
npm --version
```

The research host had 12 logical CPUs. This is an observed environment, **not a minimum hardware specification**. Minimum RAM, disk and processor requirements were not measured. Allow space for a virtual environment, two npm dependency directories and optional browser tools.

Use a writable local checkout and a writable operating-system temporary directory. Read-only folders, restricted automation sandboxes and unsupported network filesystems can prevent compilation, signer fixtures or atomic state publication.

Installation needs Internet access. The local demo needs no public RPC subscription, funded wallet or private Sepolia key. Chrome/Edge run the application; supplied automated browser configs select installed Microsoft Edge. POSIX locking exists, but the complete macOS/Linux installation has not been independently validated.

## 4. Clone the repository

In the parent directory where you want the download:

```powershell
git clone https://github.com/heisumesh2006/codex-ChainGuard.git
cd codex-ChainGuard
git branch --show-current
git rev-parse HEAD
```

Git creates `codex-ChainGuard`. Root commands below run inside it. Optional:

```powershell
code .
```

Open VS Code's **Terminal → New Terminal**, or PowerShell in that folder. A clone includes the model and historical research evidence, but not installed packages, `.env`, ignored Sepolia runtime files, a running node or a currently valid local deployment.

## QUICK START — RUN CHAINGUARD-AI LOCALLY

Follow this sequence. Keep the three service terminals open. Each new terminal begins at the **same cloned repository root**.

### One-time installation

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip check
```

If activation is blocked:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
```

The policy change lasts only for that PowerShell process. You can instead use the explicit `.venv` interpreter without activation.

```powershell
cd blockchain
npm ci
cd ..\frontend
npm ci
cd ..
```

**Do not copy `.env.example` for this quick start:** it selects Sepolia. Explicit local variables below are sufficient.

### Terminal 1 — local blockchain

From the clone root:

```powershell
cd blockchain
$env:CHAINGUARD_NETWORK = "hardhat"
npm run compile
npm run node
```

Expect `Hardhat JSON-RPC ready at http://127.0.0.1:8545`. Keep it running. The wrapper suppresses development-key listings. Chain **31337** is local Hardhat, not Sepolia.

### Terminal 2 — initialize demo and start FastAPI

From the clone root:

```powershell
$env:CHAINGUARD_NETWORK = "hardhat"
$env:CHAINGUARD_RPC_URL = "http://127.0.0.1:8545"
.\.venv\Scripts\python.exe -m backend.api.demo_server
```

**Use `demo_server` for a fresh clone/fresh chain.** It checks chain 31337, creates unique ignored temporary evidence, deploys a current registry, registers demo identities, provisions signed policy, evaluates five fixtures and anchors their batch. Tracked historical evidence remains untouched.

Wait for `Application startup complete` and `Uvicorn running on http://127.0.0.1:8001`. Earlier output includes public addresses, credential references and Module 2 completion. Real **local** transactions occur during initialization. One validation observed about 41 seconds for the printed Module 2 anchoring portion; this is not a guaranteed total startup time.

### Terminal 3 — React frontend

From the clone root:

```powershell
cd frontend
$env:VITE_API_BASE_URL = "http://127.0.0.1:8001"
npm run dev
```

Open **http://localhost:5173**. Use `localhost`: FastAPI's default browser origin is `http://localhost:5173`, not arbitrary equivalent IPs or ports.

If Vite chooses a different port because 5173 is occupied, resolve the conflict. An alternate origin is not automatically CORS-enabled.

### Verify readiness

From another terminal:

```powershell
Invoke-RestMethod http://127.0.0.1:8001/api/health
Invoke-RestMethod http://127.0.0.1:8001/api/audit/status
Invoke-RestMethod http://127.0.0.1:8001/api/audit/batches
```

Meaningful health fields should include:

```json
{
  "api_online": true,
  "rpc_connected": true,
  "chain_id": 31337,
  "network_name": "Hardhat Local",
  "contract_available": true,
  "ml_model_available": true,
  "status": "ONLINE"
}
```

Additional address/block fields vary. Initially the demo provides five AuditRecords in one anchored batch. A listening port alone does not prove readiness.

### Stop and restart

Stop frontend/backend with **Ctrl+C**, then Hardhat. Normal demo shutdown removes only its own temporary directory. Do not delete canonical records, lock files or nonce history to stop a service.

Next time skip installation unless dependencies changed. Start node, demo API, then frontend. If Hardhat restarts, restart the demo backend too: previous local deployment addresses may no longer have code. Each demo invocation creates new disposable evidence.

## 5. Backend installation and startup modes

The venv isolates project packages. Root requirements include API, blockchain and ML requirements. `requirements-research.txt` is optional plotting support.

```powershell
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -c "import fastapi,uvicorn,web3,eth_account,sklearn,joblib; print('Backend imports OK')"
```

| Entry point | Use | Important difference |
|---|---|---|
| `python -m backend.api.demo_server` | Fresh local presentation | Initializes disposable contracts/evidence; local-only guard; fixed API 8001 |
| `python -m uvicorn backend.api.main:app --host 127.0.0.1 --port 8000` | Already provisioned evidence realm | Does not perform full fresh-demo bootstrap |
| Individual module/research CLIs | Development/evaluation | Some dated scenarios require valid signed/time-aligned fixtures |

Do not substitute the normal API against stale tracked deployment addresses. `/docs` and `/redoc` on the active API expose real schemas.

POSIX equivalents, **not fully validated here**:

```bash
python3.14 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
# Backend terminal after starting Hardhat separately:
export CHAINGUARD_NETWORK=hardhat
export CHAINGUARD_RPC_URL=http://127.0.0.1:8545
python -m backend.api.demo_server
# Frontend terminal inside frontend/:
export VITE_API_BASE_URL=http://127.0.0.1:8001
npm run dev
```

## 6. Blockchain lifecycle

Hardhat is a disposable Ethereum-compatible development chain. Compile both contracts with `npm run compile`, start RPC with `npm run node`, and initialize application data through `demo_server`. No public account is needed.

The backend discovers the running registry through its deployment manifest and checks chain ID, bytecode, root and receipt context. The demo selects its temporary paths across modules, avoiding historical addresses.

`AgentTrustRegistry` stores trust commitments and audit roots. Ordinary governance records remain off-chain and are batched. Bootstrap also exercises **legacy individual action commitments** for compatibility; this is not one transaction per ordinary audit record.

`GrantAuthority` provides immutable parent-grant/transitive queries for optional local tests. The standard demo needs no separate extension deployment. Never run public deployment scripts to repair a local error.

For isolated nodes the wrapper supports `CHAINGUARD_HARDHAT_PORT`, paired with backend `CHAINGUARD_RPC_URL`. Chain ID remains 31337. The demo API port is fixed in its entry point. Preserve healthy existing services rather than resetting their chains.

## 7. Frontend configuration

`frontend/src/services/api.js` uses **`VITE_API_BASE_URL`**, with fallback 8000. The demo uses **8001**, so set the variable before Vite starts. No existing environment file is required. Optional ignored `frontend/.env.local` can hold the public loopback setting.

Never put private keys in `VITE_` variables: they are browser-visible. WebSocket URL is derived from the API base by changing HTTP to WS for `/ws/governance`; no separate WebSocket variable is required.

```powershell
# In frontend/, with API variable already set:
npm run build
npm run preview
```

Build creates ignored `dist/`. Preview defaults to localhost:4173, outside the API's default CORS origin. A successful bundle does not configure arbitrary hosting origins. Use the dev origin for the standard demo.

## 8. Local demo walkthrough

| Page / route | Main controls | Meaning |
|---|---|---|
| Dashboard `/` | Health/counts, navigation cards | Backend-derived selected-network evidence; model metrics are historical synthetic evaluation |
| Agents `/agents` | Expand details/credentials | Identity, role, scopes, effective permissions and status |
| Trust Graph `/trust-graph` | Nodes/edges/proof buttons, trace, zoom/pan/fit | Provenance, historical/current validity and revoked edges |
| Live Governance `/governance` | Scenario buttons, Auto demo, Pause/Resume/Next/Restart, signed JSON form | Saved replay versus fresh signed evaluation |
| Threat Lab `/threat-lab` | Scenario cards and pipeline navigation | Explains each case |
| ML Analytics `/analytics` | Metrics/features/category charts | Saved held-out model results, not retraining/live accuracy |
| Revocation `/revocation` | Agent lookup and proof details | Read-only status/time/reason |
| Evaluation `/evaluation` | Verdict filters/comparisons | Selected-profile decisions and labelled historic model results |
| Blockchain Audit `/blockchain-audit` | Records/batches, proof viewer, verification/copy controls | Real record-to-root verification and temporary-copy simulation |

| Scenario | Expected saved outcome | Reason |
|---|---|---|
| NORMAL | ALLOW | Valid authority/evidence, no significant drift |
| SELF_ESCALATION | BLOCK | Agent attempts authority it lacks |
| UNAUTHORIZED_DELEGATION | BLOCK | Delegator lacks required authority |
| SCOPE_CREEP | REVIEW | Valid authority but unusual behavior |
| POST_DECOMMISSION | BLOCK | Activity after decommissioning/revocation |

Use this order for Auto Demo/presentation. API IDs are lowercase, e.g. `normal`, `post_decommission`.

Saved replay rechecks audit evidence and presents the saved decision. It does not consume a fresh caller signature, append another audit record or recreate historical timings. Stage animations present returned evidence; they are not live instrumentation callbacks inside each module. Missing timings remain unavailable.

## 9. Signed request demonstration

### Why signatures are needed

Submitting `"actor": "ROOT_AUTHORIZER"` is not authentication. The backend recovers an EIP-191 signer and compares it with the registry identity. The message binds protocol, deployment domain, actor, operation, canonical payload SHA-256 digest, nonce and validity window. Nonces are consumed durably under a process lock.

The browser accepts **externally signed action JSON and authentication JSON**, not private keys. There is no unprotected HTTP signing endpoint or public self-registration API. Administration uses operator/Python/contract functions.

### Generate one local envelope

Run this from the clone root while the demo is running. It finds the live temporary deployment by matching the API contract address and calls the existing CLI-only `operator_credentials` helper. It does not embed or print a private key.

```powershell
$env:CHAINGUARD_NETWORK = "hardhat"
$env:CHAINGUARD_RPC_URL = "http://127.0.0.1:8545"
$env:CHAINGUARD_DEMO_API = "http://127.0.0.1:8001"
@'
import json, os
from pathlib import Path
from datetime import datetime, timezone
from urllib.request import urlopen
from contextlib import ExitStack
from unittest.mock import patch
from backend.api.schemas import ActionInput
from backend.core.blockchain import chain
from backend.core.authorization.operator_signing import operator_credentials

health = json.load(urlopen(os.environ["CHAINGUARD_DEMO_API"] + "/api/health"))
assert health["chain_id"] == 31337 and health["contract_available"]
live_batches = json.load(urlopen(os.environ["CHAINGUARD_DEMO_API"] + "/api/audit/batches"))
live_ids = {b["batch_id"] for b in live_batches["batches"]}
assert live_ids, "Wait for the seeded demo batch"
pattern = "*" + "/deployment.json"
matches = [p.parent for p in Path("backend/api/.demo_runtime").glob(pattern)
    if json.loads(p.read_text())["contract_address"].lower()
    == health["contract_address"].lower()
    and (p.parent / "batches.json").is_file()
    and live_ids.issubset({b["batch_id"] for b in
        json.loads((p.parent / "batches.json").read_text())["batches"]})]
assert len(matches) == 1, "Expected one running local demo"
action = ActionInput(actor="Agent_B", action="USE_PERMISSION",
    permission="CREATE_ORDER", target="order-viva",
    timestamp=datetime.now(timezone.utc).isoformat()).as_injected_action()
action.pop("record_id", None)
with ExitStack() as stack:
    for name, filename in (("DEPLOYMENT_PATH","deployment.json"),
                          ("STATE_PATH","ethereum_state.json"),
                          ("CREDENTIALS_PATH","credentials.json")):
        stack.enter_context(patch.object(chain, name, matches[0] / filename))
    authentication = operator_credentials("Agent_B","evaluate",action)["authentication"]
Path(".runtime").mkdir(exist_ok=True)
path = Path(".runtime/signed-demo-request.json")
path.write_text(json.dumps({"action": action, "authentication": authentication}, indent=2))
print("Created short-lived local request in", path)
'@ | .\.venv\Scripts\python.exe -
```

Privately open the ignored file. Paste `action` into **Action JSON**, and `authentication` into **Authentication JSON**, in Live Governance. Submit within **120 seconds**. Do not share/commit the envelope or capture it in screenshots. The form clears authentication after submission.

A fresh completed evaluation appends one local record. Valid authentication does not promise ALLOW: permission, evidence and current model history still matter. New records can remain pending until batching conditions are checked. Reusing the envelope must reject replay without another append. Generate a new envelope after expiry or nonce consumption, even if a later operation failed.

**Assumption:** Hardhat wallets are unlocked. Someone with RPC access may request their signatures. This is trusted local testing, not production key isolation. Keep RPC local and never fund/use development identities on public networks. Production key custody and enrollment are additional work.

## 10. Blockchain audit demonstration

1. Select an **anchored** action in Blockchain Audit.
2. Click **Verify Original**. Stored data is canonicalized/hashed and genuinely checked against its proof and selected contract.
3. Note target, original leaf, sibling directions, reconstructed/anchored roots, batch, network, transaction and block.
4. Click **Simulate Tampering**. Original is verified first. A temporary copy changes **`target`** to the original value plus **` [tampered demo copy]`**; an empty value uses `audit-record` before the suffix.
5. Compare **Original Stored Record** and **Simulated Modified Copy**. Original retains its verified state/hash; copy shows both actual values and a different leaf.
6. Verify Original again: hash/root remain unchanged. Select another action: previous comparison clears.

No stored log, governance verdict, batch or blockchain is edited. The backend verifies a temporary `record_override`, not a frontend-provided success label. Strict proof checking rejects the changed leaf early; the invalid-copy API can return no calculated root, accurately explained in the UI. Missing proof/RPC failure is not successful tamper detection. The comparison requires checked original/candidate results and an available matching anchored root.

```text
Original → canonical bytes → leaf → proof → anchored root → VERIFIED
Temporary target-modified copy → different leaf → same proof → mismatch → TAMPERED
```

Integrity of a recorded BLOCK decision does not authorize the agent. Integrity also does not prove that the original real-world event was truthful.

## 11. Public Sepolia mode

| Item | Existing public evidence |
|---|---|
| Network | Ethereum Sepolia, chain 11155111 |
| Registry | `0x61c74D0525f4f5A1a7b20f2eA561e485E71dd243` |
| Five-record root | `0xee6028db0fb103cc0c5e1685e586b24d9213515a806aa9717f3ed0b54341006c` |
| Batch transaction | `0xae52c353001ff8754625054d8873eeda0b74b1702af775da3e6a4cd4d33b75c2` |

[Public contract](https://sepolia.etherscan.io/address/0x61c74D0525f4f5A1a7b20f2eA561e485E71dd243), [batch](https://sepolia.etherscan.io/tx/0xae52c353001ff8754625054d8873eeda0b74b1702af775da3e6a4cd4d33b75c2), [tracked manifest](blockchain/deployments/sepolia.json).

Reads use `CHAINGUARD_NETWORK=sepolia` and a privately supplied `SEPOLIA_RPC_URL`. **No private key is required for reads.** Never publish credential-bearing RPC URLs. Compile in local mode first; public deployment settings have separate signer requirements unnecessary for read verification.

**Fresh-clone limitation:** eight canonical runtime files under ignored `backend/core/{blockchain,governance}/data/sepolia/` are not distributed by Git. A root cannot reconstruct missing records/proofs/indexes. Full historical public proof/dashboard reproduction requires the authentic owner-provided bundle and available read RPC. Do not invent substitute evidence.

With that bundle, follow [REPRODUCTION_GUIDE](docs/research-evaluation/REPRODUCTION_GUIDE.md). Its read-only verifier blocks transaction submission but writes a new result file, so it is not ordinary startup. New local GrantAuthority tests do not upgrade Sepolia. No public deployment/write is needed for a normal demo.

## 12. Testing

Unit tests isolate logic; integration tests combine components/contracts; browser E2E tests exercise rendered interactions. Use a **disposable local node/checkout**, not canonical public evidence. Do not overlap mutating tests and timed research.

```powershell
# Root: already running disposable Hardhat at8545 required.
$env:CHAINGUARD_NETWORK = "hardhat"
$env:CHAINGUARD_RPC_URL = "http://127.0.0.1:8545"
.\.venv\Scripts\python.exe -m backend.testing.run_regression

# Security with valid signed/temporal fixture:
.\.venv\Scripts\python.exe -m backend.testing.run_regression backend.core.authorization.tests.test_security backend.api.tests.test_authentication

# Isolated audit/Merkle units:
.\.venv\Scripts\python.exe -m unittest backend.core.blockchain.tests.test_audit_log backend.core.blockchain.tests.test_batching -v

# API through integrated fixture:
.\.venv\Scripts\python.exe -m backend.testing.run_regression backend.api.tests.test_api backend.api.tests.test_audit_tamper_clarity

# Syntax compilation is not a functional test:
.\.venv\Scripts\python.exe -m compileall -q backend
```

In blockchain, tests deploy fixtures to the **existing 8545 node**; they do not start it:

```powershell
$env:CHAINGUARD_NETWORK = "hardhat"
npm run compile
npm run test:contract
```

In frontend:

```powershell
$env:VITE_API_BASE_URL = "http://127.0.0.1:8001"
npm run build
# Running local demo8001/frontend5173 and installed Edge required:
npx playwright test --config playwright.local-qa.config.js
```

Default `npm run test:browser` uses an 8002 API fixture/5179 preview and retained public evidence/configuration. It is not a self-contained fresh-clone test without that bundle. The local targeted config is separate. No extension is needed to use the app or Playwright; historical connected-Chrome manual QA is different.

| Historical checkpoint | Recorded results; not newly rerun full-suite claims |
|---|---|
| Research, 2026-10-17 | 308 Python; 11 contract/network; 83 independent Merkle; 29 API matrix; 24 browser |
| Chrome/preservation, 2026-10-18 | 318 Python; same 11/83/29 categories; 24 existing plus8 targeted browser cases in separate runs;9 pages/6 journeys |
| Audit clarity, 2026-10-19 | 71 focused Python;14 targeted browser;2 extra unanchored API probes and1 transport-abort probe separately |

These overlap and refer to different commits; do not add them. Exact scopes/failures: [research verification](docs/research-evaluation/FINAL_RESEARCH_VERIFICATION.md), [stability QA](docs/qa/FINAL_STABILITY_AND_PRESERVATION.md), [audit QA](docs/qa/BLOCKCHAIN_AUDIT_TAMPER_VERIFICATION.md). Public 83/29 checks require the authentic bundle; fresh local proof demonstration does not.

## 13. Troubleshooting

Never delete evidence/nonce/lock files as a blanket fix.

| Symptom | Cause | Safe solution | Verification |
|---|---|---|---|
| Python not recognized | Install/PATH absent | Install tested interpreter, reopen shell/use launcher | `py -3.14 --version` |
| Wrong Python/wheels | Other interpreter | Separate3.14 venv; its pip | Explicit venv version |
| Activation blocked | PowerShell policy | Process RemoteSigned or explicit interpreter | pip points inside venv |
| pip install fails | Network/index/version | Correct network/interpreter; do not disable TLS | `pip check` |
| Missing module | Wrong environment | Install root requirements with venv Python | Import check |
| Temporary-directory access denied | Restricted sandbox, permissions or unwritable temp location | Use a trusted terminal and writable local clone/temp directory; keep security checks enabled | Demo completes initialization |
| npm not recognized | Node/PATH absent | Install tested Node, reopen terminal | Node/npm versions |
| Hardhat/Vite absent | Wrong folder/no packages | `npm ci` in relevant folder | `npm run` lists scripts |
| Vite `spawn EPERM` | Environment blocks the esbuild compiler subprocess | Run installed dependencies in a permitted trusted local terminal; do not alter app authentication | Vite loads its configuration |
| Port5173 occupied | Other frontend | Preserve owner; stop only your obsolete service | Vite5173/CORS match |
| Port8001 occupied | Other API | Identify correct owner/realm; avoid duplicate | Health matches intended registry |
| Port8545 occupied | Existing chain | Do not reset blindly; isolate tests | Correct RPC/chain ID |
| RPC_UNAVAILABLE | Node stopped/wrong URL | Start node, correct variable, restart demo | Health RPC true |
| Wrong chain/network | Wrong profile/RPC | Explicit local variables | Chain31337/Hardhat |
| Contract unavailable | No bootstrap/stale deployment | Compile then start demo against current node | Contract available |
| Stale deployment after restart | Local chain reset | Restart demo; do not edit historical manifests | New contract has code |
| Model unavailable | Missing artifact/incompatible dependencies | Restore authentic tracked model/install dependencies; do not retrain to hide failure | Inference works |
| Empty/disconnected dashboard | API8000 fallback/startup incomplete | Set VITE_API_BASE_URL8001; wait ready | API responses successful |
| WebSocket failure | Wrong URL/stopped API/proxy | Verify REST then `/ws/governance` | Final scenario verdict |
| CORS error | Origin not localhost5173 | Use documented origin; other hosting requires explicit configuration | Browser requests accepted |
| Missing batch/proof | Pending/wrong profile/missing data | Inspect status/select anchored record/fresh demo | ANCHORED batch |
| Authentication required | Unsigned fresh action | Signed form/helper or intentionally saved replay | Signed request accepted |
| Invalid signature | Edited body/wrong signer/domain | Normalize/sign exact live action again | Payload/domain agree |
| Expired request | Helper120seconds elapsed | Generate fresh envelope | Current validity window |
| Replay rejected | Nonce consumed | New request; never erase nonce history | No duplicate record |
| Public RPC unavailable | Provider/config/limit | Reliable authorized read provider; no secret printing | Read succeeds |
| Public record missing | Ignored bundle absent | Authentic bundle or mark unavailable | No fabricated original |
| Windows lock timeout | Cooperating process contention | Wait/retry, fresh envelope if consumed | One successful append |
| Persistent rename failure | Access/sharing/disk | Correct access/storage; preserve old snapshot | Controlled retry succeeds |
| Temporal tests fail | Wrong fixture/old dates | Use integrated signed runner | Fixture-aware tests pass |
| Browser automation unavailable | Missing Edge/disconnected extension | Required browser config; reconnect for manual Chrome | Actual launch/attachment |

Safe codes such as RPC_TIMEOUT, CHAIN_MISMATCH and CONTRACT_UNAVAILABLE help diagnosis. Report categories and reproduction steps, never full credential-bearing provider errors.

## 14. Project structure

```text
codex-ChainGuard/
├── README.md
├── requirements.txt
├── requirements-research.txt
├── backend/
│   ├── api/                    # main, demo_server, services, schemas, tests
│   ├── core/
│   │   ├── authorization/      # signed requests/grants, durable policy
│   │   ├── blockchain/         # RPC, hashing, Merkle, persistence/recovery
│   │   ├── tracing/            # required credential/authority validation
│   │   ├── drift_detection/    # features, model, synthetic evaluation
│   │   ├── revocation/         # chain status/enforcement/post-audit
│   │   └── governance/         # combined verdict/runtime evidence
│   ├── research/               # controlled experiments
│   └── testing/                # isolated signed fixture
├── blockchain/
│   ├── contracts/              # AgentTrustRegistry, GrantAuthority
│   ├── scripts/                # local node/operator tools
│   ├── test/                   # contract/network tests
│   └── deployments/            # public manifest
├── frontend/
│   ├── src/pages/              # nine pages
│   ├── src/services/api.js     # REST/WS base
│   ├── src/hooks/              # system data/governance stream
│   └── tests/                  # browser regressions
└── docs/
    ├── COMPLETE_PROJECT_EXPLANATION.md
    ├── research-evaluation/    # reports/raw data/scripts/final figures
    └── qa/                     # historical evidence
```

Environment/runtime files, nonces/policy snapshots, dependencies and builds are ignored. Some historical module/model/evaluation files are intentionally tracked; they are not proof of a currently running deployment.

## 15. Research, limitations and references

1. **Blockchain/Merkle versus hash-chain logging:** identical signed authorization/events,10/100/500/1000 records,3 paired trials. Both externally protected checkpoints detected all60 tested transformations per condition. Blockchain adds a separately queryable commitment under the storage-rewrite assumption, with extra local latency/gas.
2. **Revocation:** original versus corrected4-depth fixtures. Original incorrectly retained60 downstream permissions; corrected retained0 and preserved40/40 independent paths.
3. **Security:**180 controlled operations:30 legitimate allowed,140 attacks blocked,10 anomalies reviewed separately. This is not universal security or real-world ML accuracy.

See [results](docs/research-evaluation/RESULTS_AND_DISCUSSION.md), [reproduction](docs/research-evaluation/REPRODUCTION_GUIDE.md), [related work](docs/research-evaluation/RELATED_WORK_COMPARISON.md), [limitations](docs/research-evaluation/LIMITATIONS_AND_THREATS_TO_VALIDITY.md), [evidence map](docs/research-evaluation/EVIDENCE_MAP.md). Final CSVs/figures differ from smoke/prior runs. References include Isolation Forest, EIP-191 and genuine access-control/delegation/logging standards.

Important limits:

- Local timing/gas does not measure public confirmation latency, monetary savings or optimized database performance.
- Saved evidence is not a fresh execution; commitment integrity is not event truth.
- Enrollment, keys, clocks, verifier, RPC and trusted enforcement storage remain assumptions. Administrator rollback of nonce/policy files is not prevented.
- Tested scope is cooperating processes on a local filesystem, not distributed/NFS linearizability or unrestricted multi-tenancy.
- Nonces, files, external actions and chain publication are not one transaction. Claims prevent tested concurrent duplicate submissions, not universal on-chain exactly-once delivery.
- Uncertain submissions fail closed. Interrupted legacy revocation publication can need operator reconciliation; revocation does not cancel already-running external tasks.
- Synthetic ML data and small topologies limit generalization. False positives/negatives remain.
- Blockchain provides neither confidentiality nor lost-data recovery, and an authorized root can attest false new events.

## 16. Documentation validation

Implementation reference: main **157ab5e08b284610df344a20ef2e547618f794cb**. The documentation commit follows it. Historical reports retain their original branch/HEAD labels.

An actual fresh GitHub clone outside the development checkout was used on 20 October 2026, without copied `.env`, ignored evidence, packages or deployment state. Python 3.14.0, Node 24.15.0 and npm 11.12.1 were observed. Exact outcomes appear in [handbook Part24](docs/COMPLETE_PROJECT_EXPLANATION.md#part-24--testing-and-documentation-validation).

**Isolation disclosure:** user-owned services occupied defaults. A new independent Hardhat used18545; clone frontend5174; an external temporary launcher changed only the demo API bind to18001 and its test CORS origin tolocalhost5174, invoking unchanged application/initializer code. No tracked source/configuration was modified. Default-port commands were source-checked, not claimed to execute unchanged alongside occupied services. Public-bundle and automated-browser prerequisites remain real limitations.
