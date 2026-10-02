# ChainGuard-AI architecture

The package names describe responsibilities while the academic module numbers remain useful in reports:

| Academic module                   | Package                                          |
| --------------------------------- | ------------------------------------------------ |
| Module 1 — Authorization          | `backend.core.authorization`                     |
| Module 2 — Blockchain             | `backend.core.blockchain` and root `blockchain/` |
| Module 3 — Delegation tracing     | `backend.core.tracing`                           |
| Module 4 — Policy drift detection | `backend.core.drift_detection`                   |
| Module 5 — Revocation             | `backend.core.revocation`                        |
| Module 6 — Governance             | `backend.core.governance`                        |

An action flows through authorization, rooted trace context, the persisted drift model, revocation audit, blockchain proof checks, and a final ALLOW, REVIEW, or BLOCK verdict. `backend.api` exposes that same pipeline to the dashboard.

Each subsystem owns its data. The persisted model stays in `backend/core/drift_detection/models/`; saved metrics and reports stay under their owning `data/` folders. The sole Solidity source is `blockchain/contracts/AgentTrustRegistry.sol`. Module 2's historical off-chain deployment files are stored under `backend/core/blockchain/data/` and remain ignored by Git, as before the move.

The unchanged joblib model stores its original Python class path (`module4.detector.TrainedDetector`). `backend.core.drift_detection` registers that historical import name during loading so the same model bytes work in the new package. No model retraining or threshold change is involved.

## Off-chain audit logging

After each completed governance evaluation, the canonical pipeline adapts its action and evidence into a versioned `AuditRecord` and appends one UTF-8 JSON object to `backend/core/blockchain/data/audit_logs.jsonl`. Records contain a unique evaluation `action_id`; an existing source event ID is retained as metadata so replayed scenarios create distinct audit instances. Duplicate IDs passed directly to the store are rejected.

Canonical bytes are compact JSON with sorted object keys, UTF-8 characters preserved, and no insignificant whitespace (`json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)`). Aware datetimes are normalized to UTC with microsecond precision and a `Z` suffix; enums serialize by value, bytes as `0x`-prefixed lowercase hex, and optional values as JSON `null`. The resulting bytes are hashed with Ethereum Keccak-256 through Web3.py. Existing individual action-hash anchoring remains enabled for compatibility.

## Off-chain Merkle batching

Governance appends each completed action to the audit JSONL store, then `BatchManager` checks the pending records. Its current demo defaults seal a batch at 5 records or when the oldest locally pending record reaches 30 seconds; configure these with `CHAINGUARD_BATCH_SIZE` and `CHAINGUARD_BATCH_MAX_AGE_SECONDS`. Larger settings such as 1000 records or 300 seconds can be configured for a deployment and are not production recommendations. To enforce the age trigger during idle periods, a service should call `seal_due_batches()` periodically; the governance hook also checks after each append.

The deterministic construction is: action logs → canonical bytes → Ethereum Keccak-256 leaf hashes → ordered Merkle tree → root → blockchain anchor. Each parent is `Keccak256(left_hash_bytes || right_hash_bytes)`; children are never sorted. At every level with an odd number of nodes, the last node is duplicated as its own right sibling. Proofs list leaf-to-root siblings as `{ "hash": "0x…", "position": "left" | "right" }`, and verification checks the declared position against the leaf index and tree width. Batch metadata and the `action_id` to `batch_id` assignment live separately in ignored `data/batches.json`; audit records are never edited when assigned. Batch IDs are deterministic (`batch:<merkle_root>`), and a record can be assigned only once.

Once a batch is sealed, the manager anchors one root transaction through the registry's existing `ROOT_AUTHORIZER` gate. The contract stores only the batch key, Merkle root, log count, record time range, anchoring actor, and confirmation timestamp; audit content and proofs remain off-chain. The manager records transaction hash, block number, contract, and chain ID only after a successful receipt and state check. Failed transactions remain `SEALED_UNANCHORED` with retry metadata. The audit subsystem uses batched roots for its new action stream. Existing single action-hash commitments for Module 1 source events are retained as **legacy compatibility behavior**; identity, credential, delegation, and revocation transactions remain immediate.

## EVM network profiles

The same Solidity contract and Python provider/transaction adapter support two explicit profiles:

| Profile | Network | Chain ID | Explorer |
| --- | --- | ---: | --- |
| `hardhat` (default) | Hardhat Local | 31337 | None |
| `sepolia` | Ethereum Sepolia public test network | 11155111 | Sepolia Etherscan |

Sepolia uses test ETH and is **not Ethereum Mainnet**. Deployment metadata is saved at `blockchain/deployments/sepolia.json`; profile runtime state is isolated under `backend/core/governance/data/sepolia/` and `backend/core/blockchain/data/sepolia/`, so it does not overwrite historical Hardhat evidence. The root wallet signs administrative transactions locally in the Python process; its private key and the RPC URL are loaded from the ignored root `.env` file and are never included in API responses or persisted deployment metadata. Etherscan links are constructed only for chain ID 11155111; local Hardhat responses expose no explorer URLs.

The public path remains `ordinary actions -> append-only off-chain log -> deterministic Merkle batch -> one Sepolia root transaction`. Agent registration, credential issuance, delegation, and revocation continue as immediate contract transactions. The Sepolia deployment is an opt-in operator action; configuration alone does not deploy anything.
