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

Canonical bytes are compact JSON with sorted object keys, UTF-8 characters preserved, and no insignificant whitespace (`json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)`). Aware datetimes are normalized to UTC with microsecond precision and a `Z` suffix; enums serialize by value, bytes as `0x`-prefixed lowercase hex, and optional values as JSON `null`. The resulting bytes are hashed with Ethereum Keccak-256 through Web3.py. At this phase, logs are stored off-chain but are not yet Merkle-batched. Existing individual action-hash anchoring remains enabled for compatibility.
