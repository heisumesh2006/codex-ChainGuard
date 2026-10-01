# ChainGuard-AI architecture

The package names describe responsibilities while the academic module numbers remain useful in reports:

| Academic module | Package |
| --- | --- |
| Module 1 — Authorization | `backend.core.authorization` |
| Module 2 — Blockchain | `backend.core.blockchain` and root `blockchain/` |
| Module 3 — Delegation tracing | `backend.core.tracing` |
| Module 4 — Policy drift detection | `backend.core.drift_detection` |
| Module 5 — Revocation | `backend.core.revocation` |
| Module 6 — Governance | `backend.core.governance` |

An action flows through authorization, rooted trace context, the persisted drift model, revocation audit, blockchain proof checks, and a final ALLOW, REVIEW, or BLOCK verdict. `backend.api` exposes that same pipeline to the dashboard.

Each subsystem owns its data. The persisted model stays in `backend/core/drift_detection/models/`; saved metrics and reports stay under their owning `data/` folders. The sole Solidity source is `blockchain/contracts/AgentTrustRegistry.sol`. Module 2's historical off-chain deployment files are stored under `backend/core/blockchain/data/` and remain ignored by Git, as before the move.

The unchanged joblib model stores its original Python class path (`module4.detector.TrainedDetector`). `backend.core.drift_detection` registers that historical import name during loading so the same model bytes work in the new package. No model retraining or threshold change is involved.
