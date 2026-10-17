# ChainGuard-AI research security evaluation

This directory contains implementation evidence, reproducible local experiments, raw results, figures and proposed paper text. It supplements the completed project; it does not modify the existing IEEE PDF or public Sepolia evidence.

Start with [FINAL_RESEARCH_VERIFICATION.md](FINAL_RESEARCH_VERIFICATION.md) for exact verification/commit status and [RESULTS_AND_DISCUSSION.md](RESULTS_AND_DISCUSSION.md) for measured tables and qualified conclusions.

| Document | Purpose |
| --- | --- |
| [SECURITY_IMPROVEMENTS.md](SECURITY_IMPROVEMENTS.md) | Identity, replay, signed ancestry, revocation, persistence and proof boundaries |
| [EXPERIMENT_1_BLOCKCHAIN_VS_LOGGING.md](EXPERIMENT_1_BLOCKCHAIN_VS_LOGGING.md) | Paired audit comparison and checkpoint threat models |
| [EXPERIMENT_2_DELEGATION_REVOCATION.md](EXPERIMENT_2_DELEGATION_REVOCATION.md) | Pinned-original versus corrected paths and independent grants |
| [EXPERIMENT_3_AUTHORIZATION_SECURITY.md](EXPERIMENT_3_AUTHORIZATION_SECURITY.md) | Case definitions, exact outcomes and metric definitions |
| [RELATED_WORK_COMPARISON.md](RELATED_WORK_COMPARISON.md) | Verified primary literature and technical comparison |
| [LIMITATIONS_AND_THREATS_TO_VALIDITY.md](LIMITATIONS_AND_THREATS_TO_VALIDITY.md) | Trust, deployment, storage, timing and generalization limits |
| [REPRODUCTION_GUIDE.md](REPRODUCTION_GUIDE.md) | Commands and isolated fixture/real signing workflow |
| [IEEE_PAPER_REPLACEMENT.md](IEEE_PAPER_REPLACEMENT.md) | Candidate abstract, methods, setup, results, discussion and conclusions |
| [EVIDENCE_MAP.md](EVIDENCE_MAP.md) | Main claims linked to code and completed artifacts |

- `raw/`: final event/trial CSVs, manifests, receipt/root validation, test results and public evidence checks.
- `raw/prior/`: preserved preliminary results; excluded from final aggregates.
- `smoke/`: earlier ten-record pilot; excluded from final aggregates.
- `figures/`: four labelled figures, each exported as SVG, PDF and 300-DPI PNG.
- `scripts/`: benchmark, analysis and independent verification entry points.
- `architecture.mmd`, `delegation_revocation.mmd`, `audit_comparison.mmd`: Mermaid source diagrams.
- `results_summary.json`: metrics recalculated from completed raw CSVs.

All new chain writes use isolated local Hardhat. The original public contract/root are historical, read-only evidence. A protected hash-chain checkpoint detects the tested tampering too; no blockchain-only detection or universal attack-prevention claim is made. Timing data are local implementation measurements, not public-network performance estimates.
