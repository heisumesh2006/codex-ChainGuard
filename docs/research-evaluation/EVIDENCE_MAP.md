# Evidence map

Line ranges refer to the final reviewed source in this branch. Test names in `raw/verification_results.json` identify the actual completed methods; its log hashes refer to the locally retained `.runtime` logs. Bibliographic claims are sourced separately in `RELATED_WORK_COMPARISON.md`.

| Claim | Code evidence | Completed verification / result |
| --- | --- | --- |
| Names alone do not authenticate root issuance. | `backend/core/authorization/authentication.py:66-155`; `agents.py:151-208` | `SignedAuthorityTests` root-name, wrong-key, non-root and binding regressions; `experiment3_before_after.csv` |
| Intent, actor, domain, nonce and time are signature-bound. | `authentication.py:39-131` | Signed security and API tests; raw Experiment 3 request rows |
| Replay is checked durably across processes. | `authentication.py:114-131`; stable lock helper in `backend/core/blockchain/persistence.py` | `test_cross_process_replay_exactly_one_acceptance`; `raw/policy_multiprocess_verification.json`; real HTTP replay401 |
| Mandatory parent grants and signed metadata determine authority. | `backend/core/authorization/agents.py:102-137,214-356` | Tampered metadata, expiry, issuer, parent, clone and invalid-intermediate regressions; Experiment 3 |
| Downstream revocation preserves independent paths. | `agents.py:361-434`; `tracing/tracer.py:398-492` | Experiment 2:160 main/40 independent rows; signed security, legacy tracer and local EVM tests |
| Expired/invalid edges cannot manufacture a cycle rejection. | `agents.py:230-245` | `test_expired_delegation_does_not_create_false_cycle`, `test_expired_parent_does_not_create_false_cycle`; final affected pass |
| Failed publication does not leak uncommitted in-memory authority. | `backend/core/authorization/state.py:145-194` | `PolicyPersistenceTests`: first write, replacement, exception, nonce and post-commit ambiguity regressions |
| Malformed policy/extension metadata fails with controlled evidence errors. | `state.py:36-114`; `blockchain/grant_authority.py:23-45` | Malformed snapshot-member and malformed/wrong-network extension tests |
| Actual registered signers can use HTTP and WebSocket paths. | `backend/api/main.py:173-214`; `governance/pipeline.py:200-299` | `GrantAuthorityIntegrationTests`; `raw/live_http_verification.json` (real TCP HTTP) |
| On-chain grant ancestry is root-attested and checked independently. | `blockchain/contracts/GrantAuthority.sol`; `backend/core/blockchain/grant_authority.py:93-151` | Five added Solidity cases, twelve local EVM/API tests and all-hop commitment mismatch regression |
| Existing public contract was not upgraded. | Separate `GrantAuthority.sol`, with local-only guards; unchanged `AgentTrustRegistry.sol` | `raw/public_evidence_verification.json`; eight before/after canonical hashes; Git source diff |
| Audit comparison uses actual local anchoring and the same event generator. | `backend/research/experiment1.py:82-183`; `audit_baseline.py` | 24 trial rows,9,660 events,483 actual anchor receipts and reconstructed4,830 anchored records |
| Complete inventory verification is distinct from inclusion alone. | `experiment1.py:60-79`; `scripts/verify_experiment1_receipts.py` | `raw/experiment1_onchain_verification.json`, `experiment1_anchors.csv`, `experiment1_datasets.csv` |
| Protected checkpoints detect the tested rewrites; replaceable heads do not. | `backend/research/audit_baseline.py:verify`; `experiment1.py:changed,run` | `experiment1_tampering.csv`; `aggregated_tampering.csv`; tampering figure |
| Original weaknesses are measured without weakening production. | `backend/research/common.py:BASE,original_module` | Pinned Git source; Experiment 2 original rows; Experiment 3 before/after rows |
| Reported metrics come from defined controlled samples. | `scripts/analyze_results.py`; experiments2/3 | Aggregate CSVs, `results_summary.json`, `raw/postprocessing_manifest.json` |
| Prior security and concurrency protections remain tested. | Unchanged persistence/batch/recovery/redaction implementations plus source changes reviewed | Final308/308 integrated pass;500 successful stress actions,zero lost/duplicate records |
| Browser workflows and historical proofs remain usable. | Existing frontend, read-only saved replay in `backend/api/services.py` | Full24 browser report plus affected2 rerun;29 API checks; five VERIFIED/five TAMPERED |

## Source and interpretation qualifications

The original manifest hashes are preserved. Experiment 1's unused delegation-creation function and its new regression tests changed during final review; `experiment1_source_compatibility.json` plus its source diff demonstrate that the timed/current-authorization and root-setup definitions remained unchanged. Experiments 2/3 use the final delegation code. Final chart legend placement changed after timing; `postprocessing_layout.patch` and `postprocessing_manifest.json` record that all numeric aggregates stayed byte-identical.

The later concurrency-test-only clock correction is recorded in `concurrency_test_clock_delta.patch`, `concurrency_test_clock_provenance.json` and `concurrency_age_boundary_reproduction.json`. Benchmark processes never import that test module. Production persistence did not change; the historical306-test failure is retained, and the final308-test integrated run passes with explicit single-/two-process age coverage.

Unsupported claims include real-world anomaly accuracy, population attack recall, mainnet/Sepolia performance, blockchain-only integrity, automatic exactly-once delivery, public deployment of the new extension, and complete rollback resistance for local enforcement storage. They must not be inferred from these artifacts.
