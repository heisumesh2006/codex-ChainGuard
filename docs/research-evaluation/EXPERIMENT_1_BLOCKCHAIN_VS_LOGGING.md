# Experiment 1: Merkle anchoring versus cryptographic hash-chain logging

## Question and controlled design

Does an independently queryable blockchain commitment add auditability beyond a locally maintained cryptographic log, and what does it cost in this implementation?

`backend/research/experiment1.py` compares the production `AuditLogStore`/`BatchManager` with `backend/research/audit_baseline.py:HashChainLog`. Both variants use the same signed-request verifier, current permission engine, ordered event payloads, AuditRecord constructor, canonical UTF-8 JSON and Keccak-256. Workloads are 10, 100, 500 and 1,000 events, with three paired trials per workload. Execution order alternates A/B, B/A, A/B. A trial uses fresh temporary directories, random isolated signing keys and, for A, a new local registry. No public transaction is involved.

The benchmark isolates **signed current authorization plus ordinary-action audit persistence**, rather than running the complete six-module governance pipeline. Isolation Forest, legacy credential/delegation transaction setup and public-network confirmation are not timed. The fixed synthetic input timestamp is an audit-field value; it is not a claim that this microbenchmark performs historical credential verification at that timestamp. Historical enforcement is tested separately. Each measured operation authenticates a fresh request and checks actual current permission; it fails if authorization is denied. Both variants construct the same audit record bytes for a paired trial.

The retained-grant signature cache is warmed equally. Caller-side signing, fixture setup, registry deployment and CSV writing are outside event timers. Request verification and durable replay-cache writes are included. A seals FIFO batches of ten and waits for real local Hardhat receipts. B durably atomically replaces its JSON hash-chain snapshot. These persistence layouts differ intentionally: the measured comparison is between these concrete architectures, not a pure estimate of consensus overhead or a claim about every optimized log/database implementation.

Events are processed sequentially in one benchmark process. Both variants use the same trusted synthetic public-address resolver with real random keys and real signature verification, keeping identity lookup constant. They do not perform a production registry RPC lookup on every authentication. Production registry-bound signing/lookup is verified separately by live local-EVM/API tests. The 500-action multiprocess stress test is a separate mocked-chain fixture and must not be reported as these audit workloads' throughput.

## Measurements and definitions

| Field | Measurement boundary |
| --- | --- |
| Event-recording average, median, p95 | From request verification through durable audit write and any synchronous threshold-triggered anchor receipt |
| Authentication time | Fresh signature/nonce verification plus current permission lookup |
| Local audit time | Record construction, append and local batch-sealing work, excluding anchor RPC/receipt wait |
| Anchor time | Synchronous threshold-triggered batch submission/reconciliation and receipt wait; zero for other events |
| Processing time | Sum of measured event intervals; excludes caller signing and setup |
| Workload wall time | Workload loop, caller signing, verification and receipt/accounting reads; excludes deployment and tamper trials |
| Verification time | Complete ordered inventory verification, including local RPC reads for A; complete chain/checkpoint verification for B |
| Storage | Audit JSONL plus batch metadata for A; hash-chain snapshot for B; excludes replay/policy caches, deployment files, locks and filesystem metadata |
| Gas and audit transactions | Actual receipts for batch anchors; deployment gas is recorded separately |
| Fees | Actual local receipt gas used times effective gas price, in wei; not a Sepolia/mainnet fee estimate or monetary saving |

Per-trial medians/p95s are calculated from that trial's event samples. Summary figures show the mean of three trial statistics; error bars show observed minimum/maximum, **not** confidence intervals. The per-event p95 uses linear interpolation at index `(n-1)*0.95`. For ten events, this is a small-sample descriptive statistic. No independent-sample inference is made from thousands of events within the same run.

## Tampering and fair trust assumptions

For each trial, the attacker modifies one record, deletes one, inserts a forged record, reorders records, or rewrites all targets. The attacker can recompute every hash-chain link and replace the local head. Each attack uses a disposable copy of measured local state; the untouched original is restored and reverified after every case.

Two checkpoint policies are evaluated explicitly:

1. **Protected checkpoint:** the verifier retains an external `(head, count)` for B. A trusts the selected contract/chain and obtains its batch inventory externally. Both have an attacker-inaccessible commitment.
2. **Rewriteable local checkpoint:** B accepts a head that the storage attacker can also replace. A still has its independently retained chain commitment. This comparison intentionally exposes the different trust boundary; it is not an equal-checkpoint claim of stronger cryptography.

The A auditor discovers expected roots/counts from the authenticated registry's event inventory between the known deployment and final local block, then recomputes the entire ordered record inventory. It does not trust replacement local batch JSON as its inventory. Inclusion alone would not prove completeness; this inventory comparison additionally detects the tested deletion/insertion cases. The event scan is a bounded local experiment over that fixture, distinct from production uncertain-transaction recovery.

Expected verification failures caused by deliberate tampering are counted as detections. Untampered verification failures/false positives are recorded separately. Neither design recovers deleted data or proves the truth of a newly recorded event. A protected hash-chain checkpoint is a valid alternative external witness; blockchain is not the only tamper-evident design.

## Results and artifacts

Final numeric tables are generated from completed manifests/CSVs in [RESULTS_AND_DISCUSSION.md](RESULTS_AND_DISCUSSION.md). Pilot data under `smoke/` and superseded/interrupted runs under `raw/prior/` are excluded from final aggregates. Final inputs are:

- `raw/experiment1_summary.csv`: 24 planned variant/workload/trial rows.
- `raw/experiment1_events.csv`: 9,660 planned measured events across both variants.
- `raw/experiment1_tampering.csv`: per-attack outcomes under both checkpoint policies.
- `raw/experiment1_manifest.json`: completion status, parameters, environment, source/output hashes.
- `raw/aggregated_experiment1.csv` and `raw/aggregated_tampering.csv`: recalculated summaries.
- `figures/experiment1_performance.{svg,pdf,png}` and `experiment1_tampering.{svg,pdf,png}`.

The planned row counts above describe the protocol. Completed counts and measured conclusions must be taken from the final results/verification documents, not inferred from this method description.

## Recorded source distinction

During final review, delegation cycle discovery was tightened to ignore expired/invalid authority when considering a new delegation. Experiment 1 never invokes `delegate_permission`: it issues one root grant and measures authentication, current permission checks and audit persistence. Those functions and setup semantics are unchanged. `raw/experiment1_source_compatibility.json` and the preserved `experiment1_unmeasured_delegation_fix.patch` record the old/final checksums and verify that every other top-level authorization definition is AST-identical. Two corresponding regression tests were added after the run began; test modules are not imported by this benchmark. The original manifest is preserved rather than rewritten to claim the whole file was unchanged. Experiments 2/3 and the final affected security checks use the final delegation implementation.

## Completed numeric results

| Records | Variant | Mean event ms | Median event ms | p95 event ms | Verify ms | Audit KiB | Processing s | Audit tx | Gas |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10 | Hash chain | 41.419 | 41.902 | 52.824 | 1.208 | 6.757 | 0.414 | 0 | 0 |
| 10 | Merkle + local EVM | 116.199 | 95.836 | 235.604 | 16.025 | 7.786 | 1.162 | 1 | 94829 |
| 100 | Hash chain | 82.830 | 83.997 | 102.825 | 21.925 | 67.245 | 8.283 | 0 | 0 |
| 100 | Merkle + local EVM | 109.956 | 75.000 | 290.973 | 221.447 | 77.965 | 10.996 | 10 | 948290 |
| 500 | Hash chain | 82.405 | 81.289 | 105.578 | 69.543 | 337.167 | 41.202 | 0 | 0 |
| 500 | Merkle + local EVM | 218.475 | 203.452 | 597.357 | 1071.555 | 391.715 | 109.238 | 50 | 4741318 |
| 1000 | Hash chain | 113.872 | 112.153 | 159.620 | 156.597 | 676.522 | 113.872 | 0 | 0 |
| 1000 | Merkle + local EVM | 309.736 | 278.408 | 846.406 | 1870.462 | 788.005 | 309.736 | 100 | 9482456 |

| Variant | Checkpoint policy | Detected / attempts | Detection in this matrix |
| --- | --- | ---: | ---: |
| merkle_blockchain | protected_checkpoint | 60 / 60 | 100.0% |
| merkle_blockchain | rewriteable_local_checkpoint | 60 / 60 | 100.0% |
| hash_chain | protected_checkpoint | 60 / 60 | 100.0% |
| hash_chain | rewriteable_local_checkpoint | 0 / 60 | 0.0% |

Interpretation, binary metric definitions, run provenance and limitations: [RESULTS_AND_DISCUSSION.md](RESULTS_AND_DISCUSSION.md).
