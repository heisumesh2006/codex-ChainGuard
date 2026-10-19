# Results and discussion

All tables below are calculated from the final completed CSVs by `scripts/analyze_results.py`. They exclude pilot and archived partial results. Run manifests retain the measured source fingerprints, Windows/Python/Node/package environment and UTC times. Experiment 1 completed at 2026-10-17T17:26:51.961037+00:00; Experiment 2 at 2026-10-17T17:39:23.488425+00:00; Experiment 3 at 2026-10-17T17:40:07.075874+00:00.

## 1. Blockchain versus hash-chain audit logging

There are **24 variant/workload/trial rows and 9,660 timed event operations**, with three trials for each variant/workload. The table reports the mean of each trial statistic, not a pooled-event median/p95. Full minimum/maximum trial values remain in `raw/aggregated_experiment1.csv`; plotted bars show observed ranges, not confidence intervals.

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


Event processing includes current signed authorization, durable replay/persistence and synchronous threshold anchoring where applicable. Setup/deployment/caller signing are excluded from event timers. Audit storage excludes policy/replay caches and deployment files. Deployment gas, workload wall time, actual local effective fees and authentication/local-audit components are retained in the raw/aggregate CSVs rather than hidden in a cost claim. Deployment is additional cost, not free. Fees reflect this automining local node, not a public-network quote.

There were **0 untampered false positives** in the 24 measured complete-audit checks. Deliberate tampering outcomes are:

| Variant | Checkpoint policy | Detected / attempts | Detection in this matrix |
| --- | --- | ---: | ---: |
| merkle_blockchain | protected_checkpoint | 60 / 60 | 100.0% |
| merkle_blockchain | rewriteable_local_checkpoint | 60 / 60 | 100.0% |
| hash_chain | protected_checkpoint | 60 / 60 | 100.0% |
| hash_chain | rewriteable_local_checkpoint | 0 / 60 | 0.0% |


Each checkpoint-policy row contains 12 local trials times five attack transformations. The two EVM policy rows use the same externally protected chain model; they are not 120 distinct attack types. A protected hash-chain checkpoint detects the same tested attacks. Blockchain's additional value here is an independently queryable external inventory/commitment when the attacker can rewrite the entire local log and its local head. It offers no measured detection advantage over an equally protected external hash-chain checkpoint in these tests. Extra synchronous latency, RPC verification, storage and gas/transactions must be weighed against that operational trust benefit. Neither scheme guarantees record truth or availability.

The hash-chain snapshot and Merkle/batch persistence implementations do different local work. The results cannot isolate consensus cost alone or establish superiority over optimized databases, WORM storage, monitored transparency logs or external witnesses. No mainnet/Sepolia throughput, confirmation latency or monetary saving is inferred.

## 2. Delegation and cascading revocation

The 160 main rows cover four chain depths, two versions and 20 trials per cell. Descendant counts below sum actual C/D checks, rather than multiplying trials into unique attack techniques. A's incorrect-revocation count is separate.

| Version | Depth | Descendant checks | Invalidated | Incorrectly retained | Incorrectly revoked A | Revocation ms | Warm check/trace ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| corrected_cascade | 1 | 0 | 0 | 0 | 0 | 57.106 | 0.112 |
| corrected_cascade | 2 | 0 | 0 | 0 | 0 | 61.630 | 0.167 |
| corrected_cascade | 3 | 20 | 20 | 0 | 0 | 79.472 | 0.276 |
| corrected_cascade | 4 | 40 | 40 | 0 | 0 | 90.933 | 0.412 |
| original_flat | 1 | 0 | 0 | 0 | 0 | 0.038 | 0.001 |
| original_flat | 2 | 0 | 0 | 0 | 0 | 0.037 | 0.001 |
| original_flat | 3 | 20 | 0 | 20 | 0 | 0.038 | 0.001 |
| original_flat | 4 | 40 | 0 | 40 | 0 | 0.038 | 0.001 |


The original retained **60** downstream permissions that should have been invalid after B revocation. The corrected version retained **0** incorrectly and incorrectly revoked **0** independent A permissions. All **40** corrected independent-root/other-parent cases preserved C's valid alternative authority, with **0** incorrect revocations.

The original flat query and corrected signed ancestry traversal are different semantics. Corrected mutation timing includes crypto, durable nonce consumption and policy snapshots absent from the original. These numbers describe assurance/cost tradeoffs on four agents and warm repeated queries, not an isolated cascade algorithm speedup or an arbitrary-scale result. Separate local Solidity/API tests validate the root-attested on-chain extension; timed Experiment 2 calls enforce local policy and make no chain transactions.

## 3. Authorization security

The controlled matrix contains **180 requests**: 30 legitimate operations, 140 attacks and 10 behavioral-anomaly cases. Actual outcomes/timing are:

| Case | Requests | Expected | Allowed | Blocked | Review | Mean operation ms |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| legitimate_direct | 10 | ALLOW | 10 | 0 | 0 | 48.059 |
| legitimate_delegated | 10 | ALLOW | 10 | 0 | 0 | 85.145 |
| legitimate_root_grant | 10 | ALLOW | 10 | 0 | 0 | 74.817 |
| unauthorized_request | 10 | BLOCK | 0 | 10 | 0 | 64.516 |
| missing_permission | 10 | BLOCK | 0 | 10 | 0 | 63.316 |
| expired_credential | 10 | BLOCK | 0 | 10 | 0 | 66.841 |
| not_yet_issued | 10 | BLOCK | 0 | 10 | 0 | 63.559 |
| privilege_escalation | 10 | BLOCK | 0 | 10 | 0 | 70.628 |
| root_impersonation | 10 | BLOCK | 0 | 10 | 0 | 16.793 |
| replayed_authentication | 10 | BLOCK | 0 | 10 | 0 | 34.490 |
| unauthorized_delegation | 10 | BLOCK | 0 | 10 | 0 | 89.863 |
| self_delegation | 10 | BLOCK | 0 | 10 | 0 | 70.005 |
| revoked_agent | 10 | BLOCK | 0 | 10 | 0 | 62.277 |
| invalid_intermediate | 10 | BLOCK | 0 | 10 | 0 | 67.082 |
| tampered_credential_metadata | 10 | BLOCK | 0 | 10 | 0 | 62.085 |
| forged_proof | 10 | BLOCK | 0 | 10 | 0 | 77.978 |
| scope_creep | 10 | REVIEW | 0 | 0 | 10 | 135.345 |
| post_decommission | 10 | BLOCK | 0 | 10 | 0 | 67.066 |


With attack as the positive class and REVIEW cases excluded: TP=140, FN=0, FP=0, TN=30. Attack-blocking rate/recall=100.0%, false rejection rate=0.0%, precision=1.000, F1=1.000. These are exact finite-matrix results, not general-world estimates. All 10 expected anomalies produced REVIEW and were excluded from binary rates. Mixed-operation mean latency was 67.770 ms and median 67.508 ms; per-case timings are preferable because operations differ.

Original unauthenticated root issuance allowed 10/10 attempts; corrected root impersonation allowed 0/10. The corrected interface verifies signer ownership against a trusted registry, binds intent/domain/nonce/time and consumes the nonce durably. A valid signature still cannot confer a missing permission or revive invalid ancestry. These results do not establish security under compromised root keys, rolled-back enforcement storage, Byzantine RPC or arbitrary untested attacks.

## Independent implementation and public evidence checks

Final backend coverage comprises 308/308 methods passing in the final integrated run (earlier full/focused runs overlap and are not added to this count). Contract/network tests passed 11/11, independent Merkle checks 83/83, the public API matrix 29/29 and production browser cases 24/24; exact records and hashes are in `raw/verification_results.json` and `FINAL_RESEARCH_VERIFICATION.md`. Additional standalone probes are recorded separately, not added to these backend counts.

Existing Sepolia saved decisions remain ALLOW, BLOCK, BLOCK, REVIEW, BLOCK. Original proofs remain VERIFIED and altered in-memory copies TAMPERED, five each. Eight canonical local evidence hashes remain unchanged. This preserves historical evidence; it does not claim the new GrantAuthority extension was publicly deployed or old decisions were recomputed using corrected policy. No Sepolia transactions were submitted.

See the three experiment method documents and `LIMITATIONS_AND_THREATS_TO_VALIDITY.md` before reusing any numeric claim. High-quality SVG/PDF/300-DPI PNG figures are under `figures/`. No IEEE PDF was edited.
