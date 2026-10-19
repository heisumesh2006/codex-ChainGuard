# Experiment 2: delegation and cascading revocation

## Question and preserved baseline

Does revoking an intermediate agent invalidate authority derived through it, while preserving genuinely independent authority?

`backend/research/experiment2.py` compares the original module loaded from Git commit `f3b4574cb726264d9d6d01988e0d64940ae8c148` with the corrected production Python engine. `common.original_module` loads the pinned source into an isolated module; production security is never switched off. Both start with four temporary agents and the same logical permission P. Original behavior is intentionally measured as it existed, including its lack of authenticated mutation requests.

The four topologies are:

```text
Root -> A
Root -> A -> B
Root -> A -> B -> C
Root -> A -> B -> C -> D
```

Each version/topology runs 20 times with fresh isolated state. B is decommissioned after all intended grants are confirmed allowed. At depth one B has no authority in the tested path; A must remain allowed. At depth two B loses permission and there are no descendants beyond B. Depths three/four test C and C/D respectively. Outcomes are checked before and after revocation; this is 160 version/topology/trial rows, not 160 unique attack techniques.

## Corrected behavior

Root requests and delegations carry real EIP-191 signatures. Every retained grant binds holder, scope, issue/expiry and exact parent ID. Current permission is derived from authenticated valid ancestry rather than a copied flat permission list. Decommissioning B marks its affected grants and their descendants revoked. C/D remain active agents: only paths derived from B are invalidated. A later root re-grant cannot resurrect a child tied to the old parent ID. Renewal preserves the prior signed root grant in history; revoked delegations are retained.

Two additional corrected-only tests run 20 times each: an independently root-issued C permission, and an independent Root -> D -> C path. After B is revoked, these independent paths must still authorize C. These 40 rows test false revocation separately from the 160 main rows. Self-delegation, cycles, parent/scope substitution, malformed/expired/future grants and signed expiry attenuation are covered by permanent security regressions in addition to this controlled topology benchmark.

## Measurements and interpretation

- `authorized_before/after`: number of tested topology nodes whose local permission query allows P.
- `expected_downstream_invalidated`: descendants beyond B in that topology (0, 0, 1, 2).
- `downstream_invalidated`: those descendants denied after B revocation.
- `incorrectly_retained`: descendants still allowed through the revoked authority.
- `incorrectly_revoked`: A denied despite remaining independent of B.
- `revocation_ms`: measured mutation call. The corrected call includes signature verification, replay protection, ancestry/history updates and durable policy publication; the original is an unsigned in-memory mutation. This difference is disclosed rather than attributed solely to graph traversal.
- `trace_average_ms/trace_median_ms`: 100 repeated leaf probes within each trial. The original probe is a flat permission lookup; the corrected probe verifies local signed grant ancestry. These are different assurance levels, not two equivalent implementations of a full blockchain trace. Repeated probes in a trial are not independent research subjects.

The repeated probes use the implementation's bounded retained-signature recovery cache after setup/before-state checks. They are warm-path timings, not cold cryptographic verification or network proof-fetch benchmarks.

The experiment measures **local enforcement**, with no blockchain transactions or network latency in the timed policy calls. On-chain transitive validity is verified separately by `GrantAuthority.sol` tests and real signed HTTP/WebSocket/local-EVM integration tests. The extension is root-attested: the Python layer verifies retained delegator signatures, while the contract validates immutable parent links, scope and time/status. Existing Sepolia did not receive this extension.

Local decommissioning can deny before an on-chain revocation transaction is submitted. Conversely, the final governance decision also requires independent blockchain verification; a local permission lookup alone is never sufficient for a live accepted action. No automatic universal synchronization of all out-of-band administrative actions or retrospective migration of public credentials is claimed.

## Results and artifacts

Completed measured results appear in [RESULTS_AND_DISCUSSION.md](RESULTS_AND_DISCUSSION.md):

- `raw/experiment2_depths.csv`: original/corrected depth comparison.
- `raw/experiment2_independent_paths.csv`: independent-path preservation.
- `raw/experiment2_manifest.json`: environment, parameters, source/output hashes and completion time.
- `raw/aggregated_experiment2.csv`: exact totals and per-depth timing summaries.
- `figures/experiment2_revocation.{svg,pdf,png}`: retention, revocation cost and distinct tracing semantics.

Superseded preliminary CSVs remain under `raw/prior/` and are excluded from final aggregates. Finite four-agent topology results do not establish arbitrary-scale revocation performance or eliminate the need for trusted enforcement storage.

## Completed numeric results

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

Interpretation, binary metric definitions, run provenance and limitations: [RESULTS_AND_DISCUSSION.md](RESULTS_AND_DISCUSSION.md).
