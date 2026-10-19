# Experiment 3: controlled authorization security matrix

## Question and execution boundary

Does the corrected implementation enforce the tested identity, delegation, time-validity, proof and revocation properties?

`backend/research/experiment3.py` executes 18 defined case groups ten times in fresh isolated signing/policy fixtures. It invokes production request authentication, grant creation, ancestry checks, Merkle verification and the existing Isolation Forest scorer as appropriate. Setup/key generation are outside operation timers. No client identity is accepted because it has a privileged name.

This is a **controlled component-composition security experiment**, not 180 public users, 180 distinct attack techniques, an Internet penetration test, or a full HTTP governance evaluation for every row. Genuine signed HTTP/WebSocket positive and negative workflows, actual registered local wallets, anchored grant ancestry, persistence and final governance decisions are tested independently by `GrantAuthorityIntegrationTests`. Existing saved Sepolia decisions are replayed/verified separately and are not used as evidence that corrected policies passed these new cases.

## Cases and expected outcomes

| Case | Controlled construction | Expected |
| --- | --- | --- |
| Legitimate direct | Genuine A signature and valid root-issued P | ALLOW |
| Legitimate delegated | Genuine B signature, valid Root -> A -> B path | ALLOW |
| Legitimate root grant | Genuine authorized root signs exact grant | ALLOW |
| Unauthorized request | D signs but has no P path | BLOCK |
| Missing permission | A requests an ungranted scope | BLOCK |
| Expired credential | Genuine finite grant; controlled clock advances beyond expiry | BLOCK |
| Not yet issued | Action-time check precedes genuine grant issuance | BLOCK |
| Privilege escalation | Authenticated non-root D attempts root issuance | BLOCK |
| Root impersonation | D's key signs a message claiming ROOT_AUTHORIZER | BLOCK |
| Replayed authentication | An already consumed valid envelope is reused | BLOCK |
| Unauthorized delegation | D delegates a scope it does not possess | BLOCK |
| Self-delegation | A attempts to delegate P to itself | BLOCK |
| Revoked agent | Decommissioned A requests P | BLOCK |
| Invalid intermediate | C requests P after B's authority is revoked | BLOCK |
| Tampered credential metadata | Stored expiry altered without re-signing | BLOCK |
| Forged proof | Valid original proof checked first; record then altered | BLOCK |
| Scope creep | Fresh score of a saved synthetic anomaly with an independently validated allowed scope/path | REVIEW |
| Post-decommission | Activity after A decommissioning | BLOCK |

The expired test advances an isolated clock instead of depending on arbitrary sleeps. The not-yet-issued case separately checks historical issuance. The scope-creep case reuses one existing synthetic feature sample and freshly computes its score; ten repetitions are **not** ten new ML anomaly samples. Revoked-agent and post-decommission rows exercise closely related negative policy behavior and must not be portrayed as statistically independent threat classes.

## Metric definitions

There are 30 legitimate operations, 140 attack attempts and ten behavioral-anomaly requests in the prescribed matrix. For binary metrics, **attack is the positive class**:

```text
TP = attack attempts blocked
FN = attack attempts allowed (or otherwise not blocked)
FP = legitimate operations not allowed
TN = legitimate operations allowed
attack-blocking rate / recall = TP / (TP + FN)
false rejection rate = FP / (FP + TN)
precision = TP / (TP + FP)
F1 = 2 * precision * recall / (precision + recall)
```

The ten expected REVIEW outcomes are reported separately and excluded from this binary confusion matrix. These rates characterize only the supplied controlled cases. They are not a population attack detection rate, confidence bound, model precision/recall on real traffic, or proof of universal security.

Authorization latency is measured around the selected operation, including actual signature/nonce/state work where invoked and proof/model work for the corresponding cases. It excludes fixture setup. Operations differ, so per-case timing is more informative than the mixed aggregate. The paper must not describe this aggregate as production end-to-end latency or public-chain confirmation time.

## Before/after and artifacts

`experiment3_before_after.csv` compares ten unauthenticated original root-issuance attempts with ten corrected root-impersonation attempts signed using D's key. Both express unauthorized root issuance intent, although the corrected interface necessarily introduces a signature envelope. The exact string-spoofing reproduction is also a permanent test. Cascading-revocation before/after results are in Experiment 2; this experiment does not invent an original-system result for every new case.

Final measured counts, operation timings and confusion matrix appear in [RESULTS_AND_DISCUSSION.md](RESULTS_AND_DISCUSSION.md):

- `raw/experiment3_requests.csv`: every case, repetition, expected/actual outcome and latency.
- `raw/experiment3_before_after.csv`: original/corrected root issuance behavior.
- `raw/experiment3_manifest.json`: run provenance and source/output hashes.
- `raw/aggregated_experiment3.csv` and `results_summary.json`: recalculated metrics.
- `figures/experiment3_security_matrix.{svg,pdf,png}`.

The experiment aborts on an unexpected corrected outcome; a partial/RUNNING manifest is not a successful completed trial. Preliminary outputs are retained under `raw/prior/` rather than silently replaced or included in final totals.

## Completed numeric results

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

Interpretation, binary metric definitions, run provenance and limitations: [RESULTS_AND_DISCUSSION.md](RESULTS_AND_DISCUSSION.md).
