# ChainGuard-AI: Final End-to-End Evaluation

Canonical contract: `0x0B1a87021ec75fBaE919b1e86b2B1335FFC8F4d3` (chain 31337).
Scenarios: 21; attack/anomaly coverage: 100.00%.

## Scenario verdicts

| Scenario | Actor | Expected | Authorized | Drift | Trace | Revoked | Chain | Decision | Detected by | Resolution ms |
|---|---|---|---:|---:|---|---:|---:|---|---|---:|
| CHECK_READ_CATALOG | Agent_A | BLOCKED_CHECK | False | True | UNAUTHORIZED_ROOT | False | True | BLOCK | Module1, Module3, Module4 | 256.38 |
| CHECK_PROCESS_PAYMENT | Agent_B | BLOCKED_CHECK | False | True | UNAUTHORIZED_ROOT | False | True | BLOCK | Module1, Module3, Module4 | 236.67 |
| CHECK_VERIFY_ORDER | Agent_C | BLOCKED_CHECK | False | True | UNAUTHORIZED_ROOT | True | True | BLOCK | Module1, Module3, Module4 | 726.07 |
| CHECK_CREATE_AGENT | Agent_D | BLOCKED_CHECK | False | True | UNAUTHORIZED_ROOT | False | True | BLOCK | Module1, Module3, Module4 | 221.17 |
| ROOT_PERMISSION_GRANTED | ROOT_AUTHORIZER | ROOT_ADMIN | True | False | VALID_CHAIN | False | True | ALLOW | None | 293.99 |
| DELEGATE_CREATE_AGENT | Agent_A | LEGITIMATE | True | True | VALID_CHAIN | False | True | REVIEW | Module4 | 548.07 |
| DELEGATE_CREATE_AGENT | Agent_B | LEGITIMATE | True | True | VALID_CHAIN | False | True | REVIEW | Module4 | 614.49 |
| SELF_ESCALATION | Agent_D | ATTACK | False | True | UNAUTHORIZED_ROOT | False | True | BLOCK | Module1, Module3, Module4 | 240.51 |
| UNAUTHORIZED_DELEGATION | Agent_D | ATTACK | False | True | BROKEN_CHAIN | False | True | BLOCK | Module1, Module3, Module4 | 211.86 |
| AGENT_DECOMMISSIONED | ROOT_AUTHORIZER | ROOT_ADMIN | True | False | VALID_CHAIN | False | True | ALLOW | None | 559.13 |
| POST_DECOMMISSION_ACTIVITY | Agent_C | ATTACK | False | True | AUTHORITY_REVOKED_AT_TIME_OF_ACTION | True | True | BLOCK | Module1, Module3, Module4, Module5 | 1149.31 |
| NORMAL | Agent_B | NORMAL | True | False | VALID_CHAIN | False | True | ALLOW | None | 262.41 |
| NORMAL | Agent_B | NORMAL | True | False | VALID_CHAIN | False | True | ALLOW | None | 242.98 |
| NORMAL | Agent_D | NORMAL | True | False | VALID_CHAIN | False | True | ALLOW | None | 263.00 |
| NORMAL | Agent_B | NORMAL | True | False | VALID_CHAIN | False | True | ALLOW | None | 275.12 |
| NORMAL | Agent_D | NORMAL | True | False | VALID_CHAIN | False | True | ALLOW | None | 247.92 |
| SCOPE_CREEP | Agent_B | ANOMALY | True | True | VALID_CHAIN | False | True | REVIEW | Module4 | 382.02 |
| SCOPE_CREEP | Agent_B | ANOMALY | True | True | VALID_CHAIN | False | True | REVIEW | Module4 | 361.75 |
| SCOPE_CREEP | Agent_B | ANOMALY | True | True | VALID_CHAIN | False | True | REVIEW | Module4 | 357.43 |
| SCOPE_CREEP | Agent_B | ANOMALY | True | True | VALID_CHAIN | False | True | REVIEW | Module4 | 342.68 |
| SCOPE_CREEP | Agent_B | ANOMALY | True | True | VALID_CHAIN | False | True | REVIEW | Module4 | 319.99 |

## Pipeline latency

| Step | Average ms | Worst ms |
|---|---:|---:|
| authorization_ms | 0.01 | 0.02 |
| trace_context_ms | 190.46 | 494.76 |
| drift_scoring_ms | 35.98 | 66.41 |
| revocation_check_ms | 92.65 | 464.87 |
| chain_verification_ms | 67.09 | 438.90 |
| verdict_assembly_ms | 0.00 | 0.01 |
| TOTAL | 386.33 | 1149.31 |

Measured average bottleneck: **trace_context_ms**.

## Existing module metrics

### Module 2: blockchain

```json
{
  "registered_identities": 5,
  "credentials_issued": 7,
  "delegations_anchored": 2,
  "revocations_anchored": 1,
  "action_hashes_anchored": 11,
  "proofs_verified": 14,
  "proofs_total": 14,
  "anchoring_latency_average_ms": 2579.6290714285715,
  "anchoring_latency_worst_ms": 3711.2180000000003,
  "anchoring_latency_total_ms": 36114.807,
  "contract_address": "0x0B1a87021ec75fBaE919b1e86b2B1335FFC8F4d3",
  "chain_id": 31337
}
```

### Module 3: tracing

```json
{
  "test_count": 5,
  "correctly_classified": 5,
  "delegation_trace_accuracy": 1.0,
  "average_trace_latency_ms": 236.3771199976327,
  "worst_case_trace_latency_ms": 486.689799989108
}
```

### Module 4: anomaly detection

```json
{
  "isolation_forest": {
    "precision": 0.8518518518518519,
    "recall": 0.9583333333333334,
    "f1": 0.9019607843137255,
    "confusion_matrix": [
      [
        280,
        20
      ],
      [
        5,
        115
      ]
    ],
    "false_positive_rate": 0.06666666666666667,
    "per_category": {
      "POST_DECOMMISSION_ACTIVITY": {
        "count": 30,
        "recall": 1.0
      },
      "SCOPE_CREEP": {
        "count": 30,
        "recall": 1.0
      },
      "SELF_ESCALATION": {
        "count": 30,
        "recall": 0.8333333333333334
      },
      "UNAUTHORIZED_DELEGATION": {
        "count": 30,
        "recall": 1.0
      }
    }
  },
  "rule_baseline": {
    "precision": 1.0,
    "recall": 0.75,
    "f1": 0.8571428571428571,
    "confusion_matrix": [
      [
        300,
        0
      ],
      [
        30,
        90
      ]
    ],
    "false_positive_rate": 0.0,
    "per_category": {
      "POST_DECOMMISSION_ACTIVITY": {
        "count": 30,
        "recall": 1.0
      },
      "SCOPE_CREEP": {
        "count": 30,
        "recall": 0.0
      },
      "SELF_ESCALATION": {
        "count": 30,
        "recall": 1.0
      },
      "UNAUTHORIZED_DELEGATION": {
        "count": 30,
        "recall": 1.0
      }
    }
  },
  "latency": {
    "average_ms": 44.57129547646175,
    "worst_case_ms": 111.5871999936644,
    "feature_average_ms": 0.8234016671069965,
    "scoring_average_ms": 43.74789380935475
  },
  "dataset": {
    "normal_count": 2000,
    "attack_counts": {
      "SELF_ESCALATION": 30,
      "UNAUTHORIZED_DELEGATION": 30,
      "POST_DECOMMISSION_ACTIVITY": 30,
      "SCOPE_CREEP": 30
    },
    "train_normal_count": 1400,
    "validation_normal_count": 300,
    "test_normal_count": 300
  },
  "threshold": 0.05470855580990606
}
```

### Module 5: revocation

```json
{
  "post_revocation_attempts": 2,
  "caught_by_realtime": 1,
  "caught_by_audit": 2,
  "caught_by_either": 2,
  "revocation_completeness": 1.0,
  "public_lookup_latency_ms": 132.9069999968245,
  "public_lookup_samples_ms": [
    280.2683999907458,
    56.39759999758098,
    62.0550000021467
  ],
  "revocation_to_proof_latency_ms": 847.3519000108354,
  "proof_verification": true
}
```

## Test results

```json
{
  "source_fingerprint": "9d0b413f3b654cab60eb5bf1d24a1f1f2191892b81e74ddd52d4c4113f2d262a",
  "contract_compile": {
    "passed": true,
    "result": "Hardhat: no contracts to compile"
  },
  "contract_tests": {
    "passed": true,
    "test_count": 1
  },
  "python_tests": {
    "passed": true,
    "test_count": 48
  },
  "module1_demo": {
    "passed": true,
    "attack_attempts": 3,
    "blocked_attacks": 3,
    "detection_rate_percent": 100.0
  },
  "integration_scenarios": {
    "scenario_count": 21,
    "scenario_assertions_passed": true
  }
}
```

## Known limitations

- Behavioral evaluation uses a reproducible synthetic dataset, not production traffic.
- The registry runs on a local Hardhat chain without production consensus.
- The prototype has four agents and one root authority.
- Module 4 SELF_ESCALATION recall is below 100% on its held-out set.
- Only full-agent revocation is supported.
- These results do not establish production detection or latency performance.
