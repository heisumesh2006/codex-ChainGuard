# Self-escalation recall audit

Run `module2/.venv/Scripts/python.exe -m module4.diagnose` from the project root to reproduce the held-out scores. The script loads the persisted model, synthetic actions, and separate ground truth. It does not fit or calibrate the model. Exact feature values and comparisons are saved in `data/self_escalation_diagnostics.json`.

The threshold is **0.054709**, set at the 95th percentile of normal validation scores before evaluation. Higher scores indicate more anomalous behavior. Five of 30 self-escalation samples fell just below it:

| Source ID | Score | Margin below threshold | Recent same action / 20 | Permission ratio | Burst per minute | Log seconds since prior action |
|---|---:|---:|---:|---:|---:|---:|
| synthetic:002081 | 0.053208 | 0.001500 | 10 | 1.00 | 0.00 | 7.140 |
| synthetic:002033 | 0.053133 | 0.001576 | 10 | 1.00 | 0.00 | 6.407 |
| synthetic:002105 | 0.052335 | 0.002374 | 10 | 1.00 | 0.00 | 7.360 |
| synthetic:002109 | 0.053774 | 0.000934 | 10 | 1.00 | 0.00 | 7.353 |
| synthetic:002065 | 0.054530 | 0.000179 | 10 | 1.00 | 0.00 | 6.676 |

All five had `authorization_invalid=1`, `role_scope_deviation=1`, delegation depth 0, action `SELF_ESCALATION_ATTEMPT`, permission `CREATE_AGENT`, and target pattern `agent`. Their recent permission ratio of 1.00 and switch rate of 0 arose because the synthetic self-escalation and unauthorized-delegation events alternate with the same requested permission. Those two recent-history values also resemble stable normal behavior. No false negative had a short burst.

For comparison, detected `synthetic:002057` scored **0.166595** with burst rate **0.40/min** and log recency **1.792**. A detected nonburst sample, `synthetic:002085`, scored **0.057159** with burst rate 0. The closest preceding held-out Agent_D normal action, `synthetic:001995`, scored **-0.060796**; it used `VERIFY_ORDER`, had valid authority, no role deviation, and burst rate 0. Among all 25 detected self-escalation samples, score median was **0.105685**; among the five misses it was **0.053208**; among 75 held-out Agent_D normals it was **-0.068350**.

The encoder was fitted on normal actions only. `SELF_ESCALATION_ATTEMPT` and target pattern `agent` are unseen categories and are encoded as all zero by `OneHotEncoder(handle_unknown="ignore")`. This is the configured unknown-category behavior, not a missing feature. The numeric invalid-authority and role-deviation values remain present after preprocessing. Normal training has 1,400 records; its invalid-authority feature is constant zero, and `StandardScaler` uses scale 1 for that feature. The misses are a **score/threshold boundary effect**, helped by overlapping recent-history features. They do not indicate that Module 3 considered the actions valid. A hard authorization rule still identifies all 30 self-escalation attempts.

No feature or threshold was changed using held-out labels. Final held-out recall remains: self-escalation **25/30 (83.33%)**, unauthorized delegation **30/30 (100%)**, post-decommission activity **30/30 (100%)**, and independently measured valid-chain scope creep **30/30 (100%)**. This reproducible synthetic experiment is limited evidence for operational performance; the statistical model should not replace the authority check.
