# ChainGuard-AI live Chrome end-to-end QA

## Result and provenance

PASS for the tested implemented workflows. This is a scoped QA result, not a claim that the application is completely bug-free or production certified.

- Completed UTC: 2026-10-18T17:01:46.498669+00:00.
- Branch: `research/security-evaluation`. HEAD: `de1f7d5c4369639306c1e1bd7b5ecb5686bd7ec0`. All fixes in this report remain uncommitted.
- Main remains at `c026d5b8c7c2959937d49145571c2694d59ff674`; no branch changes, commits, pushes, merges or public deployments were performed.
- Actual Chrome extension connection, browser provider `1`, was the primary interactive test surface. Initial application tab: `574731838`; final recovery tab: `574731911`, in the same connected Chrome. Connector stalls/detachments were recovered without replacing primary verification with headless tests.
- Windows PowerShell; application virtual environment Python 3.14.0; Node v24.15.0. The helper used for some file inventories was the separate system Python 3.10.11.
- Frontend `http://localhost:5173`; backend `http://127.0.0.1:8001`; local RPC `http://127.0.0.1:8545`; chain ID 31337.
- Final local registry: `0x01fd4C7C545e628c9a000543d6fB3a96ffF4c40d`. Temporary local registries changed during necessary backend restarts. Earlier screenshots therefore legitimately show different local addresses. None are Sepolia deployments.
- Final health: API ONLINE, RPC connected, contract available, saved Isolation Forest model available. Actual HTTP page loading and WebSocket stage events establish the frontend API/WS connection to port 8001; no CORS failure was observed.

## Coverage totals

- Nine business pages plus the additional unknown-route view.
- 121 application controls/interaction positions, defined in [CONTROL_INVENTORY.md](CONTROL_INVENTORY.md). Repeated clicks are not counted again. Browser history, reload and page scrolling are additional checks.
- All six requested journeys exercised. Fresh signed evaluation is distinct from the saved five-scenario replay.
- Eleven findings addressed, with ten new Python tests and six new targeted browser cases.
- 85 genuine Chrome JPEG screenshots under [screenshots/](screenshots/). No generated or fabricated UI images.

## Page-by-page Chrome results

| Page | Result | Verified interactions/data |
|---|---|---|
| Dashboard | PASS | Registered-agent/scope inventory, five navigation/report links, saved decision/ML provenance, connected Hardhat status; absent timings remain unavailable. |
| Agents | PASS | Four registered agents; all four details expand/collapse controls, roles, scope and credential displays; Agent_C has no effective permissions. Automated assertions additionally verify every returned credential row. |
| Trust Graph | PASS | Five nodes, seven local evidence links; every edge and node selected; zoom in/out, fit and actual pointer pan; source/target details; trace selectors/actions; current revoked links distinguished from verified historical proofs. |
| Live Governance | PASS | Five saved scenario buttons, measured-stage animation, verdicts, timeline, controls, explicit signed-envelope form, malformed input, unsigned rejection, valid registered signature, replay rejection. |
| Threat Lab | PASS | All five cards, explanation dialogs, Close/Cancel/Open pipeline, Start auto demo; saved evidence replay produces no new records. |
| ML Analytics | PASS | Persisted synthetic held-out model metrics, category recall, confusion matrix and dataset description. No model retraining or new research metrics. No filter controls exist on this read-only page. |
| Revocation | PASS | Actual chain lookups for Agent_A/B/D ACTIVE, Agent_C REVOKED, Unknown_Agent not found; revocation receipt, reason, timestamps and public proof fields. No canonical agent was revoked by this QA. |
| Evaluation | PASS | ALLOW/REVIEW/BLOCK filters returned 1/1/3 rows, ALL restored five; seven architecture descriptions, Auto Demo link, selected-network provenance and unavailable timing labels. |
| Blockchain Audit | PASS | Refresh, local network/chain/contract, one five-record sealed batch, detail drawer, seventeen copy positions, all five original and altered proof checks; no public explorer link is offered on Hardhat. |
| Unknown route | PASS after fix | Blank-page reproduction replaced by Page not found and working dashboard recovery. |

## User journeys

| Journey | Result | Evidence |
|---|---|---|
| A: Dashboard -> Agents -> Graph -> Governance -> Evaluation | PASS | Direct navigation links, loaded pages, details and report controls exercised in Chrome. |
| B: Threat Lab -> Normal -> pipeline -> verdict -> audit | PASS | Card/dialog Open live pipeline, actual ALLOW verdict, then audit evidence inspection. |
| C: Audit -> record -> proof -> verify -> transaction/batch details | PASS | Five originals VERIFIED; five modified copies TAMPERED; roots, block and transaction references inspected in the batch drawer. |
| D: Agents -> delegation -> revocation -> authority | PASS | Agent_C cleared scope/REVOKED state, graph node and revoked link details; current status and historical acquisition traced separately. |
| E: Auto Demo -> pause -> resume -> next -> complete -> restart | PASS | Real animation states and final Post-revocation BLOCK with automatic controls removed. Complete sequences also asserted by the 24-case suite. |
| F: Fresh signed action -> all stages -> decision -> audit | PASS | Actual registered Agent_B signature submitted through Chrome, authorization ALLOWED, VALID_CHAIN, ML flag, REVIEW and one new disposable AuditRecord. Reusing its envelope showed AUTHENTICATION_REPLAYED and record count stayed six. |

The fresh signed case used an earlier disposable local registry during this session. Its record was `audit:2cdc6d5ecab6482facb9206406460aad`. The model score was 0.071 (display precision), so REVIEW was correct despite valid authority; no ALLOW result was forced. Displayed total pipeline time was 1720.33 ms for that single request, not a performance benchmark. The authentication textarea cleared after submission and was empty in its screenshot. Neither a private key nor a new HTTP signing service was introduced. Local Hardhat's unlocked signing RPC remains a trusted development fixture, not a production key-isolation guarantee.

## Findings and fixes

| Finding | Severity | Problem | Final status |
|---|---|---|---|
| QA-01 | P1 | Local scenarios failed although the chain was online | FIXED / retested |
| QA-02 | P1 | Valid local audit proof incorrectly reported VERIFY FAILED | FIXED / retested |
| QA-03 | P2 | Safe missing-evidence/authentication codes were obscured | FIXED / retested |
| QA-04 | P2 | Local evidence described as Sepolia | FIXED / retested |
| QA-05 | P2 | Paused or unfinished animation showed PIPELINE COMPLETE | FIXED / retested |
| QA-06 | P2 | Clipboard denial was silent | FIXED / retested |
| QA-07 | P2 | Graph proof labels selected a node or overlapped | FIXED / retested |
| QA-08 | P2 | Transient Windows rename denial aborted persistence | FIXED / retested |
| QA-09 | P1 | No legitimate signed-action workflow in the dashboard | FIXED / retested |
| QA-10 | P2 | Graph current revocation presentation relied on local status | FIXED / retested |
| QA-11 | P2 | Unknown frontend route rendered a blank page | FIXED / retested |

### QA-01: Local scenarios failed although the chain was online

- Reproduction: Run Normal action on the initial disposable server: pending stages and RPC_UNAVAILABLE / redacted error.
- Root cause: Demo startup deployed trust evidence but no batched AuditRecords.
- Fix: Startup now evaluates five genuine local fixtures and anchors their Merkle batch before serving. Canonical data is untouched.
- Files: `backend/api/demo_server.py`.
- Retest: Five manual verdicts, Auto Demo and all original/tampered local proofs passed.

### QA-02: Valid local audit proof incorrectly reported VERIFY FAILED

- Reproduction: Select an original local audit action; calculated and on-chain roots matched but verification failed.
- Root cause: Independent proof validation read the canonical deployment outside the disposable registry context.
- Fix: Keep proof GET/POST and batch verification within the selected deployment context and service lock.
- Files: `backend/api/services.py`.
- Retest: Originals VERIFIED, copies TAMPERED; context-restoration regression added.

### QA-03: Safe missing-evidence/authentication codes were obscured

- Reproduction: Initial failed scenario displayed RPC_UNAVAILABLE: [REDACTED].
- Root cause: Opaque-token protection treated long trusted diagnostic codes as credentials.
- Fix: Explicit safe-code allowlist preserves controlled diagnostics; arbitrary messages still pass through secret sanitization.
- Files: `backend/core/blockchain/diagnostics.py`.
- Retest: Focused diagnostics and full security suite passed; invalid authentication and replay codes visible in Chrome.

### QA-04: Local evidence described as Sepolia

- Reproduction: Open Evaluation with Hardhat chain 31337 and persisted-profile evidence.
- Root cause: Profile-based evidence was assumed to mean Sepolia in UI explanatory text.
- Fix: Use selected-network provenance and network-neutral limitations; do not invent absent timings.
- Files: `frontend/src/pages/Evaluation.jsx; backend/core/governance/runtime_evidence.py`.
- Retest: Hardhat labels and unavailable timings verified in Chrome; provenance regression passed.

### QA-05: Paused or unfinished animation showed PIPELINE COMPLETE

- Reproduction: Pause Auto Demo with pipeline stages still pending.
- Root cause: Header used backend completion before the frontend replay had finished.
- Fix: Display PAUSED / REPLAYING until the visible stages complete.
- Files: `frontend/src/pages/Governance.jsx`.
- Retest: Pause, resume, Next, restart and automatic completion tested; status regression passed.

### QA-06: Clipboard denial was silent

- Reproduction: Exercise copy controls where clipboard access is denied; previous catch only reset success state.
- Root cause: Denied clipboard writes had no actionable feedback.
- Fix: Show the full public value for manual copying after denial and never show a false Copied success.
- Files: `frontend/src/pages/AuditExplorer.jsx`.
- Retest: Seventeen copy positions exercised; explicit denial regression passed. Native clipboard readback remains a connector limitation.

### QA-07: Graph proof labels selected a node or overlapped

- Reproduction: At laptop size, click READ_CATALOG proof: Agent_A identity opened instead.
- Root cause: Long root edges passed behind nodes and some permission labels shared positions.
- Fix: Separate label positions, raise their interaction layer and stop drag/pan propagation.
- Files: `frontend/src/pages/TrustGraph.jsx`.
- Retest: All seven local labels opened their own proof drawers at desktop and laptop sizes.

### QA-08: Transient Windows rename denial aborted persistence

- Reproduction: First full run: ten-hop trace failed with WinError 5 replacing its isolated JSON snapshot.
- Root cause: Windows can briefly deny replacement despite the cooperating-process lock.
- Fix: Retry only Windows access/sharing errors for a bounded 0.63 seconds; permanent failure retains prior committed bytes and propagates.
- Files: `backend/core/blockchain/persistence.py`.
- Retest: Transient/permanent-denial tests, full 318-test suite and 500-action stress passed.

### QA-09: No legitimate signed-action workflow in the dashboard

- Reproduction: The governance page only offered saved-scenario replay, while fresh API actions required signatures.
- Root cause: Missing frontend signed-envelope submission; original local demonstration realm differed from the registered verifier realm.
- Fix: Add explicit action/envelope JSON submission, no signing endpoint; provision disposable local policy through genuine registered-wallet signatures at startup only.
- Files: `frontend/src/pages/Governance.jsx; frontend/src/hooks/useGovernanceStream.js; backend/api/demo_server.py`.
- Retest: Real Chrome fresh request: authorized, VALID_CHAIN, REVIEW, one persisted record; replay rejected without another record.

### QA-10: Graph current revocation presentation relied on local status

- Reproduction: Agent_C was revoked while its historical root/delegation proof labels remained green and lacked a current-revocation warning.
- Root cause: Historical proof validity and current revocation were not consistently represented separately.
- Fix: Read node revocation from the selected contract; mark links involving revoked agents/credentials and explain that historical proof validity is not current authority.
- Files: `backend/api/services.py; frontend/src/pages/TrustGraph.jsx; frontend/src/styles/identity.css`.
- Retest: Two revoked local links shown; revoked-link drawer warning captured; stale-local-state regression passed.

### QA-11: Unknown frontend route rendered a blank page

- Reproduction: Navigate to /qa-route-does-not-exist in actual Chrome.
- Root cause: Router had no wildcard view.
- Fix: Add a small Page not found view with a dashboard recovery link.
- Files: `frontend/src/App.jsx`.
- Retest: Before/after screenshots, Chrome recovery click and targeted regression passed.

## Automated regression results

| Check | Final result | Evidence |
|---|---|---|
| Python compilation | PASS | `.venv/Scripts/python.exe -m compileall -q backend` |
| Complete Python suite | 318/318 PASS; zero failures/errors/skips, 466.993 s | `.runtime/live-chrome-python-final-318.log` |
| New startup/isolation/status/persistence tests | 10/10 PASS, overlapping full suite | `.runtime/live-chrome-demo-final-tests.log`; do not add these to 318 |
| Focused diagnostics/safety run | 31/31 PASS, overlapping cases | `.runtime/live-chrome-safety-focused.log` |
| Solidity compilation | PASS | `npm run compile` reported no contracts needing recompilation |
| Contract/network tests | 11/11 PASS; zero skipped | `npm run test:contract`, recorded tool output; contract source unchanged |
| Merkle checks | 83/83 PASS | Final read-only verifier, `.runtime/LIVE_CHROME_PUBLIC_VERIFICATION.json` |
| API matrix | 29/29 PASS | Same final verifier, including negative evidence cases |
| Existing browser suite | 24/24 PASS | `.runtime/live-chrome-playwright.log`; `.runtime/live-chrome-browser-baseline-results.json` |
| Final targeted browser regressions | 6/6 PASS | `.runtime/live-chrome-local-browser-verified.log`; `.runtime/live-chrome-local-browser-results.json` |
| Frontend final production build | PASS, 27.94 s | `.runtime/live-chrome-build-final.log` |
| Secret scan and whitespace | PASS | Final configured-secret scan; `git diff --check` |

The 24 existing browser cases used the enforced read-only Sepolia fixture. The six targeted final cases used the actual running disposable Hardhat app, via `frontend/playwright.local-qa.config.js`. These are 30 distinct cases across two runs, not a fabricated single 30-case run. Supplementary tests used the configured Edge browser; the interactive screenshots and UI claims above came from connected Chrome.

### Cross-process stress

Final full-suite stress: ten OS worker processes, 500 distinct successful actions, 500 persisted records, ten deliberate duplicate rejections, zero persisted duplicate IDs, zero lost successful actions, 100 batches and 500 consistent mappings. JSONL and snapshot integrity and deterministic Merkle construction passed. Time: 124.20404 s. Four bounded lock timeouts were explicitly retried safely. Raw results: `.runtime/LIVE_CHROME_STRESS_VERIFIED.json`.

### Failed attempts retained, not counted as passes

- Initial sandbox runs could not use temporary lock files or spawn esbuild; normal Windows process permissions were needed. Logs are retained, including `.runtime/live-chrome-frontend-build-sandbox.log`.
- The first 308-case run had one WinError 5 atomic-replacement error. The bounded Windows-only replacement retry and permanent-failure tests address that failure.
- A 313-case run had one stress worker-result timeout (`queue.Empty`) under concurrent work. The exact scheduling cause is not established; it was not hidden or counted as successful. The later 315- and final 318-case full runs passed all assertions, including full 500-action integrity checks. This does not prove that arbitrary host overload can never exceed a test deadline.
- An early targeted browser server startup exceeded 120 seconds. A subsequent public-fixture targeted run passed three cases and failed two new test assumptions: it expected seven links although that saved Sepolia graph has five, and expected AUTHENTICATION_REQUIRED for an empty object although the server correctly returns INVALID_AUTHENTICATION. Tests now derive the link count from actual API evidence and assert the correct rejection code. All six final targeted local cases pass, without weakening the all-links/proof assertions.
- Chrome connector deadlines/temporary detachment interrupted a few captures; a fresh tab in the same Chrome extension connection recovered control. Interrupted attempts are not represented as extra successful measurements.

## Responsive and visual checks

Actual viewports: 1920 x 1080, 1366 x 768, 768 x 1024 and 390 x 844. Mobile navigation open, close icon and backdrop close were exercised. Signed JSON fields were also inspected open on mobile and tablet, with no horizontal page overflow.

`.runtime/LIVE_CHROME_RESPONSIVE.json` contains 34 recorded page/viewport overflow samples, all with overflow false. Laptop Agents and Graph were additionally captured/visually inspected; the attempted final logging of those two extra rows was interrupted, so no invented 36-row result is claimed. Graph pointer pan changed the viewport transform by +60/+40 pixels; fit reset and upward page scrolling were verified. Temporary viewport overrides were cleared; the final Chrome viewport returned to 1536 x 674.

Screenshots include initial, failure and final states. Some early captures contain loading states, expected offline banners during necessary backend restarts, or an older disposable local registry. Use `final-*` and `signed-action-success-final.jpg` for final presentation evidence. Historical timing metrics are unavailable where not persisted; shared ML benchmark values are explicitly synthetic and were not relabelled as live measurements.

## Console, HTTP and negative paths

Final recovered Chrome session: zero captured console errors; six warnings originated from the installed MetaMask extension (`chrome-extension:`), not project application scripts. Earlier planned backend restarts produced genuine unavailable/retry states; the UI did not keep a fake online network label. Final local page/API responses were healthy and no unexpected HTTP 500 was observed in the recorded final matrices/browser suites.

Chrome directly displayed controlled missing-record/proof and missing-batch responses; server logs confirm 404. Unknown frontend route recovery, malformed JSON, invalid authentication and signature replay were exercised interactively. Missing/altered/expired credentials, wrong network, forged identity/proofs, revocation ancestry, failed writes, receipt uncertainty and provider-secret regressions additionally passed in the full Python suite. Safe forced network-failure/retry and malformed/early-close WebSocket cases passed in the supplementary browser suite.

The connector exposes console logs but no complete HAR/network interception feed. Chrome console and live backend request logs were inspected; comprehensive per-response network capture comes from supplementary tests. A complete Chrome HAR is therefore BLOCKED by tool capability, not reported as passed. Native clipboard byte-for-byte readback was not independently confirmed through the connector. Positive control clicks and graceful denied-copy feedback are distinguished from a claim of native clipboard readback.

## Public evidence and data integrity

Final verification UTC: `2026-10-18T16:52:02.579870+00:00`. Sepolia chain 11155111, contract `0x61c74D0525f4f5A1a7b20f2eA561e485E71dd243`, root `0xee6028db0fb103cc0c5e1685e586b24d9213515a806aa9717f3ed0b54341006c`, transaction `0xae52c353001ff8754625054d8873eeda0b74b1702af775da3e6a4cd4d33b75c2`. Existing batch: five records.

Governance outcomes in requested order: **ALLOW, BLOCK, BLOCK, REVIEW, BLOCK**. Five originals VERIFIED; five altered copies TAMPERED, both in read-only public verification and independent local Chrome proof interactions. No new public records or transactions were created. Public RPC submission/signing methods were blocked in the verification harness.

All 110 protected file hashes stayed unchanged: eight canonical public evidence files plus 102 research-evaluation documents/data/figures. Original research data, plots, manifests and the existing ZIP were not rewritten. The fitted model was not retrained or overwritten. Local synthetic sample timestamps and in-memory model history move together by whole days to fit a new credential issuance; source files remain unchanged. Old bootstrap actions that precede credential issuance intentionally return BROKEN_CHAIN in historical tracing. That rule was not relaxed to make old data pass.

## Remaining limitations and untested scope

- No unresolved reproducible P0/P1 defect remains in the tested implemented workflows. This does not establish global bug-freedom, production scalability or security certification.
- Browser-native production-wallet signing/key custody is NOT TESTED. The UI accepts an externally signed envelope; it never collects private keys or provides a signing endpoint. Local Hardhat signing is a trusted development oracle.
- Existing saved decisions are replayed historical evidence, not proof that every fresh action will receive the same verdict. The independent fresh signed request was authorized but correctly REVIEWed by ML.
- Below-threshold audit records can remain PENDING until the age/size sealer is invoked. Proof reads do not submit transactions. No automatic public anchoring or background signing service was added by this QA.
- Historical cryptographic proof validity is distinct from current effective authority. On-chain current revocation is now explicitly shown, and authenticated ancestry/cascading enforcement remains separately tested.
- Recovery of uncertain public transactions does not provide unconditional on-chain exactly-once delivery. Existing bounded recovery/claim tests pass; no public crash/submission experiment was performed.
- No public mutation, canonical-agent revocation, Sepolia deployment, real-funds operation, Safari/Firefox testing or new research experiment was performed. Unsupported search/filter/admin controls were not invented for read-only pages.
- A complete connected-Chrome HAR and native clipboard readback remain BLOCKED/NOT VERIFIED as described above. Some connector captures timed out and were recovered; no fake replacement screenshots were used.

## Modified files and Git safety

Source/test changes (all left available for review):

- `backend/api/demo_server.py`
- `backend/api/services.py`
- `backend/core/blockchain/diagnostics.py`
- `backend/core/blockchain/persistence.py`
- `backend/core/governance/runtime_evidence.py`
- `frontend/src/App.jsx`
- `frontend/src/hooks/useGovernanceStream.js`
- `frontend/src/pages/AuditExplorer.jsx`
- `frontend/src/pages/Evaluation.jsx`
- `frontend/src/pages/Governance.jsx`
- `frontend/src/pages/TrustGraph.jsx`
- `frontend/src/styles/identity.css`
- `frontend/tests/project.spec.js`
- `backend/api/tests/test_demo_startup.py`
- `frontend/playwright.local-qa.config.js`

New QA artifacts: this report, `CONTROL_INVENTORY.md`, `LIVE_CHROME_RESULTS.json`, and the actual JPEG screenshots under `screenshots/`. Supporting raw logs and short-lived test envelopes remain ignored under `.runtime/`; they must not be staged. `.env`, `frontend/.env.local`, disposable runtime directories and canonical Sepolia runtime files remain ignored. No files are staged.

Exact final short status (directory grouping as Git reports it):

```text
 M backend/api/demo_server.py
 M backend/api/services.py
 M backend/core/blockchain/diagnostics.py
 M backend/core/blockchain/persistence.py
 M backend/core/governance/runtime_evidence.py
 M frontend/src/App.jsx
 M frontend/src/hooks/useGovernanceStream.js
 M frontend/src/pages/AuditExplorer.jsx
 M frontend/src/pages/Evaluation.jsx
 M frontend/src/pages/Governance.jsx
 M frontend/src/pages/TrustGraph.jsx
 M frontend/src/styles/identity.css
 M frontend/tests/project.spec.js
?? "CHAIN GUARD AI FINAL IEEE RESEARCH PACK.zip"
?? backend/api/tests/test_demo_startup.py
?? docs/qa/
?? frontend/playwright.local-qa.config.js
```

The root research ZIP was already untracked before this task and remains untouched. No commits were created. Services remain running on 5173, 8001 and 8545 for inspection. The final Chrome tab is left on an original VERIFIED local audit proof.

## Reproduction commands

Run local services as documented in README, with CHAINGUARD_NETWORK=hardhat and CHAINGUARD_RPC_URL=http://127.0.0.1:8545. The demo server refuses a public profile or non-31337 chain.

```powershell
.venv/Scripts/python.exe -m compileall -q backend
.venv/Scripts/python.exe -m backend.testing.run_regression
.venv/Scripts/python.exe -m unittest backend.api.tests.test_demo_startup -v
```

From `blockchain/`: `npm run compile`, `npm run test:contract`.
From `frontend/`: `npm run build`, `npm exec playwright test -- --config playwright.local-qa.config.js`.
The existing `npm run test:browser` uses the read-only public fixture. Public network latency can make that run slow; no private keys are required for its evidence checks.

## Screenshot index

- [screenshots/agents-expanded.jpg](screenshots/agents-expanded.jpg)
- [screenshots/agents-initial.jpg](screenshots/agents-initial.jpg)
- [screenshots/analytics-initial.jpg](screenshots/analytics-initial.jpg)
- [screenshots/audit-batch-details-final.jpg](screenshots/audit-batch-details-final.jpg)
- [screenshots/audit-initial.jpg](screenshots/audit-initial.jpg)
- [screenshots/audit-original-verified.jpg](screenshots/audit-original-verified.jpg)
- [screenshots/audit-tampered-copy.jpg](screenshots/audit-tampered-copy.jpg)
- [screenshots/auto-demo-complete.jpg](screenshots/auto-demo-complete.jpg)
- [screenshots/auto-demo-paused.jpg](screenshots/auto-demo-paused.jpg)
- [screenshots/clipboard-feedback-final.jpg](screenshots/clipboard-feedback-final.jpg)
- [screenshots/dashboard-initial.jpg](screenshots/dashboard-initial.jpg)
- [screenshots/desktop-agents.jpg](screenshots/desktop-agents.jpg)
- [screenshots/desktop-blockchain-audit.jpg](screenshots/desktop-blockchain-audit.jpg)
- [screenshots/desktop-dashboard.jpg](screenshots/desktop-dashboard.jpg)
- [screenshots/desktop-evaluation.jpg](screenshots/desktop-evaluation.jpg)
- [screenshots/desktop-governance.jpg](screenshots/desktop-governance.jpg)
- [screenshots/desktop-live-governance.jpg](screenshots/desktop-live-governance.jpg)
- [screenshots/desktop-ml-analytics.jpg](screenshots/desktop-ml-analytics.jpg)
- [screenshots/desktop-revocation.jpg](screenshots/desktop-revocation.jpg)
- [screenshots/desktop-threat-lab.jpg](screenshots/desktop-threat-lab.jpg)
- [screenshots/desktop-trust-graph.jpg](screenshots/desktop-trust-graph.jpg)
- [screenshots/evaluation-initial.jpg](screenshots/evaluation-initial.jpg)
- [screenshots/final-agents.jpg](screenshots/final-agents.jpg)
- [screenshots/final-auto-demo-complete.jpg](screenshots/final-auto-demo-complete.jpg)
- [screenshots/final-batch-details.jpg](screenshots/final-batch-details.jpg)
- [screenshots/final-blockchain-audit.jpg](screenshots/final-blockchain-audit.jpg)
- [screenshots/final-dashboard.jpg](screenshots/final-dashboard.jpg)
- [screenshots/final-evaluation.jpg](screenshots/final-evaluation.jpg)
- [screenshots/final-live-chrome-audit.jpg](screenshots/final-live-chrome-audit.jpg)
- [screenshots/final-live-governance.jpg](screenshots/final-live-governance.jpg)
- [screenshots/final-ml-analytics.jpg](screenshots/final-ml-analytics.jpg)
- [screenshots/final-mobile-signed-form.jpg](screenshots/final-mobile-signed-form.jpg)
- [screenshots/final-normal-allow.jpg](screenshots/final-normal-allow.jpg)
- [screenshots/final-post-revocation-trace.jpg](screenshots/final-post-revocation-trace.jpg)
- [screenshots/final-revocation.jpg](screenshots/final-revocation.jpg)
- [screenshots/final-revoked-link-details.jpg](screenshots/final-revoked-link-details.jpg)
- [screenshots/final-tablet-signed-form.jpg](screenshots/final-tablet-signed-form.jpg)
- [screenshots/final-tampered-proof.jpg](screenshots/final-tampered-proof.jpg)
- [screenshots/final-threat-lab.jpg](screenshots/final-threat-lab.jpg)
- [screenshots/final-trust-graph.jpg](screenshots/final-trust-graph.jpg)
- [screenshots/governance-before.jpg](screenshots/governance-before.jpg)
- [screenshots/governance-normal-final.jpg](screenshots/governance-normal-final.jpg)
- [screenshots/governance-post-decommission-final.jpg](screenshots/governance-post-decommission-final.jpg)
- [screenshots/governance-scope-creep-final.jpg](screenshots/governance-scope-creep-final.jpg)
- [screenshots/governance-self-escalation-final.jpg](screenshots/governance-self-escalation-final.jpg)
- [screenshots/governance-unauthorized-final.jpg](screenshots/governance-unauthorized-final.jpg)
- [screenshots/graph-before-pan.jpg](screenshots/graph-before-pan.jpg)
- [screenshots/invalid-route-before.jpg](screenshots/invalid-route-before.jpg)
- [screenshots/invalid-route-fixed.jpg](screenshots/invalid-route-fixed.jpg)
- [screenshots/laptop-agents.jpg](screenshots/laptop-agents.jpg)
- [screenshots/laptop-blockchain-audit.jpg](screenshots/laptop-blockchain-audit.jpg)
- [screenshots/laptop-dashboard.jpg](screenshots/laptop-dashboard.jpg)
- [screenshots/laptop-evaluation.jpg](screenshots/laptop-evaluation.jpg)
- [screenshots/laptop-live-governance.jpg](screenshots/laptop-live-governance.jpg)
- [screenshots/laptop-ml-analytics.jpg](screenshots/laptop-ml-analytics.jpg)
- [screenshots/laptop-revocation.jpg](screenshots/laptop-revocation.jpg)
- [screenshots/laptop-threat-lab.jpg](screenshots/laptop-threat-lab.jpg)
- [screenshots/laptop-trust-graph.jpg](screenshots/laptop-trust-graph.jpg)
- [screenshots/missing-proof-response.jpg](screenshots/missing-proof-response.jpg)
- [screenshots/mobile-agents.jpg](screenshots/mobile-agents.jpg)
- [screenshots/mobile-blockchain-audit.jpg](screenshots/mobile-blockchain-audit.jpg)
- [screenshots/mobile-dashboard.jpg](screenshots/mobile-dashboard.jpg)
- [screenshots/mobile-evaluation.jpg](screenshots/mobile-evaluation.jpg)
- [screenshots/mobile-live-governance.jpg](screenshots/mobile-live-governance.jpg)
- [screenshots/mobile-ml-analytics.jpg](screenshots/mobile-ml-analytics.jpg)
- [screenshots/mobile-revocation.jpg](screenshots/mobile-revocation.jpg)
- [screenshots/mobile-threat-lab.jpg](screenshots/mobile-threat-lab.jpg)
- [screenshots/mobile-trust-graph.jpg](screenshots/mobile-trust-graph.jpg)
- [screenshots/presentation-final-metrics.jpg](screenshots/presentation-final-metrics.jpg)
- [screenshots/revocation-initial.jpg](screenshots/revocation-initial.jpg)
- [screenshots/revocation-unknown.jpg](screenshots/revocation-unknown.jpg)
- [screenshots/signed-action-replay-rejected.jpg](screenshots/signed-action-replay-rejected.jpg)
- [screenshots/signed-action-success-final.jpg](screenshots/signed-action-success-final.jpg)
- [screenshots/tablet-agents.jpg](screenshots/tablet-agents.jpg)
- [screenshots/tablet-blockchain-audit.jpg](screenshots/tablet-blockchain-audit.jpg)
- [screenshots/tablet-dashboard.jpg](screenshots/tablet-dashboard.jpg)
- [screenshots/tablet-evaluation.jpg](screenshots/tablet-evaluation.jpg)
- [screenshots/tablet-live-governance.jpg](screenshots/tablet-live-governance.jpg)
- [screenshots/tablet-ml-analytics.jpg](screenshots/tablet-ml-analytics.jpg)
- [screenshots/tablet-revocation.jpg](screenshots/tablet-revocation.jpg)
- [screenshots/tablet-threat-lab.jpg](screenshots/tablet-threat-lab.jpg)
- [screenshots/tablet-trust-graph.jpg](screenshots/tablet-trust-graph.jpg)
- [screenshots/threat-lab-initial.jpg](screenshots/threat-lab-initial.jpg)
- [screenshots/trust-graph-edge-fixed.jpg](screenshots/trust-graph-edge-fixed.jpg)
- [screenshots/trust-graph-initial.jpg](screenshots/trust-graph-initial.jpg)
