# Final stability and local preservation

Date: 2026-10-18 UTC. Branch: `research/security-evaluation`.

## Outcome

PASS: the previous verified implementation is preserved in local Git history and a separately hashed recovery backup. No additional application defect was reproduced during this follow-up. No application source was changed after the preservation commits. Two permanent supplementary browser tests and final documentation were added.

BLOCKED: a full **connected Chrome** HAR/network export. The extension API advertises viewport/management/page-assets capabilities and console logs, but no network/HAR inspector. The supplementary metadata below is not a Chrome HAR and does not establish exhaustive Chrome network coverage.

NOT VERIFIED: independent native OS clipboard access. Connected Chrome clipboard readback and isolated browser clipboard readback succeeded; the connector documents a browser-session clipboard, without promising independent OS clipboard inspection.

This is scoped verification, not a claim of a completely bug-free application or an unrestricted release certification.

## Recovery and commits

Original HEAD: `de1f7d5c4369639306c1e1bd7b5ecb5686bd7ec0`.

Backup: `.runtime/qa-recovery-backup/20261018T174140Z/` (repository-relative; ignored).

The backup contains 103 QA source/test/documentation/screenshot files, a binary-capable working-tree patch, Git metadata, and SHA-256 manifests. All copied-file hashes were checked against their originals and checked again after preservation. All 85 original screenshots remain intact. No environment files, signing envelopes, private keys, runtime state, or unrelated research ZIP were copied. Original QA source/screenshot hashes matched before staging.

| Commit | Preserved changes |
|---|---|
| `93c7af6` | Bounded retries for transient Windows atomic snapshot replacement failures |
| `9c07db7` | Local-only authenticated policy/scenario initialization and safe public diagnostic codes |
| `99dca86` | Selected-registry proof verification context and contract-backed graph revocation state |
| `a497477` | Signed governance submission and accurate saved-replay/pause status |
| `d43c653` | Graph controls, clipboard failure feedback, network provenance, unknown-route recovery |
| `540dab4` | Ten Python regressions, six browser regressions, original QA reports and 85 screenshots |
| `aa979fc` | Exact clipboard-value checks and sanitized supplementary API/WebSocket journey tests |

The follow-up test commit and documentation commit can be identified without a self-referential commit hash using:

```powershell
git log --oneline de1f7d5..HEAD
git log -1 --format=%H -- docs/qa/FINAL_STABILITY_AND_PRESERVATION.md
```

## Original eleven findings

Detailed reproductions and before/after evidence remain in [LIVE_CHROME_END_TO_END_QA.md](LIVE_CHROME_END_TO_END_QA.md).

| Finding | Root cause and preserved correction |
|---|---|
| QA-01 | Empty local demo audit stream: evaluate signed disposable fixtures and anchor the five local records before serving |
| QA-02 | Proof requests used another deployment context: select and restore registry paths under the existing lock |
| QA-03 | Useful trusted error codes over-redacted: explicit allowlist for typed evidence/authentication errors |
| QA-04 | Hardhat results labelled Sepolia: selected-profile wording and accurate synthetic metric provenance |
| QA-05 | Pipeline reported complete during paused replay: visible-stage/pause-aware state |
| QA-06 | Clipboard rejection silently ignored: visible failure and full public-value manual-copy fallback |
| QA-07 | Overlapping graph labels selected the wrong element: offsets, hit targets, stopped event propagation |
| QA-08 | Transient Windows sharing denial broke atomic replacement: bounded narrow retry, preserving prior bytes on permanent failure |
| QA-09 | No custom signed-action frontend flow: accept an externally signed action/envelope, clear the envelope after submission, keep backend verification |
| QA-10 | Stale local graph status showed revoked authority as active: current contract revocation and historical-proof distinction |
| QA-11 | Unknown route rendered blank: explicit missing-page view and dashboard recovery |

The local signing adapter is CLI/startup-only, guarded to Hardhat; no signing endpoint or private-key input was introduced. Public profile startup remains rejected. Existing authentication, replay, cascading revocation, credential ancestry, and historical validity enforcement remain enabled.

## Follow-up browser investigation

Actual connected Chrome extension, browser `1`, original recovery tab `574731911`, fresh recovery tab `574731954`.

- PASS: reattachment, real navigation from Audit to Governance and back, normal replay reaching ALLOW, local proof TAMPERED followed by original VERIFIED, and final console error inspection (zero errors).
- PASS: contract, transaction hash and Merkle root Copy buttons produced exact matching connected-browser clipboard readback. Initial contract readback did not match; retry after recovering the tab did match. No clipboard contents other than equality to those known public values were recorded.
- PASS: isolated Edge clipboard permissions test confirms exact writes/readback and visible `Copied` feedback for all three values. Existing denial regression confirms no false success and the full public-value fallback.
- BLOCKED: Chrome HAR export and direct failed-network-request inspection are absent from the available tool interface. No raw HAR, request body, authentication envelope, or headers were saved.
- PASS, supplementary only: isolated Edge observed 27 local API responses, zero HTTP errors, zero failed requests, zero page exceptions, and the expected governance WebSocket stages through `VERDICT_COMPLETE`. See [STABILITY_NETWORK_METADATA.json](STABILITY_NETWORK_METADATA.json). Only origin/method/path/status, WebSocket origin/path/event names, and error categories are retained.
- A locator operation and screenshot operation timed out on the older tab. Native accessibility controls continued to work; a new tab in the same Chrome restored locator and screenshot capture. Exact cause is not established. MetaMask content-script listener/orphan-stream warnings were observed; these do not prove the cause of the connector stalls. No application change was made to work around the inspection tool.
- Fresh screenshot evidence: [reconnected audit](screenshots/stability-audit-reconnected.jpg), [original proof](screenshots/stability-original-verified.jpg), [proof viewport](screenshots/stability-proof-viewport.jpg). The full-page capture includes fixed-position UI at the capture scroll position; the viewport image is the clearer proof view.

## Verification results and provenance

No application source changed from the passing checkpoint. The sole changed checkpoint file is the supplementary Playwright configuration, to include two new test cases. Therefore previous full-suite evidence remains applicable; counts below deliberately distinguish reused and rerun checks and are not added together as independent tests.

| Check | Result | Evidence / scope |
|---|---|---|
| Full Python suite | PASS 318/318, zero skipped | Reused unchanged-code checkpoint; `.runtime/live-chrome-python-final-318.log`, 466.993 s |
| Startup/context/Windows/status tests | PASS 10/10 rerun | `.runtime/qa-preservation-focused.log`, 0.085 s; subset of 318 |
| Authentication, authorization, diagnostics, temporal security | PASS 104/104 rerun, zero skipped | `.runtime/qa-preservation-security-fixture.log`, 17.744 s; subset of 318 |
| Solidity/network | PASS 11/11 | Unchanged contract/network checkpoint in original QA results |
| Merkle checks | PASS 83/83 | Unchanged-code read-only checkpoint, `.runtime/LIVE_CHROME_PUBLIC_VERIFICATION.json` |
| API matrix | PASS 29/29 | Same checkpoint, completed `2026-10-18T16:52:02.579870+00:00` |
| Existing full browser fixture | PASS 24/24 | Reused unchanged-code checkpoint; `.runtime/live-chrome-playwright.log` |
| Targeted local browser suite | PASS 8/8 rerun | `.runtime/qa-preservation-browser-final.log`, 57.6 s; includes original six plus two new cases |
| Total distinct browser cases covered | 32 | 24 existing + eight local targeted, separate runs; not a single 32-test run |
| Multiprocess stress | PASS 500 successful / 500 persisted | Reused unchanged persistence checkpoint, `.runtime/LIVE_CHROME_STRESS_VERIFIED.json`; ten workers, zero lost/duplicate persisted IDs, 100 batches/500 mappings; ten deliberate duplicate rejections; four lock-contention failures safely retried; 124.204 s |
| Python compilation | PASS rerun | `python -m compileall -q backend` |
| Frontend production build | PASS rerun | `.runtime/qa-preservation-build.log`, 38.24 s |
| Original Chrome coverage | PASS in tested scope | Nine pages, six journeys, 121 control positions, original 85 screenshots |

A direct `unittest` invocation of the 104 security tests produced nine subcase errors because the authenticated temporal tests require the runner's valid signed registry fixture (`max()` on an empty set of credential timestamps). Failure evidence remains in `.runtime/qa-preservation-security.log`. Running the documented `backend.testing.run_regression` with the same four modules passed all 104. No rule/assertion was weakened and no application fix was made for a missing test fixture. Earlier failed attempts are retained in the original QA report.

## Evidence and security integrity

- SHA-256 comparison: all 110 protected files unchanged (102 research files and eight canonical Sepolia evidence files). No research metrics, CSVs, manifests, figures, canonical records, or public batches were regenerated.
- Existing read-only public evidence: Sepolia chain 11155111; registry `0x61c74D0525f4f5A1a7b20f2eA561e485E71dd243`; root `0xee6028db0fb103cc0c5e1685e586b24d9213515a806aa9717f3ed0b54341006c`; batch has five records. Original proofs: five VERIFIED; altered copies: five TAMPERED. Governance: ALLOW, BLOCK, BLOCK, REVIEW, BLOCK.
- Original signed HTTP checkpoint: valid signed request accepted; replay, modified body, unsigned request and root spoof rejected without extra persisted records. The rerun security suite independently rechecks these security areas.
- Secret scan PASS: 367 staged/tracked files, zero configured-secret findings. The scan uses configured credential values in memory and reports file/category only; no credential values are printed. Screenshots were visually reviewed; signed envelope inputs are cleared. No environment, runtime, generated build, research ZIP or canonical runtime artifact is staged.
- `git diff --check` and staged whitespace checks pass. `.env`, `frontend/.env.local`, `.runtime`, demo-runtime and Sepolia runtime paths remain ignored.
- Main remains `c026d5b8c7c2959937d49145571c2694d59ff674`. No push, merge, reset, stash, history rewrite or public transaction occurred. Only isolated local Hardhat test transactions were used by the documented security fixture.

## Startup and final state

All three existing services were preserved; no restart or duplicate server was needed. Health: API ONLINE, Hardhat chain 31337/RPC connected, contract available, saved ML model available; frontend HTTP 200. No viewport override was applied in this follow-up. The final Chrome proof tab is retained for inspection.

When services are not already running, use separate PowerShell terminals from the repository root:

```powershell
# Terminal 1: local blockchain only
cd blockchain
$env:CHAINGUARD_NETWORK = 'hardhat'
npm run compile
npm run node
```

```powershell
# Terminal 2: disposable local demo backend
$env:CHAINGUARD_NETWORK = 'hardhat'
$env:CHAINGUARD_RPC_URL = 'http://127.0.0.1:8545'
.\.venv\Scripts\python.exe -m backend.api.demo_server
```

```powershell
# Terminal 3: frontend
cd frontend
$env:VITE_API_BASE_URL = 'http://127.0.0.1:8001'
npm run dev
```

Open `http://localhost:5173`. Do not start duplicates while these ports are already healthy. The disposable backend creates local contracts and evidence; it is not a Sepolia startup command.

Final intended Git state after the follow-up commits: all QA source, tests and documentation committed; only the existing `CHAIN GUARD AI FINAL IEEE RESEARCH PACK.zip` remains untracked and untouched. The exact final HEAD is supplied by the documentation commit lookup above and the completion response.

Remaining limitations: blocked connected-Chrome HAR capture, unverified independent OS clipboard inspection, intermittent Chrome inspection-tool timeouts of unproven cause, and the pre-existing research/transaction-recovery limits documented in the research reports. No additional confirmed application defect remains from this follow-up; this does not imply untested behavior is certified.
