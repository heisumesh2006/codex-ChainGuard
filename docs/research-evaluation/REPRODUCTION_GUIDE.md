# Reproduction guide

Run from the repository root on the dedicated `research/security-evaluation` branch, using the final commits listed in the research verification report. Do not change branches, reset the repository, delete runtime state or replace existing evidence to reproduce these results. Commands below use Windows PowerShell; activate equivalent Python/Node commands on other platforms. Local experiment results are not public Sepolia measurements.

## Prerequisites and safety

- Install the repository's declared Python and Node dependencies in an isolated virtual environment and the existing `blockchain`/`frontend` packages. Exact observed versions are captured in each run manifest and the final report; this guide does not invent minimum hardware requirements.
- Plotting uses the optional `requirements-research.txt`; it does not add Matplotlib to the production authentication path.
- Compile both Solidity sources so the ABI/bytecode artifacts are available. This is local compilation, not deployment.
- Local write tests require Hardhat at `127.0.0.1:8545`, chain ID 31337. Keep the node running during a benchmark, and do not run other tests/benchmarks against it concurrently when collecting timings.
- Do not substitute a public RPC URL. The root `.env` may select a public profile, so set the local environment explicitly **before imports**. Never print `.env` or private key values.
- All benchmark/deployment/state tests use isolated temporary directories; they must not be repointed at `backend/core/governance/data/sepolia` or other canonical evidence.
- No command below deploys to or submits a transaction on Sepolia. Do not run public bootstrap or public deploy commands as part of these experiments.

```powershell
git branch --show-current
git rev-parse HEAD
git status --short
.venv/Scripts/python.exe -m pip install -r requirements.txt
.venv/Scripts/python.exe -m pip install -r requirements-research.txt
```

In a local node terminal:

```powershell
Set-Location blockchain
$env:CHAINGUARD_NETWORK = 'hardhat'
npm install
npm run compile
npm run node
```

The development node wrapper suppresses development private-key output. Hardhat wallets are disposable local identities and must never hold funds on a public chain.

In a second terminal at the repository root:

```powershell
$env:CHAINGUARD_NETWORK = 'hardhat'
$env:CHAINGUARD_RPC_URL = 'http://127.0.0.1:8545'
```

## Full Python verification

```powershell
.venv/Scripts/python.exe -m compileall -q backend
$env:CHAINGUARD_BATCH_MAX_AGE_SECONDS = '30'
.venv/Scripts/python.exe -m backend.testing.run_regression
```

`backend/testing/run_regression.py` creates a new local registry and new evidence under a temporary `.runtime/research-regression-*` directory. It patches storage paths rather than modifying canonical evidence. It shares an explicitly isolated signed identity fixture between bootstrap and new governance requests. Fresh fixture credentials are issued before their local demo events.

The existing synthetic scenario dataset is dated. To test it with a newly issued local credential without weakening temporal validation, the runner shifts **in-memory copies** of those synthetic timestamps and the model's history by a common whole-day offset, printing that offset. It does not rewrite the original dataset, model, credentials or public evidence; fitted weights, labels, times of day and time intervals remain unchanged. Old actions before credential issuance are intentionally invalid. Running an old dated synthetic CLI input unchanged against a new grant may therefore be blocked correctly rather than reproduce a historical saved decision.

The runner discovers `backend/**/test*.py`, prints discovered/run/failure/error/skipped counts, and records stress results under `.runtime/RESEARCH_F8_STRESS_RESULTS.json` when the stress test executes. The expected final total is the one in the final verification report, not a number hardcoded into this guide. Do not add focused suite totals to full discovery totals; focused cases overlap.

Focused checks can be run through the same isolated runner:

```powershell
.venv/Scripts/python.exe -m backend.testing.run_regression backend.core.authorization.tests.test_security backend.api.tests.test_authentication backend.core.blockchain.tests.test_grant_authority
```

The live `GrantAuthorityIntegrationTests` fixture provisions actual registered Hardhat root/agent addresses, deploys both contracts only locally, obtains real signatures from their development wallets, issues signed local grants and anchors the selected path. It then exercises direct governance, signed HTTP, payload substitution, replay, live signed WebSocket completion, cascading invalidation, independent paths, manifest/network mismatch and path-commitment conflicts. It does not use an HTTP-exposed trusted-verifier override or a mock successful governance result for the positive EVM workflow.

## Contract, frontend and browser checks

From `blockchain`:

```powershell
npm run compile
npm run test:contract
```

The contract/network command includes the existing registry/network tests and the new local grant-authority tests. Use the actual output count; do not separately add the focused GrantAuthority tests if they were already included.

From `frontend`:

```powershell
npm install
npm run build
npm run test:browser
```

Playwright uses its declared `msedge` channel, a production preview at `127.0.0.1:5179`, and the read-only fixture API on port 8002. The fixture copies the existing evidence into temporary storage and prohibits transaction submission; it never runs public scenario writes. It needs the retained off-chain public evidence and read-only provider access to verify the existing demo. Browser JSON output and failure screenshots go under `.runtime`, not into source commits. Report the final actual counts and any skips/failures; do not relabel unavailable browser or provider checks as passing.

## Experiment 1: Merkle anchoring versus hash-chain audit

Optional smoke check (separate output, not a substitute for the benchmark):

```powershell
.venv/Scripts/python.exe docs/research-evaluation/scripts/run_experiment1.py --smoke
```

Full benchmark:

```powershell
.venv/Scripts/python.exe docs/research-evaluation/scripts/run_experiment1.py
```

The full script declares workloads 10, 100, 500 and 1000 records, three trials per workload, two audit variants and batch size 10. It uses the same production authorization engine and canonical records, alternates variant execution order by trial and deploys a separate local registry for the blockchain variant. Caller signing and deployment/setup are outside event timing; signature verification, permission checks, local audit persistence and threshold-triggered real Hardhat root transactions/receipt waits are measured. ML is deliberately held constant and not executed in this experiment.

The tampering stage modifies, deletes, inserts, reorders and rewrites temporary copies. A strong off-chain attacker can recompute hash-chain links; protected versus replaceable checkpoints are separate policies. The Merkle auditor discovers expected batch roots/counts from the authenticated chain inventory rather than treating a mutable local metadata file as the trust anchor. No canonical evidence is attacked or modified.

Outputs:

- `raw/experiment1_summary.csv`: per-variant/workload/trial latency, verification, audit bytes, processing time, gas/fees/transaction count and untampered failures.
- `raw/experiment1_events.csv`: per-event authentication, local audit, anchor and total event time.
- `raw/experiment1_tampering.csv`: each controlled attack and checkpoint-policy outcome.
- `raw/experiment1_manifest.json`: parameters, source hashes, environment, dates, completion status and output hashes.

Audit-byte measurements exclude replay cache, deployment/credential files, lock files and filesystem metadata. Local gas/fees are not real-world monetary costs. Full-snapshot versus JSONL persistence is an acknowledged implementation difference.

## Experiment 2: delegation and cascading revocation

```powershell
.venv/Scripts/python.exe docs/research-evaluation/scripts/run_policy_experiments.py --delegation-only
```

The original module is retrieved with `git show` from the pinned preserved baseline commit `f3b4574cb726264d9d6d01988e0d64940ae8c148`. The reference runs in an isolated fixture. Do not check out the vulnerable baseline over corrected source or remove authentication from production code.

The default design has 20 trials at each depth Root→A, Root→A→B, Root→A→B→C and Root→A→B→C→D. It decommissions B, records permissions before/after and measures revocation time and repeated leaf-path checks. At depth one B is outside the exercised chain; at depth two it has no downstream agent in that chain. Separate trials check independent root and independent other-parent authority. Flat baseline permission checks and corrected signed ancestry have different semantics and costs; the timing comparison must say so.

Outputs are `raw/experiment2_depths.csv`, `raw/experiment2_independent_paths.csv` and `raw/experiment2_manifest.json`. Local on-chain transitive validity is checked separately by the contract/integration tests, not invented from these Python timing rows.

## Experiment 3: systematic authorization security

```powershell
.venv/Scripts/python.exe docs/research-evaluation/scripts/run_policy_experiments.py --security-only
```

The default design repeats 18 named case groups ten times. The groups include legitimate direct/delegated/root requests; missing/unauthorized scopes; expired and not-yet-issued grants; privilege escalation; root impersonation; replay; unauthorized/self delegation; revoked actors/intermediates; tampered credential metadata; forged proof; scope creep; and post-decommission activity. Genuine keys and signatures are generated within temporary identity fixtures. Expiry cases use a controlled local test clock rather than depending on a sleep delay. The scope-creep case freshly scores a saved synthetic feature example with the existing model; it does not read a saved governance decision as its answer.

Outputs are `raw/experiment3_requests.csv`, `raw/experiment3_before_after.csv` and `raw/experiment3_manifest.json`. Scope creep is expected to be REVIEW and is reported separately from binary authorization attack blocking. Attack-blocking/false-rejection/precision/recall/F1 definitions and denominators must accompany results. This constructed distribution does not estimate real-world attack prevalence or general anomaly accuracy.

Run both policy experiments together by omitting the selection flag. Do not rerun unchanged completed outputs simply to obtain a preferred measurement.

## Preserve provenance and generate figures

`backend/research/provenance.py` saves existing experiment CSVs/manifests under `raw/prior/<experiment>_<UTC stamp>/` before a new run. A new manifest begins as RUNNING and becomes COMPLETE only after the script finishes. Interrupted output is evidence of an incomplete run and must not be silently called final or discarded. Smoke output stays separate under `smoke/`.

Use the final completed source version when collecting publication tables:

```powershell
.venv/Scripts/python.exe docs/research-evaluation/scripts/analyze_results.py
```

The analysis script reads raw CSVs and produces aggregated data, `results_summary.json` and labelled PNG/SVG/PDF figures. Raw trials remain available. Do not treat repeated per-event measurements from the same run as independent experimental replicates, combine pilot/final CSVs, infer statistical significance from a few trials, or selectively remove slow but valid observations. Source hashes allow reviewers to distinguish results recorded before a later relevant code fix.

## Signed caller workflow

For the safest complete reproducible example, run `GrantAuthorityIntegrationTests` through the fixture runner above. The following is a client pattern for an **already prepared isolated** registry/API. It is not a request to create public grants or write public transactions:

```python
import json
from datetime import datetime, timezone
import requests
from backend.api.schemas import ActionInput
from backend.core.authorization.operator_signing import operator_credentials

# Operator/client process only. Hardhat's selected registry must be the same
# registry served by this isolated API, and the actor must already have a valid
# authenticated grant plus the required anchored authority evidence.
payload = ActionInput(
    actor="Agent_D", action="USE_PERMISSION", permission="P",
    timestamp=datetime.now(timezone.utc).isoformat(),
    authority_grant_id=selected_anchored_grant_id,
).model_dump(exclude_none=True)
credentials = operator_credentials("Agent_D", "evaluate", payload)
response = requests.post(
    "http://127.0.0.1:8000/api/governance/evaluate", json=payload,
    headers={"X-ChainGuard-Authentication": json.dumps(credentials["authentication"])},
    timeout=120,
)
response.raise_for_status()
```

`selected_anchored_grant_id` is an actual grant ID returned by the local operator's `grant_authority.anchor_path`, not a hardcoded demo proof or arbitrary client assertion. The integration fixture demonstrates provisioning with `chain.register_identities`, genuine signed root/delegation calls, `grant_authority.deploy_local` and `anchor_path` under temporary `local_registry`/`local_policy` contexts. Do not call these setup helpers against canonical storage. Outside local Hardhat, a legitimate caller can use `sign_request` with its own matching account; no key value should be placed in source, a report or browser storage.

For WebSockets send `{"action": payload, "authentication": envelope}` to `/ws/governance`. Reusing that envelope is a replay and must fail. Changing the action after signing must also fail. A valid signature does not create missing permission, revive a revoked parent or fabricate required chain evidence.

## Read-only existing Sepolia evidence

For additional receipt-level evidence in Experiment 1, retain the synthetic input timestamp while the measured run is active (a second terminal, after its first complete batch):

```powershell
.venv/Scripts/python.exe docs/research-evaluation/scripts/verify_experiment1_receipts.py --capture-inputs
```

After the benchmark completes, before resetting the isolated node or running other transaction-writing tests:

```powershell
.venv/Scripts/python.exe docs/research-evaluation/scripts/verify_experiment1_receipts.py
```

This optional read-only local verifier checks the last twelve benchmark registries against the expected workload/receipt counts, reconstructs every canonical input record and ordered Merkle root, and compares actual gas/fees with the raw summary CSV. It writes `experiment1_anchors.csv`, `experiment1_datasets.csv` and `experiment1_onchain_verification.json`. It refuses a non-31337 chain and caps the local inventory query at 100,000 blocks. Its chronological registry selection assumes no competing transaction-writing job ran after the measured benchmark; mismatches fail rather than inventing evidence. The retained CSVs survive a node reset, but live receipt queries require the original local node history. This is separate from production bounded transaction-recovery behavior.

After measured runs and receipt validation, run the independent policy/transport probes:

```powershell
.venv/Scripts/python.exe docs/research-evaluation/scripts/verify_policy_multiprocess.py
.venv/Scripts/python.exe docs/research-evaluation/scripts/verify_live_http.py
```

The first starts independent spawned OS processes for distinct signed updates and duplicate signed mutations, using temporary policy/nonce storage. The second provisions isolated local contracts, starts a real Uvicorn loopback HTTP server in another process, submits a genuinely registered wallet's signed action, and probes replay, body substitution, unsigned and root-impersonation failures. It checks that rejected requests do not append records. It stops the server and removes only its own temporary fixture. These are additional independent probes, not extra repetitions to inflate the discovered backend unit-test count. Keep all such activity outside timed benchmark trials.

Public contract: `0x61c74D0525f4f5A1a7b20f2eA561e485E71dd243`, chain ID `11155111`.

Public root: `0xee6028db0fb103cc0c5e1685e586b24d9213515a806aa9717f3ed0b54341006c`.

Public batch transaction: `0xae52c353001ff8754625054d8873eeda0b74b1702af775da3e6a4cd4d33b75c2`.

With the existing canonical bundle available, reproduce the public matrix and independent Merkle checks using:

```powershell
.venv/Scripts/python.exe docs/research-evaluation/scripts/verify_public_evidence.py
```

The script forces the Sepolia read profile, removes private signing credentials from its process, blocks all RPC methods outside a read allowlist and blocks the application transaction-submission function. It verifies the existing batch,29 matrix checks, five saved outcomes, five original/five altered proofs and83 independent Merkle checks; it requires eight canonical file hashes and record count to remain unchanged. It writes only a new research result file, `raw/public_evidence_final.json`. A missing evidence bundle or failed provider call is a failed/unavailable verification, not fabricated replacement data.

The final read-only checks inspect that existing deployment/batch and verify original records plus altered **in-memory copies**, retaining the original five saved decisions. They do not rerun bootstrap, regenerate the batch, add a grant extension or send public transactions. Record hashes of canonical local files before/after and compare them without printing credential-bearing contents.

A fresh clone without the retained off-chain AuditRecords, sibling proofs and runtime manifests cannot reconstruct individual proofs from the public Merkle root alone. Supply the actual authorized evidence bundle locally or mark those checks unavailable; never fabricate substitutes. Use only a read-only provider configuration and the existing API evidence views/verification paths. Public write/deploy instructions in older operator documentation are outside this reproduction procedure.

## Final validation and reporting

The concurrency fixture separates size-threshold races from age expiry: independent workers use one controlled sealing time for size tests, while dedicated tests advance time explicitly and exercise both single-process pending tails and two-process age sealing. Use the declared default30-second batch age for this test configuration. No file lock, persistence operation or successful-record/mapping assertion is mocked away. A prior integrated run exposed a live-clock test assumption (497 mapped plus3 valid pending records); `raw/concurrency_age_boundary_reproduction.json` and the preserved test-clock diff explain the correction. The failure remains in verification history.

```powershell
git diff --check
git status --short
```

Run a changed-file secret scan without printing detected values; ensure `.env`, `.runtime`, nonce/policy state, generated contract/build artifacts and canonical evidence are excluded from commits. Record actual suite counts, failures/skips, CSV and manifest hashes, figure paths, commit hashes, canonical evidence integrity and unresolved limitations. Publishing or merging is a separate operation and is not part of these commands.
