# Final research verification

Verified UTC: 2026-10-17T18:49:29.743641+00:00

**All required research implementation, experiments and scoped verification checks passed.** This is a controlled research evaluation with the explicit limitations below, not a universal production-security guarantee.

## Git and preserved baseline

- Branch: `research/security-evaluation`.
- Preserved pre-improvement baseline: `f3b4574cb726264d9d6d01988e0d64940ae8c148` (loaded only in isolated reference fixtures).
- Reviewed security implementation/test commit: `88c08573831cdabd25daa190192f052e7c9e252c`.
- Reproducible experiments, data, figures and paper-content commit: `4c190f08eb7fec87f5e01a9caf04b5ffbf0d6cad`.
- This report is a documentation-only follow-up. Its own commit is identified by `git log -1 --format=%H -- docs/research-evaluation/FINAL_RESEARCH_VERIFICATION.md`; its literal self-hash cannot be embedded in its own Git content.
- `main` remains `c026d5b8c7c2959937d49145571c2694d59ff674`. No push, merge, public deployment or Sepolia transaction occurred.

## Security implementation and independent review

1. Registry-bound EIP-191 request signatures replace trust in requester names. Canonical intent binds actor, operation, domain, payload digest, nonce and bounded time. Missing/forged/replayed requests fail before public evaluation persistence. Root mutations require the actual root signing identity; no shared-token substitute was introduced.
2. Retained signatures authenticate grant holder/scope/expiry/issuer and exact parent ID. Effective permission follows valid authenticated ancestry. B decommissioning invalidates derived C/D authority, preserves independent paths and retains revoked/renewed grant history. Changed-expiry repeated grants are rejected explicitly; expired/invalid edges cannot create false cycle denials.
3. Stable process locks and atomic policy snapshots protect read/mutate/write. Failed unpublished mutations restore memory and trusted object references; post-replacement ambiguity does not revive revoked authority. Consumed nonces stay consumed. Corrupt state/extension manifests fail with controlled evidence errors.
4. The optional local GrantAuthority contract independently exposes root-attested immutable grant ancestry and time/status. Python compares every selected hop's holder, scope, parent and applicable timing with the chain. Wrong-network, forged/intermediate-mismatched and unrelated grants cannot satisfy verification. It is separate from the unchanged public registry.
5. Legacy tracing preserves authenticated independent root paths and applies inclusive revocation boundaries. Existing sanitization, credential-time validation, network isolation, proof checks, persistence and bounded transaction recovery remain in the regression suite.

Exact changed security/config/test files (37):

- `.gitignore`
- `backend/api/main.py`
- `backend/api/schemas.py`
- `backend/api/services.py`
- `backend/api/tests/test_api.py`
- `backend/api/tests/test_authentication.py`
- `backend/core/authorization/agents.py`
- `backend/core/authorization/authentication.py`
- `backend/core/authorization/demo_identity.py`
- `backend/core/authorization/main.py`
- `backend/core/authorization/operator_signing.py`
- `backend/core/authorization/state.py`
- `backend/core/authorization/tests/__init__.py`
- `backend/core/authorization/tests/test_policy_persistence.py`
- `backend/core/authorization/tests/test_security.py`
- `backend/core/blockchain/diagnostics.py`
- `backend/core/blockchain/grant_authority.py`
- `backend/core/blockchain/tests/test_concurrency.py`
- `backend/core/blockchain/tests/test_grant_authority.py`
- `backend/core/governance/main.py`
- `backend/core/governance/pipeline.py`
- `backend/core/governance/tests/test_pipeline.py`
- `backend/core/revocation/main.py`
- `backend/core/revocation/revocation.py`
- `backend/core/revocation/tests/test_revocation.py`
- `backend/core/tracing/tests/test_independent_authority.py`
- `backend/core/tracing/tests/test_temporal_authority.py`
- `backend/core/tracing/tracer.py`
- `backend/research/__init__.py`
- `backend/research/common.py`
- `backend/testing/__init__.py`
- `backend/testing/run_regression.py`
- `backend/testing/signed_requests.py`
- `blockchain/contracts/GrantAuthority.sol`
- `blockchain/package.json`
- `blockchain/test/grant-authority.test.js`
- `frontend/src/services/api.js`

Research implementation: `backend/research/{audit_baseline,experiment1,experiment2,experiment3,provenance}.py`, the optional plotting declaration and `docs/research-evaluation/scripts/`. `EVIDENCE_MAP.md` links claims/functions/test artifacts.

## Final test results (no double counting)

| Check | Actual final result / evidence |
| --- | --- |
| Full integrated Python suite | **308/308 PASS**, 0 failures, 0 errors, 0 skipped; `.runtime/research-python-final-308.log` |
| Final focused security pass | **109/109 PASS** before the integrated run; overlaps the308 and is not added to it |
| Earlier full/focused passes |301,107 and109 passed; retained as history, not additional unique tests |
| Independent OS-process policy mutation tests | **2/2 PASS**; distinct signed updates retained, duplicate signed mutation accepted once |
| Original independent security reproductions | **3/3 PASS**; nested exception secret, short-secret public identifier and expired-child scope bypass |
| Local GrantAuthority/API integration | All 12 methods passed within306: real registered keys, live EVM paths, HTTP/WS positives, replay/tamper negatives, malformed/wrong-network/all-hop/expiry checks |
| Solidity/network contracts | **11/11 PASS**; original6 plus5 GrantAuthority cases; cached Solidity0.8.28 compile validation PASS |
| Independent Merkle reference | **83/83 PASS**; ordered Keccak construction and original/tampered/wrong-index/sibling/root cases |
| Read-only public API matrix | **29/29 PASS**, plus saved-scenario and all original/altered proof requests; explicit404/422 negatives, no unexpected500 |
| Production browser | **24/24 PASS** across all nine pages; latest affected five-scenario/complete Auto Demo rerun **2/2 PASS**, no retries/skips/unexpected console or API failures |
| Frontend build | PASS (production Vite build); no frontend source changed afterward |
| Python compilation/dependencies | Backend and research scripts compile; `pip check` PASS |
| Node dependency advisory scans | Frontend and blockchain npm audits:0 reported vulnerabilities in each |

Raw structured evidence: `raw/verification_results.json`, `browser_full_report.json`, `browser_focused_report.json`, `policy_multiprocess_verification.json` and `live_http_verification.json`. Full and focused backend test IDs are retained to make overlap inspectable.

The real loopback Uvicorn workflow returned HTTP200 with `authorized=true`, `chain_verified=true` and governance REVIEW for its unfamiliar P action. Replay, changed body, unsigned input and root impersonation all returned401; one successful evaluation produced one audit record, and rejected requests produced zero. This proves actual network-boundary usability, rather than a mocked successful verifier. It is distinct from the synthetic component-security matrix.

## Concurrency/crash regression

The integrated run's ten independent processes completed **500/500** distinct actions with **0** lost successful actions and **0** duplicate persisted records. Ten deliberate duplicates were rejected. JSONL and batch snapshots were valid, 100 batches mapped all 500 actions, and roots matched persisted ordering. Duration: **85.651 seconds**; bounded lock timeouts: **2**, safely retried. Worker errors:0. Exact worker results are in `raw/concurrency_stress.json`. Temporary/mock-chain storage was used; canonical Sepolia files were never stressed.

Fault coverage includes atomic-write failure, killed writers/OS lock release, nonce replay across independent processes, metadata CAS conflicts, concurrent sealing/submission claims, interrupted/uncertain transactions, receipt-first bounded reconciliation and malformed evidence. This does not imply a transaction across every local file and blockchain state.

An earlier 306-test integrated run had one mapping assertion failure: 500 records remained present/unique/canonical, but age-triggered partial batches left 497 mapped and 3 legitimately pending. A deterministic production-manager reproduction confirmed the behavior. Size-race tests now use an explicit controlled clock, and two additional regressions test pending-tail age expiry and real two-process age sealing. All production locking/persistence/sealing code and the 500-success/500-mapping requirement remain intact. The failed run, source diff and reproduction are retained in verification history rather than suppressed.

## Three completed experiments

### 1. Audit comparison

- 10/100/500/1,000 records,3 paired trials each,24 version/trial rows,9,660 timed operations. Actual local anchoring produced483 audit transactions across12 registries; independent read-only reconstruction matched all4,830 anchored records/roots, receipts, gas and fees.
- Protected external hash-chain checkpoints and externally anchored Merkle inventory each detected 60/60 tested transformations per policy condition. Rewriting the only local hash-chain head gave 0/60 detections. Untampered complete-audit false positives:0/24. The two EVM checkpoint-policy rows use the same external chain assumption, not120 different attacks.
- At 1,000 records, final three-trial mean event times were 309.736 ms (Merkle/local EVM) and 113.872 ms (hash chain); verification 1870.462 ms versus 156.597 ms; audit storage 788.005 KiB versus 676.522 KiB. Audit transactions 100 versus0; local audit gas 9,482,456 versus0. Full per-trial mean/median/p95/ranges/storage/gas/fees are in the CSVs, not inferred public fees.
- The measured benefit is external commitment independence under a storage-rewrite attacker. An equally protected hash-chain checkpoint detects the same tested attacks. This is not blockchain-only detection, a throughput improvement or a comparison with an optimized database.

### 2. Delegation/revocation

- 160 final version/depth/trial rows (four depths, two versions, 20 trials) plus 40 independent-path cases.
- Original flat enforcement incorrectly retained 60 tested downstream permissions after B revocation. Corrected enforcement retained 0, incorrectly revoked 0 independent A permissions, and preserved 40/40 alternative C paths.
- Timings separate original unsigned flat lookup from corrected signed/durable ancestry. The local-policy experiment makes no chain transactions; contract transitive validity is independently tested.

### 3. Authorization security

- 180 operations:30 legitimate correctly allowed,140 attacks correctly blocked,10 separately reviewed anomalies. Incorrectly blocked legitimate operations0; incorrectly allowed attacks0.
- Attack-positive confusion matrix TP140,FN0,FP0,TN30: controlled-case blocking/recall100%,false rejection0%,precision/F1=1.000. REVIEW rows are excluded from binary rates.
- Original unauthenticated root issuance allowed10/10; corrected forged-root attempts allowed0/10. The matrix is finite/component-composed, not a general attack-prevention or ML-accuracy estimate.

Final data/tables: `raw/experiment1_{summary,events,tampering,anchors,datasets}.csv`, `experiment2_{depths,independent_paths}.csv`, `experiment3_{requests,before_after}.csv`, aggregate CSVs and `results_summary.json`. Each experiment has a COMPLETE manifest with actual environment, parameters, source/output hashes and UTC dates. Preliminary/interrupted/superseded data and earlier plots remain under `raw/prior/` or `smoke/`; final analysis excludes them.

## Provenance and research-document review

Experiment 1 ran from 20261017T165326486370Z to 2026-10-17T17:26:51.961037+00:00. Its timed functions and root setup did not change. A delegation-only cycle fix/test addition occurred during review; this unused function is recorded in `experiment1_source_compatibility.json` and its preserved patch. Policy experiments were rerun after provenance detected the old imported version; final Experiments 2/3 measured production-source hashes match the final implementation. The later concurrency-test-only clock correction is recorded separately and is not imported by any benchmark. Chart legend placement changed only presentation; postprocessing manifests/diffs and independent arithmetic checks retain that distinction. Original manifests were not rewritten to conceal source changes.

Environment observed in manifests: Windows-11-10.0.26200-SP0,Python 3.14.0,Node v24.15.0,12 logical CPUs. Python packages: `{"eth-account": "0.14.0", "matplotlib": "3.11.2", "scikit-learn": "1.9.1", "web3": "8.0.0"}`. Hardware minima, public throughput/cost savings and unmeasured accuracy are not invented.

Four labelled scientific figures are visually checked and exported to SVG, PDF and 300-DPI PNG (12 final files); three Mermaid source diagrams describe actual architecture/delegation/audit trust boundaries. The literature comparison has 13 verified primary references and distinguishes standards/literature from measured outcomes. Candidate IEEE abstract/methodology/setup/results/discussion/conclusion/future-work text is in `IEEE_PAPER_REPLACEMENT.md`; the existing PDF was untouched.

## Existing public evidence, read-only

- Ethereum Sepolia 11155111; contract `0x61c74D0525f4f5A1a7b20f2eA561e485E71dd243`.
- Existing root `0xee6028db0fb103cc0c5e1685e586b24d9213515a806aa9717f3ed0b54341006c`; transaction `0xae52c353001ff8754625054d8873eeda0b74b1702af775da3e6a4cd4d33b75c2`; 5 records.
- Saved outcomes: **ALLOW,BLOCK,BLOCK,REVIEW,BLOCK**.
- Original proofs: 5 VERIFIED; altered in-memory copies: 5 TAMPERED.
- Public transactions submitted: **0**, enforced by RPC method allowlists and disabled submission functions. No evidence regenerated or canonical records appended.

| Canonical file | Unchanged SHA-256 |
| --- | --- |
| `backend/core/governance/data/sepolia/audit_logs.jsonl` | `27f02d83bb50fa0dfd7271bb9ad2618a443258fb7fa6709f1f39c67fbc4ae5fe` |
| `backend/core/governance/data/sepolia/batches.json` | `0307dc8936ac3f4cf561788fba351fa9e53485f0af84446ed9f56c1effe49a0a` |
| `backend/core/governance/data/sepolia/credentials.json` | `01803337369ab83f782ea7090ed786d99e123f8f1d7005ad314385cdf1dbc86c` |
| `backend/core/governance/data/sepolia/deployment.json` | `1d030d67eb1cb112afc1295df15e928bfc328f59428fbc700a8e01a9eca387ff` |
| `backend/core/governance/data/sepolia/ethereum_state.json` | `276142103465c0cf047e637e8036162234be90c5aa3f7c3a8397d4ba38c2b896` |
| `backend/core/blockchain/data/sepolia/credentials.json` | `44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a` |
| `backend/core/blockchain/data/sepolia/deployment.json` | `1d030d67eb1cb112afc1295df15e928bfc328f59428fbc700a8e01a9eca387ff` |
| `backend/core/blockchain/data/sepolia/ethereum_state.json` | `14878b35f5bc76473d95185fae0803a0d713883e72540d5020bd7d23bdc92e77` |

## Security/Git checks and remaining limitations

Changed/staged source/artifact scan found 0 configured-secret or credential-URL matches without printing values. `.env`,`.runtime`,frontend private env,nonce/policy snapshots,generated builds/contract artifacts and canonical Sepolia files remain ignored and outside commits. `git diff --check` and exact staged checks passed. The final report commit changes documentation only; final status is checked after it is created. No push/merge occurred.

- Existing Sepolia is the original registry. The new grant extension is tested locally only; no public upgrade, migration or production audit is claimed.
- Keys, enrollment, clock, trusted enforcement storage and the verifier/RPC remain trust assumptions. Local nonce/policy rollback by an administrator is not prevented. Hardhat unlocked signers are a trusted test oracle, not production key isolation.
- Scope is one trusted realm per worker on cooperating local-filesystem processes. Distributed/NFS semantics and arbitrary cross-host linearizable external action execution were not tested. Revocation does not cancel already-running external workflows.
- Nonce consumption, policy publication, event journaling and chain publication are not one transaction. Uncertain batches fail closed; interrupted legacy revocation publication may need operator reconciliation if its in-memory event is unavailable. No on-chain exactly-once or automatic recovery of every crash window is promised.
- Local automining, snapshot-copy persistence and the simple hash-chain snapshot baseline do not predict public-chain throughput/fees or optimized database performance. Three audit trials provide descriptive ranges, not statistical significance.
- The request matrix is constructed, topologies have four agents, and the scope-creep sample is synthetic/repeated. Perfect controlled-case rates are not universal attack recall or real-world anomaly accuracy.
- Caller action timestamps are signed assertions, not physical event-time attestations. Audit commitments establish bytes/inventory under the stated trust model, not event truth, confidentiality or data availability.
- Older standalone dated CLI demonstration data require correctly provisioned identities and temporally valid fixtures; the full runner uses isolated, explicitly shifted copies without weakening historical rules. No standalone old21-scenario CLI success is claimed.
- Starlette TestClient/httpx and Node color warnings were observed; no test skip, flaky retry, unexpected API500 or browser runtime failure was hidden. Python dependency consistency and Node advisory audits were checked; no formal third-party penetration/contract audit or complete Python CVE audit is claimed.

See `LIMITATIONS_AND_THREATS_TO_VALIDITY.md` for the precise inspected revocation-publication window and other boundaries. These are disclosed scope/availability/trust limitations; no universal/exactly-once or publicly migrated extension claim is made.

## Reproduction

Use `REPRODUCTION_GUIDE.md`: isolated Hardhat node, declared dependencies, full runner`python -m backend.testing.run_regression`,contract tests,frontend build/browser suite,benchmark scripts,analysis and the independent process/real-HTTP/public-read verifiers. Measured runs must not overlap other CPU/RPC test jobs. Capture the synthetic audit timestamp while running if reproducing receipt-level inventory validation. An owner-provided existing canonical bundle is required for the public checks; a root alone cannot reconstruct missing records/proofs.
