# Limitations and threats to validity

This document separates implemented protections from their assumptions. Passing the supplied tests establishes the tested cases, not a proof of absence of vulnerabilities. Exact final counts, run dates and measurements are recorded in the verification report and experiment CSVs; this document does not substitute planned checks for completed ones.

## Security and deployment boundary

### Identity is a key binding, not a name

`RequestVerifier` recovers an Ethereum signer from an EIP-191 signature over a canonical application message. The message binds the protocol version, registry/chain domain, actor, operation, SHA-256 payload digest, nonce, issue time and expiry. The verifier resolves the actor using the selected trusted registry rather than accepting a client-provided public-key registry. Root authorization still uses a readable root identifier as a lookup/policy key, but possession of that string is insufficient authentication.

These protections assume uncompromised caller private keys, correct identity registration, an authenticated application deployment and a sufficiently accurate server clock. The accepted future skew is five seconds; the maximum authentication lifetime is 300 seconds. The current registry does not implement a general key-rotation/recovery workflow. No hardware wallet, HSM, MFA, SPIFFE attestation, OAuth/OIDC server, DPoP interoperability or W3C Verifiable Credential compliance is claimed. Public HTTP deployment also needs transport protection and operational controls outside these local experiments.

The local Hardhat harness deliberately uses unlocked development wallets. A party with access to that trusted loopback RPC can request signatures from those wallets, including root. Local tests establish verification/binding/rejection logic under isolated test-signer assumptions; they do not establish private-key isolation against a compromised/open development RPC. The production model requires protected caller-controlled signers; no HTTP endpoint exposes the operator signing helper.

Signatures authenticate requests and retained grant metadata; they do not make a malicious but genuinely authorized root honest. A root key compromise remains a trust-root compromise. Administrative request signing is explicitly an operator/caller operation, not an automatic privilege available to arbitrary HTTP clients.

### Replay and local policy storage

Nonce check-and-consume uses stable OS-owned file locks and atomic local snapshots, including across independent backend processes. Retained grant signatures are checked again when authority is used. A grant's long-term permission lifetime is distinct from the short-lived request that originally created it; expiration of the request envelope does not automatically expire the issued grant.

The replay cache and mutable policy snapshot require trusted persistent storage. The design does not provide a hardware monotonic counter or an independently anchored version for each nonce/policy write. An administrator able to delete or roll back the entire replay cache may permit replay of an otherwise still-valid request. Restoring an older policy snapshot can restore old local status. Signature validation prevents forging changed signed scope/holder/expiry/parent fields; it is not protection against all rollback, deletion or denial-of-service attacks on enforcement storage.

An application worker selects one trusted network/identity realm; clients cannot dynamically select a verifier. Concurrently switching different trusted realms inside the same Python process is not a supported multi-tenant service mode because the in-memory agent registry is process-global. Tests switch isolated realms serially and use separate processes for cross-worker checks. Benchmark policy identities use a common trusted synthetic address resolver to isolate costs; live registered-address RPC authentication is checked separately and must not be inferred from those microbenchmark timings.

Nonce consumption and policy publication are separate durable operations. A crash after consuming a nonce but before publishing a policy update can leave the requested change unapplied. The caller must submit a **new signed request with a new nonce**; retrying the consumed envelope must not apply it twice. This is fail-closed replay handling, not an atomic transaction spanning both files. A process crash after publication but before a response can leave a completed operation whose response was lost; callers must inspect current state and use the operation's idempotence rules.

The policy snapshot retains agent/grant status and history, not the complete in-memory Module 1 `ACTION_LOG` event journal. A crash after durable local decommissioning but before legacy revocation anchoring can leave local denial without the original event needed for automatic publication retry. The legacy path reports the missing event rather than fabricating it; operator reconciliation may be required. No atomic transaction spanning local decommissioning, its event journal and on-chain publication is claimed. This limitation follows from the inspected storage/anchoring boundaries; the local policy correctness experiments do not measure automatic recovery of that publication window.

### Current permission versus historical evidence

The corrected local authority engine checks authenticated parent-grant ancestry, active status and `issued_at <= action_time < expires_at`. A child binds a specific parent grant ID; a later re-grant does not silently revive the old child. Independent valid permission paths may continue after another path is revoked. Full agent decommissioning invalidates the agent and its dependent paths while retaining grant history; it is not global decommissioning of every descendant.

Fresh action acceptance requires current authority as well as validity at the supplied action time, so backdating cannot restore a currently revoked or expired path. Historical trace/evidence checks are a separate operation. The local `authority_paths` API's `at_time` parameter does not by itself reconstruct arbitrary past mutable agent status. The optional Solidity `wasValidAt` query retains on-chain issue, expiry and revocation times, but its guarantee applies only to grants actually recorded in that contract.

An action timestamp is a signed caller assertion whose syntax/timezone and authority windows are checked; it is not an independent attestation of the physical time an external action occurred. The block time establishes anchoring time, not the truth of every record field. Nonce replay protection prevents reuse of an authentication envelope; it is not a general business-operation deduplication protocol for independently re-signed requests. Enforcement applies to workflows that actually call the trusted authorization/governance boundary, rather than sandboxing every possible external tool an agent could access.

Revocation protects newly evaluated authority paths; it does not cancel already-running external workflows or implement a cross-host linearizable action-execution transaction. Permission checks and external tool execution must not be presented as one atomic operation.

### Local-only grant extension and historical Sepolia evidence

The new `GrantAuthority` is a separate optional extension, tested/deployed only on isolated Hardhat chain ID 31337. It preserves immutable grant IDs, exact parents, holder/scope, expiry and revocation history. The root account submits grant attestations; the contract does not independently recover every agent's off-chain request signature. Thus an independent contract reader verifies root-attested ancestry and time/status, while Python additionally verifies retained agent signatures.

The contract bounds ancestry to at most 32 grants. Its chain issuance time is the anchoring block time, which can be later than the local signed grant's issue time. These times must not be presented as identical or as proof of unrecorded earlier authority. Selective grant invalidation in the extension and full-agent revocation in the legacy registry have different scope.

The existing Sepolia registry at `0x61c74D0525f4f5A1a7b20f2eA561e485E71dd243` remains the original `AgentTrustRegistry`. The public batch root `0xee6028db0fb103cc0c5e1685e586b24d9213515a806aa9717f3ed0b54341006c` is historical evidence. It does not establish that the new grant extension has been publicly deployed, that old credentials have been migrated, or that corrected policies were enforced when those old scenarios were recorded. New behavior is evaluated independently in controlled local tests. A production/public migration requires a separately reviewed deployment and operator procedure; none was performed for this work.

## Audit and transaction guarantees

### Tamper evidence is conditional on a retained external commitment

Canonical JSON and Keccak-256 commit to bytes, not their truth. A Merkle inclusion proof proves that the supplied record is included in a committed batch; inclusion alone cannot prove the availability or completeness of all history. Experiment 1 additionally discovers expected batch roots/counts from the selected registry's event inventory and compares the complete ordered local records. A forged local batch metadata file is not accepted as the authoritative inventory.

The storage attacker may modify, delete, insert, reorder or replace off-chain records and recompute all hash-chain links. Two hash-chain checkpoint policies are compared explicitly: an externally protected `(head, count)` and a checkpoint replaceable with the local log. A protected hash chain detects these changes. If the attacker can replace the only head, self-consistency is insufficient. Blockchain supplies an external commitment under the assumed trusted deployment/chain/RPC model; an independent trusted checkpoint, transparency log or witness is also a valid alternative.

Neither scheme guarantees off-chain data availability, confidentiality or correct event capture before commitment. Losing a record or its proof material can make verification unavailable even while the public root survives. Unsealed/unanchored pending records do not yet have the protection of a confirmed external commitment. The experiments do not test a Byzantine RPC service, chain reorganization, validator collusion, compromised signing authority, censorship, or a storage attacker who controls the blockchain's trusted history too.

The audit attacker may rewrite the declared audit storage/checkpoint material, not the independent verifier's executable code or trusted identity/network configuration. A compromised verifier can lie about its own result; an external auditor must use a trusted verifier and chain view. This experiment does not equate audit-volume access with arbitrary control over the running application.

### Crash-safe recovery does not equal exactly-once blockchain delivery

The production batch manager uses stable per-storage/per-batch locks, durable submission intent and transaction hashes where available. It reconciles existing chain state/receipts before submitting and does not automatically repeat a send whose outcome is uncertain. A process can die after broadcasting but before recording the result, and a provider can time out after accepting a transaction. These uncertainties cannot be removed by a filesystem lock alone.

Recovery uses a known receipt first; bounded fallback scans target the authenticated anchor timestamp and deployment range, with a maximum 256-block timestamp range and provider-compatible subdivisions. Missing, conflicting or unavailable evidence yields a controlled unresolved state. An unresolved transaction may therefore require operator reconciliation and reduce availability. The implementation does **not** promise automatic recovery from every lost transaction hash, arbitrary provider history pruning, every nonce replacement or every reorganization, nor globally exactly-once delivery across chain and local files.

Deterministic batch IDs and the registry's existing-batch guard prevent silently overwriting the same stored commitment. They do not imply that no failed duplicate transaction can ever consume gas after an operator violates the recovery procedure. No public uncertain-transaction experiment was performed.

### Filesystem concurrency scope

OS byte-range locks on Windows and `flock` on POSIX coordinate participating processes using the same resolved stable lock paths. Process-local reentrant locks handle threads as well. Atomic snapshots use unique temporary files on the same filesystem and replacement; fsync precedes replacement, with directory fsync on supported POSIX systems. Locks release on process termination; a leftover coordination file is not stale ownership and must not be deleted while workers are active.

These are local-filesystem guarantees, not a distributed lock service, database transaction, NFS/SMB guarantee or power-loss certification. Audit JSONL and batch metadata are separate files: an appended unassigned record can survive a crash and is discovered as pending on reload. They are not a single multi-file ACID transaction. A failed operation can have committed if failure occurs after replacement; callers must reload/reconcile before retrying. All stress/crash tests use isolated directories and their results should be reported only for the tested platform/workload.

## Experimental validity

| Threat | Consequence and reporting rule |
| --- | --- |
| Single development host and local Hardhat | Local automining, loopback RPC, filesystem cache, CPU scheduling and crypto libraries influence timings. Do not extrapolate latency, throughput, fees, finality or availability to Ethereum Mainnet or Sepolia. |
| Repeated trials and execution order | Multiple trials and alternating audit variants reduce one ordering effect. Small trial counts support descriptive means/dispersion, not claims of statistical significance, universal speedup or production capacity. |
| Unequal audit persistence layout | The production Merkle variant appends JSONL and writes batch state; the simple hash-chain comparator replaces a full JSON snapshot. Storage and time differences therefore include these implementation choices. They do not establish an algorithmic lower bound or superiority over optimized conventional storage. |
| Event latency versus signing/deployment | Experiment 1 measures verification/authorization and audit handling, including actual anchor receipt waits on threshold events. Caller-side signing, contract deployment, initial trust setup and ML scoring are outside that timer. These exclusions must accompany every latency table. |
| Gas versus monetary cost | Receipt gas and local effective fees are measured. Hardhat gas-price conditions do not establish real-world monetary cost, public congestion or cost savings. Ordinary audit transactions and setup/trust transactions must be counted separately. |
| Fixed benchmark batching | The audit comparison uses its declared batch size and workloads, not a search for an optimal deployment policy. Batch size changes latency, transaction count and time exposed before anchoring. |
| Preserved baseline semantics | The original code is loaded from the pinned pre-fix commit in an isolated reference fixture. Its flat permission check does less work than corrected signature/ancestry/state validation. Timing differences include stronger semantics and durable storage, not merely the cascade loop. |
| Narrow delegation topology | Four agent identities, chains up to four agents and selected independent-parent cases are controlled coverage. They are not tests of arbitrarily large delegation graphs, organizational federation or adversarial graph-scale denial of service. |
| Constructed attack distribution | Experiment 3 intentionally balances named cases and repeats them. Attack-blocking rate, precision/recall/F1 and false rejection rate describe this finite matrix and chosen definitions; they are not estimated real-world prevalence or comprehensive security detection accuracy. |
| Component versus full-pipeline tests | The systematic security matrix invokes production authentication, grant, time, permission and proof components. Separate signed HTTP/WebSocket and local contract integration tests establish boundary usability. The matrix alone is not an end-to-end public deployment trial. |
| Behavioral anomaly is not an authorization exploit | Scope creep is expected to produce REVIEW when otherwise valid. Report it separately from binary malicious-request blocking metrics; do not count REVIEW as a blocked exploit or disguise a false rejection. |
| Synthetic ML data and saved model | Isolation Forest uses the repository's synthetic behavior features and persisted model/threshold. Fresh scoring of a known synthetic scope-creep example is not a new independent real-agent generalization study. No new claim of real-world anomaly accuracy, LLM comprehension, model robustness or causality is justified. |
| Historical five-scenario demo | Preserving ALLOW/BLOCK/BLOCK/REVIEW/BLOCK and original/tampered proofs protects compatibility and evidence integrity. Those saved outcomes alone do not prove the new authentication/cascade implementation; the new independent tests are essential. |
| Test completeness and external auditing | Regression tests and adversarial cases are finite and were developed alongside implementation changes. No independent organizational penetration test, formal verification or smart-contract audit certification is claimed. |

## Deliberately unsupported claims and future evaluation

Do not claim universal attack prevention, blockchain-only tamper detection, zero false positives on real traffic, production scale, tamper-proof storage, automatic exactly-once blockchain transactions, or a publicly deployed grant-specific cascade extension. Do not combine old Hardhat measurements, new benchmark CSVs and historical Sepolia proof checks as if they were one experimental run.

Future work can evaluate an optimized append-only hash-chain/database baseline, external witnesses, durable anti-rollback state, standardized workload identity and proof-of-possession protocols, key rotation/HSMs, larger independently generated delegation graphs, audited public deployment of the extension, multi-host storage, provider/reorganization fault injection and real-agent behavioral datasets. These are proposed evaluations/integrations, not completed project features.

Primary literature and standards underlying the comparison are listed in [RELATED_WORK_COMPARISON.md](RELATED_WORK_COMPARISON.md). Reproduction entry points, source versions, raw output and exact successful checks must be taken from [REPRODUCTION_GUIDE.md](REPRODUCTION_GUIDE.md) and the final research verification report.
