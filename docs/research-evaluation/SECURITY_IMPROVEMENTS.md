# Security improvements and evidence boundaries

This research branch strengthens the implementation rather than changing paper claims alone. The preserved original authorization module is loaded from commit `f3b4574cb726264d9d6d01988e0d64940ae8c148` in isolated reference fixtures. Production code is never weakened to recreate the old behavior. Exact completed test counts and experimental results are reported separately in the final verification report and experiment documents.

## Reproduced weaknesses and corrected behavior

| Weakness in the preserved implementation | Correction | Permanent evidence |
| --- | --- | --- |
| A caller could claim the root's readable name and reach a root permission mutation without proof of identity. | Recover the actual signer of a bound EIP-191 request and compare it with the trusted registry's address. A readable actor name is only a lookup key. Root permission issuance additionally requires the authenticated root role. | `SignedAuthorityTests.test_unsigned_root_name_is_rejected_exact_original_reproduction`, `test_agent_key_cannot_claim_root_name`, `test_authenticated_nonroot_cannot_grant`; Experiment 3 before/after CSV |
| Descendants could retain flat permission entries after an intermediate delegator was decommissioned. | Resolve permissions from authenticated, time-valid grant ancestry; bind each delegation to one exact parent grant; invalidate dependent grant paths while preserving independent valid paths. | `test_cascade_exact_original_C_and_D_reproduction`, independent-root/other-parent tests; Experiment 2 depth and independent-path CSVs |
| A copied grant or mutable local field could otherwise masquerade as authority. | Retain the signed creation envelope; recompute its grant ID and issued time; verify actor, target, permission, expiry and parent binding before using the grant. Register-object checks reject caller-constructed agent clones. | Tampered metadata, cloned-agent, exact parent, expiry, forged proof and independent local-EVM tests |

## Request authentication

`backend/core/authorization/authentication.py` defines a custom signed request protocol. Canonical JSON is compact, key-sorted UTF-8 JSON with non-finite numbers rejected. Its message contains:

```text
protocol = "ChainGuard-AI signed request v1"
domain = selected chain ID and trusted registry address
actor = identity lookup key
operation = exact operation name
payload_sha256 = SHA-256 of the canonical operation payload
nonce = unique 32-character hexadecimal request value
issued_at, expires_at = integer UTC epoch seconds
signature = EIP-191 signature over the canonical message
```

The signature is recovered with `eth_account`; the expected public address is read from the selected `AgentTrustRegistry`. For the root identity it must also equal the registry's immutable `rootAuthorizer`. Clients cannot select a different resolver, registry, verifier or trust root through an HTTP parameter. A malformed envelope, changed actor/operation/payload/domain, unknown identity, bad signature, expired request, excessive lifetime or invalid nonce fails closed. A signature from Agent D over a message claiming to be the root cannot authenticate as the root.

Each request lifetime is at most 300 seconds, with at most five seconds of future clock skew. Durable replay checking serializes check-and-consume across independent OS processes. The cache key binds the domain, recovered address and nonce. A consumed request cannot be accepted again by restarting a verifier or using another participating worker. Private keys are held by the caller/operator and are not returned to the browser or stored in the envelope.

This is EIP-191 proof of possession with an application-specific schema. It is not EIP-712 typed-data signing, OAuth, DPoP, a bearer token or a standardized Verifiable Credential presentation. Application signatures authenticate request intent; transport security and trustworthy enrollment remain necessary.

## HTTP, WebSocket, SDK and demo boundaries

- Fresh HTTP governance actions supply the JSON envelope in `X-ChainGuard-Authentication`. Missing or invalid authentication returns a controlled 401 before runtime preparation or audit-record persistence.
- A custom WebSocket action supplies the same envelope in its `authentication` object. The socket's public error path uses the existing safe diagnostic handling. Replayed or substituted actions do not produce a second completed evaluation.
- Python root grants, delegations and decommissioning enforce authentication at the mutation function itself; avoiding the HTTP route does not bypass it. Internal trusted context reuse is bound to the exact actor, operation and canonical payload.
- Client requests cannot inject a trusted verifier. Explicit verifier injection is a trusted Python fixture/experiment facility only.
- Saved scenario replay is a read-only view of existing audit evidence. It does not reissue root permissions, run a privileged unsigned action, append another record or create public evidence.
- `DemoIdentity` creates short-lived keys and an independent temporary identity realm for disposable in-process demonstrations. These keys do not impersonate the existing Sepolia operator and are not persisted or exposed.
- `operator_signing.operator_credentials` is an explicit caller/CLI helper. On isolated local Hardhat it asks the registered unlocked development wallet to sign; outside Hardhat it requires a caller-provided matching operator key. It is never an automatic signing service inside an HTTP handler.

Hardhat's unlocked RPC is a **trusted development signing oracle**: anyone with access to it can ask an unlocked wallet to sign. These local experiments do not claim key isolation against an attacker controlling that RPC. It is bound to loopback for isolated tests, not a production authentication service. Outside this development harness, callers must control matching private signing credentials and protect their signer access.

Clients must sign the **normalized** public action body. In particular, `ActionInput` normalizes an aware timestamp to UTC with a `Z` suffix; the signature must cover that normalized representation. Supply an explicit timestamp before signing. Omitting it causes the server to supply a value the caller could not have signed. Caller-supplied `record_id` and `trace_result` are not authority and must not be used in the signed body; the public adapter creates its own synthetic record identity.

The local integration tests exercise genuine registry-bound Hardhat keys, signed HTTP requests, persistence, replay rejection and live WebSocket verdict completion. They are stronger evidence of usability than a unit test that merely mocks successful authentication.

## Authenticated grant graph and cascading revocation

`backend/core/authorization/agents.py` computes effective authority from grant paths rather than trusting a copied flat permission list. Root grants contain a signature-bound holder, scope and optional expiry. Delegations additionally bind the delegator, delegatee and exact `parent_grant_id`. The effective path must satisfy all of the following:

1. The agent and relevant ancestors have applicable live status.
2. Every required retained grant authenticates to its issuer's trusted public address.
3. The requested scope matches the signed scope and a selected authenticated parent path.
4. Issuance is inclusive and expiry exclusive after UTC normalization.
5. Child expiry does not exceed a finite selected parent expiry.
6. The path contains no self-delegation or cycle.

A genuine signed root request is necessary but not sufficient to give an unavailable/decommissioned agent a permission. Similarly, a genuine delegator signature is necessary but cannot create a scope the delegator does not possess.

Decommissioning an intermediate B invalidates its incoming/outgoing delegations and dependent descendants by **grant ancestry**, retaining their history. It does not globally decommission C and D. A distinct valid root-to-C or other-parent-to-C path survives. A later root grant has a new signature-derived grant ID; existing children bound to the old ID do not silently migrate to it. A newly valid independent C can explicitly authenticate a new delegation to D.

Revoked delegation rows remain in the ledger. Root decommissioning marks the retained signed root grants revoked; renewal archives an older root grant in `grant_history` before replacing the current entry. Repeated valid operations use explicit idempotence rules. An altered previously stored delegation must not shadow a fresh correctly signed reissue merely because its mutable fields appear to match.

Current action enforcement and historical evidence are intentionally distinct. Fresh requests require current authority as well as action-time validity; backdating a fresh action cannot revive a revoked path. Existing proof-based historical trace paths continue to verify the original evidence rather than replace historical issuance/expiry rules with today's status.

## Policy persistence and worker coordination

`backend/core/authorization/state.py` stores a registry/domain-specific authority snapshot under an ignored runtime location. Stable OS-owned file locks protect its whole read–mutate–write operation, and snapshots use the project's atomic replacement helper. The state reader validates domain and structural shape before hydration, preserves registered object references and prevents one worker's different identity realm from silently inheriting another realm's mutable grants.

If an operation raises before publication, its in-memory mutations are rolled back. A previously consumed nonce stays consumed, so a retry requires a new envelope. The filesystem assumptions and the separation between nonce consumption and policy publication are documented in [LIMITATIONS_AND_THREATS_TO_VALIDITY.md](LIMITATIONS_AND_THREATS_TO_VALIDITY.md). This is local durable enforcement state, not independently anchored proof of every policy update.

## Optional local grant-specific smart contract

`blockchain/contracts/GrantAuthority.sol` is a separate extension referencing `AgentTrustRegistry`. Only the immutable root can submit grant attestations or revoke a grant. Each immutable grant ID stores holder, scope, parent, block issue time, expiry and revocation time. Issuance rejects an invalid parent, scope/expiry escalation, repeated ID, unregistered/revoked holder, self/cyclic ancestry and excessive depth. `isValidNow` and `wasValidAt` walk every ancestor, applying issuance/expiry/revocation boundaries and legacy full-agent revocations. Independent same-scope grants remain distinct.

The Python adapter pins the manifest's chain/legacy registry/extension/deployment receipt and root sender. It matches **every** signed local path edge with the corresponding on-chain holder, scope, parent and applicable time fields. A valid but unrelated grant, wrong network, malformed manifest or mismatched intermediate commitment is not sufficient evidence.

Deployment and anchoring helpers refuse public profiles and require local Hardhat chain ID 31337. No existing Sepolia contract was upgraded or redeployed. The new contract verifies root-attested ancestry; it does not recover each off-chain delegator signature itself. Local signature validation, local revocation enforcement and independent on-chain evidence are therefore reported as separate layers. Existing public proofs remain legacy evidence.

## Existing protections preserved

The research changes retain context-aware provider diagnostic redaction, nested exception-chain suppression, safe public error categories, authenticated historical credential checks, issuance/expiry validation, network-specific evidence isolation, bounded receipt/event recovery, cross-process audit/batch coordination, canonical Keccak/Merkle verification and the governance engine's BLOCK/REVIEW/ALLOW policy. Their exact regression outcomes must be taken from the completed final test run, not inferred from this implementation description.

## Review map

| Area | Source | Tests / experiment |
| --- | --- | --- |
| Cryptographic request and replay | `backend/core/authorization/authentication.py` | `backend/core/authorization/tests/test_security.py`; `backend/api/tests/test_authentication.py` |
| Coordinated policy publication | `backend/core/authorization/state.py` | `backend/core/authorization/tests/test_policy_persistence.py`; signed authority and full regression tests |
| Root grant, scope, ancestry, cascade and history | `backend/core/authorization/agents.py` | Signed authority tests; Experiments 2 and 3 |
| Governance / saved replay boundary | `backend/core/governance/pipeline.py`; `backend/api/main.py`; `backend/api/services.py` | API authentication, pipeline and browser regressions |
| Contract transitive validity | `blockchain/contracts/GrantAuthority.sol` | `blockchain/test/grant-authority.test.js` |
| Signed live EVM/HTTP/WS agreement | `backend/core/blockchain/grant_authority.py` | `backend/core/blockchain/tests/test_grant_authority.py` |
| Original baseline preservation | `backend/research/common.py`: `BASE`, `original_module` | Experiments 2 and 3 before/after results |

See [REPRODUCTION_GUIDE.md](REPRODUCTION_GUIDE.md) for commands and [LIMITATIONS_AND_THREATS_TO_VALIDITY.md](LIMITATIONS_AND_THREATS_TO_VALIDITY.md) for unsupported guarantees. A finite passing matrix is not a formal security proof or a certification.
