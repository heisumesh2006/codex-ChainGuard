# Record-to-root investigation — before changes

Starting branch `main`, commit `0037ed3d7f3c66ae9543ec85b2d70461eda01146`.
Only the pre-existing research ZIP was untracked. Work proceeds on `fix/audit-tamper-clarity`; original source is recoverable from that starting commit. Protected research, public evidence and ZIP hashes are recorded in ignored `.runtime/audit-tamper-clarity/protected-before.json`.

## Existing flow

1. Selection GETs `/api/audit/actions/{id}/proof`. Verify action POSTs `/api/audit/actions/{id}/verify` without an override.
2. Test tamper detection GETs `/api/audit/actions/{id}`, shallow-copies its JSON record, and replaces only `target` with `${target || 'audit-record'} [tampered demo copy]`. It POSTs that override to the same verify endpoint. The changed field was not shown in the original summary.
3. `services._audit_action_proof` reads the real record through `AuditLogStore.get`; the candidate is the stored record or supplied override. The response's `record` remains the stored record, while `record_hash` hashes the candidate. Replacing one frontend proof state with this response made a stored-record heading show the candidate's failed result/hash.
4. `audit_log.canonicalize_record` normalizes values, then serializes sorted-key, compact, UTF-8 JSON with non-ASCII preserved and NaN forbidden. `hash_record` computes Ethereum Keccak-256 of those bytes.
5. `BatchManager.generate_proof` derives metadata from persisted batch leaves. `batch_verifier.verify_proof` checks action ID, committed leaf hash, batch/root identity, leaf count/index, sibling count, prescribed left/right direction, odd-node duplication and ordered Keccak child hashes. It rejects changed committed content at the leaf equality check, before reconstructing a valid path. No invalid reconstructed root is returned by this API.
6. Selected deployment context and provenance are checked. The service reads `auditBatches(Keccak(batch_id))` from the selected registry; a VERIFIED result additionally requires `verify_anchored_proof`, including chain, contract, anchored root, receipt and event consistency checks. RPC absence never produces VERIFIED.
7. A TAMPERED candidate result is computed from real proof rejection, not a hardcoded frontend result. However, local candidate rejection can precede successful RPC lookup; the new demonstration must also require actual original verification and the same available anchored root before presenting a confirmed blockchain comparison.
8. These GET/POST paths perform reads and hash calculations, not audit appends, batch sealing, signing or contract transactions. Copy modification does not alter persistence. The existing UI's single proof-state variable causes the contradictory presentation.

Sources: `frontend/src/pages/AuditExplorer.jsx`, `frontend/src/services/api.js`, `backend/api/main.py`, `backend/api/services.py`, `backend/core/blockchain/audit_log.py`, `batch_manager.py`, `batch_verifier.py`, `merkle.py`. Before screenshot: `before-confusing-copy.jpg` (actual connected Chrome).

Chosen scope: preserve shared backend cryptography and authentication unchanged. Correct frontend state separation and explain the existing `target` mutation; add API/cryptographic and browser regressions. No optional arbitrary field editor is necessary.
