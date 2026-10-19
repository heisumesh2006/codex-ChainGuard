"""Create and persist deterministic Merkle batches of off-chain audit records."""

from dataclasses import asdict, dataclass
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from typing import Any

from backend.core.blockchain.diagnostics import safe_error, safe_exception

from web3 import Web3
from web3.exceptions import MismatchedABI, LogTopicError

from .audit_log import AuditLogStore, hash_record
from .batch_verifier import generate_proof
from .merkle import build_merkle_tree
from .persistence import FileLock, atomic_write
from .evidence import read_object, validate_batch_state, EvidenceError


class AnchorSubmissionUncertain(RuntimeError):
    """A previous owner may have submitted; do not automatically resubmit."""


class BatchStateConflict(RuntimeError):
    """A retained snapshot is stale; retry against newly loaded state."""


DATA_DIR = Path(__file__).resolve().parent / "data"
BATCH_METADATA_PATH = DATA_DIR / "batches.json"
BATCH_SIZE = int(os.environ.get("CHAINGUARD_BATCH_SIZE", "5"))
BATCH_MAX_AGE_SECONDS = float(os.environ.get("CHAINGUARD_BATCH_MAX_AGE_SECONDS", "30"))
BATCH_SCHEMA_VERSION = "1.0"


@dataclass
class AuditBatch:
    batch_id: str
    schema_version: str
    created_at: str
    sealed_at: str
    log_count: int
    first_action_id: str
    last_action_id: str
    start_timestamp: str
    end_timestamp: str
    merkle_root: str
    action_ids: list[str]
    leaf_hashes: list[str]
    status: str
    blockchain_tx_hash: str | None = None
    blockchain_block_number: int | None = None
    blockchain_contract_address: str | None = None
    blockchain_chain_id: int | None = None
    blockchain_rpc_url: str | None = None
    blockchain_anchored_by: str | None = None
    blockchain_anchored_at: int | None = None
    anchor_retry: bool = True
    anchor_error: str | None = None


def _utc_now(value: datetime | None = None) -> datetime:
    result = value if value is not None else datetime.now(timezone.utc)
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("Batch timestamps must be timezone-aware")
    return result.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Audit record timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


def batch_key(batch_id: str) -> bytes:
    """Return the stable bytes32 registry key for a deterministic batch ID."""
    return Web3.keccak(text=batch_id)


def _matching_batch_event(web3, contract, key: bytes, root: bytes, *, deployment=None, anchored_at=None, transaction_hash=None):
    """Receipt-first recovery; fallback queries only the anchor timestamp's blocks."""
    if transaction_hash:
        receipt = web3.eth.get_transaction_receipt(transaction_hash)
        matches = []
        for log in receipt.logs:
            if log["address"].lower() != contract.address.lower():
                continue
            try:
                event = contract.events.AuditBatchAnchored().process_log(log)["args"]
            except (ValueError, KeyError, MismatchedABI, LogTopicError):
                continue
            if event["batchId"] == key and event["merkleRoot"] == root:
                matches.append(event)
        if receipt.status != 1 or len(matches) != 1:
            raise EvidenceError("RECOVERY_EVIDENCE_INVALID")
        return receipt
    signature = "AuditBatchAnchored(bytes32,bytes32,uint64,uint64,uint64,address,uint64)"
    logs = _bounded_event_logs(web3, contract.address, [Web3.keccak(text=signature), key, root], deployment or {}, anchored_at)
    if len(logs) != 1:
        raise EvidenceError("RECOVERY_EVIDENCE_INVALID")
    return _matching_batch_event(web3, contract, key, root, transaction_hash=Web3.to_hex(logs[0].transactionHash))


def _bounded_event_logs(web3, address, topics, deployment, anchored_at):
    """Bound discovery to at most 256 blocks at the authenticated anchor time."""
    start = deployment.get("block_number")
    end = int(web3.eth.block_number)
    if type(start) is not int or start < 0 or start > end or type(anchored_at) is not int:
        raise EvidenceError("RECOVERY_EVIDENCE_UNAVAILABLE")
    # Lower/upper timestamp bounds: at most 2*log2(chain height) read calls.
    def bound(strict):
        low, high = start, end + 1
        while low < high:
            mid = (low + high) // 2
            timestamp = int(web3.eth.get_block(mid).timestamp)
            if timestamp < anchored_at or strict and timestamp == anchored_at:
                low = mid + 1
            else:
                high = mid
        return low
    first, last = bound(False), bound(True) - 1
    if first > last or last - first + 1 > 256:
        raise EvidenceError("RECOVERY_RANGE_UNAVAILABLE")
    def query(low, high):
        try:
            return web3.eth.get_logs({"fromBlock": low, "toBlock": high, "address": address,
                                     "topics": topics})
        except Exception as exc:
            # Provider limits differ; bisect a bounded range, never expand it.
            if low == high or not any(term in safe_error(exc).lower() for term in ("range", "limit", "too many")):
                raise EvidenceError("RPC_RECOVERY_UNAVAILABLE") from None
            mid = (low + high) // 2
            return query(low, mid) + query(mid + 1, high)
    logs = []
    for low in range(first, last + 1, 64):
        logs.extend(query(low, min(last, low + 63)))
    return logs


class BatchManager:
    """Manage FIFO pending selection and immutable record-to-batch assignment."""

    def __init__(
        self,
        audit_store: AuditLogStore | None = None,
        metadata_path: Path | str | None = None,
        batch_size: int | None = None,
        max_age_seconds: float | None = None,
        lock_timeout: float = 10.0,
    ):
        self.audit_store = audit_store or AuditLogStore()
        self.metadata_path = (Path(metadata_path) if metadata_path is not None else BATCH_METADATA_PATH).resolve()
        self._lock = FileLock(str(self.metadata_path) + ".lock", lock_timeout)
        self.lock_timeout = lock_timeout
        self.batch_size = BATCH_SIZE if batch_size is None else batch_size
        self.max_age_seconds = BATCH_MAX_AGE_SECONDS if max_age_seconds is None else max_age_seconds
        if not isinstance(self.batch_size, int) or self.batch_size < 1:
            raise ValueError("batch_size must be a positive integer")
        if self.max_age_seconds <= 0:
            raise ValueError("max_age_seconds must be greater than zero")

    def _read_state(self) -> dict[str, Any]:
        with self._lock:
            return self._read_state_unlocked()

    def _read_state_unlocked(self) -> dict[str, Any]:
        if not self.metadata_path.exists():
            return {"schema_version": BATCH_SCHEMA_VERSION, "batches": [], "action_index": {}, "pending_since": {}}
        state = read_object(self.metadata_path)
        validate_batch_state(state)
        state.setdefault("pending_since", {})
        return state

    def _write_state(self, state: dict[str, Any]) -> None:
        with self._lock:
            validate_batch_state(state)
            current = self._read_state_unlocked()
            revision = current.get("revision", 0)
            if state.get("revision", 0) != revision:
                raise BatchStateConflict("BATCH_STATE_CONFLICT: reload before retrying")
            updated = {**state, "revision": revision + 1}
            encoded = json.dumps(updated, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
            atomic_write(self.metadata_path, encoded + b"\n")
            state["revision"] = revision + 1

    @contextmanager
    def state_transaction(self):
        """Short local read-modify-write transaction; never perform RPC here."""
        with self._lock:
            state = self._read_state()
            yield state
            self._write_state(state)

    @contextmanager
    def snapshot(self):
        """Consistent audit + batch view; lock order is metadata then audit."""
        with self._lock, self.audit_store._lock:
            yield self.audit_store.list_records(), self._read_state()

    def pending_records(self) -> list[dict[str, Any]]:
        """Return audit rows without a durable batch assignment, in append order."""
        with self._lock:
            assigned = self._read_state()["action_index"]
            return [record for record in self.audit_store.list_records()
                    if record["action_id"] not in assigned]

    def pending_summary(self, now: datetime | None = None) -> dict[str, Any]:
        """Describe the open pending group and its local queue age."""
        current_time = _utc_now(now)
        with self._lock:
            state = self._read_state()
            pending = [record for record in self.audit_store.list_records()
                       if record["action_id"] not in state["action_index"]]
            oldest = pending[0] if pending else None
            pending_since = state["pending_since"].get(oldest["action_id"]) if oldest else None
            age_seconds = (max(0.0, (current_time - _parse_timestamp(pending_since)).total_seconds())
                           if pending_since else None)
            return {
                "pending_log_count": len(pending),
                "oldest_pending_action_id": oldest["action_id"] if oldest else None,
                "oldest_pending_since": pending_since,
                "oldest_pending_age_seconds": age_seconds,
                "current_batch": {
                    "first_action_id": pending[0]["action_id"],
                    "last_action_id": pending[-1]["action_id"],
                    "log_count": len(pending),
                    "threshold": self.batch_size,
                } if pending else None,
            }

    def record_status(self, action_id: str) -> dict[str, Any] | None:
        with self._lock:
            state = self._read_state()
            batch_id = state["action_index"].get(action_id)
            if batch_id is not None:
                batch = next((item for item in state["batches"] if item["batch_id"] == batch_id), None)
                if batch is None:
                    raise ValueError("Action index points to a missing batch")
                return {"status": "BATCHED", "batch_id": batch_id, "batch": batch}
            if self.audit_store.get(action_id) is not None:
                return {"status": "PENDING", "batch_id": None, "batch": None}
            return None

    def seal_due_batches(self, now: datetime | None = None) -> list[dict[str, Any]]:
        """Seal full size groups and any aged remainder; return newly sealed batches.

        Call periodically as well as after appends to enforce the age trigger while
        the service is idle. Records are never modified; their assignment is kept
        only in the separate batch metadata index.
        """
        current_time = _utc_now(now)
        sealed = []
        with self._lock:
            state = self._read_state()
            assigned = state["action_index"]
            all_records = self.audit_store.list_records()
            pending = [record for record in all_records if record["action_id"] not in assigned]
            pending_since = state["pending_since"]
            live_pending_ids = {record["action_id"] for record in pending}
            for old_action_id in set(pending_since) - live_pending_ids:
                del pending_since[old_action_id]
            for record in pending:
                pending_since.setdefault(record["action_id"], _iso(current_time))
            # Persist first-seen times even when no batch is due yet. This clock
            # measures local pending age, not a possibly historical action time.
            if not self.metadata_path.exists() or pending:
                self._write_state(state)
            while pending:
                oldest_pending_at = _parse_timestamp(pending_since[pending[0]["action_id"]])
                aged = current_time - oldest_pending_at >= timedelta(seconds=self.max_age_seconds)
                if len(pending) >= self.batch_size:
                    selected = pending[:self.batch_size]
                elif aged:
                    selected = pending
                else:
                    break

                action_ids = [record["action_id"] for record in selected]
                leaf_hashes = [hash_record(record) for record in selected]
                merkle_root = build_merkle_tree(leaf_hashes)["root"]
                record_times = [_parse_timestamp(record["timestamp"]) for record in selected]
                batch_id = f"batch:{merkle_root}"
                if any(item["batch_id"] == batch_id for item in state["batches"]):
                    raise ValueError("Deterministic batch ID already exists without matching assignments")
                timestamp = _iso(current_time)
                batch = AuditBatch(
                    batch_id=batch_id,
                    schema_version=BATCH_SCHEMA_VERSION,
                    created_at=timestamp,
                    sealed_at=timestamp,
                    log_count=len(selected),
                    first_action_id=action_ids[0],
                    last_action_id=action_ids[-1],
                    start_timestamp=_iso(min(record_times)),
                    end_timestamp=_iso(max(record_times)),
                    merkle_root=merkle_root,
                    action_ids=action_ids,
                    leaf_hashes=leaf_hashes,
                    status="SEALED_UNANCHORED",
                )
                value = asdict(batch)
                state["batches"].append(value)
                for action_id in action_ids:
                    if action_id in assigned:
                        raise ValueError(f"Audit record already assigned to a batch: {action_id}")
                    assigned[action_id] = batch_id
                    pending_since.pop(action_id, None)
                self._write_state(state)
                sealed.append(value)
                pending = pending[len(selected):]
        return sealed

    def _persist_batch(self, batch: dict[str, Any]) -> None:
        """Merge this owner's batch into fresh state; preserve other writers."""
        with self.state_transaction() as state:
            current = next((item for item in state["batches"] if item["batch_id"] == batch["batch_id"]), None)
            if current is None:
                raise KeyError("Audit batch disappeared during anchoring")
            current.clear()
            current.update(deepcopy(batch))

    def anchor_batch(self, batch_id: str) -> dict[str, Any]:
        """Anchor one sealed root through ROOT_AUTHORIZER and persist its receipt.

        A retry first checks contract storage. If the earlier transaction was
        mined but the process failed before saving JSON metadata, its original
        event receipt is reused instead of submitting a second transaction.
        """
        operation_lock = FileLock(str(self.metadata_path) + "." + batch_key(batch_id).hex() + ".anchor.lock", self.lock_timeout)
        # Per-batch ownership may span RPC; global snapshot locks never do.
        with operation_lock:
            batch = self.get_batch(batch_id)
            if batch is None:
                raise KeyError(f"Unknown audit batch: {batch_id}")
            if batch["status"] == "ANCHORED":
                from .batch_verifier import verify_anchored_batch

                if not verify_anchored_batch(batch):
                    raise RuntimeError("Previously anchored batch no longer verifies on-chain")
                return batch

            try:
                from . import chain

                web3, contract, root_authorizer, deployment = chain.contract_context()
                key = batch_key(batch_id)
                merkle_root = bytes.fromhex(batch["merkle_root"][2:])
                start_timestamp = int(_parse_timestamp(batch["start_timestamp"]).timestamp())
                end_timestamp = int(_parse_timestamp(batch["end_timestamp"]).timestamp())
                stored = contract.functions.auditBatches(key).call()
                if stored[6]:
                    if (stored[0] != merkle_root or stored[1] != batch["log_count"]
                            or stored[2] != start_timestamp or stored[3] != end_timestamp
                            or Web3.to_checksum_address(stored[4]) != root_authorizer):
                        raise RuntimeError("Existing on-chain batch ID has conflicting metadata")
                    receipt = _matching_batch_event(web3, contract, key, merkle_root, deployment=deployment, anchored_at=int(stored[5]), transaction_hash=batch.get("anchor_claim", {}).get("transaction_hash") or batch.get("blockchain_tx_hash"))
                else:
                    if batch.get("anchor_claim", {}).get("phase") in ("SUBMITTING", "SUBMITTED"):
                        known_hash = batch["anchor_claim"].get("transaction_hash")
                        if known_hash:
                            from web3.exceptions import TransactionNotFound
                            try:
                                prior_receipt = web3.eth.get_transaction_receipt(known_hash)
                            except TransactionNotFound:
                                prior_receipt = None
                            if prior_receipt is not None and prior_receipt.status == 0:
                                batch.pop("anchor_claim", None)
                                self._persist_batch(batch)
                                raise RuntimeError("Prior audit-batch transaction reverted; retry is safe")
                        raise AnchorSubmissionUncertain("TRANSACTION_FAILED: prior submission is uncertain; reconciliation required")
                    # Intent is durable BEFORE any send. A crash in/after send
                    # cannot turn into permission for another automatic send.
                    # Serialize nonce selection + send for different batches in
                    # this profile too. This is NOT the global storage lock;
                    # readers, appends and sealing remain available during RPC.
                    submission_lock = FileLock(str(self.metadata_path) + ".submission.lock", self.lock_timeout)
                    with submission_lock:
                        batch["anchor_claim"] = {"phase": "SUBMITTING"}
                        self._persist_batch(batch)
                        def remember_signed(tx_hash, nonce):
                            batch["anchor_claim"] = {"phase": "SUBMITTED", "transaction_hash": tx_hash, "nonce": nonce}
                            self._persist_batch(batch)
                        send_options = {"before_send": remember_signed} if chain.NETWORK_PROFILE == "sepolia" else {}
                        tx_hash = chain.submit_transaction(
                            web3,
                            contract.functions.anchorAuditBatch(
                                key, merkle_root, batch["log_count"], start_timestamp, end_timestamp,
                            ),
                            root_authorizer, **send_options,
                        )
                        batch["anchor_claim"].update(phase="SUBMITTED", transaction_hash=Web3.to_hex(tx_hash))
                        self._persist_batch(batch)
                    receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
                    if receipt.status != 1:
                        # A confirmed failed receipt proves no successful send
                        # is pending, so this specific failure can be retried.
                        batch.pop("anchor_claim", None)
                        raise RuntimeError("Ethereum audit-batch transaction reverted")
                confirmed = contract.functions.auditBatches(key).call()
                if (not confirmed[6] or confirmed[0] != merkle_root
                        or confirmed[1] != batch["log_count"]
                        or confirmed[2] != start_timestamp or confirmed[3] != end_timestamp
                        or Web3.to_checksum_address(confirmed[4]) != root_authorizer):
                    raise RuntimeError("On-chain batch metadata did not match the submitted commitment")
                if receipt.status != 1:
                    raise RuntimeError("Audit-batch transaction receipt was unsuccessful")
                batch.update({
                    "status": "ANCHORED",
                    "blockchain_tx_hash": Web3.to_hex(receipt.transactionHash),
                    "blockchain_block_number": receipt.blockNumber,
                    "blockchain_contract_address": contract.address,
                    "blockchain_chain_id": web3.eth.chain_id,
                    "blockchain_rpc_url": "" if chain.NETWORK_PROFILE == "sepolia" else deployment.get("rpc_url", ""),
                    "blockchain_anchored_by": Web3.to_checksum_address(confirmed[4]),
                    "blockchain_anchored_at": confirmed[5],
                    "anchor_retry": False,
                    "anchor_error": None,
                })
                batch.pop("anchor_claim", None)
                self._persist_batch(batch)
                return batch
            except Exception as exc:
                batch["status"] = "SEALED_UNANCHORED"
                batch["anchor_retry"] = True
                batch["anchor_error"] = safe_error(exc)
                self._persist_batch(batch)
                raise safe_exception(exc) from None

    def anchor_unanchored_batches(self) -> list[dict[str, Any]]:
        """Attempt every sealed batch and retain failures as retryable metadata."""
        results = []
        for batch in self.list_batches():
            if batch["status"] == "ANCHORED":
                continue
            try:
                results.append(self.anchor_batch(batch["batch_id"]))
            except Exception:
                current = self.get_batch(batch["batch_id"])
                if current is not None:
                    results.append(current)
        return results

    def list_batches(self) -> list[dict[str, Any]]:
        with self._lock:
            return self._read_state()["batches"]

    def get_batch(self, batch_id: str) -> dict[str, Any] | None:
        with self._lock:
            return next((batch for batch in self._read_state()["batches"]
                         if batch["batch_id"] == batch_id), None)

    def generate_proof(self, action_id_or_leaf_index: str | int, batch_id: str | None = None) -> dict[str, Any]:
        """Generate a portable proof by action ID, or by index plus batch ID."""
        with self._lock:
            state = self._read_state()
            if isinstance(action_id_or_leaf_index, str):
                action_id = action_id_or_leaf_index
                resolved_batch_id = state["action_index"].get(action_id)
                if resolved_batch_id is None:
                    raise EvidenceError("PROOF_UNAVAILABLE", 503)
                batch = self.get_batch(resolved_batch_id)
                if batch is None:
                    raise ValueError("Action index points to a missing batch")
                leaf_index = batch["action_ids"].index(action_id)
            elif isinstance(action_id_or_leaf_index, int) and batch_id is not None:
                batch = self.get_batch(batch_id)
                if batch is None:
                    raise KeyError(f"Unknown batch: {batch_id}")
                leaf_index = action_id_or_leaf_index
                if not 0 <= leaf_index < batch["log_count"]:
                    raise IndexError("Batch leaf index is out of range")
                action_id = batch["action_ids"][leaf_index]
            else:
                raise TypeError("Supply an action_id or a leaf index and batch_id")
            if batch is None:
                raise ValueError("Action index points to a missing batch")
            proof = generate_proof(batch, leaf_index)
            proof["start_timestamp"] = batch["start_timestamp"]
            proof["end_timestamp"] = batch["end_timestamp"]
            if batch["status"] == "ANCHORED":
                proof["blockchain"] = {
                    "transaction_hash": batch["blockchain_tx_hash"],
                    "block_number": batch["blockchain_block_number"],
                    "contract_address": batch["blockchain_contract_address"],
                    "chain_id": batch["blockchain_chain_id"],
                    "rpc_url": batch["blockchain_rpc_url"],
                    "anchored_by": batch["blockchain_anchored_by"],
                    "anchored_at": batch["blockchain_anchored_at"],
                }
            return proof

    def verify_record_proof(self, action_id: str) -> bool:
        """Convenience local check; portable verification is batch_verifier.verify_proof."""
        from .batch_verifier import verify_proof

        proof = self.generate_proof(action_id)
        record = self.audit_store.get(action_id)
        return record is not None and verify_proof(record, proof, proof["merkle_root"])

    def verify_anchored_record_proof(self, action_id: str) -> bool:
        """Verify a record's Merkle path against the registry's stored root."""
        from .batch_verifier import verify_anchored_proof

        proof = self.generate_proof(action_id)
        record = self.audit_store.get(action_id)
        return record is not None and verify_anchored_proof(record, proof)
