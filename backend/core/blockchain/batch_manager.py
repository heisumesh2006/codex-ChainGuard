"""Create and persist deterministic Merkle batches of off-chain audit records."""

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import threading
from typing import Any

from .audit_log import AuditLogStore, hash_record
from .batch_verifier import generate_proof
from .merkle import build_merkle_tree


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
    merkle_root: str
    action_ids: list[str]
    leaf_hashes: list[str]
    status: str
    blockchain_tx_hash: str | None = None
    blockchain_block_number: int | None = None


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


class BatchManager:
    """Manage FIFO pending selection and immutable record-to-batch assignment."""

    _lock = threading.RLock()

    def __init__(
        self,
        audit_store: AuditLogStore | None = None,
        metadata_path: Path | str | None = None,
        batch_size: int | None = None,
        max_age_seconds: float | None = None,
    ):
        self.audit_store = audit_store or AuditLogStore()
        self.metadata_path = Path(metadata_path) if metadata_path is not None else BATCH_METADATA_PATH
        self.batch_size = BATCH_SIZE if batch_size is None else batch_size
        self.max_age_seconds = BATCH_MAX_AGE_SECONDS if max_age_seconds is None else max_age_seconds
        if not isinstance(self.batch_size, int) or self.batch_size < 1:
            raise ValueError("batch_size must be a positive integer")
        if self.max_age_seconds <= 0:
            raise ValueError("max_age_seconds must be greater than zero")

    def _read_state(self) -> dict[str, Any]:
        if not self.metadata_path.exists():
            return {"schema_version": BATCH_SCHEMA_VERSION, "batches": [], "action_index": {}, "pending_since": {}}
        try:
            with self.metadata_path.open("r", encoding="utf-8") as handle:
                state = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Could not read batch metadata: {self.metadata_path}") from exc
        if (not isinstance(state, dict) or not isinstance(state.get("batches"), list)
                or not isinstance(state.get("action_index"), dict)):
            raise ValueError("Batch metadata has an invalid shape")
        state.setdefault("pending_since", {})
        return state

    def _write_state(self, state: dict[str, Any]) -> None:
        self.metadata_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.metadata_path.with_suffix(self.metadata_path.suffix + ".tmp")
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(state, handle, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.metadata_path)

    def pending_records(self) -> list[dict[str, Any]]:
        """Return audit rows without a durable batch assignment, in append order."""
        with self._lock:
            assigned = self._read_state()["action_index"]
            return [record for record in self.audit_store.list_records()
                    if record["action_id"] not in assigned]

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
                    raise KeyError(f"Audit action is not assigned to a sealed batch: {action_id}")
                batch = self.get_batch(resolved_batch_id)
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
            return generate_proof(batch, leaf_index)

    def verify_record_proof(self, action_id: str) -> bool:
        """Convenience local check; portable verification is batch_verifier.verify_proof."""
        from .batch_verifier import verify_proof

        proof = self.generate_proof(action_id)
        record = self.audit_store.get(action_id)
        return record is not None and verify_proof(record, proof, proof["merkle_root"])
