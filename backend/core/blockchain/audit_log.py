"""Canonical off-chain audit records for governed agent actions.

Audit records are serialized as canonical UTF-8 JSON and hashed with Ethereum
Keccak-256. JSONL is append-only for normal writes; BatchManager assigns records
to Merkle batches separately without modifying this log.
"""

from dataclasses import asdict, dataclass, is_dataclass
from datetime import date, datetime, timezone
from decimal import Decimal
from enum import Enum
import json
import os
from pathlib import Path
import threading
from typing import Any
from uuid import uuid4

from web3 import Web3


AUDIT_LOG_PATH = Path(__file__).resolve().parent / "data" / "audit_logs.jsonl"
SCHEMA_VERSION = "1.0"


@dataclass
class AuditRecord:
    """One completed governance evaluation and its decision evidence."""

    action_id: str
    timestamp: str
    agent_id: str
    action: str
    scope: str | None
    target: str | None
    authorization_result: str
    trace_verdict: str
    anomaly_result: dict[str, Any]
    revocation_status: dict[str, Any] | None
    governance_verdict: str
    metadata: dict[str, Any]
    schema_version: str = SCHEMA_VERSION


class AuditLogError(Exception):
    """Base error for audit log persistence or decoding failures."""


class DuplicateActionIdError(AuditLogError):
    """Raised when append is attempted with an action ID already in the log."""


class AuditLogCorruptionError(AuditLogError):
    """Raised when an existing JSONL line cannot be decoded safely."""


def _normalize(value: Any) -> Any:
    """Convert supported Python values to deterministic JSON-compatible data."""
    if is_dataclass(value) and not isinstance(value, type):
        return _normalize(asdict(value))
    if isinstance(value, Enum):
        return _normalize(value.value)
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Naive datetimes are not allowed in canonical audit records")
        return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if isinstance(value, Path):
        return str(value)
    if hasattr(value, "model_dump") and callable(value.model_dump):
        return _normalize(value.model_dump(mode="python"))
    if isinstance(value, dict):
        normalized = {}
        for key, item in value.items():
            normalized_key = key.value if isinstance(key, Enum) else key
            if not isinstance(normalized_key, str):
                raise TypeError("Canonical audit JSON object keys must be strings")
            if normalized_key in normalized:
                raise ValueError(f"Duplicate canonical audit key: {normalized_key}")
            normalized[normalized_key] = _normalize(item)
        return normalized
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"Unsupported canonical audit value: {type(value).__name__}")


def canonicalize_record(record: AuditRecord | dict[str, Any]) -> bytes:
    """Return canonical UTF-8 JSON bytes for the same logical record."""
    normalized = _normalize(record)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def hash_record(record: AuditRecord | dict[str, Any]) -> str:
    """Return a 0x-prefixed Ethereum Keccak-256 digest of canonical bytes."""
    return "0x" + Web3.keccak(canonicalize_record(record)).hex().removeprefix("0x")


def audit_record_from_verdict(verdict: Any) -> AuditRecord:
    """Adapt the existing governance verdict into the stable audit schema."""
    action = verdict.action
    timestamp = action.get("timestamp")
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)
    elif isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("Governed action timestamp must be ISO-8601") from exc
    if not isinstance(timestamp, datetime):
        raise TypeError("Governed action timestamp must be a datetime or ISO-8601 string")
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("Governed action timestamp must include a timezone")
    timestamp_text = _normalize(timestamp)
    trace = verdict.trace_context_verdict
    revocation = verdict.revocation_status
    return AuditRecord(
        action_id=f"audit:{uuid4().hex}",
        timestamp=timestamp_text,
        agent_id=str(action.get("actor", "UNKNOWN")),
        action=str(action.get("action", "UNKNOWN")),
        scope=action.get("permission") or action.get("requested_permission"),
        target=action.get("target") or action.get("delegatee") or action.get("resource"),
        authorization_result="ALLOWED" if verdict.authorized else "DENIED",
        trace_verdict=str(trace),
        anomaly_result={
            "applicable": bool(verdict.drift_applicable),
            "flagged": bool(verdict.drift_flagged),
            "score": verdict.drift_score,
        },
        revocation_status=revocation,
        governance_verdict=str(verdict.governance_decision),
        metadata={
            "source_action_id": action.get("record_id"),
            "source_result": action.get("result"),
            "claimed_authority": action.get("claimed_authority"),
            "reason": action.get("reason"),
            "detected_by": verdict.detected_by,
            "chain_check_status": verdict.chain_check_status,
            "chain_evidence": verdict.chain_evidence,
        },
    )


class AuditLogStore:
    """Append-only JSONL store with deterministic duplicate-ID rejection."""

    _lock = threading.RLock()

    def __init__(self, path: Path | str | None = None):
        self.path = Path(path) if path is not None else AUDIT_LOG_PATH

    def _read_records(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        records = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise AuditLogCorruptionError(
                        f"Invalid audit JSON at {self.path}:{line_number}"
                    ) from exc
                if not isinstance(record, dict) or not isinstance(record.get("action_id"), str):
                    raise AuditLogCorruptionError(
                        f"Invalid audit record shape at {self.path}:{line_number}"
                    )
                records.append(record)
        return records

    def append(self, record: AuditRecord | dict[str, Any]) -> dict[str, Any]:
        """Append once; duplicate action IDs raise without altering prior lines."""
        encoded = canonicalize_record(record)
        value = json.loads(encoded)
        action_id = value.get("action_id")
        if not isinstance(action_id, str) or not action_id:
            raise ValueError("Audit records require a non-empty action_id")
        with self._lock:
            if any(existing["action_id"] == action_id for existing in self._read_records()):
                raise DuplicateActionIdError(f"Audit action_id already exists: {action_id}")
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("ab") as handle:
                handle.write(encoded + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
        return value

    def get(self, action_id: str) -> dict[str, Any] | None:
        for record in self._read_records():
            if record["action_id"] == action_id:
                return record
        return None

    def list_records(self) -> list[dict[str, Any]]:
        """Return decoded records in insertion order."""
        return self._read_records()

    def list_unbatched_records(self) -> list[dict[str, Any]]:
        """All records are unbatched in this phase; preserve the future API."""
        return [record for record in self._read_records() if not record.get("batch_id")]

    def count(self) -> int:
        return len(self._read_records())
