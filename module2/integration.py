"""Module 1 schema adaptation and deterministic Ethereum record identifiers."""

from copy import deepcopy
from datetime import datetime
import hashlib
import json


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def content_hash(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def blockchain_record_id(kind: str, record: dict) -> str:
    label = "action" if kind == "action" else kind
    return f"{label}:{content_hash(record)}"


def onchain_record_id(kind_code: int, digest: str) -> bytes:
    """Domain-separate records that commit the same content for different uses."""
    return hashlib.sha256(bytes([kind_code]) + bytes.fromhex(digest)).digest()


def agent_hash(agent_id: str) -> bytes:
    return bytes.fromhex(hashlib.sha256(agent_id.encode("utf-8")).hexdigest())


def permission_hash(permission: str) -> bytes:
    return bytes.fromhex(hashlib.sha256(permission.encode("utf-8")).hexdigest())


def timestamp_seconds(value: str) -> int:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("Timestamp must include a timezone")
    return int(parsed.timestamp())


def prepare_delegation(record: dict) -> dict:
    required = ("record_id", "delegator", "delegatee", "permission", "authority_source", "timestamp")
    if any(field not in record for field in required):
        raise ValueError("Incomplete Module 1 delegation record")
    return deepcopy(record)


def prepare_revocation(record: dict) -> dict:
    required = ("record_id", "action", "decommissioned_agent", "revoked_permissions", "actor", "timestamp")
    if any(field not in record for field in required) or record["action"] != "AGENT_DECOMMISSIONED":
        raise ValueError("Expected a complete Module 1 decommission action")
    return deepcopy(record)


def prepare_action(record: dict) -> dict:
    required = ("record_id", "actor", "action", "timestamp", "claimed_authority", "result")
    if any(field not in record for field in required):
        raise ValueError("Incomplete Module 1 action log entry")
    return deepcopy(record)
