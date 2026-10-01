"""Chronological action logging for Module 1."""

from copy import deepcopy
from datetime import datetime, timezone
import json
from uuid import uuid4


ACTION_LOG: list[dict] = []
VALID_RESULTS = {"ALLOWED", "BLOCKED", "REVOKED"}


def current_timestamp() -> str:
    """Return a timezone-aware ISO-8601 timestamp from the system clock."""
    return datetime.now(timezone.utc).isoformat()


def append_action_log(
    actor: str,
    action: str,
    claimed_authority: str,
    result: str,
    **extra_fields: object,
) -> dict:
    if result not in VALID_RESULTS:
        raise ValueError(f"Invalid action result: {result}")
    entry = {
        "record_id": f"action:{uuid4()}",
        "actor": actor,
        "action": action,
        "timestamp": current_timestamp(),
        "claimed_authority": claimed_authority,
        "result": result,
        **extra_fields,
    }
    ACTION_LOG.append(deepcopy(entry))
    return deepcopy(entry)


def get_action_log() -> list[dict]:
    """Return a snapshot so callers cannot mutate the audit trail."""
    return deepcopy(ACTION_LOG)


def print_action_log() -> None:
    for number, entry in enumerate(get_action_log(), start=1):
        print(f"Action {number}:")
        print(json.dumps(entry, indent=2))
