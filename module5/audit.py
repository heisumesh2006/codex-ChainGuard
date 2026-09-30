"""Independent post-revocation forensic audit over verified Module 2 evidence."""

from datetime import datetime, timezone

from .revocation import get_revocation_status


def _aware_timestamp(value):
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("Action and revocation timestamps must be timezone-aware ISO-8601")
    return parsed.astimezone(timezone.utc)


def check_post_revocation_activity(action_log_entry) -> dict:
    """Flag actions strictly after the verified local revocation time.

    The decommission event itself is excluded. The boundary is `action_time >
    revoked_at`; equality is not post-revocation activity. `result` is ignored.
    """
    actor = action_log_entry["actor"]
    action_time = _aware_timestamp(action_log_entry["timestamp"])
    if action_log_entry.get("action") == "AGENT_DECOMMISSIONED":
        return {"violation": False, "detail": "Decommission event is excluded",
                "agent_id": actor, "action_timestamp": action_log_entry["timestamp"],
                "revoked_at": None, "chain_verified": False}
    status = get_revocation_status(actor)
    if not status["is_revoked"]:
        return {"violation": False, "detail": f"Agent status is {status['status']}",
                "agent_id": actor, "action_timestamp": action_log_entry["timestamp"],
                "revoked_at": None, "chain_verified": status["agent_found"]}

    # The detailed registry stores the original Module 1 timestamp and scopes.
    # This makes the exact boundary independently available from Ethereum.
    revoked_at = _aware_timestamp(status["revoked_at"])
    violation = action_time > revoked_at
    return {
        "violation": violation,
        "detail": ("Activity occurred after verified decommission time" if violation
                   else "Activity occurred at or before verified decommission time"),
        "agent_id": actor, "action_timestamp": action_log_entry["timestamp"],
        "revoked_at": status["revoked_at"], "chain_verified": True,
        "record_id": status["chain_proof"]["record_id"],
        "transaction_hash": status["chain_proof"]["transaction_hash"],
        "block_number": status["chain_proof"]["block_number"],
    }


def calculate_revocation_completeness(attempts):
    """Count post-revocation attempts caught by real-time or audit defense."""
    total = realtime = audited = either = 0
    for action in attempts:
        audit = check_post_revocation_activity(action)
        if not audit["violation"]:
            continue
        total += 1
        blocked = action.get("result") == "BLOCKED" and action.get("reason") == "AGENT_DECOMMISSIONED"
        realtime += int(blocked)
        audited += 1
        either += int(blocked or audit["violation"])
    return {
        "post_revocation_attempts": total,
        "caught_by_realtime": realtime,
        "caught_by_audit": audited,
        "caught_by_either": either,
        "revocation_completeness": either / total if total else 0.0,
    }
