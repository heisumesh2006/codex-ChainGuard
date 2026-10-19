"""Explicit cryptographic test fixtures, not an authentication bypass."""

from backend.core.authorization.demo_identity import DemoIdentity
from contextvars import ContextVar

fixture_identity = ContextVar("signed_test_fixture_identity", default=None)


def run_signed_pipeline(action, **kwargs):
    from backend.core.governance.pipeline import run_governance_pipeline
    if not str(action.get("record_id", "")).startswith("synthetic:"):
        return run_governance_pipeline(action, **kwargs)
    payload = {k: v for k, v in action.items() if k not in ("record_id", "trace_result")}
    identity = fixture_identity.get()
    if identity is not None:
        return run_governance_pipeline(action, **identity.credentials(action["actor"], "evaluate", payload), **kwargs)
    with DemoIdentity() as identity:
        return run_governance_pipeline(action, **identity.credentials(action["actor"], "evaluate", payload), **kwargs)


def authenticated_revoke(agent_id, permissions_to_revoke, revoked_by, reason):
    from backend.core.revocation.revocation import revoke
    from backend.core.authorization import agents as a
    saved = a._policy_verifier
    try:
        with DemoIdentity() as identity:
            return revoke(agent_id, permissions_to_revoke, revoked_by, reason, **identity.credentials(
                revoked_by, "decommission", {"agent_id": agent_id, "reason": reason}))
    finally:
        a._policy_verifier = saved
