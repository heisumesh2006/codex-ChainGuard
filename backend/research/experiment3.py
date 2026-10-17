"""Request-level controlled security matrix using production component checks.

Not a simulation of public traffic and not a claim of general attack recall.
The scope-creep input comes from the saved synthetic feature benchmark; its
decision is freshly scored, not read from a saved governance decision.
"""

from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import time
from unittest.mock import patch
import joblib

from backend.core.authorization import agents as a
from backend.core.authorization.authentication import AuthenticationError, sign_request
from backend.core.authorization.state import refresh_policy, _path
from backend.core.blockchain.audit_log import hash_record
from backend.core.blockchain.batch_verifier import generate_proof, verify_proof
from backend.core.blockchain.merkle import build_merkle_tree
from backend.core.drift_detection.detector import score_action
from .common import local_policy, root_grant, delegate, revoke, original_module
from .experiment1 import save_csv, audit_record

ROOT = Path(__file__).resolve().parents[1]
CASES = ["legitimate_direct", "legitimate_delegated", "legitimate_root_grant", "unauthorized_request",
         "missing_permission", "expired_credential", "not_yet_issued", "privilege_escalation", "root_impersonation",
         "replayed_authentication", "unauthorized_delegation", "self_delegation", "revoked_agent",
         "invalid_intermediate", "tampered_credential_metadata", "forged_proof", "scope_creep", "post_decommission"]


def action_check(identity, actor, permission, *, at_time=None):
    payload = {"actor": actor, "permission": permission, "action_time": at_time}
    envelope = identity.credentials(actor, "security_action", payload)["authentication"]
    def execute():
        identity.verifier.authenticate(envelope, "security_action", payload, actor)
        refresh_policy(identity.verifier)
        allowed = bool(a.authority_paths(actor, permission, at_time=at_time))
        return "ALLOW" if allowed else "BLOCK"
    return execute


def prepare(case, identity):
    root_grant(identity)
    if case == "legitimate_direct": return action_check(identity, "Agent_A", "P")
    if case == "legitimate_delegated":
        delegate(identity, "Agent_A", "Agent_B")
        return action_check(identity, "Agent_B", "P")
    if case in ("legitimate_root_grant", "privilege_escalation", "root_impersonation"):
        actor = "ROOT_AUTHORIZER" if case != "privilege_escalation" else "Agent_D"
        payload = {"agent_id": "Agent_D", "permission": "ADMIN", "expires_at": None}
        credentials = identity.credentials(actor, "root_grant", payload)
        if case == "root_impersonation":
            credentials["authentication"] = sign_request(identity.accounts["Agent_D"], identity.verifier.domain,
                                                           "ROOT_AUTHORIZER", "root_grant", payload)
        return lambda: "ALLOW" if a.grant_root_permission("Agent_D", "ADMIN", requester=actor, **credentials)["result"] == "ALLOWED" else "BLOCK"
    if case == "unauthorized_request": return action_check(identity, "Agent_D", "P")
    if case == "missing_permission": return action_check(identity, "Agent_A", "UNKNOWN")
    if case == "expired_credential":
        future = datetime.now(timezone.utc) + timedelta(seconds=60)
        expiry = future.isoformat()
        a.grant_root_permission("Agent_A", "E", expires_at=expiry, **identity.credentials("ROOT_AUTHORIZER", "root_grant",
                               {"agent_id": "Agent_A", "permission": "E", "expires_at": expiry}))
        check = action_check(identity, "Agent_A", "E")
        class Clock(datetime):
            @classmethod
            def now(cls, tz=None): return future + timedelta(seconds=1)
        def execute():
            with patch.object(a, "datetime", Clock): return check()
        return execute
    if case == "not_yet_issued":
        return action_check(identity, "Agent_A", "P", at_time=(datetime.now(timezone.utc)-timedelta(days=1)).isoformat())
    if case == "replayed_authentication":
        check = action_check(identity, "Agent_A", "P"); assert check() == "ALLOW"
        return check
    if case in ("unauthorized_delegation", "self_delegation"):
        parent, child = ("Agent_D", "Agent_C") if case == "unauthorized_delegation" else ("Agent_A", "Agent_A")
        payload = {"delegator": parent, "delegatee": child, "permission": "P", "expires_at": None}
        credentials = identity.credentials(parent, "delegate", payload)
        return lambda: "ALLOW" if a.delegate_permission(a.AGENTS[parent], a.AGENTS[child], "P", **credentials)["result"] == "ALLOWED" else "BLOCK"
    if case in ("revoked_agent", "post_decommission"):
        revoke(identity, "Agent_A")
        return action_check(identity, "Agent_A", "P")
    if case == "invalid_intermediate":
        delegate(identity, "Agent_A", "Agent_B"); delegate(identity, "Agent_B", "Agent_C"); revoke(identity, "Agent_B")
        return action_check(identity, "Agent_C", "P")
    if case == "tampered_credential_metadata":
        path = _path(identity.verifier); state = json.loads(path.read_text())
        state["root_grants"][0]["grants"]["P"]["expires_at"] = "2999-01-01T00:00:00Z"
        path.write_text(json.dumps(state))
        return action_check(identity, "Agent_A", "P")
    if case == "forged_proof":
        record = audit_record(0, 10, datetime.now(timezone.utc).isoformat(), True)
        leaf = hash_record(record)
        batch = {"batch_id": "batch:"+leaf, "merkle_root": leaf, "log_count": 1,
                 "action_ids": [record["action_id"]], "leaf_hashes": [leaf]}
        proof = generate_proof(batch, 0)
        if not verify_proof(record, proof, leaf): raise AssertionError("Original test proof failed")
        tampered = {**record, "target": "forged"}; check = action_check(identity, "Agent_A", "P")
        return lambda: "ALLOW" if check() == "ALLOW" and verify_proof(tampered, proof, leaf) else "BLOCK"
    if case == "scope_creep":
        root_grant(identity, permission="CREATE_AGENT"); delegate(identity, "Agent_A", "Agent_B", "CREATE_AGENT")
        data = ROOT / "core/drift_detection/data"
        actions = json.loads((data / "synthetic_logs.json").read_text())
        labels = json.loads((data / "ground_truth.json").read_text())
        sample = next(deepcopy(action) for action, label in zip(actions, labels, strict=True) if label["category"] == "SCOPE_CREEP")
        model = joblib.load(ROOT / "core/drift_detection/models/isolation_forest.joblib")
        check = action_check(identity, "Agent_B", "CREATE_AGENT")
        def execute():
            if check() != "ALLOW": return "BLOCK"
            path = a.authority_paths("Agent_B", "CREATE_AGENT")[0]
            model_input = {**sample, "trace_result": {"valid": True, "chain": [{"grant": g} for g in path]}}
            _, flagged = score_action(model_input, model)
            return "REVIEW" if flagged else "ALLOW"
        return execute
    raise ValueError(case)


def run(output, repetitions=10):
    rows, before_after = [], []
    for repeat in range(repetitions):
        for case in CASES:
            with local_policy() as identity:
                perform = prepare(case, identity)
                expected = "ALLOW" if case.startswith("legitimate_") else "REVIEW" if case == "scope_creep" else "BLOCK"
                start = time.perf_counter_ns()
                try: actual = perform()
                except AuthenticationError: actual = "BLOCK"
                latency_ms = (time.perf_counter_ns()-start)/1e6
                rows.append(dict(case=case, repetition=repeat+1,
                    classification="legitimate" if expected == "ALLOW" else "behavioral_anomaly" if expected == "REVIEW" else "attack",
                    expected=expected, actual=actual, correct=int(expected==actual), authorization_latency_ms=latency_ms))
                if actual != expected: raise AssertionError(f"Security case failed: {case}: {actual}")
        with local_policy():
            old = original_module()
            original = old.grant_root_permission("Agent_D", "ADMIN")
            before_after.append(dict(case="root_name_spoof", repetition=repeat+1, version="original_flat",
                                     expected="BLOCK", actual="ALLOW" if original["result"]=="ALLOWED" else "BLOCK"))
            after = next(r for r in rows if r["case"] == "root_impersonation" and r["repetition"] == repeat+1)
            before_after.append(dict(case="root_name_spoof", repetition=repeat+1, version="corrected_signed",
                                     expected="BLOCK", actual=after["actual"]))
    save_csv(output / "experiment3_requests.csv", rows)
    save_csv(output / "experiment3_before_after.csv", before_after)
    return rows
