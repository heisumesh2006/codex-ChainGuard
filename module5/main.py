"""Demonstrate public status, full proof, audit, and isolated revoke timing."""

from contextlib import ExitStack, contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
import time
from unittest.mock import patch
from uuid import uuid4

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from module2 import chain
from module5 import revocation as revocation_module
from module5.audit import calculate_revocation_completeness, check_post_revocation_activity
from module5.revocation import _bundle_context, _record_from_status, get_revocation_status, revoke, verify_revocation_proof

DATA_DIR = Path(__file__).resolve().parent / "data"


@contextmanager
def isolated_registry():
    """Fresh contract and files; restore production/demo configuration on exit."""
    from module1 import agents
    from module1 import logger

    suffix = uuid4().hex
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    paths = {
        "STATE_PATH": DATA_DIR / f".isolated-state-{suffix}.json",
        "DEPLOYMENT_PATH": DATA_DIR / f".isolated-deployment-{suffix}.json",
        "CREDENTIALS_PATH": DATA_DIR / f".isolated-credentials-{suffix}.json",
    }
    try:
        with ExitStack() as stack:
            for name, path in paths.items():
                stack.enter_context(patch.object(chain, name, path))
            for name, path in (
                ("BUNDLE_STATE_PATH", paths["STATE_PATH"]),
                ("BUNDLE_DEPLOYMENT_PATH", paths["DEPLOYMENT_PATH"]),
                ("BUNDLE_CREDENTIALS_PATH", paths["CREDENTIALS_PATH"]),
            ):
                stack.enter_context(patch.object(revocation_module, name, path))
            stack.enter_context(patch.object(agents, "AGENTS", deepcopy(agents.AGENTS)))
            stack.enter_context(patch.object(logger, "ACTION_LOG", []))
            chain.deploy_registry()
            chain.register_identities()
            chain.issue_credential("Agent_D", "VERIFY_ORDER", "ROOT_AUTHORIZER", False)
            yield
    finally:
        for path in paths.values():
            path.unlink(missing_ok=True)
            path.with_suffix(path.suffix + ".tmp").unlink(missing_ok=True)


def _cold_status_check():
    code = (
        "import json,sys; "
        "from unittest.mock import patch; "
        "from pathlib import Path; "
        "from module2 import chain; "
        "from module5 import revocation as r; "
        "from module5.revocation import get_revocation_status,verify_revocation_proof; "
        "assert not any(k.startswith('module1') for k in sys.modules); "
        "r.BUNDLE_STATE_PATH=Path('off-chain-revocation-record-unavailable.json'); "
        "guard=patch.object(chain,'load_state',side_effect=AssertionError('off-chain index accessed')); guard.start(); "
        "c=get_revocation_status('Agent_C'); b=get_revocation_status('Agent_B'); u=get_revocation_status('Unknown_Agent'); "
        "assert c['status']=='REVOKED' and verify_revocation_proof('Agent_C',c['chain_proof']); "
        "assert c['proof_verified'] and c['revoked_at'] and c['revoked_by']=='ROOT_AUTHORIZER'; "
        "assert c['revoked_permissions']==['PROCESS_PAYMENT','CREATE_AGENT']; "
        "assert b['status']=='ACTIVE' and u['status']=='AGENT_NOT_FOUND'; "
        "print(json.dumps({'revoked':c['status'],'active':b['status'],"
        "'unknown':u['status'],'revoked_at':c['revoked_at'],'revoked_by':c['revoked_by'],"
        "'revoked_permissions':c['revoked_permissions'],'proof_verified':c['proof_verified'],"
        "'module1_loaded':any(k.startswith('module1') for k in sys.modules)}))"
    )
    return json.loads(subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                                     check=True, cwd=Path(__file__).resolve().parents[1]).stdout)


def _real_action(action_name):
    with _bundle_context():
        matches = [entry["source"] for entry in chain.load_state()["records"].values()
                   if entry["kind"] == "action" and entry["source"]["action"] == action_name]
    if len(matches) != 1:
        raise RuntimeError(f"Expected one anchored Module 1 action: {action_name}")
    return matches[0]


def run_demo():
    print("=== PUBLIC REVOCATION VERIFICATION ===")
    cold = _cold_status_check()
    assert cold["revoked"] == "REVOKED" and cold["active"] == "ACTIVE"
    assert cold["unknown"] == "AGENT_NOT_FOUND" and cold["module1_loaded"] is False
    assert cold["revoked_at"] and cold["revoked_by"] == "ROOT_AUTHORIZER"
    assert cold["revoked_permissions"] == ["PROCESS_PAYMENT", "CREATE_AGENT"] and cold["proof_verified"]
    c = get_revocation_status("Agent_C")
    assert c["chain_verified"] and verify_revocation_proof("Agent_C", c["chain_proof"])
    full_c = _record_from_status("Agent_C", c)
    assert c["revoked_at"] == full_c["revoked_at"]
    assert c["revoked_permissions"] == [x["permission"] for x in full_c["revoked_permissions"]]
    print(f"Agent: Agent_C\nStatus: {c['status']}\nRevoked At (chain-retrieved): {c['revoked_at']}")
    print(f"Revoked By: {c['revoked_by']}\nRevoked Permissions: {c['revoked_permissions']}")
    print(f"Transaction Hash: {c['chain_proof']['transaction_hash']}\nBlock Number: {c['chain_proof']['block_number']}")
    print("Proof Verification: PASS\nCold process loaded Module 1: False")

    print("\n=== ACTIVE AGENT CHECK ===")
    b = get_revocation_status("Agent_B")
    assert b["agent_found"] and b["status"] == "ACTIVE" and not b["is_revoked"]
    print(f"Agent: Agent_B\nStatus: {b['status']}\nIs Revoked: {b['is_revoked']}\nChecked Block: {b['checked_block_number']}")

    print("\n=== UNKNOWN AGENT CHECK ===")
    unknown = get_revocation_status("Unknown_Agent")
    assert not unknown["agent_found"] and unknown["status"] == "AGENT_NOT_FOUND"
    print(f"Agent: Unknown_Agent\nStatus: {unknown['status']}")

    print("\n=== DOUBLE REVOCATION TEST ===")
    before = c["chain_proof"]
    existing = revoke("Agent_C", "ALL", "ROOT_AUTHORIZER", "idempotency check")
    after = get_revocation_status("Agent_C")["chain_proof"]
    assert existing["proof_verified"] and before["transaction_hash"] == after["transaction_hash"]
    assert before["block_number"] == after["block_number"] and before["record_id"] == after["record_id"]
    print("Existing Revocation Detected\nDuplicate Blockchain Entry Created: False\nExisting Proof Reused: PASS")

    print("\n=== POST-REVOCATION AUDIT ===")
    real = _real_action("POST_DECOMMISSION_ACTIVITY")
    real_audit = check_post_revocation_activity(real)
    assert real["result"] == "BLOCKED" and real_audit["violation"] and real_audit["chain_verified"]
    print("Real Module 1 Post-Decommission Action:\nReal-Time Layer: BLOCKED\nAudit Layer: VIOLATION DETECTED")
    anchor_time = datetime.fromisoformat(c["chain_proof"]["anchored_at"])
    local_time = datetime.fromisoformat(full_c["revoked_at"])
    bypass = {
        "record_id": "isolated-audit-fixture", "actor": "Agent_C", "action": "USE_PERMISSION",
        "timestamp": (max(anchor_time, local_time) + timedelta(seconds=1)).isoformat(),
        "claimed_authority": "Agent_C", "permission": "CREATE_AGENT", "result": "ALLOWED",
    }
    bypass_audit = check_post_revocation_activity(bypass)
    assert bypass_audit["violation"] and bypass_audit["chain_verified"]
    print("\nSimulated Real-Time Bypass:\nReal-Time Layer: ALLOWED\nAudit Layer: VIOLATION DETECTED")
    completeness = calculate_revocation_completeness([real, bypass])
    assert completeness["post_revocation_attempts"] == 2 and completeness["caught_by_either"] == 2
    assert completeness["revocation_completeness"] == 1.0

    with isolated_registry():
        started = time.perf_counter()
        fresh = revoke("Agent_D", "ALL", "ROOT_AUTHORIZER", "isolated latency measurement")
        fresh_status = get_revocation_status("Agent_D")
        elapsed_ms = (time.perf_counter() - started) * 1000
        assert fresh["proof_verified"] and verify_revocation_proof("Agent_D", fresh_status["chain_proof"])

    public_latencies = [c["lookup_latency_ms"], b["lookup_latency_ms"], unknown["lookup_latency_ms"]]
    metrics = {
        **completeness,
        "public_lookup_latency_ms": sum(public_latencies) / len(public_latencies),
        "public_lookup_samples_ms": public_latencies,
        "revocation_to_proof_latency_ms": elapsed_ms,
        "proof_verification": True,
    }
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    (DATA_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print("\n=== REVOCATION METRICS ===")
    for key in ("post_revocation_attempts", "caught_by_realtime", "caught_by_audit", "caught_by_either"):
        print(f"{key.replace('_', ' ').title()}: {metrics[key]}")
    print(f"Revocation Completeness: {100 * metrics['revocation_completeness']:.2f}%")
    print(f"Public Verification Latency: {metrics['public_lookup_latency_ms']:.2f} ms")
    print(f"Revocation-To-Proof Latency: {metrics['revocation_to_proof_latency_ms']:.2f} ms")
    print("\n=== MODULE 5 COMPLETED SUCCESSFULLY ===")
    return metrics


if __name__ == "__main__":
    run_demo()
