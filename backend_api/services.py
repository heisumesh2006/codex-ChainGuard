"""Read existing module evidence and delegate decisions to Module 6."""

import json
from pathlib import Path
from threading import RLock

import joblib

from module6 import pipeline
from module1 import agents as module1_agents
from module2 import chain, integration
from module2.anchor import get_proof, verify_proof
from module3.tracer import trace_action, trace_agent_authority
from module5.revocation import get_revocation_status
from module6.main import load_scenarios
from module6.pipeline import DATA_DIR, MODEL_PATH, canonical_context, prepare_runtime, run_governance_pipeline

from .schemas import ActionInput

ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = DATA_DIR / "final_report.json"
LOCK = RLock()  # Module 6's canonical_context temporarily patches module paths.
SCENARIOS = {
    "normal": "NORMAL",
    "self_escalation": "SELF_ESCALATION",
    "unauthorized_delegation": "UNAUTHORIZED_DELEGATION",
    "post_decommission": "POST_DECOMMISSION_ACTIVITY",
    "scope_creep": "SCOPE_CREEP",
}


def final_report() -> dict:
    return json.loads(REPORT_PATH.read_text(encoding="utf-8"))


def health() -> dict:
    deployment = json.loads((DATA_DIR / "deployment.json").read_text(encoding="utf-8"))
    rpc_connected = contract_available = False
    live_chain_id = None
    error = None
    try:
        with LOCK, canonical_context():
            web3 = chain.connect(deployment["rpc_url"])
            rpc_connected = True
            live_chain_id = web3.eth.chain_id
            contract_available = (
                live_chain_id == deployment["chain_id"]
                and bool(web3.eth.get_code(deployment["contract_address"]))
            )
    except Exception as exc:
        error = str(exc)
    return {
        "api_online": True,
        "rpc_connected": rpc_connected,
        "chain_id": live_chain_id or deployment["chain_id"],
        "contract_available": contract_available,
        "contract_address": deployment["contract_address"],
        "ml_model_available": MODEL_PATH.is_file(),
        "status": "ONLINE" if rpc_connected and contract_available and MODEL_PATH.is_file() else "DEGRADED",
        "error": error,
    }


def overview() -> dict:
    report = final_report()
    blockchain = report["modules"]["module2_blockchain"]
    latency = report["end_to_end_latency"]
    return {
        "registered_agents": blockchain["registered_identities"] - 1,
        "registered_identities": blockchain["registered_identities"],
        "credentials": blockchain["credentials_issued"],
        "delegations": blockchain["delegations_anchored"],
        "revocations": blockchain["revocations_anchored"],
        "anchored_actions": blockchain["action_hashes_anchored"],
        "attack_coverage": report["end_to_end_attack_coverage"],
        "average_pipeline_latency_ms": latency["total_average_ms"],
        "worst_pipeline_latency_ms": latency["total_worst_case_ms"],
        "bottleneck_step": latency["pipeline_bottleneck_step"],
        "scenario_count": report["scenario_counts"]["total"],
    }


def agents() -> list[dict]:
    with LOCK:
        prepare_runtime()
        with canonical_context():
            _, contract, _, _ = chain.contract_context()
            addresses = {
                agent_id: contract.functions.agentAddresses(integration.agent_hash(agent_id)).call()
                for agent_id in module1_agents.AGENTS
            }
        return [
            {
                "agent_id": agent.agent_id,
                "role": agent.role,
                "status": agent.status,
                "direct_permissions": list(agent.direct_permissions),
                "delegated_permissions": list(agent.delegated_permissions),
                "effective_permissions": list(agent.effective_permissions),
                "revoked_permissions": list(agent.revoked_permissions),
                "blockchain_address": addresses[agent.agent_id],
            }
            for agent in module1_agents.AGENTS.values()
        ]


def agent_credentials(agent_id: str) -> dict:
    """Readable credential metadata; Module 3 supplies the historical proof result."""
    with LOCK, canonical_context():
        state = chain.load_state()
        web3, contract, _, _ = chain.contract_context()
        address = contract.functions.agentAddresses(integration.agent_hash(agent_id)).call()
        if address == "0x" + "0" * 40:
            raise LookupError(f"Unknown agent: {agent_id}")
        identities = {
            contract.functions.agentAddresses(integration.agent_hash(name)).call(): name
            for name in ("ROOT_AUTHORIZER", "Agent_A", "Agent_B", "Agent_C", "Agent_D")
        }
        credentials = []
        for credential in state["credentials"].values():
            if credential["agent_id"] != agent_id:
                continue
            permission = credential["allowed_permission_scope"][0]
            trace = trace_agent_authority(agent_id, permission)
            credentials.append({
                "credential_id": credential["credential_id"],
                "permission": permission,
                "issuer": identities.get(credential["issuer"], credential["issuer"]),
                "issuer_address": credential["issuer"],
                "allowed_permission_scope": credential["allowed_permission_scope"],
                "delegation_scope": credential["delegation_scope"],
                "issued_at": credential["issued_at"],
                "expires_at": credential["expires_at"],
                "status": credential["current_status"],
                "content_hash": credential["content_hash"],
                "transaction_hash": credential["transaction_hash"],
                "block_number": web3.eth.get_transaction_receipt(credential["transaction_hash"]).blockNumber,
                "proof_status": "PASS" if trace["valid"] else "FAIL",
                "proof_basis": "ROOT_CREDENTIAL" if identities.get(credential["issuer"]) == "ROOT_AUTHORIZER" else "AUTHORITY_CHAIN",
                "trace_verdict": trace["verdict"],
            })
        return {"agent_id": agent_id, "credentials": credentials}


def trace_authority(agent_id: str, permission: str) -> dict:
    with LOCK, canonical_context():
        return trace_agent_authority(agent_id, permission)


def trace_scenario_action(name: str) -> dict:
    action = scenario_action(name)
    with LOCK, canonical_context():
        return trace_action(action)


def delegation_graph() -> dict:
    with LOCK:
        prepare_runtime()
    with LOCK, canonical_context():
        state = chain.load_state()
        _, contract, _, _ = chain.contract_context()
        identities = ("ROOT_AUTHORIZER", "Agent_A", "Agent_B", "Agent_C", "Agent_D")
        nodes = [
            {
                "id": name,
                "type": "agentNode",
                "position": {"x": 100 + (index % 3) * 280, "y": 70 + (index // 3) * 230},
                "data": {
                    "label": name,
                    "role": "Trust Root" if index == 0 else module1_agents.AGENTS[name].role,
                    "address": contract.functions.agentAddresses(integration.agent_hash(name)).call(),
                    "status": "ACTIVE" if index == 0 else module1_agents.AGENTS[name].status,
                },
            }
            for index, name in enumerate(identities)
        ]
        edges = []
        root_address = contract.functions.rootAuthorizer().call()
        for credential in state["credentials"].values():
            if credential["issuer"] != root_address:
                continue
            agent_id = credential["agent_id"]
            permission = credential["allowed_permission_scope"][0]
            trace = trace_agent_authority(agent_id, permission)
            root_hop = next((hop for hop in trace["chain"]
                             if hop["evidence_type"] == "ROOT_CREDENTIAL" and hop["to"] == agent_id), None)
            verified = bool(root_hop and root_hop["proof_verified"])
            edges.append({
                "id": credential["credential_id"], "source": "ROOT_AUTHORIZER", "target": agent_id,
                "from": "ROOT_AUTHORIZER", "to": agent_id, "permission": permission,
                "evidence_type": "ROOT_CREDENTIAL", "anchored": verified,
                "proof_status": "PASS" if verified else "FAIL",
                "transaction_hash": credential.get("transaction_hash"),
                "block_number": root_hop["block_number"] if root_hop else None,
                "content_hash": credential.get("content_hash"),
                "authority_source": "ROOT_AUTHORIZER",
                "credential_status": credential.get("current_status"),
                "data": {"permission": permission, "evidence_type": "ROOT_CREDENTIAL", "proof_status": "PASS" if verified else "FAIL"},
            })
        for record_id, entry in state["records"].items():
            if entry["kind"] != "delegation":
                continue
            source = entry["source"]
            proof = get_proof(record_id)
            verified = verify_proof(source, proof)
            edges.append({
                "id": record_id, "source": source["delegator"], "target": source["delegatee"],
                "from": source["delegator"], "to": source["delegatee"],
                "permission": source["permission"], "evidence_type": "DELEGATION",
                "anchored": verified, "proof_status": "PASS" if verified else "FAIL",
                "transaction_hash": proof["transaction_hash"],
                "block_number": proof["block_number"],
                "content_hash": proof["content_hash"],
                "authority_source": source["authority_source"],
                "delegation_status": source["status"],
                "data": {"permission": source["permission"], "evidence_type": "DELEGATION", "proof_status": "PASS" if verified else "FAIL"},
            })
        return {"nodes": nodes, "edges": edges, "contract_address": contract.address}


def metrics() -> dict:
    report = final_report()
    return {
        "module2": report["modules"]["module2_blockchain"],
        "module3": report["modules"]["module3_tracing"],
        "module4": report["modules"]["module4_anomaly"],
        "module5": report["modules"]["module5_revocation"],
        "module6": {
            "attack_coverage": report["end_to_end_attack_coverage"],
            "scenario_counts": report["scenario_counts"],
            "latency": report["end_to_end_latency"],
        },
    }


def revocation(agent_id: str) -> dict:
    with LOCK, canonical_context():
        return get_revocation_status(agent_id)


def evaluate(action: ActionInput | dict) -> dict:
    payload = action.as_injected_action() if isinstance(action, ActionInput) else action
    with LOCK:
        return run_governance_pipeline(payload).to_dict()


def scenario_action(name: str) -> dict:
    code = SCENARIOS[name]
    matches = [action for category, _, action in load_scenarios() if category == code]
    if not matches:
        raise LookupError(f"No saved {name} scenario")
    return matches[0]


def run_scenario(name: str) -> dict:
    action = scenario_action(name)
    with LOCK:
        prepare_runtime()
        live_model = pipeline._runtime["model"]
        try:
            # A saved scenario is a replay. Score it from the persisted model
            # baseline so earlier UI runs cannot change its decision.
            pipeline._runtime["model"] = joblib.load(MODEL_PATH)
            verdict = run_governance_pipeline(action)
        finally:
            pipeline._runtime["model"] = live_model
    return {"scenario": name, "source": "saved_module_scenario", "verdict": verdict.to_dict()}


def stage_events(verdict: dict) -> list[dict]:
    """Replay measured stages immediately; the frontend controls visual pacing."""
    timings = verdict["step_latencies"]
    hops = (verdict.get("trace_result") or {}).get("chain") or []
    reference = None
    if hops:
        hop = hops[-1]
        reference = {"transaction_hash": hop.get("transaction_hash"), "block_number": hop.get("block_number"), "record_id": hop.get("record_id")}
    elif (verdict.get("revocation_status") or {}).get("is_revoked"):
        proof = verdict["revocation_status"].get("chain_proof") or {}
        reference = {"transaction_hash": proof.get("transaction_hash"), "block_number": proof.get("block_number"), "record_id": proof.get("record_id")}
    elif not str(verdict["action"].get("record_id", "")).startswith("synthetic:"):
        try:
            with LOCK, canonical_context():
                proof = get_proof(integration.blockchain_record_id("action", verdict["action"]))
            reference = {"transaction_hash": proof["transaction_hash"], "block_number": proof["block_number"], "record_id": proof["record_id"]}
        except (KeyError, RuntimeError, ValueError):
            pass
    stages = (
        ("AUTHORIZATION", "authorization_ms", {"authorized": verdict["authorized"]}),
        ("TRACE", "trace_context_ms", {"trace_verdict": verdict["trace_context_verdict"], "chain_depth": len(hops) if hops else None}),
        ("DRIFT_SCORING", "drift_scoring_ms", {"drift_score": verdict["drift_score"], "drift_flagged": verdict["drift_flagged"], "applicable": verdict["drift_applicable"]}),
        ("REVOCATION_CHECK", "revocation_check_ms", {"revoked": bool(verdict["revocation_status"] and verdict["revocation_status"]["is_revoked"]), "proof_available": bool(verdict["revocation_status"] and verdict["revocation_status"].get("proof_verified"))}),
        ("BLOCKCHAIN_VERIFY", "chain_verification_ms", {"proof_status": verdict["chain_check_status"], "chain_verified": verdict["chain_verified"], "reference": reference}),
    )
    events = []
    for name, latency_key, detail in stages:
        events.append({"event": f"{name}_STARTED", "status": "RUNNING", "replay": True})
        events.append({"event": f"{name}_COMPLETE", "status": "COMPLETE", "latency_ms": timings[latency_key], "replay": True, **detail})
    events.append({"event": "VERDICT_COMPLETE", "status": verdict["governance_decision"], "decision": verdict["governance_decision"], "total_latency_ms": verdict["total_latency_ms"], "replay": True, "verdict": verdict})
    return events
