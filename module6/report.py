"""Aggregate existing module evidence and render the final project report."""

from collections import Counter
from datetime import datetime
import json
from pathlib import Path
from statistics import mean

from module2 import chain, integration
from module2.anchor import get_proof, verify_proof
from module3.tracer import trace_action, trace_agent_authority
from .pipeline import DATA_DIR, canonical_context

ROOT = Path(__file__).resolve().parents[1]
STEPS = (
    "authorization_ms", "trace_context_ms", "drift_scoring_ms",
    "revocation_check_ms", "chain_verification_ms", "verdict_assembly_ms",
)
ATTACK_VERDICTS = {
    "SELF_ESCALATION": "UNAUTHORIZED_ROOT",
    "UNAUTHORIZED_DELEGATION": "BROKEN_CHAIN",
    "POST_DECOMMISSION_ACTIVITY": "AUTHORITY_REVOKED_AT_TIME_OF_ACTION",
}


def _module2_metrics():
    with canonical_context():
        state = chain.load_state()
        deployment = json.loads((DATA_DIR / "deployment.json").read_text(encoding="utf-8"))
        web3, contract, _, _ = chain.contract_context()
        counts = Counter(entry["kind"] for entry in state["records"].values())
        proofs_checked = 0
        latencies = []
        for entry in state["records"].values():
            source, proof = entry["source"], entry["proof"]
            if verify_proof(source, proof):
                proofs_checked += 1
            latencies.append((datetime.fromisoformat(proof["timestamp"]) -
                              datetime.fromisoformat(source["timestamp"])).total_seconds() * 1000)
        identities = ("ROOT_AUTHORIZER", "Agent_A", "Agent_B", "Agent_C", "Agent_D")
        registered = sum(contract.functions.agentAddresses(integration.agent_hash(name)).call()
                         != "0x" + "0" * 40 for name in identities)
        return {
            "registered_identities": registered,
            "credentials_issued": len(state["credentials"]),
            "delegations_anchored": counts["delegation"],
            "revocations_anchored": counts["revocation"],
            "action_hashes_anchored": counts["action"],
            "proofs_verified": proofs_checked,
            "proofs_total": len(state["records"]),
            "anchoring_latency_average_ms": mean(latencies),
            "anchoring_latency_worst_ms": max(latencies),
            "anchoring_latency_total_ms": sum(latencies),
            "contract_address": deployment["contract_address"],
            "chain_id": deployment["chain_id"],
        }


def _module3_metrics():
    with canonical_context():
        actions = [entry["source"] for entry in chain.load_state()["records"].values()
                   if entry["kind"] == "action"]
        cases = [
            (trace_agent_authority("Agent_B", "CREATE_AGENT"), "VALID_CHAIN"),
            (trace_agent_authority("Agent_C", "CREATE_AGENT"), "VALID_CHAIN"),
        ]
        for code, expected in (
            ("SELF_ESCALATION_ATTEMPT", "UNAUTHORIZED_ROOT"),
            ("UNAUTHORIZED_DELEGATION_ATTEMPT", "BROKEN_CHAIN"),
            ("POST_DECOMMISSION_ACTIVITY", "AUTHORITY_REVOKED_AT_TIME_OF_ACTION"),
        ):
            action = next(item for item in actions if item["action"] == code)
            cases.append((trace_action(action), expected))
        correct = sum(result["verdict"] == expected for result, expected in cases)
        latencies = [result["trace_latency_ms"] for result, _ in cases]
        return {
            "test_count": len(cases), "correctly_classified": correct,
            "delegation_trace_accuracy": correct / len(cases),
            "average_trace_latency_ms": mean(latencies),
            "worst_case_trace_latency_ms": max(latencies),
        }


def collect_module_metrics():
    return {
        "module2_blockchain": _module2_metrics(),
        "module3_tracing": _module3_metrics(),
        "module4_anomaly": json.loads((ROOT / "module4" / "data" / "metrics.json").read_text(encoding="utf-8")),
        "module5_revocation": json.loads((ROOT / "module5" / "data" / "metrics.json").read_text(encoding="utf-8")),
    }


def _scenario_row(category, expected_class, verdict):
    status = verdict.revocation_status
    return {
        "scenario": category, "actor": verdict.action["actor"],
        "action": verdict.action["action"], "record_id": verdict.action.get("record_id"),
        "expected_class": expected_class, "authorized": verdict.authorized,
        "drift_applicable": verdict.drift_applicable, "drift_flagged": verdict.drift_flagged,
        "drift_score": verdict.drift_score, "trace_verdict": verdict.trace_context_verdict,
        "revoked": bool(status and status["is_revoked"]),
        "revocation_proof_available": bool(status and status["is_revoked"] and status.get("proof_verified")),
        "chain_verified": verdict.chain_verified, "chain_check_status": verdict.chain_check_status,
        "final_decision": verdict.governance_decision, "detected_by": verdict.detected_by,
        "resolution_time_ms": verdict.total_latency_ms,
        "step_latencies": verdict.step_latencies, "reasons": verdict.reasons,
    }


def build_report(scenarios, test_results):
    """Build real metrics from measured verdicts and prior module artifacts."""
    if not scenarios:
        raise ValueError("No pipeline scenarios were provided")
    modules = collect_module_metrics()
    rows = [_scenario_row(category, expected, verdict) for category, expected, verdict in scenarios]
    attacks = [row for row in rows if row["expected_class"] in ("ATTACK", "ANOMALY")]
    attack_coverage = sum(bool(row["detected_by"]) for row in attacks) / len(attacks)
    latency = {
        "average_ms": {step: mean(row["step_latencies"][step] for row in rows) for step in STEPS},
        "worst_case_ms": {step: max(row["step_latencies"][step] for row in rows) for step in STEPS},
        "total_average_ms": mean(row["resolution_time_ms"] for row in rows),
        "total_worst_case_ms": max(row["resolution_time_ms"] for row in rows),
    }
    latency["pipeline_bottleneck_step"] = max(STEPS, key=lambda step: latency["average_ms"][step])
    counts = Counter(row["expected_class"] for row in rows)
    return {
        "system_configuration": {
            "agents": 4, "trust_root": "ROOT_AUTHORIZER",
            "blockchain": "Hardhat local Ethereum", "ml_model": "IsolationForest",
            "revocation_scope": "FULL_AGENT_ONLY", "canonical_deployment": "module6/data/deployment.json",
        },
        "blockchain_deployment": {
            "contract_address": modules["module2_blockchain"]["contract_address"],
            "chain_id": modules["module2_blockchain"]["chain_id"],
            "schema": "AgentTrustRegistry detailed on-chain revocation metadata",
        },
        "scenario_counts": {**dict(counts), "total": len(rows)},
        "scenarios": rows,
        "layer_by_layer_attack_detection": [
            {key: row[key] for key in ("scenario", "actor", "record_id", "detected_by", "final_decision")}
            for row in attacks
        ],
        "end_to_end_attack_coverage": attack_coverage,
        "modules": modules,
        "end_to_end_latency": latency,
        "overall_test_results": test_results,
        "known_limitations": [
            "Behavioral evaluation uses a reproducible synthetic dataset, not production traffic.",
            "The registry runs on a local Hardhat chain without production consensus.",
            "The prototype has four agents and one root authority.",
            "Module 4 SELF_ESCALATION recall is below 100% on its held-out set.",
            "Only full-agent revocation is supported.",
            "These results do not establish production detection or latency performance.",
        ],
    }


def write_reports(report):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    json_path = DATA_DIR / "final_report.json"
    markdown_path = DATA_DIR / "final_report.md"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False), encoding="utf-8")
    lines = ["# ChainGuard-AI: Final End-to-End Evaluation", "",
             f"Canonical contract: `{report['blockchain_deployment']['contract_address']}` (chain {report['blockchain_deployment']['chain_id']}).",
             f"Scenarios: {report['scenario_counts']['total']}; attack/anomaly coverage: {report['end_to_end_attack_coverage']:.2%}.", "",
             "## Scenario verdicts", "",
             "| Scenario | Actor | Expected | Authorized | Drift | Trace | Revoked | Chain | Decision | Detected by | Resolution ms |",
             "|---|---|---|---:|---:|---|---:|---:|---|---|---:|"]
    for row in report["scenarios"]:
        lines.append("| " + " | ".join((
            row["scenario"], row["actor"], row["expected_class"], str(row["authorized"]),
            str(row["drift_flagged"]), row["trace_verdict"], str(row["revoked"]),
            str(row["chain_verified"]), row["final_decision"], ", ".join(row["detected_by"]) or "None",
            f"{row['resolution_time_ms']:.2f}",
        )) + " |")
    lines += ["", "## Pipeline latency", "", "| Step | Average ms | Worst ms |", "|---|---:|---:|"]
    latency = report["end_to_end_latency"]
    for step in STEPS:
        lines.append(f"| {step} | {latency['average_ms'][step]:.2f} | {latency['worst_case_ms'][step]:.2f} |")
    lines.append(f"| TOTAL | {latency['total_average_ms']:.2f} | {latency['total_worst_case_ms']:.2f} |")
    lines += ["", f"Measured average bottleneck: **{latency['pipeline_bottleneck_step']}**.",
              "", "## Existing module metrics", ""]
    for title, key in (("Module 2: blockchain", "module2_blockchain"),
                       ("Module 3: tracing", "module3_tracing"),
                       ("Module 4: anomaly detection", "module4_anomaly"),
                       ("Module 5: revocation", "module5_revocation")):
        lines += [f"### {title}", "", "```json", json.dumps(report["modules"][key], indent=2), "```", ""]
    lines += ["## Test results", "", "```json", json.dumps(report["overall_test_results"], indent=2), "```", "",
              "## Known limitations", ""]
    lines += [f"- {item}" for item in report["known_limitations"]]
    markdown_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return json_path, markdown_path
