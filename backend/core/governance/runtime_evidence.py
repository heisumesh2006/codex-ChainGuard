"""Read-only presentation of persisted batched governance evidence.

AuditRecords preserve decisions, not full pipeline timings or benchmark results.
Missing measurements stay null; shared model benchmarks have explicit provenance.
"""

from collections import Counter
import json
from pathlib import Path
from statistics import mean

ROOT = Path(__file__).resolve().parents[3]
ATTACK_CODES = {
    "SELF_ESCALATION_ATTEMPT": "SELF_ESCALATION",
    "UNAUTHORIZED_DELEGATION_ATTEMPT": "UNAUTHORIZED_DELEGATION",
    "POST_DECOMMISSION_ACTIVITY": "POST_DECOMMISSION_ACTIVITY",
}


def scenario_category(record: dict) -> tuple[str, str]:
    if record["action"] in ATTACK_CODES:
        return ATTACK_CODES[record["action"]], "ATTACK"
    # The synthetic dataset labels identify the saved source, rather than
    # guessing scope creep from the model's predicted flag or final decision.
    source_id = record["metadata"].get("source_action_id")
    data = ROOT / "backend/core/drift_detection/data"
    logs = json.loads((data / "synthetic_logs.json").read_text(encoding="utf-8"))
    labels = json.loads((data / "ground_truth.json").read_text(encoding="utf-8"))
    for action, label in zip(logs, labels, strict=True):
        if action.get("record_id") == source_id:
            return label["category"], "ANOMALY" if label["label"] else "NORMAL"
    return record["action"], "UNCLASSIFIED"


def source_action(record: dict) -> dict:
    return {
        "record_id": record["metadata"].get("source_action_id") or record["action_id"],
        "timestamp": record["timestamp"], "actor": record["agent_id"],
        "action": record["action"], "permission": record["scope"],
        "target_agent": record["target"],
        "result": record["metadata"].get("source_result"),
        "claimed_authority": record["metadata"].get("claimed_authority"),
        "reason": record["metadata"].get("reason"),
    }


def saved_verdict(record: dict) -> dict:
    """Replay saved decisions without rescoring, appending records or anchoring."""
    from .report import STEPS

    metadata = record["metadata"]
    anomaly = record["anomaly_result"]
    status = metadata.get("chain_check_status")
    return {
        "action": source_action(record),
        "authorized": record["authorization_result"] == "ALLOWED",
        "drift_applicable": anomaly["applicable"], "drift_flagged": anomaly["flagged"],
        "drift_score": anomaly["score"], "trace_context_verdict": record["trace_verdict"],
        "revocation_status": record["revocation_status"],
        "chain_verified": bool(status and status.startswith("VERIFIED")),
        "chain_check_status": status, "chain_evidence": metadata.get("chain_evidence"),
        "governance_decision": record["governance_verdict"],
        "detected_by": metadata.get("detected_by", []),
        "reasons": [metadata["reason"]] if metadata.get("reason") else [],
        "step_latencies": dict.fromkeys(STEPS), "total_latency_ms": None,
        "audit_action_id": record["action_id"], "evidence_source": "persisted_audit_record",
    }


def build_persisted_report(data_dir: Path, manager) -> dict:
    """Derive inventory and saved outcomes from this profile, without RPC writes."""
    from .report import STEPS, _scenario_row
    from types import SimpleNamespace

    state = json.loads((data_dir / "ethereum_state.json").read_text(encoding="utf-8"))
    deployment = json.loads((data_dir / "deployment.json").read_text(encoding="utf-8"))
    records = manager.audit_store.list_records()
    batches = manager.list_batches()
    rows = []
    for record in records:
        verdict = saved_verdict(record)
        rows.append(_scenario_row(*scenario_category(record), SimpleNamespace(**verdict)))
    kinds = Counter(entry["kind"] for entry in state["records"].values())
    identities = {credential["agent_id"] for credential in state["credentials"].values()}
    identities.update(record["agent_id"] for record in records if (record["revocation_status"] or {}).get("agent_found"))
    identities.add("ROOT_AUTHORIZER")
    anchored_ids = {action_id for batch in batches if batch["status"] == "ANCHORED" for action_id in batch["action_ids"]}
    revoked = [record for record in records if record["action"] == "POST_DECOMMISSION_ACTIVITY"]
    realtime = sum(record["authorization_result"] == "DENIED" for record in revoked)
    audit = sum("Module5" in record["metadata"].get("detected_by", []) for record in revoked)
    caught = sum(record["authorization_result"] == "DENIED" or "Module5" in record["metadata"].get("detected_by", []) for record in revoked)
    lookups = [record["revocation_status"]["lookup_latency_ms"] for record in records
               if (record["revocation_status"] or {}).get("lookup_latency_ms") is not None]
    attacks = [row for row in rows if row["expected_class"] in ("ATTACK", "ANOMALY")]
    counts = Counter(row["expected_class"] for row in rows)
    drift = json.loads((ROOT / "backend/core/drift_detection/data/metrics.json").read_text(encoding="utf-8"))
    return {
        "evidence_source": "profile_persisted_audit_records",
        "metric_provenance": {
            "inventory": "Profile state, observed credential holders and registered audit actors; batch metadata",
            "governance": "Saved AuditRecord outcomes (not recomputed)",
            "module4": "Shared synthetic held-out model benchmark, not Sepolia traffic",
            "latency": "Pipeline stage timings were not persisted; null means unavailable",
            "proofs": "Live verification is available through audit proof and scenario trace endpoints",
        },
        "system_configuration": {"agents": len(identities) - 1, "trust_root": "ROOT_AUTHORIZER",
                                 "blockchain": "Ethereum Sepolia", "ml_model": "IsolationForest",
                                 "revocation_scope": "FULL_AGENT_ONLY"},
        "blockchain_deployment": {"contract_address": deployment["contract_address"], "chain_id": deployment["chain_id"]},
        "scenario_counts": {**dict(counts), "total": len(rows)}, "scenarios": rows,
        "layer_by_layer_attack_detection": [{key: row[key] for key in ("scenario", "actor", "record_id", "detected_by", "final_decision")} for row in attacks],
        "end_to_end_attack_coverage": sum(bool(row["detected_by"]) for row in attacks) / len(attacks) if attacks else None,
        "modules": {
            "module2_blockchain": {"registered_identities": len(identities), "credentials_issued": len(state["credentials"]),
                                   "delegations_anchored": kinds["delegation"], "revocations_anchored": kinds["revocation"],
                                   "action_hashes_anchored": kinds["action"], "audit_records": len(records),
                                   "anchored_audit_records": sum(record["action_id"] in anchored_ids for record in records),
                                   "anchored_batch_count": sum(batch["status"] == "ANCHORED" for batch in batches),
                                   "contract_address": deployment["contract_address"], "chain_id": deployment["chain_id"]},
            "module3_tracing": {"delegation_trace_accuracy": None, "average_trace_latency_ms": None,
                                "worst_case_trace_latency_ms": None, "saved_trace_verdicts": dict(Counter(record["trace_verdict"] for record in records))},
            "module4_anomaly": drift,
            "module5_revocation": {"post_revocation_attempts": len(revoked), "caught_by_either": caught,
                                   "caught_by_realtime": realtime, "caught_by_audit": audit,
                                   "revocation_completeness": caught / len(revoked) if revoked else None,
                                   "public_lookup_latency_ms": mean(lookups) if lookups else None,
                                   "revocation_to_proof_latency_ms": None},
        },
        "end_to_end_latency": {"average_ms": {}, "worst_case_ms": {}, "total_average_ms": None,
                               "total_worst_case_ms": None, "pipeline_bottleneck_step": None,
                               "unavailable_steps": list(STEPS)},
        "overall_test_results": None,
        "known_limitations": ["Pipeline timings and trace benchmark accuracy were not persisted and are unavailable.",
                              "Shared model metrics use synthetic held-out data, not Sepolia traffic.",
                              "Inventory anchoring counts use saved metadata; proof endpoints verify current Ethereum evidence.",
                              "Saved governance outcomes are preserved; current historical traces may add revocation context.",
                              "Sepolia is a public testnet; these results do not establish production performance."],
    }
