"""Fail-closed validation of stored evidence; never repair canonical data."""

from datetime import datetime, timezone
import json
import math
from pathlib import Path

from web3 import Web3


class EvidenceError(RuntimeError):
    def __init__(self, code="EVIDENCE_UNAVAILABLE", status_code=503):
        self.code = code
        self.status_code = status_code
        super().__init__(code)


def aware_timestamp(value):
    if not isinstance(value, str):
        raise ValueError("Timestamp must be an ISO-8601 string with a timezone")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def _reject_constant(value):
    raise ValueError("Non-finite JSON number")


def decode_json(text):
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON member")
            result[key] = value
        return result
    return json.loads(text, parse_constant=_reject_constant, object_pairs_hook=unique_object)


def read_object(path: Path, *, optional=False):
    try:
        if optional and not path.exists():
            return {}
        value = decode_json(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (OSError, UnicodeError, ValueError):
        raise EvidenceError() from None


def validate_record(record):
    try:
        required = {"action_id", "timestamp", "agent_id", "action", "scope", "target",
                    "authorization_result", "trace_verdict", "anomaly_result",
                    "revocation_status", "governance_verdict", "metadata", "schema_version"}
        if not isinstance(record, dict) or not required.issubset(record):
            raise ValueError()
        for key in ("action_id", "agent_id", "action", "trace_verdict"):
            if not isinstance(record[key], str) or not record[key]:
                raise ValueError()
        aware_timestamp(record["timestamp"])
        if record["schema_version"] != "1.0" or record["authorization_result"] not in ("ALLOWED", "DENIED") or record["governance_verdict"] not in ("ALLOW", "BLOCK", "REVIEW"):
            raise ValueError()
        for key in ("scope", "target"):
            if record[key] is not None and not isinstance(record[key], str):
                raise ValueError()
        anomaly = record["anomaly_result"]
        if not isinstance(anomaly, dict) or type(anomaly.get("applicable")) is not bool or type(anomaly.get("flagged")) is not bool:
            raise ValueError()
        score = anomaly.get("score")
        if "score" not in anomaly or score is not None and (type(score) not in (int, float) or not math.isfinite(score)):
            raise ValueError()
        metadata = record["metadata"]
        if not isinstance(metadata, dict) or not isinstance(metadata.get("detected_by", []), list):
            raise ValueError()
        if any(not isinstance(v, str) for v in metadata.get("detected_by", [])):
            raise ValueError()
        if metadata.get("chain_check_status") is not None and not isinstance(metadata["chain_check_status"], str):
            raise ValueError()
        if record["revocation_status"] is not None and not isinstance(record["revocation_status"], dict):
            raise ValueError()
        revocation = record["revocation_status"] or {}
        latency = revocation.get("lookup_latency_ms")
        if latency is not None and (type(latency) not in (int, float) or not math.isfinite(latency) or latency < 0):
            raise ValueError()
        if metadata.get("reason") is not None and not isinstance(metadata["reason"], str):
            raise ValueError()
        json.dumps(record, allow_nan=False)
    except (ValueError, TypeError, KeyError, OverflowError):
        raise EvidenceError("EVIDENCE_CORRUPT") from None


def validate_deployment(deployment, profile):
    if not isinstance(deployment, dict):
        raise EvidenceError("EVIDENCE_CORRUPT")
    expected = {"hardhat": 31337, "sepolia": 11155111}.get(profile)
    if not expected or type(deployment.get("chain_id")) is not int or deployment["chain_id"] != expected:
        raise EvidenceError("NETWORK_MISMATCH", 409)
    if not Web3.is_address(deployment.get("contract_address")):
        raise EvidenceError("EVIDENCE_CORRUPT")


def validate_provenance(evidence, deployment, *, prefix=""):
    if not isinstance(evidence, dict) or not isinstance(deployment, dict) or not Web3.is_address(deployment.get("contract_address")) or type(deployment.get("chain_id")) is not int:
        raise EvidenceError("EVIDENCE_CORRUPT")
    chain_id = evidence.get(prefix + "chain_id")
    address = evidence.get(prefix + "contract_address")
    if type(chain_id) is not int or chain_id != deployment["chain_id"] or not Web3.is_address(address) or address.lower() != deployment["contract_address"].lower():
        raise EvidenceError("NETWORK_MISMATCH", 409)


def validate_credential_metadata(credential):
    try:
        for key in ("credential_id", "agent_id", "issuer", "current_status", "content_hash", "transaction_hash"):
            if not isinstance(credential[key], str) or not credential[key]:
                raise ValueError()
        for key in ("allowed_permission_scope", "delegation_scope"):
            if not isinstance(credential[key], list) or any(not isinstance(v, str) for v in credential[key]):
                raise ValueError()
        if not credential["allowed_permission_scope"] or not Web3.is_address(credential["issuer"]):
            raise ValueError()
        if aware_timestamp(credential["issued_at"]) >= aware_timestamp(credential["expires_at"]):
            raise ValueError()
    except (KeyError, TypeError, ValueError, OverflowError):
        raise EvidenceError("EVIDENCE_CORRUPT") from None


def validate_model_metrics(metrics):
    try:
        for name in ("isolation_forest", "rule_baseline"):
            model = metrics[name]
            for key in ("precision", "recall", "f1", "false_positive_rate"):
                if type(model[key]) not in (int, float) or not 0 <= model[key] <= 1:
                    raise ValueError()
            matrix = model["confusion_matrix"]
            if not isinstance(matrix, list) or len(matrix) != 2 or any(not isinstance(row, list) or len(row) != 2 or any(type(v) is not int or v < 0 for v in row) for row in matrix):
                raise ValueError()
            for category in model["per_category"].values():
                if type(category["count"]) is not int or category["count"] < 0 or type(category["recall"]) not in (int, float) or not 0 <= category["recall"] <= 1:
                    raise ValueError()
        for key in ("normal_count", "train_normal_count", "validation_normal_count", "test_normal_count"):
            if type(metrics["dataset"][key]) is not int or metrics["dataset"][key] < 0:
                raise ValueError()
        if any(type(v) is not int or v < 0 for v in metrics["dataset"]["attack_counts"].values()):
            raise ValueError()
        for key in ("average_ms", "worst_case_ms", "feature_average_ms", "scoring_average_ms"):
            if type(metrics["latency"][key]) not in (int, float) or not math.isfinite(metrics["latency"][key]) or metrics["latency"][key] < 0:
                raise ValueError()
        if type(metrics["threshold"]) not in (int, float) or not math.isfinite(metrics["threshold"]):
            raise ValueError()
    except (KeyError, TypeError, ValueError, AttributeError):
        raise EvidenceError("EVIDENCE_CORRUPT") from None


def validate_inventory(state, batches, deployment, profile):
    validate_deployment(deployment, profile)
    try:
        if state.get("version") != 2 or not isinstance(state["records"], dict) or not isinstance(state["credentials"], dict):
            raise ValueError()
        for entry in state["records"].values():
            if not isinstance(entry, dict) or entry.get("kind") not in ("credential", "delegation", "revocation", "action") or entry.get("status") not in ("confirmed", "anchored"):
                raise ValueError()
            if entry.get("status") in ("confirmed", "anchored"):
                validate_provenance(entry["proof"], deployment)
        for credential in state["credentials"].values():
            validate_credential_metadata(credential)
        for batch in batches:
            if batch["status"] == "ANCHORED":
                validate_provenance(batch, deployment, prefix="blockchain_")
    except (KeyError, TypeError, ValueError):
        raise EvidenceError("EVIDENCE_CORRUPT") from None


def validate_batch_state(state):
    from .merkle import build_merkle_tree
    try:
        if state.get("schema_version") != "1.0" or not isinstance(state["batches"], list) or not isinstance(state["action_index"], dict) or not isinstance(state.get("pending_since", {}), dict):
            raise ValueError()
        if type(state.get("revision", 0)) is not int or state.get("revision", 0) < 0:
            raise ValueError()
        for value in state.get("pending_since", {}).values():
            aware_timestamp(value)
        mapping = {}
        batch_ids = set()
        for batch in state["batches"]:
            if batch.get("schema_version") != "1.0":
                raise ValueError()
            count = batch["log_count"]
            ids, leaves = batch["action_ids"], batch["leaf_hashes"]
            if type(count) is not int or count < 1 or not isinstance(ids, list) or not isinstance(leaves, list) or len(ids) != count or len(leaves) != count:
                raise ValueError()
            if any(not isinstance(i, str) or not i for i in ids) or len(set(ids)) != count or set(ids).intersection(mapping):
                raise ValueError()
            if batch["merkle_root"] != build_merkle_tree(leaves)["root"] or batch["batch_id"] != "batch:" + batch["merkle_root"] or batch["batch_id"] in batch_ids:
                raise ValueError()
            if batch["first_action_id"] != ids[0] or batch["last_action_id"] != ids[-1] or batch["status"] not in ("ANCHORED", "SEALED_UNANCHORED"):
                raise ValueError()
            if aware_timestamp(batch["start_timestamp"]) > aware_timestamp(batch["end_timestamp"]):
                raise ValueError()
            for key in ("created_at", "sealed_at"):
                aware_timestamp(batch[key])
            claim = batch.get("anchor_claim")
            if claim is not None:
                if not isinstance(claim, dict) or claim.get("phase") not in ("SUBMITTING", "SUBMITTED"):
                    raise ValueError()
                if claim["phase"] == "SUBMITTED":
                    tx = claim["transaction_hash"]
                    if not isinstance(tx, str) or not tx.startswith("0x") or len(bytes.fromhex(tx[2:])) != 32:
                        raise ValueError()
                if "nonce" in claim and (type(claim["nonce"]) is not int or claim["nonce"] < 0):
                    raise ValueError()
            if batch["status"] == "ANCHORED":
                if not Web3.is_address(batch["blockchain_contract_address"]) or not Web3.is_address(batch["blockchain_anchored_by"]) or type(batch["blockchain_chain_id"]) is not int or type(batch["blockchain_block_number"]) is not int:
                    raise ValueError()
                tx = batch["blockchain_tx_hash"]
                if not isinstance(tx, str) or not tx.startswith("0x") or len(bytes.fromhex(tx[2:])) != 32:
                    raise ValueError()
            mapping.update(dict.fromkeys(ids, batch["batch_id"]))
            batch_ids.add(batch["batch_id"])
        if mapping != state["action_index"]:
            raise ValueError()
    except (KeyError, TypeError, ValueError, AttributeError):
        raise EvidenceError("EVIDENCE_CORRUPT") from None
