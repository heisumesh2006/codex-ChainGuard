"""Trace Module 1 authority through Module 2 Ethereum evidence."""

from dataclasses import dataclass
from datetime import datetime
import time
from typing import TypedDict

from web3 import Web3

from module2 import chain as blockchain, integration
from module2.anchor import get_proof, verify_proof


VERDICTS = {
    "VALID_CHAIN",
    "BROKEN_CHAIN",
    "TAMPERED",
    "UNAUTHORIZED_ROOT",
    "AUTHORITY_REVOKED_AT_TIME_OF_ACTION",
    "CIRCULAR_CHAIN",
}


class TraceResult(TypedDict):
    chain: list[dict]
    valid: bool
    verdict: str
    reason: str
    trace_latency_ms: float


@dataclass
class TraceContext:
    delegations: list[dict]
    actions: list[dict]
    revocations: list[dict]
    credentials: list[dict]


def _load_context() -> TraceContext:
    """Use local records for discovery; never use them as proof of validity."""
    state = blockchain.load_state()
    records = list(state["records"].values())
    return TraceContext(
        delegations=[entry["source"] for entry in records if entry["kind"] == "delegation"],
        actions=[entry["source"] for entry in records if entry["kind"] == "action"],
        revocations=[entry["source"] for entry in records if entry["kind"] == "revocation"],
        credentials=list(state["credentials"].values()),
    )


def _finish(chain: list[dict], verdict: str, reason: str, started: float, **extra: object) -> TraceResult:
    if verdict not in VERDICTS:
        raise ValueError(f"Unsupported trace verdict: {verdict}")
    result: TraceResult = {
        "chain": chain,
        "valid": verdict == "VALID_CHAIN",
        "verdict": verdict,
        "reason": reason,
        "trace_latency_ms": (time.perf_counter() - started) * 1000,
    }
    result.update(extra)
    return result


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("Trace timestamp must include a timezone")
    return parsed


def _verify_root_credential(credential: dict, agent_id: str, permission: str) -> dict:
    """Verify the issuance commitment, receipt, event, registration and scope."""
    payload_fields = (
        "agent_id", "agent_hash", "agent_address", "issuer",
        "allowed_permission_scope", "delegation_scope", "issued_at",
        "expires_at", "status_at_issuance",
    )
    try:
        payload = {field: credential[field] for field in payload_fields}
        digest = integration.content_hash(payload)
        onchain_id = integration.onchain_record_id(blockchain.KIND_CODES["credential"], digest)
        if credential["credential_id"] != f"credential:{digest}":
            raise ValueError("Credential ID does not match content")
        if credential["content_hash"] != digest or credential["onchain_id"] != "0x" + onchain_id.hex():
            raise ValueError("Credential content commitment mismatch")
        if payload["agent_id"] != agent_id or payload["allowed_permission_scope"] != [permission]:
            raise ValueError("Credential holder or permission scope mismatch")
        if payload["status_at_issuance"] != "ACTIVE":
            raise ValueError("Credential was not active at issuance")
        if payload["agent_hash"] != "0x" + integration.agent_hash(agent_id).hex():
            raise ValueError("Agent hash mismatch")

        web3, contract, root, _ = blockchain.contract_context()
        if payload["issuer"] != root or contract.functions.rootAuthorizer().call() != root:
            raise ValueError("Credential issuer is not ROOT_AUTHORIZER")
        if contract.functions.agentAddresses(integration.agent_hash("ROOT_AUTHORIZER")).call() != root:
            raise ValueError("Root identity is not registered")
        if contract.functions.agentAddresses(integration.agent_hash(agent_id)).call() != payload["agent_address"]:
            raise ValueError("Agent identity is not registered")
        stored = contract.functions.credentials(onchain_id).call()
        expected_scope = integration.permission_hash(permission)
        expected_delegation_scope = expected_scope if payload["delegation_scope"] == [permission] else bytes(32)
        if payload["delegation_scope"] not in ([], [permission]):
            raise ValueError("Unexpected delegation scope")
        if (
            stored[0] != integration.agent_hash(agent_id)
            or stored[1] != payload["agent_address"]
            or stored[2] != root
            or stored[3] != expected_scope
            or stored[4] != expected_delegation_scope
            or stored[5] != integration.timestamp_seconds(payload["issued_at"])
            or stored[6] != integration.timestamp_seconds(payload["expires_at"])
            or stored[8] != bytes.fromhex(digest)
        ):
            raise ValueError("On-chain credential fields differ from issuance content")
        commitment = contract.functions.commitments(onchain_id).call()
        if commitment[0] != bytes.fromhex(digest) or commitment[1] != blockchain.KIND_CODES["credential"]:
            raise ValueError("On-chain credential commitment missing")
        receipt = web3.eth.get_transaction_receipt(credential["transaction_hash"])
        if receipt.status != 1 or receipt.to != contract.address:
            raise ValueError("Credential issuance transaction failed")
        transaction = web3.eth.get_transaction(credential["transaction_hash"])
        if transaction["from"] != root:
            raise ValueError("Credential issuance was not sent by root")
        event = contract.events.CredentialIssued()
        matches = [
            event.process_log(log)
            for log in receipt.logs
            if log["address"].lower() == contract.address.lower()
            and log["topics"][0] == Web3.keccak(text=blockchain.EVENT_SIGNATURES["credential"])
        ]
        if len(matches) != 1 or (
            matches[0]["args"]["recordId"] != onchain_id
            or matches[0]["args"]["agentHash"] != integration.agent_hash(agent_id)
            or matches[0]["args"]["contentHash"] != bytes.fromhex(digest)
        ):
            raise ValueError("CredentialIssued event mismatch")
        return {
            "verified": True,
            "reason": "Root credential and issuance transaction verified",
            "transaction_hash": Web3.to_hex(receipt.transactionHash),
            "block_number": receipt.blockNumber,
        }
    except Exception as exc:
        return {"verified": False, "reason": str(exc), "transaction_hash": None, "block_number": None}


def _root_grant_evidence(context: TraceContext, agent_id: str, permission: str) -> dict | None:
    matches = [
        action for action in context.actions
        if action.get("action") == "ROOT_PERMISSION_GRANTED"
        and action.get("target_agent") == agent_id
        and action.get("permission") == permission
        and action.get("result") == "ALLOWED"
        and action.get("actor") == "ROOT_AUTHORIZER"
    ]
    if not matches:
        return None
    return min(matches, key=lambda item: item["timestamp"])


def _walk_authority(
    agent_id: str, permission: str, context: TraceContext, started: float,
    action_time: datetime | None = None,
) -> TraceResult:
    current = agent_id
    visited: set[str] = set()
    reverse_records: list[dict] = []

    # Build the logical path iteratively. Detect loops before any network call
    # so even malformed, unanchored fixture data cannot cause infinite tracing.
    while True:
        if current in visited:
            return _finish([], "CIRCULAR_CHAIN", f"Delegation revisits {current}", started)
        visited.add(current)
        candidates = [
            item for item in context.delegations
            if item.get("delegatee") == current and item.get("permission") == permission
        ]
        if not candidates:
            break
        candidate = max(candidates, key=lambda item: item.get("timestamp", ""))
        reverse_records.append(candidate)
        current = candidate["delegator"]

    root_agent = current
    credential_candidates = [
        item for item in context.credentials
        if item.get("agent_id") == root_agent
        and permission in item.get("allowed_permission_scope", [])
    ]
    if not credential_candidates:
        return _finish(
            [], "UNAUTHORIZED_ROOT",
            f"{root_agent} has no trusted root-issued {permission} credential", started,
        )
    root_credential = next(
        (item for item in credential_candidates if item.get("issuer") == blockchain.identity_addresses()["ROOT_AUTHORIZER"]),
        None,
    )
    if root_credential is None:
        return _finish(
            [], "BROKEN_CHAIN",
            f"{root_agent} has a non-root credential but its incoming delegation is missing", started,
        )
    credential_check = _verify_root_credential(root_credential, root_agent, permission)
    root_hop = {
        "from": "ROOT_AUTHORIZER", "to": root_agent, "permission": permission,
        "evidence_type": "ROOT_CREDENTIAL",
        "anchored": credential_check["verified"],
        "proof_verified": credential_check["verified"],
        "record_id": root_credential["credential_id"],
        "transaction_hash": credential_check["transaction_hash"],
        "block_number": credential_check["block_number"],
        "valid_at_action_time": True if action_time else None,
    }
    if not credential_check["verified"]:
        return _finish([root_hop], "TAMPERED", credential_check["reason"], started)

    root_grant = _root_grant_evidence(context, root_agent, permission)
    if root_grant is not None:
        try:
            root_proof = get_proof(integration.blockchain_record_id("action", root_grant))
        except (KeyError, RuntimeError, ValueError):
            return _finish([root_hop], "BROKEN_CHAIN", "Root grant action has no blockchain proof", started)
        if not verify_proof(root_grant, root_proof):
            return _finish([root_hop], "TAMPERED", "Root grant action proof failed", started)
        root_hop["root_grant_record_id"] = root_grant["record_id"]
        root_hop["root_grant_proof_verified"] = True
        root_hop["root_grant_transaction_hash"] = root_proof["transaction_hash"]
        if action_time and _parse_time(root_grant["timestamp"]) > action_time:
            return _finish([root_hop], "BROKEN_CHAIN", "Root grant occurred after the action", started)

    ordered_hops = [root_hop]
    last_grant_time = _parse_time(root_grant["timestamp"]) if root_grant else None
    for record in reversed(reverse_records):
        deterministic_id = integration.blockchain_record_id("delegation", record)
        hop = {
            "from": record["delegator"], "to": record["delegatee"],
            "permission": permission, "evidence_type": "DELEGATION",
            "anchored": False, "proof_verified": False,
            "record_id": deterministic_id,
            "source_record_id": record.get("record_id"),
            "transaction_hash": None, "block_number": None,
            "valid_at_action_time": True if action_time else None,
        }
        ordered_hops.append(hop)
        grant_time = _parse_time(record["timestamp"])
        if last_grant_time and grant_time < last_grant_time:
            return _finish(ordered_hops, "BROKEN_CHAIN", "Delegation timestamps are out of order", started)
        if action_time and grant_time > action_time:
            return _finish(ordered_hops, "BROKEN_CHAIN", "Delegation occurred after the action", started)
        last_grant_time = grant_time
        try:
            proof = get_proof(deterministic_id)
        except (KeyError, RuntimeError, ValueError):
            # A changed field changes the deterministic ID. The Module 1 UUID
            # is used only as a diagnostic source reference: the original
            # record must still verify against Ethereum before we call this
            # TAMPERED. It never authorizes a hop by itself.
            try:
                source_proof = get_proof(record["record_id"])
                original = blockchain.load_state()["records"][source_proof["record_id"]]["source"]
                if (
                    source_proof.get("kind") == "delegation"
                    and verify_proof(original, source_proof)
                    and not verify_proof(record, source_proof)
                ):
                    hop["anchored"] = True
                    hop["transaction_hash"] = source_proof["transaction_hash"]
                    hop["block_number"] = source_proof["block_number"]
                    return _finish(
                        ordered_hops, "TAMPERED",
                        f"{record['delegator']} -> {record['delegatee']} differs from its verified blockchain record",
                        started,
                    )
            except (KeyError, RuntimeError, ValueError):
                pass
            return _finish(
                ordered_hops, "BROKEN_CHAIN",
                f"Required {record['delegator']} -> {record['delegatee']} delegation is not anchored", started,
            )
        hop["anchored"] = True
        hop["transaction_hash"] = proof.get("transaction_hash")
        hop["block_number"] = proof.get("block_number")
        if not verify_proof(record, proof):
            return _finish(
                ordered_hops, "TAMPERED",
                f"Blockchain proof failed for {record['delegator']} -> {record['delegatee']}", started,
            )
        hop["proof_verified"] = True

    return _finish(ordered_hops, "VALID_CHAIN", "Every authority hop verifies back to ROOT_AUTHORIZER", started)


def trace_agent_authority(agent_id: str, permission: str) -> TraceResult:
    """Trace historical acquisition of a permission, independent of current status."""
    started = time.perf_counter()
    try:
        return _walk_authority(agent_id, permission, _load_context(), started)
    except Exception as exc:
        return _finish([], "BROKEN_CHAIN", f"Could not complete authority trace: {exc}", started)


def _revocation_at_time(context: TraceContext, agent_id: str, action_time: datetime) -> tuple[str | None, str, dict | None]:
    matches = [
        record for record in context.revocations
        if record.get("decommissioned_agent") == agent_id
    ]
    if not matches:
        # If the contract says revoked but the off-chain event is unavailable,
        # the action time cannot be established and the trace fails closed.
        _, contract, _, _ = blockchain.contract_context()
        if contract.functions.agentRevoked(integration.agent_hash(agent_id)).call():
            return "BROKEN_CHAIN", "On-chain revocation exists but its timestamped record is missing", None
        return None, "", None
    for record in matches:
        try:
            proof = get_proof(record["record_id"])
        except (KeyError, RuntimeError, ValueError):
            return "BROKEN_CHAIN", "Revocation record has no blockchain proof", None
        if proof.get("kind") != "revocation" or not verify_proof(record, proof):
            return "TAMPERED", "Anchored revocation proof failed", None
        _, contract, _, _ = blockchain.contract_context()
        if not contract.functions.agentRevoked(integration.agent_hash(agent_id)).call():
            return "BROKEN_CHAIN", "Revocation commitment exists but on-chain status is not revoked", None
        revoked_at = _parse_time(record["decommissioned_at"])
        evidence = {
            "record_id": record["record_id"],
            "transaction_hash": proof["transaction_hash"],
            "block_number": proof["block_number"],
            "revoked_at": record["decommissioned_at"],
            "proof_verified": True,
        }
        if action_time > revoked_at:
            return (
                "AUTHORITY_REVOKED_AT_TIME_OF_ACTION",
                f"{agent_id} was decommissioned at {record['decommissioned_at']} before this action",
                evidence,
            )
    return None, "", None


def trace_action(action_log_entry: dict) -> TraceResult:
    """Trace an action's permission and compare it to anchored revocation time."""
    started = time.perf_counter()
    try:
        context = _load_context()
        actor = action_log_entry["actor"]
        action_code = action_log_entry["action"]
        action_time = _parse_time(action_log_entry["timestamp"])
        try:
            action_proof = get_proof(integration.blockchain_record_id("action", action_log_entry))
        except (KeyError, RuntimeError, ValueError):
            return _finish([], "BROKEN_CHAIN", "Action log entry is not anchored", started)
        if not verify_proof(action_log_entry, action_proof):
            return _finish([], "TAMPERED", "Action log commitment failed verification", started)

        if action_code == "AGENT_DECOMMISSIONED" and actor == "ROOT_AUTHORIZER":
            _, contract, root, _ = blockchain.contract_context()
            if contract.functions.rootAuthorizer().call() == root:
                return _finish([], "VALID_CHAIN", "Root-authorized decommission action verified", started)
        if action_code == "ROOT_PERMISSION_GRANTED" and actor == "ROOT_AUTHORIZER":
            result = _walk_authority(action_log_entry["target_agent"], action_log_entry["permission"], context, started, action_time)
            result["action_result"] = action_log_entry["result"]
            return result

        permission = action_log_entry.get("permission")
        if permission is None and action_code.startswith("DELEGATE_"):
            permission = action_code.removeprefix("DELEGATE_")
        if permission is None and action_code.startswith("CHECK_"):
            permission = action_code.removeprefix("CHECK_")
        if not permission:
            return _finish([], "BROKEN_CHAIN", f"No permission can be inferred from {action_code}", started)

        historical = _walk_authority(actor, permission, context, started, action_time)
        if action_code == "UNAUTHORIZED_DELEGATION_ATTEMPT" and not historical["valid"]:
            return _finish(
                historical["chain"], "BROKEN_CHAIN",
                f"{actor} lacked a rooted {permission} permission and could not delegate it", started,
                action_result=action_log_entry["result"],
            )
        if action_code == "SELF_ESCALATION_ATTEMPT" and not historical["valid"]:
            return _finish(
                historical["chain"], "UNAUTHORIZED_ROOT",
                f"{actor} could not grant itself {permission}; no trusted root authority exists", started,
                action_result=action_log_entry["result"],
            )
        if not historical["valid"]:
            historical["action_result"] = action_log_entry["result"]
            return historical

        revoked_verdict, revoked_reason, revocation_evidence = _revocation_at_time(context, actor, action_time)
        if revoked_verdict:
            if revoked_verdict == "AUTHORITY_REVOKED_AT_TIME_OF_ACTION":
                historical["chain"][-1]["valid_at_action_time"] = False
            return _finish(
                historical["chain"], revoked_verdict, revoked_reason, started,
                action_result=action_log_entry["result"], revocation_evidence=revocation_evidence,
            )
        return _finish(
            historical["chain"], "VALID_CHAIN", "Authority was valid at the action timestamp", started,
            action_result=action_log_entry["result"],
        )
    except Exception as exc:
        return _finish([], "BROKEN_CHAIN", f"Could not complete action trace: {exc}", started)
