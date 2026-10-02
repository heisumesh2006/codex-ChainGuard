"""Standalone Merkle audit proof generation and verification."""

import json
from typing import Any

from .audit_log import AuditRecord, canonicalize_record, hash_record
from .merkle import _digest_bytes, _hex, hash_pair


def generate_proof(batch: dict[str, Any], leaf_index: int) -> dict[str, Any]:
    """Construct portable proof metadata from a persisted batch descriptor."""
    from .merkle import generate_merkle_proof

    action_ids = batch["action_ids"]
    leaf_hashes = batch["leaf_hashes"]
    if len(action_ids) != batch["log_count"] or len(leaf_hashes) != batch["log_count"]:
        raise ValueError("Persisted batch leaf metadata is inconsistent")
    if not 0 <= leaf_index < batch["log_count"]:
        raise IndexError("Batch leaf index is out of range")
    return {
        "proof_version": "1.0",
        "batch_id": batch["batch_id"],
        "action_id": action_ids[leaf_index],
        "leaf_index": leaf_index,
        "leaf_count": batch["log_count"],
        "leaf_hash": leaf_hashes[leaf_index],
        "merkle_root": batch["merkle_root"],
        "siblings": generate_merkle_proof(leaf_hashes, leaf_index),
    }


def verify_proof(
    record: AuditRecord | dict[str, Any],
    proof: dict[str, Any],
    expected_root: str,
) -> bool:
    """Verify record content, proof positions, batch identity, and expected root."""
    try:
        value = json.loads(canonicalize_record(record))
        if not isinstance(proof, dict) or value.get("action_id") != proof.get("action_id"):
            return False
        root_bytes = _digest_bytes(expected_root)
        if _digest_bytes(proof["merkle_root"]) != root_bytes:
            return False

        leaf = hash_record(record)
        if _digest_bytes(proof["leaf_hash"]) != _digest_bytes(leaf):
            return False
        if proof.get("batch_id") != f"batch:{_hex(root_bytes)}":
            return False

        leaf_count = proof["leaf_count"]
        index = proof["leaf_index"]
        siblings = proof["siblings"]
        if (not isinstance(leaf_count, int) or leaf_count < 1 or
                not isinstance(index, int) or not 0 <= index < leaf_count or
                not isinstance(siblings, list)):
            return False

        current = leaf
        width = leaf_count
        level_index = index
        proof_level = 0
        while width > 1:
            if proof_level >= len(siblings):
                return False
            sibling = siblings[proof_level]
            if not isinstance(sibling, dict):
                return False
            position = "left" if level_index % 2 else "right"
            if sibling.get("position") != position:
                return False
            sibling_hash = _hex(_digest_bytes(sibling["hash"]))
            # For the final unpaired node, the prescribed sibling is itself.
            if width % 2 and level_index == width - 1 and sibling_hash != current:
                return False
            current = (hash_pair(sibling_hash, current) if position == "left"
                       else hash_pair(current, sibling_hash))
            width = (width + 1) // 2
            level_index //= 2
            proof_level += 1

        return proof_level == len(siblings) and _digest_bytes(current) == root_bytes
    except (KeyError, TypeError, ValueError, OverflowError):
        return False


def verify_anchored_batch(batch: dict[str, Any]) -> bool:
    """Independently compare persisted batch evidence with Ethereum state/event data."""
    try:
        from web3 import Web3

        from . import chain

        blockchain = {
            "transaction_hash": batch["blockchain_tx_hash"],
            "block_number": batch["blockchain_block_number"],
            "contract_address": batch["blockchain_contract_address"],
            "chain_id": batch["blockchain_chain_id"],
            "rpc_url": batch["blockchain_rpc_url"],
            "anchored_by": batch["blockchain_anchored_by"],
            "anchored_at": batch["blockchain_anchored_at"],
        }
        web3 = chain.connect(blockchain["rpc_url"])
        if web3.eth.chain_id != blockchain["chain_id"]:
            return False
        address = Web3.to_checksum_address(blockchain["contract_address"])
        if not web3.eth.get_code(address):
            return False
        contract = web3.eth.contract(address=address, abi=chain.artifact()["abi"])
        root_authorizer = contract.functions.rootAuthorizer().call()
        if Web3.to_checksum_address(root_authorizer) != Web3.to_checksum_address(blockchain["anchored_by"]):
            return False

        batch_id = batch["batch_id"]
        if batch_id != f"batch:{batch['merkle_root']}":
            return False
        batch_key = Web3.keccak(text=batch_id)
        merkle_root = _digest_bytes(batch["merkle_root"])
        parsed_start = _parse_timestamp(batch["start_timestamp"])
        parsed_end = _parse_timestamp(batch["end_timestamp"])
        start_timestamp = int(parsed_start.timestamp())
        end_timestamp = int(parsed_end.timestamp())
        stored = contract.functions.auditBatches(batch_key).call()
        if (not stored[6] or stored[0] != merkle_root
                or stored[1] != batch["log_count"]
                or stored[2] != start_timestamp or stored[3] != end_timestamp
                or Web3.to_checksum_address(stored[4]) != Web3.to_checksum_address(blockchain["anchored_by"])
                or stored[5] != blockchain["anchored_at"]):
            return False

        receipt = web3.eth.get_transaction_receipt(blockchain["transaction_hash"])
        if receipt.status != 1 or receipt.blockNumber != blockchain["block_number"]:
            return False
        transaction = web3.eth.get_transaction(blockchain["transaction_hash"])
        if (Web3.to_checksum_address(transaction["to"]) != address
                or Web3.to_checksum_address(transaction["from"]) != Web3.to_checksum_address(root_authorizer)):
            return False
        events = []
        for log in receipt.logs:
            if log["address"].lower() != address.lower():
                continue
            try:
                parsed = contract.events.AuditBatchAnchored().process_log(log)
            except Exception:
                continue
            if parsed["args"]["batchId"] == batch_key:
                events.append(parsed["args"])
        return len(events) == 1 and (
            events[0]["merkleRoot"] == merkle_root
            and events[0]["logCount"] == batch["log_count"]
            and events[0]["startTimestamp"] == start_timestamp
            and events[0]["endTimestamp"] == end_timestamp
            and Web3.to_checksum_address(events[0]["anchoredBy"]) == Web3.to_checksum_address(blockchain["anchored_by"])
            and events[0]["anchoredAt"] == blockchain["anchored_at"]
        )
    except Exception:
        return False


def verify_anchored_proof(record: AuditRecord | dict[str, Any], proof: dict[str, Any]) -> bool:
    """Verify the record path to a root, then verify that root against Ethereum."""
    try:
        if not isinstance(proof, dict) or not verify_proof(record, proof, proof["merkle_root"]):
            return False
        blockchain = proof["blockchain"]
        batch = {
            "batch_id": proof["batch_id"],
            "merkle_root": proof["merkle_root"],
            "log_count": proof["leaf_count"],
            "blockchain_tx_hash": blockchain["transaction_hash"],
            "blockchain_block_number": blockchain["block_number"],
            "blockchain_contract_address": blockchain["contract_address"],
            "blockchain_chain_id": blockchain["chain_id"],
            "blockchain_rpc_url": blockchain["rpc_url"],
            "blockchain_anchored_by": blockchain["anchored_by"],
            "blockchain_anchored_at": blockchain["anchored_at"],
        }
        # Timestamp bounds are supplied in the proof to keep validation independent
        # from batches.json and other local batch-manager state.
        batch["start_timestamp"] = proof["start_timestamp"]
        batch["end_timestamp"] = proof["end_timestamp"]
        return verify_anchored_batch(batch)
    except Exception:
        return False


def _parse_timestamp(value: str):
    from datetime import datetime, timezone

    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Batch timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)
