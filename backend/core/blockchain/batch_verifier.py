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
