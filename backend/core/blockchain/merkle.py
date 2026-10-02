"""Deterministic Ethereum-Keccak Merkle tree helpers for audit batches."""

from web3 import Web3


def _digest_bytes(digest: str | bytes) -> bytes:
    if isinstance(digest, bytes):
        value = digest
    elif isinstance(digest, str):
        normalized = digest[2:] if digest.startswith("0x") else digest
        try:
            value = bytes.fromhex(normalized)
        except ValueError as exc:
            raise ValueError("Merkle hashes must be hexadecimal") from exc
    else:
        raise TypeError("Merkle hashes must be hex strings or bytes")
    if len(value) != 32:
        raise ValueError("Merkle hashes must be exactly 32 bytes")
    return value


def _hex(value: bytes) -> str:
    return "0x" + value.hex()


def hash_pair(left: str | bytes, right: str | bytes) -> str:
    """Hash ordered children; sibling order is never sorted."""
    return _hex(Web3.keccak(_digest_bytes(left) + _digest_bytes(right)))


def build_merkle_tree(leaf_hashes: list[str | bytes]) -> dict:
    """Build a tree, duplicating the final node on every odd-width level."""
    if not leaf_hashes:
        raise ValueError("A Merkle tree requires at least one leaf")
    levels = [[_hex(_digest_bytes(item)) for item in leaf_hashes]]
    while len(levels[-1]) > 1:
        current = levels[-1]
        next_level = []
        for index in range(0, len(current), 2):
            left = current[index]
            right = current[index + 1] if index + 1 < len(current) else left
            next_level.append(hash_pair(left, right))
        levels.append(next_level)
    return {"root": levels[-1][0], "levels": levels}


def generate_merkle_proof(leaf_hashes: list[str | bytes], leaf_index: int) -> list[dict[str, str]]:
    """Return leaf-to-root siblings with explicit left/right positions."""
    tree = build_merkle_tree(leaf_hashes)
    if not isinstance(leaf_index, int) or not 0 <= leaf_index < len(leaf_hashes):
        raise IndexError("Merkle leaf index is out of range")
    proof = []
    index = leaf_index
    for level in tree["levels"][:-1]:
        if index % 2:
            sibling_index = index - 1
            position = "left"
        else:
            sibling_index = index + 1 if index + 1 < len(level) else index
            position = "right"
        proof.append({"hash": level[sibling_index], "position": position})
        index //= 2
    return proof
