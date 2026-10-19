"""Cryptographic hash-chain baseline with an explicit checkpoint trust policy."""

import json
from pathlib import Path
from web3 import Web3
from backend.core.blockchain.audit_log import canonicalize_record, validate_record
from backend.core.blockchain.persistence import FileLock, atomic_write

ZERO = "0x" + "00" * 32


def chain_entries(records):
    entries, previous = [], ZERO
    for record in records:
        digest = Web3.to_hex(Web3.keccak(bytes.fromhex(previous[2:]) + canonicalize_record(record)))
        entries.append({"record": record, "previous": previous, "hash": digest})
        previous = digest
    return {"entries": entries, "head": previous}


class HashChainLog:
    def __init__(self, path): self.path = Path(path)

    def read(self):
        return json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {"entries": [], "head": ZERO}

    def append(self, record):
        validate_record(record)
        with FileLock(str(self.path) + ".lock"):
            state = self.read()
            if any(entry["record"]["action_id"] == record["action_id"] for entry in state["entries"]):
                raise ValueError("DUPLICATE_ACTION_ID")
            previous = state["head"]
            digest = Web3.to_hex(Web3.keccak(bytes.fromhex(previous[2:]) + canonicalize_record(record)))
            state["entries"].append({"record": record, "previous": previous, "hash": digest})
            state["head"] = digest
            atomic_write(self.path, canonicalize_record(state))

    def verify(self, checkpoint=None):
        try:
            state = self.read()
            records = [entry["record"] for entry in state["entries"]]
            for record in records: validate_record(record)
            if len({r["action_id"] for r in records}) != len(records): return False
            if chain_entries(records) != state: return False
            expected = checkpoint or {"head": state["head"], "count": len(records)}
            return state["head"] == expected["head"] and len(records) == expected["count"]
        except (ValueError, TypeError, KeyError):
            return False
