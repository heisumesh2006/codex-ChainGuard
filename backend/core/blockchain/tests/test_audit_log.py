"""Canonical serialization and append-only audit store tests."""

from datetime import datetime, timezone
from enum import Enum
import json
from pathlib import Path
import tempfile
from unittest import TestCase

from backend.core.blockchain.audit_log import (
    AuditLogStore,
    AuditRecord,
    DuplicateActionIdError,
    canonicalize_record,
    hash_record,
)

TEMP_ROOT = Path(__file__).resolve().parents[4] / ".runtime"
TEMP_ROOT.mkdir(exist_ok=True)


class Result(Enum):
    ALLOWED = "ALLOWED"


def sample_record(**updates):
    value = {
        "action_id": "audit:sample-1",
        "timestamp": datetime(2026, 10, 2, 12, 30, tzinfo=timezone.utc),
        "agent_id": "Agent_B",
        "action": "CREATE_ORDER",
        "scope": "CREATE_ORDER",
        "target": "order-7",
        "authorization_result": Result.ALLOWED,
        "trace_verdict": "VALID_CHAIN",
        "anomaly_result": {"flagged": False, "score": None, "applicable": True},
        "revocation_status": None,
        "governance_verdict": "ALLOW",
        "metadata": {"labels": ["normal", "purchase"], "source_action_id": "source-1"},
        "schema_version": "1.0",
    }
    value.update(updates)
    return value


class AuditLogTests(TestCase):
    def test_canonical_bytes_and_hash_are_repeatable(self):
        record = sample_record()
        self.assertEqual(canonicalize_record(record), canonicalize_record(record))
        self.assertEqual(hash_record(record), hash_record(record))
        self.assertTrue(hash_record(record).startswith("0x"))

    def test_meaningful_field_changes_hash(self):
        original = sample_record()
        changed = sample_record(governance_verdict="REVIEW")
        self.assertNotEqual(hash_record(original), hash_record(changed))

    def test_mapping_insertion_order_does_not_change_bytes_or_hash(self):
        left = sample_record()
        right = dict(reversed(list(sample_record().items())))
        right["metadata"] = dict(reversed(list(right["metadata"].items())))
        self.assertEqual(canonicalize_record(left), canonicalize_record(right))
        self.assertEqual(hash_record(left), hash_record(right))

    def test_datetime_and_enum_normalization_is_explicit(self):
        encoded = canonicalize_record(sample_record())
        decoded = json.loads(encoded)
        self.assertEqual(decoded["timestamp"], "2026-10-02T12:30:00.000000Z")
        self.assertEqual(decoded["authorization_result"], "ALLOWED")
        with self.assertRaises(ValueError):
            canonicalize_record(sample_record(timestamp=datetime(2026, 10, 2)))

    def test_append_retrieve_insertion_order_count_and_unbatched_listing(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as folder:
            store = AuditLogStore(Path(folder) / "nested" / "audit.jsonl")
            first = sample_record()
            second = sample_record(action_id="audit:sample-2", action="VERIFY_ORDER")
            store.append(first)
            store.append(second)
            self.assertEqual(store.count(), 2)
            self.assertEqual(store.get("audit:sample-1")["action"], "CREATE_ORDER")
            self.assertIsNone(store.get("missing"))
            self.assertEqual([item["action_id"] for item in store.list_records()],
                             ["audit:sample-1", "audit:sample-2"])
            self.assertEqual(store.list_unbatched_records(), store.list_records())
            self.assertEqual(len(store.path.read_text(encoding="utf-8").splitlines()), 2)

    def test_duplicate_action_id_is_rejected_without_overwriting(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as folder:
            store = AuditLogStore(Path(folder) / "audit.jsonl")
            original = sample_record()
            store.append(original)
            before = store.path.read_bytes()
            with self.assertRaises(DuplicateActionIdError):
                store.append(sample_record(governance_verdict="BLOCK"))
            self.assertEqual(store.path.read_bytes(), before)
            self.assertEqual(store.count(), 1)


if __name__ == "__main__":
    import unittest

    unittest.main()
