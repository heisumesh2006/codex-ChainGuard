"""Deterministic Merkle proofs and off-chain audit batching tests."""

from datetime import datetime, timedelta, timezone
from contextlib import ExitStack
import json
from pathlib import Path
import tempfile
from unittest import TestCase
from unittest.mock import patch
from uuid import uuid4

from backend.core.blockchain.audit_log import AuditLogStore
from backend.core.blockchain.batch_manager import BatchManager
from backend.core.blockchain.batch_verifier import verify_proof
from backend.core.blockchain.batch_verifier import verify_anchored_proof
from backend.core.blockchain import chain
from backend.core.blockchain.merkle import build_merkle_tree, generate_merkle_proof


TEMP_ROOT = Path(__file__).resolve().parents[4] / ".runtime"
TEMP_ROOT.mkdir(exist_ok=True)


def record(index: int) -> dict:
    timestamp = datetime(2026, 10, 2, tzinfo=timezone.utc) + timedelta(seconds=index)
    return {
        "action_id": f"audit:test-{index}",
        "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
        "agent_id": "Agent_B",
        "action": "CREATE_ORDER",
        "scope": "CREATE_ORDER",
        "target": f"order-{index}",
        "authorization_result": "ALLOWED",
        "trace_verdict": "VALID_CHAIN",
        "anomaly_result": {"applicable": True, "flagged": False, "score": 0.01},
        "revocation_status": None,
        "governance_verdict": "ALLOW",
        "metadata": {"source_action_id": f"source-{index}"},
        "schema_version": "1.0",
    }


class MerkleTreeTests(TestCase):
    def _case(self, count: int):
        from backend.core.blockchain.audit_log import hash_record

        records = [record(index) for index in range(count)]
        leaves = [hash_record(item) for item in records]
        tree = build_merkle_tree(leaves)
        return records, leaves, tree

    def test_one_leaf(self):
        records, leaves, tree = self._case(1)
        proof = {
            "proof_version": "1.0", "batch_id": f"batch:{tree['root']}",
            "action_id": records[0]["action_id"], "leaf_index": 0,
            "leaf_count": 1, "leaf_hash": leaves[0], "merkle_root": tree["root"], "siblings": [],
        }
        self.assertEqual(tree["root"], leaves[0])
        self.assertTrue(verify_proof(records[0], proof, tree["root"]))

    def test_two_leaves_and_even_count(self):
        for count in (2, 4):
            with self.subTest(count=count):
                records, leaves, tree = self._case(count)
                for index, item in enumerate(records):
                    proof = {
                        "proof_version": "1.0", "batch_id": f"batch:{tree['root']}",
                        "action_id": item["action_id"], "leaf_index": index,
                        "leaf_count": count, "leaf_hash": leaves[index], "merkle_root": tree["root"],
                        "siblings": generate_merkle_proof(leaves, index),
                    }
                    self.assertTrue(verify_proof(item, proof, tree["root"]))

    def test_three_and_five_leaves_duplicate_odd_final_node(self):
        for count in (3, 5):
            with self.subTest(count=count):
                records, leaves, tree = self._case(count)
                proof = {
                    "proof_version": "1.0", "batch_id": f"batch:{tree['root']}",
                    "action_id": records[-1]["action_id"], "leaf_index": count - 1,
                    "leaf_count": count, "leaf_hash": leaves[-1], "merkle_root": tree["root"],
                    "siblings": generate_merkle_proof(leaves, count - 1),
                }
                self.assertEqual(proof["siblings"][0], {"hash": leaves[-1], "position": "right"})
                self.assertTrue(verify_proof(records[-1], proof, tree["root"]))

    def test_same_inputs_have_same_root(self):
        _, leaves, first = self._case(5)
        second = build_merkle_tree(list(leaves))
        self.assertEqual(first["root"], second["root"])

    def test_modified_record_sibling_direction_or_root_fails(self):
        records, leaves, tree = self._case(3)
        proof = {
            "proof_version": "1.0", "batch_id": f"batch:{tree['root']}",
            "action_id": records[0]["action_id"], "leaf_index": 0,
            "leaf_count": 3, "leaf_hash": leaves[0], "merkle_root": tree["root"],
            "siblings": generate_merkle_proof(leaves, 0),
        }
        self.assertTrue(verify_proof(records[0], proof, tree["root"]))

        changed_record = dict(records[0], target="changed")
        self.assertFalse(verify_proof(changed_record, proof, tree["root"]))

        changed_sibling = json.loads(json.dumps(proof))
        changed_sibling["siblings"][0]["hash"] = "0x" + "ff" * 32
        self.assertFalse(verify_proof(records[0], changed_sibling, tree["root"]))

        wrong_side = json.loads(json.dumps(proof))
        wrong_side["siblings"][0]["position"] = "left"
        self.assertFalse(verify_proof(records[0], wrong_side, tree["root"]))

        _, _, other_tree = self._case(2)
        self.assertFalse(verify_proof(records[0], proof, other_tree["root"]))

    def test_record_and_proof_from_other_batch_fail(self):
        first_records, first_leaves, first_tree = self._case(2)
        other_records = [record(index + 10) for index in range(3)]
        from backend.core.blockchain.audit_log import hash_record

        other_leaves = [hash_record(item) for item in other_records]
        other_tree = build_merkle_tree(other_leaves)
        first_proof = {
            "proof_version": "1.0", "batch_id": f"batch:{first_tree['root']}",
            "action_id": first_records[0]["action_id"], "leaf_index": 0,
            "leaf_count": 2, "leaf_hash": first_leaves[0], "merkle_root": first_tree["root"],
            "siblings": generate_merkle_proof(first_leaves, 0),
        }
        self.assertFalse(verify_proof(other_records[0], first_proof, first_tree["root"]))
        self.assertFalse(verify_proof(first_records[0], first_proof, other_tree["root"]))


class BatchManagerTests(TestCase):
    def _manager(self, folder: str, *, batch_size=5, max_age_seconds=30):
        root = Path(folder)
        store = AuditLogStore(root / "audit.jsonl")
        manager = BatchManager(
            store,
            metadata_path=root / "batches.json",
            batch_size=batch_size,
            max_age_seconds=max_age_seconds,
        )
        return store, manager

    def test_batch_size_trigger_and_exactly_one_assignment(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as folder:
            store, manager = self._manager(folder, batch_size=5)
            for index in range(4):
                store.append(record(index))
            self.assertEqual(manager.seal_due_batches(), [])
            store.append(record(4))
            sealed = manager.seal_due_batches()
            self.assertEqual(len(sealed), 1)
            batch = sealed[0]
            self.assertEqual(batch["log_count"], 5)
            self.assertEqual(batch["status"], "SEALED_UNANCHORED")
            self.assertIsNone(batch["blockchain_tx_hash"])
            self.assertIsNone(batch["blockchain_block_number"])
            self.assertEqual(len(manager.pending_records()), 0)
            self.assertEqual(manager.record_status("audit:test-0")["batch_id"], batch["batch_id"])
            self.assertEqual(manager.seal_due_batches(), [])
            self.assertEqual(len(manager.list_batches()), 1)

            proof = manager.generate_proof("audit:test-4")
            audit_record = store.get("audit:test-4")
            self.assertTrue(verify_proof(audit_record, proof, batch["merkle_root"]))
            self.assertTrue(manager.verify_record_proof("audit:test-4"))

    def test_age_trigger_uses_pending_since_and_seals_small_batch(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as folder:
            store, manager = self._manager(folder, batch_size=5, max_age_seconds=30)
            start = datetime(2026, 10, 2, tzinfo=timezone.utc)
            store.append(record(0))
            store.append(record(1))
            self.assertEqual(manager.seal_due_batches(now=start), [])
            self.assertEqual(manager.seal_due_batches(now=start + timedelta(seconds=29)), [])
            sealed = manager.seal_due_batches(now=start + timedelta(seconds=30))
            self.assertEqual(len(sealed), 1)
            self.assertEqual(sealed[0]["log_count"], 2)

    def test_already_batched_records_are_excluded_and_never_reassigned(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as folder:
            store, manager = self._manager(folder, batch_size=2)
            store.append(record(0))
            store.append(record(1))
            first = manager.seal_due_batches()[0]
            store.append(record(2))
            self.assertEqual([item["action_id"] for item in manager.pending_records()], ["audit:test-2"])
            self.assertEqual(manager.seal_due_batches(), [])
            self.assertEqual(manager.record_status("audit:test-0")["batch_id"], first["batch_id"])
            self.assertIsNone(manager.record_status("audit:missing"))

    def test_chain_anchor_idempotence_and_independent_record_proof(self):
        suffix = uuid4().hex
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as folder:
            root = Path(folder)
            store, manager = self._manager(folder, batch_size=2)
            paths = {
                "DEPLOYMENT_PATH": root / f"deployment-{suffix}.json",
                "STATE_PATH": root / f"state-{suffix}.json",
                "CREDENTIALS_PATH": root / f"credentials-{suffix}.json",
            }
            with ExitStack() as stack:
                for name, path in paths.items():
                    stack.enter_context(patch.object(chain, name, path))
                chain.deploy_registry()
                store.append(record(100))
                store.append(record(101))
                sealed = manager.seal_due_batches()
                self.assertEqual(len(sealed), 1)

                anchored = manager.anchor_batch(sealed[0]["batch_id"])
                repeated = manager.anchor_batch(sealed[0]["batch_id"])
                self.assertEqual(anchored["status"], "ANCHORED")
                self.assertEqual(anchored["blockchain_tx_hash"], repeated["blockchain_tx_hash"])
                self.assertEqual(anchored["blockchain_block_number"], repeated["blockchain_block_number"])

                proof = manager.generate_proof("audit:test-100")
                self.assertTrue(verify_anchored_proof(store.get("audit:test-100"), proof))
                changed = dict(store.get("audit:test-100"), target="tampered")
                self.assertFalse(verify_anchored_proof(changed, proof))
                changed_root = dict(proof, merkle_root="0x" + "ff" * 32)
                self.assertFalse(verify_anchored_proof(store.get("audit:test-100"), changed_root))

    def test_failed_chain_transaction_remains_unanchored_and_retryable(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as folder:
            store, manager = self._manager(folder, batch_size=1)
            store.append(record(200))
            batch = manager.seal_due_batches()[0]
            with patch.object(chain, "contract_context", side_effect=ConnectionError("simulated RPC outage")):
                with self.assertRaises(ConnectionError):
                    manager.anchor_batch(batch["batch_id"])
            current = manager.get_batch(batch["batch_id"])
            self.assertEqual(current["status"], "SEALED_UNANCHORED")
            self.assertTrue(current["anchor_retry"])
            self.assertIn("simulated RPC outage", current["anchor_error"])


if __name__ == "__main__":
    import unittest

    unittest.main()
