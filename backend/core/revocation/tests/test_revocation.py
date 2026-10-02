"""Live-chain Module 5 public status, proof, failure, and audit checks."""

from copy import deepcopy
from datetime import datetime, timedelta
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from backend.core.blockchain import chain
from backend.core.revocation.audit import calculate_revocation_completeness, check_post_revocation_activity
from backend.core.revocation.main import _cold_status_check, _real_action, isolated_registry
from backend.core.revocation.revocation import (
    RevocationAnchoringError, _bundle_context, _record_from_status, _revocation_events, get_revocation_status,
    revoke, verify_revocation_proof,
)


class NarrowProviderEventTests(unittest.TestCase):
    def test_revocation_event_lookup_queries_only_confirmed_block(self):
        web3 = Mock()
        web3.eth.block_number = 115
        web3.eth.get_block.side_effect = lambda number: SimpleNamespace(timestamp=1000 + number - 100)
        web3.eth.get_logs.return_value = ["revocation-log"]
        contract = Mock()
        contract.address = "0x" + "1" * 40
        contract.functions.getRevocationDetails.return_value.call.return_value = (
            "2026-10-02T00:00:00+00:00", "ROOT_AUTHORIZER", [], bytes(32), bytes(32), 1010,
        )
        contract.events.RevocationAnchored.return_value.process_log.return_value = {"verified": True}

        self.assertEqual(_revocation_events(web3, contract, "Agent_C", from_block=100), [{"verified": True}])
        query = web3.eth.get_logs.call_args.args[0]
        self.assertEqual((query["fromBlock"], query["toBlock"]), (110, 110))
        self.assertEqual(query["address"], contract.address)

    def test_revocation_event_lookup_rejects_missing_confirmation_block(self):
        web3 = Mock()
        web3.eth.block_number = 102
        web3.eth.get_block.side_effect = lambda number: SimpleNamespace(timestamp=1000 + number - 100)
        contract = Mock()
        contract.functions.getRevocationDetails.return_value.call.return_value = (
            "2026-10-02T00:00:00+00:00", "ROOT_AUTHORIZER", [], bytes(32), bytes(32), 2000,
        )

        self.assertEqual(_revocation_events(web3, contract, "Agent_C", from_block=100), [])
        web3.eth.get_logs.assert_not_called()


class PublicStatusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c = get_revocation_status("Agent_C")

    def test_three_distinct_statuses_and_chain_proof(self):
        self.assertEqual(self.c["status"], "REVOKED")
        self.assertTrue(self.c["agent_found"] and self.c["is_revoked"])
        self.assertTrue(verify_revocation_proof("Agent_C", self.c["chain_proof"]))
        active = get_revocation_status("Agent_B")
        self.assertEqual(active["status"], "ACTIVE")
        self.assertTrue(active["agent_found"])
        self.assertFalse(active["is_revoked"])
        self.assertIsInstance(active["checked_block_number"], int)
        unknown = get_revocation_status("Unknown_Agent")
        self.assertEqual(unknown["status"], "AGENT_NOT_FOUND")
        self.assertFalse(unknown["agent_found"])

    def test_public_status_does_not_read_local_anchor_index(self):
        with patch.object(chain, "load_state", side_effect=AssertionError("local state read")):
            status = get_revocation_status("Agent_C")
            self.assertTrue(verify_revocation_proof("Agent_C", status["chain_proof"]))

    def test_cold_process_does_not_load_module1(self):
        cold = _cold_status_check()
        self.assertEqual(cold["revoked"], "REVOKED")
        self.assertEqual(cold["active"], "ACTIVE")
        self.assertEqual(cold["unknown"], "AGENT_NOT_FOUND")
        self.assertFalse(cold["module1_loaded"])
        self.assertEqual(cold["revoked_by"], "ROOT_AUTHORIZER")
        self.assertEqual(cold["revoked_permissions"], ["PROCESS_PAYMENT", "CREATE_AGENT"])
        self.assertEqual(cold["revoked_at"], self.c["revoked_at"])
        self.assertTrue(cold["proof_verified"])

    def test_full_content_and_tampered_proof(self):
        complete = _record_from_status("Agent_C", self.c)
        self.assertTrue(complete["proof_verified"])
        self.assertEqual(self.c["revoked_at"], complete["revoked_at"])
        self.assertEqual(self.c["revoked_permissions"], [x["permission"] for x in complete["revoked_permissions"]])
        with _bundle_context():
            source = next(entry["source"] for entry in chain.load_state()["records"].values()
                          if entry["kind"] == "revocation" and entry["source"]["decommissioned_agent"] == "Agent_C")
        full_proof = {**self.c["chain_proof"], "source_record": source, "source_record_id": source["record_id"]}
        self.assertTrue(verify_revocation_proof("Agent_C", full_proof))
        changed_source = deepcopy(full_proof)
        changed_source["source_record"]["reason"] = "forged"
        self.assertFalse(verify_revocation_proof("Agent_C", changed_source))
        changed_chain = dict(full_proof, transaction_hash="0x" + "00" * 32)
        self.assertFalse(verify_revocation_proof("Agent_C", changed_chain))
        changed_scope = dict(full_proof, revoked_permissions=["CREATE_AGENT"])
        self.assertFalse(verify_revocation_proof("Agent_C", changed_scope))
        self.assertFalse(verify_revocation_proof("Agent_B", full_proof))

    def test_double_revoke_reuses_same_transaction(self):
        before = self.c["chain_proof"]
        first = revoke("Agent_C", "ALL", "ROOT_AUTHORIZER", "again")
        second = revoke("Agent_C", None, "ROOT_AUTHORIZER", "again")
        after = get_revocation_status("Agent_C")["chain_proof"]
        self.assertEqual(first["transaction_hash"], second["transaction_hash"])
        self.assertEqual(before["transaction_hash"], after["transaction_hash"])
        self.assertEqual(before["record_id"], after["record_id"])
        self.assertEqual(before["block_number"], after["block_number"])

    def test_partial_revocation_rejected(self):
        with self.assertRaisesRegex(ValueError, "PARTIAL_REVOCATION_NOT_SUPPORTED"):
            revoke("Agent_B", ["READ_CATALOG"], "ROOT_AUTHORIZER", "subset")
        self.assertEqual(get_revocation_status("Agent_B")["status"], "ACTIVE")

    def test_missing_agent_rejected(self):
        with self.assertRaisesRegex(ValueError, "AGENT_NOT_FOUND"):
            revoke("Unknown_Agent", "ALL", "ROOT_AUTHORIZER", "unknown")


class AuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.real = _real_action("POST_DECOMMISSION_ACTIVITY")
        cls.decommission = _real_action("AGENT_DECOMMISSIONED")
        cls.status = get_revocation_status("Agent_C")
        cls.full = _record_from_status("Agent_C", cls.status)

    def test_real_blocked_and_allowed_bypass(self):
        audit = check_post_revocation_activity(self.real)
        self.assertTrue(audit["violation"] and audit["chain_verified"])
        anchored = datetime.fromisoformat(self.status["chain_proof"]["anchored_at"])
        local = datetime.fromisoformat(self.full["revoked_at"])
        bypass = dict(self.real, result="ALLOWED", reason=None,
                      timestamp=(max(anchored, local) + timedelta(seconds=1)).isoformat())
        bypass_audit = check_post_revocation_activity(bypass)
        self.assertTrue(bypass_audit["violation"] and bypass_audit["chain_verified"])
        counts = calculate_revocation_completeness([self.real, bypass])
        self.assertEqual(counts["post_revocation_attempts"], 2)
        self.assertEqual(counts["caught_by_realtime"], 1)
        self.assertEqual(counts["caught_by_audit"], 2)
        self.assertEqual(counts["revocation_completeness"], 1.0)

    def test_strict_timestamp_boundary_and_event_exclusion(self):
        local = datetime.fromisoformat(self.full["revoked_at"])
        at_boundary = dict(self.real, timestamp=local.isoformat())
        before = dict(self.real, timestamp=(local - timedelta(microseconds=1)).isoformat())
        after = dict(self.real, timestamp=(local + timedelta(microseconds=1)).isoformat())
        self.assertFalse(check_post_revocation_activity(before)["violation"])
        self.assertFalse(check_post_revocation_activity(at_boundary)["violation"])
        self.assertTrue(check_post_revocation_activity(after)["violation"])
        self.assertFalse(check_post_revocation_activity(self.decommission)["violation"])
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            check_post_revocation_activity(dict(self.real, timestamp=local.replace(tzinfo=None).isoformat()))

    def test_active_agent_not_a_violation(self):
        action = dict(self.real, actor="Agent_B")
        self.assertFalse(check_post_revocation_activity(action)["violation"])


class FreshRevocationTests(unittest.TestCase):
    def test_fresh_full_revocation_and_latency(self):
        with isolated_registry():
            import time
            started = time.perf_counter()
            result = revoke("Agent_D", ["VERIFY_ORDER"], "ROOT_AUTHORIZER", "isolated")
            status = get_revocation_status("Agent_D")
            latency = (time.perf_counter() - started) * 1000
            self.assertTrue(result["proof_verified"] and status["is_revoked"])
            self.assertTrue(verify_revocation_proof("Agent_D", status["chain_proof"]))
            self.assertGreater(latency, 0)
            self.assertEqual([item["permission"] for item in result["revoked_permissions"]], ["VERIFY_ORDER"])

    def test_failed_anchor_is_incomplete_and_retryable(self):
        from backend.core.authorization import agents
        with isolated_registry():
            with patch.object(chain, "contract_context", side_effect=ConnectionError("simulated outage")):
                with self.assertRaises(RevocationAnchoringError) as caught:
                    revoke("Agent_D", "ALL", "ROOT_AUTHORIZER", "outage")
            error = caught.exception
            self.assertEqual(error.code, "REVOCATION_ANCHORING_FAILED")
            self.assertTrue(error.local_revocation)
            self.assertFalse(error.blockchain_anchored or error.revocation_complete)
            self.assertEqual(agents.AGENTS["Agent_D"].status, "DECOMMISSIONED")
            self.assertEqual(get_revocation_status("Agent_D")["status"], "ACTIVE")
            failures = list(chain.load_state()["failed"].values())
            self.assertEqual(len(failures), 1)
            self.assertTrue(failures[0]["retry"])
            result = revoke("Agent_D", "ALL", "ROOT_AUTHORIZER", "retry")
            self.assertTrue(result["proof_verified"])
            self.assertFalse(chain.load_state()["failed"])
            self.assertEqual(get_revocation_status("Agent_D")["status"], "REVOKED")

    def test_anchor_without_verified_proof_is_incomplete(self):
        with isolated_registry():
            with patch("backend.core.revocation.revocation.verify_revocation_proof", return_value=False):
                with self.assertRaises(RevocationAnchoringError) as caught:
                    revoke("Agent_D", "ALL", "ROOT_AUTHORIZER", "proof failure")
            self.assertEqual(caught.exception.code, "REVOCATION_PROOF_FAILED")
            self.assertTrue(caught.exception.local_revocation)
            self.assertTrue(caught.exception.blockchain_anchored)
            self.assertFalse(caught.exception.revocation_complete)
            self.assertEqual(get_revocation_status("Agent_D")["status"], "REVOKED")


class MetricsTests(unittest.TestCase):
    def test_metrics_file(self):
        path = Path(__file__).resolve().parents[1] / "data" / "metrics.json"
        self.assertTrue(path.exists())
        metrics = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(metrics["revocation_completeness"], 1.0)
        self.assertEqual(metrics["post_revocation_attempts"], 2)
        self.assertGreater(metrics["public_lookup_latency_ms"], 0)
        self.assertGreater(metrics["revocation_to_proof_latency_ms"], 0)
        self.assertTrue(metrics["proof_verification"])


if __name__ == "__main__":
    unittest.main()
