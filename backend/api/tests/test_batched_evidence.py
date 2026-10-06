"""Profile isolation and read-only batched evidence integration regressions."""

from contextlib import ExitStack
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.api import services
from backend.api.main import app
from backend.core.blockchain import chain, batch_verifier
from backend.core.blockchain.audit_log import AuditLogStore
from backend.core.blockchain.batch_manager import BatchManager
from backend.core.governance import pipeline
from backend.core.tracing import tracer


class BatchedEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.directory = Path(self.stack.enter_context(tempfile.TemporaryDirectory(dir=services.ROOT / ".runtime")))
        store = AuditLogStore(self.directory / "audit.jsonl")
        self.manager = BatchManager(store, self.directory / "batches.json", batch_size=5)
        codes = ("USE_PERMISSION", "SELF_ESCALATION_ATTEMPT", "UNAUTHORIZED_DELEGATION_ATTEMPT", "USE_PERMISSION", "POST_DECOMMISSION_ACTIVITY")
        for index, (code, decision) in enumerate(zip(codes, ("ALLOW", "BLOCK", "BLOCK", "REVIEW", "BLOCK"), strict=True)):
            actor = "Agent_C" if index == 4 else "Agent_D" if index in (1, 2) else "Agent_B"
            store.append({"action_id": f"audit:fixture-{index}", "timestamp": f"2026-10-03T06:10:0{index}Z",
                          "agent_id": actor, "action": code, "scope": "CREATE_AGENT", "target": None,
                          "authorization_result": "ALLOWED" if index in (0, 3) else "DENIED",
                          "trace_verdict": "UNAUTHORIZED_ROOT" if index in (1, 2) else "VALID_CHAIN",
                          "anomaly_result": {"applicable": True, "flagged": index != 0, "score": index / 10},
                          "revocation_status": {"agent_found": True, "is_revoked": index == 4, "proof_verified": index == 4, "lookup_latency_ms": 10},
                          "governance_verdict": decision, "schema_version": "1.0",
                          "metadata": {"source_action_id": "synthetic:000925" if index == 0 else "synthetic:002004" if index == 3 else f"synthetic:test-{index}",
                                       "source_result": "ALLOWED" if index in (0, 3) else "BLOCKED",
                                       "detected_by": [] if index == 0 else ["Module4"],
                                       "chain_check_status": "VERIFIED_VALID_CHAIN" if index in (0, 3, 4) else "FAILED"}})
        self.manager.seal_due_batches()
        metadata = self.manager._read_state()
        metadata["batches"][0].update(status="ANCHORED", blockchain_chain_id=11155111,
                                     blockchain_contract_address="0x" + "12" * 20, blockchain_tx_hash="0x" + "34" * 32,
                                     blockchain_block_number=123, blockchain_anchored_by="0x" + "56" * 20,
                                     blockchain_anchored_at=123, blockchain_rpc_url="")
        self.manager._write_state(metadata)
        state = {"version": 2, "records": {}, "credentials": {"test": {"agent_id": "Agent_A"}}}
        (self.directory / "ethereum_state.json").write_text(json.dumps(state))
        (self.directory / "deployment.json").write_text(json.dumps({"chain_id": 11155111, "contract_address": "0x" + "12" * 20}))
        for module, attr, value in ((chain, "NETWORK_PROFILE", "sepolia"), (chain, "STATE_PATH", self.directory / "ethereum_state.json"), (pipeline, "DATA_DIR", self.directory),
                                    (services, "DATA_DIR", self.directory), (services, "REPORT_PATH", self.directory / "missing.json"),
                                    (pipeline, "AUDIT_BATCH_MANAGER", self.manager)):
            self.stack.enter_context(patch.object(module, attr, value))
        # Keep real Merkle validation; mock only Ethereum and authority discovery.
        self.stack.enter_context(patch.object(batch_verifier, "verify_anchored_batch", return_value=True))
        self.stack.enter_context(patch.object(tracer, "_walk_authority", side_effect=self.walk))
        self.stack.enter_context(patch.object(tracer, "_revocation_at_time", side_effect=lambda ctx, actor, when:
                                             ("AUTHORITY_REVOKED_AT_TIME_OF_ACTION", "Revoked before action", {"proof_verified": True}) if actor == "Agent_C" else (None, "", None)))
        self.client = self.stack.enter_context(TestClient(app))

    @staticmethod
    def walk(actor, permission, context, started, action_time=None):
        assert not context.actions  # This fixture has zero legacy commitments.
        return {"chain": [{"proof_verified": True, "valid_at_action_time": True}], "valid": actor != "Agent_D",
                "verdict": "UNAUTHORIZED_ROOT" if actor == "Agent_D" else "VALID_CHAIN", "reason": "Fixture authority", "trace_latency_ms": 1}

    def test_overview_without_report_or_legacy_actions(self):
        response = self.client.get("/api/system/overview")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["anchored_actions"], 5)
        self.assertEqual(response.json()["registered_agents"], 4)
        self.assertIsNone(response.json()["average_pipeline_latency_ms"])

    def test_metrics_preserve_zero_legacy_transactions(self):
        response = self.client.get("/api/metrics")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["module2"]["action_hashes_anchored"], 0)
        self.assertEqual(response.json()["module2"]["anchored_batch_count"], 1)

    def test_evaluation_preserves_saved_outcomes_and_missing_measurements(self):
        response = self.client.get("/api/final-report")
        self.assertEqual(response.status_code, 200)
        report = response.json()
        self.assertEqual([row["final_decision"] for row in report["scenarios"]], ["ALLOW", "BLOCK", "BLOCK", "REVIEW", "BLOCK"])
        self.assertIsNone(report["end_to_end_latency"]["total_average_ms"])
        self.assertIsNone(report["modules"]["module3_tracing"]["delegation_trace_accuracy"])
        self.assertIsNone(report["overall_test_results"])
        self.assertIn("Shared synthetic", report["metric_provenance"]["module4"])

    def assert_trace(self, name, verdict, decision):
        with patch.object(services, "load_scenarios", side_effect=AssertionError("legacy loader invoked")), patch.object(tracer, "get_proof", side_effect=AssertionError("legacy action proof invoked")):
            response = self.client.get(f"/api/trace/scenario/{name}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["verdict"], verdict)
        self.assertEqual(response.json()["governance_decision"], decision)
        self.assertTrue(response.json()["action_proof_verified"])
        self.assertEqual(response.json()["evidence_type"], "AUDIT_BATCH")

    def test_trace_normal(self):
        self.assert_trace("normal", "VALID_CHAIN", "ALLOW")

    def test_trace_self_escalation(self):
        self.assert_trace("self_escalation", "UNAUTHORIZED_ROOT", "BLOCK")

    def test_trace_unauthorized_delegation(self):
        self.assert_trace("unauthorized_delegation", "BROKEN_CHAIN", "BLOCK")

    def test_trace_scope_creep(self):
        self.assert_trace("scope_creep", "VALID_CHAIN", "REVIEW")

    def test_trace_post_decommission(self):
        self.assert_trace("post_decommission", "AUTHORITY_REVOKED_AT_TIME_OF_ACTION", "BLOCK")

    def test_replay_does_not_run_pipeline_or_change_evidence(self):
        before = {path.name: path.read_bytes() for path in self.directory.iterdir()}
        with patch.object(services, "run_governance_pipeline", side_effect=AssertionError("write attempted")):
            for name in services.SCENARIOS:
                response = self.client.post(f"/api/scenarios/{name}")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()["source"], "persisted_audit_record")
                self.assertEqual(len(services.stage_events(response.json()["verdict"])), 11)
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.directory.iterdir()})

    def test_websocket_replays_saved_evidence(self):
        with self.client.websocket_connect("/ws/governance") as socket:
            socket.send_json({"scenario": "scope_creep"})
            events = [socket.receive_json() for _ in range(12)]
        self.assertEqual(events[-1]["decision"], "REVIEW")
        self.assertIsNone(events[-1]["total_latency_ms"])

    def test_tampered_record_cannot_enter_authority_trace(self):
        record = self.manager.audit_store.list_records()[0]
        proof = self.manager.generate_proof(record["action_id"])
        candidate = deepcopy(record)
        candidate["governance_verdict"] = "BLOCK"
        result = tracer.trace_audit_record(candidate, proof)
        self.assertEqual(result["verdict"], "TAMPERED")
        self.assertFalse(result["action_proof_verified"])

    def test_failed_chain_anchor_cannot_enter_authority_trace(self):
        record = self.manager.audit_store.list_records()[0]
        with patch.object(batch_verifier, "verify_anchored_batch", return_value=False), patch.object(tracer, "_walk_authority") as walk:
            self.assertEqual(tracer.trace_audit_record(record, self.manager.generate_proof(record["action_id"]))["verdict"], "TAMPERED")
            walk.assert_not_called()

    def test_critical_authority_failure_is_not_hidden_by_batch(self):
        record = self.manager.audit_store.list_records()[0]
        with patch.object(tracer, "_walk_authority", return_value={"chain": [], "valid": False, "verdict": "TAMPERED", "reason": "Credential mismatch", "trace_latency_ms": 1}):
            result = tracer.trace_audit_record(record, self.manager.generate_proof(record["action_id"]))
        self.assertEqual(result["verdict"], "TAMPERED")
        self.assertTrue(result["action_proof_verified"])

    def test_report_counts_are_not_hardcoded_to_five(self):
        record = deepcopy(self.manager.audit_store.list_records()[0])
        record["action_id"] = "audit:fixture-extra"
        self.manager.audit_store.append(record)
        report = services.final_report()
        self.assertEqual(report["scenario_counts"]["total"], 6)
        self.assertEqual(report["modules"]["module2_blockchain"]["audit_records"], 6)
        self.assertEqual(report["modules"]["module2_blockchain"]["anchored_audit_records"], 5)

    def test_hardhat_uses_legacy_report(self):
        path = self.directory / "legacy.json"
        path.write_text(json.dumps({"legacy": "unchanged"}))
        with patch.object(chain, "NETWORK_PROFILE", "hardhat"), patch.object(services, "REPORT_PATH", path):
            self.assertEqual(services.final_report(), {"legacy": "unchanged"})

    def test_hardhat_trace_uses_legacy_evidence(self):
        action = {"record_id": "legacy:test"}
        with patch.object(chain, "NETWORK_PROFILE", "hardhat"), patch.object(services, "load_scenarios", return_value=[("NORMAL", "NORMAL", action)]), patch.object(services, "trace_action", return_value={"legacy": True}) as trace:
            self.assertEqual(services.trace_scenario_action("normal"), {"legacy": True})
            trace.assert_called_once_with(action)


if __name__ == "__main__":
    unittest.main()
