"""Contract tests for the adapter; security decisions stay in Modules 1–6."""

import unittest

from fastapi.testclient import TestClient

from backend.api.main import app


class PresentationApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def test_health_and_real_overview(self):
        health = self.client.get("/api/health")
        self.assertEqual(health.status_code, 200)
        self.assertTrue(health.json()["rpc_connected"])
        self.assertTrue(health.json()["contract_available"])
        self.assertTrue(health.json()["ml_model_available"])
        overview = self.client.get("/api/system/overview").json()
        self.assertEqual(overview["registered_agents"], 4)
        self.assertEqual(overview["anchored_actions"], 11)
        self.assertEqual(overview["scenario_count"], 21)

    def test_cors_and_saved_report(self):
        response = self.client.get("/api/final-report", headers={"Origin": "http://localhost:5173"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["access-control-allow-origin"], "http://localhost:5173")
        self.assertEqual(len(response.json()["scenarios"]), 21)
        self.assertIn("module4", self.client.get("/api/metrics").json())

    def test_agents_graph_and_public_revocation(self):
        agents = self.client.get("/api/agents").json()
        self.assertEqual(len(agents), 4)
        self.assertTrue(all(agent["blockchain_address"].startswith("0x") for agent in agents))
        graph = self.client.get("/api/delegation-graph").json()
        self.assertEqual({node["id"] for node in graph["nodes"]},
                         {"ROOT_AUTHORIZER", "Agent_A", "Agent_B", "Agent_C", "Agent_D"})
        self.assertTrue(all(edge["proof_status"] == "PASS" for edge in graph["edges"]))
        self.assertEqual(len(graph["edges"]), 7)
        self.assertTrue(all(edge["transaction_hash"] and edge["block_number"] and edge["content_hash"]
                            for edge in graph["edges"]))
        self.assertFalse(any(edge["from"] == "ROOT_AUTHORIZER" and edge["to"] in ("Agent_B", "Agent_C")
                             and edge["permission"] == "CREATE_AGENT" for edge in graph["edges"]))
        status = self.client.get("/api/revocation/Agent_C").json()
        self.assertEqual(status["status"], "REVOKED")
        self.assertTrue(status["proof_verified"])

    def test_credentials_and_historical_trace(self):
        credentials = self.client.get("/api/agents/Agent_C/credentials").json()["credentials"]
        self.assertEqual({item["permission"] for item in credentials}, {"PROCESS_PAYMENT", "CREATE_AGENT"})
        self.assertTrue(all(item["proof_status"] == "PASS" for item in credentials))
        self.assertEqual(self.client.get("/api/agents/Unknown/credentials").status_code, 404)
        trace = self.client.get("/api/trace", params={"agent_id": "Agent_C", "permission": "CREATE_AGENT"}).json()
        self.assertEqual(trace["verdict"], "VALID_CHAIN")
        self.assertEqual([hop["to"] for hop in trace["chain"]], ["Agent_A", "Agent_B", "Agent_C"])
        action_trace = self.client.get("/api/trace/scenario/post_decommission").json()
        self.assertEqual(action_trace["verdict"], "AUTHORITY_REVOKED_AT_TIME_OF_ACTION")

    def test_scenario_and_injected_authorization(self):
        attack = self.client.post("/api/scenarios/self_escalation")
        self.assertEqual(attack.status_code, 200)
        self.assertEqual(attack.json()["verdict"]["governance_decision"], "BLOCK")
        spoof = self.client.post("/api/governance/evaluate", json={
            "actor": "Agent_D", "action": "CHECK_CREATE_AGENT",
            "permission": "CREATE_AGENT", "result": "ALLOWED",
        })
        self.assertEqual(spoof.status_code, 200)
        self.assertFalse(spoof.json()["authorized"])
        self.assertEqual(spoof.json()["governance_decision"], "BLOCK")
        self.assertTrue(spoof.json()["action"]["record_id"].startswith("synthetic:api:"))

    def test_websocket_stage_sequence_uses_measured_latency(self):
        with self.client.websocket_connect("/ws/governance") as socket:
            socket.send_json({"scenario": "normal"})
            events = [socket.receive_json() for _ in range(12)]
        self.assertEqual(events[0]["event"], "ACTION_RECEIVED")
        self.assertEqual(events[-1]["event"], "VERDICT_COMPLETE")
        self.assertIn(events[-1]["decision"], ("ALLOW", "REVIEW"))
        self.assertTrue(events[-1]["verdict"]["authorized"])
        self.assertEqual(events[-1]["verdict"]["trace_context_verdict"], "VALID_CHAIN")
        self.assertEqual(events[2]["event"], "AUTHORIZATION_COMPLETE")
        self.assertGreaterEqual(events[2]["latency_ms"], 0)
        self.assertEqual(events[-1]["total_latency_ms"], events[-1]["verdict"]["total_latency_ms"])

    def test_all_saved_scenarios_stream_real_verdicts(self):
        expected = {
            "self_escalation": "BLOCK", "unauthorized_delegation": "BLOCK",
            "post_decommission": "BLOCK", "scope_creep": "REVIEW",
        }
        with self.client.websocket_connect("/ws/governance") as socket:
            for scenario, decision in expected.items():
                socket.send_json({"scenario": scenario})
                events = [socket.receive_json() for _ in range(12)]
                self.assertEqual(events[0]["event"], "ACTION_RECEIVED")
                self.assertEqual(events[-1]["decision"], decision)
                self.assertTrue(events[-1]["verdict"]["chain_verified"])
                blockchain = next(event for event in events if event["event"] == "BLOCKCHAIN_VERIFY_COMPLETE")
                self.assertTrue(blockchain["reference"]["transaction_hash"])
                self.assertIsInstance(blockchain["reference"]["block_number"], int)


if __name__ == "__main__":
    unittest.main()
