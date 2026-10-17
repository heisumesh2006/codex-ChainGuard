"""HTTP/WebSocket authentication is enforced before governance persistence."""

from datetime import datetime, timezone
from copy import deepcopy
import json
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from backend.api.main import app
from backend.core.authorization.demo_identity import DemoIdentity
from backend.core.governance import pipeline


class AuthenticationApiTests(unittest.TestCase):
    def setUp(self):
        from backend.core.authorization import agents
        from backend.core.authorization.logger import ACTION_LOG
        self.saved_policy = deepcopy((agents.AGENTS, agents.ROOT_AUTHORITY_RECORD, agents.DELEGATION_LEDGER, ACTION_LOG))
        self.saved_verifier = agents._policy_verifier
        self.client = TestClient(app)
        self.identity = DemoIdentity()
        self.action = {"actor": "Agent_B", "action": "USE_PERMISSION", "permission": "CREATE_ORDER",
                       "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}

    def tearDown(self):
        from backend.core.authorization import agents
        from backend.core.authorization.logger import ACTION_LOG
        agents.AGENTS.clear(); agents.AGENTS.update(self.saved_policy[0])
        agents.ROOT_AUTHORITY_RECORD[:] = self.saved_policy[1]
        agents.DELEGATION_LEDGER[:] = self.saved_policy[2]
        ACTION_LOG[:] = self.saved_policy[3]
        agents._policy_verifier = self.saved_verifier
        self.client.close(); self.identity.close()

    def header(self, action=None, actor=None):
        action = action or self.action
        envelope = self.identity.credentials(actor or action["actor"], "evaluate", action)["authentication"]
        return {"X-ChainGuard-Authentication": json.dumps(envelope)}

    def test_missing_signature_is_401_and_never_prepares_or_persists(self):
        with patch.object(pipeline, "prepare_runtime") as prepare, patch.object(pipeline.AUDIT_LOG_STORE, "append") as append:
            response = self.client.post("/api/governance/evaluate", json=self.action)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"]["code"], "AUTHENTICATION_REQUIRED")
        prepare.assert_not_called(); append.assert_not_called()

    def test_claimed_root_with_agent_signature_rejected(self):
        action = {**self.action, "actor": "ROOT_AUTHORIZER", "action": "ROOT_PERMISSION_GRANTED"}
        from backend.core.authorization.authentication import sign_request
        envelope = sign_request(self.identity.accounts["Agent_D"], self.identity.verifier.domain,
                                "ROOT_AUTHORIZER", "evaluate", action)
        with patch.object(pipeline, "registered_verifier", return_value=self.identity.verifier), patch.object(pipeline, "prepare_runtime") as prepare:
            response = self.client.post("/api/governance/evaluate", json=action,
                                       headers={"X-ChainGuard-Authentication": json.dumps(envelope)})
        self.assertEqual(response.status_code, 401); prepare.assert_not_called()

    def test_modified_action_does_not_match_signature(self):
        with patch.object(pipeline, "registered_verifier", return_value=self.identity.verifier):
            response = self.client.post("/api/governance/evaluate", json={**self.action, "permission": "ADMIN"}, headers=self.header())
        self.assertEqual(response.status_code, 401)

    def test_invalid_header_is_controlled_and_does_not_echo_content(self):
        response = self.client.post("/api/governance/evaluate", json=self.action,
                                   headers={"X-ChainGuard-Authentication": '{"secret":"SYNTHETIC",broken'})
        self.assertEqual(response.status_code, 401)
        self.assertNotIn("SYNTHETIC", response.text)

    def test_websocket_unsigned_action_cannot_bypass(self):
        with patch.object(pipeline, "prepare_runtime") as prepare:
            with self.client.websocket_connect("/ws/governance") as socket:
                socket.send_json({"action": self.action})
                self.assertEqual(socket.receive_json()["event"], "ACTION_RECEIVED")
                error = socket.receive_json()
                self.assertEqual(error["event"], "ERROR")
                self.assertIn("AUTHENTICATION_REQUIRED", error["detail"])
        prepare.assert_not_called()

    def test_signed_actor_is_bound_before_governance(self):
        # The sentinel exception proves authentication was passed and reaches
        # the actual pipeline. No fake successful governance result is used.
        with patch.object(pipeline, "registered_verifier", return_value=self.identity.verifier), \
                patch.object(pipeline, "prepare_runtime", side_effect=RuntimeError("FIXTURE_STOP_AFTER_AUTH")):
            response = self.client.post("/api/governance/evaluate", json=self.action, headers=self.header())
        self.assertEqual(response.status_code, 503)

    def test_http_replayed_authentication_is_rejected_before_governance(self):
        header = self.header()
        with patch.object(pipeline, "registered_verifier", return_value=self.identity.verifier), \
                patch.object(pipeline, "prepare_runtime", side_effect=RuntimeError("FIXTURE_STOP_AFTER_AUTH")) as prepare:
            self.client.post("/api/governance/evaluate", json=self.action, headers=header)
            second = self.client.post("/api/governance/evaluate", json=self.action, headers=header)
        self.assertEqual(second.status_code, 401)
        self.assertIn("REPLAYED", second.text)
        self.assertEqual(prepare.call_count, 1)
