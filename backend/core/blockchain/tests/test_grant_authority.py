"""Live local EVM + signed application policy + governance agreement."""

from contextlib import ExitStack
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import joblib
import json
from fastapi.testclient import TestClient
from backend.api.main import app
from backend.api.schemas import ActionInput
from backend.core.blockchain.evidence import EvidenceError

from backend.research.common import local_policy, local_registry
from backend.core.authorization import agents as a
from backend.core.authorization.operator_signing import operator_credentials
from backend.core.blockchain import chain, grant_authority as g
from backend.core.blockchain.anchor import anchor_revocation
from backend.core.authorization.logger import get_action_log
from backend.core.blockchain.audit_log import AuditLogStore
from backend.core.blockchain.batch_manager import BatchManager
from backend.core.governance import pipeline
from backend.core.revocation import revocation


class GrantAuthorityIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(local_policy())
        self.folder = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix="grant-e2e-")))
        self.web3, self.registry, self.root, _ = self.stack.enter_context(local_registry(self.folder))
        chain.register_identities()
        g.deploy_local()
        self.contract = g.context()[1]
        self.stack.enter_context(patch.object(pipeline, "DATA_DIR", self.folder))
        for name, file in (("BUNDLE_STATE_PATH", "state.json"), ("BUNDLE_DEPLOYMENT_PATH", "deployment.json"), ("BUNDLE_CREDENTIALS_PATH", "credentials.json")):
            self.stack.enter_context(patch.object(revocation, name, self.folder/file))
        store = AuditLogStore(self.folder/"audit.jsonl")
        self.stack.enter_context(patch.object(pipeline, "AUDIT_LOG_STORE", store))
        self.stack.enter_context(patch.object(pipeline, "AUDIT_BATCH_MANAGER", BatchManager(store, self.folder/"batches.json", batch_size=100)))
        self.stack.enter_context(patch.dict(pipeline._runtime, {"module1_ready": True, "model": joblib.load(pipeline.MODEL_PATH)}))
        self.grant("Agent_A")
        for parent, child in (("Agent_A", "Agent_B"), ("Agent_B", "Agent_C"), ("Agent_C", "Agent_D")):
            self.delegate(parent, child)
        self.leaf = g.anchor_path("Agent_D", "P")

    def grant(self, target):
        payload = {"agent_id": target, "permission": "P", "expires_at": None}
        return a.grant_root_permission(target, "P", **operator_credentials("ROOT_AUTHORIZER", "root_grant", payload))

    def delegate(self, parent, child):
        parent_id = a.authority_paths(parent, "P")[0][-1]
        payload = {"delegator": parent, "delegatee": child, "permission": "P", "expires_at": None, "parent_grant_id": parent_id}
        return a.delegate_permission(a.AGENTS[parent], a.AGENTS[child], "P", parent_grant_id=parent_id,
                                     **operator_credentials(parent, "delegate", payload))

    def decommission(self, target):
        return a.decommission_agent(target, reason="integration", **operator_credentials("ROOT_AUTHORIZER", "decommission", {"agent_id": target, "reason": "integration"}))

    def evaluate(self, actor="Agent_D", leaf=None):
        timestamp = datetime.fromtimestamp(self.web3.eth.get_block("latest").timestamp, timezone.utc).isoformat()
        payload = {"actor": actor, "action": "USE_PERMISSION", "permission": "P", "timestamp": timestamp}
        if leaf: payload["authority_grant_id"] = leaf
        return pipeline.run_governance_pipeline({**payload, "record_id": "synthetic:grant-integration"},
                                                **operator_credentials(actor, "evaluate", payload))

    def test_real_registered_keys_and_governance_allow_live_valid_path(self):
        result = self.evaluate(leaf=self.leaf)
        self.assertTrue(result.authorized and result.chain_verified, result)
        self.assertIn(result.governance_decision, ("ALLOW", "REVIEW"))
        self.assertEqual(result.trace_context_verdict, "VALID_CHAIN")
        self.assertTrue(result.chain_evidence["authority_hops"])

    def test_signed_http_workflow_and_replay_are_enforced_end_to_end(self):
        # Sign the public schema's normalized body, as a real caller must.
        payload = ActionInput(actor="Agent_D", action="USE_PERMISSION", permission="P",
                              timestamp=datetime.fromtimestamp(self.web3.eth.get_block("latest").timestamp,
                                                               timezone.utc).isoformat(),
                              authority_grant_id=self.leaf).model_dump(exclude_none=True)
        credentials = operator_credentials("Agent_D", "evaluate", payload)
        headers = {"X-ChainGuard-Authentication": json.dumps(credentials["authentication"])}
        client = TestClient(app)
        before = len(pipeline.AUDIT_LOG_STORE.list_records())
        response = client.post("/api/governance/evaluate", json=payload, headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn(response.json()["governance_decision"], ("ALLOW", "REVIEW"))
        self.assertEqual(len(pipeline.AUDIT_LOG_STORE.list_records()), before + 1)
        replay = client.post("/api/governance/evaluate", json=payload, headers=headers)
        self.assertEqual(replay.status_code, 401, replay.text)
        self.assertEqual(len(pipeline.AUDIT_LOG_STORE.list_records()), before + 1)

    def test_signed_http_payload_substitution_has_no_persistence(self):
        payload = ActionInput(actor="Agent_D", action="USE_PERMISSION", permission="P",
                              timestamp=datetime.now(timezone.utc).isoformat()).model_dump(exclude_none=True)
        credentials = operator_credentials("Agent_D", "evaluate", payload)
        before = len(pipeline.AUDIT_LOG_STORE.list_records())
        response = TestClient(app).post("/api/governance/evaluate", json={**payload, "permission": "ADMIN"},
                                      headers={"X-ChainGuard-Authentication": json.dumps(credentials["authentication"])})
        self.assertEqual(response.status_code, 401, response.text)
        self.assertEqual(len(pipeline.AUDIT_LOG_STORE.list_records()), before)

    def test_cascade_before_and_after_independent_onchain_revocation(self):
        self.decommission("Agent_B")
        self.assertEqual(self.evaluate(leaf=self.leaf).governance_decision, "BLOCK")
        # Demonstrate the distinction: local enforcement precedes a transaction.
        self.assertTrue(self.contract.functions.isValidNow(g.key(self.leaf)).call())
        event = next(row for row in reversed(get_action_log()) if row.get("decommissioned_agent") == "Agent_B")
        anchor_revocation(event)
        self.assertFalse(self.contract.functions.isValidNow(g.key(self.leaf)).call())
        self.assertFalse(g.trace("Agent_D", "P", grant_id=self.leaf)["valid"])

    def test_independent_same_scope_and_explicit_redelegation_survive(self):
        self.decommission("Agent_B")
        self.grant("Agent_C"); independent = g.anchor_path("Agent_C", "P")
        self.assertTrue(g.trace("Agent_C", "P", grant_id=independent)["valid"])
        self.assertEqual(self.evaluate(leaf=self.leaf).governance_decision, "BLOCK")
        self.delegate("Agent_C", "Agent_D"); replacement = g.anchor_path("Agent_D", "P")
        self.assertNotEqual(replacement, self.leaf)
        self.assertNotEqual(self.evaluate(leaf=replacement).governance_decision, "BLOCK")

    def test_cross_agent_grant_id_cannot_authorize_request(self):
        self.assertEqual(self.evaluate("Agent_C", self.leaf).governance_decision, "BLOCK")

    def test_wrong_extension_network_fails_closed(self):
        manifest = json.loads(g.manifest_path().read_text()); manifest["chain_id"] = 11155111
        g.manifest_path().write_text(json.dumps(manifest))
        with self.assertRaisesRegex(EvidenceError, "NETWORK_MISMATCH"): g.context()

    def test_malformed_extension_manifest_fails_with_controlled_error(self):
        g.manifest_path().write_text(json.dumps({"chain_id": 31337}))
        with self.assertRaisesRegex(EvidenceError, "GRANT_MANIFEST_CORRUPT"): g.context()

    def test_every_onchain_hop_must_match_signed_local_path(self):
        records = g.records()
        intermediate = next(row for row in records.values() if row["holder"] == "Agent_B")
        intermediate["holder"] = "Agent_C"
        with patch.object(g, "records", return_value=records):
            with self.assertRaisesRegex(EvidenceError, "GRANT_COMMITMENT_MISMATCH"):
                g.trace("Agent_D", "P", grant_id=self.leaf)

    def test_existing_anchor_cannot_change_signed_expiry(self):
        records = g.records()
        records[self.leaf]["expires_at"] = "2999-01-01T00:00:00Z"
        with patch.object(g, "records", return_value=records):
            with self.assertRaisesRegex(EvidenceError, "GRANT_COMMITMENT_MISMATCH"):
                g.anchor_path("Agent_D", "P")

    def test_live_signed_websocket_and_replay(self):
        payload = ActionInput(actor="Agent_D", action="USE_PERMISSION", permission="P",
                              timestamp=datetime.fromtimestamp(self.web3.eth.get_block("latest").timestamp,
                                                               timezone.utc).isoformat(),
                              authority_grant_id=self.leaf).model_dump(exclude_none=True)
        envelope = operator_credentials("Agent_D", "evaluate", payload)["authentication"]
        with TestClient(app).websocket_connect("/ws/governance") as socket:
            socket.send_json({"action": payload, "authentication": envelope})
            events = [socket.receive_json() for _ in range(12)]
            self.assertEqual(events[-1]["event"], "VERDICT_COMPLETE", events)
            self.assertIn(events[-1]["decision"], ("ALLOW", "REVIEW"))
            count = pipeline.AUDIT_LOG_STORE.count()
            socket.send_json({"action": payload, "authentication": envelope})
            self.assertEqual(socket.receive_json()["event"], "ACTION_RECEIVED")
            error = socket.receive_json()
            self.assertEqual(error["event"], "ERROR")
            self.assertIn("AUTHENTICATION_REPLAYED", error["detail"])
            self.assertEqual(pipeline.AUDIT_LOG_STORE.count(), count)

    def test_extension_cannot_deploy_on_public_profile(self):
        with patch.object(chain, "NETWORK_PROFILE", "sepolia"):
            with self.assertRaisesRegex(RuntimeError, "LOCAL_HARDHAT"): g.deploy_local()
