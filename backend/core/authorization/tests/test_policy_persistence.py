"""Synthetic-key fault injection for durable authorization snapshots."""

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from eth_account import Account
from backend.core.authorization import agents as a, state
from backend.core.authorization.authentication import AuthenticationError, RequestVerifier, sign_request
from backend.core.authorization.logger import ACTION_LOG
from backend.core.blockchain.evidence import EvidenceError


class PolicyPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.saved = deepcopy((a.AGENTS, a.ROOT_AUTHORITY_RECORD, a.DELEGATION_LEDGER, ACTION_LOG))
        self.old_verifier = a._policy_verifier
        self.directory = tempfile.TemporaryDirectory(prefix="policy-persistence-")
        self.addCleanup(self.directory.cleanup)
        self.accounts = {actor: Account.create() for actor in ("ROOT_AUTHORIZER", "Agent_A", "Agent_B")}
        self.verifier = RequestVerifier("isolated-policy-persistence", lambda actor: self.accounts[actor].address,
                                        Path(self.directory.name) / "nonces.json")
        a.AGENTS.clear()
        a.AGENTS.update({actor: a.Agent(actor, "test") for actor in ("Agent_A", "Agent_B")})
        a.ROOT_AUTHORITY_RECORD.clear(); a.DELEGATION_LEDGER.clear(); ACTION_LOG.clear()
        a._policy_verifier = None

    def tearDown(self):
        a.AGENTS.clear(); a.AGENTS.update(self.saved[0])
        a.ROOT_AUTHORITY_RECORD[:] = self.saved[1]; a.DELEGATION_LEDGER[:] = self.saved[2]
        ACTION_LOG[:] = self.saved[3]; a._policy_verifier = self.old_verifier

    def credentials(self, actor, operation, payload):
        return {"authentication": sign_request(self.accounts[actor], self.verifier.domain, actor, operation, payload),
                "verifier": self.verifier}

    def grant(self, permission="P", credentials=None):
        payload = {"agent_id": "Agent_A", "permission": permission, "expires_at": None}
        return a.grant_root_permission("Agent_A", permission,
                                       **(credentials or self.credentials("ROOT_AUTHORIZER", "root_grant", payload)))

    def delegate(self):
        parent_id = a.authority_paths("Agent_A", "P")[0][-1]
        payload = {"delegator": "Agent_A", "delegatee": "Agent_B", "permission": "P",
                   "expires_at": None, "parent_grant_id": parent_id}
        return a.delegate_permission(a.AGENTS["Agent_A"], a.AGENTS["Agent_B"], "P", parent_grant_id=parent_id,
                                     **self.credentials("Agent_A", "delegate", payload))

    def test_first_snapshot_failure_does_not_publish_in_memory_grant(self):
        original = a.AGENTS["Agent_A"]
        with patch.object(state, "atomic_write", side_effect=OSError("controlled write failure")):
            with self.assertRaises(OSError): self.grant()
        self.assertIs(a.AGENTS["Agent_A"], original)
        self.assertFalse(state._path(self.verifier).exists())
        self.assertEqual(ACTION_LOG, [])
        self.assertFalse(a.authority_paths("Agent_A", "P"))
        state.refresh_policy(self.verifier)
        self.assertFalse(a.authority_paths("Agent_A", "P"))

    def test_failed_replacement_preserves_previous_snapshot_and_object(self):
        self.grant()
        original = a.AGENTS["Agent_A"]
        before = state._path(self.verifier).read_bytes()
        with patch.object(state, "atomic_write", side_effect=OSError("controlled replace failure")):
            with self.assertRaises(OSError): self.grant("Q")
        self.assertIs(a.AGENTS["Agent_A"], original)
        self.assertEqual(state._path(self.verifier).read_bytes(), before)
        self.assertTrue(a.authority_paths("Agent_A", "P"))
        self.assertFalse(a.authority_paths("Agent_A", "Q"))

    def test_failed_delegation_restores_ledger_permissions_and_log(self):
        self.grant()
        before = deepcopy(ACTION_LOG)
        original = a.AGENTS["Agent_B"]
        with patch.object(state, "atomic_write", side_effect=OSError("controlled write failure")):
            with self.assertRaises(OSError): self.delegate()
        self.assertIs(a.AGENTS["Agent_B"], original)
        self.assertEqual(a.DELEGATION_LEDGER, [])
        self.assertEqual(original.delegated_permissions, [])
        self.assertEqual(ACTION_LOG, before)

    def test_failed_decommission_preserves_existing_authority(self):
        self.grant(); self.delegate()
        before = deepcopy((a.DELEGATION_LEDGER, ACTION_LOG))
        original = a.AGENTS["Agent_A"]
        payload = {"agent_id": "Agent_A", "reason": "controlled"}
        with patch.object(state, "atomic_write", side_effect=OSError("controlled write failure")):
            with self.assertRaises(OSError):
                a.decommission_agent("Agent_A", reason="controlled", **self.credentials("ROOT_AUTHORIZER", "decommission", payload))
        self.assertIs(a.AGENTS["Agent_A"], original)
        self.assertEqual(original.status, "ACTIVE")
        self.assertTrue(a.authority_paths("Agent_B", "P"))
        self.assertEqual((a.DELEGATION_LEDGER, ACTION_LOG), before)

    def test_error_after_atomic_commit_does_not_revive_revoked_authority(self):
        self.grant(); self.delegate()
        write = state.atomic_write
        def committed_then_failed(path, content):
            write(path, content)
            raise OSError("controlled post-replacement failure")
        payload = {"agent_id": "Agent_A", "reason": "controlled"}
        with patch.object(state, "atomic_write", side_effect=committed_then_failed):
            with self.assertRaises(OSError):
                a.decommission_agent("Agent_A", reason="controlled", **self.credentials(
                    "ROOT_AUTHORIZER", "decommission", payload))
        self.assertEqual(a.AGENTS["Agent_A"].status, "DECOMMISSIONED")
        self.assertFalse(a.authority_paths("Agent_B", "P"))
        self.assertEqual(ACTION_LOG[-1]["action"], "AGENT_DECOMMISSIONED")
        state.refresh_policy(self.verifier)
        self.assertFalse(a.authority_paths("Agent_B", "P"))

    def test_nonce_stays_consumed_after_failed_publication(self):
        payload = {"agent_id": "Agent_A", "permission": "P", "expires_at": None}
        credentials = self.credentials("ROOT_AUTHORIZER", "root_grant", payload)
        with patch.object(state, "atomic_write", side_effect=OSError("controlled write failure")):
            with self.assertRaises(OSError): self.grant(credentials=credentials)
        with self.assertRaisesRegex(AuthenticationError, "REPLAYED"):
            self.grant(credentials=credentials)
        self.assertEqual(self.grant()["result"], "ALLOWED")

    def test_operation_exception_rolls_back_partial_mutation(self):
        @state.coordinated_policy("test_mutation", lambda f: "ROOT_AUTHORIZER", lambda f: {})
        def operation(*, authentication=None, verifier=None):
            a.AGENTS["Agent_A"].status = "DECOMMISSIONED"
            ACTION_LOG.append({"test": "unpublished"})
            raise ValueError("controlled operation failure")
        with self.assertRaisesRegex(ValueError, "controlled operation failure"):
            operation(**self.credentials("ROOT_AUTHORIZER", "test_mutation", {}))
        self.assertEqual(a.AGENTS["Agent_A"].status, "ACTIVE")
        self.assertEqual(ACTION_LOG, [])

    def test_missing_different_realm_cannot_inherit_signed_authority(self):
        self.grant(); self.delegate()
        a.AGENTS["Agent_B"].status = "DECOMMISSIONED"
        other = RequestVerifier("different-isolated-realm", lambda actor: self.accounts[actor].address,
                                Path(self.directory.name) / "other-nonces.json")
        state.refresh_policy(other)
        self.assertFalse(a.authority_paths("Agent_A", "P"))
        self.assertFalse(a.authority_paths("Agent_B", "P"))
        self.assertEqual(a.DELEGATION_LEDGER, [])
        self.assertEqual(a.AGENTS["Agent_B"].status, "ACTIVE")
        self.assertEqual(a.AGENTS["Agent_B"].direct_permissions, ["CREATE_ORDER", "READ_CATALOG"])
        self.assertEqual(ACTION_LOG, [])
        self.assertIs(a._policy_verifier, other)

    def test_malformed_snapshot_members_raise_controlled_error_without_mutation(self):
        self.grant(); self.delegate()
        path = state._path(self.verifier)
        valid = json.loads(path.read_text())
        original = a.AGENTS["Agent_A"]
        mutations = [
            lambda value: value.update(root_grants=[{}]),
            lambda value: value.update(delegations=[{}]),
            lambda value: value["root_grants"][0].update(grants={"P": {}}),
            lambda value: value["root_grants"][0].update(grant_history={"old": {}}),
            lambda value: value["agents"]["Agent_A"].update(direct_permissions="P"),
            lambda value: value["agents"]["Agent_B"].update(delegated_permissions=[{"permission": "P"}]),
            lambda value: value["agents"]["Agent_B"].update(revoked_permissions=["invalid"]),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutations.index(mutation)):
                malformed = deepcopy(valid); mutation(malformed)
                path.write_text(json.dumps(malformed))
                with self.assertRaisesRegex(EvidenceError, "AUTHORITY_STATE_CORRUPT"):
                    state.refresh_policy(self.verifier)
                self.assertIs(a.AGENTS["Agent_A"], original)
                self.assertTrue(a.authority_paths("Agent_A", "P"))
        path.write_text(json.dumps(valid))

    def test_renewed_root_history_remains_loadable_and_preserves_old_signature(self):
        self.grant()
        path = state._path(self.verifier)
        snapshot = json.loads(path.read_text())
        old = snapshot["root_grants"][0]["grants"]["P"]
        old["status"] = "REVOKED"
        path.write_text(json.dumps(snapshot))
        self.grant()
        state.refresh_policy(self.verifier)
        root = a.ROOT_AUTHORITY_RECORD[0]
        self.assertNotEqual(root["grants"]["P"]["record_id"], old["record_id"])
        self.assertEqual(root["grant_history"], [{"permission": "P", **old}])
        self.assertTrue(a.authority_paths("Agent_A", "P"))
