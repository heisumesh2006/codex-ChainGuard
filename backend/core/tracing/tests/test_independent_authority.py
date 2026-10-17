"""Independent root paths and inclusive revocation, with isolated proof stubs."""

from contextlib import ExitStack
from copy import deepcopy
from datetime import datetime, timedelta
import time
import unittest
from unittest.mock import MagicMock, patch

from backend.core.tracing import tracer


class IndependentAuthorityTests(unittest.TestCase):
    root = "0x" + "12" * 20
    permission = "P"
    when = datetime.fromisoformat("2026-10-01T12:00:00Z")

    def credential(self, agent, issuer=None, verified=True):
        return {"agent_id": agent, "issuer": issuer or self.root,
                "allowed_permission_scope": [self.permission], "credential_id": "credential:" + agent,
                "issued_at": "2026-10-01T00:00:00Z", "expires_at": "2026-10-02T00:00:00Z",
                "proof_is_valid": verified}

    def context(self, leaf="Agent_C"):
        delegations = [{"record_id": "delegation:BC", "delegator": "Agent_B", "delegatee": "Agent_C",
                        "permission": self.permission, "timestamp": "2026-10-01T01:00:00Z"}]
        if leaf == "Agent_D":
            delegations.append({"record_id": "delegation:CD", "delegator": "Agent_C", "delegatee": "Agent_D",
                                "permission": self.permission, "timestamp": "2026-10-01T02:00:00Z"})
        revoked = {"record_id": "revocation:B", "decommissioned_agent": "Agent_B",
                   "decommissioned_at": "2026-10-01T10:00:00Z"}
        return tracer.TraceContext(delegations, [], [revoked],
                                   [self.credential("Agent_B"), self.credential("Agent_C")])

    def proof_stubs(self):
        stack = ExitStack()
        contract = MagicMock()
        contract.functions.agentRevoked.side_effect = lambda digest: MagicMock(
            call=lambda: digest == tracer.integration.agent_hash("Agent_B"))
        stack.enter_context(patch.object(tracer.blockchain, "contract_context", return_value=(None, contract, self.root, {})))
        stack.enter_context(patch.object(tracer.blockchain, "identity_addresses", return_value={"ROOT_AUTHORIZER": self.root}))
        def verify_credential(credential, agent, permission):
            return {"verified": credential.get("proof_is_valid", False), "reason": "Controlled issuance proof result",
                    "transaction_hash": "public-test-proof", "block_number": 1}
        stack.enter_context(patch.object(tracer, "_verify_root_credential", side_effect=verify_credential))
        stack.enter_context(patch.object(tracer, "_root_grant_evidence", return_value=None))
        # Model the legacy registry's authenticated zero child-credential binding.
        stack.enter_context(patch.object(tracer, "_delegated_credential_binding", return_value=(None, self.root)))
        stack.enter_context(patch.object(tracer, "get_proof", return_value={
            "kind": "revocation", "transaction_hash": "public-test-proof", "block_number": 1}))
        stack.enter_context(patch.object(tracer, "verify_proof", return_value=True))
        return stack

    def walk(self, context, leaf="Agent_C"):
        with self.proof_stubs():
            return tracer._walk_authority(leaf, self.permission, context, time.perf_counter(), self.when)

    def test_independent_root_credential_survives_incoming_revoked_parent(self):
        result = self.walk(self.context())
        self.assertTrue(result["valid"], result)
        self.assertEqual([hop["to"] for hop in result["chain"]], ["Agent_C"])
        self.assertTrue(result["chain"][0]["proof_verified"])

    def test_independent_root_at_intermediate_preserves_descendant(self):
        result = self.walk(self.context("Agent_D"), "Agent_D")
        self.assertTrue(result["valid"], result)
        self.assertEqual([hop["to"] for hop in result["chain"]], ["Agent_C", "Agent_D"])

    def test_unverified_root_candidate_cannot_bypass_revoked_parent(self):
        context = self.context()
        context.credentials[1]["proof_is_valid"] = False
        self.assertFalse(self.walk(context)["valid"])

    def test_nonroot_issuer_candidate_cannot_bypass_revoked_parent(self):
        context = self.context()
        context.credentials[1]["issuer"] = "0x" + "34" * 20
        self.assertFalse(self.walk(context)["valid"])

    def test_absent_independent_credential_does_not_manufacture_a_path(self):
        context = self.context()
        context.credentials = context.credentials[:1]
        result = self.walk(context)
        self.assertFalse(result["valid"])
        self.assertEqual(result["verdict"], "AUTHORITY_REVOKED_AT_TIME_OF_ACTION")

    def test_revocation_boundary_is_inclusive_and_before_remains_historical(self):
        context = self.context()
        boundary = datetime.fromisoformat(context.revocations[0]["decommissioned_at"])
        with self.proof_stubs():
            before = tracer._revocation_at_time(context, "Agent_B", boundary - timedelta(microseconds=1))
            exact = tracer._revocation_at_time(context, "Agent_B", boundary)
            after = tracer._revocation_at_time(context, "Agent_B", boundary + timedelta(microseconds=1))
        self.assertIsNone(before[0])
        self.assertEqual(exact[0], "AUTHORITY_REVOKED_AT_TIME_OF_ACTION")
        self.assertEqual(after[0], "AUTHORITY_REVOKED_AT_TIME_OF_ACTION")
        self.assertTrue(exact[2]["proof_verified"])

    def test_timezone_equivalent_boundary_is_revoked(self):
        context = deepcopy(self.context())
        context.revocations[0]["decommissioned_at"] = "2026-10-01T15:30:00+05:30"
        with self.proof_stubs():
            result = tracer._revocation_at_time(context, "Agent_B", datetime.fromisoformat("2026-10-01T10:00:00Z"))
        self.assertEqual(result[0], "AUTHORITY_REVOKED_AT_TIME_OF_ACTION")
