"""Historical time policy with mocked issuance/receipt verification only."""

from copy import deepcopy
from datetime import datetime
from datetime import timedelta
import time
from unittest import TestCase
from unittest.mock import MagicMock, patch

from backend.core.tracing import tracer


class TemporalAuthorityTests(TestCase):
    root = "0x" + "12" * 20
    parent = "0x" + "34" * 20

    def credential(self, agent="Agent_A", issuer=None):
        return {"agent_id": agent, "issuer": issuer or self.root,
                "allowed_permission_scope": ["CREATE_AGENT"], "credential_id": "mock-" + agent,
                "onchain_id": "mock-onchain-" + agent,
                "issued_at": "2026-10-01T00:00:00Z", "expires_at": "2026-10-02T00:00:00Z",
                "current_status": "REVOKED"}

    def walk(self, when, credential=None, delegations=None, credentials=None, legacy=False):
        context = tracer.TraceContext(delegations or [], [], [], credentials or [credential or self.credential()])
        checked = {"verified": True, "reason": "Mock issuance proof verified",
                   "transaction_hash": "mock", "block_number": 1}
        with patch.object(tracer.blockchain, "identity_addresses", return_value={"ROOT_AUTHORIZER": self.root, "Agent_A": self.parent}), \
                patch.object(tracer, "_verify_root_credential", return_value=checked), \
                patch.object(tracer, "_root_grant_evidence", return_value=None), \
                patch.object(tracer, "_delegated_credential_binding", return_value=(None if legacy else "mock-onchain-Agent_B", self.parent)), \
                patch.object(tracer, "get_proof", return_value={"transaction_hash": "mock", "block_number": 1}), \
                patch.object(tracer, "verify_proof", return_value=True):
            return tracer._walk_authority("Agent_B" if delegations else "Agent_A", "CREATE_AGENT", context,
                                          time.perf_counter(), datetime.fromisoformat(when) if when else None)

    def assert_invalid(self, result):
        self.assertFalse(result["valid"], result)
        self.assertEqual(result["verdict"], "BROKEN_CHAIN")
        self.assertFalse(result["chain"][-1]["valid_at_action_time"])

    def test_issued_before_action(self):
        self.assertTrue(self.walk("2026-10-01T00:00:01Z")["valid"])

    def test_issue_boundary_inclusive(self):
        self.assertTrue(self.walk("2026-10-01T00:00:00Z")["valid"])

    def test_exact_not_yet_issued_reproduction(self):
        self.assert_invalid(self.walk("2026-09-30T00:00:00Z"))

    def test_exact_expired_reproduction(self):
        self.assert_invalid(self.walk("2026-10-03T00:00:00Z"))

    def test_expiry_boundary_exclusive(self):
        self.assert_invalid(self.walk("2026-10-02T00:00:00Z"))

    def test_inside_window_historical_revoked_status(self):
        self.assertTrue(self.walk("2026-10-01T12:00:00Z")["valid"])

    def test_no_expiry_after_issue(self):
        credential = self.credential()
        credential.pop("expires_at")
        self.assertTrue(self.walk("2027-10-01T12:00:00Z", credential)["valid"])

    def test_malformed_and_naive_issue_or_expiry_fail_closed(self):
        for field in ("issued_at", "expires_at"):
            for value in ("invalid", "2026-10-01T00:00:00", "", 42):
                with self.subTest(field=field, value=value):
                    credential = self.credential()
                    credential[field] = value
                    self.assert_invalid(self.walk("2026-10-01T12:00:00Z", credential))

    def test_timezone_normalized(self):
        self.assertTrue(self.walk("2026-10-01T05:30:00+05:30")["valid"])
        self.assert_invalid(self.walk("2026-10-02T05:30:00+05:30"))

    def test_naive_action_time_fails_closed(self):
        self.assert_invalid(self.walk("2026-10-01T12:00:00"))

    def test_acquisition_trace_does_not_apply_current_expiry(self):
        result = self.walk(None)
        self.assertTrue(result["valid"])
        self.assertIsNone(result["chain"][0]["valid_at_action_time"])

    def delegation(self):
        return {"record_id": "mock-delegation", "delegator": "Agent_A", "delegatee": "Agent_B",
                "permission": "CREATE_AGENT", "timestamp": "2026-10-01T01:00:00Z"}

    def test_delegation_after_action_is_invalid(self):
        self.assert_invalid(self.walk("2026-10-01T00:30:00Z", delegations=[self.delegation()]))

    def test_one_invalid_credential_hop_invalidates_chain(self):
        child = self.credential("Agent_B", self.parent)
        child["expires_at"] = "2026-10-01T11:00:00Z"
        checked = {"verified": True, "reason": "Mock issuance proof verified", "transaction_hash": "mock", "block_number": 1}
        with patch.object(tracer, "_verify_credential", return_value=checked):
            result = self.walk("2026-10-01T12:00:00Z", delegations=[self.delegation()],
                               credentials=[self.credential(), child])
        self.assert_invalid(result)
        self.assertTrue(result["chain"][0]["valid_at_action_time"])

    def test_altered_child_credential_fails_proof_before_time_check(self):
        checked = {"verified": False, "reason": "Credential content commitment mismatch", "transaction_hash": None, "block_number": None}
        with patch.object(tracer, "_verify_credential", return_value=checked):
            result = self.walk("2026-10-01T12:00:00Z", delegations=[self.delegation()],
                               credentials=[self.credential(), self.credential("Agent_B", self.parent)])
        self.assertFalse(result["valid"])
        self.assertEqual(result["verdict"], "TAMPERED")

    def test_delegation_malformed_timestamp_fails_closed(self):
        record = deepcopy(self.delegation())
        record["timestamp"] = "invalid"
        self.assert_invalid(self.walk("2026-10-01T12:00:00Z", delegations=[record]))

    def test_changed_child_issuer_cannot_skip_credential_check(self):
        child = self.credential("Agent_B", "0x" + "ff" * 20)
        checked = {"verified": False, "reason": "Credential issuer mismatch", "transaction_hash": None, "block_number": None}
        with patch.object(tracer, "_verify_credential", return_value=checked) as verifier:
            result = self.walk("2026-10-01T12:00:00Z", delegations=[self.delegation()],
                               credentials=[self.credential(), child])
        self.assertFalse(result["valid"])
        self.assertEqual(result["verdict"], "TAMPERED")
        verifier.assert_called_once_with(child, "Agent_B", "CREATE_AGENT", self.parent)

    def test_delegation_expiry_when_present_is_exclusive(self):
        record = self.delegation()
        record["expires_at"] = "2026-10-01T12:00:00Z"
        self.assert_invalid(self.walk("2026-10-01T12:00:00Z", delegations=[record]))

    def test_exact_expired_child_scope_bypass_reproduction(self):
        child = self.credential("Agent_B", self.parent)
        child["expires_at"] = "2026-10-01T11:00:00Z"
        checked = {"verified": True, "reason": "Mock issuance proof verified", "transaction_hash": "mock", "block_number": 1}
        with patch.object(tracer, "_verify_credential", return_value=checked):
            self.assert_invalid(self.walk("2026-10-01T12:00:00Z", delegations=[self.delegation()], credentials=[self.credential(), child]))
            child["allowed_permission_scope"] = ["READ_CATALOG"]
            self.assert_invalid(self.walk("2026-10-01T12:00:00Z", delegations=[self.delegation()], credentials=[self.credential(), child]))

    def test_required_child_missing_fails_closed(self):
        self.assert_invalid(self.walk("2026-10-01T12:00:00Z", delegations=[self.delegation()], credentials=[self.credential()]))

    def test_required_child_discovery_id_altered_fails_closed(self):
        child = self.credential("Agent_B", self.parent)
        child["onchain_id"] = "altered"
        self.assert_invalid(self.walk("2026-10-01T12:00:00Z", delegations=[self.delegation()], credentials=[self.credential(), child]))

    def test_required_child_duplicate_fails_closed(self):
        child = self.credential("Agent_B", self.parent)
        self.assert_invalid(self.walk("2026-10-01T12:00:00Z", delegations=[self.delegation()], credentials=[self.credential(), child, deepcopy(child)]))

    def test_wrong_holder_scope_issuer_and_proof_are_not_filtered_out(self):
        for field, value in (("agent_id", "Agent_X"), ("allowed_permission_scope", ["READ_CATALOG"]),
                             ("issuer", self.root), ("content_hash", "altered")):
            with self.subTest(field=field):
                child = self.credential("Agent_B", self.parent)
                child[field] = value
                with patch.object(tracer, "_verify_credential", return_value={"verified": False, "reason": "Credential proof mismatch"}) as verifier:
                    result = self.walk("2026-10-01T12:00:00Z", delegations=[self.delegation()], credentials=[self.credential(), child])
                self.assertFalse(result["valid"])
                self.assertEqual(result["verdict"], "TAMPERED")
                verifier.assert_called_once_with(child, "Agent_B", "CREATE_AGENT", self.parent)

    def test_child_validity_boundaries_and_timezones(self):
        checked = {"verified": True}
        for issued, expires, valid in (("2026-10-01T12:00:00Z", "2026-10-02T00:00:00Z", True),
                                       ("2026-10-01T12:00:01Z", "2026-10-02T00:00:00Z", False),
                                       ("2026-10-01T00:00:00Z", "2026-10-01T12:00:00Z", False),
                                       ("2026-10-01T17:30:00+05:30", "2026-10-02T00:00:00Z", True),
                                       ("invalid", "2026-10-02T00:00:00Z", False)):
            with self.subTest(issued=issued, expires=expires), patch.object(tracer, "_verify_credential", return_value=checked):
                child = self.credential("Agent_B", self.parent)
                child.update(issued_at=issued, expires_at=expires)
                result = self.walk("2026-10-01T12:00:00Z", delegations=[self.delegation()], credentials=[self.credential(), child])
                self.assertEqual(result["valid"], valid)

    def test_authenticated_legacy_direct_grant_remains_valid(self):
        self.assertTrue(self.walk("2026-10-01T12:00:00Z", delegations=[self.delegation()], legacy=True)["valid"])


class RegistryBindingTests(TestCase):
    def contract(self, credential_id=bytes(32), granted=True, registered=True):
        contract = MagicMock()
        contract.functions.agentAddresses.return_value.call.return_value = "0x" + ("12" if registered else "00") * 20
        contract.functions.delegationGrants.return_value.call.return_value = granted
        contract.functions.scopeCredentials.return_value.call.return_value = credential_id
        return contract

    def binding(self, contract):
        with patch.object(tracer.blockchain, "contract_context", return_value=(None, contract, None, None)):
            return tracer._delegated_credential_binding({"delegator": "Parent", "delegatee": "Child"}, "CREATE_AGENT")

    def test_immutable_registry_id_controls_discovery(self):
        contract = self.contract(bytes.fromhex("ab" * 32))
        self.assertEqual(self.binding(contract)[0], "0x" + "ab" * 32)
        contract.functions.scopeCredentials.assert_called_once_with(tracer.integration.agent_hash("Child"), tracer.integration.permission_hash("CREATE_AGENT"))

    def test_zero_binding_requires_authenticated_grant(self):
        self.assertIsNone(self.binding(self.contract())[0])
        with self.assertRaises(ValueError):
            self.binding(self.contract(granted=False))

    def test_unregistered_identity_cannot_establish_legacy_authority(self):
        with self.assertRaises(ValueError):
            self.binding(self.contract(registered=False))


class AuthenticatedTemporalTests(TestCase):
    """Read-only checks against the runner's isolated valid Hardhat fixture."""

    def context_and_time(self):
        context = deepcopy(tracer._load_context())
        times = [tracer._parse_time(item["issued_at"]) for item in context.credentials]
        times.extend(tracer._parse_time(item["timestamp"]) for item in context.delegations + context.actions)
        when = max(times) + timedelta(seconds=1)
        return context, when

    def walk(self, context, when, agent="Agent_B"):
        return tracer._walk_authority(agent, "CREATE_AGENT", context, time.perf_counter(), when)

    def test_real_verified_child_is_valid(self):
        context, when = self.context_and_time()
        result = self.walk(context, when)
        self.assertTrue(result["valid"], result)

    def test_real_registry_binding_rejects_local_discovery_mutations(self):
        for field, value in (("agent_id", "Agent_X"), ("allowed_permission_scope", ["READ_CATALOG"]),
                             ("issuer", "0x" + "ff" * 20), ("onchain_id", "altered"), ("content_hash", "altered")):
            with self.subTest(field=field):
                context, when = self.context_and_time()
                child = next(item for item in context.credentials if item["agent_id"] == "Agent_B" and item["allowed_permission_scope"] == ["CREATE_AGENT"])
                child[field] = value
                self.assertFalse(self.walk(context, when)["valid"])

    def test_real_required_credential_removed_fails_closed(self):
        context, when = self.context_and_time()
        context.credentials = [item for item in context.credentials if not (item["agent_id"] == "Agent_B" and item["allowed_permission_scope"] == ["CREATE_AGENT"])]
        self.assertFalse(self.walk(context, when)["valid"])

    def test_real_invalid_intermediate_credential_invalidates_chain(self):
        context, when = self.context_and_time()
        child = next(item for item in context.credentials if item["agent_id"] == "Agent_B" and item["allowed_permission_scope"] == ["CREATE_AGENT"])
        child["expires_at"] = when.isoformat()
        self.assertFalse(self.walk(context, when, "Agent_C")["valid"])

    def test_real_invalid_intermediate_delegation_invalidates_chain(self):
        context, when = self.context_and_time()
        delegation = next(item for item in context.delegations if item["delegatee"] == "Agent_B")
        delegation["permission"] = "READ_CATALOG"
        self.assertFalse(self.walk(context, when, "Agent_C")["valid"])
