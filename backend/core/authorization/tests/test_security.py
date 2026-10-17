"""Real signatures and isolated state, including adversarial identity requests."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import multiprocessing
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from eth_account import Account
from backend.core.authorization import agents as a
from backend.core.authorization.authentication import AuthenticationError, RequestVerifier, sign_request
from backend.core.authorization.demo_identity import DemoIdentity
from backend.core.authorization.main import simulate_direct_grant


def replay_worker(path, domain, addresses, envelope, ready, start, queue):
    verifier = RequestVerifier(domain, addresses.__getitem__, Path(path))
    ready.put(True)
    start.wait(30)
    try:
        verifier.authenticate(envelope, "probe", {"value": 1}, "Agent_A")
        queue.put("ACCEPTED")
    except AuthenticationError as exc:
        queue.put(str(exc))


class SignedAuthorityTests(unittest.TestCase):
    def setUp(self):
        from backend.core.authorization.logger import ACTION_LOG
        self.saved_actions = deepcopy(ACTION_LOG)
        self.saved_verifier = a._policy_verifier
        self.saved = deepcopy((a.AGENTS, a.ROOT_AUTHORITY_RECORD, a.DELEGATION_LEDGER))
        a.AGENTS.clear()
        a.AGENTS.update({"Agent_" + n: a.Agent("Agent_" + n, "test") for n in "ABCD"})
        a.ROOT_AUTHORITY_RECORD.clear()
        a.DELEGATION_LEDGER.clear()
        self.identity = DemoIdentity()
        a._policy_verifier = self.identity.verifier

    def tearDown(self):
        from backend.core.authorization.logger import ACTION_LOG
        ACTION_LOG[:] = self.saved_actions
        a.AGENTS.clear(); a.AGENTS.update(self.saved[0])
        a.ROOT_AUTHORITY_RECORD[:] = self.saved[1]
        a.DELEGATION_LEDGER[:] = self.saved[2]
        a._policy_verifier = self.saved_verifier
        self.identity.close()

    def grant(self, target="Agent_A", permission="P", expires_at=None, actor="ROOT_AUTHORIZER"):
        payload = {"agent_id": target, "permission": permission, "expires_at": expires_at}
        return a.grant_root_permission(target, permission, requester=actor, expires_at=expires_at,
                                       **self.identity.credentials(actor, "root_grant", payload))

    def delegate(self, parent="Agent_A", child="Agent_B", permission="P", expires_at=None):
        payload = {"delegator": parent, "delegatee": child, "permission": permission, "expires_at": expires_at}
        return a.delegate_permission(a.AGENTS[parent], a.AGENTS[child], permission, expires_at=expires_at,
                                     **self.identity.credentials(parent, "delegate", payload))

    def revoke(self, target="Agent_B"):
        return a.decommission_agent(target, reason="test", **self.identity.credentials(
            "ROOT_AUTHORIZER", "decommission", {"agent_id": target, "reason": "test"}))

    def chain(self):
        self.assertEqual(self.grant()["result"], "ALLOWED")
        for parent, child in (("Agent_A", "Agent_B"), ("Agent_B", "Agent_C"), ("Agent_C", "Agent_D")):
            self.assertEqual(self.delegate(parent, child)["result"], "ALLOWED")

    def envelope(self, **overrides):
        fields = dict(account=self.identity.accounts["Agent_A"], domain=self.identity.verifier.domain,
                      actor="Agent_A", operation="probe", payload={"value": 1})
        fields.update(overrides)
        return sign_request(**fields)

    def verify(self, envelope, **changes):
        fields = dict(operation="probe", payload={"value": 1}, actor="Agent_A")
        fields.update(changes)
        return self.identity.verifier.authenticate(envelope, **fields)

    def test_unsigned_root_name_is_rejected_exact_original_reproduction(self):
        result = simulate_direct_grant("ROOT_AUTHORIZER", "Agent_D", "P")
        self.assertEqual(result["result"], "BLOCKED")
        self.assertFalse(a.authority_paths("Agent_D", "P"))

    def test_direct_root_function_cannot_bypass_authentication(self):
        with self.assertRaises(AuthenticationError): a.grant_root_permission("Agent_A", "P")

    def test_genuine_root_signed_grant(self):
        self.assertEqual(self.grant()["result"], "ALLOWED")
        self.assertEqual(a.check_permission(a.AGENTS["Agent_A"], "P")["result"], "ALLOWED")

    def test_agent_key_cannot_claim_root_name(self):
        payload = {"agent_id": "Agent_D", "permission": "P", "expires_at": None}
        envelope = sign_request(self.identity.accounts["Agent_D"], self.identity.verifier.domain,
                                "ROOT_AUTHORIZER", "root_grant", payload)
        with self.assertRaises(AuthenticationError):
            a.grant_root_permission("Agent_D", "P", authentication=envelope, verifier=self.identity.verifier)

    def test_authenticated_nonroot_cannot_grant(self):
        self.assertEqual(self.grant(actor="Agent_D")["reason"], "ROOT_AUTHORITY_REQUIRED")

    def test_invalid_signature(self):
        envelope = self.envelope(); envelope["signature"] = "0x" + "00" * 65
        with self.assertRaises(AuthenticationError): self.verify(envelope)

    def test_payload_substitution(self):
        with self.assertRaises(AuthenticationError): self.verify(self.envelope(), payload={"value": 2})

    def test_actor_substitution(self):
        with self.assertRaises(AuthenticationError): self.verify(self.envelope(), actor="Agent_B")

    def test_operation_substitution(self):
        with self.assertRaises(AuthenticationError): self.verify(self.envelope(), operation="root_grant")

    def test_wrong_deployment_domain(self):
        with self.assertRaises(AuthenticationError): self.verify(self.envelope(domain="different-deployment"))

    def test_expired_request(self):
        with self.assertRaises(AuthenticationError): self.verify(self.envelope(now=1))

    def test_future_request(self):
        import time
        with self.assertRaises(AuthenticationError): self.verify(self.envelope(now=int(time.time()) + 60))

    def test_excessive_lifetime(self):
        with self.assertRaises(AuthenticationError): self.verify(self.envelope(ttl=301))

    def test_malformed_nonce(self):
        with self.assertRaises(AuthenticationError): self.verify(self.envelope(nonce="bad"))

    def test_unknown_identity(self):
        envelope = self.envelope(actor="Unknown")
        with self.assertRaises(AuthenticationError): self.verify(envelope, actor="Unknown")

    def test_replay_after_verifier_restart(self):
        envelope = self.envelope(); self.verify(envelope)
        verifier = RequestVerifier(self.identity.verifier.domain, self.identity.verifier.resolve_identity,
                                   self.identity.verifier.path)
        with self.assertRaisesRegex(AuthenticationError, "REPLAYED"):
            verifier.authenticate(envelope, "probe", {"value": 1}, "Agent_A")

    def test_cross_process_replay_exactly_one_acceptance(self):
        ctx = multiprocessing.get_context("spawn")
        ready, queue, start = ctx.Queue(), ctx.Queue(), ctx.Event()
        addresses = {k: v.address for k, v in self.identity.accounts.items()}
        envelope = self.envelope()
        workers = [ctx.Process(target=replay_worker, args=(str(self.identity.verifier.path),
                   self.identity.verifier.domain, addresses, envelope, ready, start, queue)) for _ in range(2)]
        for worker in workers: worker.start()
        try:
            for _ in workers: self.assertTrue(ready.get(timeout=30))
            start.set()
            results = [queue.get(timeout=30) for _ in workers]
            self.assertEqual(sorted(results), ["ACCEPTED", "AUTHENTICATION_REPLAYED"])
            for worker in workers:
                worker.join(30); self.assertEqual(worker.exitcode, 0)
        finally:
            for worker in workers:
                if worker.is_alive(): worker.terminate(); worker.join()
            ready.close(); queue.close()

    def test_corrupt_nonce_store_fails_closed(self):
        self.identity.verifier.path.write_text("not-json")
        with self.assertRaisesRegex(AuthenticationError, "STORE_UNAVAILABLE"): self.verify(self.envelope())

    def test_unsigned_delegation_and_decommission_rejected(self):
        with self.assertRaises(AuthenticationError): a.delegate_permission(a.AGENTS["Agent_A"], a.AGENTS["Agent_B"], "P")
        with self.assertRaises(AuthenticationError): a.decommission_agent("Agent_B")

    def test_missing_permission(self):
        self.assertEqual(a.check_permission(a.AGENTS["Agent_A"], "P")["result"], "DENIED")

    def test_cascade_exact_original_C_and_D_reproduction(self):
        self.chain(); self.revoke()
        for child in ("Agent_C", "Agent_D"):
            self.assertEqual(a.check_permission(a.AGENTS[child], "P")["result"], "DENIED")
            self.assertNotIn("P", a.AGENTS[child].effective_permissions)
            self.assertEqual(a.AGENTS[child].status, "ACTIVE")

    def test_independent_root_path_survives(self):
        self.chain(); self.grant("Agent_D"); self.revoke()
        self.assertEqual(a.check_permission(a.AGENTS["Agent_D"], "P")["result"], "ALLOWED")
        self.assertEqual(a.check_permission(a.AGENTS["Agent_C"], "P")["result"], "DENIED")

    def test_independent_other_parent_survives(self):
        self.grant(); self.grant("Agent_D")
        self.delegate(); self.delegate("Agent_B", "Agent_C"); self.delegate("Agent_D", "Agent_C")
        self.revoke()
        self.assertEqual(a.check_permission(a.AGENTS["Agent_C"], "P")["result"], "ALLOWED")

    def test_repeated_grant_idempotent_and_no_duplicate_delegations(self):
        self.grant(); self.delegate(); self.delegate()
        self.assertEqual(len(a.DELEGATION_LEDGER), 1)
        first = deepcopy(a.ROOT_AUTHORITY_RECORD)
        self.grant(); self.assertEqual(a.ROOT_AUTHORITY_RECORD, first)

    def test_cycle_and_self_delegation_rejected(self):
        self.grant(); self.delegate()
        self.assertEqual(self.delegate("Agent_A", "Agent_A")["reason"], "SELF_DELEGATION")
        self.assertEqual(self.delegate("Agent_B", "Agent_A")["reason"], "CIRCULAR_DELEGATION")

    def expiry_cycle_fixture(self, parent_expires):
        expiry = datetime.now(timezone.utc)+timedelta(seconds=60)
        self.grant("Agent_B", expires_at=expiry.isoformat() if parent_expires else None)
        self.delegate("Agent_B", "Agent_A", expires_at=None if parent_expires else expiry.isoformat())
        self.grant("Agent_A")
        class Clock(datetime):
            @classmethod
            def now(cls, tz=None): return expiry+timedelta(seconds=1)
        with patch.object(a, "datetime", Clock):
            self.assertEqual(self.delegate("Agent_A", "Agent_B")["result"], "ALLOWED")
            self.assertTrue(a.authority_paths("Agent_B", "P"))
            self.assertEqual(len(a.DELEGATION_LEDGER), 2)

    def test_expired_delegation_does_not_create_false_cycle(self):
        self.expiry_cycle_fixture(parent_expires=False)

    def test_expired_parent_does_not_create_false_cycle(self):
        self.expiry_cycle_fixture(parent_expires=True)

    def test_expired_parent_invalidates_child(self):
        self.grant(); self.delegate()
        a.ROOT_AUTHORITY_RECORD[0]["grants"]["P"]["expires_at"] = "2000-01-01T00:00:00Z"
        self.assertFalse(a.authority_paths("Agent_B", "P"))

    def test_not_yet_issued_parent_invalidates_child(self):
        self.grant(); self.delegate()
        a.ROOT_AUTHORITY_RECORD[0]["grants"]["P"]["issued_at"] = "2999-01-01T00:00:00Z"
        self.assertFalse(a.authority_paths("Agent_B", "P"))

    def test_expiry_exclusive_and_issuance_inclusive(self):
        self.grant(expires_at=(datetime.now(timezone.utc)+timedelta(days=1)).isoformat())
        grant = a.ROOT_AUTHORITY_RECORD[0]["grants"]["P"]
        self.assertTrue(a.authority_paths("Agent_A", "P", at_time=grant["issued_at"]))
        self.assertFalse(a.authority_paths("Agent_A", "P", at_time=grant["expires_at"]))

    def test_malformed_grant_time_fails_closed(self):
        self.grant(); a.ROOT_AUTHORITY_RECORD[0]["grants"]["P"]["issued_at"] = "bad"
        self.assertFalse(a.authority_paths("Agent_A", "P"))

    def test_unauthorized_delegation(self):
        self.assertEqual(self.delegate()["result"], "BLOCKED")

    def test_revoked_agent_cannot_redelegate(self):
        self.chain(); self.revoke()
        self.assertEqual(self.delegate("Agent_B", "Agent_D")["result"], "BLOCKED")

    def test_revocation_history_is_preserved(self):
        self.chain(); original = len(a.DELEGATION_LEDGER); self.revoke()
        self.assertEqual(len(a.DELEGATION_LEDGER), original)
        self.assertTrue(all(g["status"] == "REVOKED" and g.get("revoked_at") for g in a.DELEGATION_LEDGER))

    def test_new_root_grant_does_not_resurrect_old_children(self):
        self.grant(); self.delegate()
        old = a.ROOT_AUTHORITY_RECORD[0]["grants"]["P"]
        old.update(status="REVOKED")
        # Publish this isolated controlled revocation fixture. Production
        # mutations reload durable state rather than trusting edited memory.
        import json
        from backend.core.authorization.state import _path
        path = _path(self.identity.verifier)
        state = json.loads(path.read_text())
        state["root_grants"] = a.ROOT_AUTHORITY_RECORD
        path.write_text(json.dumps(state))
        self.grant()
        self.assertFalse(a.authority_paths("Agent_B", "P"))
        history = a.ROOT_AUTHORITY_RECORD[0]["grant_history"]
        self.assertEqual(history[0]["record_id"], old["record_id"])
        self.assertEqual(history[0]["status"], "REVOKED")

    def test_child_expiry_cannot_extend_selected_parent(self):
        expiry = datetime.now(timezone.utc) + timedelta(days=1)
        self.grant(expires_at=expiry.isoformat())
        result = self.delegate(expires_at=(expiry + timedelta(days=1)).isoformat())
        self.assertEqual(result["reason"], "CHILD_EXPIRY_EXCEEDS_PARENT")
        self.assertFalse(a.authority_paths("Agent_B", "P"))

    def test_root_idempotence_does_not_silently_ignore_changed_expiry(self):
        self.grant()
        before = deepcopy(a.ROOT_AUTHORITY_RECORD)
        result = self.grant(expires_at=(datetime.now(timezone.utc)+timedelta(days=1)).isoformat())
        self.assertEqual(result["reason"], "EXISTING_GRANT_DIFFERS")
        self.assertEqual(result["result"], "BLOCKED")
        self.assertEqual(a.ROOT_AUTHORITY_RECORD, before)

    def test_delegation_idempotence_does_not_silently_ignore_changed_expiry(self):
        self.grant(); self.delegate()
        before = deepcopy(a.DELEGATION_LEDGER)
        result = self.delegate(expires_at=(datetime.now(timezone.utc)+timedelta(days=1)).isoformat())
        self.assertEqual(result["reason"], "EXISTING_GRANT_DIFFERS")
        self.assertEqual(result["result"], "BLOCKED")
        self.assertEqual(a.DELEGATION_LEDGER, before)

    def test_decommission_retains_revoked_signed_root_grant(self):
        self.grant()
        grant = deepcopy(a.ROOT_AUTHORITY_RECORD[0]["grants"]["P"])
        self.revoke("Agent_A")
        stored = a.ROOT_AUTHORITY_RECORD[0]["grants"]["P"]
        self.assertEqual(stored["record_id"], grant["record_id"])
        self.assertEqual(stored["authentication"], grant["authentication"])
        self.assertEqual(stored["status"], "REVOKED")
        self.assertTrue(stored["revoked_at"])

    def test_corrupted_existing_delegation_does_not_shadow_signed_reissue(self):
        import json
        from backend.core.authorization.state import _path
        self.grant(); self.delegate()
        old_id = a.DELEGATION_LEDGER[0]["record_id"]
        path = _path(self.identity.verifier)
        state = json.loads(path.read_text())
        state["delegations"][0]["expires_at"] = "2999-01-01T00:00:00Z"
        path.write_text(json.dumps(state))
        self.assertEqual(self.delegate()["result"], "ALLOWED")
        self.assertNotEqual(a.DELEGATION_LEDGER[-1]["record_id"], old_id)
        self.assertTrue(a.authority_paths("Agent_B", "P"))

    def test_cloned_agent_metadata_cannot_change_registered_holder(self):
        self.grant()
        clone = a.Agent("Agent_A", "forged", direct_permissions=["P", "ADMIN"])
        payload = {"delegator": "Agent_A", "delegatee": "Agent_B", "permission": "P", "expires_at": None}
        result = a.delegate_permission(clone, a.AGENTS["Agent_B"], "P",
                                      **self.identity.credentials("Agent_A", "delegate", payload))
        self.assertEqual(result["result"], "BLOCKED")


if __name__ == "__main__": unittest.main()
