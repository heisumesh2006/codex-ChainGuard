"""Live Hardhat backend checks, isolated from the demo's local index."""

from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch
from uuid import uuid4

from module2 import chain
from module2.anchor import anchor_action_hash, get_proof, verify_proof


class EthereumBackendTests(TestCase):
    def test_failure_retry_idempotence_and_independent_verifier(self) -> None:
        suffix = uuid4().hex
        folder = Path(__file__).resolve().parent.parent
        paths = {
            "STATE_PATH": folder / f".test-state-{suffix}.json",
            "DEPLOYMENT_PATH": folder / f".test-deployment-{suffix}.json",
            "CREDENTIALS_PATH": folder / f".test-credentials-{suffix}.json",
        }
        try:
            with ExitStack() as stack:
                for name, path in paths.items():
                    stack.enter_context(patch.object(chain, name, path))
                chain.deploy_registry()
                action = {
                    "record_id": f"action:{suffix}",
                    "actor": "Agent_D",
                    "action": "SELF_ESCALATION_ATTEMPT",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "claimed_authority": "Agent_D",
                    "result": "BLOCKED",
                    "reason": "ROOT_AUTHORITY_REQUIRED",
                }
                with patch.object(chain, "contract_context", side_effect=ConnectionError("simulated outage")):
                    with self.assertRaises(ConnectionError):
                        anchor_action_hash(action)
                state = chain.load_state()
                self.assertEqual(len(state["failed"]), 1)
                self.assertFalse(state["pending"])
                self.assertTrue(next(iter(state["failed"].values()))["retry"])

                first = anchor_action_hash(action)
                second = anchor_action_hash(action)
                self.assertEqual(first["transaction_hash"], second["transaction_hash"])
                self.assertFalse(chain.load_state()["failed"])
                proof = get_proof(action["record_id"])
                with patch.object(chain, "load_state", side_effect=AssertionError("local index accessed")):
                    self.assertTrue(verify_proof(action, proof))
                changed = dict(action, reason="tampered")
                self.assertFalse(verify_proof(changed, proof))
        finally:
            for path in paths.values():
                path.unlink(missing_ok=True)
                path.with_suffix(path.suffix + ".tmp").unlink(missing_ok=True)
