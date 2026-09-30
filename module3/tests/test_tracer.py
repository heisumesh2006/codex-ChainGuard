"""Live-chain Module 3 tests and isolated adversarial fixtures."""

from contextlib import ExitStack
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch
from uuid import uuid4

from web3 import Web3

from module2 import chain as blockchain, integration
from module2.anchor import anchor_delegation, get_proof, verify_proof
from module3 import tracer


class ExistingChainTraceTests(TestCase):
    def test_agent_b_reaches_verified_root(self) -> None:
        result = tracer.trace_agent_authority("Agent_B", "CREATE_AGENT")
        self.assertEqual(result["verdict"], "VALID_CHAIN", result)
        self.assertEqual([hop["to"] for hop in result["chain"]], ["Agent_A", "Agent_B"])
        self.assertTrue(all(hop["anchored"] and hop["proof_verified"] for hop in result["chain"]))
        self.assertTrue(result["chain"][0]["root_grant_proof_verified"])

    def test_delegation_lookup_does_not_require_source_uuid_index(self) -> None:
        state = deepcopy(blockchain.load_state())
        state["index"] = {}
        with patch.object(blockchain, "load_state", return_value=state):
            result = tracer.trace_agent_authority("Agent_B", "CREATE_AGENT")
        self.assertEqual(result["verdict"], "VALID_CHAIN", result)
        delegation = result["chain"][1]
        source = next(item["source"] for item in state["records"].values() if item["kind"] == "delegation" and item["source"]["delegatee"] == "Agent_B")
        self.assertEqual(delegation["record_id"], integration.blockchain_record_id("delegation", source))
        self.assertEqual(delegation["source_record_id"], source["record_id"])
        self.assertTrue(delegation["proof_verified"])
        proof = get_proof(delegation["record_id"])
        digest = integration.content_hash(source)
        onchain_id = integration.onchain_record_id(blockchain.KIND_CODES["delegation"], digest)
        self.assertEqual(proof["onchain_record_id"], "0x" + onchain_id.hex())
        self.assertTrue(verify_proof(source, proof))
        _, contract, _, _ = blockchain.contract_context()
        self.assertEqual(contract.functions.commitments(onchain_id).call()[0], bytes.fromhex(digest))

    def test_agent_c_historical_chain(self) -> None:
        result = tracer.trace_agent_authority("Agent_C", "CREATE_AGENT")
        self.assertEqual(result["verdict"], "VALID_CHAIN", result)
        self.assertEqual([hop["to"] for hop in result["chain"]], ["Agent_A", "Agent_B", "Agent_C"])
        self.assertTrue(all(hop["proof_verified"] for hop in result["chain"]))

    def test_real_attack_actions(self) -> None:
        actions = tracer._load_context().actions
        expected = {
            "SELF_ESCALATION_ATTEMPT": "UNAUTHORIZED_ROOT",
            "UNAUTHORIZED_DELEGATION_ATTEMPT": "BROKEN_CHAIN",
            "POST_DECOMMISSION_ACTIVITY": "AUTHORITY_REVOKED_AT_TIME_OF_ACTION",
        }
        for action_name, verdict in expected.items():
            with self.subTest(action=action_name):
                action = next(item for item in actions if item["action"] == action_name)
                result = tracer.trace_action(action)
                self.assertEqual(result["verdict"], verdict, result)
                self.assertFalse(result["valid"])
                if action_name == "POST_DECOMMISSION_ACTIVITY":
                    self.assertEqual(len(result["chain"]), 3)
                    self.assertFalse(result["chain"][-1]["valid_at_action_time"])
                    self.assertTrue(all(hop["valid_at_action_time"] for hop in result["chain"][:-1]))
                    self.assertTrue(result["revocation_evidence"]["proof_verified"])
                    self.assertGreater(
                        datetime.fromisoformat(action["timestamp"]),
                        datetime.fromisoformat(result["revocation_evidence"]["revoked_at"]),
                    )

    def test_missing_unanchored_delegation(self) -> None:
        context = deepcopy(tracer._load_context())
        context.delegations.append({
            "record_id": f"delegation:{uuid4()}",
            "delegator": "Agent_A",
            "delegatee": "Agent_Z",
            "permission": "CREATE_AGENT",
            "authority_source": "ROOT_AUTHORIZER",
            "status": "ACTIVE",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        with patch.object(tracer, "_load_context", return_value=context):
            result = tracer.trace_agent_authority("Agent_Z", "CREATE_AGENT")
        self.assertEqual(result["verdict"], "BROKEN_CHAIN", result)
        self.assertFalse(result["chain"][-1]["anchored"])

    def test_tampered_delegation(self) -> None:
        context = deepcopy(tracer._load_context())
        record = next(item for item in context.delegations if item["delegatee"] == "Agent_B")
        record["authority_source"] = "Agent_D"
        with patch.object(tracer, "_load_context", return_value=context):
            result = tracer.trace_agent_authority("Agent_B", "CREATE_AGENT")
        self.assertEqual(result["verdict"], "TAMPERED", result)
        self.assertTrue(result["chain"][-1]["anchored"])
        self.assertFalse(result["chain"][-1]["proof_verified"])

    def test_circular_delegation_terminates(self) -> None:
        timestamp = datetime.now(timezone.utc).isoformat()
        context = tracer.TraceContext(
            delegations=[
                {"record_id": "fixture:xy", "delegator": "Agent_X", "delegatee": "Agent_Y", "permission": "CREATE_AGENT", "timestamp": timestamp},
                {"record_id": "fixture:yx", "delegator": "Agent_Y", "delegatee": "Agent_X", "permission": "CREATE_AGENT", "timestamp": timestamp},
            ],
            actions=[], revocations=[], credentials=[],
        )
        with patch.object(tracer, "_load_context", return_value=context):
            result = tracer.trace_agent_authority("Agent_X", "CREATE_AGENT")
        self.assertEqual(result["verdict"], "CIRCULAR_CHAIN", result)
        self.assertLess(result["trace_latency_ms"], 1000)


class DeepChainTraceTests(TestCase):
    def test_ten_real_anchored_delegations(self) -> None:
        suffix = uuid4().hex
        folder = Path(__file__).resolve().parent.parent.parent / "module2"
        paths = {
            "STATE_PATH": folder / f".trace-state-{suffix}.json",
            "DEPLOYMENT_PATH": folder / f".trace-deployment-{suffix}.json",
            "CREDENTIALS_PATH": folder / f".trace-credentials-{suffix}.json",
        }
        try:
            with ExitStack() as stack:
                for name, path in paths.items():
                    stack.enter_context(patch.object(blockchain, name, path))
                blockchain.deploy_registry()
                web3, contract, root, _ = blockchain.contract_context()
                names = ["ROOT_AUTHORIZER"] + [f"Agent_X{i}" for i in range(11)]
                addresses = dict(zip(names, web3.eth.accounts[:len(names)]))
                for name, address in addresses.items():
                    receipt = web3.eth.wait_for_transaction_receipt(
                        contract.functions.registerAgent(integration.agent_hash(name), address).transact({"from": root})
                    )
                    self.assertEqual(receipt.status, 1)

                def issue_scope(agent_name: str, issuer_name: str, can_delegate: bool) -> dict:
                    issued = datetime.now(timezone.utc).replace(microsecond=0)
                    expires = issued + timedelta(days=365)
                    payload = {
                        "agent_id": agent_name,
                        "agent_hash": "0x" + integration.agent_hash(agent_name).hex(),
                        "agent_address": addresses[agent_name],
                        "issuer": addresses[issuer_name],
                        "allowed_permission_scope": ["CREATE_AGENT"],
                        "delegation_scope": ["CREATE_AGENT"] if can_delegate else [],
                        "issued_at": issued.isoformat(),
                        "expires_at": expires.isoformat(),
                        "status_at_issuance": "ACTIVE",
                    }
                    digest = integration.content_hash(payload)
                    onchain_id = integration.onchain_record_id(blockchain.KIND_CODES["credential"], digest)
                    receipt = web3.eth.wait_for_transaction_receipt(
                        contract.functions.issueCredential(
                            onchain_id,
                            integration.agent_hash(agent_name),
                            addresses[agent_name], addresses[issuer_name],
                            integration.permission_hash("CREATE_AGENT"),
                            integration.permission_hash("CREATE_AGENT") if can_delegate else bytes(32),
                            integration.timestamp_seconds(payload["issued_at"]),
                            integration.timestamp_seconds(payload["expires_at"]),
                            bytes.fromhex(digest),
                        ).transact({"from": root})
                    )
                    self.assertEqual(receipt.status, 1)
                    return {
                        **payload,
                        "credential_id": f"credential:{digest}",
                        "onchain_id": "0x" + onchain_id.hex(),
                        "content_hash": digest,
                        "current_status": "ACTIVE",
                        "transaction_hash": Web3.to_hex(receipt.transactionHash),
                    }

                root_credential = issue_scope("Agent_X0", "ROOT_AUTHORIZER", True)
                state = blockchain.load_state()
                state["credentials"][root_credential["credential_id"]] = root_credential
                blockchain.save_state(state)

                for index in range(10):
                    delegator = f"Agent_X{index}"
                    delegatee = f"Agent_X{index + 1}"
                    record = {
                        "record_id": f"delegation:{uuid4()}",
                        "delegator": delegator,
                        "delegatee": delegatee,
                        "permission": "CREATE_AGENT",
                        "authority_source": "ROOT_AUTHORIZER",
                        "status": "ACTIVE",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                    anchor_delegation(record)
                    if index < 9:
                        issue_scope(delegatee, delegator, True)

                result = tracer.trace_agent_authority("Agent_X10", "CREATE_AGENT")
                self.assertEqual(result["verdict"], "VALID_CHAIN", result)
                self.assertEqual(len(result["chain"]), 11)
                self.assertTrue(all(hop["proof_verified"] for hop in result["chain"]))
                self.assertGreater(result["trace_latency_ms"], 0)
        finally:
            for path in paths.values():
                path.unlink(missing_ok=True)
                path.with_suffix(path.suffix + ".tmp").unlink(missing_ok=True)
