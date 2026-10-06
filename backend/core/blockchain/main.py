"""Live EVM deployment, Module 1 replay, and blockchain proof demonstration."""

from contextlib import redirect_stdout
from copy import deepcopy
from datetime import datetime
import io
from . import chain, integration
from .anchor import (
    anchor_action_hash, anchor_delegation, anchor_revocation, get_proof, verify_proof,
)

from backend.core.authorization.agents import DELEGATION_LEDGER, ROOT_AUTHORITY_RECORD
from backend.core.authorization.logger import get_action_log
from backend.core.authorization.main import run_demo


def latency_ms(created_at: str, confirmed_at: str) -> float:
    return (datetime.fromisoformat(confirmed_at) - datetime.fromisoformat(created_at)).total_seconds() * 1000


def run_blockchain_demo() -> None:
    # Module 1 is imported without schema changes and run exactly once.
    with redirect_stdout(io.StringIO()) as module1_output:
        run_demo()
    assert "Detection Rate: 100.00%" in module1_output.getvalue()
    assert "MODULE 1 COMPLETED SUCCESSFULLY" in module1_output.getvalue()
    actions = get_action_log()
    delegations = deepcopy(DELEGATION_LEDGER)
    revocations = [action for action in actions if action["action"] == "AGENT_DECOMMISSIONED"]
    assert len(delegations) == 2 and len(revocations) == 1 and len(actions) == 11

    deployment = chain.deploy_registry()
    web3, contract, root, _ = chain.contract_context()
    network_name = "Hardhat Local" if deployment["chain_id"] == 31337 else "Ethereum Sepolia"
    print(f"{network_name} connected: chain_id={deployment['chain_id']}")
    print(f"AgentTrustRegistry deployed: {deployment['contract_address']}")

    identities = chain.register_identities()
    print("=== REGISTERED PUBLIC ADDRESSES ===")
    for agent_id, address in identities.items():
        assert contract.functions.agentAddresses(integration.agent_hash(agent_id)).call() == address
        print(f"{agent_id}: {address}")

    # Module 1's root record retains initial direct grants, including Agent_C's
    # pre-decommission PROCESS_PAYMENT credential. Delegated credentials follow
    # each on-chain grant so issuer provenance is enforceable by the contract.
    print("=== SCOPE-BOUND CREDENTIALS ===")
    for root_record in ROOT_AUTHORITY_RECORD:
        agent_id = root_record["granted_to"]
        for permission in root_record["permissions"]:
            credential = chain.issue_credential(
                agent_id, permission, "ROOT_AUTHORIZER",
                can_delegate=(agent_id == "Agent_A" and permission == "CREATE_AGENT"),
            )
            print(f"{agent_id} / {permission}: {credential['credential_id']}")

    # An agent address cannot call an administrative function, even though
    # Hardhat exposes it as an unlocked transaction sender.
    try:
        contract.functions.registerAgent(
            integration.agent_hash("Unauthorized"), identities["Agent_D"]
        ).call({"from": identities["Agent_D"]})
        raise AssertionError("Unauthorized administrative caller was accepted")
    except Exception as exc:
        if isinstance(exc, AssertionError):
            raise
    print("Unauthorized administrative caller: REJECTED")

    latencies = []
    print("=== ON-CHAIN DELEGATIONS ===")
    for delegation in delegations:
        proof = anchor_delegation(delegation)
        latencies.append(latency_ms(delegation["timestamp"], proof["timestamp"]))
        print(
            f"{delegation['delegator']} -> {delegation['delegatee']}: "
            f"content_hash={proof['content_hash']} tx={proof['transaction_hash']} "
            f"block={proof['block_number']}"
        )
        recipient = delegation["delegatee"]
        delegated_credential = chain.issue_credential(
            recipient, delegation["permission"], delegation["delegator"],
            can_delegate=(recipient == "Agent_B"),
        )
        print(f"{recipient} delegated scope: {delegated_credential['credential_id']}")

    repeated = anchor_delegation(delegations[0])
    assert repeated["transaction_hash"] == get_proof(delegations[0]["record_id"])["transaction_hash"]
    print("Duplicate delegation anchor: EXISTING TRANSACTION RETURNED")

    print("=== ON-CHAIN REVOCATIONS ===")
    for revocation in revocations:
        proof = anchor_revocation(revocation)
        latencies.append(latency_ms(revocation["timestamp"], proof["timestamp"]))
        print(
            f"{revocation['decommissioned_agent']}: content_hash={proof['content_hash']} "
            f"tx={proof['transaction_hash']} block={proof['block_number']}"
        )
    assert contract.functions.agentRevoked(integration.agent_hash("Agent_C")).call()
    state = chain.load_state()
    for credential in state["credentials"].values():
        if credential["agent_id"] == "Agent_C":
            assert credential["current_status"] == "REVOKED"
            assert not contract.functions.credentials(bytes.fromhex(credential["onchain_id"][2:])).call()[7]

    print("=== ACTION HASH COMMITMENTS ===")
    for action in actions:
        proof = anchor_action_hash(action)
        latencies.append(latency_ms(action["timestamp"], proof["timestamp"]))
    print(f"Action hashes committed on-chain: {len(actions)}")

    selected = delegations[1]
    proof = get_proof(selected["record_id"])
    assert all(key in proof for key in (
        "record_id", "content_hash", "transaction_hash", "block_number", "contract_address", "chain_id"
    ))
    valid = verify_proof(selected, proof)
    print(f"Original record verification: {'PASS' if valid else 'FAIL'}")
    assert valid
    tampered = deepcopy(selected)
    tampered["permission"] = "PROCESS_PAYMENT"
    tamper_valid = verify_proof(tampered, proof)
    print(f"Tampered record verification: {'PASS' if tamper_valid else 'FAIL'}")
    assert not tamper_valid

    state = chain.load_state()
    assert len(state["records"]) == len(delegations) + len(revocations) + len(actions)
    assert not state["pending"] and not state["failed"]
    assert len(state["credentials"]) == 7
    print(f"Total anchoring latency: {sum(latencies):.3f} ms")
    print("=== MODULE 2 COMPLETED SUCCESSFULLY ===")


if __name__ == "__main__":
    run_blockchain_demo()
