"""Full-agent revocation and public proofs from detailed Ethereum evidence.

The new registry exposes Module 1's original ISO timestamp and readable scopes
directly on-chain. Optional source JSON can additionally be checked against the
content commitment with Module 2's full-record verifier.
"""

from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import time
from typing import TypedDict
from unittest.mock import patch

from web3 import Web3

from backend.core.blockchain import chain, integration
from backend.core.blockchain.anchor import anchor_revocation, get_proof, verify_proof


ZERO_ADDRESS = Web3.to_checksum_address("0x" + "0" * 40)
DATA_DIR = Path(__file__).resolve().parent / "data"
BUNDLE_DEPLOYMENT_PATH = DATA_DIR / "deployment.json"
BUNDLE_STATE_PATH = DATA_DIR / "ethereum_state.json"
BUNDLE_CREDENTIALS_PATH = DATA_DIR / "credentials.json"


@contextmanager
def _bundle_context():
    """Point Module 2's unchanged anchor/proof APIs at the Module 5 registry."""
    with ExitStack() as stack:
        for name, path in (
            ("DEPLOYMENT_PATH", BUNDLE_DEPLOYMENT_PATH),
            ("STATE_PATH", BUNDLE_STATE_PATH),
            ("CREDENTIALS_PATH", BUNDLE_CREDENTIALS_PATH),
        ):
            stack.enter_context(patch.object(chain, name, path))
        yield


class RevocationRecord(TypedDict):
    agent_id: str
    status: str
    revoked_at: str
    revoked_by: str
    revoked_permissions: list[dict]
    reason: str | None
    record_id: str
    content_hash: str
    transaction_hash: str
    block_number: int
    contract_address: str
    chain_id: int
    proof_verified: bool


class RevocationAnchoringError(RuntimeError):
    def __init__(self, cause: Exception, blockchain_anchored=False):
        self.code = "REVOCATION_PROOF_FAILED" if blockchain_anchored else "REVOCATION_ANCHORING_FAILED"
        super().__init__(f"{self.code}: local decommission succeeded but Ethereum anchoring/proof failed: {cause}")
        self.local_revocation = True
        self.blockchain_anchored = blockchain_anchored
        self.revocation_complete = False


def _registry():
    """Connect from RPC/deployment/ABI only; no unlocked account is required."""
    deployment = json.loads(BUNDLE_DEPLOYMENT_PATH.read_text(encoding="utf-8"))
    web3 = chain.connect(deployment.get("rpc_url") or chain.RPC_URL)
    if web3.eth.chain_id != deployment["chain_id"]:
        raise RuntimeError("Configured chain ID differs from Ethereum")
    address = Web3.to_checksum_address(deployment["contract_address"])
    if not web3.eth.get_code(address):
        raise RuntimeError("AgentTrustRegistry is absent at the configured address")
    contract = web3.eth.contract(address=address, abi=chain.artifact()["abi"])
    return web3, contract, deployment


def _revocation_events(web3, contract, agent_id, *, from_block=0):
    # The contract exposes the confirmation timestamp. Locate its block with
    # read-only block queries so public RPCs with narrow eth_getLogs limits can
    # verify the event without scanning from genesis.
    agent_key = integration.agent_hash(agent_id)
    confirmed_at = contract.functions.getRevocationDetails(agent_key).call()[5]
    low, high = from_block, web3.eth.block_number
    while low < high:
        middle = (low + high) // 2
        if web3.eth.get_block(middle).timestamp < confirmed_at:
            low = middle + 1
        else:
            high = middle
    if web3.eth.get_block(low).timestamp != confirmed_at:
        return []
    topic = Web3.keccak(text=chain.EVENT_SIGNATURES["revocation"])
    logs = web3.eth.get_logs({
        "fromBlock": low, "toBlock": low, "address": contract.address,
        "topics": [topic, None, agent_key],
    })
    event = contract.events.RevocationAnchored()
    return [event.process_log(log) for log in logs]


def get_revocation_status(agent_id) -> dict:
    """Public status from current Ethereum state, independent of Module 1/state indexes."""
    started = time.perf_counter()
    web3, contract, deployment = _registry()
    agent_key = integration.agent_hash(agent_id)
    registered_address = contract.functions.agentAddresses(agent_key).call()
    checked_block = web3.eth.block_number
    base = {
        "agent_id": agent_id, "registered_address": registered_address if registered_address != ZERO_ADDRESS else None,
        "checked_block_number": checked_block, "contract_address": contract.address,
        "chain_id": web3.eth.chain_id,
    }
    if registered_address == ZERO_ADDRESS:
        return {**base, "agent_found": False, "status": "AGENT_NOT_FOUND", "is_revoked": False,
                "revoked_at": None, "revoked_by": None, "revoked_permissions": None,
                "chain_proof": None, "lookup_latency_ms": (time.perf_counter() - started) * 1000}
    revoked = contract.functions.agentRevoked(agent_key).call()
    if not revoked:
        return {**base, "agent_found": True, "status": "ACTIVE", "is_revoked": False,
                "revoked_at": None, "revoked_by": None, "revoked_permissions": None,
                "chain_proof": {"proof_type": "CURRENT_CONTRACT_STATE", "checked_block_number": checked_block,
                                "contract_address": contract.address, "chain_id": web3.eth.chain_id},
                "lookup_latency_ms": (time.perf_counter() - started) * 1000}

    events = _revocation_events(web3, contract, agent_id, from_block=deployment.get("block_number", 0))
    if len(events) != 1:
        raise RuntimeError(f"Revoked agent {agent_id} has {len(events)} RevocationAnchored events; expected one")
    event = events[0]
    receipt = web3.eth.get_transaction_receipt(event["transactionHash"])
    block = web3.eth.get_block(receipt.blockNumber)
    transaction = web3.eth.get_transaction(receipt.transactionHash)
    digest = bytes(event["args"]["contentHash"]).hex()
    details = contract.functions.getRevocationDetails(agent_key).call()
    revoked_at, revoked_by, permissions, stored_hash, stored_id, confirmed_at = details
    if not revoked_at or stored_hash != bytes.fromhex(digest) or stored_id != event["args"]["recordId"]:
        raise RuntimeError("Public revocation details disagree with the commitment")
    proof = {
        "proof_type": "CHAIN_STATUS", "kind": "revocation", "agent_id": agent_id,
        "record_id": f"revocation:{digest}",
        "onchain_record_id": "0x" + bytes(event["args"]["recordId"]).hex(),
        "content_hash": digest, "transaction_hash": Web3.to_hex(receipt.transactionHash),
        "block_number": receipt.blockNumber, "block_hash": Web3.to_hex(block.hash),
        "contract_address": contract.address, "chain_id": web3.eth.chain_id,
        "rpc_url": deployment.get("rpc_url", ""), "issuer_address": transaction["from"],
        "anchored_at": datetime.fromtimestamp(block.timestamp, timezone.utc).isoformat(),
        "revoked_at": revoked_at, "revoked_by": revoked_by,
        "revoked_permissions": list(permissions), "confirmed_at": int(confirmed_at),
    }
    if not verify_revocation_proof(agent_id, proof):
        raise RuntimeError("Ethereum revocation status proof failed")
    return {**base, "agent_found": True, "status": "REVOKED", "is_revoked": True,
            "revoked_at": revoked_at, "revoked_by": revoked_by,
            "revoked_permissions": list(permissions), "chain_proof": proof, "chain_verified": True,
            "proof_verified": True,
            "lookup_latency_ms": (time.perf_counter() - started) * 1000}


def verify_revocation_proof(agent_id, proof) -> bool:
    """Verify chain status; if source JSON is supplied, also use Module 2 content proof."""
    try:
        if not isinstance(proof, dict) or proof.get("agent_id") != agent_id:
            return False
        web3, contract, deployment = _registry()
        if proof["contract_address"] != contract.address or proof["chain_id"] != web3.eth.chain_id:
            return False
        if proof.get("rpc_url", "") != deployment.get("rpc_url", ""):
            return False
        agent_key = integration.agent_hash(agent_id)
        if contract.functions.agentAddresses(agent_key).call() == ZERO_ADDRESS:
            return False
        if not contract.functions.agentRevoked(agent_key).call():
            return False
        details = contract.functions.getRevocationDetails(agent_key).call()
        if (proof["revoked_at"] != details[0] or proof["revoked_by"] != details[1]
                or proof["revoked_permissions"] != list(details[2])
                or proof["confirmed_at"] != details[5]):
            return False
        parsed_time = datetime.fromisoformat(proof["revoked_at"])
        if parsed_time.tzinfo is None:
            return False
        if proof["revoked_by"] != "ROOT_AUTHORIZER":
            return False
        digest = proof["content_hash"]
        expected_id = integration.onchain_record_id(chain.KIND_CODES["revocation"], digest)
        if proof["record_id"] != f"revocation:{digest}" or proof["onchain_record_id"] != "0x" + expected_id.hex():
            return False
        commitment = contract.functions.commitments(expected_id).call()
        if commitment[0] != bytes.fromhex(digest) or commitment[1] != chain.KIND_CODES["revocation"]:
            return False
        if details[3] != bytes.fromhex(digest) or details[4] != expected_id:
            return False
        receipt = web3.eth.get_transaction_receipt(proof["transaction_hash"])
        if receipt.status != 1 or receipt.blockNumber != proof["block_number"] or receipt.to != contract.address:
            return False
        block = web3.eth.get_block(receipt.blockNumber)
        if Web3.to_hex(block.hash) != proof["block_hash"]:
            return False
        if datetime.fromtimestamp(block.timestamp, timezone.utc).isoformat() != proof["anchored_at"]:
            return False
        if block.timestamp != proof["confirmed_at"]:
            return False
        transaction = web3.eth.get_transaction(receipt.transactionHash)
        root = contract.functions.rootAuthorizer().call()
        if transaction["from"] != root or transaction["from"] != proof["issuer_address"]:
            return False
        if Web3.to_hex(receipt.transactionHash) != proof["transaction_hash"]:
            return False
        events = _revocation_events(web3, contract, agent_id, from_block=deployment.get("block_number", 0))
        if len(events) != 1:
            return False
        event = events[0]
        if (event["transactionHash"] != receipt.transactionHash
                or event["args"]["recordId"] != expected_id
                or event["args"]["agentHash"] != agent_key
                or event["args"]["contentHash"] != bytes.fromhex(digest)):
            return False
        source = proof.get("source_record")
        if source is not None:
            if source.get("decommissioned_agent") != agent_id:
                return False
            if (source.get("decommissioned_at") != proof["revoked_at"]
                    or source.get("actor") != proof["revoked_by"]
                    or [item["permission"] for item in source.get("revoked_permissions", [])] != proof["revoked_permissions"]):
                return False
            module2_proof = {**proof, "kind": "revocation", "source_record_id": proof.get("source_record_id")}
            if not verify_proof(source, module2_proof):
                return False
        return True
    except Exception:
        return False


def _verified_source(agent_id, chain_proof):
    """Optional readable record from Module 2; never used to decide public status."""
    with _bundle_context():
        state = chain.load_state()
    entry = state["records"].get(chain_proof["record_id"])
    if not entry or entry["kind"] != "revocation":
        raise RuntimeError("Verified chain status has no readable off-chain revocation record")
    source = entry["source"]
    with _bundle_context():
        module2_proof = get_proof(chain_proof["record_id"])
    if source.get("decommissioned_agent") != agent_id or not verify_proof(source, module2_proof):
        raise RuntimeError("Readable revocation record failed Module 2 verification")
    for field in ("content_hash", "transaction_hash", "block_number", "contract_address", "chain_id"):
        if module2_proof[field] != chain_proof[field]:
            raise RuntimeError(f"Readable revocation record disagrees with chain: {field}")
    return source, module2_proof


def _record_from_status(agent_id, status):
    source, proof = _verified_source(agent_id, status["chain_proof"])
    enriched = {**status["chain_proof"], "source_record": source,
                "source_record_id": source["record_id"]}
    if not verify_revocation_proof(agent_id, enriched):
        raise RuntimeError("Full-content revocation proof failed")
    return RevocationRecord(
        agent_id=agent_id, status="REVOKED", revoked_at=source["decommissioned_at"],
        revoked_by=source["actor"], revoked_permissions=source["revoked_permissions"],
        reason=source.get("reason"), record_id=proof["record_id"],
        content_hash=proof["content_hash"], transaction_hash=proof["transaction_hash"],
        block_number=proof["block_number"], contract_address=proof["contract_address"],
        chain_id=proof["chain_id"], proof_verified=True,
    )


def _validate_full_request(requested, current_permissions):
    if requested is None or requested == "ALL":
        return
    if isinstance(requested, (list, tuple, set)) and set(requested) == set(current_permissions):
        return
    raise ValueError("PARTIAL_REVOCATION_NOT_SUPPORTED")


def revoke(agent_id, permissions_to_revoke, revoked_by, reason) -> RevocationRecord:
    """Fully decommission locally and anchor before declaring success.

    Selective revocation is future work. A prior local-only failure is retried
    from its existing decommission action rather than decommissioning twice.
    """
    from backend.core.authorization import agents as module1_agents
    from backend.core.authorization.logger import get_action_log

    agent = module1_agents.AGENTS.get(agent_id)
    if agent is None:
        raise ValueError("AGENT_NOT_FOUND")
    if revoked_by != module1_agents.ROOT_AUTHORIZER:
        raise ValueError("ROOT_AUTHORITY_REQUIRED")
    status = get_revocation_status(agent_id)
    if not status["agent_found"]:
        raise ValueError("AGENT_NOT_REGISTERED_ON_CHAIN")
    if status["is_revoked"]:
        existing = _record_from_status(agent_id, status)
        _validate_full_request(permissions_to_revoke, [item["permission"] for item in existing["revoked_permissions"]])
        return existing
    _validate_full_request(permissions_to_revoke, agent.effective_permissions)

    if agent.status == "DECOMMISSIONED":
        candidates = [item for item in get_action_log() if item.get("action") == "AGENT_DECOMMISSIONED"
                      and item.get("decommissioned_agent") == agent_id]
        if not candidates:
            raise RuntimeError("Local agent is decommissioned but its revocation event is unavailable")
        event = candidates[-1]
    else:
        result = module1_agents.decommission_agent(agent_id, revoked_by=revoked_by, reason=reason)
        if result["result"] != "REVOKED":
            raise RuntimeError(f"Module 1 decommission failed: {result}")
        event = next(item for item in reversed(get_action_log()) if item.get("action") == "AGENT_DECOMMISSIONED"
                     and item.get("decommissioned_agent") == agent_id)
    anchored = False
    try:
        with _bundle_context():
            anchor_revocation(event)
        anchored = True
        status = get_revocation_status(agent_id)
        if not status["is_revoked"]:
            raise RuntimeError("Ethereum still reports agent active after anchoring")
        return _record_from_status(agent_id, status)
    except Exception as exc:
        raise RevocationAnchoringError(exc, blockchain_anchored=anchored) from exc
