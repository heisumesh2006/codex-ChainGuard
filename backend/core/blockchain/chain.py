"""Web3.py access to the Hardhat AgentTrustRegistry and durable local indexes."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path

from web3 import Web3

try:
    from .integration import agent_hash, blockchain_record_id, content_hash, onchain_record_id, permission_hash, timestamp_seconds
except ImportError:
    from integration import agent_hash, blockchain_record_id, content_hash, onchain_record_id, permission_hash, timestamp_seconds


BLOCKCHAIN_DIR = Path(__file__).resolve().parents[3] / "blockchain"
ARTIFACT_PATH = BLOCKCHAIN_DIR / "artifacts" / "contracts" / "AgentTrustRegistry.sol" / "AgentTrustRegistry.json"
DATA_DIR = Path(__file__).resolve().parent / "data"
DEPLOYMENT_PATH = DATA_DIR / "deployment.json"
STATE_PATH = DATA_DIR / "ethereum_state.json"
CREDENTIALS_PATH = DATA_DIR / "credentials.json"
RPC_URL = os.environ.get("CHAINGUARD_RPC_URL", "http://127.0.0.1:8545")
KIND_CODES = {"credential": 1, "delegation": 2, "revocation": 3, "action": 4}
EVENT_NAMES = {
    "credential": "CredentialIssued",
    "delegation": "DelegationAnchored",
    "revocation": "RevocationAnchored",
    "action": "ActionHashAnchored",
}
EVENT_SIGNATURES = {
    "credential": "CredentialIssued(bytes32,bytes32,bytes32)",
    "delegation": "DelegationAnchored(bytes32,bytes32,bytes32,bytes32)",
    "revocation": "RevocationAnchored(bytes32,bytes32,bytes32)",
    "action": "ActionHashAnchored(bytes32,bytes32)",
}


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, ensure_ascii=False, allow_nan=False)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _read_json(path: Path, default: dict) -> dict:
    if not path.exists():
        return deepcopy(default)
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def empty_state() -> dict:
    return {"version": 2, "records": {}, "index": {}, "pending": {}, "failed": {}, "credentials": {}}


def load_state() -> dict:
    state = _read_json(STATE_PATH, empty_state())
    if state.get("version") != 2:
        raise ValueError("Unsupported Ethereum state version")
    return state


def save_state(state: dict) -> None:
    _write_json(STATE_PATH, state)
    _write_json(CREDENTIALS_PATH, state["credentials"])


def connect(rpc_url: str = RPC_URL) -> Web3:
    web3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 20}))
    if not web3.is_connected():
        raise ConnectionError(f"Hardhat RPC unavailable at {rpc_url}")
    return web3


def artifact() -> dict:
    if not ARTIFACT_PATH.exists():
        raise FileNotFoundError("Compile AgentTrustRegistry.sol with npm run compile first")
    return _read_json(ARTIFACT_PATH, {})


def deploy_registry() -> dict:
    """Deploy a fresh registry for one demo run and reset only its off-chain index."""
    web3 = connect()
    accounts = web3.eth.accounts
    if len(accounts) < 5:
        raise RuntimeError("Hardhat must expose at least five unlocked public addresses")
    factory = web3.eth.contract(abi=artifact()["abi"], bytecode=artifact()["bytecode"])
    tx_hash = factory.constructor().transact({"from": accounts[0]})
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    if receipt.status != 1 or not receipt.contractAddress:
        raise RuntimeError("AgentTrustRegistry deployment failed")
    deployment = {
        "contract_address": receipt.contractAddress,
        "chain_id": web3.eth.chain_id,
        "deployment_transaction_hash": Web3.to_hex(receipt.transactionHash),
        "block_number": receipt.blockNumber,
        "rpc_url": RPC_URL,
    }
    _write_json(DEPLOYMENT_PATH, deployment)
    save_state(empty_state())
    return deployment


def contract_context() -> tuple[Web3, object, str, dict]:
    deployment = _read_json(DEPLOYMENT_PATH, {})
    if not deployment:
        raise RuntimeError("Deploy AgentTrustRegistry before anchoring")
    web3 = connect(deployment["rpc_url"])
    if web3.eth.chain_id != deployment["chain_id"]:
        raise RuntimeError("Chain ID does not match deployment")
    address = Web3.to_checksum_address(deployment["contract_address"])
    if not web3.eth.get_code(address):
        raise RuntimeError("Registry contract is absent from the connected chain")
    contract = web3.eth.contract(address=address, abi=artifact()["abi"])
    root = web3.eth.accounts[0]
    if contract.functions.rootAuthorizer().call() != root:
        raise RuntimeError("Connected registry has a different ROOT_AUTHORIZER")
    return web3, contract, root, deployment


def identity_addresses() -> dict[str, str]:
    accounts = connect().eth.accounts
    if len(accounts) < 5:
        raise RuntimeError("Five unlocked Hardhat accounts are required")
    return dict(zip(("ROOT_AUTHORIZER", "Agent_A", "Agent_B", "Agent_C", "Agent_D"), accounts[:5]))


def register_identities() -> dict[str, str]:
    web3, contract, root, _ = contract_context()
    identities = identity_addresses()
    for agent_id, address in identities.items():
        current = contract.functions.agentAddresses(agent_hash(agent_id)).call()
        if current == Web3.to_checksum_address("0x" + "0" * 40):
            receipt = web3.eth.wait_for_transaction_receipt(
                contract.functions.registerAgent(agent_hash(agent_id), address).transact({"from": root}),
                timeout=120,
            )
            if receipt.status != 1:
                raise RuntimeError(f"Registration failed for {agent_id}")
        elif current != address:
            raise RuntimeError(f"Conflicting blockchain identity for {agent_id}")
    return identities


def issue_credential(agent_id: str, permission: str, issuer_id: str, can_delegate: bool) -> dict:
    web3, contract, root, _ = contract_context()
    identities = identity_addresses()
    agent_address = identities[agent_id]
    issuer_address = identities[issuer_id]
    issued_at = datetime.now(timezone.utc).replace(microsecond=0)
    expires_at = issued_at + timedelta(days=365)
    payload = {
        "agent_id": agent_id,
        "agent_hash": "0x" + agent_hash(agent_id).hex(),
        "agent_address": agent_address,
        "issuer": issuer_address,
        "allowed_permission_scope": [permission],
        "delegation_scope": [permission] if can_delegate else [],
        "issued_at": issued_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "status_at_issuance": "ACTIVE",
    }
    digest = content_hash(payload)
    credential_id = f"credential:{digest}"
    state = load_state()
    if credential_id in state["credentials"]:
        return deepcopy(state["credentials"][credential_id])
    onchain_id = onchain_record_id(KIND_CODES["credential"], digest)
    tx_hash = contract.functions.issueCredential(
        onchain_id,
        agent_hash(agent_id),
        agent_address,
        issuer_address,
        permission_hash(permission),
        permission_hash(permission) if can_delegate else bytes(32),
        timestamp_seconds(payload["issued_at"]),
        timestamp_seconds(payload["expires_at"]),
        bytes.fromhex(digest),
    ).transact({"from": root})
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    if receipt.status != 1:
        raise RuntimeError(f"Credential issuance failed for {agent_id}/{permission}")
    credential = {
        **payload,
        "credential_id": credential_id,
        "onchain_id": "0x" + onchain_id.hex(),
        "content_hash": digest,
        "current_status": "ACTIVE",
        "transaction_hash": Web3.to_hex(receipt.transactionHash),
    }
    state["credentials"][credential_id] = credential
    save_state(state)
    return deepcopy(credential)


def credential_ids_for_agent(agent_id: str) -> list[bytes]:
    return [
        bytes.fromhex(credential["onchain_id"][2:])
        for credential in load_state()["credentials"].values()
        if credential["agent_id"] == agent_id and credential["current_status"] == "ACTIVE"
    ]


def _event_receipt(web3: Web3, contract: object, kind: str, digest: str):
    topic = Web3.keccak(text=EVENT_SIGNATURES[kind])
    onchain_id = onchain_record_id(KIND_CODES[kind], digest)
    logs = web3.eth.get_logs(
        {"fromBlock": 0, "toBlock": "latest", "address": contract.address, "topics": [topic, onchain_id]}
    )
    if len(logs) != 1:
        raise RuntimeError(f"Expected one {EVENT_NAMES[kind]} event for {digest}; found {len(logs)}")
    return web3.eth.get_transaction_receipt(logs[0].transactionHash)


def _proof_payload(web3: Web3, contract: object, kind: str, source: dict, digest: str, receipt) -> dict:
    block = web3.eth.get_block(receipt.blockNumber)
    record_id = blockchain_record_id(kind, source)
    onchain_id = onchain_record_id(KIND_CODES[kind], digest)
    return {
        "record_id": record_id,
        "onchain_record_id": "0x" + onchain_id.hex(),
        "source_record_id": source.get("record_id"),
        "kind": kind,
        "content_hash": digest,
        "tx_id": Web3.to_hex(receipt.transactionHash),
        "transaction_hash": Web3.to_hex(receipt.transactionHash),
        "block_number": receipt.blockNumber,
        "block_hash": Web3.to_hex(block.hash),
        "contract_address": contract.address,
        "chain_id": web3.eth.chain_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rpc_url": RPC_URL,
    }


def commit(kind: str, source: dict, build_call) -> dict:
    """Commit once on Ethereum; persist pending and retryable failures off-chain."""
    digest = content_hash(source)
    record_id = blockchain_record_id(kind, source)
    onchain_id = onchain_record_id(KIND_CODES[kind], digest)
    state = load_state()
    existing = state["records"].get(record_id)
    if existing:
        web3, contract, _, _ = contract_context()
        onchain = contract.functions.commitments(onchain_id).call()
        if onchain[0] != bytes.fromhex(digest) or onchain[1] != KIND_CODES[kind]:
            raise RuntimeError("Local index disagrees with blockchain commitment")
        web3.eth.get_transaction_receipt(existing["proof"]["transaction_hash"])
        return deepcopy(existing["proof"])

    state["failed"].pop(record_id, None)
    state["pending"][record_id] = {"kind": kind, "content_hash": digest, "retry": True, "source": deepcopy(source)}
    save_state(state)
    try:
        web3, contract, root, _ = contract_context()
        onchain = contract.functions.commitments(onchain_id).call()
        if onchain[1]:
            if onchain[0] != bytes.fromhex(digest) or onchain[1] != KIND_CODES[kind]:
                raise RuntimeError("Conflicting on-chain record ID")
            receipt = _event_receipt(web3, contract, kind, digest)
        else:
            tx_hash = build_call(contract, onchain_id, bytes.fromhex(digest), state).transact({"from": root})
            receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            if receipt.status != 1:
                raise RuntimeError("Ethereum transaction reverted")
        proof = _proof_payload(web3, contract, kind, source, digest, receipt)
        candidate = deepcopy(state)
        candidate["pending"].pop(record_id, None)
        candidate["records"][record_id] = {
            "kind": kind,
            "status": "anchored",
            "source": deepcopy(source),
            "proof": proof,
        }
        source_id = source.get("record_id")
        if source_id:
            candidate["index"].setdefault(source_id, {})[kind] = record_id
        if kind == "revocation":
            for credential in candidate["credentials"].values():
                if credential["agent_id"] == source["decommissioned_agent"]:
                    credential["current_status"] = "REVOKED"
        save_state(candidate)
        return deepcopy(proof)
    except Exception as exc:
        state["pending"].pop(record_id, None)
        state["failed"][record_id] = {
            "kind": kind,
            "content_hash": digest,
            "source": deepcopy(source),
            "retry": True,
            "error": str(exc),
            "failed_at": datetime.now(timezone.utc).isoformat(),
        }
        save_state(state)
        raise


def proof_for(record_id: str) -> dict:
    state = load_state()
    if record_id in state["records"]:
        target = record_id
    else:
        choices = state["index"].get(record_id, {})
        target = next((choices[k] for k in ("delegation", "revocation", "action") if k in choices), None)
    if not target:
        raise KeyError(record_id)
    return deepcopy(state["records"][target]["proof"])
