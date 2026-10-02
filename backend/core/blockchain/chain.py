"""Web3.py access to the Hardhat AgentTrustRegistry and durable local indexes."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re

from eth_account import Account
from web3 import Web3

try:
    from .integration import agent_hash, blockchain_record_id, content_hash, onchain_record_id, permission_hash, timestamp_seconds
except ImportError:
    from integration import agent_hash, blockchain_record_id, content_hash, onchain_record_id, permission_hash, timestamp_seconds


def _load_project_env() -> None:
    """Load simple KEY=VALUE entries from the ignored repository-root .env."""
    env_path = Path(__file__).resolve().parents[3] / ".env"
    if not env_path.is_file():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if value[:1] in ("'", '"') and value[-1:] == value[:1]:
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value


_load_project_env()


BLOCKCHAIN_DIR = Path(__file__).resolve().parents[3] / "blockchain"
ARTIFACT_PATH = BLOCKCHAIN_DIR / "artifacts" / "contracts" / "AgentTrustRegistry.sol" / "AgentTrustRegistry.json"
DATA_DIR = Path(__file__).resolve().parent / "data"
NETWORK_PROFILE = os.environ.get("CHAINGUARD_NETWORK", "hardhat").strip().lower()
NETWORK_DATA_DIR = DATA_DIR / NETWORK_PROFILE if NETWORK_PROFILE == "sepolia" else DATA_DIR
DEPLOYMENT_PATH = NETWORK_DATA_DIR / "deployment.json"
STATE_PATH = NETWORK_DATA_DIR / "ethereum_state.json"
CREDENTIALS_PATH = NETWORK_DATA_DIR / "credentials.json"
RPC_URL = (
    os.environ.get("SEPOLIA_RPC_URL", "").strip()
    if NETWORK_PROFILE == "sepolia"
    else os.environ.get("CHAINGUARD_RPC_URL", "http://127.0.0.1:8545").strip()
)
EXPECTED_CHAIN_IDS = {"hardhat": 31337, "sepolia": 11155111}
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


def _selected_private_key() -> str | None:
    return os.environ.get("SEPOLIA_PRIVATE_KEY") if NETWORK_PROFILE == "sepolia" else None


def validate_configuration(require_signer: bool = False) -> None:
    if NETWORK_PROFILE not in EXPECTED_CHAIN_IDS:
        raise RuntimeError("CHAINGUARD_NETWORK must be either 'hardhat' or 'sepolia'")
    if NETWORK_PROFILE == "sepolia":
        if not os.environ.get("SEPOLIA_RPC_URL", "").strip():
            raise RuntimeError("SEPOLIA_RPC_URL is not configured")
        private_key = os.environ.get("SEPOLIA_PRIVATE_KEY", "").strip()
        if require_signer and not private_key:
            raise RuntimeError("SEPOLIA_PRIVATE_KEY is not configured")
        if private_key and not re.fullmatch(r"0x[0-9a-fA-F]{64}", private_key):
            raise RuntimeError("SEPOLIA_PRIVATE_KEY must be a 0x-prefixed 32-byte hexadecimal key")


def connect(rpc_url: str | None = None) -> Web3:
    validate_configuration()
    endpoint = (rpc_url or RPC_URL).strip()
    if not endpoint:
        raise RuntimeError("Configured blockchain RPC URL is empty")
    web3 = Web3(Web3.HTTPProvider(endpoint, request_kwargs={"timeout": 20}))
    if not web3.is_connected():
        raise ConnectionError("Configured blockchain RPC is unavailable")
    return web3


def root_account(web3: Web3 | None = None):
    """Resolve the root signer without exposing its private key."""
    private_key = _selected_private_key()
    if private_key:
        return Account.from_key(private_key)
    provider = web3 or connect()
    accounts = provider.eth.accounts
    if not accounts:
        raise RuntimeError("No root signer configured; set SEPOLIA_PRIVATE_KEY")
    return Web3.to_checksum_address(accounts[0])


def root_address(web3: Web3 | None = None) -> str:
    signer = root_account(web3)
    return signer.address if hasattr(signer, "address") else Web3.to_checksum_address(signer)


def submit_transaction(web3: Web3, transaction_builder, sender: str):
    """Submit through an unlocked local account or sign with the configured root key."""
    private_key = _selected_private_key()
    if not private_key:
        if NETWORK_PROFILE == "sepolia":
            raise RuntimeError("SEPOLIA_PRIVATE_KEY is not configured")
        return transaction_builder.transact({"from": sender})
    account = Account.from_key(private_key)
    if account.address != Web3.to_checksum_address(sender):
        raise RuntimeError("Configured root signer does not match the registry ROOT_AUTHORIZER")
    nonce = web3.eth.get_transaction_count(account.address, "pending")
    gas_price = web3.eth.gas_price
    tx = transaction_builder.build_transaction({
        "from": account.address,
        "nonce": nonce,
        "chainId": web3.eth.chain_id,
        "gasPrice": gas_price,
    })
    tx.update({"from": account.address, "nonce": nonce, "chainId": web3.eth.chain_id, "gasPrice": gas_price})
    if "gas" not in tx:
        tx["gas"] = int(web3.eth.estimate_gas(tx) * 1.2)
    signed = account.sign_transaction(tx)
    return web3.eth.send_raw_transaction(signed.raw_transaction)


def _validate_selected_network(web3: Web3) -> None:
    expected = EXPECTED_CHAIN_IDS.get(NETWORK_PROFILE)
    if expected is not None and web3.eth.chain_id != expected:
        raise RuntimeError(
            f"CHAINGUARD_NETWORK={NETWORK_PROFILE} requires chain ID {expected}, got {web3.eth.chain_id}"
        )


def artifact() -> dict:
    if not ARTIFACT_PATH.exists():
        raise FileNotFoundError("Compile AgentTrustRegistry.sol with npm run compile first")
    return _read_json(ARTIFACT_PATH, {})


def deploy_registry() -> dict:
    """Deploy a fresh registry for one demo run and reset only its off-chain index."""
    validate_configuration(require_signer=NETWORK_PROFILE == "sepolia")
    web3 = connect()
    _validate_selected_network(web3)
    if NETWORK_PROFILE == "sepolia":
        manifest_path = BLOCKCHAIN_DIR / "deployments" / "sepolia.json"
        if manifest_path.is_file():
            public_metadata = _read_json(manifest_path, {})
            if public_metadata.get("chain_id") != 11155111:
                raise RuntimeError("Sepolia deployment metadata has the wrong chain ID")
            address = Web3.to_checksum_address(public_metadata["contract_address"])
            if not web3.eth.get_code(address):
                raise RuntimeError("Sepolia contract address has no deployed code")
            sender = root_address(web3)
            contract = web3.eth.contract(address=address, abi=artifact()["abi"])
            if Web3.to_checksum_address(contract.functions.rootAuthorizer().call()) != sender:
                raise RuntimeError("Sepolia deployment root does not match SEPOLIA_PRIVATE_KEY")
            deployment = {
                "contract_address": address,
                "chain_id": 11155111,
                "deployment_transaction_hash": public_metadata["deployment_tx_hash"],
                "block_number": public_metadata["deployment_block"],
                "rpc_url": "",
                "root_authorizer": sender,
            }
            _write_json(DEPLOYMENT_PATH, deployment)
            save_state(empty_state())
            return deployment
    accounts = web3.eth.accounts
    if not _selected_private_key() and len(accounts) < 5:
        raise RuntimeError("Hardhat must expose at least five unlocked public addresses")
    factory = web3.eth.contract(abi=artifact()["abi"], bytecode=artifact()["bytecode"])
    sender = root_address(web3)
    tx_hash = submit_transaction(web3, factory.constructor(), sender)
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    if receipt.status != 1 or not receipt.contractAddress:
        raise RuntimeError("AgentTrustRegistry deployment failed")
    deployment = {
        "contract_address": receipt.contractAddress,
        "chain_id": web3.eth.chain_id,
        "deployment_transaction_hash": Web3.to_hex(receipt.transactionHash),
        "block_number": receipt.blockNumber,
        "rpc_url": "" if NETWORK_PROFILE == "sepolia" else RPC_URL,
        "root_authorizer": sender,
    }
    _write_json(DEPLOYMENT_PATH, deployment)
    if NETWORK_PROFILE == "sepolia":
        block = web3.eth.get_block(receipt.blockNumber)
        public_manifest = BLOCKCHAIN_DIR / "deployments" / "sepolia.json"
        _write_json(public_manifest, {
            "network": "Sepolia",
            "chain_id": web3.eth.chain_id,
            "contract_address": receipt.contractAddress,
            "deployment_tx_hash": Web3.to_hex(receipt.transactionHash),
            "deployment_block": receipt.blockNumber,
            "deployed_at": datetime.fromtimestamp(block.timestamp, timezone.utc).isoformat(),
            "root_authorizer": sender,
        })
    save_state(empty_state())
    return deployment


def contract_context() -> tuple[Web3, object, str, dict]:
    deployment = _read_json(DEPLOYMENT_PATH, {})
    if not deployment:
        raise RuntimeError("Deploy AgentTrustRegistry before anchoring")
    web3 = connect(deployment.get("rpc_url") or RPC_URL)
    if web3.eth.chain_id != deployment["chain_id"]:
        raise RuntimeError("Chain ID does not match deployment")
    _validate_selected_network(web3)
    address = Web3.to_checksum_address(deployment["contract_address"])
    if not web3.eth.get_code(address):
        raise RuntimeError("Registry contract is absent from the connected chain")
    contract = web3.eth.contract(address=address, abi=artifact()["abi"])
    contract_root = Web3.to_checksum_address(contract.functions.rootAuthorizer().call())
    if _selected_private_key():
        root = root_address(web3)
        if contract_root != root:
            raise RuntimeError("Configured root signer does not match the registry ROOT_AUTHORIZER")
    elif NETWORK_PROFILE != "sepolia":
        root = root_address(web3)
        if contract_root != root:
            raise RuntimeError("Connected registry has a different ROOT_AUTHORIZER")
    else:
        root = contract_root
    if contract_root != root:
        raise RuntimeError("Connected registry has a different ROOT_AUTHORIZER")
    return web3, contract, root, deployment


def identity_addresses() -> dict[str, str]:
    web3 = connect()
    names = ("ROOT_AUTHORIZER", "Agent_A", "Agent_B", "Agent_C", "Agent_D")
    accounts = web3.eth.accounts
    if not _selected_private_key() and NETWORK_PROFILE == "sepolia":
        deployment = _read_json(DEPLOYMENT_PATH, {})
        root = deployment.get("root_authorizer")
        if not root:
            raise RuntimeError("Sepolia registry is not deployed; deploy it before registering identities")
        identities = {"ROOT_AUTHORIZER": Web3.to_checksum_address(root)}
        for name in names[1:]:
            identity_bytes = Web3.keccak(text=f"ChainGuard-AI public identity:{name}")[-20:]
            identities[name] = Web3.to_checksum_address(identity_bytes)
        return identities
    if not _selected_private_key():
        if len(accounts) < 5:
            raise RuntimeError("Five unlocked Hardhat addresses are required")
        return dict(zip(names, accounts[:5]))
    root = root_address(web3)
    identities = {"ROOT_AUTHORIZER": root}
    for name in names[1:]:
        # Agents are public registry identities; only ROOT_AUTHORIZER signs
        # administrative transactions in the current contract design.
        identity_bytes = Web3.keccak(text=f"ChainGuard-AI public identity:{name}")[-20:]
        identities[name] = Web3.to_checksum_address(identity_bytes)
    return identities


def register_identities() -> dict[str, str]:
    web3, contract, root, _ = contract_context()
    identities = identity_addresses()
    for agent_id, address in identities.items():
        current = contract.functions.agentAddresses(agent_hash(agent_id)).call()
        if current == Web3.to_checksum_address("0x" + "0" * 40):
            receipt = web3.eth.wait_for_transaction_receipt(
                submit_transaction(
                    web3, contract.functions.registerAgent(agent_hash(agent_id), address), root
                ),
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
    tx_hash = submit_transaction(web3, contract.functions.issueCredential(
        onchain_id,
        agent_hash(agent_id),
        agent_address,
        issuer_address,
        permission_hash(permission),
        permission_hash(permission) if can_delegate else bytes(32),
        timestamp_seconds(payload["issued_at"]),
        timestamp_seconds(payload["expires_at"]),
        bytes.fromhex(digest),
    ), root)
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
        # Provider URLs can contain access tokens. Sepolia verifiers use their
        # locally configured RPC instead of persisting or returning credentials.
        "rpc_url": "" if NETWORK_PROFILE == "sepolia" else RPC_URL,
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
            tx_hash = submit_transaction(
                web3, build_call(contract, onchain_id, bytes.fromhex(digest), state), root
            )
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
