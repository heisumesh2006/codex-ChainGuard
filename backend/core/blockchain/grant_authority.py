"""Optional grant-specific registry adapter; deployment is local-only here.

The existing Sepolia registry/evidence is never migrated or modified. New
deployments require explicit operator management, not a client-supplied address.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
from web3 import Web3
from . import chain, integration
from .evidence import read_object, EvidenceError, aware_timestamp
from .persistence import atomic_write


def manifest_path(): return chain.STATE_PATH.parent / "grant_authority.json"


def artifact():
    return read_object(chain.BLOCKCHAIN_DIR / "artifacts/contracts/GrantAuthority.sol/GrantAuthority.json")


def context():
    web3, registry, root, deployment = chain.contract_context()
    manifest = read_object(manifest_path())
    try:
        if (type(manifest["chain_id"]) is not int or type(manifest["block_number"]) is not int
                or manifest["block_number"] < 0
                or not Web3.is_address(manifest["registry"])
                or not Web3.is_address(manifest["contract_address"])
                or len(Web3.to_bytes(hexstr=manifest["transaction_hash"])) != 32):
            raise ValueError()
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        raise EvidenceError("GRANT_MANIFEST_CORRUPT") from None
    if manifest["chain_id"] != web3.eth.chain_id or manifest["registry"].lower() != registry.address.lower():
        raise EvidenceError("NETWORK_MISMATCH", 409)
    contract = web3.eth.contract(address=Web3.to_checksum_address(manifest["contract_address"]), abi=artifact()["abi"])
    if not web3.eth.get_code(contract.address) or contract.functions.registry().call() != registry.address or contract.functions.rootAuthorizer().call() != root:
        raise EvidenceError("GRANT_REGISTRY_MISMATCH", 409)
    receipt = web3.eth.get_transaction_receipt(manifest["transaction_hash"])
    transaction = web3.eth.get_transaction(manifest["transaction_hash"])
    if (receipt.status != 1 or receipt.contractAddress != contract.address or transaction["from"] != root
            or receipt.blockNumber != manifest["block_number"]):
        raise EvidenceError("GRANT_REGISTRY_PROOF_INVALID")
    return web3, contract, root, manifest


def deploy_local():
    if chain.NETWORK_PROFILE != "hardhat":
        raise RuntimeError("GRANT_EXTENSION_DEPLOYMENT_REQUIRES_LOCAL_HARDHAT")
    web3, registry, root, _ = chain.contract_context()
    if chain.NETWORK_PROFILE != "hardhat" or web3.eth.chain_id != 31337:
        raise RuntimeError("GRANT_EXTENSION_DEPLOYMENT_REQUIRES_LOCAL_HARDHAT")
    if manifest_path().exists():
        return context()[3]
    data = artifact()
    factory = web3.eth.contract(abi=data["abi"], bytecode=data["bytecode"])
    receipt = web3.eth.wait_for_transaction_receipt(chain.submit_transaction(web3, factory.constructor(registry.address), root))
    if receipt.status != 1: raise RuntimeError("GRANT_REGISTRY_DEPLOYMENT_FAILED")
    manifest = {"chain_id": 31337, "registry": registry.address, "contract_address": receipt.contractAddress,
                "transaction_hash": Web3.to_hex(receipt.transactionHash), "block_number": receipt.blockNumber}
    atomic_write(manifest_path(), json.dumps(manifest, sort_keys=True).encode())
    return manifest


def key(grant_id):
    prefix, digest = grant_id.split(":", 1)
    if prefix not in ("grant", "delegation") or len(digest) != 64: raise ValueError("INVALID_GRANT_ID")
    return bytes.fromhex(digest)


def records():
    from backend.core.authorization import agents as a
    result = {}
    for root in a.ROOT_AUTHORITY_RECORD:
        for scope, grant in root.get("grants", {}).items():
            result[grant["record_id"]] = {**grant, "holder": root["granted_to"], "permission": scope, "parent_grant_id": None}
    for grant in a.DELEGATION_LEDGER:
        result[grant["record_id"]] = {**grant, "holder": grant["delegatee"]}
    return result


def _check_commitment(grant, stored, permission, parent_key):
    """Match every signed path edge; a valid but unrelated chain is insufficient."""
    expected_expiry = int(aware_timestamp(grant["expires_at"]).timestamp()) if grant.get("expires_at") else None
    if (not stored[6] or stored[0] != integration.agent_hash(grant["holder"])
            or stored[1] != integration.permission_hash(permission) or stored[2] != parent_key
            or (expected_expiry is not None and stored[4] != expected_expiry)
            or stored[3] < int(aware_timestamp(grant["issued_at"]).timestamp())):
        raise EvidenceError("GRANT_COMMITMENT_MISMATCH")


def anchor_path(agent_id, permission):
    from backend.core.authorization import agents as a
    if chain.NETWORK_PROFILE != "hardhat":
        raise RuntimeError("RESEARCH_ANCHORING_REQUIRES_LOCAL_HARDHAT")
    web3, contract, root, _ = context()
    if chain.NETWORK_PROFILE != "hardhat" or web3.eth.chain_id != 31337:
        raise RuntimeError("RESEARCH_ANCHORING_REQUIRES_LOCAL_HARDHAT")
    paths = a.authority_paths(agent_id, permission)
    if not paths: raise ValueError("NO_VALID_SIGNED_AUTHORITY")
    path = paths[0]; data = records()
    for grant_id in path:
        grant = data[grant_id]; parent = grant.get("parent_grant_id")
        parent_key = key(parent) if parent else bytes(32)
        expiry = int(datetime.fromisoformat(grant["expires_at"]).timestamp()) if grant.get("expires_at") else (
            contract.functions.grants(parent_key).call()[4] if parent else int(web3.eth.get_block("latest").timestamp)+365*86400)
        stored = contract.functions.grants(key(grant_id)).call()
        if stored[6]:
            _check_commitment(grant, stored, permission, parent_key)
            continue
        receipt = web3.eth.wait_for_transaction_receipt(chain.submit_transaction(web3,
            contract.functions.issueGrant(key(grant_id), integration.agent_hash(grant["holder"]),
                                         integration.permission_hash(permission), parent_key, expiry), root))
        if receipt.status != 1: raise RuntimeError("GRANT_ANCHOR_FAILED")
    return path[-1]


def trace(agent_id, permission, *, at_time=None, grant_id=None):
    """Authenticate a selected current/historical grant path against the chain."""
    from backend.core.authorization import agents as a
    web3, contract, root, manifest = context()
    paths = a.authority_paths(agent_id, permission)
    if at_time:
        # Both historical issuance/expiry and current revocation must hold for
        # a fresh caller; it cannot backdate a request to revive authority.
        historical = a.authority_paths(agent_id, permission, at_time=aware_timestamp(at_time).isoformat())
        paths = [path for path in paths if path in historical]
    paths = [path for path in paths if all(node.startswith(("grant:", "delegation:")) for node in path)]
    if grant_id: paths = [path for path in paths if path[-1] == grant_id]
    data = records()
    for path in paths:
        leaf = contract.functions.grants(key(path[-1])).call()
        if leaf[0] != integration.agent_hash(agent_id) or leaf[1] != integration.permission_hash(permission): continue
        if not contract.functions.isValidNow(key(path[-1])).call(): continue
        when = int(aware_timestamp(at_time).timestamp()) if at_time else int(web3.eth.get_block("latest").timestamp)
        if not contract.functions.wasValidAt(key(path[-1]), when).call(): continue
        hops = []
        for index, node in enumerate(path):
            stored = contract.functions.grants(key(node)).call()
            parent_key = key(path[index-1]) if index else bytes(32)
            _check_commitment(data[node], stored, permission, parent_key)
            hops.append({"record_id": node, "anchored": True, "proof_verified": True,
                         "from": "ROOT_AUTHORIZER" if stored[2] == bytes(32) else Web3.to_hex(stored[2]),
                         "to": Web3.to_hex(stored[0]), "permission": permission,
                         "valid_at_action_time": True})
        return {"chain": hops, "valid": True, "verdict": "VALID_CHAIN", "reason": "Signed grant ancestry and on-chain transitive validity verified",
                "trace_latency_ms": None, "evidence_type": "GRANT_AUTHORITY", "authority_grant_id": path[-1],
                "authority_contract": contract.address, "chain_id": web3.eth.chain_id}
    return {"chain": [], "valid": False, "verdict": "BROKEN_CHAIN", "reason": "No valid anchored grant path",
            "trace_latency_ms": None, "evidence_type": "GRANT_AUTHORITY"}
