"""Module 2's stable Ethereum-backed anchoring and verification interface."""

from web3 import Web3

try:
    from . import chain, integration
except ImportError:
    import chain
    import integration


def anchor_delegation(delegation_record: dict) -> dict:
    record = integration.prepare_delegation(delegation_record)
    return chain.commit(
        "delegation",
        record,
        lambda contract, onchain_id, digest, state: contract.functions.anchorDelegation(
            onchain_id,
            integration.agent_hash(record["delegator"]),
            integration.agent_hash(record["delegatee"]),
            integration.permission_hash(record["permission"]),
            digest,
        ),
    )


def anchor_revocation(revocation_record: dict) -> dict:
    record = integration.prepare_revocation(revocation_record)
    return chain.commit(
        "revocation",
        record,
        lambda contract, onchain_id, digest, state: contract.functions.anchorRevocation(
            onchain_id,
            integration.agent_hash(record["decommissioned_agent"]),
            [
                bytes.fromhex(credential["onchain_id"][2:])
                for credential in state["credentials"].values()
                if credential["agent_id"] == record["decommissioned_agent"]
                and credential["current_status"] == "ACTIVE"
            ],
            digest,
        ),
    )


def anchor_action_hash(action_log_entry: dict) -> dict:
    record = integration.prepare_action(action_log_entry)
    return chain.commit(
        "action",
        record,
        lambda contract, onchain_id, digest, state: contract.functions.anchorActionHash(onchain_id, digest),
    )


def get_proof(record_id: str) -> dict:
    """Accept a Module 1 source ID or deterministic blockchain record ID."""
    return chain.proof_for(record_id)


def verify_proof(record: dict, proof: dict) -> bool:
    """Check a transaction, emitted event and contract storage on the supplied chain.

    This intentionally reads neither Module 1 objects nor Module 2's local index.
    The caller supplies a reachable RPC endpoint in the proof.
    """
    try:
        if not isinstance(record, dict) or not isinstance(proof, dict):
            return False
        kind = proof["kind"]
        if kind not in ("delegation", "revocation", "action"):
            return False
        prepared = {
            "delegation": integration.prepare_delegation,
            "revocation": integration.prepare_revocation,
            "action": integration.prepare_action,
        }[kind](record)
        digest = integration.content_hash(prepared)
        if digest != proof["content_hash"]:
            return False
        if integration.blockchain_record_id(kind, prepared) != proof["record_id"]:
            return False
        if prepared["record_id"] != proof["source_record_id"]:
            return False

        web3 = chain.connect(proof["rpc_url"])
        if web3.eth.chain_id != proof["chain_id"]:
            return False
        address = Web3.to_checksum_address(proof["contract_address"])
        if not web3.eth.get_code(address):
            return False
        contract = web3.eth.contract(address=address, abi=chain.artifact()["abi"])
        receipt = web3.eth.get_transaction_receipt(proof["transaction_hash"])
        if receipt.status != 1 or receipt.blockNumber != proof["block_number"]:
            return False
        if Web3.to_hex(receipt.transactionHash) != proof["transaction_hash"]:
            return False
        if Web3.to_hex(web3.eth.get_block(receipt.blockNumber).hash) != proof["block_hash"]:
            return False
        transaction = web3.eth.get_transaction(proof["transaction_hash"])
        if Web3.to_checksum_address(transaction["to"]) != address:
            return False
        if transaction["from"] != contract.functions.rootAuthorizer().call():
            return False
        onchain_id = integration.onchain_record_id(chain.KIND_CODES[kind], digest)
        if proof["onchain_record_id"] != "0x" + onchain_id.hex():
            return False
        onchain = contract.functions.commitments(onchain_id).call()
        if onchain[0] != bytes.fromhex(digest) or onchain[1] != chain.KIND_CODES[kind]:
            return False

        event = getattr(contract.events, chain.EVENT_NAMES[kind])()
        matching = [
            event.process_log(log)
            for log in receipt.logs
            if log["address"].lower() == address.lower()
            and log["topics"][0] == Web3.keccak(text=chain.EVENT_SIGNATURES[kind])
        ]
        return len(matching) == 1 and (
            matching[0]["args"]["recordId"] == onchain_id
            and matching[0]["args"]["contentHash"] == bytes.fromhex(digest)
        )
    except Exception:
        return False
