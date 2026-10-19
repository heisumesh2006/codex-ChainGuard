"""Explicit operator/CLI signing. Never called by an HTTP request handler."""

import time
from uuid import uuid4
from eth_account import Account
from web3 import Web3
from .authentication import canonical, request_message, registered_verifier, sign_request


def operator_credentials(actor, operation, payload):
    from backend.core.blockchain import chain
    verifier = registered_verifier()
    web3, _, _, _ = chain.contract_context()
    if web3.eth.chain_id == 31337:
        address = verifier.resolve_identity(actor)
        now = int(time.time())
        message = request_message(verifier.domain, actor, operation, payload, uuid4().hex, now, now + 120)
        signed = web3.eth.sign(address, data=canonical(message))
        envelope = {**message, "signature": Web3.to_hex(signed)}
    else:
        key = chain._selected_private_key()
        if not key:
            raise ValueError("OPERATOR_SIGNER_REQUIRED")
        account = Account.from_key(key)
        if account.address != verifier.resolve_identity(actor):
            raise ValueError("OPERATOR_IDENTITY_MISMATCH")
        envelope = sign_request(account, verifier.domain, actor, operation, payload)
    return {"authentication": envelope, "verifier": verifier}
