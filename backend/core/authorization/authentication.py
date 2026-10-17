"""EIP-191 request signatures, registry-bound identities and durable replay protection.

Identity names are lookup keys, never credentials. Private keys are held by the
caller, not by this verifier. A trusted process can inject an isolated verifier
for experiments; the HTTP boundary never accepts verifier configuration.
"""

from dataclasses import dataclass
from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import json
from pathlib import Path
import re
import time
from uuid import uuid4
from functools import lru_cache

from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3

from backend.core.blockchain.persistence import FileLock, atomic_write

_verified_operation = ContextVar("chainguard_verified_operation", default=None)


@lru_cache(maxsize=4096)
def _recover_retained_grant(message, signature):
    # Only public messages/signatures are cached. Request nonce checking is
    # never cached; metadata changes produce a different cache key.
    return Account.recover_message(encode_defunct(primitive=message), signature=signature)


class AuthenticationError(ValueError):
    """Safe public authentication failure; never includes signature or payload."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def request_message(domain, actor, operation, payload, nonce, issued_at, expires_at):
    return {"protocol": "ChainGuard-AI signed request v1", "domain": domain,
            "actor": actor, "operation": operation,
            "payload_sha256": hashlib.sha256(canonical(payload)).hexdigest(),
            "nonce": nonce, "issued_at": issued_at, "expires_at": expires_at}


def sign_request(account, domain, actor, operation, payload, *, now=None, ttl=120, nonce=None):
    """Caller-side helper. The returned envelope contains no private key."""
    now = int(time.time()) if now is None else now
    message = request_message(domain, actor, operation, payload, nonce or uuid4().hex, now, now + ttl)
    signature = Account.sign_message(encode_defunct(primitive=canonical(message)), account.key).signature
    return {**message, "signature": "0x" + signature.hex().removeprefix("0x")}


@dataclass(frozen=True)
class Principal:
    actor: str
    address: str
    request_id: str


class RequestVerifier:
    def __init__(self, domain, resolve_identity, nonce_path: Path, *, clock=time.time):
        self.domain = domain
        self.resolve_identity = resolve_identity
        self.path = Path(nonce_path)
        self.clock = clock

    def verify_grant(self, envelope, operation, payload, actor):
        """Check a retained signed grant without consuming/re-expiring its request.

        A request's short authentication lifetime is not a credential's lifetime.
        Retained scope/holder/issuer/expiry metadata remains signature-bound.
        """
        try:
            issued, expiry = envelope["issued_at"], envelope["expires_at"]
            if (type(issued) is not int or type(expiry) is not int or not 0 < expiry-issued <= 300
                    or issued > int(self.clock()) + 5): return False
            expected = request_message(self.domain, actor, operation, payload, envelope["nonce"], issued, expiry)
            if {k:v for k,v in envelope.items() if k != "signature"} != expected: return False
            recovered = _recover_retained_grant(canonical(expected), envelope["signature"])
            return recovered == Web3.to_checksum_address(self.resolve_identity(actor))
        except Exception:
            return False

    def authenticate(self, envelope, operation, payload, actor):
        if not isinstance(envelope, dict):
            raise AuthenticationError("AUTHENTICATION_REQUIRED")
        expected_keys = {"protocol", "domain", "actor", "operation", "payload_sha256",
                         "nonce", "issued_at", "expires_at", "signature"}
        if set(envelope) != expected_keys:
            raise AuthenticationError("INVALID_AUTHENTICATION")
        now = int(self.clock())
        issued, expiry, nonce = envelope["issued_at"], envelope["expires_at"], envelope["nonce"]
        if (type(issued) is not int or type(expiry) is not int or not isinstance(nonce, str)
                or not re.fullmatch(r"[0-9a-f]{32}", nonce)
                or issued > now + 5 or not issued < expiry or expiry - issued > 300
                or now >= expiry):
            raise AuthenticationError("AUTHENTICATION_EXPIRED_OR_INVALID")
        expected = request_message(self.domain, actor, operation, payload, nonce, issued, expiry)
        if {k: v for k, v in envelope.items() if k != "signature"} != expected:
            raise AuthenticationError("AUTHENTICATION_BINDING_MISMATCH")
        try:
            address = Web3.to_checksum_address(self.resolve_identity(actor))
            if int(address, 16) == 0:
                raise ValueError()
            recovered = Account.recover_message(encode_defunct(primitive=canonical(expected)),
                                                signature=envelope["signature"])
        except Exception:
            raise AuthenticationError("INVALID_IDENTITY_SIGNATURE") from None
        if recovered != address:
            raise AuthenticationError("INVALID_IDENTITY_SIGNATURE")
        # Serializes check-and-consume across unrelated worker processes.
        key = hashlib.sha256(canonical([self.domain, address, nonce])).hexdigest()
        with FileLock(str(self.path) + ".lock"):
            try:
                used = json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {}
                if not isinstance(used, dict) or any(type(v) is not int for v in used.values()):
                    raise ValueError()
            except (ValueError, OSError):
                raise AuthenticationError("AUTHENTICATION_STORE_UNAVAILABLE") from None
            used = {k: v for k, v in used.items() if v > now}
            if key in used:
                raise AuthenticationError("AUTHENTICATION_REPLAYED")
            used[key] = expiry
            atomic_write(self.path, canonical(used))
        return Principal(actor, address, key)


def registered_verifier():
    """Use the live selected registry, never a client-selected trust root/RPC."""
    from backend.core.blockchain import chain, integration
    web3, contract, root, _ = chain.contract_context()
    domain = f"chainguard:{web3.eth.chain_id}:{contract.address.lower()}"
    def resolve(actor):
        address = contract.functions.agentAddresses(integration.agent_hash(actor)).call()
        if actor == "ROOT_AUTHORIZER" and address != root:
            raise AuthenticationError("ROOT_IDENTITY_MISMATCH")
        return address
    return RequestVerifier(domain, resolve, chain.STATE_PATH.parent / "authentication_nonces.json")


def authenticate(envelope, operation, payload, actor, verifier=None):
    bound = (operation, hashlib.sha256(canonical(payload)).hexdigest(), actor)
    current = _verified_operation.get()
    if current is not None and current[0] == bound:
        return current[1]
    # Reject unauthenticated requests before touching RPC or any mutable state.
    if envelope is None:
        raise AuthenticationError("AUTHENTICATION_REQUIRED")
    return (verifier or registered_verifier()).authenticate(envelope, operation, payload, actor)


@contextmanager
def authenticated_operation(envelope, operation, payload, actor, verifier=None):
    principal = authenticate(envelope, operation, payload, actor, verifier)
    token = _verified_operation.set(((operation, hashlib.sha256(canonical(payload)).hexdigest(), actor), principal))
    try:
        yield principal
    finally:
        _verified_operation.reset(token)
