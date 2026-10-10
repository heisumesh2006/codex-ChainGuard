"""Safe diagnostics and public copies; never rewrite committed evidence."""

from functools import wraps
import os
import re
from urllib.parse import urlsplit, unquote


REDACTED = "[REDACTED]"
_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_CODES = {"RPC_UNAVAILABLE", "RPC_TIMEOUT", "CHAIN_MISMATCH", "CONTRACT_UNAVAILABLE",
          "TRANSACTION_FAILED", "PROOF_VERIFICATION_FAILED", "RPC_OFFLINE",
          "CONTRACT_NOT_DEPLOYED_ON_CURRENT_NETWORK"}


def redact_text(value: object, *, diagnostic: bool = False) -> str:
    text = str(value)
    # Known bare credentials are matched as complete tokens, never substrings
    # of public addresses, roots, transaction hashes or batch identifiers.
    secrets = set()
    for name in ("SEPOLIA_RPC_URL", "SEPOLIA_PRIVATE_KEY", "CHAINGUARD_RPC_URL"):
        secret = os.environ.get(name, "").strip()
        if not secret:
            continue
        if name.endswith("RPC_URL"):
            try:
                parts = urlsplit(secret)
            except ValueError:
                secrets.add(secret)
                continue
            if parts.hostname in ("localhost", "127.0.0.1", "::1") and not parts.username and not parts.query and not parts.path.strip("/"):
                continue
            secrets.add(secret)
            if parts.username:
                secrets.update(component for component in (parts.username, parts.password) if component and len(component) >= 12)
            for match in re.finditer(r"(?:/v[23]/|[?&](?:api[_-]?key|access[_-]?token|token|key)=)([^&/?#]+)", parts.path + "?" + parts.query, re.IGNORECASE):
                component = unquote(match.group(1))
                if len(component) >= 12:
                    secrets.add(component)
        else:
            secrets.update((secret, secret.removeprefix("0x")))
    for secret in sorted(secrets, key=len, reverse=True):
        text = re.sub(r"(?<![\w])" + re.escape(secret) + r"(?![\w])", REDACTED, text)

    def url(match):
        endpoint = match.group(0)
        try:
            parts = urlsplit(endpoint)
        except ValueError:
            return REDACTED
        sensitive = (parts.username is not None or bool(parts.query)
                     or bool(re.search(r"/(?:v[23]|rpc)/[^/]+", parts.path, re.IGNORECASE))
                     or "alchemy.com" in (parts.hostname or "")
                     or "infura.io" in (parts.hostname or ""))
        return REDACTED if diagnostic or sensitive else endpoint

    text = _URL.sub(url, text)
    text = re.sub(r"\b((?:authorization[\"']?\s*[:=]\s*[\"']?\s*)?(?:Bearer|Basic)\s+)[^\s,;\"']+",
                  lambda m: m.group(1) + REDACTED, text, flags=re.IGNORECASE)
    text = re.sub(r"\b(authorization[\"']?\s*[:=]\s*[\"']?)[^\r\n,;\"']+",
                  lambda m: m.group(1) + REDACTED, text, flags=re.IGNORECASE)
    text = re.sub(r"\b((?:api[_ -]?key|access[_ -]?token|token|password|private[_ -]?key|secret)[\"']?\s*[:=]\s*[\"']?)[^\s,;\"']+",
                  lambda m: m.group(1) + REDACTED, text, flags=re.IGNORECASE)
    if diagnostic:
        # A 32-byte public hash is indistinguishable from a key by length.
        # Require a secret/signing context instead of destroying all hashes.
        text = re.sub(r"(\bsigner failed with\s+)(?:0x)?[0-9a-fA-F]{64}\b",
                      lambda m: m.group(1) + REDACTED, text, flags=re.IGNORECASE)
        # A provider sometimes returns only an opaque credential as its entire
        # error. Keep recognizable public hex identifiers, including 0x forms.
        if re.fullmatch(r"[A-Za-z0-9_-]{24,}", text) and text not in _CODES and not re.fullmatch(r"(?:0x)?[0-9a-fA-F]{40}|(?:0x)?[0-9a-fA-F]{64}", text):
            text = REDACTED
    return text


def _exception_chain(error: object):
    """Inspect both links, including suppressed contexts, without cycles."""
    pending = [error]
    seen = set()
    while pending:
        item = pending.pop()
        if id(item) in seen:
            continue
        seen.add(id(item))
        yield item
        if isinstance(item, BaseException):
            pending.extend(link for link in (item.__context__, item.__cause__) if link is not None)


def safe_error(error: object) -> str:
    chain = list(_exception_chain(error))
    message = redact_text(error, diagnostic=True)
    if any(message.startswith(code + ":") or message == code for code in _CODES):
        return message
    lower = " ".join(redact_text(item, diagnostic=True) for item in chain).lower()
    if any(isinstance(item, TimeoutError) for item in chain) or "timeout" in lower or "timed out" in lower:
        code = "RPC_TIMEOUT"
    elif "chain" in lower and any(term in lower for term in ("mismatch", "requires chain", "wrong", "expected")):
        code = "CHAIN_MISMATCH"
    elif "contract" in lower and any(term in lower for term in ("unavailable", "deployed", "missing")):
        code = "CONTRACT_UNAVAILABLE"
    elif any(term in lower for term in ("transaction", "receipt", "revert")):
        code = "TRANSACTION_FAILED"
    elif any(term in lower for term in ("proof", "commitment", "credential", "event mismatch")):
        code = "PROOF_VERIFICATION_FAILED"
    else:
        code = "RPC_UNAVAILABLE"
    return f"{code}: {message}"


def safe_exception(error: Exception) -> Exception:
    """Keep common failure types and suppress raw exception chains at rethrow."""
    cls = (TimeoutError if isinstance(error, TimeoutError) else
           ConnectionError if isinstance(error, ConnectionError) else
           ValueError if isinstance(error, ValueError) else
           LookupError if isinstance(error, LookupError) else RuntimeError)
    return cls(safe_error(error))


def public_data(value: object, field: str = "") -> object:
    """Sanitize a response copy, including old error state, without mutating it."""
    if isinstance(value, dict):
        return {key: public_data(item, str(key).lower()) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [public_data(item, field) for item in value]
    if isinstance(value, str):
        if field in ("rpc_url", "blockchain_rpc_url"):
            # Portable public proofs use the verifier's locally configured RPC.
            try:
                parts = urlsplit(value)
            except ValueError:
                return ""
            return value if parts.hostname in ("localhost", "127.0.0.1", "::1") and not parts.username and not parts.query and not parts.path.strip("/") and not parts.fragment else ""
        if field in ("private_key", "sepolia_private_key", "authorization", "api_key", "access_token", "password"):
            return REDACTED
        return safe_error(value) if field in ("error", "anchor_error", "detail") else redact_text(value, diagnostic=field == "reason")
    return value


def public_response(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return public_data(function(*args, **kwargs))
        except Exception as exc:
            # Always cross the public boundary with a fresh safe exception.
            # Checking only the outer message leaves nested causes/contexts
            # visible to logger.exception(), exc_info and traceback rendering.
            raise safe_exception(exc) from None
    return wrapped
