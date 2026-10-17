"""Explicit isolated demonstration/test identities; never a production fallback.

Random keys live only in this object's memory and are never printed/persisted.
The independent realm cannot authenticate to the deployed public registry.
"""

from pathlib import Path
import tempfile
from uuid import uuid4
from eth_account import Account
from .authentication import RequestVerifier, sign_request


class DemoIdentity:
    def __init__(self):
        self.folder = tempfile.TemporaryDirectory(prefix="chainguard-signers-")
        self.accounts = {name: Account.create() for name in
                         ("ROOT_AUTHORIZER", "Agent_A", "Agent_B", "Agent_C", "Agent_D")}
        addresses = {k: v.address for k, v in self.accounts.items()}
        self.verifier = RequestVerifier("isolated-demo:" + uuid4().hex,
                                       addresses.__getitem__,
                                       Path(self.folder.name) / "nonces.json")

    def credentials(self, actor, operation, payload):
        extra = {}
        if operation == "delegate" and "parent_grant_id" not in payload:
            from .agents import authority_paths
            paths = authority_paths(payload["delegator"], payload["permission"])
            parent_id = paths[0][-1] if paths else None
            payload = {**payload, "parent_grant_id": parent_id}
            extra["parent_grant_id"] = parent_id
        return {"authentication": sign_request(self.accounts[actor], self.verifier.domain,
                                                actor, operation, payload),
                "verifier": self.verifier, **extra}

    def close(self):
        self.accounts.clear()
        self.folder.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
