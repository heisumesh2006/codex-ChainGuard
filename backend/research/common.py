"""Local-only fixtures and immutable baseline source loading."""

from contextlib import contextmanager, ExitStack
from copy import deepcopy
import subprocess
import sys
import types
from unittest.mock import patch
from backend.core.authorization import agents as a
from backend.core.authorization.logger import ACTION_LOG
from backend.core.authorization.demo_identity import DemoIdentity

BASE = "f3b4574cb726264d9d6d01988e0d64940ae8c148"


@contextmanager
def local_policy():
    saved_verifier = a._policy_verifier
    saved = deepcopy((a.AGENTS, a.ROOT_AUTHORITY_RECORD, a.DELEGATION_LEDGER, ACTION_LOG))
    a.AGENTS.clear(); a.AGENTS.update({"Agent_" + n: a.Agent("Agent_" + n, "experiment") for n in "ABCD"})
    a.ROOT_AUTHORITY_RECORD.clear(); a.DELEGATION_LEDGER.clear(); ACTION_LOG.clear()
    try:
        with DemoIdentity() as identity:
            # This fixture deliberately starts with no bootstrap permissions.
            # Select its realm before any operation can refresh policy state.
            a._policy_verifier = identity.verifier
            yield identity
    finally:
        a.AGENTS.clear(); a.AGENTS.update(saved[0])
        a.ROOT_AUTHORITY_RECORD[:] = saved[1]; a.DELEGATION_LEDGER[:] = saved[2]; ACTION_LOG[:] = saved[3]
        a._policy_verifier = saved_verifier


def root_grant(identity, target="Agent_A", permission="P"):
    return a.grant_root_permission(target, permission, **identity.credentials("ROOT_AUTHORIZER", "root_grant",
        {"agent_id": target, "permission": permission, "expires_at": None}))


def delegate(identity, parent, child, permission="P"):
    return a.delegate_permission(a.AGENTS[parent], a.AGENTS[child], permission,
        **identity.credentials(parent, "delegate", {"delegator": parent, "delegatee": child,
                                                   "permission": permission, "expires_at": None}))


def revoke(identity, target):
    return a.decommission_agent(target, reason="controlled experiment", **identity.credentials(
        "ROOT_AUTHORIZER", "decommission", {"agent_id": target, "reason": "controlled experiment"}))


def original_module():
    source = subprocess.check_output(["git", "show", BASE + ":backend/core/authorization/agents.py"], text=True)
    module = types.ModuleType("chainguard_preserved_reference")
    module.__package__ = "backend.core.authorization"
    sys.modules[module.__name__] = module
    exec(compile(source, BASE + ":agents.py", "exec"), module.__dict__)
    module.AGENTS.clear(); module.AGENTS.update({"Agent_" + n: module.Agent("Agent_" + n, "experiment") for n in "ABCD"})
    module.ROOT_AUTHORITY_RECORD.clear(); module.DELEGATION_LEDGER.clear()
    return module


@contextmanager
def local_registry(folder):
    from backend.core.blockchain import chain
    if chain.NETWORK_PROFILE != "hardhat" or chain.connect().eth.chain_id != 31337:
        raise RuntimeError("EXPERIMENTS_REQUIRE_LOCAL_HARDHAT_31337")
    with ExitStack() as stack:
        for name, filename in (("STATE_PATH", "state.json"), ("DEPLOYMENT_PATH", "deployment.json"),
                               ("CREDENTIALS_PATH", "credentials.json")):
            stack.enter_context(patch.object(chain, name, folder / filename))
        chain.deploy_registry()
        yield chain.contract_context()
