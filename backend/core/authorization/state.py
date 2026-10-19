"""Profile/registry-specific atomic snapshots for mutable local authority.

Nonce consumption and policy publication are separate durable operations. A
crash between them requires a NEW signed request; it cannot replay an old one.
This file is enforcement state, not independently anchored blockchain evidence.
"""

from dataclasses import asdict
from copy import deepcopy
from functools import wraps
import hashlib
import inspect
import json

from backend.core.blockchain.persistence import FileLock, atomic_write
from backend.core.blockchain.evidence import decode_json, EvidenceError
from .authentication import canonical, authenticated_operation, registered_verifier


def _path(verifier):
    return verifier.path.parent / ("authorization_state_" + hashlib.sha256(verifier.domain.encode()).hexdigest()[:24] + ".json")


def _string_list(value):
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _grant_shape(grant):
    return (isinstance(grant, dict) and isinstance(grant.get("record_id"), str)
            and grant.get("status") in ("ACTIVE", "REVOKED")
            and isinstance(grant.get("issued_at"), str)
            and (grant.get("expires_at") is None or isinstance(grant["expires_at"], str))
            and isinstance(grant.get("authentication"), dict))


def _read(verifier):
    from . import agents as a
    path = _path(verifier)
    if not path.exists():
        previous = a._policy_verifier
        if previous is not None and previous.domain != verifier.domain:
            # A different registry/realm cannot inherit this worker's mutable
            # authority. Only immutable application bootstrap policy survives;
            # it is trusted configuration, not a claim of blockchain proof.
            for agent in a.AGENTS.values():
                agent.status = "ACTIVE"
                agent.direct_permissions = sorted(permission for holder, permission in a._BOOTSTRAP_PERMISSIONS
                                                   if holder == agent.agent_id)
                agent.delegated_permissions = []
                agent.revoked_permissions = []
            a.ROOT_AUTHORITY_RECORD[:] = [
                {"granted_to": agent.agent_id, "permissions": agent.direct_permissions.copy()}
                for agent in a.AGENTS.values() if agent.direct_permissions]
            a.DELEGATION_LEDGER.clear()
            from .logger import ACTION_LOG
            ACTION_LOG.clear()
        a._policy_verifier = verifier
        return
    try:
        state = decode_json(path.read_text(encoding="utf-8"))
        if state["domain"] != verifier.domain or not isinstance(state["agents"], dict):
            raise ValueError()
        loaded = {}
        for key, value in state["agents"].items():
            if (not isinstance(key, str) or value["agent_id"] != key
                    or value["status"] not in ("ACTIVE", "DECOMMISSIONED")
                    or not isinstance(value.get("role"), str)
                    or not _string_list(value.get("direct_permissions"))
                    or not isinstance(value.get("delegated_permissions"), list)
                    or not isinstance(value.get("revoked_permissions"), list)):
                raise ValueError()
            for grant in value["delegated_permissions"]:
                if not isinstance(grant, dict) or any(not isinstance(grant.get(field), str)
                        for field in ("permission", "delegator", "authority_source")):
                    raise ValueError()
            if any(not isinstance(grant, dict) or not isinstance(grant.get("permission"), str)
                   for grant in value["revoked_permissions"]):
                raise ValueError()
            loaded[key] = a.Agent(**value)
        roots, grants = state["root_grants"], state["delegations"]
        if not isinstance(roots, list) or not isinstance(grants, list):
            raise ValueError()
        for root in roots:
            if (not isinstance(root, dict) or root.get("granted_to") not in loaded
                    or not _string_list(root.get("permissions"))):
                raise ValueError()
            values = root.get("grants", {})
            if not isinstance(values, dict) or any(not isinstance(key, str) or not _grant_shape(grant)
                                                   for key, grant in values.items()):
                raise ValueError()
            history = root.get("grant_history", [])
            if (not isinstance(history, list) or any(not _grant_shape(grant)
                    or not isinstance(grant.get("permission"), str) for grant in history)):
                raise ValueError()
        for grant in grants:
            if (not _grant_shape(grant) or any(not isinstance(grant.get(field), str)
                    for field in ("delegator", "delegatee", "permission", "authority_source", "timestamp"))
                    or grant["delegator"] not in loaded or grant["delegatee"] not in loaded
                    or not isinstance(grant.get("parent_grant_id"), str)):
                raise ValueError()
    except (KeyError, TypeError, ValueError, UnicodeError, OSError):
        raise EvidenceError("AUTHORITY_STATE_CORRUPT") from None
    a._policy_verifier = verifier
    # Preserve references held by the trusted caller; never accept a clone's
    # caller-supplied state as the registered agent object.
    for key in set(a.AGENTS) - set(loaded):
        del a.AGENTS[key]
    for key, agent in loaded.items():
        if key in a.AGENTS:
            a.AGENTS[key].__dict__.update(agent.__dict__)
        else:
            a.AGENTS[key] = agent
    a.ROOT_AUTHORITY_RECORD[:] = roots
    a.DELEGATION_LEDGER[:] = grants


def refresh_policy(verifier):
    with FileLock(str(_path(verifier)) + ".lock"):
        _read(verifier)


def _snapshot():
    from . import agents as a
    from .logger import ACTION_LOG
    # Keep the actual registered objects so a failed operation cannot detach a
    # caller's trusted Agent reference from the restored registry.
    return (dict(a.AGENTS), {key: deepcopy(agent.__dict__) for key, agent in a.AGENTS.items()},
            deepcopy(a.ROOT_AUTHORITY_RECORD), deepcopy(a.DELEGATION_LEDGER), deepcopy(ACTION_LOG))


def _restore(snapshot):
    from . import agents as a
    from .logger import ACTION_LOG
    objects, values, roots, delegations, actions = snapshot
    a.AGENTS.clear()
    a.AGENTS.update(objects)
    for key, agent in objects.items():
        agent.__dict__.clear()
        agent.__dict__.update(values[key])
    a.ROOT_AUTHORITY_RECORD[:] = roots
    a.DELEGATION_LEDGER[:] = delegations
    ACTION_LOG[:] = actions


def coordinated_policy(operation, actor_field, payload_fields):
    def decorate(function):
        signature = inspect.signature(function)
        @wraps(function)
        def wrapped(*args, **kwargs):
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            fields = bound.arguments
            envelope = fields.get("authentication")
            if envelope is None:
                # The function also checks for an already-verified, exactly
                # matching internal revocation operation.
                return function(*args, **kwargs)
            verifier = fields.get("verifier") or registered_verifier()
            actor = actor_field(fields)
            payload = payload_fields(fields)
            with authenticated_operation(envelope, operation, payload, actor, verifier):
                path = _path(verifier)
                with FileLock(str(path) + ".lock"):
                    _read(verifier)
                    previous = _snapshot()
                    encoded = None
                    try:
                        result = function(*args, **kwargs)
                        from . import agents as a
                        state = {"domain": verifier.domain, "agents": {k: asdict(v) for k, v in a.AGENTS.items()},
                                 "root_grants": a.ROOT_AUTHORITY_RECORD, "delegations": a.DELEGATION_LEDGER}
                        encoded = canonical(state)
                        atomic_write(path, encoded)
                        return result
                    except BaseException:
                        # An unpublished mutation must not remain usable by
                        # this worker. Nonce consumption stays durable: retry
                        # with a new signed request after storage recovers.
                        # Atomic replacement can commit before a later fsync/
                        # cleanup error. Reload the complete durable snapshot
                        # rather than reviving permissions revoked by that
                        # committed operation. The caller still receives the
                        # failure and must inspect state before a new request.
                        try:
                            committed = encoded is not None and path.read_bytes() == encoded
                        except OSError:
                            committed = False
                        if not committed:
                            _restore(previous)
                            if path.exists():
                                _read(verifier)
                        raise
        return wrapped
    return decorate
