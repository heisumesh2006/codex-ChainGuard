"""Agents, root grants, delegation, and local credential revocation."""

from dataclasses import dataclass, field
from copy import deepcopy
from typing import Literal
from uuid import uuid4
from datetime import datetime, timezone
import hashlib
from .authentication import authenticate, AuthenticationError
from .authentication import canonical
from .state import coordinated_policy

try:
    from .logger import append_action_log, current_timestamp
except ImportError:  # Support running this file directly.
    from logger import append_action_log, current_timestamp


ROOT_AUTHORIZER = "ROOT_AUTHORIZER"


@dataclass
class Agent:
    agent_id: str
    role: str
    status: Literal["ACTIVE", "DECOMMISSIONED"] = "ACTIVE"
    direct_permissions: list[str] = field(default_factory=list)
    delegated_permissions: list[dict] = field(default_factory=list)
    revoked_permissions: list[dict] = field(default_factory=list)

    @property
    def effective_permissions(self) -> list[str]:
        permissions = self.direct_permissions + [
            delegation["permission"] for delegation in self.delegated_permissions
        ]
        return [permission for permission in dict.fromkeys(permissions)
                if authority_paths(self.agent_id, permission)]


AGENTS: dict[str, Agent] = {
    "Agent_A": Agent("Agent_A", "Coordinator"),
    "Agent_B": Agent(
        "Agent_B", "Purchase Agent", direct_permissions=["READ_CATALOG", "CREATE_ORDER"]
    ),
    "Agent_C": Agent("Agent_C", "Payment Agent", direct_permissions=["PROCESS_PAYMENT"]),
    "Agent_D": Agent("Agent_D", "Verification Agent", direct_permissions=["VERIFY_ORDER"]),
}

# Initial direct permissions are trusted root-issued credentials. Their records
# exist from initialization, while the demo grant to Agent_A is logged at runtime.
ROOT_AUTHORITY_RECORD: list[dict] = [
    {"granted_to": agent.agent_id, "permissions": agent.direct_permissions.copy()}
    for agent in AGENTS.values()
    if agent.direct_permissions
]
DELEGATION_LEDGER: list[dict] = []
_policy_verifier = None
_BOOTSTRAP_PERMISSIONS = frozenset((record["granted_to"], permission)
                                  for record in ROOT_AUTHORITY_RECORD for permission in record["permissions"])


def _authenticated_grant(grant, agent_id, permission, parent=None):
    envelope = grant.get("authentication")
    if envelope is None:
        return parent is None and (agent_id, permission) in _BOOTSTRAP_PERMISSIONS and grant.get("record_id") == f"initial:{agent_id}:{permission}"
    if _policy_verifier is None:
        return False
    if not isinstance(envelope, dict) or type(envelope.get("issued_at")) is not int:
        return False
    prefix = "grant:" if parent is None else "delegation:"
    try:
        expected_id = prefix + hashlib.sha256(canonical(envelope)).hexdigest()
        issued_at = datetime.fromtimestamp(envelope["issued_at"], timezone.utc).isoformat()
    except (ValueError, TypeError, OverflowError, OSError):
        return False
    if grant.get("record_id") != expected_id or grant.get("issued_at") != issued_at:
        return False
    operation = "root_grant" if parent is None else "delegate"
    actor = ROOT_AUTHORIZER if parent is None else parent
    payload = ({"agent_id": agent_id, "permission": permission, "expires_at": grant.get("expires_at")}
               if parent is None else {"delegator": parent, "delegatee": agent_id,
                                        "permission": permission, "expires_at": grant.get("expires_at"),
                                        "parent_grant_id": grant.get("parent_grant_id")})
    return _policy_verifier.verify_grant(envelope, operation, payload, actor)


def _time(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Authority timestamps require a timezone")
    return parsed.astimezone(timezone.utc)


def _window(record, when):
    try:
        return (_time(record.get("issued_at", record.get("timestamp", "1970-01-01T00:00:00Z"))) <= when
                and (not record.get("expires_at") or when < _time(record["expires_at"])))
    except (ValueError, TypeError, AttributeError):
        return False


def authority_paths(agent_id, permission, *, at_time=None, visited=frozenset()):
    """All live, grant-specific paths. A revoked parent never authorizes a child.

    Independent grants remain independent. Newly delegated grants bind the
    chosen parent record; they cannot migrate silently to a later re-grant.
    """
    try:
        when = _time(at_time) if at_time else datetime.now(timezone.utc)
    except (ValueError, TypeError, AttributeError):
        return []
    if agent_id in visited or agent_id not in AGENTS:
        return []
    agent = AGENTS[agent_id]
    if agent.status != "ACTIVE":
        return []
    paths = []
    for root in ROOT_AUTHORITY_RECORD:
        if root["granted_to"] == agent_id and permission in root["permissions"]:
            grants = root.get("grants", {})
            grant = grants.get(permission, {"record_id": f"initial:{agent_id}:{permission}"})
            if (grant.get("status", "ACTIVE") == "ACTIVE" and _window(grant, when)
                    and _authenticated_grant(grant, agent_id, permission)):
                paths.append([grant["record_id"]])
    for grant in DELEGATION_LEDGER:
        if (grant["delegatee"] != agent_id or grant["permission"] != permission
                or grant.get("status") != "ACTIVE" or not _window(grant, when)):
            continue
        if not _authenticated_grant(grant, agent_id, permission, grant["delegator"]):
            continue
        parents = authority_paths(grant["delegator"], permission, at_time=when.isoformat(),
                                  visited=visited | {agent_id})
        for path in parents:
            if grant.get("parent_grant_id") and path[-1] != grant["parent_grant_id"]:
                continue
            paths.append(path + [grant["record_id"]])
    return paths


def check_permission(agent: Agent, requested_permission: str) -> dict:
    """Check current authorization without changing state or writing a log."""
    if agent.status != "ACTIVE":
        return {"result": "DENIED", "reason": "AGENT_DECOMMISSIONED"}
    if not authority_paths(agent.agent_id, requested_permission):
        return {"result": "DENIED", "reason": "PERMISSION_NOT_GRANTED"}
    return {"result": "ALLOWED", "reason": None}


@coordinated_policy("root_grant", lambda f: f["requester"], lambda f: {
    "agent_id": f["agent_id"], "permission": f["permission"], "expires_at": f["expires_at"]})
def grant_root_permission(agent_id: str, permission: str, *, requester=ROOT_AUTHORIZER,
                          authentication=None, verifier=None, expires_at=None) -> dict:
    """Require the registered root key, bound to this exact grant and nonce."""
    payload = {"agent_id": agent_id, "permission": permission, "expires_at": expires_at}
    principal = authenticate(authentication, "root_grant", payload, requester, verifier)
    if principal.actor != ROOT_AUTHORIZER:
        return {"result": "BLOCKED", "reason": "ROOT_AUTHORITY_REQUIRED"}
    if expires_at is not None and _time(expires_at) <= datetime.now(timezone.utc):
        return {"result": "BLOCKED", "reason": "CREDENTIAL_EXPIRED"}
    agent = AGENTS[agent_id]
    if agent.status != "ACTIVE":
        append_action_log(
            actor=ROOT_AUTHORIZER,
            action="ROOT_PERMISSION_GRANTED",
            claimed_authority=ROOT_AUTHORIZER,
            result="BLOCKED",
            target_agent=agent_id,
            permission=permission,
            reason="AGENT_DECOMMISSIONED",
        )
        return {"result": "BLOCKED", "reason": "AGENT_DECOMMISSIONED"}

    if permission not in agent.direct_permissions:
        agent.direct_permissions.append(permission)
    root_record = next(
        (record for record in ROOT_AUTHORITY_RECORD if record["granted_to"] == agent_id),
        None,
    )
    if root_record is None:
        root_record = {"granted_to": agent_id, "permissions": []}
        ROOT_AUTHORITY_RECORD.append(root_record)
    if permission not in root_record["permissions"]:
        root_record["permissions"].append(permission)
    grant = root_record.setdefault("grants", {}).get(permission)
    if (grant and grant.get("status") == "ACTIVE" and _window(grant, datetime.now(timezone.utc))
            and _authenticated_grant(grant, agent_id, permission)):
        if ((None if grant.get("expires_at") is None else _time(grant["expires_at"]))
                != (None if expires_at is None else _time(expires_at))):
            return {"result": "BLOCKED", "reason": "EXISTING_GRANT_DIFFERS"}
        return {"result": "ALLOWED", "reason": "EXISTING_GRANT"}
    if grant:
        # Renewal never destroys the signed evidence for an older grant.
        root_record.setdefault("grant_history", []).append({"permission": permission, **deepcopy(grant)})
    root_record["grants"][permission] = {
        "record_id": "grant:" + hashlib.sha256(canonical(authentication)).hexdigest(),
        "issued_at": datetime.fromtimestamp(authentication["issued_at"], timezone.utc).isoformat(),
        "expires_at": expires_at, "status": "ACTIVE", "authentication": authentication,
    }

    append_action_log(
        actor=ROOT_AUTHORIZER,
        action="ROOT_PERMISSION_GRANTED",
        claimed_authority=ROOT_AUTHORIZER,
        result="ALLOWED",
        target_agent=agent_id,
        permission=permission,
    )
    return {"result": "ALLOWED", "reason": None}


@coordinated_policy("delegate", lambda f: f["delegator_agent"].agent_id, lambda f: {
    "delegator": f["delegator_agent"].agent_id, "delegatee": f["delegatee_agent"].agent_id,
    "permission": f["permission"], "expires_at": f["expires_at"], "parent_grant_id": f["parent_grant_id"]})
def delegate_permission(delegator_agent: Agent, delegatee_agent: Agent, permission: str, *,
                        authentication=None, verifier=None, expires_at=None, parent_grant_id=None) -> dict:
    payload = {"delegator": delegator_agent.agent_id, "delegatee": delegatee_agent.agent_id,
               "permission": permission, "expires_at": expires_at, "parent_grant_id": parent_grant_id}
    authenticate(authentication, "delegate", payload, delegator_agent.agent_id, verifier)
    # Only registered objects may be used, not caller-constructed active clones.
    if (AGENTS.get(delegator_agent.agent_id) is not delegator_agent
            or AGENTS.get(delegatee_agent.agent_id) is not delegatee_agent):
        return {"result": "BLOCKED", "reason": "UNKNOWN_AGENT"}
    if delegator_agent.agent_id == delegatee_agent.agent_id:
        return {"result": "BLOCKED", "reason": "SELF_DELEGATION"}
    if expires_at is not None and _time(expires_at) <= datetime.now(timezone.utc):
        return {"result": "BLOCKED", "reason": "CREDENTIAL_EXPIRED"}
    # Reject cycles in effective authenticated authority, not expired or
    # otherwise invalid local rows that could deny a legitimate new grant.
    live_grants = {path[-1] for agent_id in AGENTS
                   for path in authority_paths(agent_id, permission)}
    descendants = {delegatee_agent.agent_id}
    for _ in range(len(AGENTS)):
        descendants |= {g["delegatee"] for g in DELEGATION_LEDGER
                        if g["delegator"] in descendants and g.get("status") == "ACTIVE"
                        and g["permission"] == permission and g["record_id"] in live_grants}
    if delegator_agent.agent_id in descendants:
        return {"result": "BLOCKED", "reason": "CIRCULAR_DELEGATION"}
    authorization = check_permission(delegator_agent, permission)
    if authorization["result"] != "ALLOWED":
        reason = authorization["reason"]
        append_action_log(
            actor=delegator_agent.agent_id,
            action="UNAUTHORIZED_DELEGATION_ATTEMPT",
            claimed_authority=delegator_agent.agent_id,
            result="BLOCKED",
            delegatee=delegatee_agent.agent_id,
            permission=permission,
            reason=reason,
        )
        return {"result": "BLOCKED", "reason": reason}

    if delegatee_agent.status != "ACTIVE":
        append_action_log(
            actor=delegator_agent.agent_id,
            action=f"DELEGATE_{permission}",
            claimed_authority=delegator_agent.agent_id,
            result="BLOCKED",
            delegatee=delegatee_agent.agent_id,
            reason="AGENT_DECOMMISSIONED",
        )
        return {"result": "BLOCKED", "reason": "AGENT_DECOMMISSIONED"}

    if permission in delegator_agent.direct_permissions:
        root_record = next(
            (
                record
                for record in ROOT_AUTHORITY_RECORD
                if record["granted_to"] == delegator_agent.agent_id
                and permission in record["permissions"]
            ),
            None,
        )
        if root_record is None:
            append_action_log(
                actor=delegator_agent.agent_id,
                action=f"DELEGATE_{permission}",
                claimed_authority=delegator_agent.agent_id,
                result="BLOCKED",
                delegatee=delegatee_agent.agent_id,
                reason="ROOT_AUTHORITY_REQUIRED",
            )
            return {"result": "BLOCKED", "reason": "ROOT_AUTHORITY_REQUIRED"}
        authority_source = ROOT_AUTHORIZER
    else:
        source_record = next(
            (
                record
                for record in delegator_agent.delegated_permissions
                if record["permission"] == permission
                and record["authority_source"] == ROOT_AUTHORIZER
            ),
            None,
        )
        if source_record is None:
            append_action_log(
                actor=delegator_agent.agent_id,
                action=f"DELEGATE_{permission}",
                claimed_authority=delegator_agent.agent_id,
                result="BLOCKED",
                delegatee=delegatee_agent.agent_id,
                reason="ROOT_AUTHORITY_REQUIRED",
            )
            return {"result": "BLOCKED", "reason": "ROOT_AUTHORITY_REQUIRED"}
        authority_source = source_record["authority_source"]

    parent_path = next((path for path in authority_paths(delegator_agent.agent_id, permission)
                        if path[-1] == parent_grant_id), None)
    if parent_path is None:
        return {"result": "BLOCKED", "reason": "PARENT_GRANT_BINDING_REQUIRED"}
    parent = next((g for root in ROOT_AUTHORITY_RECORD for g in root.get("grants", {}).values()
                   if g["record_id"] == parent_path[-1]), None)
    if parent is None:
        parent = next((g for g in DELEGATION_LEDGER if g["record_id"] == parent_path[-1]), None)
    if (expires_at is not None and parent and parent.get("expires_at")
            and _time(expires_at) > _time(parent["expires_at"])):
        return {"result": "BLOCKED", "reason": "CHILD_EXPIRY_EXCEEDS_PARENT"}
    existing = next((g for g in DELEGATION_LEDGER if g["delegator"] == delegator_agent.agent_id
                     and g["delegatee"] == delegatee_agent.agent_id and g["permission"] == permission
                     and g.get("parent_grant_id") == parent_path[-1] and g["status"] == "ACTIVE"
                     and _window(g, datetime.now(timezone.utc))
                     and _authenticated_grant(g, delegatee_agent.agent_id, permission,
                                              delegator_agent.agent_id)), None)
    if existing:
        if ((None if existing.get("expires_at") is None else _time(existing["expires_at"]))
                != (None if expires_at is None else _time(expires_at))):
            return {"result": "BLOCKED", "reason": "EXISTING_GRANT_DIFFERS"}
        return {"result": "ALLOWED", "reason": "EXISTING_GRANT"}
    delegation = {
        "permission": permission,
        "delegator": delegator_agent.agent_id,
        "authority_source": authority_source,
    }
    delegatee_agent.delegated_permissions.append(delegation)
    logged = append_action_log(
        actor=delegator_agent.agent_id,
        action=f"DELEGATE_{permission}",
        claimed_authority=authority_source,
        result="ALLOWED",
        delegatee=delegatee_agent.agent_id,
    )
    DELEGATION_LEDGER.append(
        {
            "record_id": "delegation:" + hashlib.sha256(canonical(authentication)).hexdigest(),
            "delegator": delegator_agent.agent_id,
            "delegatee": delegatee_agent.agent_id,
            "permission": permission,
            "authority_source": authority_source,
            "status": "ACTIVE",
            "timestamp": logged["timestamp"],
            "issued_at": datetime.fromtimestamp(authentication["issued_at"], timezone.utc).isoformat(),
            "expires_at": expires_at,
            "parent_grant_id": parent_path[-1],
            "authentication": authentication,
        }
    )
    return {"result": "ALLOWED", "reason": None}


@coordinated_policy("decommission", lambda f: f["revoked_by"], lambda f: {
    "agent_id": f["agent_id"], "reason": f["reason"]})
def decommission_agent(
    agent_id: str, revoked_by: str = ROOT_AUTHORIZER, reason: str | None = None, *,
    authentication=None, verifier=None,
) -> dict:
    authenticate(authentication, "decommission", {"agent_id": agent_id, "reason": reason},
                 revoked_by, verifier)
    # Module 1 permits only root-initiated full decommissioning. Module 5 may
    # extend the authorized revoker policy; this constraint is intentional here.
    if revoked_by != ROOT_AUTHORIZER:
        append_action_log(
            actor=revoked_by,
            action="AGENT_DECOMMISSION_ATTEMPT",
            claimed_authority=revoked_by,
            result="BLOCKED",
            decommissioned_agent=agent_id,
            reason="ROOT_AUTHORITY_REQUIRED",
        )
        return {"result": "BLOCKED", "reason": "ROOT_AUTHORITY_REQUIRED"}

    agent = AGENTS[agent_id]
    if agent.status == "DECOMMISSIONED":
        append_action_log(
            actor=revoked_by,
            action="AGENT_DECOMMISSION_ATTEMPT",
            claimed_authority=revoked_by,
            result="BLOCKED",
            decommissioned_agent=agent_id,
            reason="AGENT_DECOMMISSIONED",
        )
        return {"result": "BLOCKED", "reason": "AGENT_DECOMMISSIONED"}

    previous_permissions = agent.effective_permissions.copy()
    decommissioned_at = current_timestamp()
    agent.revoked_permissions.extend(
        {
            "permission": permission,
            "revoked_at": decommissioned_at,
            "revoked_by": revoked_by,
        }
        for permission in previous_permissions
    )
    agent.direct_permissions = []
    agent.delegated_permissions = []
    agent.status = "DECOMMISSIONED"
    for root in ROOT_AUTHORITY_RECORD:
        if root["granted_to"] == agent_id:
            for grant in root.get("grants", {}).values():
                grant.update(status="REVOKED", revoked_at=decommissioned_at)
    for delegation in DELEGATION_LEDGER:
        if agent_id in (delegation["delegatee"], delegation["delegator"]):
            delegation["status"] = "REVOKED"
            delegation["revoked_at"] = decommissioned_at
    # Cascade by grant ancestry, never by globally decommissioning descendants.
    # A descendant's independent direct or other-parent authority survives.
    revoked_ids = {g["record_id"] for g in DELEGATION_LEDGER if g["status"] == "REVOKED"}
    for _ in range(len(DELEGATION_LEDGER)):
        for grant in DELEGATION_LEDGER:
            if grant.get("parent_grant_id") in revoked_ids and grant["status"] == "ACTIVE":
                grant.update(status="REVOKED", revoked_at=decommissioned_at,
                             revocation_reason="ANCESTOR_REVOKED")
                revoked_ids.add(grant["record_id"])

    append_action_log(
        actor=revoked_by,
        action="AGENT_DECOMMISSIONED",
        claimed_authority=revoked_by,
        result="REVOKED",
        decommissioned_agent=agent_id,
        previous_permissions=previous_permissions,
        revoked_permissions=agent.revoked_permissions.copy(),
        decommissioned_at=decommissioned_at,
        reason=reason,
    )
    return {"result": "REVOKED", "reason": None}
