"""Agents, root grants, delegation, and local credential revocation."""

from dataclasses import dataclass, field
from typing import Literal
from uuid import uuid4

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
        return list(dict.fromkeys(permissions))


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


def check_permission(agent: Agent, requested_permission: str) -> dict:
    """Check current authorization without changing state or writing a log."""
    if agent.status != "ACTIVE":
        return {"result": "DENIED", "reason": "AGENT_DECOMMISSIONED"}
    if requested_permission not in agent.effective_permissions:
        return {"result": "DENIED", "reason": "PERMISSION_NOT_GRANTED"}
    return {"result": "ALLOWED", "reason": None}


def grant_root_permission(agent_id: str, permission: str) -> dict:
    """Root-only grant entry point; calls to this function originate at the root."""
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

    append_action_log(
        actor=ROOT_AUTHORIZER,
        action="ROOT_PERMISSION_GRANTED",
        claimed_authority=ROOT_AUTHORIZER,
        result="ALLOWED",
        target_agent=agent_id,
        permission=permission,
    )
    return {"result": "ALLOWED", "reason": None}


def delegate_permission(delegator_agent: Agent, delegatee_agent: Agent, permission: str) -> dict:
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
            "record_id": f"delegation:{uuid4()}",
            "delegator": delegator_agent.agent_id,
            "delegatee": delegatee_agent.agent_id,
            "permission": permission,
            "authority_source": authority_source,
            "status": "ACTIVE",
            "timestamp": logged["timestamp"],
        }
    )
    return {"result": "ALLOWED", "reason": None}


def decommission_agent(
    agent_id: str, revoked_by: str = ROOT_AUTHORIZER, reason: str | None = None
) -> dict:
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
    for delegation in DELEGATION_LEDGER:
        if delegation["delegatee"] == agent_id:
            delegation["status"] = "REVOKED"

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
