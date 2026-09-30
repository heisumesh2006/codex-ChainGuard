"""Run the Module 1 trust, delegation, attack, and revocation demonstration."""

import json

try:
    from .agents import (
        AGENTS,
        DELEGATION_LEDGER,
        ROOT_AUTHORITY_RECORD,
        ROOT_AUTHORIZER,
        check_permission,
        decommission_agent,
        delegate_permission,
        grant_root_permission,
    )
    from .logger import append_action_log, get_action_log, print_action_log
except ImportError:  # Support running module1/main.py directly.
    from agents import (
        AGENTS,
        DELEGATION_LEDGER,
        ROOT_AUTHORITY_RECORD,
        ROOT_AUTHORIZER,
        check_permission,
        decommission_agent,
        delegate_permission,
        grant_root_permission,
    )
    from logger import append_action_log, get_action_log, print_action_log


ENABLED_ATTACKS = [
    "SELF_ESCALATION",
    "UNAUTHORIZED_DELEGATION",
    "POST_DECOMMISSION_ACTIVITY",
]


def section(title: str) -> None:
    print(f"\n=== {title} ===")


def print_agents() -> None:
    for agent in AGENTS.values():
        print(
            json.dumps(
                {
                    "agent_id": agent.agent_id,
                    "role": agent.role,
                    "status": agent.status,
                    "direct_permissions": agent.direct_permissions,
                    "delegated_permissions": agent.delegated_permissions,
                    "effective_permissions": agent.effective_permissions,
                    "revoked_permissions": agent.revoked_permissions,
                },
                indent=2,
            )
        )


def print_attack(name: str, actor: str, permission: str, result: dict) -> None:
    print(
        f"{name}: actor={actor}, permission={permission}, "
        f"result={result['result']}, reason={result['reason']}"
    )


def simulate_direct_grant(actor_id: str, target_agent_id: str, permission: str) -> dict:
    """Route a simulated grant request according to its claimed authority."""
    if actor_id != ROOT_AUTHORIZER:
        result = {"result": "BLOCKED", "reason": "ROOT_AUTHORITY_REQUIRED"}
        append_action_log(
            actor=actor_id,
            action="SELF_ESCALATION_ATTEMPT",
            claimed_authority=actor_id,
            result="BLOCKED",
            target_agent=target_agent_id,
            permission=permission,
            reason=result["reason"],
        )
        return result
    return grant_root_permission(target_agent_id, permission)


def run_demo() -> None:
    print("=" * 54)
    print("CHAINGUARD-AI | MODULE 1: TRUST AND DELEGATION")
    print("=" * 54)

    section("INITIAL AGENT STATE")
    print_agents()

    section("PERMISSION CHECKS")
    checks = [
        ("Agent_A", "READ_CATALOG"),
        ("Agent_B", "CREATE_ORDER"),
        ("Agent_B", "PROCESS_PAYMENT"),
        ("Agent_C", "PROCESS_PAYMENT"),
        ("Agent_C", "VERIFY_ORDER"),
        ("Agent_D", "VERIFY_ORDER"),
        ("Agent_D", "CREATE_AGENT"),
    ]
    for agent_id, permission in checks:
        result = check_permission(AGENTS[agent_id], permission)
        print(f"{agent_id} / {permission}: {result['result']} ({result['reason']})")
        if result["result"] == "DENIED":
            append_action_log(
                actor=agent_id,
                action=f"CHECK_{permission}",
                claimed_authority=agent_id,
                result="BLOCKED",
                reason=result["reason"],
            )

    section("ROOT AUTHORIZER")
    root_result = grant_root_permission("Agent_A", "CREATE_AGENT")
    assert root_result["result"] == "ALLOWED"
    print(f"{ROOT_AUTHORIZER} -> Agent_A / CREATE_AGENT: {root_result['result']}")

    section("DELEGATION CHAIN")
    for delegator_id, delegatee_id in (("Agent_A", "Agent_B"), ("Agent_B", "Agent_C")):
        result = delegate_permission(AGENTS[delegator_id], AGENTS[delegatee_id], "CREATE_AGENT")
        assert result["result"] == "ALLOWED"
        print(f"{delegator_id} -> {delegatee_id} / CREATE_AGENT: {result['result']}")

    section("DELEGATION LEDGER")
    print(json.dumps(DELEGATION_LEDGER, indent=2))

    section("ROOT AUTHORITY RECORD")
    print(json.dumps(ROOT_AUTHORITY_RECORD, indent=2))

    section("ATTACK TESTING")
    total_attack_attempts = 0
    blocked_attacks = 0

    if "SELF_ESCALATION" in ENABLED_ATTACKS:
        result = simulate_direct_grant("Agent_D", "Agent_D", "CREATE_AGENT")
        total_attack_attempts += 1
        blocked_attacks += result["result"] == "BLOCKED"
        assert result == {"result": "BLOCKED", "reason": "ROOT_AUTHORITY_REQUIRED"}
        assert "CREATE_AGENT" not in AGENTS["Agent_D"].effective_permissions
        print_attack("SELF_ESCALATION", "Agent_D", "CREATE_AGENT", result)

    if "UNAUTHORIZED_DELEGATION" in ENABLED_ATTACKS:
        result = delegate_permission(AGENTS["Agent_D"], AGENTS["Agent_C"], "CREATE_AGENT")
        total_attack_attempts += 1
        blocked_attacks += result["result"] == "BLOCKED"
        assert result == {"result": "BLOCKED", "reason": "PERMISSION_NOT_GRANTED"}
        print_attack("UNAUTHORIZED_DELEGATION", "Agent_D", "CREATE_AGENT", result)

    decommission_result = decommission_agent("Agent_C", reason="Attack simulation")
    assert decommission_result["result"] == "REVOKED"
    print(f"Agent_C decommissioned: {decommission_result['result']}")

    if "POST_DECOMMISSION_ACTIVITY" in ENABLED_ATTACKS:
        check = check_permission(AGENTS["Agent_C"], "CREATE_AGENT")
        result = {"result": "BLOCKED", "reason": check["reason"]}
        append_action_log(
            actor="Agent_C",
            action="POST_DECOMMISSION_ACTIVITY",
            claimed_authority="Agent_C",
            result="BLOCKED",
            permission="CREATE_AGENT",
            reason=check["reason"],
        )
        total_attack_attempts += 1
        blocked_attacks += check["result"] == "DENIED"
        assert check == {"result": "DENIED", "reason": "AGENT_DECOMMISSIONED"}
        print_attack("POST_DECOMMISSION_ACTIVITY", "Agent_C", "CREATE_AGENT", result)

    section("SECURITY SUMMARY")
    detection_rate = 100 * blocked_attacks / total_attack_attempts if total_attack_attempts else 0
    print(f"Total Attack Attempts: {total_attack_attempts}")
    print(f"Blocked Attacks: {blocked_attacks}")
    print(f"Detection Rate: {detection_rate:.2f}%")
    if set(ENABLED_ATTACKS) == {
        "SELF_ESCALATION",
        "UNAUTHORIZED_DELEGATION",
        "POST_DECOMMISSION_ACTIVITY",
    }:
        assert total_attack_attempts == blocked_attacks == 3

    section("FINAL AGENT STATE")
    print_agents()

    section("ACTION LOG")
    print_action_log()

    agent_c = AGENTS["Agent_C"]
    assert agent_c.direct_permissions == []
    assert agent_c.delegated_permissions == []
    assert agent_c.effective_permissions == []
    assert {record["permission"] for record in agent_c.revoked_permissions} == {
        "PROCESS_PAYMENT", "CREATE_AGENT"
    }
    assert any(entry["action"] == "AGENT_DECOMMISSIONED" for entry in get_action_log())
    print("\n=== MODULE 1 COMPLETED SUCCESSFULLY ===")


if __name__ == "__main__":
    run_demo()
