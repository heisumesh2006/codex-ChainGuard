"""Reproducible behavioral experiment data, with labels kept out of actions."""

from collections import Counter
from datetime import datetime, timedelta, timezone
import random

from backend.core.authorization.agents import AGENTS
from backend.core.blockchain import chain
from backend.core.tracing.tracer import trace_agent_authority, trace_action

RANDOM_SEED = 42
CATEGORIES = ("SELF_ESCALATION", "UNAUTHORIZED_DELEGATION", "POST_DECOMMISSION_ACTIVITY", "SCOPE_CREEP")


def build_agent_profiles() -> dict[str, dict]:
    """Take role expectations from Module 1 and authority evidence from Module 3."""
    definitions = {
        "Agent_A": ("CREATE_AGENT", 17, (9, 17)),
        "Agent_B": ("READ_CATALOG", 17, (8, 18)),
        "Agent_C": ("PROCESS_PAYMENT", 17, (9, 19)),
        "Agent_D": ("VERIFY_ORDER", 17, (8, 17)),
    }
    profiles = {}
    for agent_id, (primary, daily_rate, hours) in definitions.items():
        expected = list(AGENTS[agent_id].direct_permissions)
        if agent_id == "Agent_A":
            expected = ["CREATE_AGENT"]
        if agent_id == "Agent_C":
            expected = ["PROCESS_PAYMENT"]  # Current Module 1 state may be decommissioned.
        authorized = list(dict.fromkeys(expected + (["CREATE_AGENT"] if agent_id in ("Agent_B", "Agent_C") else [])))
        traces = {permission: trace_agent_authority(agent_id, permission) for permission in authorized}
        profiles[agent_id] = {
            "agent_id": agent_id,
            "role": AGENTS[agent_id].role,
            "normal_action_types": ["USE_PERMISSION"] + (["DELEGATE_CREATE_AGENT"] if agent_id in ("Agent_A", "Agent_B") else []),
            "expected_role_permissions": expected,
            "authorized_permissions": authorized,
            "expected_delegation_depth": max((len(t["chain"]) - 1 for t in traces.values() if t["valid"]), default=0),
            "normal_activity_frequency_per_day": daily_rate,
            "typical_hours_utc": list(hours),
            "primary_permission": primary,
            "authority_traces": traces,
        }
    return profiles


def _attack_traces() -> tuple[dict[str, dict], datetime]:
    records = [entry["source"] for entry in chain.load_state()["records"].values() if entry["kind"] == "action"]
    actions = {entry["action"]: entry for entry in records}
    traces = {
        "SELF_ESCALATION": trace_action(actions["SELF_ESCALATION_ATTEMPT"]),
        "UNAUTHORIZED_DELEGATION": trace_action(actions["UNAUTHORIZED_DELEGATION_ATTEMPT"]),
        "POST_DECOMMISSION_ACTIVITY": trace_action(actions["POST_DECOMMISSION_ACTIVITY"]),
    }
    revoked_at = datetime.fromisoformat(actions["AGENT_DECOMMISSIONED"]["decommissioned_at"])
    return traces, revoked_at


def generate_synthetic_logs(agent_profiles, n_normal_per_agent, n_anomalies_per_type):
    """Return parallel action and label lists. Model features never receive labels."""
    rng = random.Random(RANDOM_SEED)
    attack_traces, revoked_at = _attack_traces()
    # Agent_C's baseline is historical; the others' delegated behavior follows
    # issuance. Module 3 authority snapshots describe those real chain paths.
    base = (revoked_at + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    historical_base = (revoked_at - timedelta(days=35)).replace(hour=0, minute=0, second=0, microsecond=0)
    pairs = []
    serial = 0

    def add(actor, action, permission, when, trace, label, category, target="order"):
        nonlocal serial
        serial += 1
        log = {
            "record_id": f"synthetic:{serial:06d}", "actor": actor, "action": action,
            "timestamp": when.isoformat(), "claimed_authority": actor,
            "result": "ALLOWED" if label == 0 or category == "SCOPE_CREEP" else "BLOCKED",
            "permission": permission, "target": target,
            "trace_result": {"valid": trace["valid"], "verdict": trace["verdict"], "chain": trace["chain"]},
        }
        pairs.append((log, {"label": label, "category": category}))

    for agent_id, profile in agent_profiles.items():
        start_hour, end_hour = profile["typical_hours_utc"]
        for i in range(n_normal_per_agent):
            day = i * 30 // max(1, n_normal_per_agent)
            agent_base = historical_base if agent_id == "Agent_C" else base
            when = agent_base + timedelta(days=day, hours=rng.randrange(start_hour, end_hour), minutes=rng.randrange(60), seconds=rng.randrange(60))
            permission = profile["primary_permission"]
            if agent_id == "Agent_B":
                permission = rng.choices(["READ_CATALOG", "CREATE_ORDER", "CREATE_AGENT"], [0.57, 0.41, 0.02])[0]
            action = "USE_PERMISSION"
            if permission == "CREATE_AGENT" and agent_id in ("Agent_A", "Agent_B") and rng.random() < 0.1:
                action = "DELEGATE_CREATE_AGENT"
            add(agent_id, action, permission, when, profile["authority_traces"][permission], 0, "NORMAL", f"order-{rng.randrange(200)}")

    for i in range(n_anomalies_per_type):
        when = base + timedelta(days=30, hours=10 + i % 6, minutes=rng.randrange(60), seconds=i)
        add("Agent_D", "SELF_ESCALATION_ATTEMPT", "CREATE_AGENT", when,
            attack_traces["SELF_ESCALATION"], 1, "SELF_ESCALATION", "Agent_D")
        add("Agent_D", "UNAUTHORIZED_DELEGATION_ATTEMPT", "CREATE_AGENT", when + timedelta(seconds=1),
            attack_traces["UNAUTHORIZED_DELEGATION"], 1, "UNAUTHORIZED_DELEGATION", "Agent_C")
        add("Agent_C", "POST_DECOMMISSION_ACTIVITY", "CREATE_AGENT", revoked_at + timedelta(seconds=i + 1),
            attack_traces["POST_DECOMMISSION_ACTIVITY"], 1, "POST_DECOMMISSION_ACTIVITY", "order")
        # Authorized Agent_B use at a normal hour, but compressed into a short burst.
        scope_when = base + timedelta(days=31, hours=14, seconds=20 * i)
        add("Agent_B", "USE_PERMISSION", "CREATE_AGENT", scope_when,
            agent_profiles["Agent_B"]["authority_traces"]["CREATE_AGENT"], 1, "SCOPE_CREEP",
            f"order-{rng.randrange(200)}")

    pairs.sort(key=lambda pair: (pair[0]["timestamp"], pair[0]["record_id"]))
    return [item[0] for item in pairs], [item[1] for item in pairs]


def dataset_counts(labels):
    return Counter(item["category"] for item in labels)
