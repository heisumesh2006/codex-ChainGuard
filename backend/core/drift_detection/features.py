"""Explicit behavioral features; Module 3 supplies authority facts."""

from datetime import datetime, timedelta
import math

ROLLING_N = 20
BURST_WINDOW_SECONDS = 300
CATEGORICAL_FEATURES = ("actor", "action_type", "permission_requested", "target_pattern")
NUMERIC_FEATURES = (
    "frequency_in_last_N_actions", "permission_frequency_ratio", "role_scope_deviation",
    "authorization_invalid", "delegation_depth_at_time_of_action", "time_since_last_action_by_this_agent",
    "hour_sin", "hour_cos", "burst_rate", "recent_permission_switch_rate",
)
FEATURE_COLUMNS = CATEGORICAL_FEATURES + NUMERIC_FEATURES
FORBIDDEN_COLUMNS = frozenset(("label", "category", "ground_truth", "is_attack", "is_anomaly", "expected_result"))


def extract_features(action_log_entry, agent_history, trace_result):
    """Return only schema-approved model inputs, never ground-truth metadata."""
    if trace_result is None:
        raise ValueError("A Module 3 trace result is required")
    if isinstance(agent_history, dict):
        history = agent_history.get("events", [])
        profile = agent_history.get("profile", {})
    else:
        history, profile = agent_history, {}
    recent = history[-ROLLING_N:]
    permission = action_log_entry.get("permission") or action_log_entry.get("requested_permission") or "UNKNOWN"
    action = action_log_entry["action"]
    when = datetime.fromisoformat(action_log_entry["timestamp"])
    same_action = sum(item.get("action") == action for item in recent)
    same_permission = sum((item.get("permission") or item.get("requested_permission")) == permission for item in recent)
    gaps = [max(0.0, (when - datetime.fromisoformat(item["timestamp"])).total_seconds()) for item in history[-1:]]
    elapsed = gaps[0] if gaps else 86400.0
    burst = sum(0 <= (when - datetime.fromisoformat(item["timestamp"])).total_seconds() <= BURST_WINDOW_SECONDS for item in history)
    switches = sum(
        (recent[i].get("permission") or recent[i].get("requested_permission"))
        != (recent[i - 1].get("permission") or recent[i - 1].get("requested_permission"))
        for i in range(1, len(recent))
    )
    target = str(action_log_entry.get("target", ""))
    target_pattern = "unfamiliar" if target.startswith("unfamiliar-resource-") else ("agent" if target.startswith("Agent_") else "routine")
    hour = when.hour + when.minute / 60
    return {
        "actor": action_log_entry["actor"], "action_type": action,
        "permission_requested": permission, "target_pattern": target_pattern,
        "frequency_in_last_N_actions": float(same_action),
        "permission_frequency_ratio": same_permission / len(recent) if recent else 0.0,
        "role_scope_deviation": float(bool(profile) and permission not in profile.get("expected_role_permissions", [])),
        "authorization_invalid": float(not trace_result["valid"]),
        "delegation_depth_at_time_of_action": float(max(0, len(trace_result.get("chain", [])) - 1)),
        "time_since_last_action_by_this_agent": math.log1p(elapsed),
        "hour_sin": math.sin(2 * math.pi * hour / 24),
        "hour_cos": math.cos(2 * math.pi * hour / 24),
        "burst_rate": burst / (BURST_WINDOW_SECONDS / 60),
        "recent_permission_switch_rate": switches / max(1, len(recent) - 1),
    }
