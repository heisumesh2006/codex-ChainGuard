"""Reproduce held-out scores and write a diagnostic report without retraining."""

from datetime import datetime
import json
from statistics import median

import joblib

from .detector import _features_for_action, score_action
from .main import DATA_DIR, MODEL_DIR, split_normal


def audit_self_escalation():
    logs = json.loads((DATA_DIR / "synthetic_logs.json").read_text(encoding="utf-8"))
    labels = json.loads((DATA_DIR / "ground_truth.json").read_text(encoding="utf-8"))
    model = joblib.load(MODEL_DIR / "isolation_forest.joblib")
    _, _, normal_test, attacks = split_normal(logs, labels)
    test = sorted(normal_test + attacks, key=lambda pair: (pair[0]["timestamp"], pair[0]["record_id"]))
    rows = []
    for action, label in test:
        features = _features_for_action(action, model)
        score, flagged = score_action(action, model)
        rows.append({
            "record_id": action["record_id"], "timestamp": action["timestamp"],
            "actor": action["actor"], "category": label["category"],
            "score": score, "flagged": flagged, "features": features,
        })
    self_rows = [row for row in rows if row["category"] == "SELF_ESCALATION"]
    misses = [row for row in self_rows if not row["flagged"]]
    detections = [row for row in self_rows if row["flagged"]]
    normal_d = [row for row in rows if row["category"] == "NORMAL" and row["actor"] == "Agent_D"]
    for miss in misses:
        miss_time = datetime.fromisoformat(miss["timestamp"])
        miss["nearest_normal"] = min(normal_d, key=lambda row: abs((datetime.fromisoformat(row["timestamp"]) - miss_time).total_seconds()))
        miss["nearest_detected"] = min(detections, key=lambda row: abs((datetime.fromisoformat(row["timestamp"]) - miss_time).total_seconds()))

    key_features = (
        "action_type", "permission_requested", "target_pattern", "authorization_invalid",
        "role_scope_deviation", "delegation_depth_at_time_of_action", "frequency_in_last_N_actions",
        "permission_frequency_ratio", "time_since_last_action_by_this_agent", "hour_sin", "hour_cos",
        "burst_rate", "recent_permission_switch_rate",
    )

    def compact(row):
        return {
            "record_id": row["record_id"], "timestamp": row["timestamp"],
            "score": round(row["score"], 6), "margin": round(row["score"] - model.threshold, 6),
            "flagged": row["flagged"],
            "features": {key: row["features"][key] for key in key_features},
        }

    print(f"Threshold (normal validation 95th percentile): {model.threshold:.6f}")
    print(f"SELF_ESCALATION: {len(detections)}/{len(self_rows)} detected; {len(misses)} false negatives")
    for miss in misses:
        print("\nFALSE NEGATIVE", json.dumps(compact(miss), indent=2))
        print("NEAREST DETECTED", json.dumps(compact(miss["nearest_detected"]), indent=2))
        print("NEAREST NORMAL Agent_D", json.dumps(compact(miss["nearest_normal"]), indent=2))
    for name, group in (("misses", misses), ("detected", detections), ("Agent_D normal", normal_d)):
        print(f"\n{name}: count={len(group)}, score min/median/max="
              f"{min(row['score'] for row in group):.6f}/"
              f"{median(row['score'] for row in group):.6f}/"
              f"{max(row['score'] for row in group):.6f}")
    for category in ("UNAUTHORIZED_DELEGATION", "POST_DECOMMISSION_ACTIVITY", "SCOPE_CREEP"):
        group = [row for row in rows if row["category"] == category]
        print(f"{category} recall: {sum(row['flagged'] for row in group)}/{len(group)} = "
              f"{sum(row['flagged'] for row in group) / len(group):.2%}")
    report = {
        "threshold": model.threshold, "false_negatives": [compact(row) for row in misses],
        "nearest_detected": [compact(row["nearest_detected"]) for row in misses],
        "nearest_normal": [compact(row["nearest_normal"]) for row in misses],
        "detected_count": len(detections), "total_count": len(self_rows),
    }
    path = DATA_DIR / "self_escalation_diagnostics.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


if __name__ == "__main__":
    audit_self_escalation()
