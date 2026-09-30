"""Run the normal-only policy drift experiment and save Module 6 metrics."""

from collections import Counter, defaultdict
from copy import deepcopy
import json
from pathlib import Path
import sys

import joblib

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from module2 import chain
from module4.detector import calibrate_threshold, fit_baseline, score_action
from module4.evaluate import evaluate, evaluate_rule_baseline
from module4.synth_data import CATEGORIES, build_agent_profiles, generate_synthetic_logs

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "models"


def _save_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False), encoding="utf-8")


def split_normal(logs, labels):
    """Per-agent chronological 70/15/15 split; attacks stay wholly unseen."""
    normal = defaultdict(list)
    attacks = []
    for log, label in zip(logs, labels, strict=True):
        if label["label"] == 0:
            normal[log["actor"]].append((log, label))
        else:
            attacks.append((log, label))
    train, validation, test = [], [], []
    for agent_id, entries in sorted(normal.items()):
        entries.sort(key=lambda item: item[0]["timestamp"])
        n = len(entries)
        train.extend(entries[: int(n * 0.70)])
        validation.extend(entries[int(n * 0.70): int(n * 0.85)])
        test.extend(entries[int(n * 0.85):])
    for group in (train, validation, test):
        group.sort(key=lambda item: (item[0]["timestamp"], item[0]["record_id"]))
    attacks.sort(key=lambda item: (item[0]["timestamp"], item[0]["record_id"]))
    return train, validation, test, attacks


def _print_metrics(title, result):
    print(f"\n=== {title} ===")
    for key in ("precision", "recall", "f1", "false_positive_rate"):
        print(f"{key.replace('_', ' ').title()}: {result[key]:.4f}")
    print(f"Confusion Matrix [TN FP; FN TP]: {result['confusion_matrix']}")
    for category in CATEGORIES:
        print(f"{category} Recall: {result['per_category'][category]['recall']:.4f}")
    print(f"Average Detection Latency: {result['latency']['average_ms']:.3f} ms")
    print(f"Worst-Case Detection Latency: {result['latency']['worst_case_ms']:.3f} ms")


def run_demo():
    profiles = build_agent_profiles()
    logs, labels = generate_synthetic_logs(profiles, 500, 30)
    counts = Counter(item["category"] for item in labels)
    assert counts["NORMAL"] >= 2000 and all(counts[name] >= 30 for name in CATEGORIES)
    assert all(log.get("trace_result", {}).get("verdict") == "VALID_CHAIN" for log, label in zip(logs, labels, strict=True) if label["category"] == "SCOPE_CREEP")
    _save_json(DATA_DIR / "synthetic_logs.json", logs)
    _save_json(DATA_DIR / "ground_truth.json", labels)
    train, validation, normal_test, attacks = split_normal(logs, labels)
    assert len(train) == 1400 and len(validation) == 300 and len(normal_test) == 300
    assert all(label["label"] == 0 for _, label in train + validation)

    print("=== DATASET SUMMARY ===")
    print(f"Normal Samples: {counts['NORMAL']}")
    for category in CATEGORIES:
        print(f"{category}: {counts[category]}")
    print(f"Training Normal Samples: {len(train)}")
    print(f"Validation Normal Samples: {len(validation)}")
    print(f"Test Normal Samples: {len(normal_test)}")

    model = fit_baseline([action for action, _ in train], profiles)
    assert len(model.training_record_ids) == len(train)
    threshold = calibrate_threshold(model, [action for action, _ in validation])
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_DIR / "isolation_forest.joblib")
    test = sorted(normal_test + attacks, key=lambda item: (item[0]["timestamp"], item[0]["record_id"]))
    test_logs = [item[0] for item in test]
    truth = [item[1] for item in test]
    rule = evaluate_rule_baseline(model, test_logs, truth)
    ml = evaluate(model, test_logs, truth)
    _print_metrics("ISOLATION FOREST", ml)
    _print_metrics("RULE BASELINE", rule)

    print("\n=== COMPARISON ===")
    print(f"{'Metric':26} {'Isolation Forest':>18} {'Rule Baseline':>18}")
    for key in ("precision", "recall", "f1", "false_positive_rate"):
        print(f"{key:26} {ml[key]:18.4f} {rule[key]:18.4f}")
    print(f"{'scope_creep_recall':26} {ml['per_category']['SCOPE_CREEP']['recall']:18.4f} {rule['per_category']['SCOPE_CREEP']['recall']:18.4f}")

    metrics = {
        "isolation_forest": {key: value for key, value in ml.items() if key != "latency"},
        "rule_baseline": {key: value for key, value in rule.items() if key != "latency"},
        "latency": ml["latency"],
        "dataset": {"normal_count": counts["NORMAL"], "attack_counts": {category: counts[category] for category in CATEGORIES},
                    "train_normal_count": len(train), "validation_normal_count": len(validation), "test_normal_count": len(normal_test)},
        "threshold": threshold,
    }
    _save_json(DATA_DIR / "metrics.json", metrics)

    print("\n=== REAL MODULE 1 ACTION SANITY CHECK ===")
    real_actions = [entry["source"] for entry in chain.load_state()["records"].values() if entry["kind"] == "action"]
    selected = [entry for entry in real_actions if entry["action"] in ("SELF_ESCALATION_ATTEMPT", "UNAUTHORIZED_DELEGATION_ATTEMPT", "POST_DECOMMISSION_ACTIVITY")]
    assert len(selected) == 3
    sanity_model = joblib.load(MODEL_DIR / "isolation_forest.joblib")
    for action in selected:
        score, flagged = score_action(action, sanity_model)  # Calls Module 3 trace_action.
        print(f"{action['action']}: score={score:.4f}, flagged={flagged}")

    assert (DATA_DIR / "metrics.json").exists() and (MODEL_DIR / "isolation_forest.joblib").exists()
    print("\n=== MODULE 4 COMPLETED SUCCESSFULLY ===")
    return metrics


if __name__ == "__main__":
    run_demo()
