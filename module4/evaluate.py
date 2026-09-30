"""Held-out anomaly detection metrics with separate ground truth."""

from collections import defaultdict
from copy import deepcopy

from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

from .detector import score_action, score_rule_action


def _metrics(labels, predictions):
    truth = [int(item["label"]) for item in labels]
    matrix = confusion_matrix(truth, predictions, labels=[0, 1])
    tn, fp, fn, tp = (int(value) for value in matrix.ravel())
    categories = sorted({item["category"] for item in labels if item["label"] == 1})
    per_category = {}
    for category in categories:
        indices = [i for i, item in enumerate(labels) if item["category"] == category]
        per_category[category] = {"count": len(indices), "recall": sum(bool(predictions[i]) for i in indices) / len(indices)}
    return {
        "precision": float(precision_score(truth, predictions, zero_division=0)),
        "recall": float(recall_score(truth, predictions, zero_division=0)),
        "f1": float(f1_score(truth, predictions, zero_division=0)),
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "per_category": per_category,
    }


def evaluate(model, test_logs, ground_truth):
    """Evaluate an untouched held-out set; labels never enter scoring."""
    if len(test_logs) != len(ground_truth):
        raise ValueError("Actions and labels must align")
    model.latency_samples.clear()
    predictions = [score_action(action, model)[1] for action in test_logs]
    result = _metrics(ground_truth, predictions)
    latencies = model.latency_samples
    result["latency"] = {
        "average_ms": sum(row["total_detection_latency_ms"] for row in latencies) / len(latencies) if latencies else 0.0,
        "worst_case_ms": max((row["total_detection_latency_ms"] for row in latencies), default=0.0),
        "feature_average_ms": sum(row["feature_latency_ms"] for row in latencies) / len(latencies) if latencies else 0.0,
        "scoring_average_ms": sum(row["scoring_latency_ms"] for row in latencies) / len(latencies) if latencies else 0.0,
    }
    return result


def evaluate_rule_baseline(model, test_logs, ground_truth):
    """Score the same held-out actions using a separate history snapshot."""
    comparator = deepcopy(model)
    comparator.latency_samples.clear()
    predictions = [score_rule_action(action, comparator)[1] for action in test_logs]
    result = _metrics(ground_truth, predictions)
    result["latency"] = {
        "average_ms": sum(row["total_detection_latency_ms"] for row in comparator.latency_samples) / len(comparator.latency_samples) if comparator.latency_samples else 0.0,
        "worst_case_ms": max((row["total_detection_latency_ms"] for row in comparator.latency_samples), default=0.0),
    }
    return result
