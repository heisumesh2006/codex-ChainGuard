"""Normal-only Isolation Forest and a deliberately simple rule comparator."""

from collections import defaultdict
from copy import deepcopy
from dataclasses import dataclass, field
import time

import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from module3.tracer import trace_action
from .features import CATEGORICAL_FEATURES, FEATURE_COLUMNS, NUMERIC_FEATURES, extract_features


@dataclass
class TrainedDetector:
    pipeline: Pipeline
    profiles: dict
    threshold: float = 0.0
    history_by_agent: dict = field(default_factory=dict)
    training_record_ids: tuple = ()
    last_latency: dict = field(default_factory=dict)
    latency_samples: list = field(default_factory=list)

    def clone_history(self):
        return deepcopy(self.history_by_agent)


def _trace(action):
    return action.get("trace_result") or trace_action(action)


def _frame(features):
    return np.asarray([[item[key] for key in FEATURE_COLUMNS] for item in features], dtype=object)


def fit_baseline(normal_logs, agent_profiles=None):
    """Fit only caller-supplied normal logs; labels are never accepted as features."""
    if not normal_logs:
        raise ValueError("Normal-only training requires at least one action")
    if agent_profiles is None:
        from .synth_data import build_agent_profiles
        agent_profiles = build_agent_profiles()
    histories = defaultdict(list)
    features = []
    ordered = sorted(normal_logs, key=lambda item: (item["timestamp"], item.get("record_id", "")))
    for action in ordered:
        actor = action["actor"]
        features.append(extract_features(action, {"events": histories[actor], "profile": agent_profiles.get(actor, {})}, _trace(action)))
        histories[actor].append(action)
    preprocess = ColumnTransformer(
        [("categorical", OneHotEncoder(handle_unknown="ignore", sparse_output=False), list(range(len(CATEGORICAL_FEATURES)))),
         ("numeric", StandardScaler(), list(range(len(CATEGORICAL_FEATURES), len(FEATURE_COLUMNS))))],
        remainder="drop",
    )
    pipeline = Pipeline([("preprocess", preprocess), ("isolation_forest", IsolationForest(
        n_estimators=150, contamination="auto", random_state=42, n_jobs=1,
    ))])
    pipeline.fit(_frame(features))
    return TrainedDetector(
        pipeline=pipeline, profiles=agent_profiles,
        history_by_agent=dict(histories),
        training_record_ids=tuple(item.get("record_id") for item in ordered),
    )


def _features_for_action(action, model):
    actor = action["actor"]
    history = model.history_by_agent.setdefault(actor, [])
    return extract_features(action, {"events": history, "profile": model.profiles.get(actor, {})}, _trace(action))


def score_action(action_log_entry, model):
    """Return (higher-is-more-anomalous score, threshold flag)."""
    started = time.perf_counter()
    features = _features_for_action(action_log_entry, model)
    extracted = time.perf_counter()
    anomaly_score = -float(model.pipeline.decision_function(_frame([features]))[0])
    scored = time.perf_counter()
    model.history_by_agent.setdefault(action_log_entry["actor"], []).append(action_log_entry)
    model.last_latency = {
        "feature_latency_ms": (extracted - started) * 1000,
        "scoring_latency_ms": (scored - extracted) * 1000,
        "total_detection_latency_ms": (scored - started) * 1000,
    }
    model.latency_samples.append(model.last_latency.copy())
    return anomaly_score, bool(anomaly_score > model.threshold)


def calibrate_threshold(model, validation_normal_logs, false_alarm_quantile=0.95):
    """Use normal validation scores only; no attack labels influence threshold."""
    if not validation_normal_logs:
        raise ValueError("Validation normals are required")
    scores = [score_action(action, model)[0] for action in sorted(validation_normal_logs, key=lambda x: x["timestamp"])]
    model.threshold = float(np.quantile(scores, false_alarm_quantile))
    model.latency_samples.clear()
    return model.threshold


def rule_flag(features):
    """Fixed rule comparator; intentionally has no learned behavior baseline."""
    return bool(
        features["authorization_invalid"]
        or (features["role_scope_deviation"] and features["burst_rate"] > 3)
        or features["burst_rate"] > 10
    )


def score_rule_action(action_log_entry, model):
    started = time.perf_counter()
    features = _features_for_action(action_log_entry, model)
    extracted = time.perf_counter()
    flagged = rule_flag(features)
    scored = time.perf_counter()
    model.history_by_agent.setdefault(action_log_entry["actor"], []).append(action_log_entry)
    model.last_latency = {
        "feature_latency_ms": (extracted - started) * 1000,
        "scoring_latency_ms": (scored - extracted) * 1000,
        "total_detection_latency_ms": (scored - started) * 1000,
    }
    model.latency_samples.append(model.last_latency.copy())
    return float(flagged), flagged
