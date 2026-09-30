"""Behavioral detector contracts and live Module 3 trace consumption."""

from collections import Counter
from copy import deepcopy
import math
from pathlib import Path
import unittest
from unittest.mock import patch

import joblib

from module4.detector import calibrate_threshold, fit_baseline, score_action
from module4.evaluate import _metrics, evaluate
from module4.features import FEATURE_COLUMNS, FORBIDDEN_COLUMNS, extract_features
from module4.main import split_normal
from module4.synth_data import CATEGORIES, build_agent_profiles, generate_synthetic_logs


class DetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profiles = build_agent_profiles()
        cls.logs, cls.labels = generate_synthetic_logs(cls.profiles, 500, 30)
        cls.train, cls.validation, cls.normal_test, cls.attacks = split_normal(cls.logs, cls.labels)
        cls.model = fit_baseline([log for log, _ in cls.train], cls.profiles)
        calibrate_threshold(cls.model, [log for log, _ in cls.validation])

    def test_minimum_dataset_and_separate_labels(self):
        normal_by_actor = Counter(log["actor"] for log, label in zip(self.logs, self.labels, strict=True) if label["label"] == 0)
        counts = Counter(label["category"] for label in self.labels)
        self.assertTrue(all(normal_by_actor[agent] >= 500 for agent in self.profiles))
        self.assertTrue(all(counts[category] >= 30 for category in CATEGORIES))
        self.assertFalse(any(FORBIDDEN_COLUMNS.intersection(log) for log in self.logs))

    def test_fixed_seed_reproducibility(self):
        again_logs, again_labels = generate_synthetic_logs(self.profiles, 2, 1)
        repeated_logs, repeated_labels = generate_synthetic_logs(self.profiles, 2, 1)
        self.assertEqual((again_logs, again_labels), (repeated_logs, repeated_labels))

    def test_training_contains_only_normal_records(self):
        normal_ids = {log["record_id"] for log, label in zip(self.logs, self.labels, strict=True) if label["label"] == 0}
        self.assertEqual(len(self.model.training_record_ids), 1400)
        self.assertTrue(set(self.model.training_record_ids) <= normal_ids)
        self.assertEqual(len(self.validation), 300)
        self.assertEqual(len(self.normal_test), 300)

    def test_no_ground_truth_feature_leakage(self):
        log = deepcopy(self.logs[0])
        log.update({"label": 1, "category": "SCOPE_CREEP", "is_attack": True})
        base = extract_features(self.logs[0], {"events": [], "profile": self.profiles[log["actor"]]}, log["trace_result"])
        changed = extract_features(log, {"events": [], "profile": self.profiles[log["actor"]]}, log["trace_result"])
        self.assertEqual(base, changed)
        self.assertEqual(set(base), set(FEATURE_COLUMNS))
        self.assertFalse(set(FEATURE_COLUMNS) & FORBIDDEN_COLUMNS)

    def test_unseen_categorical_values(self):
        model = deepcopy(self.model)
        log = dict(self.logs[0], action="NEW_ACTION_TYPE", permission="NEVER_SEEN_PERMISSION", target="new-target")
        score, flag = score_action(log, model)
        self.assertTrue(math.isfinite(score))
        self.assertIsInstance(flag, bool)

    def test_first_action_and_trace_consumption(self):
        log = self.logs[0]
        features = extract_features(log, {"events": [], "profile": self.profiles[log["actor"]]}, log["trace_result"])
        self.assertEqual(features["permission_frequency_ratio"], 0)
        self.assertEqual(features["burst_rate"], 0)
        invalid = dict(log["trace_result"], valid=False, chain=[])
        changed = extract_features(log, {"events": [], "profile": self.profiles[log["actor"]]}, invalid)
        self.assertEqual(features["authorization_invalid"], 0)
        self.assertEqual(changed["authorization_invalid"], 1)
        self.assertEqual(changed["delegation_depth_at_time_of_action"], 0)

    def test_scope_creep_is_anchored_valid_authority(self):
        scope = [log for log, label in zip(self.logs, self.labels, strict=True) if label["category"] == "SCOPE_CREEP"]
        self.assertEqual(len(scope), 30)
        self.assertTrue(all(log["trace_result"]["verdict"] == "VALID_CHAIN" for log in scope))
        self.assertTrue(all(log["trace_result"]["valid"] and all(hop["proof_verified"] for hop in log["trace_result"]["chain"]) for log in scope))

    def test_scoring_latency_and_persistence(self):
        model = deepcopy(self.model)
        log = self.normal_test[0][0]
        score, flagged = score_action(log, model)
        self.assertIsInstance(score, float)
        self.assertIsInstance(flagged, bool)
        self.assertGreater(model.last_latency["total_detection_latency_ms"], 0)
        path = Path(__file__).resolve().parents[1] / "models" / "test_model.joblib"
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            joblib.dump(self.model, path)
            loaded = joblib.load(path)
            original_score = score_action(log, deepcopy(self.model))
            loaded_score = score_action(log, loaded)
            self.assertAlmostEqual(original_score[0], loaded_score[0], places=12)
            self.assertEqual(original_score[1], loaded_score[1])
        finally:
            path.unlink(missing_ok=True)

    def test_evaluation_formulas_and_category_recall(self):
        labels = [{"label": 0, "category": "NORMAL"}, {"label": 0, "category": "NORMAL"},
                  {"label": 1, "category": "SELF_ESCALATION"}, {"label": 1, "category": "SCOPE_CREEP"}]
        result = _metrics(labels, [False, True, True, False])
        self.assertEqual(result["confusion_matrix"], [[1, 1], [1, 1]])
        self.assertEqual(result["precision"], 0.5)
        self.assertEqual(result["recall"], 0.5)
        self.assertEqual(result["f1"], 0.5)
        self.assertEqual(result["false_positive_rate"], 0.5)
        self.assertEqual(result["per_category"]["SELF_ESCALATION"]["recall"], 1)
        self.assertEqual(result["per_category"]["SCOPE_CREEP"]["recall"], 0)

    def test_evaluation_latency_present(self):
        selected = [self.normal_test[0], self.attacks[0]]
        result = evaluate(deepcopy(self.model), [entry[0] for entry in selected], [entry[1] for entry in selected])
        self.assertGreater(result["latency"]["average_ms"], 0)
        self.assertGreaterEqual(result["latency"]["worst_case_ms"], result["latency"]["average_ms"])


if __name__ == "__main__":
    unittest.main()
