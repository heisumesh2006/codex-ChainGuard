"""Canonical deployment integration and final governance decision tests."""

from collections import Counter
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from backend.core.blockchain import chain
from backend.core.revocation import revocation as module5_revocation
from backend.core.governance import pipeline
from backend.core.governance.main import load_scenarios
from backend.core.governance.report import build_report, write_reports


class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scenarios = load_scenarios()
        pipeline.prepare_runtime()

    @classmethod
    def _action(cls, category):
        return next(action for name, _, action in cls.scenarios if name == category)

    def test_canonical_latest_registry_is_shared(self):
        with pipeline.canonical_context():
            _, contract, _, deployment = chain.contract_context()
            _, public_contract, public_deployment = module5_revocation._registry()
            self.assertEqual(contract.address, public_contract.address)
            self.assertEqual(deployment["contract_address"], public_deployment["contract_address"])
            self.assertTrue(hasattr(contract.functions, "getRevocationDetails"))

    def test_unauthorized_and_post_revocation_are_blocked(self):
        for category, expected in (
            ("SELF_ESCALATION", "UNAUTHORIZED_ROOT"),
            ("UNAUTHORIZED_DELEGATION", "BROKEN_CHAIN"),
            ("POST_DECOMMISSION_ACTIVITY", "AUTHORITY_REVOKED_AT_TIME_OF_ACTION"),
        ):
            with self.subTest(category=category):
                result = pipeline.run_governance_pipeline(self._action(category))
                self.assertIsInstance(result, pipeline.GovernanceVerdict)
                self.assertEqual(result.governance_decision, "BLOCK")
                self.assertEqual(result.trace_context_verdict, expected)
                self.assertTrue(result.chain_verified)
                if category == "POST_DECOMMISSION_ACTIVITY":
                    self.assertTrue(result.audit_result["violation"])
                    self.assertTrue(result.revocation_status["proof_verified"])

    def test_authorized_scope_creep_is_review_not_block(self):
        actions = [action for name, expected, action in self.scenarios if name == "SCOPE_CREEP"]
        self.assertEqual(len(actions), 5)
        result = pipeline.run_governance_pipeline(actions[0])
        self.assertTrue(result.authorized)
        self.assertEqual(result.trace_context_verdict, "VALID_CHAIN")
        self.assertTrue(result.chain_verified)
        self.assertEqual(result.governance_decision, "REVIEW" if result.drift_flagged else "ALLOW")

    def test_clean_action_not_hard_blocked_by_ml(self):
        actions = [action for name, expected, action in self.scenarios if name == "NORMAL"]
        self.assertEqual(len(actions), 5)
        result = pipeline.run_governance_pipeline(actions[0])
        self.assertTrue(result.authorized)
        self.assertIn(result.governance_decision, ("ALLOW", "REVIEW"))
        self.assertEqual(result.trace_context_verdict, "VALID_CHAIN")

    def test_trace_is_reused_by_module4(self):
        action = self._action("SELF_ESCALATION")
        original = pipeline.trace_action
        original_score = pipeline.score_action
        seen = []

        def score_wrapper(model_input, model):
            seen.append(model_input["trace_result"])
            return original_score(model_input, model)

        with patch.object(pipeline, "trace_action", wraps=original) as tracer_call:
            with patch.object(pipeline, "score_action", side_effect=score_wrapper):
                with patch("backend.core.drift_detection.detector.trace_action", side_effect=AssertionError("redundant trace")):
                    result = pipeline.run_governance_pipeline(action)
        self.assertEqual(tracer_call.call_count, 1)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]["verdict"], result.trace_context_verdict)
        self.assertFalse(seen[0]["valid"])

    def test_failed_proof_differs_from_unrooted_authority(self):
        action = self._action("SELF_ESCALATION")
        ordinary = pipeline.run_governance_pipeline(action)
        self.assertEqual(ordinary.chain_check_status, "VERIFIED_NO_VALID_AUTHORITY")
        with patch.object(pipeline, "get_proof", side_effect=KeyError("simulated missing proof")):
            failed = pipeline.run_governance_pipeline(action)
        self.assertEqual(failed.chain_check_status, "FAILED")
        self.assertFalse(failed.chain_verified)
        self.assertEqual(failed.governance_decision, "BLOCK")

    def test_root_has_no_fabricated_ml_score(self):
        result = pipeline.run_governance_pipeline(self._action("ROOT_PERMISSION_GRANTED"))
        self.assertFalse(result.drift_applicable)
        self.assertFalse(result.drift_flagged)
        self.assertIsNone(result.drift_score)
        self.assertTrue(result.chain_verified)

    def test_latency_fields_and_consistency(self):
        result = pipeline.run_governance_pipeline(self._action("SELF_ESCALATION"))
        self.assertEqual(set(result.step_latencies), {
            "authorization_ms", "trace_context_ms", "drift_scoring_ms",
            "revocation_check_ms", "chain_verification_ms", "verdict_assembly_ms",
        })
        self.assertTrue(all(value >= 0 for value in result.step_latencies.values()))
        self.assertGreater(result.total_latency_ms, 0)
        self.assertLess(abs(result.total_latency_ms - sum(result.step_latencies.values())), 30)

    def test_all_required_scenarios_and_heldout_selection(self):
        counts = Counter(expected for _, expected, _ in self.scenarios)
        self.assertEqual(counts["ATTACK"], 3)
        self.assertEqual(counts["LEGITIMATE"], 2)
        self.assertEqual(counts["ROOT_ADMIN"], 2)
        self.assertEqual(counts["NORMAL"], 5)
        self.assertEqual(counts["ANOMALY"], 5)
        self.assertEqual(counts["BLOCKED_CHECK"], 4)
        self.assertTrue(all(action["record_id"].startswith("synthetic:") for _, kind, action in self.scenarios if kind in ("NORMAL", "ANOMALY")))

    def test_reports_contain_real_metrics_and_both_formats(self):
        attack = pipeline.run_governance_pipeline(self._action("SELF_ESCALATION"))
        normal = pipeline.run_governance_pipeline(next(action for name, _, action in self.scenarios if name == "NORMAL"))
        report = build_report([
            ("SELF_ESCALATION", "ATTACK", attack), ("NORMAL", "NORMAL", normal),
        ], {"integration_test": {"passed": True, "test_count": 1}})
        self.assertEqual(report["modules"]["module2_blockchain"]["proofs_verified"], 14)
        self.assertEqual(report["modules"]["module3_tracing"]["delegation_trace_accuracy"], 1.0)
        self.assertGreater(report["modules"]["module4_anomaly"]["isolation_forest"]["f1"], 0)
        self.assertEqual(report["modules"]["module5_revocation"]["revocation_completeness"], 1.0)
        self.assertGreater(report["end_to_end_latency"]["total_average_ms"], 0)
        # Inspect both rendered formats without replacing the 21-scenario artifact.
        written = {}

        def capture(path, content, **_kwargs):
            written[path.name] = content
            return len(content)

        with patch("backend.core.governance.report.Path.write_text", autospec=True, side_effect=capture):
            json_path, markdown_path = write_reports(report)
        self.assertIn(json_path.name, written)
        self.assertIn(markdown_path.name, written)
        self.assertNotIn("TBD", written[markdown_path.name])
        self.assertEqual(json.loads(written[json_path.name])["scenario_counts"]["total"], 2)


if __name__ == "__main__":
    unittest.main()
