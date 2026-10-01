"""Run every required scenario, regressions, and publish final evidence."""

from collections import Counter
import hashlib
import json
from pathlib import Path

from backend.core.blockchain import chain
from backend.core.drift_detection.main import split_normal
from backend.core.governance.pipeline import DATA_DIR, canonical_context, run_governance_pipeline
from backend.core.governance.report import build_report, write_reports

ROOT = Path(__file__).resolve().parents[3]
ATTACK_CODES = {
    "SELF_ESCALATION_ATTEMPT": "SELF_ESCALATION",
    "UNAUTHORIZED_DELEGATION_ATTEMPT": "UNAUTHORIZED_DELEGATION",
    "POST_DECOMMISSION_ACTIVITY": "POST_DECOMMISSION_ACTIVITY",
}


def load_scenarios():
    """All 11 real action events plus deterministic held-out synthetic cases."""
    with canonical_context():
        real = [entry["source"] for entry in chain.load_state()["records"].values()
                if entry["kind"] == "action"]
    real.sort(key=lambda item: (item["timestamp"], item["record_id"]))
    assert len(real) == 11
    scenarios = []
    for action in real:
        code = action["action"]
        if code in ATTACK_CODES:
            scenarios.append((ATTACK_CODES[code], "ATTACK", action))
        elif code.startswith("CHECK_"):
            scenarios.append((code, "BLOCKED_CHECK", action))
        elif action["actor"] == "ROOT_AUTHORIZER":
            scenarios.append((code, "ROOT_ADMIN", action))
        else:
            scenarios.append((code, "LEGITIMATE", action))

    logs = json.loads((ROOT / "backend" / "core" / "drift_detection" / "data" / "synthetic_logs.json").read_text(encoding="utf-8"))
    labels = json.loads((ROOT / "backend" / "core" / "drift_detection" / "data" / "ground_truth.json").read_text(encoding="utf-8"))
    _, _, normal_test, attacks = split_normal(logs, labels)
    normals = [(action, label) for action, label in normal_test if action["actor"] in ("Agent_B", "Agent_D")][:5]
    scope = [(action, label) for action, label in attacks if label["category"] == "SCOPE_CREEP"][:5]
    assert len(normals) == len(scope) == 5
    assert all(label["label"] == 0 for _, label in normals)
    assert all(label["category"] == "SCOPE_CREEP" for _, label in scope)
    scenarios.extend(("NORMAL", "NORMAL", action) for action, _ in normals)
    scenarios.extend(("SCOPE_CREEP", "ANOMALY", action) for action, _ in scope)
    return scenarios


def _print_verdict(number, category, expected, verdict):
    print(f"\n=== SCENARIO {number}: {category} / {verdict.action['actor']} ===")
    print(f"Expected Class    : {expected}")
    print(f"Authorization     : {verdict.authorized}")
    print(f"Drift Applicable  : {verdict.drift_applicable}")
    print(f"Drift Flagged     : {verdict.drift_flagged}")
    print(f"Drift Score       : {verdict.drift_score if verdict.drift_score is not None else 'N/A'}")
    print(f"Trace Verdict     : {verdict.trace_context_verdict}")
    print(f"Revoked           : {bool(verdict.revocation_status and verdict.revocation_status['is_revoked'])}")
    print(f"Chain Verification: {verdict.chain_check_status}")
    print(f"Governance        : {verdict.governance_decision}")
    print(f"Detected By       : {', '.join(verdict.detected_by) or 'None'}")
    print(f"Resolution Time   : {verdict.total_latency_ms:.2f} ms")


def _validate_scenarios(results):
    counts = Counter(expected for _, expected, _ in results)
    assert counts["ATTACK"] == 3 and counts["ANOMALY"] == 5 and counts["NORMAL"] == 5
    assert counts["LEGITIMATE"] == 2 and counts["ROOT_ADMIN"] == 2
    assert counts["BLOCKED_CHECK"] == 4
    for category, expected, verdict in results:
        assert verdict.chain_verified, (category, verdict.chain_check_status, verdict.chain_evidence)
        assert set(verdict.step_latencies) == {
            "authorization_ms", "trace_context_ms", "drift_scoring_ms",
            "revocation_check_ms", "chain_verification_ms", "verdict_assembly_ms",
        }
        assert abs(verdict.total_latency_ms - sum(verdict.step_latencies.values())) < 30
        if expected == "ATTACK":
            assert verdict.governance_decision == "BLOCK", (category, verdict)
            assert verdict.detected_by
        elif expected in ("LEGITIMATE", "ROOT_ADMIN", "NORMAL", "ANOMALY"):
            assert verdict.governance_decision != "BLOCK", (category, verdict)
        if expected == "ANOMALY":
            assert verdict.authorized and verdict.trace_context_verdict == "VALID_CHAIN"
            assert verdict.governance_decision == ("REVIEW" if verdict.drift_flagged else "ALLOW")
        if expected == "ROOT_ADMIN":
            assert not verdict.drift_applicable and verdict.drift_score is None
    assert any(verdict.governance_decision == "REVIEW" for _, expected, verdict in results if expected == "ANOMALY")
    return {"scenario_count": len(results), "scenario_assertions_passed": True}


def source_fingerprint():
    """Bind externally run regression results to the current source tree."""
    digest = hashlib.sha256()
    paths = []
    for name in ("authorization", "blockchain", "tracing", "drift_detection", "revocation", "governance"):
        folder = ROOT / "backend" / "core" / name
        paths.extend(folder.glob("*.py"))
        paths.extend((folder / "tests").glob("*.py"))
    paths.extend((ROOT / "blockchain" / "contracts").glob("*.sol"))
    paths.extend((ROOT / "blockchain" / "test").glob("*.js"))
    for path in sorted(paths):
        digest.update(str(path.relative_to(ROOT)).encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


def run_regression_checks():
    """Read results of direct tool-run suites, which can spawn Hardhat on Windows."""
    path = DATA_DIR / "regression_results.json"
    if not path.exists():
        raise RuntimeError("Run the direct contract/Python regression suites and record their results first")
    results = json.loads(path.read_text(encoding="utf-8"))
    if results.get("source_fingerprint") != source_fingerprint():
        raise RuntimeError("Regression results do not match the current source tree")
    for name in ("contract_compile", "contract_tests", "python_tests", "module1_demo"):
        if not results.get(name, {}).get("passed"):
            raise RuntimeError(f"Required regression result is missing or failed: {name}")
    return results


def run_demo(run_tests=True):
    scenarios = load_scenarios()
    results = []
    print("=" * 62)
    print("CHAINGUARD-AI | FINAL INTEGRATED GOVERNANCE EVALUATION")
    print("=" * 62)
    with canonical_context():
        deployment = json.loads((DATA_DIR / "deployment.json").read_text(encoding="utf-8"))
        print(f"Canonical Registry: {deployment['contract_address']} | chain {deployment['chain_id']}")
    for number, (category, expected, action) in enumerate(scenarios, start=1):
        verdict = run_governance_pipeline(action)
        results.append((category, expected, verdict))
        _print_verdict(number, category, expected, verdict)
    scenario_tests = _validate_scenarios(results)
    if not run_tests:
        return results

    tests = run_regression_checks()
    tests["integration_scenarios"] = scenario_tests
    report = build_report(results, tests)
    json_path, markdown_path = write_reports(report)
    print("\n=== END-TO-END METRICS ===")
    print(f"Attack Coverage: {report['end_to_end_attack_coverage']:.2%}")
    print(f"Total Latency Average: {report['end_to_end_latency']['total_average_ms']:.2f} ms")
    print(f"Total Latency Worst: {report['end_to_end_latency']['total_worst_case_ms']:.2f} ms")
    print(f"Bottleneck: {report['end_to_end_latency']['pipeline_bottleneck_step']}")
    print(f"Final JSON: {json_path}")
    print(f"Final Markdown: {markdown_path}")
    print("\n=== CHAINGUARD-AI END-TO-END EVALUATION COMPLETE ===")
    return report


if __name__ == "__main__":
    run_demo()
