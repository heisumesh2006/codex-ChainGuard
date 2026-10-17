"""Run the complete Python suite against a fresh local-only signed fixture.

Usage: python -m backend.testing.run_regression [unittest.module ...]
Requires an already running Hardhat node at 127.0.0.1:8545. It never resets
that node or reads/writes the project's canonical evidence bundle.
"""

from contextlib import ExitStack
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import io
from contextlib import redirect_stdout
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch


def main(names=None):
    # Set these before importing chain, whose profile is selected at import.
    os.environ["CHAINGUARD_NETWORK"] = "hardhat"
    os.environ["CHAINGUARD_RPC_URL"] = "http://127.0.0.1:8545"
    import joblib
    from backend.api import services
    from backend.core.authorization.demo_identity import DemoIdentity
    from backend.core.authorization import main as authorization_main
    from backend.core.blockchain import chain, main as blockchain_main
    from backend.core.blockchain.audit_log import AuditLogStore
    from backend.core.blockchain.batch_manager import BatchManager
    from backend.core.governance import bootstrap, main as governance_main, pipeline, report
    from backend.core.revocation import revocation
    from backend.testing.signed_requests import fixture_identity

    if chain.NETWORK_PROFILE != "hardhat" or chain.connect().eth.chain_id != 31337:
        raise RuntimeError("Isolated regression requires local Hardhat chain 31337")
    root = Path(__file__).resolve().parents[2]
    runtime = root / ".runtime"
    runtime.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="research-regression-", dir=runtime) as temporary, ExitStack() as stack:
        folder = Path(temporary)
        paths = {name: folder / filename for name, filename in (
            ("STATE_PATH", "ethereum_state.json"),
            ("DEPLOYMENT_PATH", "deployment.json"),
            ("CREDENTIALS_PATH", "credentials.json"),
        )}
        for name, path in paths.items():
            stack.enter_context(patch.object(chain, name, path))
            stack.enter_context(patch.object(revocation, "BUNDLE_" + name, path))
        stack.enter_context(patch.object(bootstrap, "DATA_DIR", folder))
        stack.enter_context(patch.object(bootstrap, "PATHS", paths))
        for module in (pipeline, report, governance_main, services):
            stack.enter_context(patch.object(module, "DATA_DIR", folder))
        shutil.copyfile(root / "backend/core/governance/data/final_report.json", folder / "final_report.json")
        stack.enter_context(patch.object(services, "REPORT_PATH", folder / "final_report.json"))
        store = AuditLogStore(folder / "audit_logs.jsonl")
        stack.enter_context(patch.object(pipeline, "AUDIT_LOG_STORE", store))
        stack.enter_context(patch.object(pipeline, "AUDIT_BATCH_MANAGER", BatchManager(store, folder / "batches.json")))

        # Bootstrap grants and subsequent evaluation requests share one genuine
        # cryptographic identity realm. These keys exist only for this fixture.
        identity = stack.enter_context(DemoIdentity())
        token = fixture_identity.set(identity)
        stack.callback(fixture_identity.reset, token)
        stack.enter_context(patch.object(blockchain_main, "run_demo", lambda: authorization_main.run_demo(identity)))

        class FixtureIssuance(datetime):
            @classmethod
            def now(cls, tz=None):
                return datetime.now(tz) - timedelta(minutes=1)

        original_issue = chain.issue_credential

        def issue_fixture_credential(*args, **kwargs):
            # Only newly created local credentials are issued before the demo's
            # historical actions. No saved credential or evidence is altered.
            with patch.object(chain, "datetime", FixtureIssuance):
                return original_issue(*args, **kwargs)

        with patch.object(chain, "issue_credential", issue_fixture_credential), redirect_stdout(io.StringIO()):
            bootstrap.bootstrap()
        pipeline._runtime["module1_ready"] = True

        # The held-out synthetic dataset is dated, while the isolated registry
        # is new. Shift its in-memory copies and the model's history together by
        # whole days. Hours, intervals, labels, fitted weights and original files
        # stay intact; every evaluated timestamp now follows fixture issuance.
        original_scenarios = governance_main.load_scenarios
        dated = [a for _, _, a in original_scenarios() if str(a["record_id"]).startswith("synthetic:")]
        earliest = min(datetime.fromisoformat(a["timestamp"]) for a in dated)
        tomorrow = datetime.now(timezone.utc).date() + timedelta(days=1)
        shift = timedelta(days=(tomorrow - earliest.date()).days)

        def shifted_scenarios():
            rows = deepcopy(original_scenarios())
            for _, _, action in rows:
                if str(action["record_id"]).startswith("synthetic:"):
                    action["timestamp"] = (datetime.fromisoformat(action["timestamp"]) + shift).isoformat()
            return rows

        original_load = joblib.load

        def fixture_model(path, *args, **kwargs):
            model = original_load(path, *args, **kwargs)
            if Path(path).resolve() == pipeline.MODEL_PATH.resolve():
                for events in model.history_by_agent.values():
                    for event in events:
                        event["timestamp"] = (datetime.fromisoformat(event["timestamp"]) + shift).isoformat()
            return model

        stack.enter_context(patch.object(governance_main, "load_scenarios", shifted_scenarios))
        stack.enter_context(patch.object(services, "load_scenarios", shifted_scenarios))
        stack.enter_context(patch.object(joblib, "load", fixture_model))
        pipeline._runtime["model"] = fixture_model(pipeline.MODEL_PATH)
        print("FIXTURE=isolated Hardhat, shared signed identities, new valid credentials", flush=True)
        print("SYNTHETIC_COPY_DAY_SHIFT=" + str(shift.days), flush=True)
        suite = (unittest.defaultTestLoader.loadTestsFromNames(names) if names else
                 unittest.defaultTestLoader.discover("backend", pattern="test*.py", top_level_dir="."))
        print("DISCOVERED_PYTHON_TESTS=" + str(suite.countTestCases()), flush=True)
        stress_path = Path(tempfile.gettempdir()) / "F8_STRESS_RESULTS.json"
        stress_before = stress_path.stat().st_mtime_ns if stress_path.exists() else None
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        if stress_path.exists() and stress_path.stat().st_mtime_ns != stress_before:
            shutil.copyfile(stress_path, runtime / "RESEARCH_F8_STRESS_RESULTS.json")
        print(json.dumps({"tests": result.testsRun, "failures": len(result.failures),
                          "errors": len(result.errors), "skipped": len(result.skipped)}), flush=True)
        return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
