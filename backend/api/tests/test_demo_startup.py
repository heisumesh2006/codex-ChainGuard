"""Local presentation startup and safe error-code regression checks."""
from copy import deepcopy
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch
from backend.api import demo_server
from backend.core.blockchain.diagnostics import public_data, safe_error
from backend.core.blockchain.evidence import EvidenceError


class DemoStartupTests(TestCase):
    def test_public_profile_is_rejected_before_bootstrap(self):
        with patch.object(demo_server.chain, "NETWORK_PROFILE", "sepolia"), patch.object(demo_server.bootstrap, "bootstrap") as bootstrap:
            with self.assertRaisesRegex(RuntimeError, "local Hardhat"):
                demo_server.main()
            bootstrap.assert_not_called()

    def test_wrong_chain_is_rejected_before_bootstrap(self):
        with patch.object(demo_server.chain, "NETWORK_PROFILE", "hardhat"), patch.object(demo_server.chain, "connect", return_value=SimpleNamespace(eth=SimpleNamespace(chain_id=11155111))), patch.object(demo_server.bootstrap, "bootstrap") as bootstrap:
            with self.assertRaisesRegex(RuntimeError, "31337"):
                demo_server.main()
            bootstrap.assert_not_called()

    def test_seed_uses_signed_copies_and_anchors_all_five_records(self):
        from contextlib import nullcontext
        rows = [(code, "fixture", {"record_id": ("synthetic:" if code in ("NORMAL", "SCOPE_CREEP") else "action:") + code,
                "timestamp": "2025-01-01T12:00:00+00:00", "actor": "Agent_B", "action": "USE_PERMISSION", "permission": "CREATE_ORDER"}) for code in demo_server.services.SCENARIOS.values()]
        original = deepcopy(rows)
        identity = Mock()
        identity.credentials.return_value = {"authentication": {"signature": "synthetic-test-signature"}, "verifier": Mock()}
        model = SimpleNamespace(history_by_agent={"Agent_B": [{"timestamp": "2025-01-01T11:00:00+00:00"}]})
        manager = Mock()
        manager.list_batches.return_value = [{"status": "ANCHORED"}]
        with patch.object(demo_server.module6_main, "load_scenarios", return_value=rows), patch("joblib.load", return_value=model), patch.object(demo_server.pipeline, "_runtime", {}), patch.object(demo_server.pipeline, "AUDIT_BATCH_MANAGER", manager), patch.object(demo_server.pipeline, "canonical_context", nullcontext), patch.object(demo_server.pipeline, "run_governance_pipeline") as run:
            demo_server.seed_scenarios(identity)
        self.assertEqual(rows, original)
        self.assertEqual(run.call_count, 5)
        self.assertEqual(identity.credentials.call_count, 2)
        self.assertEqual(sum("authentication" in c.kwargs for c in run.call_args_list), 2)
        manager.anchor_unanchored_batches.assert_called_once()

    def test_missing_evidence_code_survives_public_serialization(self):
        error = EvidenceError("SAVED_SCENARIO_UNAVAILABLE", 404)
        self.assertEqual(safe_error(error), "SAVED_SCENARIO_UNAVAILABLE")
        self.assertEqual(public_data({"detail": safe_error(error)})["detail"], "SAVED_SCENARIO_UNAVAILABLE")


class AuditDeploymentContextTests(TestCase):
    def test_proof_get_and_post_use_selected_registry_and_restore_paths(self):
        from pathlib import Path
        from backend.api import services
        from backend.core.governance import pipeline
        from backend.core.blockchain import chain
        original = chain.DEPLOYMENT_PATH
        selected = Path("isolated-local-fixture")
        def verify(*args):
            self.assertEqual(chain.DEPLOYMENT_PATH, selected / "deployment.json")
            return {"result": "VERIFIED"}
        with patch.object(pipeline, "DATA_DIR", selected), patch.object(services, "_audit_action_proof", side_effect=verify):
            self.assertEqual(services.audit_action_proof("fixture")["result"], "VERIFIED")
            self.assertEqual(services.verify_audit_action("fixture")["result"], "VERIFIED")
        self.assertEqual(chain.DEPLOYMENT_PATH, original)


class WindowsSnapshotRetryTests(TestCase):
    def test_transient_windows_sharing_denial_preserves_then_publishes(self):
        import os, tempfile
        from pathlib import Path
        from backend.core.blockchain import persistence
        if os.name != "nt": self.skipTest("Windows sharing semantics")
        with tempfile.TemporaryDirectory(dir=Path.cwd()/".runtime") as folder:
            target=Path(folder)/"state.json"
            target.write_bytes(b"old")
            original=persistence.os.replace
            calls=[]
            def replace(source, destination):
                calls.append(1)
                if len(calls)==1:
                    self.assertEqual(target.read_bytes(), b"old")
                    error=PermissionError("synthetic sharing denial"); error.winerror=32
                    raise error
                original(source,destination)
            with patch.object(persistence.os,"replace",side_effect=replace), patch.object(persistence.time,"sleep"):
                persistence.atomic_write(target,b"new")
            self.assertEqual(target.read_bytes(),b"new")
            self.assertEqual(len(calls),2)

    def test_permanent_windows_denial_is_bounded_and_retains_committed_bytes(self):
        import os, tempfile
        from pathlib import Path
        from backend.core.blockchain import persistence
        if os.name != "nt": self.skipTest("Windows sharing semantics")
        with tempfile.TemporaryDirectory(dir=Path.cwd()/".runtime") as folder:
            target=Path(folder)/"state.json";target.write_bytes(b"old")
            error=PermissionError("synthetic access denial");error.winerror=5
            with patch.object(persistence.os,"replace",side_effect=error) as replace, patch.object(persistence.time,"sleep"):
                with self.assertRaises(PermissionError):persistence.atomic_write(target,b"new")
            self.assertEqual(replace.call_count,7)
            self.assertEqual(target.read_bytes(),b"old")
            self.assertEqual(list(Path(folder).glob("*.tmp")),[])


class LocalOperatorIsolationTests(TestCase):
    def test_operator_signer_cannot_use_public_profile(self):
        with patch.object(demo_server.chain,"NETWORK_PROFILE","sepolia"):
            with self.assertRaisesRegex(RuntimeError,"Hardhat"):
                demo_server.LocalOperator().credentials("ROOT_AUTHORIZER","root_grant",{})

    def test_policy_provisioning_cannot_use_public_profile(self):
        with patch.object(demo_server.chain,"NETWORK_PROFILE","sepolia"), patch.object(demo_server.chain,"connect") as connect:
            with self.assertRaisesRegex(RuntimeError,"Hardhat"):
                demo_server.provision_local_policy()
            connect.assert_not_called()


class GraphLiveStatusTests(TestCase):
    def test_contract_revocation_overrides_stale_local_agent_status(self):
        from contextlib import nullcontext
        from unittest.mock import MagicMock
        from backend.api import services
        from backend.core.authorization import agents
        from backend.core.blockchain import integration
        contract=MagicMock();contract.address="0x"+"12"*20
        contract.functions.agentAddresses.return_value.call.return_value="0x"+"34"*20
        contract.functions.agentRevoked.side_effect=lambda key:SimpleNamespace(call=lambda:key==integration.agent_hash("Agent_C"))
        with patch.object(services,"prepare_runtime"),patch.object(services,"canonical_context",nullcontext),patch.object(services.chain,"load_state",return_value={"credentials":{},"records":{}}),patch.object(services.chain,"contract_context",return_value=(Mock(),contract,"0x"+"56"*20,{})),patch.object(agents.AGENTS["Agent_C"],"status","ACTIVE"):
            graph=services.delegation_graph()
        states={node["id"]:node["data"]["status"] for node in graph["nodes"]}
        self.assertEqual(states["Agent_C"],"DECOMMISSIONED")
        self.assertEqual(states["Agent_B"],"ACTIVE")
