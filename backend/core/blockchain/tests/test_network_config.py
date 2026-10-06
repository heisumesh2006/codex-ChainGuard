"""Sepolia profile safety checks; tests never connect to a public RPC."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from eth_account import Account
from fastapi.testclient import TestClient
from backend.api.main import app
from backend.core.blockchain import chain
from backend.api import services


ROOT = Path(__file__).resolve().parents[4]


class NetworkConfigurationTests(unittest.TestCase):
    def _audit_status_for_profile(self, profile: str) -> tuple[dict, dict, dict]:
        test_root = ROOT / ".runtime"
        test_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=test_root) as temporary:
            root = Path(temporary)
            governance_dir = root / "governance"
            governance_dir.mkdir()
            blockchain_path = root / "blockchain" / ("sepolia" if profile == "sepolia" else "") / "deployment.json"
            blockchain_path.parent.mkdir(parents=True, exist_ok=True)
            local_address = "0x" + "1" * 40
            sepolia_address = "0x" + "2" * 40
            (governance_dir / "deployment.json").write_text(
                json.dumps({"chain_id": 31337, "contract_address": local_address}), encoding="utf-8"
            )
            blockchain_path.write_text(
                json.dumps({
                    "chain_id": 11155111 if profile == "sepolia" else 31337,
                    "contract_address": sepolia_address if profile == "sepolia" else "0x" + "3" * 40,
                }), encoding="utf-8"
            )
            expected_address = sepolia_address if profile == "sepolia" else local_address
            web3 = Mock()
            web3.eth.chain_id = 11155111 if profile == "sepolia" else 31337
            web3.eth.block_number = 12345
            web3.eth.get_code.side_effect = lambda address: b"\x01" if address == expected_address else b""
            manager = Mock()
            manager.pending_summary.return_value = {"pending_log_count": 0}
            manager.list_batches.return_value = []
            manager.batch_size = 5
            manager.max_age_seconds = 30
            with (
                patch.object(services, "DATA_DIR", governance_dir),
                patch.object(chain, "NETWORK_PROFILE", profile),
                patch.object(chain, "DEPLOYMENT_PATH", blockchain_path),
                patch.object(chain, "connect", return_value=web3),
                patch.object(services.pipeline, "AUDIT_BATCH_MANAGER", manager),
                TestClient(app) as client,
            ):
                status = client.get("/api/audit/status")
                health = client.get("/api/health")
                batches = client.get("/api/audit/batches")
            self.assertEqual((status.status_code, health.status_code, batches.status_code), (200, 200, 200))
            return status.json(), health.json(), batches.json()

    def test_hardhat_audit_status_keeps_canonical_governance_deployment(self):
        status, health, batches = self._audit_status_for_profile("hardhat")
        expected_address = "0x" + "1" * 40
        self.assertEqual(status["contract_address"], expected_address)
        self.assertEqual(status["deployment_contract_address"], expected_address)
        self.assertTrue(status["contract_available"])
        self.assertEqual(status["connection_status"], "CONNECTED")
        self.assertEqual(health["contract_address"], expected_address)
        self.assertFalse(status["explorer_available"])
        self.assertEqual(batches["total"], 0)

    def test_sepolia_audit_status_uses_blockchain_deployment(self):
        status, health, batches = self._audit_status_for_profile("sepolia")
        expected_address = "0x" + "2" * 40
        self.assertEqual(status["contract_address"], expected_address)
        self.assertEqual(status["deployment_contract_address"], expected_address)
        self.assertTrue(status["contract_available"])
        self.assertEqual(status["connection_status"], "CONNECTED")
        self.assertEqual(status["chain_id"], 11155111)
        self.assertEqual(health["contract_address"], expected_address)
        self.assertEqual(status["explorer"]["contract_url"], f"https://sepolia.etherscan.io/address/{expected_address}")
        self.assertEqual(batches["total"], 0)

    def test_sepolia_profile_parses_without_leaking_configuration(self):
        env = os.environ.copy()
        env.update({
            "CHAINGUARD_NETWORK": "sepolia",
            "SEPOLIA_RPC_URL": "https://rpc.example.invalid/api-key-marker",
            "SEPOLIA_PRIVATE_KEY": "0x" + "1" * 64,
        })
        completed = subprocess.run(
            [sys.executable, "-c", (
                "import json; from backend.core.blockchain import chain; "
                "print(json.dumps({'network': chain.NETWORK_PROFILE, 'chain_id': "
                "chain.EXPECTED_CHAIN_IDS[chain.NETWORK_PROFILE], 'data_dir': "
                "chain.NETWORK_DATA_DIR.name}))"
            )],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(completed.stdout.strip(), '{"network": "sepolia", "chain_id": 11155111, "data_dir": "sepolia"}')
        self.assertNotIn("api-key-marker", completed.stdout)
        self.assertNotIn("" + "1" * 64, completed.stdout)

    def test_missing_sepolia_rpc_has_clear_error(self):
        with patch.object(chain, "NETWORK_PROFILE", "sepolia"), patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "SEPOLIA_RPC_URL is not configured"):
                chain.validate_configuration()

    def test_sepolia_chain_id_is_enforced(self):
        class Eth:
            chain_id = 31337

        class Provider:
            eth = Eth()

        with patch.object(chain, "NETWORK_PROFILE", "sepolia"):
            with self.assertRaisesRegex(RuntimeError, "requires chain ID 11155111"):
                chain._validate_selected_network(Provider())

    def test_sepolia_transaction_is_signed_locally(self):
        private_key = "0x" + "11" * 32
        account = Account.from_key(private_key)
        builder = Mock()
        builder.build_transaction.return_value = {"from": account.address, "gas": 21000, "to": account.address}
        web3 = Mock()
        web3.eth.get_transaction_count.return_value = 3
        web3.eth.chain_id = 11155111
        web3.eth.gas_price = 9
        web3.eth.send_raw_transaction.return_value = b"tx-hash"
        with patch.object(chain, "NETWORK_PROFILE", "sepolia"), patch.dict(
            os.environ, {"SEPOLIA_PRIVATE_KEY": private_key}, clear=False
        ):
            tx_hash = chain.submit_transaction(web3, builder, account.address)
        self.assertEqual(tx_hash, b"tx-hash")
        builder.transact.assert_not_called()
        signed_tx = web3.eth.send_raw_transaction.call_args.args[0]
        self.assertNotIn(private_key.encode(), signed_tx)

    def test_explorer_links_are_only_for_sepolia(self):
        self.assertIsNone(services._audit_explorer_base(31337))
        self.assertEqual(services._audit_explorer_base(11155111), "https://sepolia.etherscan.io")
        self.assertIsNone(services._audit_explorer_base(1))

    def test_health_never_reflects_an_rpc_credential(self):
        credential = "never-return-this-rpc-token"
        with patch.object(services.chain, "connect", side_effect=RuntimeError(f"RPC failed: {credential}")):
            response = services.health()
        self.assertEqual(response["status"], "DEGRADED")
        self.assertEqual(response["error"], "RPC_OFFLINE")
        self.assertNotIn(credential, repr(response))


if __name__ == "__main__":
    unittest.main()
