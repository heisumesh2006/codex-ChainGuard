"""Sepolia profile safety checks; tests never connect to a public RPC."""

import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

from eth_account import Account
from backend.core.blockchain import chain
from backend.api import services


ROOT = Path(__file__).resolve().parents[4]


class NetworkConfigurationTests(unittest.TestCase):
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
