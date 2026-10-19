"""Provider diagnostics must be safe before storage, HTTP and logging."""

from copy import deepcopy
import io
import json
import logging
import os
from pathlib import Path
import tempfile
import traceback
from unittest import TestCase
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.api import services
from backend.api.main import app
from backend.core.blockchain import chain
from backend.core.blockchain.audit_log import AuditLogStore
from backend.core.blockchain.batch_manager import BatchManager
from backend.core.blockchain.diagnostics import public_data, public_response, redact_text, safe_error
from backend.core.blockchain.tests.test_batching import record
from backend.core.governance import pipeline


class DiagnosticTests(TestCase):
    sentinel = "SYNTHETIC_NESTED_TOKEN"

    def nested_error(self, implicit=False, levels=1):
        try:
            raise TimeoutError("RPC failed https://example.invalid?token=" + self.sentinel)
        except TimeoutError as inner:
            try:
                if implicit:
                    raise RuntimeError("provider request failed")
                raise RuntimeError("provider request failed") from inner
            except RuntimeError as outer:
                for _ in range(levels - 1):
                    wrapper = RuntimeError("wrapped provider failure")
                    wrapper.__cause__ = outer
                    outer = wrapper
                return outer

    def test_nested_explicit_implicit_multilevel_logs_and_tracebacks(self):
        for implicit, levels in ((False, 1), (False, 4), (True, 1)):
            with self.subTest(implicit=implicit, levels=levels):
                error = self.nested_error(implicit, levels)
                @public_response
                def fail():
                    raise error
                output = io.StringIO()
                logger = logging.getLogger("chainguard.nested.test")
                handler = logging.StreamHandler(output)
                logger.addHandler(handler)
                try:
                    try:
                        fail()
                    except RuntimeError as safe:
                        logger.exception("Public request failed")
                        logger.error("Public request failed", exc_info=True)
                        rendered = "".join(traceback.format_exception(safe))
                        self.assertNotIn(self.sentinel, rendered)
                        self.assertIsNone(safe.__cause__)
                        self.assertTrue(safe.__suppress_context__)
                        self.assertIn("RPC_TIMEOUT", str(safe))
                    self.assertNotIn(self.sentinel, output.getvalue())
                finally:
                    logger.removeHandler(handler)

    def test_exception_chain_cycle_does_not_hang(self):
        error = self.nested_error()
        error.__cause__.__context__ = error
        self.assertIn("RPC_TIMEOUT", safe_error(error))

    def test_nested_websocket_error_serialization(self):
        with patch.object(services, "scenario_action", return_value={"actor": "Agent_B", "action": "USE_PERMISSION"}), \
                patch.object(services, "run_scenario", side_effect=self.nested_error()), \
                TestClient(app) as client, client.websocket_connect("/ws/governance") as socket:
            socket.send_json({"scenario": "normal"})
            socket.receive_json()
            response = socket.receive_json()
            self.assertNotIn(self.sentinel, json.dumps(response))
            self.assertIn("RPC_TIMEOUT", response["detail"])

    def test_nested_http_error_serialization(self):
        error = LookupError("public action not found")
        error.__cause__ = self.nested_error()
        with patch.object(services, "audit_action", side_effect=error), TestClient(app) as client:
            response = client.get("/api/audit/actions/synthetic-missing")
        self.assertEqual(response.status_code, 404)
        self.assertNotIn(self.sentinel, response.text)
        self.assertIn("RPC_TIMEOUT", response.json()["detail"])

    def test_unknown_provider_path_and_multiple_credentials(self):
        message = "https://example.invalid/v2/SYNTHETIC_PATH https://example-user:beef@example.invalid?token=SYNTHETIC_QUERY Bearer SYNTHETIC_AUTH"
        for diagnostic in (True, False):
            result = redact_text(message, diagnostic=diagnostic)
            for secret in ("SYNTHETIC_PATH", "beef", "SYNTHETIC_QUERY", "SYNTHETIC_AUTH"):
                self.assertNotIn(secret, result)

    def test_harmless_public_exception_remains_visible(self):
        @public_response
        def fail():
            raise ValueError("ordinary harmless failure")
        with self.assertRaises(ValueError) as caught:
            fail()
        self.assertIn("ordinary harmless failure", str(caught.exception))

    def test_exact_short_password_preserves_all_public_identifiers(self):
        original = {"transaction_hash": "0x" + "beef" * 16,
                    "agent_address": "0x" + "beef" * 10,
                    "merkle_root": "0x" + "beef" * 16,
                    "batch_id": "batch:" + "beef" * 16,
                    "contract_address": "0x" + "beef" * 10,
                    "proof_hash": "0x" + "beef" * 16, "block_number": 11155111}
        with patch.dict(os.environ, {"SEPOLIA_RPC_URL": "https://example-user:beef@example.invalid", "SEPOLIA_PRIVATE_KEY": ""}):
            self.assertEqual(public_data(original), original)
            self.assertEqual(redact_text("ordinary beef order", diagnostic=True), "ordinary beef order")
            self.assertNotIn("beef", redact_text("Failed https://example-user:beef@example.invalid"))
            for value in original.values():
                if isinstance(value, str):
                    self.assertEqual(redact_text(value, diagnostic=True), value)

    def test_nested_error_preserves_hash_and_redacts_multiple_secrets(self):
        public_hash = "0x" + "beef" * 16
        error = self.nested_error(levels=3)
        error.args = ("Transaction " + public_hash + " failed https://example.invalid?token=SYNTHETIC_QUERY Authorization: Bearer SYNTHETIC_AUTH",)
        result = safe_error(error)
        self.assertIn(public_hash, result)
        for secret in (self.sentinel, "SYNTHETIC_QUERY", "SYNTHETIC_AUTH"):
            self.assertNotIn(secret, result)
        self.assertEqual(safe_error(result), result)

    def assert_redacted(self, message, *secrets):
        result = safe_error(RuntimeError(message))
        for secret in secrets:
            self.assertNotIn(secret, result)
        self.assertIn("[REDACTED]", result)

    def test_harmless_failure_retains_useful_detail(self):
        self.assertIn("simulated RPC outage", safe_error(ConnectionError("simulated RPC outage")))

    def test_provider_url_token(self):
        self.assert_redacted("Failed https://eth-sepolia.g.alchemy.com/v2/EXAMPLE_TOKEN", "EXAMPLE_TOKEN", "alchemy.com")

    def test_url_credentials(self):
        self.assert_redacted("Failed https://example-user:example-password@example.com", "example-user", "example-password")

    def test_query_token(self):
        self.assert_redacted("Failed https://example.com?api_key=EXAMPLE_QUERY", "EXAMPLE_QUERY")

    def test_authorization_header(self):
        for message in ("Authorization: Bearer EXAMPLE_AUTH", "{'Authorization': 'Bearer EXAMPLE_AUTH'}", "Authorization: Basic EXAMPLE_AUTH"):
            with self.subTest(message=message):
                self.assert_redacted(message, "EXAMPLE_AUTH")

    def test_private_key_like_values(self):
        key = "ab" * 32
        self.assert_redacted("private key: 0x" + key, key)
        self.assert_redacted("signer failed with " + key, key)

    def test_configured_bare_token_and_key(self):
        token = "example-provider-token"
        key = "cd" * 32
        with patch.dict(os.environ, {"SEPOLIA_RPC_URL": "https://example.com/v3/" + token,
                                     "SEPOLIA_PRIVATE_KEY": "0x" + key}):
            self.assert_redacted(token + " failed with " + key, token, key)

    def test_diagnostic_codes_and_idempotence(self):
        cases = ((TimeoutError("request timed out"), "RPC_TIMEOUT"),
                 (RuntimeError("Sepolia requires chain ID 11155111"), "CHAIN_MISMATCH"),
                 (RuntimeError("Contract is not deployed"), "CONTRACT_UNAVAILABLE"),
                 (RuntimeError("Ethereum transaction reverted"), "TRANSACTION_FAILED"),
                 (RuntimeError("Proof verification failed"), "PROOF_VERIFICATION_FAILED"))
        for error, code in cases:
            with self.subTest(code=code):
                sanitized = safe_error(error)
                self.assertTrue(sanitized.startswith(code + ":"), sanitized)
                self.assertEqual(safe_error(sanitized), sanitized)

    def test_public_hashes_explorer_and_shape_retained_without_mutation(self):
        original = {"merkle_root": "0x" + "ef" * 32, "proof_siblings": ["0x" + "ab" * 32],
                    "explorer_contract_url": "https://sepolia.etherscan.io/address/example",
                    "blockchain": {"rpc_url": "https://example.com?token=EXAMPLE_TOKEN"},
                    "anchor_error": "https://example.com?token=EXAMPLE_TOKEN"}
        before = deepcopy(original)
        sanitized = public_data(original)
        self.assertEqual(set(sanitized), set(original))
        self.assertEqual(sanitized["merkle_root"], original["merkle_root"])
        self.assertEqual(sanitized["proof_siblings"], original["proof_siblings"])
        self.assertEqual(sanitized["explorer_contract_url"], original["explorer_contract_url"])
        self.assertEqual(sanitized["blockchain"]["rpc_url"], "")
        self.assertNotIn("EXAMPLE_TOKEN", json.dumps(sanitized))
        self.assertEqual(original, before)

    def test_public_service_exception_logs_are_safe(self):
        @public_response
        def fail():
            raise ConnectionError("Failed https://example.com?token=EXAMPLE_TOKEN")
        output = io.StringIO()
        logger = logging.getLogger("chainguard.diagnostics.test")
        handler = logging.StreamHandler(output)
        logger.addHandler(handler)
        try:
            try:
                fail()
            except ConnectionError:
                logger.exception("Service request failed")
            self.assertNotIn("EXAMPLE_TOKEN", output.getvalue())
            self.assertIn("RPC_UNAVAILABLE", output.getvalue())
        finally:
            logger.removeHandler(handler)

    def test_malformed_provider_urls_do_not_break_redaction(self):
        self.assert_redacted("Failed https://[malformed/EXAMPLE_TOKEN", "EXAMPLE_TOKEN")
        self.assertEqual(public_data({"rpc_url": "https://[malformed"}), {"rpc_url": ""})

    def test_websocket_provider_error_is_safe(self):
        with patch.object(services, "scenario_action", return_value={"actor": "Agent_B", "action": "USE_PERMISSION"}), \
                patch.object(services, "run_scenario", side_effect=RuntimeError("https://example.com?token=EXAMPLE_TOKEN")), \
                TestClient(app) as client, client.websocket_connect("/ws/governance") as socket:
            socket.send_json({"scenario": "normal"})
            self.assertEqual(socket.receive_json()["event"], "ACTION_RECEIVED")
            response = socket.receive_json()
            self.assertEqual(response["event"], "ERROR")
            self.assertNotIn("EXAMPLE_TOKEN", json.dumps(response))
            self.assertIn("RPC_UNAVAILABLE", response["detail"])


class PersistedDiagnosticTests(TestCase):
    def setUp(self):
        root = services.ROOT / ".runtime"
        root.mkdir(exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=root)
        self.addCleanup(self.directory.cleanup)
        store = AuditLogStore(Path(self.directory.name) / "audit.jsonl")
        self.manager = BatchManager(store, Path(self.directory.name) / "batches.json", batch_size=1)
        store.append(record(500))
        self.batch_id = self.manager.seal_due_batches()[0]["batch_id"]

    def test_exact_f1_reproduction_persistence_api_and_logs(self):
        secret = "QA_SENTINEL_PROVIDER_TOKEN"
        output = io.StringIO()
        logger = logging.getLogger("chainguard.batch.test")
        handler = logging.StreamHandler(output)
        logger.addHandler(handler)
        try:
            with patch.object(chain, "contract_context", side_effect=RuntimeError(secret)):
                try:
                    self.manager.anchor_batch(self.batch_id)
                except RuntimeError:
                    logger.exception("Anchor failed")
            persisted = self.manager.metadata_path.read_text()
            self.assertNotIn(secret, persisted)
            self.assertNotIn(secret, output.getvalue())
            self.assertIn("RPC_UNAVAILABLE", persisted)
            with patch.object(pipeline, "AUDIT_BATCH_MANAGER", self.manager), TestClient(app) as client:
                response = client.get("/api/audit/batches/" + self.batch_id)
            self.assertEqual(response.status_code, 200)
            self.assertNotIn(secret, response.text)
            self.assertEqual(response.json()["proof_status"], "ANCHOR FAILED")
            self.assertEqual(response.json()["anchor_error"], self.manager.get_batch(self.batch_id)["anchor_error"])
            self.assertTrue(response.json()["anchor_retry"])
        finally:
            logger.removeHandler(handler)

    def test_old_error_state_sanitized_in_all_batch_api_representations(self):
        state = self.manager._read_state()
        state["batches"][0].update(anchor_error="Failed https://example.com?token=EXAMPLE_TOKEN",
                                   blockchain_rpc_url="https://example.com/v2/EXAMPLE_TOKEN")
        self.manager._write_state(state)
        before = self.manager.metadata_path.read_bytes()
        with patch.object(pipeline, "AUDIT_BATCH_MANAGER", self.manager), \
                patch.object(chain, "connect", side_effect=ConnectionError("offline")), TestClient(app) as client:
            for path in ("/api/audit/batches", "/api/audit/batches/" + self.batch_id,
                         "/api/audit/logs", "/api/audit/actions/audit:test-500"):
                with self.subTest(path=path):
                    response = client.get(path)
                    self.assertEqual(response.status_code, 200)
                    self.assertNotIn("EXAMPLE_TOKEN", response.text)
        self.assertEqual(self.manager.metadata_path.read_bytes(), before)

    def test_legacy_commit_failure_persisted_and_raised_safely(self):
        root = Path(self.directory.name)
        with patch.object(chain, "STATE_PATH", root / "state.json"), \
                patch.object(chain, "CREDENTIALS_PATH", root / "credentials.json"), \
                patch.object(chain, "contract_context", side_effect=TimeoutError("https://example.com?token=EXAMPLE_TOKEN")):
            with self.assertRaises(TimeoutError) as caught:
                chain.commit("action", {"record_id": "mock"}, lambda *args: None)
            self.assertNotIn("EXAMPLE_TOKEN", str(caught.exception))
            self.assertNotIn("EXAMPLE_TOKEN", (root / "state.json").read_text())
            self.assertIn("RPC_TIMEOUT", (root / "state.json").read_text())

    def test_nested_batch_error_persistence_http_and_traceback(self):
        error = DiagnosticTests().nested_error(levels=3)
        with patch.object(chain, "contract_context", side_effect=error):
            try:
                self.manager.anchor_batch(self.batch_id)
            except RuntimeError as safe:
                self.assertNotIn(DiagnosticTests.sentinel, "".join(traceback.format_exception(safe)))
        self.assertNotIn(DiagnosticTests.sentinel, self.manager.metadata_path.read_text())
        self.assertIn("RPC_TIMEOUT", self.manager.metadata_path.read_text())
        with patch.object(pipeline, "AUDIT_BATCH_MANAGER", self.manager), TestClient(app) as client:
            response = client.get("/api/audit/batches/" + self.batch_id)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(DiagnosticTests.sentinel, response.text)
