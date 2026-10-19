"""Real canonical hashing/Merkle checks; Ethereum reads use an isolated fixture."""
from copy import deepcopy
from unittest import TestCase
from unittest.mock import Mock, patch

from web3 import Web3

from backend.api.tests import test_batched_evidence as fixtures
from backend.core.blockchain import chain
from backend.core.blockchain.audit_log import canonicalize_record, hash_record
from backend.core.blockchain.batch_verifier import verify_proof
from backend.core.blockchain.evidence import EvidenceError
from backend.core.blockchain.merkle import hash_pair


class AuditTamperClarityTests(TestCase):
    def setUp(self):
        self.fixture = fixtures.BatchedEvidenceTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.manager, self.client = self.fixture.manager, self.fixture.client
        self.record = self.manager.audit_store.list_records()[0]
        self.action_id = self.record['action_id']
        self.path = f'/api/audit/actions/{self.action_id}/verify'
        self.root = self.manager.generate_proof(self.action_id)['merkle_root']
        self.web3, self.contract = Mock(), Mock()
        self.contract.functions.auditBatches.return_value.call.return_value = (
            bytes.fromhex(self.root[2:]), 5, 0, 0, '0x' + '56' * 20, 123, True)
        self.context = patch.object(chain, 'contract_context', return_value=(self.web3, self.contract, None, {}))
        self.context.start()
        self.addCleanup(self.context.stop)

    def test_target_copy_rehashes_rejects_and_preserves_original_and_all_files(self):
        before = {p.name: p.read_bytes() for p in self.fixture.directory.iterdir() if p.is_file()}
        original = self.client.post(self.path).json()
        self.assertEqual(original['result'], 'VERIFIED')
        candidate = deepcopy(self.record)
        candidate['target'] = f"{candidate['target'] or 'audit-record'} [tampered demo copy]"
        response = self.client.post(self.path, json={'record_override': candidate})
        self.assertEqual(response.status_code, 200)
        modified = response.json()
        self.assertEqual(modified['result'], 'TAMPERED')
        self.assertEqual(modified['record'], self.record)  # API returns stored data, candidate hash.
        self.assertNotEqual(original['record_hash'], modified['record_hash'])
        self.assertEqual(modified['record_hash'], Web3.to_hex(Web3.keccak(canonicalize_record(candidate))))
        proof = self.manager.generate_proof(self.action_id)
        self.assertFalse(verify_proof(candidate, proof, self.root))
        self.assertTrue(verify_proof(self.record, proof, self.root))
        folded = hash_record(candidate)
        for sibling in proof['siblings']:
            folded = hash_pair(sibling['hash'], folded) if sibling['position'] == 'left' else hash_pair(folded, sibling['hash'])
        self.assertNotEqual(folded, self.root)
        self.assertIsNone(modified['calculated_root'])  # Never invent an API-returned root.
        again = self.client.post(self.path).json()
        self.assertEqual(again['result'], 'VERIFIED')
        self.assertEqual(again['record_hash'], original['record_hash'])
        self.assertEqual(again['blockchain_root'], modified['blockchain_root'])
        self.assertEqual(again['blockchain_root'], self.root)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.fixture.directory.iterdir() if p.is_file()})
        self.web3.eth.send_transaction.assert_not_called()
        self.web3.eth.send_raw_transaction.assert_not_called()

    def test_client_supplied_verified_label_cannot_override_calculation(self):
        forged = {**self.record, 'target': 'changed', 'result': 'VERIFIED'}
        response = self.client.post(self.path, json={'record_override': forged})
        self.assertEqual(response.json()['result'], 'TAMPERED')

    def test_rpc_failure_never_verifies_original(self):
        with patch.object(chain, 'contract_context', side_effect=RuntimeError('synthetic RPC offline')):
            result = self.client.post(self.path).json()
        self.assertEqual(result['result'], 'VERIFY FAILED')
        self.assertIsNone(result['blockchain_root'])

    def test_missing_proof_is_controlled_not_tampered(self):
        with patch.object(self.manager, 'generate_proof', side_effect=EvidenceError('PROOF_UNAVAILABLE', 503)):
            result = self.client.post(self.path)
        self.assertEqual(result.status_code, 503)
        self.assertNotIn('TAMPERED', result.text)

    def test_wrong_network_metadata_cannot_verify(self):
        state = self.manager._read_state()
        state['batches'][0]['blockchain_chain_id'] = 31337
        self.manager._write_state(state)
        response = self.client.post(self.path)
        self.assertNotEqual(response.status_code, 200)
        self.assertNotIn('VERIFIED', response.text)
