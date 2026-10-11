"""Adversarial isolated fixtures for provenance, corruption and API boundaries."""

from copy import deepcopy
import json
from unittest import TestCase
from unittest.mock import patch

from backend.api import services
from backend.api.schemas import ActionInput
from backend.api.tests import test_batched_evidence as fixtures
from backend.core.blockchain.evidence import EvidenceError
from backend.core.blockchain import chain


class EvidenceFailureTests(TestCase):
    def setUp(self):
        self.fixture = fixtures.BatchedEvidenceTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.client = self.fixture.client
        self.manager = self.fixture.manager
        self.folder = self.fixture.directory

    def replace_json(self, name, mutate):
        path = self.folder / name
        value = json.loads(path.read_text())
        mutate(value)
        path.write_text(json.dumps(value))

    def test_invalid_timestamps_reject_before_governance_or_persistence(self):
        before = self.manager.audit_store.path.read_bytes()
        with patch.object(services, 'run_governance_pipeline') as run:
            for value in ('invalid', '2026-10-01T00:00:00', '2026-10-01', '', '2026-02-30T00:00:00Z', 123, True):
                with self.subTest(value=value):
                    response = self.client.post('/api/governance/evaluate', json={'actor':'Agent_B','action':'CREATE_ORDER','timestamp':value})
                    self.assertEqual(response.status_code,422)
            run.assert_not_called()
        self.assertEqual(self.manager.audit_store.path.read_bytes(),before)

    def test_timezone_normalization_and_optional_timestamp(self):
        action=ActionInput(actor='Agent_B',action='CREATE_ORDER',timestamp='2026-10-01T05:30:00+05:30')
        self.assertEqual(action.timestamp,'2026-10-01T00:00:00Z')
        self.assertIsNotNone(ActionInput(actor='Agent_B',action='CREATE_ORDER').as_injected_action()['timestamp'])

    def test_invalid_websocket_timestamp_never_runs_pipeline(self):
        with patch.object(services,'run_governance_pipeline') as run, self.client.websocket_connect('/ws/governance') as socket:
            socket.send_json({'action':{'actor':'Agent_B','action':'CREATE_ORDER','timestamp':'invalid'}})
            self.assertEqual(socket.receive_json()['event'],'ERROR')
            run.assert_not_called()

    def test_action_id_only_cannot_be_appended(self):
        before=self.manager.audit_store.path.read_bytes()
        with self.assertRaises(EvidenceError): self.manager.audit_store.append({'action_id':'invalid'})
        self.assertEqual(self.manager.audit_store.path.read_bytes(),before)

    def test_corrupt_jsonl_is_controlled_and_not_rewritten(self):
        self.manager.audit_store.path.write_text('{broken SYNTHETIC_TOKEN')
        before=self.manager.audit_store.path.read_bytes()
        for path in ('/api/audit/logs','/api/audit/actions/known','/api/final-report','/api/scenarios/normal'):
            with self.subTest(path=path):
                response=self.client.request('POST' if '/scenarios/' in path else 'GET',path)
                self.assertEqual(response.status_code,503)
                self.assertNotIn('SYNTHETIC_TOKEN',response.text)
        self.assertEqual(self.manager.audit_store.path.read_bytes(),before)

    def test_missing_record_fields_are_controlled(self):
        self.manager.audit_store.path.write_text(json.dumps({'action_id':'broken'})+'\n')
        self.assertEqual(self.client.get('/api/final-report').status_code,503)

    def test_bad_nested_record_types_are_controlled(self):
        records=self.manager.audit_store.list_records()
        for field,value in (('metadata',[]),('anomaly_result',{}),('revocation_status','bad'),('timestamp','invalid')):
            with self.subTest(field=field):
                bad=deepcopy(records);bad[0][field]=value
                self.manager.audit_store.path.write_text('\n'.join(json.dumps(r) for r in bad)+'\n')
                self.assertEqual(self.client.get('/api/audit/logs').status_code,503)

    def test_duplicate_stored_ids_fail_closed(self):
        content=self.manager.audit_store.path.read_bytes()
        self.manager.audit_store.path.write_bytes(content+content.splitlines()[0]+b'\n')
        self.assertEqual(self.client.get('/api/audit/logs').status_code,503)

    def test_invalid_deployment_json_all_consumers(self):
        (self.folder/'deployment.json').write_text('{"password": "SYNTHETIC_TOKEN", broken')
        for path in ('/api/health','/api/audit/status','/api/audit/batches','/api/final-report'):
            response=self.client.get(path)
            self.assertEqual(response.status_code,503)
            self.assertNotIn('SYNTHETIC_TOKEN',response.text)

    def test_wrong_profile_deployment_is_rejected(self):
        self.replace_json('deployment.json',lambda d:d.update(chain_id=31337))
        for path in ('/api/health','/api/audit/status','/api/audit/batches','/api/final-report'):
            with self.subTest(path=path):self.assertEqual(self.client.get(path).status_code,409)

    def test_wrong_batch_chain_is_rejected(self):
        self.replace_json('batches.json',lambda d:d['batches'][0].update(blockchain_chain_id=31337))
        for path in ('/api/audit/status','/api/audit/batches','/api/final-report'):
            with self.subTest(path=path):self.assertEqual(self.client.get(path).status_code,409)

    def test_wrong_batch_contract_is_rejected(self):
        self.replace_json('batches.json',lambda d:d['batches'][0].update(blockchain_contract_address='0x'+'78'*20))
        self.assertEqual(self.client.get('/api/final-report').status_code,409)

    def test_wrong_legacy_proof_network_is_rejected(self):
        self.replace_json('ethereum_state.json',lambda d:d['records'].update({'bad':{'kind':'delegation','status':'anchored','proof':{'chain_id':31337,'contract_address':'0x'+'12'*20}}}))
        self.assertEqual(self.client.get('/api/final-report').status_code,409)

    def test_invalid_state_container_is_controlled(self):
        self.replace_json('ethereum_state.json',lambda d:d.update(records=[]))
        self.assertEqual(self.client.get('/api/final-report').status_code,503)

    def test_invalid_batch_mapping_is_controlled(self):
        self.replace_json('batches.json',lambda d:d['action_index'].update({'missing':'batch:missing'}))
        self.assertEqual(self.client.get('/api/audit/batches').status_code,503)

    def test_invalid_batch_root_is_controlled(self):
        self.replace_json('batches.json',lambda d:d['batches'][0].update(merkle_root='0x'+'00'*32))
        self.assertEqual(self.client.get('/api/audit/batches').status_code,503)

    def test_missing_saved_scenario_is_404(self):
        self.manager.audit_store.path.write_text('')
        self.assertEqual(self.client.post('/api/scenarios/normal').status_code,404)

    def test_missing_saved_batch_is_503(self):
        (self.folder/'batches.json').unlink()
        self.assertEqual(self.client.post('/api/scenarios/normal').status_code,503)

    def test_unavailable_saved_proof_is_503(self):
        with patch.object(services,'trace_audit_record',return_value={'action_proof_verified':False}):
            self.assertEqual(self.client.post('/api/scenarios/normal').status_code,503)

    def test_unknown_audit_resources_are_404(self):
        for path in ('/api/audit/actions/unknown','/api/audit/actions/unknown/proof','/api/audit/batches/unknown'):
            with self.subTest(path=path):self.assertEqual(self.client.get(path).status_code,404)

    def test_graph_missing_or_wrong_network_proof_is_controlled(self):
        from unittest.mock import Mock
        contract=Mock();contract.address='0x'+'12'*20
        contract.functions.agentAddresses.return_value.call.return_value='0x'+'56'*20
        contract.functions.rootAuthorizer.return_value.call.return_value='0x'+'56'*20
        source={'delegator':'Agent_A','delegatee':'Agent_B','permission':'CREATE_AGENT','authority_source':'ROOT_AUTHORIZER','status':'ACTIVE'}
        self.replace_json('ethereum_state.json',lambda d:d.update(credentials={},records={'broken':{'kind':'delegation','status':'pending','source':source}}))
        deployment=json.loads((self.folder/'deployment.json').read_text())
        with patch.object(chain,'contract_context',return_value=(Mock(),contract,None,deployment)):
            response=self.client.get('/api/delegation-graph')
            self.assertEqual(response.status_code,503)
            self.assertEqual(response.json()['detail']['code'],'PROOF_UNAVAILABLE')
            self.replace_json('ethereum_state.json',lambda d:d['records']['broken'].update(status='anchored',proof={'chain_id':31337,'contract_address':contract.address}))
            self.assertEqual(self.client.get('/api/delegation-graph').status_code,409)

    def test_sepolia_unavailability_does_not_fallback_to_hardhat(self):
        with patch.object(chain,'connect',side_effect=ConnectionError('offline')):
            response=self.client.get('/api/audit/status')
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json()['chain_id'],11155111)
        self.assertFalse(response.json()['rpc_connected'])

    def test_wrong_rpc_chain_never_returns_connected(self):
        from unittest.mock import Mock
        web3=Mock();web3.eth.chain_id=31337;web3.eth.block_number=1
        with patch.object(chain,'connect',return_value=web3):
            response=self.client.get('/api/audit/status')
        self.assertNotEqual(response.json().get('connection_status'),'CONNECTED')
        self.assertEqual(response.status_code,409)

    def test_null_provenance_is_controlled(self):
        self.replace_json('ethereum_state.json',lambda d:d['records'].update({'bad':{'kind':'delegation','status':'anchored','proof':None}}))
        self.assertEqual(self.client.get('/api/final-report').status_code,503)

    def test_invalid_utf8_record_storage_is_controlled(self):
        self.manager.audit_store.path.write_bytes(b'\xff\xfe')
        self.assertEqual(self.client.get('/api/audit/logs').status_code,503)

    def test_duplicate_json_member_is_corrupt_evidence(self):
        path=self.folder/'deployment.json'
        path.write_text('{"chain_id":31337,"chain_id":11155111,"contract_address":"0x'+'12'*20+'"}')
        self.assertEqual(self.client.get('/api/health').status_code,503)

    def test_malformed_anchor_claim_is_controlled(self):
        self.replace_json('batches.json',lambda d:d['batches'][0].update(anchor_claim=[]))
        self.assertEqual(self.client.get('/api/audit/batches').status_code,503)

    def test_malformed_pending_timestamp_is_controlled(self):
        self.replace_json('batches.json',lambda d:d.update(pending_since={'missing':'invalid'}))
        self.assertEqual(self.client.get('/api/audit/status').status_code,503)

    def test_nonfinite_override_rejected_before_verification(self):
        from backend.api.schemas import AuditVerifyInput
        from pydantic import ValidationError
        for value in (float('nan'),float('inf')):
            with self.assertRaises(ValidationError):AuditVerifyInput(record_override={'score':value})

    def test_nonfinite_json_http_validation_is_422(self):
        response=self.client.post('/api/audit/actions/audit:fixture-0/verify',content='{"record_override":{"score":NaN}}',headers={'Content-Type':'application/json'})
        self.assertEqual(response.status_code,422)

    def test_corrupt_model_metrics_are_rejected(self):
        from backend.core.blockchain.evidence import validate_model_metrics
        for value in ({}, {'isolation_forest': []}):
            with self.assertRaises(EvidenceError):validate_model_metrics(value)

    def test_provider_failure_is_controlled_and_sanitized(self):
        with patch.object(services,'agents',side_effect=RuntimeError('failed https://fake.example/v2/SYNTHETIC_SECRET')):
            with self.assertLogs('backend.api.main',level='ERROR') as logs:
                response=self.client.get('/api/agents')
        self.assertEqual(response.status_code,503)
        self.assertNotIn('SYNTHETIC_SECRET',response.text+''.join(logs.output))
        self.assertEqual(response.json()['detail']['code'],'RPC_UNAVAILABLE')
        with patch.object(services,'agents',side_effect=TimeoutError('synthetic timeout')):
            with self.assertLogs('backend.api.main',level='ERROR'):
                response=self.client.get('/api/agents')
        self.assertEqual(response.status_code,503)
        self.assertEqual(response.json()['detail']['code'],'RPC_TIMEOUT')

    def test_corrupt_legacy_report_consumers_fail_closed(self):
        with patch.object(chain,'NETWORK_PROFILE','hardhat'),patch.object(services,'REPORT_PATH',self.folder/'report.json'):
            (self.folder/'report.json').write_text('{}')
            for path in ('/api/system/overview','/api/metrics'):
                self.assertEqual(self.client.get(path).status_code,503)
