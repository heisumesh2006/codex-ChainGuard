"""Receipt-first, bounded, fail-closed anchoring recovery without public writes."""

from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from backend.core.blockchain import chain
from backend.core.blockchain.batch_manager import _matching_batch_event, batch_key
from backend.core.blockchain.evidence import EvidenceError
from backend.core.blockchain.tests import test_concurrency as fixtures


class RecoveryTests(TestCase):
    def setUp(self):
        self.web3,self.contract=Mock(),Mock()
        self.contract.address='0x'+'12'*20
        self.key,self.root=bytes.fromhex('34'*32),bytes.fromhex('56'*32)
        self.tx='0x'+'78'*32
        self.receipt=SimpleNamespace(status=1,blockNumber=500,logs=[{'address':self.contract.address}])
        self.web3.eth.get_transaction_receipt.return_value=self.receipt
        self.contract.events.AuditBatchAnchored.return_value.process_log.return_value={'args':{'batchId':self.key,'merkleRoot':self.root}}
        self.web3.eth.block_number=1000
        self.web3.eth.get_block.side_effect=lambda block:SimpleNamespace(timestamp=500 if 500<=block<=510 else block)

    def recover(self,**kwargs):
        return _matching_batch_event(self.web3,self.contract,self.key,self.root,**kwargs)

    def test_known_hash_uses_receipt_without_log_scan(self):
        self.assertIs(self.recover(transaction_hash=self.tx),self.receipt)
        self.web3.eth.get_logs.assert_not_called()

    def test_wrong_receipt_event_rejected(self):
        self.contract.events.AuditBatchAnchored.return_value.process_log.return_value={'args':{'batchId':bytes(32),'merkleRoot':self.root}}
        with self.assertRaises(EvidenceError):self.recover(transaction_hash=self.tx)

    def test_failed_receipt_rejected(self):
        self.receipt.status=0
        with self.assertRaises(EvidenceError):self.recover(transaction_hash=self.tx)

    def test_wrong_contract_receipt_rejected(self):
        self.receipt.logs=[{'address':'0x'+'99'*20}]
        with self.assertRaises(EvidenceError):self.recover(transaction_hash=self.tx)

    def test_bounded_fallback_adapts_to_provider_range_limit(self):
        ranges=[]
        def logs(query):
            low,high=query['fromBlock'],query['toBlock'];ranges.append((low,high))
            self.assertGreaterEqual(low,500);self.assertLessEqual(high,510)
            if high-low>1:raise ValueError('provider block range limit')
            return [SimpleNamespace(transactionHash=bytes.fromhex(self.tx[2:]))] if low<=500<=high else []
        self.web3.eth.get_logs.side_effect=logs
        self.assertIs(self.recover(deployment={'block_number':100},anchored_at=500),self.receipt)
        self.assertLessEqual(len(ranges),21)
        self.assertLessEqual(self.web3.eth.get_block.call_count,22)

    def test_missing_deployment_bound_never_scans(self):
        with self.assertRaises(EvidenceError):self.recover(anchored_at=500)
        self.web3.eth.get_logs.assert_not_called()

    def test_too_many_same_timestamp_blocks_fail_closed(self):
        self.web3.eth.get_block.side_effect=lambda block:SimpleNamespace(timestamp=500)
        with self.assertRaises(EvidenceError):self.recover(deployment={'block_number':100},anchored_at=500)
        self.web3.eth.get_logs.assert_not_called()

    def test_timeout_does_not_multiply_rpc_requests(self):
        self.web3.eth.get_logs.side_effect=TimeoutError('synthetic timeout')
        with self.assertRaises(EvidenceError):self.recover(deployment={'block_number':100},anchored_at=500)
        self.assertEqual(self.web3.eth.get_logs.call_count,1)

    def test_ambiguous_events_fail_closed(self):
        self.web3.eth.get_logs.return_value=[Mock(),Mock()]
        with self.assertRaises(EvidenceError):self.recover(deployment={'block_number':100},anchored_at=500)

    def test_signed_hash_is_persisted_before_broadcast(self):
        from eth_account import Account
        key='0x'+'11'*32
        account=Account.from_key(key)
        web3,builder=Mock(),Mock()
        web3.eth.get_transaction_count.return_value=3
        web3.eth.chain_id=11155111;web3.eth.gas_price=9
        builder.build_transaction.return_value={'from':account.address,'to':account.address,'gas':21000}
        seen=[]
        def broadcast(raw):
            self.assertEqual(len(seen),1)
            self.assertEqual(seen[0][0],chain.Web3.to_hex(chain.Web3.keccak(raw)))
            return bytes(32)
        web3.eth.send_raw_transaction.side_effect=broadcast
        with patch.object(chain,'NETWORK_PROFILE','sepolia'),patch.dict('os.environ',{'SEPOLIA_PRIVATE_KEY':key}):
            chain.submit_transaction(web3,builder,account.address,before_send=lambda tx,nonce:seen.append((tx,nonce)))
        self.assertEqual(seen[0][1],3)

    def test_failed_intent_persistence_prevents_broadcast(self):
        from eth_account import Account
        key='0x'+'11'*32;account=Account.from_key(key)
        web3,builder=Mock(),Mock()
        web3.eth.get_transaction_count.return_value=3;web3.eth.chain_id=11155111;web3.eth.gas_price=9
        builder.build_transaction.return_value={'from':account.address,'to':account.address,'gas':21000}
        with patch.object(chain,'NETWORK_PROFILE','sepolia'),patch.dict('os.environ',{'SEPOLIA_PRIVATE_KEY':key}):
            with self.assertRaises(OSError):
                chain.submit_transaction(web3,builder,account.address,before_send=Mock(side_effect=OSError('synthetic persistence failure')))
        web3.eth.send_raw_transaction.assert_not_called()

    def test_confirmed_revert_clears_claim_without_automatic_resend(self):
        with tempfile.TemporaryDirectory(dir=fixtures.TEMP_ROOT) as folder:
            store,manager=fixtures.stores(folder,size=1)
            store.append(fixtures.record(0));batch=manager.seal_due_batches()[0]
            with manager.state_transaction() as state:
                state['batches'][0]['anchor_claim']={'phase':'SUBMITTED','transaction_hash':self.tx}
            with fixtures.fake_chain(folder):
                w,_,_,_=chain.contract_context()
                w.eth.get_transaction_receipt.return_value=SimpleNamespace(status=0)
                with self.assertRaises(RuntimeError):manager.anchor_batch(batch['batch_id'])
                self.assertNotIn('anchor_claim',manager.get_batch(batch['batch_id']))
                self.assertFalse((Path(folder)/'mock-chain.json').exists())
                self.assertEqual(manager.anchor_batch(batch['batch_id'])['status'],'ANCHORED')

    def test_mined_submission_recovers_after_metadata_crash_without_resend(self):
        with tempfile.TemporaryDirectory(dir=fixtures.TEMP_ROOT) as folder:
            store,manager=fixtures.stores(folder,size=1)
            store.append(fixtures.record(0));batch=manager.seal_due_batches()[0]
            original=manager._persist_batch
            def crash_after_mine(value):
                if value['status']=='ANCHORED':raise OSError('synthetic crash before final snapshot')
                return original(value)
            with fixtures.fake_chain(folder):
                with patch.object(manager,'_persist_batch',side_effect=crash_after_mine):
                    with self.assertRaises(RuntimeError):manager.anchor_batch(batch['batch_id'])
                with patch('backend.core.blockchain.batch_manager._matching_batch_event',return_value=SimpleNamespace(status=1,transactionHash=bytes.fromhex('56'*32),blockNumber=1)):
                    self.assertEqual(manager.anchor_batch(batch['batch_id'])['status'],'ANCHORED')
            import json
            self.assertEqual(json.loads((Path(folder)/'mock-chain.json').read_text())['sends'],1)

    def test_pending_known_hash_never_grants_permission_to_resubmit(self):
        from web3.exceptions import TransactionNotFound
        with tempfile.TemporaryDirectory(dir=fixtures.TEMP_ROOT) as folder:
            store,manager=fixtures.stores(folder,size=1)
            store.append(fixtures.record(0));batch=manager.seal_due_batches()[0]
            with manager.state_transaction() as state:
                state['batches'][0]['anchor_claim']={'phase':'SUBMITTED','transaction_hash':self.tx,'nonce':3}
            with fixtures.fake_chain(folder):
                w,_,_,_=chain.contract_context()
                w.eth.get_transaction_receipt.side_effect=TransactionNotFound('not yet mined')
                with self.assertRaises(RuntimeError):manager.anchor_batch(batch['batch_id'])
            self.assertFalse((Path(folder)/'mock-chain.json').exists())
            self.assertEqual(manager.get_batch(batch['batch_id'])['anchor_claim']['nonce'],3)

    def test_legacy_event_recovery_uses_bounded_timestamp_range(self):
        import json
        digest='ab'*32
        self.contract.functions.commitments.return_value.call.return_value=[bytes.fromhex(digest),4,500]
        self.web3.eth.get_logs.return_value=[SimpleNamespace(transactionHash=bytes.fromhex(self.tx[2:]))]
        with tempfile.TemporaryDirectory(dir=fixtures.TEMP_ROOT) as folder:
            deployment=Path(folder)/'deployment.json'
            deployment.write_text(json.dumps({'chain_id':31337,'contract_address':self.contract.address,'block_number':100}))
            with patch.object(chain,'DEPLOYMENT_PATH',deployment),patch.object(chain,'NETWORK_PROFILE','hardhat'):
                self.assertIs(chain._event_receipt(self.web3,self.contract,'action',digest),self.receipt)
        for call in self.web3.eth.get_logs.call_args_list:
            self.assertGreaterEqual(call.args[0]['fromBlock'],500)
            self.assertLessEqual(call.args[0]['toBlock'],510)
