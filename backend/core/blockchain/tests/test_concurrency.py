"""F8: real independent spawn processes, isolated files and mocked sends."""
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import json
import multiprocessing as mp
import os
from pathlib import Path
import tempfile
import time
import traceback
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock, patch

from backend.core.blockchain.audit_log import AuditLogStore, DuplicateActionIdError, hash_record, canonicalize_record
from backend.core.blockchain.batch_manager import BatchManager, BatchStateConflict
from backend.core.blockchain.merkle import build_merkle_tree
from backend.core.blockchain.persistence import FileLock, PersistenceLockTimeout, atomic_write
from backend.core.blockchain.tests.test_batching import record

TEMP_ROOT = Path(tempfile.gettempdir())
SIZE_TEST_TIME = datetime(2026, 10, 1, tzinfo=timezone.utc)


class SizeThresholdBatchManager(BatchManager):
    """Keep size-race tests independent of scheduling/host clock pauses.

    All production persistence/locking/sealing code runs unchanged. Age-policy
    boundaries are exercised separately below using explicit advancing times.
    """
    def seal_due_batches(self, now=None):
        return super().seal_due_batches(now=SIZE_TEST_TIME if now is None else now)


def stores(folder, size=5, timeout=10):
    folder = Path(folder)
    store = AuditLogStore(folder / 'audit.jsonl', lock_timeout=timeout)
    return store, SizeThresholdBatchManager(store, folder / 'batches.json', batch_size=size, lock_timeout=timeout)


def fake_chain(folder, receipt_ready=None, receipt_release=None, crash_send=False):
    from backend.core.blockchain import chain
    path = Path(folder) / 'mock-chain.json'
    lock = FileLock(str(path) + '.lock')
    root = '0x' + '12' * 20
    contract = MagicMock()
    contract.address = '0x' + '34' * 20
    web3 = MagicMock()
    web3.eth.chain_id = 31337
    def read():
        return json.loads(path.read_text()) if path.exists() else {'batches': {}, 'sends': 0}
    def stored(key):
        with lock:
            item = read()['batches'].get(key.hex())
            return item if item else [bytes(32), 0, 0, 0, root, 0, False]
    contract.functions.auditBatches.side_effect = lambda key: SimpleNamespace(call=lambda: stored(key))
    contract.functions.anchorAuditBatch.side_effect = lambda *args: args
    def submit(w, args, sender):
        with lock:
            state = read(); state['sends'] += 1
            if not crash_send:
                key, digest, count, start, end = args
                state['batches'][key.hex()] = [digest.hex(), count, start, end, root, 1, True]
            atomic_write(path, json.dumps(state).encode())
        if crash_send:
            receipt_ready.set(); receipt_release.wait(60)
        return bytes.fromhex('56' * 32)
    # Mock file JSON stores a hex root; contract ABI returns bytes32.
    original_stored = stored
    def abi_stored(key):
        item = original_stored(key)
        if isinstance(item[0], str): item[0] = bytes.fromhex(item[0])
        return item
    contract.functions.auditBatches.side_effect = lambda key: SimpleNamespace(call=lambda: abi_stored(key))
    def wait(tx, timeout):
        if receipt_ready is not None:
            receipt_ready.set(); assert receipt_release.wait(60)
        return SimpleNamespace(status=1, transactionHash=tx, blockNumber=1)
    web3.eth.wait_for_transaction_receipt.side_effect = wait
    stack = ExitStack()
    stack.enter_context(patch.object(chain, 'NETWORK_PROFILE', 'hardhat'))
    stack.enter_context(patch.object(chain, 'contract_context', return_value=(web3, contract, root, {'rpc_url':'http://127.0.0.1:8545'})))
    stack.enter_context(patch.object(chain, 'submit_transaction', side_effect=submit))
    stack.enter_context(patch('backend.core.blockchain.batch_verifier.verify_anchored_batch', return_value=True))
    return stack


def operation_worker(folder, mode, index, barrier, queue, count=1, size=5, ready=None, release=None):
    store, manager = stores(folder, size)
    result = {'worker': index, 'success': 0, 'duplicates': 0, 'timeouts': 0, 'errors': []}
    try:
        barrier.wait(60)
        if mode == 'seal':
            result['sealed'] = len(manager.seal_due_batches())
        elif mode == 'seal_age':
            result['sealed'] = len(manager.seal_due_batches(now=SIZE_TEST_TIME + timedelta(seconds=31)))
        elif mode == 'update':
            with manager.state_transaction() as state:
                state['pending_since'][str(index)] = '2026-10-01T00:00:00Z'
            result['success'] = 1
        elif mode == 'stale_update':
            state = manager._read_state()
            barrier.wait(60)
            state['pending_since'][str(index)] = '2026-10-01T00:00:00Z'
            try:
                manager._write_state(state)
                result['success'] = 1
            except BatchStateConflict:
                result['conflicts'] = 1
                with manager.state_transaction() as fresh:
                    fresh['pending_since'][str(index)] = '2026-10-01T00:00:00Z'
                result['success'] = 1
        elif mode == 'anchor':
            with fake_chain(folder, ready, release):
                result['status'] = manager.anchor_batch(manager.list_batches()[0]['batch_id'])['status']
        else:
            for number in range(count):
                item = record(0 if mode == 'same' else index * count + number)
                for attempt in range(6):
                    try:
                        store.append(item); result['success'] += 1
                        break
                    except DuplicateActionIdError:
                        result['duplicates'] += 1; break
                    except PersistenceLockTimeout:
                        result['timeouts'] += 1
                        if attempt == 5: raise
                if mode in ('append_seal', 'stress'):
                    for attempt in range(6):
                        try:
                            manager.seal_due_batches()
                            break
                        except PersistenceLockTimeout:
                            result['timeouts'] += 1
                            if attempt == 5: raise
            if mode == 'stress':
                try: store.append(record(index * count))
                except DuplicateActionIdError: result['duplicates'] += 1
    except Exception as exc:
        result['errors'].append(type(exc).__name__)
        result['error_details'] = {'errno': getattr(exc,'errno',None), 'winerror': getattr(exc,'winerror',None), 'frames': [frame.name for frame in traceback.extract_tb(exc.__traceback__)]}
    queue.put(result)


def hold_worker(path, ready, release):
    with FileLock(path):
        ready.set(); release.wait(60)


def crash_write_worker(folder, ready, release, after_publish):
    from backend.core.blockchain import persistence
    store, _ = stores(folder)
    original = persistence.os.replace
    def interrupted(source, target):
        if after_publish: original(source, target)
        ready.set(); release.wait(60)
        if not after_publish: original(source, target)
    with patch.object(persistence.os, 'replace', side_effect=interrupted): store.append(record(1))


def crash_anchor_worker(folder, ready, release):
    _, manager = stores(folder)
    with fake_chain(folder, ready, release, crash_send=True):
        manager.anchor_batch(manager.list_batches()[0]['batch_id'])


def coordinated_writer(folder, ready, acknowledged, count):
    store, manager = stores(folder)
    for index in range(count):
        store.append(record(index)); manager.seal_due_batches()
        ready.set(); assert acknowledged.wait(30)
        acknowledged.clear(); ready.clear()


class ConcurrencyTests(TestCase):
    def setUp(self):
        TEMP_ROOT.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=TEMP_ROOT, prefix='f8-test-')
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.store, self.manager = stores(self.folder)
        self.ctx = mp.get_context('spawn')

    def run_workers(self, mode, workers=2, count=1, size=5, ready=None, release=None):
        barrier = self.ctx.Barrier(workers)
        queue = self.ctx.Queue()
        processes = [self.ctx.Process(target=operation_worker, args=(str(self.folder), mode, i, barrier, queue, count, size, ready, release)) for i in range(workers)]
        for p in processes: p.start()
        try:
            if ready is not None:
                self.assertTrue(ready.wait(60))
                # Global storage remains writable while a per-batch RPC waits.
                self.store.append(record(9999))
                self.manager.seal_due_batches()
                release.set()
            results = [queue.get(timeout=180) for _ in processes]
            for p in processes:
                p.join(30); self.assertEqual(p.exitcode, 0)
            (TEMP_ROOT / ('F8_WORKERS_' + mode + '.json')).write_text(json.dumps(results, indent=2))
            self.assertTrue(all(not r['errors'] for r in results), results)
            return results
        finally:
            if release is not None: release.set()
            for p in processes:
                if p.is_alive(): p.terminate(); p.join(10)
            queue.close(); queue.join_thread()

    def integrity(self, expected, mapped=None):
        records = self.store.list_records()
        self.assertEqual(len(records), expected)
        ids = [r['action_id'] for r in records]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(self.store.path.read_bytes().splitlines()), expected)
        for line in self.store.path.read_bytes().splitlines(): self.assertEqual(line, canonicalize_record(json.loads(line)))
        state = self.manager._read_state()
        flattened = [i for b in state['batches'] for i in b['action_ids']]
        self.assertEqual(len(flattened), len(set(flattened)))
        self.assertEqual(set(flattened), set(state['action_index']))
        self.assertTrue(set(flattened).issubset(ids))
        if mapped is not None: self.assertEqual(len(flattened), mapped)
        by_id = {r['action_id']:r for r in records}
        offset = 0
        for batch in state['batches']:
            self.assertEqual(batch['action_ids'], ids[offset:offset+batch['log_count']])
            leaves = [hash_record(by_id[i]) for i in batch['action_ids']]
            self.assertEqual(batch['leaf_hashes'], leaves)
            self.assertEqual(batch['merkle_root'], build_merkle_tree(leaves)['root'])
            for i in batch['action_ids']: self.assertEqual(state['action_index'][i], batch['batch_id'])
            offset += batch['log_count']
        return state

    def test_two_processes_same_action_original_race(self):
        results = self.run_workers('same')
        self.assertEqual(sum(r['success'] for r in results),1)
        self.assertEqual(sum(r['duplicates'] for r in results),1)
        self.integrity(1)

    def test_two_processes_distinct_actions(self):
        results = self.run_workers('distinct')
        self.assertEqual(sum(r['success'] for r in results),2); self.integrity(2)

    def test_ten_processes_distinct_actions(self):
        results = self.run_workers('distinct',workers=10)
        self.assertEqual(sum(r['success'] for r in results),10); self.integrity(10)

    def test_repeated_duplicate_submissions(self):
        results = self.run_workers('same',count=10)
        self.assertEqual(sum(r['success'] for r in results),1)
        self.assertEqual(sum(r['duplicates'] for r in results),19); self.integrity(1)

    def test_concurrent_appends_at_threshold(self):
        self.run_workers('append_seal',count=5); self.integrity(10,10)

    def test_concurrent_sealing_is_idempotent(self):
        for i in range(5): self.store.append(record(i))
        results = self.run_workers('seal')
        self.assertEqual(sum(r['sealed'] for r in results),1); self.integrity(5,5)

    def test_simultaneous_batch_state_updates(self):
        self.run_workers('update')
        self.assertEqual(set(self.manager._read_state()['pending_since']),{'0','1'})

    def test_stale_cross_process_snapshot_rejected_and_retried(self):
        results = self.run_workers('stale_update')
        self.assertEqual(sum(r.get('conflicts',0) for r in results),1)
        self.assertEqual(set(self.manager._read_state()['pending_since']),{'0','1'})

    def test_reader_during_writer_activity(self):
        ready, ack = self.ctx.Event(), self.ctx.Event()
        p = self.ctx.Process(target=coordinated_writer,args=(str(self.folder),ready,ack,10)); p.start()
        try:
            for i in range(10):
                self.assertTrue(ready.wait(30))
                with self.manager.snapshot() as (records,state):
                    self.assertEqual(len(records),i+1)
                    self.assertTrue(set(state['action_index']).issubset(r['action_id'] for r in records))
                ready.clear(); ack.set()
            p.join(30); self.assertEqual(p.exitcode,0); self.integrity(10,10)
        finally:
            ack.set()
            if p.is_alive(): p.terminate(); p.join(10)

    def kill_at_write(self, after_publish):
        self.store.append(record(0)); before = self.store.path.read_bytes()
        ready, release = self.ctx.Event(), self.ctx.Event()
        p = self.ctx.Process(target=crash_write_worker,args=(str(self.folder),ready,release,after_publish)); p.start()
        try:
            self.assertTrue(ready.wait(30)); p.terminate(); p.join(10)
            if after_publish:
                self.integrity(2)
                with self.assertRaises(DuplicateActionIdError): self.store.append(record(1))
            else:
                self.assertEqual(self.store.path.read_bytes(),before)
                self.store.append(record(1)); self.integrity(2)
        finally:
            if p.is_alive(): p.terminate(); p.join(10)

    def test_process_crash_before_atomic_publication(self): self.kill_at_write(False)
    def test_process_crash_after_atomic_publication(self): self.kill_at_write(True)

    def test_reader_during_unpublished_write_fails_bounded_then_recovers(self):
        self.store.append(record(0));before=self.store.path.read_bytes()
        ready,release=self.ctx.Event(),self.ctx.Event()
        p=self.ctx.Process(target=crash_write_worker,args=(str(self.folder),ready,release,False));p.start()
        try:
            self.assertTrue(ready.wait(30))
            reader=AuditLogStore(self.store.path,lock_timeout=0.1)
            with self.assertRaises(PersistenceLockTimeout):reader.list_records()
            self.assertEqual(self.store.path.read_bytes(),before)
            p.terminate();p.join(10)
            self.assertEqual(len(reader.list_records()),1)
        finally:
            if p.is_alive():p.terminate();p.join(10)

    def test_failed_atomic_replacement_keeps_prior_records(self):
        self.store.append(record(0)); before = self.store.path.read_bytes()
        with patch('backend.core.blockchain.persistence.os.replace', side_effect=OSError('synthetic replacement failure')):
            with self.assertRaises(OSError): self.store.append(record(1))
        self.assertEqual(self.store.path.read_bytes(),before)
        self.assertEqual(list(self.folder.glob('*.tmp')),[])
        self.store.append(record(1)); self.integrity(2)

    def test_failed_batch_replacement_keeps_mapping(self):
        for i in range(5):self.store.append(record(i))
        self.manager.seal_due_batches(); before=self.manager.metadata_path.read_bytes()
        with patch('backend.core.blockchain.persistence.os.replace',side_effect=OSError('synthetic replacement failure')):
            with self.assertRaises(OSError):
                with self.manager.state_transaction() as state:state['pending_since']['extra']='2026-10-01T00:00:00Z'
        self.assertEqual(self.manager.metadata_path.read_bytes(),before);self.integrity(5,5)

    def test_lock_timeout_and_abnormal_release(self):
        path=str(self.folder/'held.lock');ready,release=self.ctx.Event(),self.ctx.Event()
        p=self.ctx.Process(target=hold_worker,args=(path,ready,release));p.start()
        try:
            self.assertTrue(ready.wait(30))
            with self.assertRaises(PersistenceLockTimeout):
                with FileLock(path,timeout=0.1):pass
            p.terminate();p.join(10)
            with FileLock(path,timeout=1):pass
            self.assertTrue(Path(path).exists())
        finally:
            if p.is_alive():p.terminate();p.join(10)

    def test_stable_lock_reentrancy_across_instances(self):
        with FileLock(self.folder/'same.lock',timeout=0):
            with FileLock(self.folder/'same.lock',timeout=0):pass

    def test_profile_specific_locks_are_independent(self):
        hardhat=AuditLogStore(self.folder/'hardhat'/'audit.jsonl')
        sepolia=AuditLogStore(self.folder/'sepolia'/'audit.jsonl',lock_timeout=0.1)
        self.assertNotEqual(hardhat._lock.path,sepolia._lock.path)
        ready,release=self.ctx.Event(),self.ctx.Event()
        p=self.ctx.Process(target=hold_worker,args=(str(hardhat._lock.path),ready,release));p.start()
        try:
            self.assertTrue(ready.wait(30));sepolia.append(record(0))
        finally:
            if p.is_alive():p.terminate();p.join(10)
        self.assertEqual(sepolia.count(),1);self.assertEqual(hardhat.count(),0)

    def test_submission_lock_timeout_does_not_create_uncertain_claim(self):
        self.store.append(record(0));self.manager=stores(self.folder,size=1,timeout=0.1)[1]
        batch=self.manager.seal_due_batches()[0]
        ready,release=self.ctx.Event(),self.ctx.Event()
        path=str(self.manager.metadata_path)+'.submission.lock'
        p=self.ctx.Process(target=hold_worker,args=(path,ready,release));p.start()
        try:
            self.assertTrue(ready.wait(30))
            with fake_chain(self.folder):
                with self.assertRaisesRegex(TimeoutError,'PERSISTENCE_LOCK_TIMEOUT'):
                    self.manager.anchor_batch(batch['batch_id'])
            self.assertNotIn('anchor_claim',self.manager.get_batch(batch['batch_id']))
            self.assertFalse((self.folder/'mock-chain.json').exists())
        finally:
            if p.is_alive():p.terminate();p.join(10)
        with fake_chain(self.folder):self.manager.anchor_batch(batch['batch_id'])
        self.assertEqual(json.loads((self.folder/'mock-chain.json').read_text())['sends'],1)

    def test_append_before_seal_crash_window_is_recovered(self):
        self.store.append(record(0));self.assertEqual(self.manager.record_status(record(0)['action_id'])['status'],'PENDING')
        self.manager=stores(self.folder,size=1)[1]
        self.manager.seal_due_batches();self.integrity(1,1)

    def test_existing_anchored_batch_unchanged_on_duplicate_requests(self):
        self.store.append(record(0));self.manager=stores(self.folder,size=1)[1]
        batch=self.manager.seal_due_batches()[0]
        with fake_chain(self.folder):
            self.manager.anchor_batch(batch['batch_id']);before=self.manager.metadata_path.read_bytes()
            self.manager.anchor_batch(batch['batch_id'])
        self.assertEqual(self.manager.metadata_path.read_bytes(),before)
        self.assertEqual(json.loads((self.folder/'mock-chain.json').read_text())['sends'],1)

    def test_two_processes_cannot_submit_same_batch_and_rpc_does_not_block_storage(self):
        for i in range(5):self.store.append(record(i))
        self.manager.seal_due_batches()
        ready,release=self.ctx.Event(),self.ctx.Event()
        results=self.run_workers('anchor',ready=ready,release=release)
        self.assertEqual([r['status'] for r in results],['ANCHORED','ANCHORED'])
        self.assertEqual(json.loads((self.folder/'mock-chain.json').read_text())['sends'],1)
        self.integrity(6,5)

    def test_crashed_submission_claim_blocks_automatic_resend(self):
        self.store.append(record(0));self.manager=stores(self.folder,size=1)[1];batch=self.manager.seal_due_batches()[0]
        ready,release=self.ctx.Event(),self.ctx.Event()
        p=self.ctx.Process(target=crash_anchor_worker,args=(str(self.folder),ready,release));p.start()
        try:
            self.assertTrue(ready.wait(30));p.terminate();p.join(10)
            self.assertEqual(self.manager.get_batch(batch['batch_id'])['anchor_claim']['phase'],'SUBMITTING')
            with fake_chain(self.folder):
                with self.assertRaises(RuntimeError):self.manager.anchor_batch(batch['batch_id'])
            self.assertEqual(json.loads((self.folder/'mock-chain.json').read_text())['sends'],1)
        finally:
            if p.is_alive():p.terminate();p.join(10)

    def test_single_process_compatibility_and_pending_order(self):
        for i in range(6):self.store.append(record(i))
        self.manager.seal_due_batches();self.integrity(6,5)
        self.assertEqual(self.manager.pending_records()[0]['action_id'],record(5)['action_id'])
        self.assertTrue(self.manager.verify_record_proof(record(0)['action_id']))

    def test_concurrent_age_sealing_is_idempotent(self):
        for i in range(2): self.store.append(record(i))
        self.manager.seal_due_batches(now=SIZE_TEST_TIME)
        results = self.run_workers('seal_age')
        self.assertEqual(sum(result['sealed'] for result in results), 1)
        state = self.integrity(2, 2)
        self.assertEqual([batch['log_count'] for batch in state['batches']], [2])

    def test_age_partial_batch_preserves_below_threshold_tail_until_due(self):
        self.manager = BatchManager(self.store, self.manager.metadata_path, batch_size=5, max_age_seconds=30)
        for i in range(2): self.store.append(record(i))
        self.manager.seal_due_batches(now=SIZE_TEST_TIME)
        self.manager.seal_due_batches(now=SIZE_TEST_TIME + timedelta(seconds=31))
        for i in range(2, 10): self.store.append(record(i))
        self.manager.seal_due_batches(now=SIZE_TEST_TIME + timedelta(seconds=31))
        state = self.integrity(10, 7)
        self.assertEqual([b['log_count'] for b in state['batches']], [2, 5])
        self.assertEqual([r['action_id'] for r in self.manager.pending_records()],
                         [record(i)['action_id'] for i in range(7, 10)])
        self.manager.seal_due_batches(now=SIZE_TEST_TIME + timedelta(seconds=62))
        state = self.integrity(10, 10)
        self.assertEqual([b['log_count'] for b in state['batches']], [2, 5, 3])

    def test_bounded_ten_process_500_action_stress(self):
        start=time.perf_counter();results=self.run_workers('stress',workers=10,count=50)
        self.assertEqual(sum(r['success'] for r in results),500)
        self.assertEqual(sum(r['duplicates'] for r in results),10)
        self.manager.seal_due_batches();state=self.integrity(500,500)
        result={'seconds':time.perf_counter()-start,'workers':10,'distinct_attempts':500,'successful_actions':500,'deliberate_duplicate_rejections':10,'persisted_records':500,'persisted_duplicates':0,'lost_successful_actions':0,'batches':len(state['batches']),'mapped_actions':len(state['action_index']),'lock_timeouts':sum(r['timeouts'] for r in results),'worker_results':results,'jsonl_valid':True,'mapping_valid':True,'deterministic_merkle_from_persisted_order':True,'size_threshold_clock_controlled':True}
        (TEMP_ROOT/'F8_STRESS_RESULTS.json').write_text(json.dumps(result,indent=2))
