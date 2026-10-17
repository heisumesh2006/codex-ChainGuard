"""Independent OS-process regression for authenticated policy publication."""
from copy import deepcopy
import json
import multiprocessing
from pathlib import Path
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))


def worker(folder, domain, address, permission, envelope, ready, start, output):
    from backend.core.authorization import agents as a
    from backend.core.authorization.authentication import RequestVerifier, AuthenticationError
    from backend.core.authorization.logger import ACTION_LOG
    verifier = RequestVerifier(domain, {"ROOT_AUTHORIZER": address}.__getitem__, Path(folder)/"nonces.json")
    a.AGENTS.clear(); a.AGENTS["Agent_A"] = a.Agent("Agent_A", "isolated")
    a.ROOT_AUTHORITY_RECORD.clear(); a.DELEGATION_LEDGER.clear(); ACTION_LOG.clear()
    a._policy_verifier = verifier
    ready.put(True)
    if not start.wait(30):
        output.put("START_TIMEOUT"); return
    try:
        result = a.grant_root_permission("Agent_A", permission, authentication=envelope, verifier=verifier)
        output.put(result["result"])
    except AuthenticationError as exc:
        output.put(str(exc))
    except Exception as exc:
        output.put(type(exc).__name__)


class PolicyProcessTests(unittest.TestCase):
    def setUp(self):
        from backend.core.authorization import agents as a
        from backend.core.authorization.logger import ACTION_LOG
        self.saved = deepcopy((a.AGENTS, a.ROOT_AUTHORITY_RECORD, a.DELEGATION_LEDGER, ACTION_LOG))
        self.verifier = a._policy_verifier
        self.temporary = tempfile.TemporaryDirectory(prefix="signed-policy-process-")
        self.addCleanup(self.temporary.cleanup)

    def tearDown(self):
        from backend.core.authorization import agents as a
        from backend.core.authorization.logger import ACTION_LOG
        a.AGENTS.clear(); a.AGENTS.update(self.saved[0])
        a.ROOT_AUTHORITY_RECORD[:] = self.saved[1]; a.DELEGATION_LEDGER[:] = self.saved[2]
        ACTION_LOG[:] = self.saved[3]; a._policy_verifier = self.verifier

    def run_workers(self, duplicate):
        from eth_account import Account
        from backend.core.authorization import agents as a
        from backend.core.authorization.authentication import RequestVerifier, sign_request
        from backend.core.authorization.state import refresh_policy
        account = Account.create()
        domain = "isolated-policy-process:" + Path(self.temporary.name).name
        permissions = ("P", "P" if duplicate else "Q")
        envelopes = [sign_request(account, domain, "ROOT_AUTHORIZER", "root_grant",
                     {"agent_id":"Agent_A", "permission": permission, "expires_at":None}) for permission in permissions]
        if duplicate: envelopes[1] = envelopes[0]
        ctx = multiprocessing.get_context("spawn")
        ready, output, start = ctx.Queue(), ctx.Queue(), ctx.Event()
        processes = [ctx.Process(target=worker, args=(self.temporary.name, domain, account.address, permission,
                     envelope, ready, start, output)) for permission, envelope in zip(permissions,envelopes)]
        try:
            for process in processes: process.start()
            for _ in processes: self.assertTrue(ready.get(timeout=30))
            start.set()
            outcomes = [output.get(timeout=30) for _ in processes]
            for process in processes:
                process.join(30); self.assertEqual(process.exitcode, 0)
        finally:
            for process in processes:
                if process.is_alive(): process.terminate(); process.join(10)
        verifier = RequestVerifier(domain, {"ROOT_AUTHORIZER":account.address}.__getitem__,
                                   Path(self.temporary.name)/"nonces.json")
        refresh_policy(verifier)
        self.assertTrue(a.authority_paths("Agent_A", "P"))
        if duplicate:
            self.assertCountEqual(outcomes, ["ALLOWED", "AUTHENTICATION_REPLAYED"])
        else:
            self.assertEqual(outcomes, ["ALLOWED", "ALLOWED"])
            self.assertTrue(a.authority_paths("Agent_A", "Q"))
        return outcomes

    def test_distinct_signed_policy_updates_are_not_lost(self): self.run_workers(False)
    def test_duplicate_signed_mutation_is_accepted_once(self): self.run_workers(True)


if __name__ == "__main__":
    started = time.perf_counter()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(PolicyProcessTests))
    report = {"tests":result.testsRun,"failures":len(result.failures),"errors":len(result.errors),
              "skipped":len(result.skipped),"elapsed_seconds":time.perf_counter()-started,
              "independent_processes_per_case":2,"temporary_storage_only":True,"public_transactions":0}
    (ROOT/"docs/research-evaluation/raw/policy_multiprocess_verification.json").write_text(json.dumps(report,indent=2)+"\n")
    raise SystemExit(0 if result.wasSuccessful() else 1)
