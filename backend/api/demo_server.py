"""Run a disposable, live Hardhat registry for the presentation UI.

The saved Module 6 evidence is left untouched.  Each invocation deploys a new
registry and replays the existing Module 1 records into temporary files.
"""

from pathlib import Path
import shutil
import json
from uuid import uuid4
from contextlib import ExitStack
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import uvicorn

from backend.core.governance import bootstrap
from backend.core.governance import main as module6_main
from backend.core.blockchain.audit_log import AuditLogStore
from backend.core.blockchain.batch_manager import BatchManager
from backend.core.governance import pipeline
from backend.api import services
from backend.api.main import app
from backend.core.authorization.demo_identity import DemoIdentity
from backend.core.authorization import main as authorization_main
from backend.core.blockchain import chain, main as blockchain_main


class LocalOperator:
    """Explicit local startup/CLI adapter, never exposed through an API."""
    def credentials(self, actor, operation, payload):
        if chain.NETWORK_PROFILE != 'hardhat':
            raise RuntimeError('Local signer requires Hardhat')
        from backend.core.authorization.operator_signing import operator_credentials
        from backend.core.authorization.agents import authority_paths
        extra = {}
        if operation == 'delegate':
            paths = authority_paths(payload['delegator'], payload['permission'])
            extra['parent_grant_id'] = paths[0][-1] if paths else None
            payload = {**payload, **extra}
        with pipeline.canonical_context():
            return {**operator_credentials(actor, operation, payload), **extra}


def provision_local_policy():
    """Bind this disposable demo's policy to its actual registered wallets.

    Bootstrap's independent demonstration realm cannot authenticate HTTP users.
    Replace only that in-memory fixture policy, before serving requests. All
    new grants are signed by the registered root, with the existing verifier.
    """
    from backend.core.authorization import agents
    if chain.NETWORK_PROFILE != 'hardhat' or chain.connect().eth.chain_id != 31337:
        raise RuntimeError('Local policy requires Hardhat chain 31337')
    operator = LocalOperator()
    for actor, permission in [('Agent_A', 'CREATE_AGENT'), ('Agent_B', 'READ_CATALOG'),
                              ('Agent_B', 'CREATE_ORDER'), ('Agent_D', 'VERIFY_ORDER')]:
        payload = {'agent_id': actor, 'permission': permission, 'expires_at': None}
        result = agents.grant_root_permission(actor, permission, **operator.credentials('ROOT_AUTHORIZER', 'root_grant', payload))
        if result['result'] != 'ALLOWED':
            raise RuntimeError('LOCAL_DEMO_POLICY_UNAVAILABLE')
    payload = {'delegator': 'Agent_A', 'delegatee': 'Agent_B', 'permission': 'CREATE_AGENT', 'expires_at': None}
    result = agents.delegate_permission(agents.AGENTS['Agent_A'], agents.AGENTS['Agent_B'], 'CREATE_AGENT',
                                       **operator.credentials('Agent_A', 'delegate', payload))
    if result['result'] != 'ALLOWED':
        raise RuntimeError('LOCAL_DEMO_POLICY_UNAVAILABLE')
    reason = 'Local demonstration: existing on-chain revocation'
    result = agents.decommission_agent('Agent_C', reason=reason,
        **operator.credentials('ROOT_AUTHORIZER', 'decommission', {'agent_id': 'Agent_C', 'reason': reason}))
    if result['result'] != 'REVOKED':
        raise RuntimeError('LOCAL_DEMO_POLICY_UNAVAILABLE')
    return operator


def seed_scenarios(identity):
    """Evaluate real local fixtures once; HTTP only replays their anchored proofs.

    Dated synthetic samples and the fitted model's history move together in
    memory, by whole days. Credentials, the dataset and model files stay intact.
    No request handler has access to this operator-only signing identity.
    """
    import joblib
    rows = module6_main.load_scenarios()
    synthetic = [action for _, _, action in rows if action['record_id'].startswith('synthetic:')]
    earliest = min(datetime.fromisoformat(action['timestamp']) for action in synthetic)
    shift = timedelta(days=(datetime.now(timezone.utc).date() + timedelta(days=1) - earliest.date()).days)
    model = joblib.load(pipeline.MODEL_PATH)
    for events in model.history_by_agent.values():
        for event in events:
            event['timestamp'] = (datetime.fromisoformat(event['timestamp']) + shift).isoformat()
    pipeline._runtime['model'] = model
    for category in services.SCENARIOS.values():
        action = deepcopy(next(action for code, _, action in rows if code == category))
        credentials = {}
        if action['record_id'].startswith('synthetic:'):
            action['timestamp'] = (datetime.fromisoformat(action['timestamp']) + shift).isoformat()
            payload = {k: v for k, v in action.items() if k not in ('record_id', 'trace_result')}
            credentials = identity.credentials(action['actor'], 'evaluate', payload)
        pipeline.run_governance_pipeline(action, **credentials)
    with pipeline.canonical_context():
        pipeline.AUDIT_BATCH_MANAGER.seal_due_batches()
        pipeline.AUDIT_BATCH_MANAGER.anchor_unanchored_batches()
    if any(batch['status'] != 'ANCHORED' for batch in pipeline.AUDIT_BATCH_MANAGER.list_batches()):
        raise RuntimeError('LOCAL_DEMO_ANCHOR_UNAVAILABLE')


def main() -> None:
    if chain.NETWORK_PROFILE != 'hardhat' or chain.connect().eth.chain_id != 31337:
        raise RuntimeError('Disposable demo requires local Hardhat chain 31337')
    runtime_root = (Path(__file__).resolve().parent / ".demo_runtime").resolve()
    data_dir = (runtime_root / uuid4().hex).resolve()
    if data_dir.parent != runtime_root:
        raise RuntimeError("Demo data directory escaped its workspace root")
    data_dir.mkdir(parents=True)
    identity = DemoIdentity()
    try:
        bootstrap.DATA_DIR = data_dir
        bootstrap.PATHS = {
            "STATE_PATH": data_dir / "ethereum_state.json",
            "DEPLOYMENT_PATH": data_dir / "deployment.json",
            "CREDENTIALS_PATH": data_dir / "credentials.json",
        }
        with ExitStack() as stack:
            stack.enter_context(patch.object(blockchain_main, 'run_demo', lambda: authorization_main.run_demo(identity)))
            bootstrap.bootstrap()
        # Bootstrap already replayed Module 1 in this process.
        pipeline._runtime["module1_ready"] = True
        # Keep the live presentation registry's audit stream isolated with its
        # disposable deployment; do not mix demo roots into saved audit state.
        pipeline.AUDIT_LOG_STORE = AuditLogStore(data_dir / "audit_logs.jsonl")
        pipeline.AUDIT_BATCH_MANAGER = BatchManager(
            pipeline.AUDIT_LOG_STORE, data_dir / "batches.json", batch_size=5,
        )

        pipeline.DATA_DIR = data_dir
        module6_main.DATA_DIR = data_dir
        services.DATA_DIR = data_dir
        services.REPORT_PATH = data_dir / "final_report.json"

        seed_scenarios(provision_local_policy())
        identity.close()
        report = services.build_persisted_report(data_dir, pipeline.AUDIT_BATCH_MANAGER)
        services.REPORT_PATH.write_text(json.dumps(report, indent=2), encoding='utf-8')
        uvicorn.run(app, host="127.0.0.1", port=8001)
    finally:
        identity.close()
        shutil.rmtree(data_dir)


if __name__ == "__main__":
    main()
