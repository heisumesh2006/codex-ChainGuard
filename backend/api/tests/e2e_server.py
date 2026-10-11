"""Read-only public-chain browser fixture with private temporary audit storage.

No deployment or transaction submission is possible. Saved evidence is copied
byte-for-byte, not fabricated, and never written back to canonical directories.
"""

from contextlib import ExitStack
import os
from pathlib import Path
import shutil
import tempfile
from unittest.mock import patch


def main():
    os.environ['CHAINGUARD_NETWORK'] = 'sepolia'
    from backend.core.blockchain import chain
    from web3 import HTTPProvider
    import uvicorn
    from backend.api import services
    from backend.api.main import app
    from fastapi.middleware.cors import CORSMiddleware
    from backend.core.governance import pipeline
    from backend.core.revocation import revocation
    from backend.core.blockchain.audit_log import AuditLogStore
    from backend.core.blockchain.batch_manager import BatchManager

    os.environ['SEPOLIA_PRIVATE_KEY'] = ''
    request = HTTPProvider.make_request
    read_methods = {'web3_clientVersion','eth_chainId','eth_blockNumber','eth_getCode','eth_call',
                    'eth_getTransactionReceipt','eth_getTransactionByHash','eth_getBlockByNumber',
                    'eth_getBlockByHash','eth_getLogs','eth_accounts','eth_getBalance','eth_getTransactionCount','net_version'}
    def read_only(self, method, params):
        if str(method) not in read_methods:
            raise RuntimeError('PUBLIC_WRITE_FORBIDDEN')
        try:
            return request(self, method, params)
        except Exception:
            raise ConnectionError('PUBLIC_RPC_UNAVAILABLE') from None

    root = Path(__file__).resolve().parents[3]
    app.add_middleware(CORSMiddleware, allow_origins=['http://127.0.0.1:5179'],
                       allow_methods=['GET','POST'], allow_headers=['*'])
    with tempfile.TemporaryDirectory(prefix='browser-evidence-',dir=root/'.runtime') as folder, ExitStack() as stack:
        data = Path(folder)
        for name in ('ethereum_state.json','credentials.json','deployment.json','audit_logs.jsonl','batches.json'):
            shutil.copyfile(pipeline.DATA_DIR/name,data/name)
        store = AuditLogStore(data/'audit_logs.jsonl')
        manager = BatchManager(store,data/'batches.json')
        for module, attr, value in ((pipeline,'DATA_DIR',data),(services,'DATA_DIR',data),
                                    (pipeline,'AUDIT_LOG_STORE',store),(pipeline,'AUDIT_BATCH_MANAGER',manager)):
            stack.enter_context(patch.object(module,attr,value))
        for attr, name in (('DEPLOYMENT_PATH','deployment.json'),('STATE_PATH','ethereum_state.json'),('CREDENTIALS_PATH','credentials.json')):
            stack.enter_context(patch.object(chain,attr,data/name))
            stack.enter_context(patch.object(revocation,'BUNDLE_'+attr,data/name))
        stack.enter_context(patch.object(HTTPProvider,'make_request',read_only))
        stack.enter_context(patch.object(chain,'submit_transaction',side_effect=RuntimeError('PUBLIC_WRITE_FORBIDDEN')))
        uvicorn.run(app,host='127.0.0.1',port=8002,log_level='warning')


if __name__ == '__main__':
    main()
