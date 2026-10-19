"""Reproduce saved Sepolia API/proof and independent Merkle checks read-only.

Requires the owner's existing canonical evidence bundle and configured RPC.
No secrets, runtime evidence or deployment manifests are written by this test.
"""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
os.environ["CHAINGUARD_NETWORK"] = "sepolia"
os.environ.pop("CHAINGUARD_RPC_URL", None)
os.environ["SEPOLIA_PRIVATE_KEY"] = ""


def run():
    from web3 import Web3, HTTPProvider
    from backend.core.blockchain import chain
    os.environ["SEPOLIA_PRIVATE_KEY"] = ""
    original = HTTPProvider.make_request
    allowed = {"web3_clientVersion","eth_chainId","eth_blockNumber","eth_getCode","eth_call",
               "eth_getTransactionReceipt","eth_getTransactionByHash","eth_getBlockByNumber",
               "eth_getBlockByHash","eth_getLogs","eth_accounts","eth_getBalance","eth_getTransactionCount","net_version"}
    counts = {}
    def read_only(self, method, params):
        if str(method) not in allowed: raise RuntimeError("PUBLIC_WRITE_FORBIDDEN")
        counts[str(method)] = counts.get(str(method),0)+1
        try: return original(self,method,params)
        except Exception: raise ConnectionError("PUBLIC_RPC_READ_UNAVAILABLE") from None
    with patch.object(HTTPProvider,"make_request",read_only), patch.object(chain,"submit_transaction",side_effect=AssertionError("PUBLIC_WRITE_FORBIDDEN")):
        from backend.core.governance import pipeline
        from backend.core.blockchain.batch_verifier import verify_anchored_batch,generate_proof,verify_proof
        from backend.core.blockchain.audit_log import hash_record
        from backend.core.blockchain.merkle import build_merkle_tree
        from backend.api.main import app
        from fastapi.testclient import TestClient
        paths = [ROOT/f"backend/core/{module}/data/sepolia/{name}" for module,names in (
            ("governance",("audit_logs.jsonl","batches.json","credentials.json","deployment.json","ethereum_state.json")),
            ("blockchain",("credentials.json","deployment.json","ethereum_state.json"))) for name in names]
        before={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
        web3,contract,_,_=chain.contract_context()
        assert web3.eth.chain_id==11155111 and contract.address=="0x61c74D0525f4f5A1a7b20f2eA561e485E71dd243"
        batches=pipeline.AUDIT_BATCH_MANAGER.list_batches(); assert len(batches)==1
        batch=batches[0]
        assert batch['merkle_root']=="0xee6028db0fb103cc0c5e1685e586b24d9213515a806aa9717f3ed0b54341006c"
        assert batch['blockchain_tx_hash']=="0xae52c353001ff8754625054d8873eeda0b74b1702af775da3e6a4cd4d33b75c2"
        records=pipeline.AUDIT_LOG_STORE.list_records(); assert len(records)==batch['log_count']==5
        assert verify_anchored_batch(batch)
        aid,bid=records[0]['action_id'],batch['batch_id']
        names=['normal','self_escalation','unauthorized_delegation','scope_creep','post_decommission']
        paths_api=['/api/health','/api/audit/status','/api/audit/logs','/api/audit/batches','/api/audit/batches/'+bid,
            '/api/audit/actions/'+aid,'/api/audit/actions/'+aid+'/proof','/api/system/overview','/api/agents',
            '/api/agents/Agent_B/credentials','/api/trace?agent_id=Agent_C&permission=CREATE_AGENT','/api/delegation-graph',
            '/api/metrics','/api/revocation/Agent_C','/api/final-report','/api/audit/actions/invalid','/api/audit/actions/invalid/proof',
            '/api/audit/batches/invalid','/api/audit/logs?limit=0','/api/trace/scenario/invalid']
        paths_api += ['/api/trace/scenario/'+name for name in names]
        checks=[]
        with TestClient(app) as client:
            def request(method,path,expected=200,**kwargs):
                response=client.request(method,path,**kwargs)
                assert response.status_code==expected,(method,path,response.status_code)
                checks.append({'method':method,'path':path,'http':response.status_code})
                return response.json() if response.content and method!='OPTIONS' else {}
            for path in paths_api:
                expected=422 if path.endswith('?limit=0') else 404 if path.endswith('/invalid') or '/invalid/' in path else 200
                request('GET',path,expected)
            path='/api/audit/actions/'+aid+'/verify'
            assert request('POST',path,json={})['result']=='VERIFIED'
            altered=deepcopy(records[0]); altered['metadata']['reason']='synthetic in-memory tamper'
            assert request('POST',path,json={'record_override':altered})['result']=='TAMPERED'
            request('POST','/api/audit/actions/invalid/verify',404,json={})
            request('OPTIONS','/api/health',headers={'Origin':'http://localhost:5173','Access-Control-Request-Method':'GET','Access-Control-Request-Headers':'content-type'})
            matrix_count=len(checks); assert matrix_count==29
            outcomes=[request('POST','/api/scenarios/'+name,json={})['verdict']['governance_decision'] for name in names]
            assert outcomes==['ALLOW','BLOCK','BLOCK','REVIEW','BLOCK']
            originals=[];tampered=[]
            for record in records:
                path='/api/audit/actions/'+record['action_id']+'/verify'
                originals.append(request('POST',path,json={})['result'])
                altered=deepcopy(record);altered['metadata']['reason']='synthetic altered copy'
                tampered.append(request('POST',path,json={'record_override':altered})['result'])
            assert originals==['VERIFIED']*5 and tampered==['TAMPERED']*5
        cases=0
        for n in range(1,6):
            copies=[{**deepcopy(records[0]),'action_id':f'edge:{i}'} for i in range(n)]
            leaves=[hash_record(r) for r in copies]; layer=[bytes.fromhex(h[2:]) for h in leaves]
            while len(layer)>1:
                layer=[bytes(Web3.keccak(layer[i]+(layer[i+1] if i+1<len(layer) else layer[i]))) for i in range(0,len(layer),2)]
            root='0x'+layer[0].hex();assert build_merkle_tree(leaves)['root']==root
            b={'batch_id':'batch:'+root,'merkle_root':root,'log_count':n,'action_ids':[r['action_id'] for r in copies],'leaf_hashes':leaves}
            for index,record in enumerate(copies):
                proof=generate_proof(b,index);assert verify_proof(record,proof,root);cases+=1
                assert not verify_proof({**record,'agent_id':'tampered'},proof,root);cases+=1
                bad=deepcopy(proof);bad['leaf_index']=n;assert not verify_proof(record,bad,root);cases+=1
                assert not verify_proof(record,proof,'0x'+'00'*32);cases+=1
                if proof['siblings']:
                    bad=deepcopy(proof);bad['siblings'][0]['hash']='0x'+'00'*32;assert not verify_proof(record,bad,root);cases+=1
            assert build_merkle_tree(leaves)==build_merkle_tree(leaves);cases+=1
            if n>1:assert build_merkle_tree(leaves[::-1])['root']!=root;cases+=1
        assert cases==83
        after={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
        assert before==after and pipeline.AUDIT_LOG_STORE.count()==5
        report={'completed_utc':datetime.now(timezone.utc).isoformat(),'api_matrix':matrix_count,'merkle_checks':cases,
            'governance_outcomes':outcomes,'original_proofs':originals,'tampered_copies':tampered,
            'canonical_files_unchanged':True,'canonical_sha256':after,'contract':contract.address,
            'batch_root':batch['merkle_root'],'batch_transaction':batch['blockchain_tx_hash'],'batch_records':5,
            'public_transactions':0,'rpc_counts':counts,'checks':checks}
        (ROOT/'docs/research-evaluation/raw/public_evidence_final.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({k:v for k,v in report.items() if k not in ('checks','canonical_sha256','rpc_counts')}))


if __name__=='__main__':
    try: run()
    except Exception as exc:
        print(json.dumps({'status':'FAILED','error_type':type(exc).__name__}))
        raise SystemExit(1) from None
