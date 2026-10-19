"""Exercise a real loopback HTTP server with registered local wallet signatures.

Provisions disposable local contracts/storage; never uses canonical evidence.
Run after measured benchmarks so setup work cannot contaminate their timings.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
os.environ["CHAINGUARD_NETWORK"] = "hardhat"
os.environ["CHAINGUARD_RPC_URL"] = "http://127.0.0.1:8545"


def serve(folder, port):
    import joblib
    import uvicorn
    from backend.api import services
    from backend.api.main import app
    from backend.core.governance import pipeline
    from backend.core.blockchain.audit_log import AuditLogStore
    from backend.core.blockchain.batch_manager import BatchManager
    data = Path(folder)
    services.DATA_DIR = pipeline.DATA_DIR = data
    pipeline.AUDIT_LOG_STORE = AuditLogStore(data/"audit.jsonl")
    pipeline.AUDIT_BATCH_MANAGER = BatchManager(pipeline.AUDIT_LOG_STORE, data/"batches.json", batch_size=100)
    pipeline._runtime.update(module1_ready=True, model=joblib.load(pipeline.MODEL_PATH))
    uvicorn.run(app, host="127.0.0.1", port=int(port), log_level="warning")


def verify():
    from datetime import datetime, timezone
    from backend.core.blockchain.tests.test_grant_authority import GrantAuthorityIntegrationTests
    from backend.core.authorization.operator_signing import operator_credentials
    from backend.core.authorization.authentication import sign_request
    from backend.api.schemas import ActionInput
    from eth_account import Account
    fixture = GrantAuthorityIntegrationTests(methodName="test_real_registered_keys_and_governance_allow_live_valid_path")
    process = None
    try:
        fixture.setUp()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0)); port = listener.getsockname()[1]
        with (fixture.folder/"http-server.log").open("wb") as log:
            process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--serve", str(fixture.folder), str(port)],
                                       cwd=ROOT, stdout=log, stderr=log, creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
            base = f"http://127.0.0.1:{port}"
            deadline = time.monotonic()+60
            while True:
                if process.poll() is not None: raise RuntimeError("Isolated HTTP server exited")
                try:
                    with urllib.request.urlopen(base+"/api/health", timeout=2) as response:
                        if response.status == 200: break
                except (urllib.error.URLError, TimeoutError):
                    if time.monotonic() >= deadline: raise RuntimeError("Isolated HTTP readiness timeout")
                    time.sleep(.1)
            payload = ActionInput(actor="Agent_D", action="USE_PERMISSION", permission="P",
                timestamp=datetime.fromtimestamp(fixture.web3.eth.get_block("latest").timestamp, timezone.utc).isoformat(),
                authority_grant_id=fixture.leaf).model_dump(exclude_none=True)
            credentials = operator_credentials("Agent_D", "evaluate", payload)
            envelope = credentials["authentication"]
            def request(body, authentication=None):
                headers={"Content-Type":"application/json"}
                if authentication is not None: headers["X-ChainGuard-Authentication"] = json.dumps(authentication)
                req=urllib.request.Request(base+"/api/governance/evaluate", data=json.dumps(body).encode(), headers=headers)
                try:
                    with urllib.request.urlopen(req,timeout=120) as response: return response.status,json.load(response)
                except urllib.error.HTTPError as response: return response.code,json.load(response)
            status, verdict = request(payload,envelope)
            assert status==200 and verdict["authorized"] and verdict["chain_verified"]
            assert verdict["governance_decision"] in ("ALLOW","REVIEW")
            replay,_=request(payload,envelope)
            modified,_=request({**payload,"permission":"ADMIN"},envelope)
            unsigned,_=request(payload)
            impersonated={**payload,"actor":"ROOT_AUTHORIZER"}
            forged=sign_request(Account.create(),credentials["verifier"].domain,"ROOT_AUTHORIZER","evaluate",impersonated)
            spoofed,_=request(impersonated,forged)
            assert (replay,modified,unsigned,spoofed)==(401,401,401,401)
            assert fixture.stack is not None
            from backend.core.governance import pipeline
            assert pipeline.AUDIT_LOG_STORE.count()==1
            report={"transport":"real loopback TCP / Uvicorn / urllib HTTP", "chain_id":31337,
                "authenticated_http":status,"authenticated_governance_decision":verdict["governance_decision"],
                "chain_verified":verdict["chain_verified"],"replay_http":replay,"modified_body_http":modified,
                "unsigned_http":unsigned,"root_impersonation_http":spoofed,"persisted_audit_records":1,
                "rejected_requests_persisted":0,"public_transactions":0}
            (ROOT/"docs/research-evaluation/raw/live_http_verification.json").write_text(json.dumps(report,indent=2)+"\n")
            print(json.dumps(report))
    finally:
        if process is not None:
            process.terminate()
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=10)
        fixture.doCleanups()


if __name__=="__main__":
    serve(sys.argv[2],sys.argv[3]) if len(sys.argv)>1 and sys.argv[1]=="--serve" else verify()
