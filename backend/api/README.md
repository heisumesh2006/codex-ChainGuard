# ChainGuard-AI API

Run from the project root, with the Hardhat node already running and the Module 6 canonical deployment available:

```powershell
.venv/Scripts/python.exe -m pip install -r requirements.txt
.venv/Scripts/python.exe -m uvicorn backend.api.main:app --host 127.0.0.1 --port 8000
```

The adapter reads the Module 6 canonical deployment, saved report and saved ML model. It calls the existing Module 6 pipeline for decisions. It does not deploy or write blockchain records.

If the saved Module 6 contract is unavailable on the current Hardhat chain, start the disposable presentation registry instead:

```powershell
.venv/Scripts/python.exe -m backend.api.demo_server
```

This deploys a fresh contract through the existing Module 6 bootstrap, stores its state under the Git-ignored `backend/api/.demo_runtime`, and serves the same API on `http://127.0.0.1:8001`. Set `VITE_API_BASE_URL=http://127.0.0.1:8001` for the frontend before starting Vite. Saved scenario replays start from the persisted ML baseline so repeated demos return consistent decisions.

Presentation reads added for the trust UI:

- `GET /api/agents/{agent_id}/credentials` returns readable credential metadata and the existing Module 3 authority proof result.
- `GET /api/trace?agent_id=Agent_C&permission=CREATE_AGENT` calls Module 3's historical authority tracer.
- `GET /api/trace/scenario/post_decommission` traces the saved action at its original timestamp.

The WebSocket accepts `{"scenario":"normal"}` or `{"action":{"actor":"Agent_B","action":"CHECK_CREATE_ORDER","permission":"CREATE_ORDER"}}`. It sends `ACTION_RECEIVED` immediately, then replays the pipeline's measured stage results after evaluation. `replay: true` means the UI can animate the completed stages without fake backend delays.
