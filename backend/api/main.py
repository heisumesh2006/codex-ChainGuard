"""ChainGuard-AI presentation API. Run from the project root with Uvicorn."""

import asyncio
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from backend.api import services
from backend.api.schemas import ActionInput, AuditVerifyInput, GovernanceStreamRequest

app = FastAPI(title="ChainGuard-AI API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health():
    return services.health()


@app.get("/api/system/overview")
def overview():
    return services.overview()


@app.get("/api/agents")
def agents():
    return services.agents()


@app.get("/api/agents/{agent_id}/credentials")
def agent_credentials(agent_id: str):
    try:
        return services.agent_credentials(agent_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/trace")
def trace_authority(agent_id: str, permission: str):
    return services.trace_authority(agent_id, permission)


@app.get("/api/trace/scenario/{scenario_name}")
def trace_scenario_action(scenario_name: str):
    if scenario_name not in services.SCENARIOS:
        raise HTTPException(status_code=404, detail="Unknown scenario")
    return services.trace_scenario_action(scenario_name)


@app.get("/api/delegation-graph")
def delegation_graph():
    return services.delegation_graph()


@app.get("/api/metrics")
def metrics():
    return services.metrics()


@app.get("/api/revocation/{agent_id}")
def revocation(agent_id: str):
    return services.revocation(agent_id)


@app.get("/api/final-report")
def final_report():
    return services.final_report()


@app.get("/api/audit/status")
def audit_status():
    return services.audit_status()


@app.get("/api/audit/logs")
def audit_logs(limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0)):
    return services.audit_logs(limit=limit, offset=offset)


@app.get("/api/audit/batches")
def audit_batches(limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0)):
    return services.audit_batches(limit=limit, offset=offset)


@app.get("/api/audit/batches/{batch_id}")
def audit_batch(batch_id: str):
    try:
        return services.audit_batch(batch_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/audit/actions/{action_id}")
def audit_action(action_id: str):
    try:
        return services.audit_action(action_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/audit/actions/{action_id}/proof")
def audit_action_proof(action_id: str):
    try:
        return services.audit_action_proof(action_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/audit/actions/{action_id}/verify")
def verify_audit_action(action_id: str, request: AuditVerifyInput | None = None):
    try:
        return services.verify_audit_action(
            action_id, request.record_override if request is not None else None,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/governance/evaluate")
def evaluate(action: ActionInput):
    return services.evaluate(action)


@app.post("/api/scenarios/{scenario_name}")
def scenario(scenario_name: str):
    if scenario_name not in services.SCENARIOS:
        raise HTTPException(status_code=404, detail="Unknown scenario")
    return services.run_scenario(scenario_name)


@app.websocket("/ws/governance")
async def governance_stream(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            try:
                request = GovernanceStreamRequest.model_validate(await websocket.receive_json())
                if bool(request.scenario) == bool(request.action):
                    raise ValueError("Provide exactly one scenario or action")
                if request.scenario and request.scenario not in services.SCENARIOS:
                    raise ValueError("Unknown scenario")
                incoming = services.scenario_action(request.scenario) if request.scenario else request.action.model_dump(exclude_none=True)
                await websocket.send_json({"event": "ACTION_RECEIVED", "status": "RECEIVED", "scenario": request.scenario,
                                           "actor": incoming["actor"], "action": incoming["action"], "timestamp": incoming.get("timestamp")})
                if request.scenario:
                    result = await asyncio.to_thread(services.run_scenario, request.scenario)
                    verdict = result["verdict"]
                else:
                    verdict = await asyncio.to_thread(services.evaluate, request.action)
                for event in services.stage_events(verdict):
                    await websocket.send_json(event)
            except Exception as exc:
                await websocket.send_json({"event": "ERROR", "detail": str(exc)})
    except WebSocketDisconnect:
        return
