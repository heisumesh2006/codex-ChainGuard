"""ChainGuard-AI presentation API. Run from the project root with Uvicorn."""

import asyncio
from pathlib import Path
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from backend_api import services
from backend_api.schemas import ActionInput, GovernanceStreamRequest

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
