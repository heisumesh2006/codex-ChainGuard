"""Orchestrate the five existing security layers on one canonical registry."""

from contextlib import ExitStack, contextmanager, redirect_stdout
from dataclasses import asdict, dataclass
import io
from pathlib import Path
import time
from unittest.mock import patch

import joblib

from backend.core.authorization import agents as module1_agents
from backend.core.authorization.main import run_demo as run_module1_demo
from backend.core.blockchain import chain, integration
from backend.core.blockchain.anchor import get_proof, verify_proof
from backend.core.blockchain.audit_log import AuditLogStore, audit_record_from_verdict
from backend.core.blockchain.batch_manager import BatchManager
from backend.core.tracing.tracer import trace_action, trace_agent_authority
from backend.core.drift_detection.detector import score_action
from backend.core.revocation import revocation as module5_revocation
from backend.core.revocation.audit import check_post_revocation_activity
from backend.core.revocation.revocation import get_revocation_status, verify_revocation_proof

DATA_DIR = Path(__file__).resolve().parent / "data"
MODEL_PATH = Path(__file__).resolve().parents[1] / "drift_detection" / "models" / "isolation_forest.joblib"
_runtime = {"model": None, "module1_ready": False}
AUDIT_LOG_STORE = AuditLogStore()
AUDIT_BATCH_MANAGER = BatchManager(AUDIT_LOG_STORE)


@contextmanager
def canonical_context():
    """Point Modules 2, 3, and 5 at the same latest-schema deployment."""
    paths = {
        "DEPLOYMENT_PATH": DATA_DIR / "deployment.json",
        "STATE_PATH": DATA_DIR / "ethereum_state.json",
        "CREDENTIALS_PATH": DATA_DIR / "credentials.json",
    }
    with ExitStack() as stack:
        for name, path in paths.items():
            stack.enter_context(patch.object(chain, name, path))
        for name, path in (
            ("BUNDLE_DEPLOYMENT_PATH", paths["DEPLOYMENT_PATH"]),
            ("BUNDLE_STATE_PATH", paths["STATE_PATH"]),
            ("BUNDLE_CREDENTIALS_PATH", paths["CREDENTIALS_PATH"]),
        ):
            stack.enter_context(patch.object(module5_revocation, name, path))
        yield


@dataclass
class GovernanceVerdict:
    action: dict
    authorized: bool
    drift_applicable: bool
    drift_flagged: bool
    drift_score: float | None
    trace_result: dict | None
    trace_context_verdict: str
    revocation_status: dict | None
    chain_verified: bool
    chain_check_status: str
    governance_decision: str
    reasons: list[str]
    total_latency_ms: float
    step_latencies: dict
    audit_result: dict | None
    detected_by: list[str]
    chain_evidence: dict

    def to_dict(self):
        return asdict(self)


def prepare_runtime():
    """Use Module 1's real demo state and Module 4's persisted fitted model."""
    if not _runtime["module1_ready"]:
        with redirect_stdout(io.StringIO()) as output:
            run_module1_demo()
        if "MODULE 1 COMPLETED SUCCESSFULLY" not in output.getvalue():
            raise RuntimeError("Module 1 replay did not complete")
        _runtime["module1_ready"] = True
    if _runtime["model"] is None:
        _runtime["model"] = joblib.load(MODEL_PATH)


def _permission(action):
    permission = action.get("permission") or action.get("requested_permission")
    code = action["action"]
    if permission is None and code.startswith("DELEGATE_"):
        permission = code.removeprefix("DELEGATE_")
    if permission is None and code.startswith("CHECK_"):
        permission = code.removeprefix("CHECK_")
    return permission


def _authorize(action):
    # Existing anchored Module 1 events carry the actual real-time outcome.
    if not str(action.get("record_id", "")).startswith("synthetic:"):
        return action.get("result") in ("ALLOWED", "REVOKED")
    actor = action["actor"]
    agent = module1_agents.AGENTS.get(actor)
    permission = _permission(action)
    return bool(agent and permission and
                module1_agents.check_permission(agent, permission)["result"] == "ALLOWED")


def _trace_context(action):
    if str(action.get("record_id", "")).startswith("synthetic:"):
        return trace_agent_authority(action["actor"], _permission(action))
    return trace_action(action)


def _verify_chain(action, trace, status, audit):
    evidence = {"action_hash": None, "delegation": None, "revocation": None,
                "authority_hops": None, "public_revocation": None, "error": None}
    try:
        synthetic = str(action.get("record_id", "")).startswith("synthetic:")
        if not synthetic:
            action_proof = get_proof(integration.blockchain_record_id("action", action))
            evidence["action_hash"] = verify_proof(action, action_proof)
            if not evidence["action_hash"]:
                return False, "FAILED", evidence
            if action["action"].startswith("DELEGATE_"):
                ledger = [entry["source"] for entry in chain.load_state()["records"].values()
                          if entry["kind"] == "delegation"
                          and entry["source"]["delegator"] == action["actor"]
                          and entry["source"]["delegatee"] == action.get("delegatee")
                          and entry["source"]["timestamp"] == action["timestamp"]]
                if len(ledger) != 1:
                    raise RuntimeError("Matching anchored delegation is missing or ambiguous")
                delegation_proof = get_proof(integration.blockchain_record_id("delegation", ledger[0]))
                evidence["delegation"] = verify_proof(ledger[0], delegation_proof)
                if not evidence["delegation"]:
                    return False, "FAILED", evidence
            if action["action"] == "AGENT_DECOMMISSIONED":
                revocation_proof = get_proof(integration.blockchain_record_id("revocation", action))
                evidence["revocation"] = verify_proof(action, revocation_proof)
                public = get_revocation_status(action["decommissioned_agent"])
                evidence["public_revocation"] = bool(public["is_revoked"] and
                    verify_revocation_proof(action["decommissioned_agent"], public["chain_proof"]))
                if not evidence["revocation"] or not evidence["public_revocation"]:
                    return False, "FAILED", evidence

        if trace["chain"]:
            evidence["authority_hops"] = all(
                hop["anchored"] and hop["proof_verified"] for hop in trace["chain"]
            )
            if not evidence["authority_hops"]:
                return False, "FAILED", evidence
        elif synthetic:
            # A synthetic action is not anchored itself. An unrooted synthetic
            # authority path therefore has no positive blockchain evidence.
            return False, "FAILED", evidence

        if status and status["is_revoked"]:
            evidence["public_revocation"] = verify_revocation_proof(action["actor"], status["chain_proof"])
            if not evidence["public_revocation"]:
                return False, "FAILED", evidence
        if audit and audit["violation"]:
            return True, "VERIFIED_REVOCATION", evidence
        if trace["verdict"] in ("UNAUTHORIZED_ROOT", "BROKEN_CHAIN") and not trace["chain"]:
            return True, "VERIFIED_NO_VALID_AUTHORITY", evidence
        if trace["verdict"] in ("TAMPERED", "CIRCULAR_CHAIN"):
            return False, "FAILED", evidence
        if trace["valid"] and trace["chain"]:
            return True, "VERIFIED_VALID_CHAIN", evidence
        if trace["valid"]:
            return True, "VERIFIED_CONTEXT", evidence
        return False, "FAILED", evidence
    except Exception as exc:
        evidence["error"] = str(exc)
        return False, "FAILED", evidence


def run_governance_pipeline(action_log_entry) -> GovernanceVerdict:
    """Return a timed verdict; trace once and pass it into Module 4 scoring."""
    prepare_runtime()
    action = dict(action_log_entry)
    pipeline_started = time.perf_counter()
    timings = {}

    started = time.perf_counter()
    authorized = _authorize(action)
    timings["authorization_ms"] = (time.perf_counter() - started) * 1000

    with canonical_context():
        started = time.perf_counter()
        trace = _trace_context(action)
        timings["trace_context_ms"] = (time.perf_counter() - started) * 1000

        started = time.perf_counter()
        applicable = action["actor"] != module1_agents.ROOT_AUTHORIZER
        if applicable:
            # Module 4 consumes the exact Module 3 result; no second trace.
            model_input = {**action, "trace_result": trace}
            drift_score, drift_flagged = score_action(model_input, _runtime["model"])
        else:
            drift_score, drift_flagged = None, False
        timings["drift_scoring_ms"] = (time.perf_counter() - started) * 1000

        started = time.perf_counter()
        status = audit = None
        if applicable:
            status = get_revocation_status(action["actor"])
            if status["is_revoked"]:
                audit = check_post_revocation_activity(action)
        timings["revocation_check_ms"] = (time.perf_counter() - started) * 1000

        started = time.perf_counter()
        chain_verified, chain_status, evidence = _verify_chain(action, trace, status, audit)
        timings["chain_verification_ms"] = (time.perf_counter() - started) * 1000

    started = time.perf_counter()
    reasons = []
    layers = []
    if not authorized:
        layers.append("Module1")
        reasons.append("Module 1 real-time authorization denied the action")
    if not trace["valid"]:
        layers.append("Module3")
        reasons.append(f"Authority trace returned {trace['verdict']}: {trace['reason']}")
    if drift_flagged:
        layers.append("Module4")
        reasons.append("Behavior deviates from the trained normal baseline")
    if audit and audit["violation"]:
        layers.append("Module5")
        reasons.append("Action occurred after the chain-retrieved revocation timestamp")
    if not chain_verified:
        layers.append("Module2")
        reasons.append("Required blockchain evidence could not be verified")

    if not authorized or not trace["valid"] or (audit and audit["violation"]) or not chain_verified:
        decision = "BLOCK"
    elif drift_flagged:
        decision = "REVIEW"
    else:
        decision = "ALLOW"
        reasons.append("Authorized with verified chain evidence and no significant drift")
    display_trace = trace if (not authorized or drift_flagged or not trace["valid"]
                              or (status and status["is_revoked"])) else None
    timings["verdict_assembly_ms"] = (time.perf_counter() - started) * 1000
    total = (time.perf_counter() - pipeline_started) * 1000
    verdict = GovernanceVerdict(
        action=action, authorized=authorized, drift_applicable=applicable,
        drift_flagged=drift_flagged, drift_score=drift_score,
        trace_result=display_trace, trace_context_verdict=trace["verdict"],
        revocation_status=status, chain_verified=chain_verified,
        chain_check_status=chain_status, governance_decision=decision,
        reasons=reasons, total_latency_ms=total, step_latencies=timings,
        audit_result=audit, detected_by=layers, chain_evidence=evidence,
    )
    # Persist once at the completed evaluation boundary. Reads/serialization of
    # this verdict do not write a second audit entry.
    AUDIT_LOG_STORE.append(audit_record_from_verdict(verdict))
    AUDIT_BATCH_MANAGER.seal_due_batches()
    return verdict
