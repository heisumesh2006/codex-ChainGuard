"""Preserved pre-fix versus signed, grant-specific cascading enforcement."""

import statistics
import time
from .common import local_policy, root_grant, delegate, revoke, original_module
from .experiment1 import save_csv
from backend.core.authorization import agents as a


def run(output, trials=20):
    rows = []
    for depth in range(1, 5):
        nodes = ["Agent_" + letter for letter in "ABCD"[:depth]]
        for trial in range(trials):
            for version in ("original_flat", "corrected_cascade"):
                with local_policy() as identity:
                    engine = original_module() if version == "original_flat" else a
                    grant = (lambda: engine.grant_root_permission("Agent_A", "P")) if version == "original_flat" else (lambda: root_grant(identity))
                    if grant()["result"] != "ALLOWED": raise AssertionError("Root grant failed")
                    for parent, child in zip(nodes, nodes[1:]):
                        result = (engine.delegate_permission(engine.AGENTS[parent], engine.AGENTS[child], "P")
                                  if version == "original_flat" else delegate(identity, parent, child))
                        if result["result"] != "ALLOWED": raise AssertionError("Valid delegation rejected")
                    before = {node: engine.check_permission(engine.AGENTS[node], "P")["result"] == "ALLOWED" for node in nodes}
                    trace_times = []
                    for _ in range(100):
                        start = time.perf_counter_ns()
                        if version == "original_flat": engine.check_permission(engine.AGENTS[nodes[-1]], "P")
                        else: a.authority_paths(nodes[-1], "P")
                        trace_times.append((time.perf_counter_ns()-start)/1e6)
                    start = time.perf_counter_ns()
                    result = (engine.decommission_agent("Agent_B") if version == "original_flat" else revoke(identity, "Agent_B"))
                    revocation_ms = (time.perf_counter_ns()-start)/1e6
                    if result["result"] != "REVOKED": raise AssertionError("Revocation rejected")
                    after = {node: engine.check_permission(engine.AGENTS[node], "P")["result"] == "ALLOWED" for node in nodes}
                    downstream = nodes[2:]
                    rows.append(dict(version=version, depth=depth, trial=trial+1,
                        authorized_before=sum(before.values()), authorized_after=sum(after.values()),
                        expected_downstream_invalidated=len(downstream),
                        downstream_invalidated=sum(not after[node] for node in downstream),
                        incorrectly_retained=sum(after[node] for node in downstream),
                        incorrectly_revoked=int(not after["Agent_A"]),
                        revocation_ms=revocation_ms, trace_average_ms=statistics.mean(trace_times),
                        trace_median_ms=statistics.median(trace_times),
                        trace_semantics="flat permission check" if version == "original_flat" else "verified signed local grant ancestry"))
    save_csv(output / "experiment2_depths.csv", rows)
    independent = []
    for trial in range(trials):
        for scenario in ("independent_root", "independent_parent"):
            with local_policy() as identity:
                root_grant(identity); delegate(identity, "Agent_A", "Agent_B"); delegate(identity, "Agent_B", "Agent_C")
                if scenario == "independent_root": root_grant(identity, "Agent_C")
                else:
                    root_grant(identity, "Agent_D"); delegate(identity, "Agent_D", "Agent_C")
                revoke(identity, "Agent_B")
                allowed = a.check_permission(a.AGENTS["Agent_C"], "P")["result"] == "ALLOWED"
                independent.append(dict(scenario=scenario, trial=trial+1, expected="ALLOW", actual="ALLOW" if allowed else "BLOCK",
                                        incorrectly_revoked=int(not allowed), history_records=len(a.DELEGATION_LEDGER),
                                        revoked_grants=sum(g["status"] == "REVOKED" for g in a.DELEGATION_LEDGER)))
                if not allowed: raise AssertionError("Independent path revoked")
    save_csv(output / "experiment2_independent_paths.csv", independent)
    return rows, independent
