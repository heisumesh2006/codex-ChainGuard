"""Real local-Hardhat Merkle anchoring versus protected/rewriteable hash chains."""

from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import csv
import json
from pathlib import Path
import statistics
import tempfile
import time
from web3 import Web3

from backend.core.authorization import agents as a
from backend.core.authorization.authentication import RequestVerifier
from backend.core.blockchain.audit_log import AuditRecord, AuditLogStore, hash_record, canonicalize_record
from backend.core.blockchain.batch_manager import BatchManager
from backend.core.blockchain.merkle import build_merkle_tree
from backend.core.blockchain.persistence import atomic_write
from .audit_baseline import HashChainLog, chain_entries
from .common import local_policy, local_registry, root_grant


def save_csv(path, rows):
    with Path(path).open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)


def quantile(values, q):
    ordered = sorted(values); index = (len(ordered) - 1) * q
    lo = int(index); hi = min(lo + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (index - lo)


def audit_record(index, count, timestamp, authorized):
    return asdict(AuditRecord(
        action_id=f"experiment:{count}:{index}", timestamp=timestamp,
        agent_id="Agent_A", action="USE_PERMISSION", scope="P", target=f"order:{index}",
        authorization_result="ALLOWED" if authorized else "DENIED", trace_verdict="LOCAL_VALID_PATH",
        anomaly_result={"applicable": False, "flagged": False, "score": None}, revocation_status=None,
        governance_verdict="ALLOW" if authorized else "BLOCK",
        metadata={"source_action_id": f"input:{count}:{index}", "detected_by": [],
                  "measurement_scope": "signed authorization plus audit; ML held constant/not executed"}))


def changed(records, attack):
    records = deepcopy(records)
    if attack == "modify": records[len(records) // 2]["target"] = "attacker-modified"
    elif attack == "delete": del records[len(records) // 2]
    elif attack == "insert":
        forged = deepcopy(records[0]); forged.update(action_id="forged:record", target="forged")
        records.insert(len(records) // 2, forged)
    elif attack == "reorder": records[0], records[-1] = records[-1], records[0]
    elif attack == "rewrite_history":
        for row in records: row["target"] = "rewritten-history"
    else: raise ValueError(attack)
    return records


def verify_chain_inventory(store, web3, contract, deployment, final_block):
    """Auditor discovers expected roots externally, not from local batch JSON.

    Trust assumptions: authenticated deployment/chain and an honest local RPC.
    Complete audit availability and order are checked, not inclusion alone.
    """
    records = store.list_records()
    events = contract.events.AuditBatchAnchored().get_logs(
        from_block=deployment["block_number"], to_block=final_block)
    offset = 0
    for event in events:
        args = event["args"]; count = int(args["logCount"])
        chunk = records[offset:offset + count]
        if len(chunk) != count: return False
        root = build_merkle_tree([hash_record(record) for record in chunk])["root"]
        stored = contract.functions.auditBatches(args["batchId"]).call()
        if (not stored[6] or stored[0] != bytes.fromhex(root[2:]) or stored[1] != count
                or stored[0] != args["merkleRoot"]): return False
        offset += count
    return offset == len(records) and bool(events)


def run(output, workloads=(10, 100, 500, 1000), trials=3):
    output = Path(output); output.mkdir(parents=True, exist_ok=True)
    summaries, timings, attacks = [], [], []
    timestamp = datetime.now(timezone.utc).isoformat()
    for count in workloads:
        for trial in range(trials):
            with tempfile.TemporaryDirectory(prefix="research-audit-") as tmp, local_policy() as identity:
                folder = Path(tmp); root_grant(identity)
                versions = ["merkle_blockchain", "hash_chain"] if trial % 2 == 0 else ["hash_chain", "merkle_blockchain"]
                for version in versions:
                    data = folder / version; data.mkdir()
                    verifier = RequestVerifier(identity.verifier.domain, identity.verifier.resolve_identity, data / "authentication_nonces.json")
                    store = AuditLogStore(data / "audit.jsonl") if version == "merkle_blockchain" else HashChainLog(data / "hash_chain.json")
                    manager = BatchManager(store, data / "batches.json", batch_size=10, max_age_seconds=3600) if version == "merkle_blockchain" else None
                    # Deploy only in the blockchain variant. Deployment time/
                    # gas is reported separately and excluded from event cost.
                    context = local_registry(data) if manager else _no_registry()
                    with context as connection:
                        # Warm retained-signature verification equally for
                        # both variants; request signatures remain fresh.
                        if a.check_permission(a.AGENTS["Agent_A"], "P")["result"] != "ALLOWED":
                            raise AssertionError("Benchmark warm-up authorization failed")
                        trial_started = time.perf_counter_ns()
                        auth_times, local_times, event_times = [], [], []
                        processing_ns = 0
                        for index in range(count):
                            payload = {"actor": "Agent_A", "permission": "P", "event": index, "workload": count}
                            envelope = identity.credentials("Agent_A", "benchmark_action", payload)["authentication"]
                            start = time.perf_counter_ns()
                            verifier.authenticate(envelope, "benchmark_action", payload, "Agent_A")
                            allowed = a.check_permission(a.AGENTS["Agent_A"], "P")["result"] == "ALLOWED"
                            auth_end = time.perf_counter_ns()
                            if not allowed: raise AssertionError("Valid benchmark authorization failed")
                            record = audit_record(index, count, timestamp, allowed)
                            store.append(record)
                            if manager: sealed = manager.seal_due_batches()
                            local_end = time.perf_counter_ns()
                            if manager:
                                for batch in sealed:
                                    anchored = manager.anchor_batch(batch["batch_id"])
                                    if anchored["status"] != "ANCHORED": raise AssertionError("Anchor failed")
                            end = time.perf_counter_ns(); processing_ns += end - start
                            auth_ms, local_ms, total_ms = (auth_end-start)/1e6, (local_end-auth_end)/1e6, (end-start)/1e6
                            auth_times.append(auth_ms); local_times.append(local_ms); event_times.append(total_ms)
                            timings.append(dict(version=version, workload=count, trial=trial+1, event=index,
                                                auth_ms=auth_ms, local_audit_ms=local_ms,
                                                anchor_ms=(end-local_end)/1e6, event_recording_ms=total_ms))
                        if manager:
                            web3, contract, root, deployment = connection
                            final_block = web3.eth.block_number
                            check = lambda: verify_chain_inventory(store, web3, contract, deployment, final_block)
                            batches = manager.list_batches()
                            receipts = [web3.eth.get_transaction_receipt(b["blockchain_tx_hash"]) for b in batches]
                            gas = sum(int(r.gasUsed) for r in receipts)
                            fees = sum(int(r.gasUsed) * int(r.effectiveGasPrice) for r in receipts)
                            tx_count = len(receipts)
                            deployment_receipt = web3.eth.get_transaction_receipt(deployment["deployment_transaction_hash"])
                            deployment_gas = int(deployment_receipt.gasUsed)
                            records = store.list_records()
                        else:
                            state = store.read(); records = [entry["record"] for entry in state["entries"]]
                            checkpoint = {"head": state["head"], "count": len(records)}
                            check = lambda: store.verify(checkpoint)
                            gas = fees = tx_count = 0
                            deployment_gas = 0
                        start = time.perf_counter_ns(); verified = check(); verification_ms = (time.perf_counter_ns()-start)/1e6
                        if not verified: raise AssertionError("Untampered log failed verification")
                        # Persistent audit bytes only, excluding replay cache,
                        # deployment/credentials, lock files and filesystem metadata.
                        storage = sum(p.stat().st_size for p in data.iterdir()
                                      if p.name in ("audit.jsonl", "batches.json", "hash_chain.json"))
                        summaries.append(dict(version=version, workload=count, trial=trial+1,
                            recording_average_ms=statistics.mean(event_times), recording_median_ms=statistics.median(event_times),
                            recording_p95_ms=quantile(event_times,.95), auth_average_ms=statistics.mean(auth_times),
                            local_audit_average_ms=statistics.mean(local_times), verification_ms=verification_ms,
                            storage_bytes=storage, processing_ms=processing_ns/1e6, gas_used=gas, gas_fee_wei=fees,
                            audit_transactions=tx_count, verification_failures=0, untampered_false_positives=0))
                        summaries[-1].update(deployment_gas_used=deployment_gas,
                                              workload_wall_ms=(time.perf_counter_ns()-trial_started)/1e6)
                        original_bytes = store.path.read_bytes()
                        for policy in ("protected_checkpoint", "rewriteable_local_checkpoint"):
                            for attack in ("modify", "delete", "insert", "reorder", "rewrite_history"):
                                forged = changed(records, attack)
                                if manager:
                                    atomic_write(store.path, b"".join(canonicalize_record(r)+b"\n" for r in forged))
                                    result = check()
                                else:
                                    # Strong storage attacker can recompute every
                                    # link. Only the external checkpoint differs.
                                    atomic_write(store.path, canonicalize_record(chain_entries(forged)))
                                    result = store.verify(checkpoint if policy == "protected_checkpoint" else None)
                                attacks.append(dict(version=version, workload=count, trial=trial+1,
                                                    checkpoint_policy=policy, attack=attack,
                                                    detected=int(not result), falsely_accepted=int(result)))
                                atomic_write(store.path, original_bytes)
                        if not check(): raise AssertionError("Original restoration failed")
                        print(f"experiment1 {version} n={count} trial={trial+1} complete", flush=True)
                    # Persist after each run so interrupted work is reviewable.
                    save_csv(output / "experiment1_summary.csv", summaries)
                    save_csv(output / "experiment1_events.csv", timings)
                    save_csv(output / "experiment1_tampering.csv", attacks)
    return summaries, attacks


from contextlib import contextmanager
@contextmanager
def _no_registry(): yield None
