"""Independent read-only local-EVM validation of the completed audit benchmark.

Use --capture-inputs once while the benchmark runs to retain its synthetic
timestamp. Default mode validates every anchor receipt/root after completion.
No signing, deployment, public RPC or transaction submission is implemented.
"""
from collections import defaultdict
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
RAW = ROOT / "docs/research-evaluation/raw"


def capture():
    manifest = json.loads((RAW / "experiment1_manifest.json").read_text())
    start = datetime.strptime(manifest["started_utc"], "%Y%m%dT%H%M%S%fZ").replace(tzinfo=timezone.utc).timestamp()
    timestamps = []
    for path in Path(tempfile.gettempdir()).glob("research-audit-*/merkle_blockchain/audit.jsonl"):
        try:
            if path.stat().st_mtime < start: continue
            with path.open(encoding="utf-8") as stream: record = json.loads(next(stream))
            if (record["action_id"].startswith("experiment:") and record["metadata"].get("measurement_scope")
                    == "signed authorization plus audit; ML held constant/not executed"):
                timestamps.append(record["timestamp"])
        except (OSError, StopIteration, ValueError):
            continue
    if not timestamps or len(set(timestamps)) != 1:
        raise RuntimeError("No unique active benchmark timestamp; capture while a measured workload is running")
    path = RAW / "experiment1_inputs.json"
    if path.exists():
        previous = json.loads(path.read_text())
        if previous["manifest_started_utc"] != manifest["started_utc"]:
            archive = RAW / "prior" / ("experiment1_inputs_" + previous["manifest_started_utc"])
            archive.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, archive / path.name)
    path.write_text(json.dumps({"input_timestamp": timestamps[0],
        "source": "Read-only capture from active isolated benchmark audit JSONL",
        "manifest_started_utc": manifest["started_utc"],
        "event_generator": "backend.research.experiment1.audit_record"}, indent=2)+"\n")
    print("Synthetic benchmark input timestamp retained; no audit state changed")


def verify():
    os.environ["CHAINGUARD_NETWORK"] = "hardhat"
    os.environ["CHAINGUARD_RPC_URL"] = "http://127.0.0.1:8545"
    from web3 import Web3
    from backend.research.experiment1 import audit_record, save_csv
    manifest = json.loads((RAW / "experiment1_manifest.json").read_text())
    inputs = json.loads((RAW / "experiment1_inputs.json").read_text())
    if manifest["status"] != "COMPLETE" or inputs["manifest_started_utc"] != manifest["started_utc"]:
        raise RuntimeError("Completed matching run required")
    web3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
    if web3.eth.chain_id != 31337: raise RuntimeError("LOCAL_HARDHAT_ONLY")
    artifact = json.loads((ROOT / "blockchain/artifacts/contracts/AgentTrustRegistry.sol/AgentTrustRegistry.json").read_text())
    event_abi = next(a for a in artifact["abi"] if a.get("name") == "AuditBatchAnchored" and a["type"] == "event")
    topic = Web3.keccak(text=event_abi["name"]+"("+",".join(a["type"] for a in event_abi["inputs"])+")")
    final = web3.eth.block_number
    if final > 100_000: raise RuntimeError("Local verification block cap exceeded")
    groups = defaultdict(list)
    decoder = web3.eth.contract(abi=artifact["abi"]).events.AuditBatchAnchored()
    for first in range(0, final+1, 128):
        for log in web3.eth.get_logs({"fromBlock": first, "toBlock": min(first+127, final), "topics": [topic]}):
            groups[log["address"]].append(decoder.process_log(log))
    with (RAW/"experiment1_summary.csv").open(newline="") as stream:
        summaries = [row for row in csv.DictReader(stream) if row["version"] == "merkle_blockchain"]
    ordered = sorted(groups.items(), key=lambda item: item[1][0]["blockNumber"])[-len(summaries):]
    if len(ordered) != len(summaries): raise RuntimeError("Missing local benchmark contracts")
    receipts, datasets = [], []
    for row, (address, events) in zip(summaries, ordered, strict=True):
        count, trial = int(row["workload"]), int(row["trial"])
        assert len(events) == count//10
        records = [audit_record(i, count, inputs["input_timestamp"], True) for i in range(count)]
        encoded = [json.dumps(r, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode() for r in records]
        datasets.append({"workload": count, "trial": trial, "canonical_jsonl_sha256": hashlib.sha256(b"".join(r+b"\n" for r in encoded)).hexdigest()})
        deployment = web3.eth.get_block(events[0]["blockNumber"]-1, full_transactions=True)
        creations = [web3.eth.get_transaction_receipt(tx["hash"]) for tx in deployment.transactions if tx["to"] is None]
        creation = next(r for r in creations if r.contractAddress == address)
        assert creation.status == 1 and creation.gasUsed == int(row["deployment_gas_used"])
        gas = fees = 0
        for index, event in enumerate(events):
            leaves = [bytes(Web3.keccak(data)) for data in encoded[index*10:(index+1)*10]]
            while len(leaves)>1:
                leaves = [bytes(Web3.keccak(leaves[i]+(leaves[i+1] if i+1<len(leaves) else leaves[i]))) for i in range(0,len(leaves),2)]
            assert event["args"]["logCount"] == 10 and leaves[0] == event["args"]["merkleRoot"]
            receipt = web3.eth.get_transaction_receipt(event["transactionHash"])
            assert receipt.status == 1 and receipt.to == address
            gas += int(receipt.gasUsed); fees += int(receipt.gasUsed)*int(receipt.effectiveGasPrice)
            receipts.append({"workload": count, "trial": trial, "batch_index": index, "registry": address,
                "merkle_root": Web3.to_hex(leaves[0]), "log_count": 10, "transaction_hash": Web3.to_hex(receipt.transactionHash),
                "block_number": receipt.blockNumber, "gas_used": receipt.gasUsed,
                "effective_gas_price": receipt.effectiveGasPrice, "fee_wei": int(receipt.gasUsed)*int(receipt.effectiveGasPrice),
                "deployment_transaction_hash": Web3.to_hex(creation.transactionHash), "deployment_gas_used": creation.gasUsed})
        assert gas == int(row["gas_used"]) and fees == int(row["gas_fee_wei"])
    save_csv(RAW/"experiment1_anchors.csv", receipts)
    save_csv(RAW/"experiment1_datasets.csv", datasets)
    result = {"chain_id":31337,"contracts_verified":len(ordered),"anchor_receipts_verified":len(receipts),
              "records_reconstructed":sum(int(r["workload"]) for r in summaries), "all_roots_match":True,
              "gas_and_fees_match_raw_csv":True, "public_transactions":0,
              "local_inventory_query_range":[0,final],"input_manifest_started_utc":manifest["started_utc"]}
    (RAW/"experiment1_onchain_verification.json").write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result))


if __name__ == "__main__":
    capture() if "--capture-inputs" in sys.argv else verify()
