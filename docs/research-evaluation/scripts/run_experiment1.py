"""Usage: python docs/research-evaluation/scripts/run_experiment1.py [--smoke]."""
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
os.environ["CHAINGUARD_NETWORK"] = "hardhat"
os.environ["CHAINGUARD_RPC_URL"] = "http://127.0.0.1:8545"
from backend.research.experiment1 import run
from backend.research.provenance import begin_run, finish_run

if __name__ == "__main__":
    smoke = "--smoke" in sys.argv
    output = ROOT / "docs/research-evaluation" / ("smoke" if smoke else "raw")
    workloads, trials = ((10,), 1) if smoke else ((10, 100, 500, 1000), 3)
    path, manifest = begin_run(output, "experiment1", {"workloads": workloads, "trials": trials, "batch_size": 10})
    run(output, workloads=workloads, trials=trials)
    finish_run(path, manifest)
