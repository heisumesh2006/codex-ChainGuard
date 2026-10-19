import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
os.environ["CHAINGUARD_NETWORK"] = "hardhat"
from backend.research.experiment2 import run as delegation
from backend.research.experiment3 import run as security
from backend.research.provenance import begin_run, finish_run

if __name__ == "__main__":
    out = ROOT / "docs/research-evaluation/raw"; out.mkdir(parents=True, exist_ok=True)
    if "--security-only" not in sys.argv:
        path, manifest = begin_run(out, "experiment2", {"trials": 20, "depths": [1, 2, 3, 4], "trace_repetitions_per_trial": 100})
        print("delegation_rows", len(delegation(out)[0]), flush=True)
        finish_run(path, manifest)
    if "--delegation-only" not in sys.argv:
        path, manifest = begin_run(out, "experiment3", {"repetitions": 10, "case_groups": 18})
        print("security_requests", len(security(out)), flush=True)
        finish_run(path, manifest)
