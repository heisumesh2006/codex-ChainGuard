"""Non-secret run manifests and preservation of superseded pilot outputs."""

from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys


def begin_run(output, name, parameters):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    previous = list(output.glob(name + "_*.csv")) + list(output.glob(name + "_manifest.json"))
    if previous:
        archive = output / "prior" / (name + "_" + stamp)
        archive.mkdir(parents=True)
        for path in previous:
            shutil.copy2(path, archive / path.name)
    root = Path(__file__).resolve().parents[2]
    sources = sorted((root / "backend/research").glob("*.py"))
    sources += sorted((root / "backend/core").rglob("*.py"))
    sources += sorted((root / "docs/research-evaluation/scripts").glob("*.py"))
    sources += sorted((root / "blockchain/contracts").glob("*.sol"))
    sources += [root / "backend/core/drift_detection/models/isolation_forest.joblib",
                root / "backend/core/drift_detection/data/synthetic_logs.json",
                root / "backend/core/drift_detection/data/ground_truth.json",
                root / "blockchain/hardhat.config.js", root / "blockchain/package-lock.json",
                root / "requirements.txt", root / "requirements-research.txt"]
    manifest = {
        "started_utc": stamp, "parameters": parameters,
        "branch": subprocess.check_output(["git", "branch", "--show-current"], cwd=root, text=True).strip(),
        "base_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
        "platform": platform.platform(), "python": sys.version.split()[0],
        "node": subprocess.check_output(["node", "--version"], text=True).strip(),
        "processor": platform.processor(), "logical_cpu_count": os.cpu_count(),
        "packages": {name: importlib.metadata.version(name) for name in ("web3", "eth-account", "scikit-learn", "matplotlib")},
        "node_packages": {name: json.loads((root / "blockchain/node_modules" / name / "package.json").read_text())["version"]
                          for name in ("hardhat", "ethers")},
        "source_sha256": {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
        "network": "isolated local Hardhat 31337", "public_transactions": 0,
        "status": "RUNNING",
    }
    path = output / (name + "_manifest.json")
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return path, manifest


def finish_run(path, manifest):
    manifest["completed_utc"] = datetime.now(timezone.utc).isoformat()
    manifest["status"] = "COMPLETE"
    manifest["csv_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                              for p in path.parent.glob(path.name.removesuffix("_manifest.json") + "_*.csv")}
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
