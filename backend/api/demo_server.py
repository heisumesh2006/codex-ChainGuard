"""Run a disposable, live Hardhat registry for the presentation UI.

The saved Module 6 evidence is left untouched.  Each invocation deploys a new
registry and replays the existing Module 1 records into temporary files.
"""

from pathlib import Path
import shutil
from uuid import uuid4

import uvicorn

from backend.core.governance import bootstrap
from backend.core.governance import main as module6_main
from backend.core.governance import pipeline
from backend.api import services
from backend.api.main import app


def main() -> None:
    runtime_root = (Path(__file__).resolve().parent / ".demo_runtime").resolve()
    data_dir = (runtime_root / uuid4().hex).resolve()
    if data_dir.parent != runtime_root:
        raise RuntimeError("Demo data directory escaped its workspace root")
    data_dir.mkdir(parents=True)
    try:
        bootstrap.DATA_DIR = data_dir
        bootstrap.PATHS = {
            "STATE_PATH": data_dir / "ethereum_state.json",
            "DEPLOYMENT_PATH": data_dir / "deployment.json",
            "CREDENTIALS_PATH": data_dir / "credentials.json",
        }
        bootstrap.bootstrap()
        # Bootstrap already replayed Module 1 in this process.
        pipeline._runtime["module1_ready"] = True
        shutil.copyfile(Path(__file__).resolve().parents[2] / "backend" / "core" / "governance" / "data" / "final_report.json", data_dir / "final_report.json")

        pipeline.DATA_DIR = data_dir
        module6_main.DATA_DIR = data_dir
        services.DATA_DIR = data_dir
        services.REPORT_PATH = data_dir / "final_report.json"
        uvicorn.run(app, host="127.0.0.1", port=8001)
    finally:
        shutil.rmtree(data_dir)


if __name__ == "__main__":
    main()
