"""Deploy one isolated latest-schema registry and replay Module 1 into it."""

from contextlib import ExitStack
from pathlib import Path
import sys
from unittest.mock import patch

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from module2 import chain
from module2.main import run_blockchain_demo

DATA_DIR = Path(__file__).resolve().parent / "data"
PATHS = {
    "STATE_PATH": DATA_DIR / "ethereum_state.json",
    "DEPLOYMENT_PATH": DATA_DIR / "deployment.json",
    "CREDENTIALS_PATH": DATA_DIR / "credentials.json",
}


def bootstrap():
    if any(path.exists() for path in PATHS.values()):
        raise RuntimeError("Canonical Module 6 registry already exists; refusing to overwrite it")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with ExitStack() as stack:
        for name, path in PATHS.items():
            stack.enter_context(patch.object(chain, name, path))
        run_blockchain_demo()
    print("Canonical Module 6 registry deployed without changing Module 2 or Module 5 state")


if __name__ == "__main__":
    bootstrap()
