"""Deploy one isolated latest-schema registry and replay Module 1 into it."""

from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from backend.core.blockchain import chain
from backend.core.blockchain.main import run_blockchain_demo

DATA_DIR = Path(__file__).resolve().parent / "data"
if chain.NETWORK_PROFILE == "sepolia":
    DATA_DIR = DATA_DIR / "sepolia"
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
