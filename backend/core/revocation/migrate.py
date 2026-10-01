"""Create a separate detailed-revocation registry without replacing Module 2 files."""

from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from backend.core.blockchain import chain
from backend.core.blockchain.main import run_blockchain_demo

DATA_DIR = Path(__file__).resolve().parent / "data"
PATHS = {
    "STATE_PATH": DATA_DIR / "ethereum_state.json",
    "DEPLOYMENT_PATH": DATA_DIR / "deployment.json",
    "CREDENTIALS_PATH": DATA_DIR / "credentials.json",
}


def migrate():
    if any(path.exists() for path in PATHS.values()):
        raise RuntimeError("Module 5 registry files already exist; migration refuses to overwrite them")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with ExitStack() as stack:
        for name, path in PATHS.items():
            stack.enter_context(patch.object(chain, name, path))
        run_blockchain_demo()
    print("Module 5 detailed-revocation registry created separately from Module 2 state")


if __name__ == "__main__":
    migrate()
