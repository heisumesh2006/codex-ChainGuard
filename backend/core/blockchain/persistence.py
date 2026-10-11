"""Local-filesystem process locks and atomic snapshots (no network locks)."""

from contextlib import contextmanager
import errno
import os
from pathlib import Path
import tempfile
import threading
import time

if os.name == "nt":
    import msvcrt
else:
    import fcntl


class PersistenceLockTimeout(TimeoutError):
    """Storage is busy; the operation did not acquire its coordination lock."""


class _LockState:
    def __init__(self):
        self.thread_lock = threading.RLock()
        self.local = threading.local()
        self.handle = None


_states = {}
_states_guard = threading.Lock()


def _after_fork():
    global _states, _states_guard
    # Closing inherited descriptors must not unlock the parent's flock.
    # Otherwise a surviving fork child could retain a crashed parent's lock.
    for state in _states.values():
        if state.handle is not None:
            state.handle.close()
    _states = {}
    _states_guard = threading.Lock()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork)


class FileLock:
    """Reentrant within a thread; OS-owned across unrelated processes.

    Coordination files must never be deleted or replaced while in use. Their
    presence is not ownership: Windows byte locks / POSIX flock are released
    by the OS on process exit. Supported scope is a local filesystem, not NFS.
    """

    def __init__(self, path: Path | str, timeout: float = 10.0):
        if timeout < 0 or not float(timeout) < float("inf"):
            raise ValueError("Lock timeout must be finite and nonnegative")
        self.path = Path(path).resolve()
        self.timeout = timeout
        self.pid = os.getpid()
        with _states_guard:
            self.state = _states.setdefault(os.path.normcase(str(self.path)), _LockState())

    def _refresh_after_fork(self):
        if self.pid != os.getpid():
            with _states_guard:
                self.state = _states.setdefault(os.path.normcase(str(self.path)), _LockState())
            self.pid = os.getpid()

    @contextmanager
    def hold(self):
        self._refresh_after_fork()
        deadline = time.monotonic() + self.timeout
        state = self.state
        if not state.thread_lock.acquire(timeout=self.timeout):
            raise PersistenceLockTimeout("PERSISTENCE_LOCK_TIMEOUT: storage is busy")
        handle = None
        acquired = False
        nested = getattr(state.local, "depth", 0) > 0
        try:
            if not nested:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                handle = self.path.open("a+b")
                state.handle = handle
                # Both APIs lock beyond EOF. Do not initialize a byte here:
                # an unrelated owner can already have byte zero locked.
                while True:
                    try:
                        if os.name == "nt":
                            handle.seek(0)
                            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                        else:
                            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        acquired = True
                        break
                    except OSError as exc:
                        if exc.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                            raise
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise PersistenceLockTimeout("PERSISTENCE_LOCK_TIMEOUT: storage is busy") from None
                        time.sleep(min(0.02, remaining))
            state.local.depth = getattr(state.local, "depth", 0) + 1
            try:
                yield
            finally:
                state.local.depth -= 1
        finally:
            try:
                if acquired:
                    if os.name == "nt":
                        handle.seek(0)
                        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            finally:
                if handle is not None:
                    handle.close()
                    state.handle = None
                state.thread_lock.release()

    def __enter__(self):
        self._refresh_after_fork()
        # Each invocation gets its own context; nested calls share OS ownership.
        stack = getattr(self.state.local, "contexts", None)
        if stack is None:
            stack = self.state.local.contexts = []
        context = self.hold()
        context.__enter__()
        stack.append(context)
        return self

    def __exit__(self, *exc):
        return self.state.local.contexts.pop().__exit__(*exc)


def atomic_write(path: Path, content: bytes) -> None:
    """Publish a complete snapshot; failures before replacement retain old bytes.

    Caller owns the stable coordination lock. Orphaned unique temp files from
    killed writers are inert; never promote them or infer committed state from
    them. File fsync precedes replacement; POSIX also fsyncs the directory.
    A failure after replacement can have committed: reload before retrying.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)
