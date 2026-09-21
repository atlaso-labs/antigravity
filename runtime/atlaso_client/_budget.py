"""Wall-clock cancellation for standalone SessionStart hook processes.

HTTP timeouts alone do not bound credential locking + exchange + response reads.
The hook host also has a five-second fuse, covering interpreter/bootstrap time.
"""
from __future__ import annotations

from contextlib import contextmanager
import signal
import threading
import time


class HookTimeout(BaseException):
    """Cancellation must pass through best-effort `except Exception` handlers."""


@contextmanager
def hook_budget(seconds: float = 3.0):
    """Cancel the whole main-thread POSIX hook after `seconds`, then restore it.

    Other platforms/threads rely on the hook host's outer timeout and individual
    transport limits. This helper is for standalone hooks, not background workers.
    A pre-existing earlier alarm is preserved and its handler is respected.
    """
    if not hasattr(signal, "setitimer") or threading.current_thread() is not threading.main_thread():
        yield
        return
    old_handler = signal.getsignal(signal.SIGALRM)
    old_delay, old_interval = signal.getitimer(signal.ITIMER_REAL)
    started = time.monotonic()
    delay = max(0.001, seconds)
    earlier = bool(old_delay and old_delay <= delay)

    def expired(signum, frame):
        if earlier and callable(old_handler):
            old_handler(signum, frame)
        raise HookTimeout()

    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, min(delay, old_delay) if old_delay else delay)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)
        if old_delay:
            signal.setitimer(signal.ITIMER_REAL,
                             max(0.001, old_delay - (time.monotonic() - started)), old_interval)
