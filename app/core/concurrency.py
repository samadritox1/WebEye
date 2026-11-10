import asyncio
import weakref
from contextlib import asynccontextmanager
from typing import Dict

from app.config import settings
from app.core.observability import metrics

_LOOP_SEMAPHORES: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, Dict[str, asyncio.Semaphore]]" = (
    weakref.WeakKeyDictionary()
)


def get_loop_semaphore(channel: str, limit: int) -> asyncio.Semaphore:
    """
    Return an asyncio.Semaphore bound safely to the current running event loop.
    Prevents cross-loop errors across FastAPI lifespan & unittest TestClient portals.
    """
    loop = asyncio.get_running_loop()
    channel_map = _LOOP_SEMAPHORES.get(loop)
    if channel_map is None:
        channel_map = {}
        _LOOP_SEMAPHORES[loop] = channel_map
    sem = channel_map.get(channel)
    if sem is None:
        sem = asyncio.Semaphore(max(1, int(limit)))
        channel_map[channel] = sem
    return sem


def reset_loop_semaphores() -> None:
    """Clear cached semaphores (useful when tests mutate concurrency settings dynamically)."""
    _LOOP_SEMAPHORES.clear()


@asynccontextmanager
async def bounded_scan_slot(limit: int | None = None):
    """Enforce bounded concurrency on HTTP/URL scans and update live concurrency metrics."""
    cap = max(1, int(limit or settings.SCAN_MAX_CONCURRENCY))
    sem = get_loop_semaphore(f"scan:{cap}", cap)
    await sem.acquire()
    metrics.inc_active_scans(1)
    try:
        yield
    finally:
        metrics.inc_active_scans(-1)
        sem.release()


@asynccontextmanager
async def bounded_sandbox_slot(limit: int | None = None):
    """Enforce bounded concurrency on headless browser detonations."""
    cap = max(1, int(limit or settings.SANDBOX_MAX_CONCURRENCY))
    sem = get_loop_semaphore(f"sandbox:{cap}", cap)
    await sem.acquire()
    metrics.inc_active_sandbox(1)
    try:
        yield
    finally:
        metrics.inc_active_sandbox(-1)
        sem.release()
