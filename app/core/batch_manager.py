import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

from app.config import settings
from app.core.observability import get_logger, metrics
from app.core.security_guard import SSRFBlockedError, validate_target_url
from app.models.database import (
    create_batch_job,
    get_batch_job_by_id,
    list_batch_jobs,
    update_batch_job,
)

logger = get_logger("phishpulse.batch")


def _summarize_results(results: List[Optional[Dict[str, Any]]]) -> Dict[str, int]:
    counts = {"MALICIOUS": 0, "HIGH_RISK": 0, "SUSPICIOUS": 0, "BENIGN": 0, "ERROR": 0}
    for item in results:
        if not item:
            continue
        if item.get("error"):
            counts["ERROR"] += 1
        else:
            verdict = str(item.get("verdict") or "BENIGN").upper()
            counts[verdict] = counts.get(verdict, 0) + 1
    return counts


class BatchJobManager:
    """
    Bounded-concurrency asynchronous batch URL scanner.
    Prevents a 25-URL batch from overwhelming FastAPI, DNS, or upstream CTI providers,
    while persisting job progress and partial results into SQLite for non-blocking polling.
    """

    def __init__(self) -> None:
        self._tasks: Dict[str, asyncio.Task] = {}
        self._cancel_events: Dict[str, asyncio.Event] = {}

    async def _scan_single_item(
        self,
        target: str,
        scoring_engine: Any,
        *,
        fetch_content: bool,
        deep_dns: bool,
    ) -> Dict[str, Any]:
        try:
            clean_url = await asyncio.to_thread(validate_target_url, target)
            report = await scoring_engine.execute_scan(
                url=clean_url,
                fetch_content=fetch_content,
                deep_dns=deep_dns,
            )
            return {
                "url": target,
                "domain": report["target_domain"],
                "score": report["overall_score"],
                "verdict": report["verdict"],
                "verdict_color": report["verdict_color"],
                "scan_id": report["scan_id"],
                "summary": report["summary"],
            }
        except SSRFBlockedError as exc:
            metrics.record_ssrf_block()
            return {"url": target, "error": exc.detail}
        except HTTPException as exc:
            return {"url": target, "error": str(exc.detail)}
        except Exception as exc:
            return {"url": target, "error": str(exc)}

    async def run_bounded_batch(
        self,
        urls: List[str],
        scoring_engine: Any,
        *,
        concurrency: Optional[int] = None,
        fetch_content: bool = False,
        deep_dns: bool = True,
    ) -> Dict[str, Any]:
        """Run a batch inside the current await with strict semaphore concurrency bounds."""
        worker_limit = max(1, min(int(concurrency or settings.BATCH_WORKER_CONCURRENCY), settings.SCAN_MAX_CONCURRENCY))
        sem = asyncio.Semaphore(worker_limit)
        slots: List[Optional[Dict[str, Any]]] = [None] * len(urls)

        async def _worker(idx: int, target: str) -> None:
            async with sem:
                slots[idx] = await self._scan_single_item(
                    target,
                    scoring_engine,
                    fetch_content=fetch_content,
                    deep_dns=deep_dns,
                )

        await asyncio.gather(*(_worker(idx, target) for idx, target in enumerate(urls)))
        results = [item for item in slots if item is not None]
        return {
            "total": len(urls),
            "concurrency_limit": worker_limit,
            "summary": _summarize_results(results),
            "results": results,
        }

    async def enqueue_batch(
        self,
        urls: List[str],
        scoring_engine: Any,
        *,
        concurrency: Optional[int] = None,
        fetch_content: bool = False,
        deep_dns: bool = True,
        requested_by: str = "anonymous",
    ) -> Dict[str, Any]:
        """Create a persisted async batch job and schedule bounded background execution."""
        job_id = f"JOB-{uuid.uuid4().hex[:8].upper()}"
        worker_limit = max(1, min(int(concurrency or settings.BATCH_WORKER_CONCURRENCY), settings.SCAN_MAX_CONCURRENCY))
        create_batch_job(
            job_id=job_id,
            urls=urls,
            concurrency_limit=worker_limit,
            requested_by=requested_by,
            status="queued",
        )
        metrics.record_batch_job("queued")

        cancel_evt = asyncio.Event()
        self._cancel_events[job_id] = cancel_evt

        task = asyncio.create_task(
            self._execute_job(
                job_id=job_id,
                urls=urls,
                scoring_engine=scoring_engine,
                worker_limit=worker_limit,
                fetch_content=fetch_content,
                deep_dns=deep_dns,
                cancel_evt=cancel_evt,
            ),
            name=f"batch-{job_id}",
        )
        self._tasks[job_id] = task

        def _cleanup(_done_task: asyncio.Task) -> None:
            self._tasks.pop(job_id, None)
            self._cancel_events.pop(job_id, None)

        task.add_done_callback(_cleanup)

        created = get_batch_job_by_id(job_id) or {}
        logger.info(
            f"Queued async batch scan job {job_id} ({len(urls)} URLs, concurrency={worker_limit})",
            extra={
                "event": "batch_job_queued",
                "fields": {"job_id": job_id, "total_urls": len(urls), "concurrency": worker_limit},
            },
        )
        return created

    async def _execute_job(
        self,
        *,
        job_id: str,
        urls: List[str],
        scoring_engine: Any,
        worker_limit: int,
        fetch_content: bool,
        deep_dns: bool,
        cancel_evt: asyncio.Event,
    ) -> None:
        started_at = datetime.now(timezone.utc).isoformat()
        update_batch_job(job_id, status="running", started_at=started_at)
        metrics.record_batch_job("running")
        metrics.inc_active_batch_jobs(1)

        sem = asyncio.Semaphore(worker_limit)
        progress_lock = asyncio.Lock()
        slots: List[Optional[Dict[str, Any]]] = [None] * len(urls)
        completed = 0
        failed = 0

        async def _run_item(idx: int, target: str) -> None:
            nonlocal completed, failed
            if cancel_evt.is_set():
                return
            async with sem:
                if cancel_evt.is_set():
                    return
                res = await self._scan_single_item(
                    target,
                    scoring_engine,
                    fetch_content=fetch_content,
                    deep_dns=deep_dns,
                )
                async with progress_lock:
                    slots[idx] = res
                    completed += 1
                    if res.get("error"):
                        failed += 1
                    done_items = [item for item in slots if item is not None]
                    update_batch_job(
                        job_id,
                        completed_urls=completed,
                        failed_urls=failed,
                        results=done_items,
                        summary=_summarize_results(done_items),
                    )

        try:
            await asyncio.gather(*(_run_item(idx, url) for idx, url in enumerate(urls)))
            final_items = [item for item in slots if item is not None]
            if cancel_evt.is_set():
                final_status = "cancelled"
            elif failed == len(urls) and urls:
                final_status = "failed"
            elif failed > 0:
                final_status = "completed_with_errors"
            else:
                final_status = "completed"

            update_batch_job(
                job_id,
                status=final_status,
                completed_urls=len(final_items),
                failed_urls=failed,
                results=final_items,
                summary=_summarize_results(final_items),
                finished_at=datetime.now(timezone.utc).isoformat(),
            )
            metrics.record_batch_job(final_status)
            logger.info(
                f"Finished async batch scan job {job_id} with status={final_status} ({len(final_items)}/{len(urls)})",
                extra={
                    "event": "batch_job_finished",
                    "fields": {"job_id": job_id, "status": final_status, "failed": failed, "total": len(urls)},
                },
            )
        except Exception as exc:
            update_batch_job(
                job_id,
                status="failed",
                error=str(exc),
                finished_at=datetime.now(timezone.utc).isoformat(),
            )
            metrics.record_batch_job("failed")
            logger.error(f"Batch scan job {job_id} crashed: {exc}", extra={"event": "batch_job_crashed"})
        finally:
            metrics.inc_active_batch_jobs(-1)

    def cancel_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        job = get_batch_job_by_id(job_id)
        if not job:
            return None
        evt = self._cancel_events.get(job_id)
        if evt is not None:
            evt.set()
        if job["status"] in ("queued", "running") and evt is None:
            update_batch_job(
                job_id,
                status="cancelled",
                finished_at=datetime.now(timezone.utc).isoformat(),
            )
        return get_batch_job_by_id(job_id)

    async def await_job(self, job_id: str, timeout: float = 10.0) -> Optional[Dict[str, Any]]:
        task = self._tasks.get(job_id)
        if task is not None:
            await asyncio.wait_for(asyncio.shield(task), timeout=timeout)
        return get_batch_job_by_id(job_id)

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        return get_batch_job_by_id(job_id)

    def recent_jobs(self, limit: int = 20) -> List[Dict[str, Any]]:
        return list_batch_jobs(limit=limit)


batch_manager = BatchJobManager()
