"""
app/services/scheduler.py
──────────────────────────
APScheduler AsyncIOScheduler that runs run_all_ingesters on a
configurable interval. Integrates with the FastAPI lifespan via
start() / shutdown() coroutines called from app/main.py.
"""

from __future__ import annotations

import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from app.services.ingester import run_all_ingesters

logger = logging.getLogger(__name__)

_scheduler: AsyncIOScheduler | None = None

# Default interval — can be overridden from settings in a future phase
_INTERVAL_MINUTES: int = 60


async def _run_job() -> None:
    logger.info("Scheduled ingestion job starting…")
    summaries = await run_all_ingesters()
    for s in summaries:
        logger.info(
            "  [%s] status=%s fetched=%d inserted=%d updated=%d errors=%d",
            s.source, s.status, s.fetched, s.inserted, s.updated, s.errors,
        )


def start(interval_minutes: int = _INTERVAL_MINUTES) -> None:
    """Start the background scheduler. Called once from the lifespan startup."""
    global _scheduler
    if _scheduler and _scheduler.running:
        logger.warning("Scheduler already running — skipping start()")
        return

    _scheduler = AsyncIOScheduler(timezone="UTC")
    _scheduler.add_job(
        _run_job,
        trigger=IntervalTrigger(minutes=interval_minutes),
        id="ingest_all_feeds",
        name="Run All Feed Ingesters",
        replace_existing=True,
        misfire_grace_time=300,  # allow up to 5-min misfire
    )
    _scheduler.start()
    logger.info(
        "Scheduler started — ingestion runs every %d minutes.", interval_minutes
    )


def shutdown() -> None:
    """Gracefully stop the scheduler. Called from lifespan teardown."""
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("Scheduler stopped.")
