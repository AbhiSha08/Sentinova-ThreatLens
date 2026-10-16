"""
app/routers/feeds.py
─────────────────────
Feed management and manual sync endpoints.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.threat import Feed, Indicator, RawFeedEntry
from app.services.cache import invalidate_prefix
from app.services.ingester import IngestSummary, run_all_ingesters

router = APIRouter(prefix="/feeds", tags=["Feeds"])


@router.post(
    "/sync",
    summary="Trigger immediate ingestion run across all feeds",
    response_model=list[dict],
)
async def sync_feeds(db: Session = Depends(get_db)) -> list[dict]:
    """
    Immediately runs all feed ingesters and returns a per-source summary
    including indicator counts, status, and any error messages.
    """
    summaries: list[IngestSummary] = await run_all_ingesters()
    await invalidate_prefix("threatlens:")

    results = []
    for s in summaries:
        indicator_count = (
            db.query(Indicator).filter(Indicator.source == _source_key(s.source)).count()
        )
        results.append(
            {
                "source":           s.source,
                "status":           s.status,
                "fetched":          s.fetched,
                "inserted":         s.inserted,
                "updated":          s.updated,
                "errors":           s.errors,
                "total_in_db":      indicator_count,
                "message":          s.message or None,
            }
        )
    return results


@router.get(
    "/",
    summary="List all registered feeds and their health",
    response_model=list[dict],
)
def list_feeds(db: Session = Depends(get_db)) -> list[dict]:
    feeds = db.query(Feed).order_by(Feed.name).all()
    return [
        {
            "id":                  f.id,
            "name":                f.name,
            "url":                 f.url,
            "feed_type":           f.feed_type,
            "is_enabled":          f.is_enabled,
            "last_fetched_at":     f.last_fetched_at.isoformat() if f.last_fetched_at else None,
            "last_fetch_status":   f.last_fetch_status,
            "indicators_ingested": f.indicators_ingested,
            "last_error_message":  f.last_error_message,
        }
        for f in feeds
    ]


@router.get(
    "/stats",
    summary="Global ingestion statistics",
)
def feed_stats(db: Session = Depends(get_db)) -> dict:
    total_indicators = db.query(Indicator).count()
    active_indicators = db.query(Indicator).filter(Indicator.is_active == True).count()  # noqa: E712
    raw_entries = db.query(RawFeedEntry).count()
    unprocessed = db.query(RawFeedEntry).filter(RawFeedEntry.is_processed == False).count()  # noqa: E712

    by_severity: dict[str, int] = {}
    for label in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        by_severity[label] = (
            db.query(Indicator).filter(Indicator.severity_label == label).count()
        )

    by_type: dict[str, int] = {}
    for row in db.query(Indicator.ioc_type, Indicator.id).all():
        ioc_type = row[0]
        by_type[ioc_type] = by_type.get(ioc_type, 0) + 1

    return {
        "total_indicators":  total_indicators,
        "active_indicators": active_indicators,
        "raw_entries":       raw_entries,
        "unprocessed":       unprocessed,
        "by_severity":       by_severity,
        "by_ioc_type":       by_type,
    }


def _source_key(source_name: str) -> str:
    """Map IngestSummary.source → Indicator.source field value."""
    mapping = {
        "CISA KEV":           "CISA_KEV",
        "URLhaus Recent":     "URLhaus",
        "AbuseIPDB Blacklist":"AbuseIPDB",
        "OTX":                "OTX",
    }
    return mapping.get(source_name, source_name)
