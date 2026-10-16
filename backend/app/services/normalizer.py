"""
app/services/normalizer.py
──────────────────────────
Transforms raw RawFeedEntry payloads into unified Indicator records.

Rules:
  • (value, ioc_type) is the natural deduplication key.
  • On duplicate: update last_seen, merge tags/mitre_techniques, rescore.
  • On new: insert full Indicator record.
  • Always mark the RawFeedEntry as processed (idempotent on replay).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.threat import Indicator, RawFeedEntry
from app.services.scorer import calculate_score, map_mitre_techniques

logger = logging.getLogger(__name__)


@dataclass
class NormResult:
    inserted: int = 0
    updated: int = 0
    errors: int = 0


def _merge_csv(existing: str | None, new_items: list[str]) -> str:
    """Merge two comma-separated value strings, deduplicating entries."""
    parts: list[str] = []
    if existing:
        parts = [p.strip() for p in existing.split(",") if p.strip()]
    for item in new_items:
        for sub in item.split(","):
            sub = sub.strip()
            if sub and sub not in parts:
                parts.append(sub)
    return ",".join(parts)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_raw(entry: RawFeedEntry) -> dict | None:
    try:
        return json.loads(entry.raw_json)
    except (json.JSONDecodeError, TypeError) as exc:
        logger.warning("Failed to parse RawFeedEntry id=%s: %s", entry.id, exc)
        return None


def upsert_indicator(
    db: Session,
    *,
    value: str,
    ioc_type: str,
    source: str,
    tags: str | None = None,
    threat_type: str | None = None,
    country_code: str | None = None,
    asn: str | None = None,
    confidence: int = 50,
    raw_data: str | None = None,
    abuse_confidence: int = 0,
    is_kev: bool = False,
    last_seen: datetime | None = None,
) -> tuple[Indicator, bool]:
    """
    Upsert a single Indicator.

    Returns:
        (indicator, created) where created=True means it was newly inserted.
    """
    now = last_seen or _utcnow()
    score = calculate_score(
        source=source,
        tags=tags,
        threat_type=threat_type,
        last_seen=now,
        abuse_confidence=abuse_confidence,
        is_kev=is_kev,
    )

    existing: Indicator | None = (
        db.query(Indicator)
        .filter(Indicator.value == value, Indicator.ioc_type == ioc_type)
        .first()
    )

    if existing:
        existing.last_seen = now
        existing.updated_at = _utcnow()
        existing.tags = _merge_csv(existing.tags, [tags or ""])
        existing.mitre_techniques = _merge_csv(
            existing.mitre_techniques, score.mitre_techniques
        )
        existing.severity_score = score.total
        existing.severity_label = score.label
        if confidence > existing.confidence:
            existing.confidence = confidence
        if country_code and not existing.country_code:
            existing.country_code = country_code
        if asn and not existing.asn:
            existing.asn = asn
        if raw_data:
            existing.raw_data = raw_data
        if threat_type and not existing.threat_type:
            existing.threat_type = threat_type
        return existing, False

    indicator = Indicator(
        value=value,
        ioc_type=ioc_type,
        source=source,
        tags=tags,
        threat_type=threat_type,
        country_code=country_code,
        asn=asn,
        confidence=confidence,
        severity_score=score.total,
        severity_label=score.label,
        mitre_techniques=",".join(score.mitre_techniques) if score.mitre_techniques else None,
        raw_data=raw_data,
        first_seen=now,
        last_seen=now,
        is_active=True,
    )
    db.add(indicator)
    return indicator, True


def process_raw_entry(db: Session, entry: RawFeedEntry) -> bool:
    """
    Process a single RawFeedEntry: parse → upsert indicator → mark processed.

    Returns True on success, False on error.
    """
    if entry.is_processed:
        return True  # idempotent replay guard

    payload = _parse_raw(entry)
    if payload is None:
        entry.is_processed = True
        entry.processing_error = "JSON parse failed"
        entry.processed_at = _utcnow()
        return False

    try:
        indicator, created = upsert_indicator(
            db,
            value=payload["value"],
            ioc_type=payload["ioc_type"],
            source=payload.get("source", "unknown"),
            tags=payload.get("tags"),
            threat_type=payload.get("threat_type"),
            country_code=payload.get("country_code"),
            asn=payload.get("asn"),
            confidence=int(payload.get("confidence", 50)),
            raw_data=entry.raw_json,
            abuse_confidence=int(payload.get("abuse_confidence", 0)),
            is_kev=bool(payload.get("is_kev", False)),
            last_seen=datetime.fromisoformat(payload["last_seen"])
            if payload.get("last_seen")
            else None,
        )

        db.flush()  # get indicator.id without committing
        entry.indicator_id = indicator.id
        entry.is_processed = True
        entry.processed_at = _utcnow()
        entry.processing_error = None
        return True

    except Exception as exc:
        logger.error(
            "Failed to normalise RawFeedEntry id=%s: %s", entry.id, exc, exc_info=True
        )
        entry.is_processed = True
        entry.processing_error = str(exc)[:1024]
        entry.processed_at = _utcnow()
        return False


def process_feed_entries(
    db: Session,
    feed_id: int,
    batch_size: int = 200,
) -> NormResult:
    """
    Process all unprocessed RawFeedEntry rows for a given feed in batches.
    Commits after each batch for crash-safety.
    """
    result = NormResult()

    while True:
        entries: list[RawFeedEntry] = (
            db.query(RawFeedEntry)
            .filter(
                RawFeedEntry.feed_id == feed_id,
                RawFeedEntry.is_processed == False,  # noqa: E712
            )
            .limit(batch_size)
            .all()
        )
        if not entries:
            break

        pre_counts = db.query(Indicator).count()
        for entry in entries:
            ok = process_raw_entry(db, entry)
            if not ok:
                result.errors += 1

        try:
            db.commit()
        except Exception as exc:
            logger.error("Batch commit failed for feed_id=%s: %s", feed_id, exc)
            db.rollback()
            result.errors += len(entries)
            break

        post_counts = db.query(Indicator).count()
        result.inserted += post_counts - pre_counts
        result.updated += len(entries) - (post_counts - pre_counts) - result.errors

    return result
