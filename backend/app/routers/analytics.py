"""
app/routers/analytics.py
────────────────────────
Executive & Threat Landscape Analytics router for ThreatLens.

Provides high-level KPIs, severity distribution, MITRE ATT&CK breakdown,
vendor exposure metrics, and country origin heatmaps for executive and SOC lead dashboards.
Cached for 300 seconds with instant invalidation on feed ingestion.
"""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.threat import Feed, Indicator, RawFeedEntry
from app.schemas.threat import IndicatorResponse
from app.services.cache import get_cached, set_cached

router = APIRouter(prefix="/analytics", tags=["Analytics (Executive View)"])

# ── MITRE ATT&CK Catalog ───────────────────────────────────────────────────────
MITRE_DESCRIPTIONS: dict[str, str] = {
    "T1190": "Exploit Public-Facing Application",
    "T1105": "Ingress Tool Transfer",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1095": "Non-Application Layer Protocol",
    "T1486": "Data Encrypted for Impact",
    "T1490": "Inhibit System Recovery",
    "T1110": "Brute Force",
    "T1110.001": "Password Guessing",
    "T1595": "Active Scanning",
    "T1566": "Phishing",
    "T1566.002": "Spearphishing Link",
    "T1059": "Command and Scripting Interpreter",
    "T1543": "Create or Modify System Process",
}


# ── Response Models ────────────────────────────────────────────────────────────

class MitreTechniqueStat(BaseModel):
    id: str
    name: str
    count: int


class VendorStat(BaseModel):
    vendor: str
    count: int


class CountryStat(BaseModel):
    country_code: str
    count: int


class ExecutiveSummaryResponse(BaseModel):
    total_indicators: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    active_feeds_count: int
    ransomware_linked_count: int
    average_risk_score: float
    severity_distribution: dict[str, int]
    ioc_type_distribution: dict[str, int]
    source_distribution: dict[str, int]
    top_mitre_techniques: list[MitreTechniqueStat]
    top_targeted_vendors: list[VendorStat]
    top_origin_countries: list[CountryStat]
    recent_critical_alerts: list[IndicatorResponse]


@router.get(
    "/executive-summary",
    summary="Executive dashboard KPIs and threat landscape summary (cached 300s)",
    response_model=ExecutiveSummaryResponse,
)
async def get_executive_summary(db: Session = Depends(get_db)) -> Any:
    cache_key = "threatlens:analytics:executive-summary"
    cached = await get_cached(cache_key)
    if cached is not None:
        return cached

    # 1. Total & severity counts
    total_indicators = db.query(Indicator).count()
    active_feeds_count = db.query(Feed).filter(Feed.is_enabled == True).count()  # noqa: E712

    severity_counts = dict(
        db.query(Indicator.severity_label, func.count(Indicator.id))
        .group_by(Indicator.severity_label)
        .all()
    )
    critical_count = severity_counts.get("CRITICAL", 0)
    high_count     = severity_counts.get("HIGH", 0)
    medium_count   = severity_counts.get("MEDIUM", 0)
    low_count      = severity_counts.get("LOW", 0)

    # 2. Average risk score
    avg_score_row = db.query(func.avg(Indicator.severity_score)).scalar()
    average_risk_score = round(float(avg_score_row), 1) if avg_score_row else 0.0

    # 3. Ransomware linked count (tags or threat_type containing ransomware)
    ransomware_linked_count = (
        db.query(Indicator)
        .filter(
            (Indicator.tags.ilike("%ransomware%")) | (Indicator.threat_type.ilike("%ransomware%"))
        )
        .count()
    )

    # 4. IoC type distribution
    ioc_type_rows = (
        db.query(Indicator.ioc_type, func.count(Indicator.id))
        .group_by(Indicator.ioc_type)
        .all()
    )
    ioc_type_distribution = {row[0]: row[1] for row in ioc_type_rows}

    # 5. Source distribution
    source_rows = (
        db.query(Indicator.source, func.count(Indicator.id))
        .group_by(Indicator.source)
        .all()
    )
    source_distribution = {row[0]: row[1] for row in source_rows}

    # 6. Top MITRE ATT&CK techniques
    tech_counter: Counter[str] = Counter()
    for row in db.query(Indicator.mitre_techniques).filter(Indicator.mitre_techniques.isnot(None)).all():
        raw_tech = row[0]
        if raw_tech:
            for tid in raw_tech.split(","):
                tid = tid.strip()
                if tid:
                    tech_counter[tid] += 1

    top_mitre_techniques: list[dict[str, Any]] = [
        {
            "id": tid,
            "name": f"{tid} - {MITRE_DESCRIPTIONS.get(tid, 'Unknown Technique')}",
            "count": count,
        }
        for tid, count in tech_counter.most_common(8)
    ]

    # 7. Top targeted vendors (from CISA KEV metadata in raw_data)
    vendor_counter: Counter[str] = Counter()
    kev_entries = (
        db.query(Indicator.raw_data)
        .filter(Indicator.source == "CISA_KEV", Indicator.raw_data.isnot(None))
        .all()
    )
    for (raw_str,) in kev_entries:
        if raw_str:
            try:
                blob = json.loads(raw_str)
                vendor = blob.get("vendor") or blob.get("vendorProject")
                if vendor and str(vendor).strip():
                    vendor_counter[str(vendor).strip()] += 1
            except Exception:
                pass

    top_targeted_vendors: list[dict[str, Any]] = [
        {"vendor": v, "count": c}
        for v, c in vendor_counter.most_common(8)
    ]

    # 8. Top origin countries
    country_rows = (
        db.query(Indicator.country_code, func.count(Indicator.id))
        .filter(Indicator.country_code.isnot(None), Indicator.country_code != "")
        .group_by(Indicator.country_code)
        .order_by(func.count(Indicator.id).desc())
        .limit(8)
        .all()
    )
    top_origin_countries = [
        {"country_code": row[0], "count": row[1]} for row in country_rows
    ]

    # 9. Recent CRITICAL alerts
    critical_alerts = (
        db.query(Indicator)
        .filter(Indicator.severity_label == "CRITICAL")
        .order_by(Indicator.severity_score.desc(), Indicator.last_seen.desc())
        .limit(5)
        .all()
    )
    recent_critical_alerts = [
        IndicatorResponse.model_validate(alert).model_dump(mode="json")
        for alert in critical_alerts
    ]

    result = {
        "total_indicators": total_indicators,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "active_feeds_count": active_feeds_count,
        "ransomware_linked_count": ransomware_linked_count,
        "average_risk_score": average_risk_score,
        "severity_distribution": {
            "CRITICAL": critical_count,
            "HIGH": high_count,
            "MEDIUM": medium_count,
            "LOW": low_count,
        },
        "ioc_type_distribution": ioc_type_distribution,
        "source_distribution": source_distribution,
        "top_mitre_techniques": top_mitre_techniques,
        "top_targeted_vendors": top_targeted_vendors,
        "top_origin_countries": top_origin_countries,
        "recent_critical_alerts": recent_critical_alerts,
    }

    await set_cached(cache_key, result, ttl_seconds=300)
    return result
