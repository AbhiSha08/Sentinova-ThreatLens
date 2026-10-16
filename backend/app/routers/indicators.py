"""
app/routers/indicators.py
─────────────────────────
SOC Analyst tactical IOC router for ThreatLens.

Endpoints:
  • GET  /indicators               Paginated, filterable, sortable IOC table
  • GET  /indicators/lookup        Enrichment lookup (?q=) with score explanation & related IOCs
  • POST /indicators/bulk-lookup   Batch triage of up to 50 IOCs (matched vs unmatched)
  • GET  /indicators/export        SIEM export (JSON or downloadable CSV)
"""

from __future__ import annotations

import csv
import io
import math
from typing import Any, List, Optional, Union

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import or_, desc, asc
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.threat import Indicator
from app.schemas.threat import IndicatorResponse
from app.services.cache import get_cached, set_cached
from app.services.scorer import calculate_score

router = APIRouter(prefix="/indicators", tags=["Indicators (SOC View)"])


# ── Schemas for Router Responses ───────────────────────────────────────────────

class PaginatedIndicatorsResponse(BaseModel):
    total: int
    page: int
    page_size: int
    total_pages: int
    items: list[IndicatorResponse]


class BulkLookupRequest(BaseModel):
    indicators: list[str] = Field(..., max_length=50, description="List of raw IOC values (max 50)")


class BulkLookupResponse(BaseModel):
    total_queried: int
    matched_count: int
    unmatched_count: int
    matched: list[IndicatorResponse]
    unmatched: list[str]


class LookupDetailResponse(BaseModel):
    indicator: IndicatorResponse
    score_breakdown: dict[str, Any]
    related_indicators: list[IndicatorResponse]


# ── 1. Fast IOC Enrichment Lookup ─────────────────────────────────────────────

@router.get(
    "/lookup",
    summary="Fast IOC enrichment lookup with score explanation",
    response_model=LookupDetailResponse,
)
async def lookup_indicator(
    q: str = Query(..., min_length=1, description="Exact or prefix IOC value (IP, CVE, URL, domain)"),
    db: Session = Depends(get_db),
) -> Any:
    cache_key = f"threatlens:lookup:{q.strip().lower()}"
    cached = await get_cached(cache_key)
    if cached is not None:
        return cached

    val = q.strip()
    # Exact match first
    indicator = db.query(Indicator).filter(Indicator.value == val).first()
    if not indicator:
        # Case-insensitive / prefix fallback for CVEs, IPs or domains
        indicator = db.query(Indicator).filter(Indicator.value.ilike(f"{val}%")).first()

    if not indicator:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Indicator '{val}' not found in ThreatLens threat database.",
        )

    # Recalculate transparent score breakdown
    is_kev = bool(indicator.source == "CISA_KEV" or (indicator.tags and "kev" in indicator.tags))
    breakdown = calculate_score(
        source=indicator.source,
        tags=indicator.tags,
        threat_type=indicator.threat_type,
        last_seen=indicator.last_seen,
        abuse_confidence=indicator.confidence if indicator.source == "AbuseIPDB" else 0,
        is_kev=is_kev,
    )

    score_data = {
        "source_component": breakdown.source_component,
        "context_component": breakdown.context_component,
        "recency_component": breakdown.recency_component,
        "total": breakdown.total,
        "label": breakdown.label,
        "mitre_techniques": breakdown.mitre_techniques,
        "explanation": breakdown.explanation,
    }

    # Find related indicators sharing same MITRE techniques or source
    related: list[Indicator] = []
    if indicator.mitre_techniques:
        first_tech = indicator.mitre_techniques.split(",")[0].strip()
        related = (
            db.query(Indicator)
            .filter(
                Indicator.id != indicator.id,
                Indicator.mitre_techniques.ilike(f"%{first_tech}%"),
            )
            .limit(5)
            .all()
        )
    if not related:
        related = (
            db.query(Indicator)
            .filter(
                Indicator.id != indicator.id,
                Indicator.source == indicator.source,
            )
            .limit(5)
            .all()
        )

    result = {
        "indicator": IndicatorResponse.model_validate(indicator).model_dump(mode="json"),
        "score_breakdown": score_data,
        "related_indicators": [
            IndicatorResponse.model_validate(r).model_dump(mode="json") for r in related
        ],
    }

    await set_cached(cache_key, result, ttl_seconds=300)
    return result


# ── 2. Bulk Lookup Triage ──────────────────────────────────────────────────────

@router.post(
    "/bulk-lookup",
    summary="Batch triage up to 50 raw IOC strings",
    response_model=BulkLookupResponse,
)
def bulk_lookup(
    body: Union[BulkLookupRequest, list[str]],
    db: Session = Depends(get_db),
) -> BulkLookupResponse:
    raw_list: list[str] = body.indicators if isinstance(body, BulkLookupRequest) else body
    if len(raw_list) > 50:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum 50 indicators allowed per bulk-lookup request.",
        )

    cleaned = [s.strip() for s in raw_list if s.strip()]
    matched_records = db.query(Indicator).filter(Indicator.value.in_(cleaned)).all()

    matched_values = {m.value for m in matched_records}
    unmatched = [v for v in cleaned if v not in matched_values]

    return BulkLookupResponse(
        total_queried=len(cleaned),
        matched_count=len(matched_records),
        unmatched_count=len(unmatched),
        matched=[IndicatorResponse.model_validate(m) for m in matched_records],
        unmatched=unmatched,
    )


# ── 3. SIEM Export (JSON or CSV) ──────────────────────────────────────────────

@router.get(
    "/export",
    summary="Export filtered indicators as JSON or downloadable CSV",
)
def export_indicators(
    format: str = Query("json", pattern="^(json|csv)$", description="Export format: json or csv"),
    ioc_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    active_only: bool = Query(True),
    search: Optional[str] = Query(None),
    db: Session = Depends(get_db),
) -> Response:
    query = db.query(Indicator)

    if active_only:
        query = query.filter(Indicator.is_active == True)  # noqa: E712
    if ioc_type:
        query = query.filter(Indicator.ioc_type == ioc_type.lower())
    if severity:
        query = query.filter(Indicator.severity_label == severity.upper())
    if source:
        query = query.filter(Indicator.source == source)
    if search:
        pattern = f"%{search.strip()}%"
        query = query.filter(
            or_(
                Indicator.value.ilike(pattern),
                Indicator.tags.ilike(pattern),
                Indicator.threat_type.ilike(pattern),
            )
        )

    records = query.order_by(desc(Indicator.severity_score)).all()

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "id", "value", "ioc_type", "source", "severity_score", "severity_label",
            "confidence", "threat_type", "tags", "mitre_techniques", "country_code",
            "asn", "is_active", "first_seen", "last_seen",
        ])
        for r in records:
            writer.writerow([
                r.id,
                r.value,
                r.ioc_type,
                r.source,
                r.severity_score,
                r.severity_label,
                r.confidence,
                r.threat_type or "",
                r.tags or "",
                r.mitre_techniques or "",
                r.country_code or "",
                r.asn or "",
                r.is_active,
                r.first_seen.isoformat() if r.first_seen else "",
                r.last_seen.isoformat() if r.last_seen else "",
            ])
        csv_content = output.getvalue()
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=threatlens_indicators.csv"},
        )

    # JSON export
    data = [IndicatorResponse.model_validate(r).model_dump(mode="json") for r in records]
    import json
    return Response(
        content=json.dumps(data, indent=2),
        media_type="application/json",
    )


# ── 4. Filterable & Paginated IOC Table ───────────────────────────────────────

@router.get(
    "",
    summary="Paginated, filterable, and sortable IOC list",
    response_model=PaginatedIndicatorsResponse,
)
def list_indicators(
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(25, ge=1, le=100, description="Items per page (max 100)"),
    ioc_type: Optional[str] = Query(None, description="e.g. ip, cve, url, domain, hash"),
    severity: Optional[str] = Query(None, description="CRITICAL, HIGH, MEDIUM, LOW"),
    source: Optional[str] = Query(None, description="Originating feed name"),
    mitre_technique: Optional[str] = Query(None, description="e.g. T1190, T1071.001"),
    search: Optional[str] = Query(None, description="Substring search on value, tags, or threat_type"),
    active_only: bool = Query(True, description="Filter for active indicators only"),
    sort_by: str = Query("severity_score", description="Field to sort by: severity_score, last_seen, confidence"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort direction: asc or desc"),
    db: Session = Depends(get_db),
) -> PaginatedIndicatorsResponse:
    query = db.query(Indicator)

    if active_only:
        query = query.filter(Indicator.is_active == True)  # noqa: E712
    if ioc_type:
        query = query.filter(Indicator.ioc_type == ioc_type.lower())
    if severity:
        query = query.filter(Indicator.severity_label == severity.upper())
    if source:
        query = query.filter(Indicator.source == source)
    if mitre_technique:
        query = query.filter(Indicator.mitre_techniques.ilike(f"%{mitre_technique.strip()}%"))
    if search:
        pattern = f"%{search.strip()}%"
        query = query.filter(
            or_(
                Indicator.value.ilike(pattern),
                Indicator.tags.ilike(pattern),
                Indicator.threat_type.ilike(pattern),
            )
        )

    total = query.count()
    total_pages = max(1, math.ceil(total / page_size))

    # Sorting
    sort_col = getattr(Indicator, sort_by, Indicator.severity_score)
    if sort_order == "desc":
        query = query.order_by(desc(sort_col))
    else:
        query = query.order_by(asc(sort_col))

    offset = (page - 1) * page_size
    items = query.offset(offset).limit(page_size).all()

    return PaginatedIndicatorsResponse(
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        items=[IndicatorResponse.model_validate(it) for it in items],
    )
