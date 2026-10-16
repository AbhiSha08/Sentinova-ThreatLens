from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ── Enums / Literals ────────────────────────────────────────────────────────────

IocType = Literal["ip", "domain", "url", "sha256", "md5", "email", "cve", "hash"]
SeverityLabel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
FetchStatus = Literal["success", "error", "partial"]


# ── Indicator Schemas ────────────────────────────────────────────────────────────

class IndicatorBase(BaseModel):
    value: str = Field(..., max_length=512, description="Raw IoC value")
    ioc_type: str = Field(..., description="Indicator type (e.g. ip, cve, url, domain, hash)")
    source: str = Field(..., max_length=64, description="Originating feed name")
    severity_score: float = Field(default=0.0, ge=0.0, le=100.0)
    severity_label: SeverityLabel = Field(default="LOW")
    confidence: int = Field(default=50, ge=0, le=100, description="0–100 confidence score")
    threat_type: str | None = Field(
        default=None, max_length=128, description="e.g. malware, phishing, botnet"
    )
    tags: str | None = Field(
        default=None,
        description="Comma-separated tags stored as plain text",
    )
    mitre_techniques: str | None = Field(
        default=None,
        description="Comma-separated MITRE ATT&CK technique IDs",
    )
    country_code: str | None = Field(default=None, max_length=4)
    asn: str | None = Field(default=None, max_length=64)
    is_active: bool = Field(default=True)
    raw_data: str | None = Field(default=None, description="Original JSON blob from source")

    @field_validator("value")
    @classmethod
    def value_must_not_be_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Indicator value must not be blank")
        return v.strip()

    @field_validator("severity_label", mode="before")
    @classmethod
    def normalise_severity_label(cls, v: str) -> str:
        return v.upper()


class IndicatorCreate(IndicatorBase):
    pass


class IndicatorUpdate(BaseModel):
    severity_score: float | None = Field(default=None, ge=0.0, le=100.0)
    severity_label: SeverityLabel | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    threat_type: str | None = Field(default=None, max_length=128)
    tags: str | None = None
    mitre_techniques: str | None = None
    country_code: str | None = Field(default=None, max_length=4)
    asn: str | None = Field(default=None, max_length=64)
    is_active: bool | None = None
    raw_data: str | None = None
    last_seen: datetime | None = None


class IndicatorOut(IndicatorBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime


IndicatorResponse = IndicatorOut


# ── Feed Schemas ─────────────────────────────────────────────────────────────────

class FeedBase(BaseModel):
    name: str = Field(..., max_length=64, description="Unique human-readable feed name")
    url: str = Field(..., max_length=512)
    feed_type: str = Field(
        ..., max_length=32, description="e.g. CISA_KEV, URLhaus, AbuseIPDB, OTX"
    )
    is_enabled: bool = Field(default=True)


class FeedCreate(FeedBase):
    pass


class FeedUpdate(BaseModel):
    url: str | None = Field(default=None, max_length=512)
    feed_type: str | None = Field(default=None, max_length=32)
    is_enabled: bool | None = None


class FeedOut(FeedBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    last_fetched_at: datetime | None
    last_fetch_status: FetchStatus | None
    last_error_message: str | None
    indicators_ingested: int
    created_at: datetime
    updated_at: datetime


# ── RawFeedEntry Schemas ─────────────────────────────────────────────────────────

class RawFeedEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    feed_id: int
    indicator_id: int | None
    raw_json: str
    source_ref: str | None
    is_processed: bool
    processing_error: str | None
    fetched_at: datetime
    processed_at: datetime | None


# ── Pagination / Envelope ────────────────────────────────────────────────────────

class PaginatedIndicators(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[IndicatorOut]


class PaginatedFeeds(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[FeedOut]
