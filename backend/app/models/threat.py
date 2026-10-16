from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Indicator(Base):
    """
    Atomic Indicator of Compromise (IoC) normalised from one or more
    threat-intelligence sources.

    Severity ladder  : LOW → MEDIUM → HIGH → CRITICAL
    Supported types  : ip | domain | url | sha256 | md5 | email | cve
    """

    __tablename__ = "indicators"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    value: Mapped[str] = mapped_column(
        String(512), unique=True, nullable=False, index=True
    )
    ioc_type: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )
    source: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )

    # ── Severity ───────────────────────────────────────────────────────────────
    severity_score: Mapped[float] = mapped_column(
        Float, default=0.0, nullable=False, index=True
    )
    severity_label: Mapped[str] = mapped_column(
        String(16), default="LOW", nullable=False, index=True
    )
    confidence: Mapped[int] = mapped_column(Integer, default=50, nullable=False)

    # ── Classification ─────────────────────────────────────────────────────────
    threat_type: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    tags: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # ── MITRE ATT&CK ──────────────────────────────────────────────────────────
    mitre_techniques: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True,
        comment="Comma-separated MITRE ATT&CK technique IDs, e.g. T1190,T1071.001"
    )

    # ── Geo / Network context ──────────────────────────────────────────────────
    country_code: Mapped[Optional[str]] = mapped_column(String(4), nullable=True)
    asn: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # ── Lifecycle ──────────────────────────────────────────────────────────────
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    raw_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )

    # ── Relationships ──────────────────────────────────────────────────────────
    raw_entries: Mapped[list["RawFeedEntry"]] = relationship(
        "RawFeedEntry", back_populates="indicator", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_indicators_type_source", "ioc_type", "source"),
        Index("ix_indicators_severity_score_label", "severity_score", "severity_label"),
        Index("ix_indicators_active_last_seen", "is_active", "last_seen"),
    )

    def __repr__(self) -> str:
        return (
            f"<Indicator id={self.id} type={self.ioc_type!r} "
            f"value={self.value!r} severity={self.severity_label}>"
        )


class Feed(Base):
    """
    Represents a configured threat-intelligence feed/source.

    Tracks ingestion health so the scheduler can surface stale or
    broken feeds in the dashboard.
    """

    __tablename__ = "feeds"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    name: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    url: Mapped[str] = mapped_column(String(512), nullable=False)
    feed_type: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # ── Ingestion health ───────────────────────────────────────────────────────
    last_fetched_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_fetch_status: Mapped[Optional[str]] = mapped_column(
        String(16), nullable=True
    )
    last_error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    indicators_ingested: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )

    # ── Relationships ──────────────────────────────────────────────────────────
    raw_entries: Mapped[list["RawFeedEntry"]] = relationship(
        "RawFeedEntry", back_populates="feed", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Feed id={self.id} name={self.name!r} enabled={self.is_enabled}>"


class RawFeedEntry(Base):
    """
    Immutable audit log of every raw record pulled from a feed before
    normalisation. Enables replay / re-enrichment without re-fetching.
    """

    __tablename__ = "raw_feed_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    feed_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("feeds.id", ondelete="CASCADE"), nullable=False, index=True
    )
    indicator_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("indicators.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    raw_json: Mapped[str] = mapped_column(Text, nullable=False)
    source_ref: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    is_processed: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False, index=True
    )
    processing_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False, index=True
    )
    processed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ── Relationships ──────────────────────────────────────────────────────────
    feed: Mapped["Feed"] = relationship("Feed", back_populates="raw_entries")
    indicator: Mapped[Optional["Indicator"]] = relationship(
        "Indicator", back_populates="raw_entries"
    )

    __table_args__ = (
        Index("ix_raw_entries_feed_processed", "feed_id", "is_processed"),
        Index("ix_raw_entries_fetched_at", "fetched_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<RawFeedEntry id={self.id} feed_id={self.feed_id} "
            f"processed={self.is_processed}>"
        )
