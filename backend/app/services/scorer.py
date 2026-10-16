"""
app/services/scorer.py
─────────────────────
Deterministic, explainable risk scoring engine for Sentinova ThreatLens.

Composite score formula (0.0 – 100.0):
  40% → Source Reliability / Feed Base Weight (max 40 pts)
  35% → Context & Threat-Type Multiplier (max 35 pts)
  25% → Recency Decay (max 25 pts)

Severity thresholds:
  CRITICAL  ≥ 85.0
  HIGH      65.0 – 84.9
  MEDIUM    40.0 – 64.9
  LOW       < 40.0
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# ── Source base weights (max 100) ──────────────────────────────────────────────
_SOURCE_BASE: dict[str, float] = {
    "CISA_KEV":  95.0,
    "URLhaus":   80.0,
    "AbuseIPDB": 70.0,
    "OTX":       75.0,
}

# ── Threat-type context bonus points (0 to 100 scale, multiplied by 0.35) ──────
# Yields up to 35 points towards the total score
_THREAT_BONUS: list[tuple[set[str], float]] = [
    ({"ransomware"},                                                   100.0),
    ({"c2", "command_and_control"},                                     85.0),
    ({"botnet", "malware_download", "payload"},                         65.0),
    ({"exploit", "known_exploited"},                                    55.0),
    ({"phishing", "malware", "trojan", "backdoor"},                     45.0),
    ({"brute_force", "ssh"},                                            25.0),
    ({"scanner", "telnet"},                                             15.0),
    ({"suspicious", "recon", "low_risk"},                                5.0),
]

# ── MITRE technique mapping ───────────────────────────────────────────────────
_MITRE_MAP: list[tuple[set[str], list[str]]] = [
    ({"kev", "known_exploited", "exploit"},              ["T1190"]),
    ({"malware_download", "payload"},                    ["T1105"]),
    ({"c2", "command_and_control", "botnet"},            ["T1071.001", "T1095"]),
    ({"ransomware"},                                     ["T1486", "T1490"]),
    ({"brute_force", "ssh"},                             ["T1110", "T1110.001"]),
    ({"scanner", "telnet"},                              ["T1595", "T1110"]),
    ({"phishing"},                                       ["T1566", "T1566.002"]),
    ({"trojan", "backdoor"},                             ["T1059", "T1543"]),
]

_DECAY_DAYS = 45.0          # linear decay window in days
_DECAY_HOURS_FULL = 24.0    # full recency score within 24 hours


@dataclass
class ScoreBreakdown:
    """Transparent breakdown of every score component for auditability."""
    source_component: float = 0.0
    context_component: float = 0.0
    recency_component: float = 0.0
    total: float = 0.0
    label: str = "LOW"
    mitre_techniques: list[str] = field(default_factory=list)
    explanation: str = ""


def _normalise_tags(tags: Optional[str]) -> set[str]:
    """Lower-case, strip, split comma/space-delimited tag string."""
    if not tags:
        return set()
    return {t.strip().lower() for t in tags.replace(" ", ",").split(",") if t.strip()}


def _source_weight(source: str, abuse_confidence: int = 0) -> float:
    key = source.strip()
    if key == "AbuseIPDB":
        if abuse_confidence > 0:
            return float(min(100, max(10, abuse_confidence)))
        return 70.0
    return _SOURCE_BASE.get(key, 50.0)


def _context_bonus(tags: set[str], threat_type: Optional[str], is_kev: bool) -> float:
    effective_tags = set(tags)
    if threat_type:
        effective_tags.update(threat_type.lower().replace(" ", "_").split(","))

    # Check ransomware first (highest severity)
    if "ransomware" in effective_tags:
        return 100.0

    if is_kev:
        effective_tags.add("known_exploited")

    for keyword_set, bonus in _THREAT_BONUS:
        if effective_tags & keyword_set:
            return bonus
    return 10.0 if is_kev else 0.0


def _recency_score(last_seen: Optional[datetime]) -> float:
    if last_seen is None:
        return 0.5

    now = datetime.now(timezone.utc)
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)

    age_hours = (now - last_seen).total_seconds() / 3600.0
    if age_hours < 0:
        age_hours = 0.0

    if age_hours <= _DECAY_HOURS_FULL:
        return 1.0
    age_days = age_hours / 24.0
    if age_days >= _DECAY_DAYS:
        return 0.1
    decay = 1.0 - (age_days / _DECAY_DAYS)
    return max(0.1, decay)


def _label_from_score(score: float) -> str:
    if score >= 85.0:
        return "CRITICAL"
    if score >= 65.0:
        return "HIGH"
    if score >= 40.0:
        return "MEDIUM"
    return "LOW"


def map_mitre_techniques(
    tags: Optional[str],
    threat_type: Optional[str],
    is_kev: bool = False,
) -> list[str]:
    """Return a de-duplicated list of MITRE ATT&CK technique IDs."""
    effective_tags = _normalise_tags(tags)
    if threat_type:
        effective_tags.update(threat_type.lower().replace(" ", "_").split(","))
    if is_kev:
        effective_tags.add("kev")

    techniques: list[str] = []
    for keyword_set, tech_ids in _MITRE_MAP:
        if effective_tags & keyword_set:
            for tid in tech_ids:
                if tid not in techniques:
                    techniques.append(tid)
    return techniques


def calculate_score(
    source: str,
    tags: Optional[str] = None,
    threat_type: Optional[str] = None,
    last_seen: Optional[datetime] = None,
    abuse_confidence: int = 0,
    is_kev: bool = False,
) -> ScoreBreakdown:
    """
    Calculate composite severity score and return a full breakdown.
    Composite score formula (0.0 – 100.0):
      40% Source Reliability (raw_source * 0.40)
      35% Context & Threat-Type (raw_context * 0.35)
      25% Recency Decay (raw_recency * 25.0)
    """
    tag_set = _normalise_tags(tags)

    raw_source = _source_weight(source, abuse_confidence)
    raw_context = _context_bonus(tag_set, threat_type, is_kev)
    raw_recency = _recency_score(last_seen)

    # If it's a CISA KEV:
    # 1. If known ransomware link -> guarantee CRITICAL (>= 85.0)
    # 2. If recent dateAdded / observation (recency > 0.8) -> boost context so it reaches >= 85.0 (CRITICAL)
    # 3. Older KEV without ransomware -> lands in HIGH (65.0 – 84.9)
    if is_kev:
        if "ransomware" in tag_set:
            raw_context = 100.0
            if raw_recency < 0.5:
                raw_recency = 0.5
        elif raw_recency >= 0.8:
            raw_context = max(raw_context, 75.0)
        else:
            raw_context = min(raw_context, 55.0)

    # Weighted combination
    source_component = raw_source * 0.40
    context_component = raw_context * 0.35
    recency_component = raw_recency * 25.0

    total = min(100.0, source_component + context_component + recency_component)

    if is_kev:
        if "ransomware" in tag_set or raw_recency >= 0.8:
            total = max(85.0, total)
        else:
            total = min(84.5, max(65.0, total))

    label = _label_from_score(total)
    techniques = map_mitre_techniques(tags, threat_type, is_kev)

    explanation = (
        f"source={source_component:.1f}/40 "
        f"(base={raw_source:.0f}) "
        f"| context={context_component:.1f}/35 "
        f"(bonus={raw_context:.0f}) "
        f"| recency={recency_component:.1f}/25 "
        f"(decay={raw_recency:.2f}) "
        f"→ total={total:.1f} [{label}]"
    )
    logger.debug("Score: %s", explanation)

    return ScoreBreakdown(
        source_component=round(source_component, 2),
        context_component=round(context_component, 2),
        recency_component=round(recency_component, 2),
        total=round(total, 2),
        label=label,
        mitre_techniques=techniques,
        explanation=explanation,
    )
