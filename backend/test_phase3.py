"""
test_phase3.py
──────────────
Complete Phase 3 Verification Suite for ThreatLens.
Tests:
  1. Module imports and Python 3.14 compatibility
  2. Cache layer (in-memory TTL fallback & prefix invalidation)
  3. Ingestion sync & scoring calibration (ensuring 4 distinct severity tiers: CRITICAL, HIGH, MEDIUM, LOW)
  4. IoC type diversity (cve, ip, url, domain)
  5. SOC Analyst endpoints (GET /indicators, GET /lookup, POST /bulk-lookup, GET /export)
  6. Executive Analytics endpoint (GET /analytics/executive-summary)
"""

import asyncio
import json
import os
import sys

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

async def run_verification():
    print("==================================================================")
    print(" ThreatLens Phase 3 Verification Suite")
    print("==================================================================")

    # ── Step 1: Import check ───────────────────────────────────────────────────
    print("\n[Step 1] Checking imports and app initialization...")
    from app.main import app
    from app.database import Base, engine, SessionLocal
    from app.models.threat import Indicator, Feed, RawFeedEntry
    from app.services.cache import get_cached, set_cached, invalidate_prefix, init_cache
    from app.services.ingester import run_all_ingesters
    print("  ✓ All modules imported successfully on Python 3.14.")

    # ── Step 2: Cache Test ─────────────────────────────────────────────────────
    print("\n[Step 2] Testing resilient caching layer...")
    await init_cache()
    await set_cached("threatlens:test:key", {"status": "ok", "count": 42}, ttl_seconds=10)
    cached_val = await get_cached("threatlens:test:key")
    assert cached_val is not None and cached_val.get("count") == 42, f"Cache retrieval failed: {cached_val}"
    print("  ✓ Cache set/get succeeded:", cached_val)

    del_count = await invalidate_prefix("threatlens:test:")
    assert await get_cached("threatlens:test:key") is None, "Cache prefix invalidation failed"
    print(f"  ✓ Cache invalidate_prefix succeeded (purged {del_count} keys).")

    # ── Step 3: Database Reset & Ingestion Sync ────────────────────────────────
    print("\n[Step 3] Running fresh ingestion with calibrated scorer & URLhaus parser...")
    db = SessionLocal()
    # Reset indicators & raw entries to ensure fresh calibration without old stale state
    db.query(RawFeedEntry).delete()
    db.query(Indicator).delete()
    db.commit()

    summaries = await run_all_ingesters()
    for s in summaries:
        print(f"  → Ingested '{s.source}': fetched={s.fetched}, inserted={s.inserted}, updated={s.updated}, errors={s.errors}")

    total_indicators = db.query(Indicator).count()
    print(f"\n  Total Indicators in Database: {total_indicators}")
    assert total_indicators > 0, "No indicators were ingested!"

    # ── Step 4: Severity & IoC Type Distribution Verification ──────────────────
    print("\n[Step 4] Checking Severity & IoC Type Distribution...")
    severity_counts = {}
    for label in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        cnt = db.query(Indicator).filter(Indicator.severity_label == label).count()
        severity_counts[label] = cnt
        print(f"  • Severity {label:8s} : {cnt:3d} indicators")

    for label in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        assert severity_counts[label] > 0, f"Severity level '{label}' has 0 indicators! Calibration failed."
    print("  ✓ All 4 severity tiers (CRITICAL, HIGH, MEDIUM, LOW) successfully populated!")

    ioc_types = {}
    for r in db.query(Indicator.ioc_type).all():
        ioc_types[r[0]] = ioc_types.get(r[0], 0) + 1
    print("\n  • IoC Types in DB:")
    for t, c in sorted(ioc_types.items()):
        print(f"    - {t:8s} : {c:3d}")

    for expected_type in ["cve", "ip", "url", "domain"]:
        assert ioc_types.get(expected_type, 0) > 0, f"Expected ioc_type '{expected_type}' missing from DB!"
    print("  ✓ All required IoC types (cve, ip, url, domain) present in DB!")

    db.close()

    # ── Step 5: FastAPI TestClient for SOC & Executive Endpoints ───────────────
    print("\n[Step 5] Testing API Endpoints with httpx.AsyncClient...")
    import httpx
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:

        # 5.1 GET /api/v1/indicators
        resp = await client.get("/api/v1/indicators?page=1&page_size=10")
        assert resp.status_code == 200, f"GET /indicators failed: {resp.text}"
        data = resp.json()
        assert "items" in data and len(data["items"]) == 10
        assert data["total"] == total_indicators
        print(f"  ✓ GET /api/v1/indicators: OK (total={data['total']}, page={data['page']}, items={len(data['items'])})")

        # 5.2 Filter by severity
        resp_crit = await client.get("/api/v1/indicators?severity=CRITICAL&page_size=5")
        assert resp_crit.status_code == 200
        for item in resp_crit.json()["items"]:
            assert item["severity_label"] == "CRITICAL"
        print(f"  ✓ GET /api/v1/indicators?severity=CRITICAL: OK ({resp_crit.json()['total']} found)")

        # 5.3 Filter by ioc_type
        resp_url = await client.get("/api/v1/indicators?ioc_type=url&page_size=5")
        assert resp_url.status_code == 200
        for item in resp_url.json()["items"]:
            assert item["ioc_type"] == "url"
        print(f"  ✓ GET /api/v1/indicators?ioc_type=url: OK ({resp_url.json()['total']} found)")

        # 5.4 GET /api/v1/indicators/lookup
        sample_indicator = data["items"][0]
        sample_val = sample_indicator["value"]
        resp_lookup = await client.get(f"/api/v1/indicators/lookup?q={sample_val}")
        assert resp_lookup.status_code == 200, f"Lookup failed: {resp_lookup.text}"
        lookup_data = resp_lookup.json()
        assert "indicator" in lookup_data
        assert "score_breakdown" in lookup_data
        assert "related_indicators" in lookup_data
        print(f"  ✓ GET /api/v1/indicators/lookup?q={sample_val[:30]}: OK (breakdown total={lookup_data['score_breakdown']['total']}, label={lookup_data['score_breakdown']['label']})")

        # 5.5 POST /api/v1/indicators/bulk-lookup
        sample_val2 = data["items"][1]["value"]
        bulk_payload = {"indicators": [sample_val, sample_val2, "192.0.2.1-clean-test", "CLEAN-CVE-NONEXISTENT"]}
        resp_bulk = await client.post("/api/v1/indicators/bulk-lookup", json=bulk_payload)
        assert resp_bulk.status_code == 200
        bulk_data = resp_bulk.json()
        assert bulk_data["matched_count"] == 2
        assert bulk_data["unmatched_count"] == 2
        print(f"  ✓ POST /api/v1/indicators/bulk-lookup: OK (queried=4, matched={bulk_data['matched_count']}, unmatched={bulk_data['unmatched_count']})")

        # 5.6 GET /api/v1/indicators/export (CSV)
        resp_csv = await client.get("/api/v1/indicators/export?format=csv&severity=CRITICAL")
        assert resp_csv.status_code == 200
        assert "text/csv" in resp_csv.headers["content-type"]
        csv_lines = resp_csv.text.strip().splitlines()
        assert len(csv_lines) > 1
        assert "id,value,ioc_type,source" in csv_lines[0]
        print(f"  ✓ GET /api/v1/indicators/export?format=csv: OK ({len(csv_lines)-1} rows exported)")

        # 5.7 GET /api/v1/indicators/export (JSON)
        resp_json = await client.get("/api/v1/indicators/export?format=json&ioc_type=domain")
        assert resp_json.status_code == 200
        assert "application/json" in resp_json.headers["content-type"]
        json_data = resp_json.json()
        assert isinstance(json_data, list) and len(json_data) > 0
        print(f"  ✓ GET /api/v1/indicators/export?format=json: OK ({len(json_data)} domains exported)")

        # 5.8 GET /api/v1/analytics/executive-summary
        resp_exec = await client.get("/api/v1/analytics/executive-summary")
        assert resp_exec.status_code == 200
        exec_data = resp_exec.json()
        assert exec_data["total_indicators"] == total_indicators
        assert exec_data["critical_count"] > 0
        assert exec_data["high_count"] > 0
        assert exec_data["medium_count"] > 0
        assert exec_data["low_count"] > 0
        assert len(exec_data["top_mitre_techniques"]) > 0
        assert len(exec_data["top_targeted_vendors"]) > 0
        assert len(exec_data["top_origin_countries"]) > 0
        assert len(exec_data["recent_critical_alerts"]) > 0
        print("\n[Step 6] Executive Analytics Summary:")
        print(f"  • Total IoCs              : {exec_data['total_indicators']}")
        print(f"  • Critical / High / Med / Low : {exec_data['critical_count']} / {exec_data['high_count']} / {exec_data['medium_count']} / {exec_data['low_count']}")
        print(f"  • Active Feeds            : {exec_data['active_feeds_count']}")
        print(f"  • Ransomware Linked IoCs  : {exec_data['ransomware_linked_count']}")
        print(f"  • Average Risk Score      : {exec_data['average_risk_score']}")
        print("  • Top MITRE Techniques    :", [t["id"] for t in exec_data["top_mitre_techniques"][:4]])
        print("  • Top Vendors Exposed     :", [v["vendor"] for v in exec_data["top_targeted_vendors"][:4]])
        print("  • Top Origin Countries    :", [c["country_code"] for c in exec_data["top_origin_countries"][:4]])
        print(f"  • Recent Critical Alerts  : {len(exec_data['recent_critical_alerts'])} items")

    print("\n==================================================================")
    print(" ALL PHASE 3 VERIFICATIONS PASSED SUCCESSFULLY! ")
    print("==================================================================")

if __name__ == "__main__":
    asyncio.run(run_verification())
