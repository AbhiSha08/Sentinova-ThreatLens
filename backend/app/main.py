from contextlib import asynccontextmanager
from typing import AsyncIterator
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import Base, engine
from app.routers import analytics_router, feeds_router, indicators_router
from app.services import (
    close_cache,
    init_cache,
    scheduler_shutdown,
    scheduler_start,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # ── Startup ────────────────────────────────────────────────────────────────
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables verified / created.")

    # Resilient caching layer initialization
    await init_cache()

    # Periodic background feed scheduler
    scheduler_start(interval_minutes=60)

    yield

    # ── Shutdown ───────────────────────────────────────────────────────────────
    scheduler_shutdown()
    await close_cache()
    logger.info("Sentinova ThreatLens shutting down.")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=(
        "Sentinova ThreatLens Cyber Threat Intelligence aggregation and visualization platform. "
        "Aggregates IoCs from CISA KEV, URLhaus, AbuseIPDB, OTX, and more."
    ),
    docs_url=f"{settings.API_V1_STR}/docs",
    redoc_url=f"{settings.API_V1_STR}/redoc",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ────────────────────────────────────────────────────────────────────
app.include_router(feeds_router, prefix=settings.API_V1_STR)
app.include_router(indicators_router, prefix=settings.API_V1_STR)
app.include_router(analytics_router, prefix=settings.API_V1_STR)


# ── Health ─────────────────────────────────────────────────────────────────────
@app.get(f"{settings.API_V1_STR}/health", tags=["Health"])
async def health_check() -> dict:
    return {
        "status": "ok",
        "project": settings.PROJECT_NAME,
        "version": settings.VERSION,
    }
