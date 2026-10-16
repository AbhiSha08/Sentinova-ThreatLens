from app.routers.feeds import router as feeds_router
from app.routers.indicators import router as indicators_router
from app.routers.analytics import router as analytics_router

__all__ = ["feeds_router", "indicators_router", "analytics_router"]
