"""
app/services/cache.py
─────────────────────
Resilient caching layer for ThreatLens.

Supports Redis via `redis.asyncio` with seamless, zero-crash graceful
degradation to an in-memory TTL dictionary cache when Redis is unavailable.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Optional

import redis.asyncio as aioredis
from app.config import settings

logger = logging.getLogger(__name__)

# Module-level state
_redis_client: Optional[aioredis.Redis] = None
_using_fallback: bool = False
_in_memory_store: dict[str, tuple[str, float]] = {}  # key -> (serialized_json, expire_timestamp)
_lock = asyncio.Lock()


async def init_cache() -> None:
    """
    Attempt to connect to Redis. If Redis is unreachable or raises an error,
    gracefully fall back to the in-memory TTL cache with a single startup notice.
    """
    global _redis_client, _using_fallback
    try:
        client = aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
            socket_connect_timeout=1.5,
            socket_timeout=1.5,
        )
        # Ping with short timeout to check availability
        await asyncio.wait_for(client.ping(), timeout=1.5)
        _redis_client = client
        _using_fallback = False
        logger.info("Connected to Redis cache at %s", settings.REDIS_URL)
    except Exception as exc:
        _redis_client = None
        _using_fallback = True
        logger.warning("Redis unavailable — using in-memory TTL cache fallback (%s)", exc)


async def close_cache() -> None:
    """Close Redis connection pool if active."""
    global _redis_client
    if _redis_client is not None:
        try:
            await _redis_client.close()
        except Exception:
            pass
        _redis_client = None


async def get_cached(key: str) -> Optional[Any]:
    """
    Retrieve and deserialise cached value by key.
    Returns None on cache miss or expiration.
    """
    global _redis_client, _using_fallback

    # 1. Try Redis if active
    if _redis_client is not None and not _using_fallback:
        try:
            raw = await _redis_client.get(key)
            if raw is not None:
                return json.loads(raw)
            return None
        except Exception as exc:
            logger.debug("Redis GET error for key %s (%s) — falling back to memory", key, exc)
            _using_fallback = True

    # 2. In-memory TTL fallback
    async with _lock:
        item = _in_memory_store.get(key)
        if item is None:
            return None
        val_str, exp = item
        if time.time() > exp:
            _in_memory_store.pop(key, None)
            return None
        try:
            return json.loads(val_str)
        except Exception:
            return val_str


async def set_cached(key: str, value: Any, ttl_seconds: int = 300) -> None:
    """
    Serialize value to JSON and store with TTL in seconds.
    """
    global _redis_client, _using_fallback

    try:
        val_str = json.dumps(value, default=str)
    except Exception as exc:
        logger.error("Failed to JSON-serialize cache value for key %s: %s", key, exc)
        return

    # 1. Try Redis
    if _redis_client is not None and not _using_fallback:
        try:
            await _redis_client.set(key, val_str, ex=ttl_seconds)
            return
        except Exception as exc:
            logger.debug("Redis SET error for key %s (%s) — using memory", key, exc)
            _using_fallback = True

    # 2. In-memory fallback
    async with _lock:
        expire_at = time.time() + ttl_seconds
        _in_memory_store[key] = (val_str, expire_at)


async def invalidate_prefix(prefix: str) -> int:
    """
    Invalidate all keys matching the given prefix.
    Returns the count of invalidated keys.
    """
    global _redis_client, _using_fallback
    count = 0

    # 1. Try Redis
    if _redis_client is not None and not _using_fallback:
        try:
            keys = []
            async for k in _redis_client.scan_iter(f"{prefix}*"):
                keys.append(k)
            if keys:
                count = await _redis_client.delete(*keys)
        except Exception as exc:
            logger.debug("Redis invalidate_prefix error (%s)", exc)
            _using_fallback = True

    # 2. In-memory cleanup
    async with _lock:
        to_del = [k for k in _in_memory_store if k.startswith(prefix)]
        for k in to_del:
            _in_memory_store.pop(k, None)
        count = max(count, len(to_del))

    logger.debug("Invalidated %d cache keys matching prefix '%s'", count, prefix)
    return count
