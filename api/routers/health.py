"""Liveness and readiness.

``/healthz`` answers "is this process alive" and must stay dependency-free so a
crash-looping database can't take the container down with it. ``/readyz``
answers "can this process actually do work", checks every dependency, and is
what the compose healthcheck and Kubernetes readiness probe use.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Response, status

from core.config import BARE_VERSION, Settings, get_settings

router = APIRouter(tags=["health"])


@router.get("/healthz", summary="Liveness probe")
def healthz() -> dict[str, str]:
    return {"status": "ok", "version": BARE_VERSION}


@router.get("/readyz", summary="Readiness probe")
def readyz(response: Response) -> dict[str, Any]:
    """Report the API's own dependencies, and the sandbox as advisory context.

    Only ``checks`` gates readiness. The sandbox is reported separately and
    deliberately does not: the API has no Docker socket by design — spawning
    containers is the worker's job — so a sandbox problem is not something
    taking the API out of the load balancer would fix, and doing so would turn
    a degraded worker into a total outage.
    """
    settings = get_settings()
    checks = {
        "database": _check_database(settings),
        "redis": _check_redis(settings),
        "object_store": _check_object_store(settings),
    }
    ready = all(check["healthy"] for check in checks.values())
    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "ready": ready,
        "version": BARE_VERSION,
        "checks": checks,
        "advisory": {"sandbox": _check_sandbox(settings)},
    }


def _result(healthy: bool, detail: str = "") -> dict[str, Any]:
    return {"healthy": healthy, "detail": detail}


def _check_database(settings: Settings) -> dict[str, Any]:
    try:
        from sqlalchemy import create_engine, text

        engine = create_engine(settings.database_url, pool_pre_ping=True)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
    except Exception as exc:
        return _result(False, str(exc)[:300])
    return _result(True)


def _check_redis(settings: Settings) -> dict[str, Any]:
    try:
        import redis

        client = redis.Redis.from_url(settings.redis_url, socket_connect_timeout=3)
        client.ping()
        client.close()
    except Exception as exc:
        return _result(False, str(exc)[:300])
    return _result(True)


def _check_object_store(settings: Settings) -> dict[str, Any]:
    try:
        import boto3
        from botocore.config import Config

        client = boto3.client(
            "s3",
            endpoint_url=settings.s3_endpoint_url,
            aws_access_key_id=settings.s3_access_key,
            aws_secret_access_key=settings.s3_secret_key,
            region_name=settings.s3_region,
            config=Config(connect_timeout=3, read_timeout=3, retries={"max_attempts": 1}),
        )
        client.list_buckets()
    except Exception as exc:
        return _result(False, str(exc)[:300])
    return _result(True)


def _check_sandbox(settings: Settings) -> dict[str, Any]:
    """Advisory only — see :func:`readyz`.

    In the reference deployment this reports unhealthy from inside the API
    container because no Docker socket is mounted there, which is correct and
    intended. M1 replaces it with the worker's own heartbeat, which is the
    component whose sandbox health actually matters.
    """
    try:
        from core.sandbox import driver_from_settings

        driver = driver_from_settings()
        health = driver.health()
        driver.close()
    except Exception as exc:
        return _result(False, str(exc)[:300])
    detail = health.detail
    if health.warnings:
        detail = f"{detail} warnings={list(health.warnings)}"
    return _result(health.healthy, detail)
