import logging
from collections import defaultdict, deque
from threading import Lock
from time import monotonic, perf_counter
from uuid import uuid4

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from app.core.config import settings

logger = logging.getLogger("ai_security_analyst.audit")


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid4())
        request.state.request_id = request_id
        started = perf_counter()

        response = await call_next(request)

        duration_ms = round((perf_counter() - started) * 1000, 2)
        principal = getattr(request.state, "principal", None)
        actor = getattr(principal, "name", "anonymous")
        role = getattr(principal, "role", "anonymous")

        logger.info(
            "request_complete request_id=%s method=%s path=%s status=%s "
            "duration_ms=%s actor=%s role=%s",
            request_id,
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
            actor,
            role,
        )
        response.headers["X-Request-ID"] = request_id
        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        raw_length = request.headers.get("content-length")
        if raw_length:
            try:
                content_length = int(raw_length)
            except ValueError:
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid Content-Length header."},
                )
            if content_length > settings.max_request_bytes:
                return JSONResponse(
                    status_code=413,
                    content={"detail": "Request body exceeds configured maximum."},
                )
        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app) -> None:
        super().__init__(app)
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    async def dispatch(self, request: Request, call_next) -> Response:
        if (
            not settings.rate_limit_enabled
            or request.url.path == "/health"
            or settings.rate_limit_requests_per_minute <= 0
        ):
            return await call_next(request)

        client_host = request.client.host if request.client else "unknown"
        now = monotonic()
        cutoff = now - 60.0

        with self._lock:
            bucket = self._requests[client_host]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            if len(bucket) >= settings.rate_limit_requests_per_minute:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded."},
                    headers={"Retry-After": "60"},
                )
            bucket.append(now)

        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        if settings.app_env.lower() == "production":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response
