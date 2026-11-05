import ipaddress
import logging
import re
from collections import deque
from threading import Lock
from time import monotonic, perf_counter
from uuid import uuid4

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import settings

logger = logging.getLogger("ai_security_analyst.audit")

_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_RATE_LIMIT_WINDOW_SECONDS = 60.0

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def _safe_request_id(value: str | None) -> str:
    """Accept a client supplied request id only if it is short and log-safe."""
    if value and _REQUEST_ID_PATTERN.fullmatch(value):
        return value
    return str(uuid4())


def _trusted_networks() -> list[IPNetwork]:
    networks: list[IPNetwork] = []
    for entry in settings.trusted_proxy_list:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            logger.warning("Ignoring invalid TRUSTED_PROXIES entry: %r", entry)
    return networks


def _is_trusted(host: str, networks: list[IPNetwork]) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(address in network for network in networks)


def resolve_client_ip(request: Request) -> str:
    """Return the client IP, honouring X-Forwarded-For only behind a trusted proxy.

    The socket peer must be listed in TRUSTED_PROXIES; the header is then walked
    from the right and the first address that is not itself a trusted proxy wins,
    so clients cannot spoof their identity by prepending entries.
    """
    peer = request.client.host if request.client else "unknown"
    networks = _trusted_networks()
    if not networks or not _is_trusted(peer, networks):
        return peer

    forwarded = request.headers.get("x-forwarded-for", "")
    candidates = [part.strip() for part in forwarded.split(",") if part.strip()]
    for candidate in reversed(candidates):
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            return peer
        if not _is_trusted(candidate, networks):
            return candidate
    return peer


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = _safe_request_id(request.headers.get("X-Request-ID"))
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


class _BodyTooLarge(Exception):
    pass


class RequestSizeLimitMiddleware:
    """Pure ASGI middleware enforcing the body limit, including chunked uploads."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        limit = settings.max_request_bytes
        headers = dict(scope.get("headers") or [])
        raw_length = headers.get(b"content-length")
        if raw_length:
            try:
                content_length = int(raw_length)
            except ValueError:
                await self._reject(scope, receive, send, 400, "Invalid Content-Length header.")
                return
            if content_length > limit:
                await self._reject(
                    scope, receive, send, 413, "Request body exceeds configured maximum."
                )
                return

        received = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise _BodyTooLarge
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _BodyTooLarge:
            if response_started:
                raise
            await self._reject(
                scope, receive, send, 413, "Request body exceeds configured maximum."
            )

    @staticmethod
    async def _reject(
        scope: Scope, receive: Receive, send: Send, status_code: int, detail: str
    ) -> None:
        response = JSONResponse(status_code=status_code, content={"detail": detail})
        await response(scope, receive, send)


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app) -> None:
        super().__init__(app)
        self._requests: dict[str, deque[float]] = {}
        self._lock = Lock()
        self._last_sweep = monotonic()

    def _sweep(self, cutoff: float, now: float) -> None:
        """Drop idle clients so the dictionary cannot grow without bound."""
        if now - self._last_sweep < _RATE_LIMIT_WINDOW_SECONDS:
            return
        self._last_sweep = now
        stale = [
            key
            for key, bucket in self._requests.items()
            if not bucket or bucket[-1] <= cutoff
        ]
        for key in stale:
            del self._requests[key]

    async def dispatch(self, request: Request, call_next) -> Response:
        if (
            not settings.rate_limit_enabled
            or request.url.path == "/health"
            or settings.rate_limit_requests_per_minute <= 0
        ):
            return await call_next(request)

        client_host = resolve_client_ip(request)
        now = monotonic()
        cutoff = now - _RATE_LIMIT_WINDOW_SECONDS

        with self._lock:
            self._sweep(cutoff, now)
            bucket = self._requests.setdefault(client_host, deque())
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
