import logging

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.routes.ai_analysis import router as ai_analysis_router
from app.api.routes.analysis import router as analysis_router
from app.api.routes.analytics import router as analytics_router
from app.api.routes.correlation import router as correlation_router
from app.api.routes.events import router as events_router
from app.api.routes.health import router as health_router
from app.api.routes.ingestion import router as ingestion_router
from app.api.routes.reviews import router as reviews_router
from app.api.routes.threat_intel import router as threat_intel_router
from app.api.routes.threats import router as threats_router
from app.core.config import settings
from app.middleware.security import (
    RateLimitMiddleware,
    RequestContextMiddleware,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
)
from app.security.auth import require_analyst, validate_security_configuration

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

validate_security_configuration()

docs_enabled = settings.app_env.lower() != "production" or settings.enable_api_docs

app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    description=(
        "Explainable security-event ingestion and analysis API. "
        "Deterministic evidence remains authoritative."
    ),
    docs_url="/docs" if docs_enabled else None,
    redoc_url="/redoc" if docs_enabled else None,
    openapi_url="/openapi.json" if docs_enabled else None,
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestSizeLimitMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(RequestContextMiddleware)

if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "X-API-Key", "X-Request-ID"],
    )

if settings.trusted_hosts:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.trusted_hosts,
    )

protected = [Depends(require_analyst)]

app.include_router(health_router)
app.include_router(events_router, dependencies=protected)
app.include_router(ingestion_router, dependencies=protected)
app.include_router(analysis_router, dependencies=protected)
app.include_router(ai_analysis_router, dependencies=protected)
app.include_router(threats_router, dependencies=protected)
app.include_router(threat_intel_router, dependencies=protected)
app.include_router(analytics_router, dependencies=protected)
app.include_router(correlation_router, dependencies=protected)
app.include_router(reviews_router, dependencies=protected)
