from fastapi import FastAPI

from app.api.routes.ai_analysis import router as ai_analysis_router
from app.api.routes.analysis import router as analysis_router
from app.api.routes.events import router as events_router
from app.api.routes.health import router as health_router
from app.api.routes.ingestion import router as ingestion_router
from app.api.routes.threat_intel import router as threat_intel_router
from app.api.routes.threats import router as threats_router
from app.core.config import settings

app = FastAPI(
    title=settings.app_name,
    version="0.4.0",
    description=(
        "Explainable security-event ingestion and analysis API. "
        "Deterministic evidence remains authoritative."
    ),
)

app.include_router(health_router)
app.include_router(events_router)
app.include_router(ingestion_router)
app.include_router(analysis_router)
app.include_router(ai_analysis_router)
app.include_router(threats_router)
app.include_router(threat_intel_router)
