from fastapi import FastAPI

from app.api.routes.events import router as events_router
from app.api.routes.health import router as health_router
from app.api.routes.ingestion import router as ingestion_router
from app.core.config import settings

app = FastAPI(
    title=settings.app_name,
    version="0.2.0",
    description=(
        "Explainable security-event ingestion and analysis API. "
        "Deterministic evidence remains authoritative."
    ),
)

app.include_router(health_router)
app.include_router(events_router)
app.include_router(ingestion_router)
