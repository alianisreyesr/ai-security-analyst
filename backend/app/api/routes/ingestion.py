from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.ingestion.batch import BatchParseError, parse_batch
from app.models.security_event import SecurityEvent
from app.schemas.ingestion import BatchIngestRequest, BatchIngestResponse

router = APIRouter(prefix="/api/v1/ingest", tags=["ingestion"])


@router.post("/batch", response_model=BatchIngestResponse)
def ingest_batch(
    payload: BatchIngestRequest,
    db: Session = Depends(get_db),
) -> BatchIngestResponse:
    if len(payload.content) > settings.max_batch_content_chars:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=(
                "Batch content exceeds configured maximum of "
                f"{settings.max_batch_content_chars} characters."
            ),
        )

    try:
        parsed, errors = parse_batch(payload.format, payload.content)
    except BatchParseError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    records: list[SecurityEvent] = []
    for event in parsed:
        data = event.model_dump()
        for field in ("source_ip", "destination_ip"):
            if data[field] is not None:
                data[field] = str(data[field])
        records.append(SecurityEvent(**data))

    try:
        db.add_all(records)
        db.commit()
        for record in records:
            db.refresh(record)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to persist ingested events.",
        ) from exc

    return BatchIngestResponse(
        accepted=len(records),
        rejected=len(errors),
        event_ids=[record.id for record in records],
        errors=errors,
    )
