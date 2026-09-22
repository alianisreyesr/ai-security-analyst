from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.security_event import SecurityEvent
from app.schemas.security_event import SecurityEventAccepted, SecurityEventCreate

router = APIRouter(prefix="/api/v1/events", tags=["events"])


@router.post(
    "",
    response_model=SecurityEventAccepted,
    status_code=status.HTTP_201_CREATED,
)
def create_event(
    payload: SecurityEventCreate,
    db: Session = Depends(get_db),
) -> SecurityEventAccepted:
    data = payload.model_dump()
    for field in ("source_ip", "destination_ip"):
        if data[field] is not None:
            data[field] = str(data[field])

    event = SecurityEvent(**data)

    try:
        db.add(event)
        db.commit()
        db.refresh(event)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to persist security event.",
        ) from exc

    return SecurityEventAccepted(id=event.id)
