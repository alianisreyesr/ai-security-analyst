from ipaddress import ip_address

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.threat import Threat
from app.schemas.threat_intel import ReputationResponse
from app.services.reputation import lookup_ip_reputation

router = APIRouter(prefix="/api/v1/threat-intel", tags=["threat-intelligence"])


@router.get("/reputation/{ip_value}", response_model=ReputationResponse)
def reputation_lookup(
    ip_value: str,
    db: Session = Depends(get_db),
) -> ReputationResponse:
    try:
        ip_address(ip_value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid IP address.",
        ) from exc

    return lookup_ip_reputation(db, ip_value)


@router.get("/threats/{threat_id}/reputation", response_model=ReputationResponse)
def threat_reputation(
    threat_id: int,
    db: Session = Depends(get_db),
) -> ReputationResponse:
    threat = db.scalar(select(Threat).where(Threat.id == threat_id))
    if threat is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat not found.",
        )
    if threat.source_ip is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Threat has no source IP.",
        )

    return lookup_ip_reputation(db, threat.source_ip)
