from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.correlation import (
    CorrelationRunRequest,
    CorrelationRunResponse,
    SecurityCaseResponse,
)
from app.services.correlation import run_correlation

router = APIRouter(prefix="/api/v1/correlation", tags=["correlation"])


@router.post("/run", response_model=CorrelationRunResponse)
def correlate(
    payload: CorrelationRunRequest,
    db: Session = Depends(get_db),
) -> CorrelationRunResponse:
    cases = run_correlation(db, limit=payload.limit)

    return CorrelationRunResponse(
        cases=[
            SecurityCaseResponse(
                id=case.id,
                source_ip=case.source_ip,
                title=case.title,
                status=case.status,
                first_seen=case.first_seen,
                last_seen=case.last_seen,
                threat_ids=case.threat_ids,
                event_ids=case.event_ids,
                evidence=case.evidence,
            )
            for case in cases
        ]
    )
