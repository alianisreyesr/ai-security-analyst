from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.ai_analysis import AnalystOutput, ThreatAnalysisResponse
from app.services.ai_analysis import analyze_threat, get_threat_or_none

router = APIRouter(prefix="/api/v1/threats", tags=["threat-analysis"])


@router.post(
    "/{threat_id}/analysis",
    response_model=ThreatAnalysisResponse,
)
def create_threat_analysis(
    threat_id: int,
    db: Session = Depends(get_db),
) -> ThreatAnalysisResponse:
    threat = get_threat_or_none(db, threat_id)
    if threat is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat not found.",
        )

    analysis = analyze_threat(db, threat)

    return ThreatAnalysisResponse(
        id=analysis.id,
        threat_id=analysis.threat_id,
        status=analysis.status,
        provider=analysis.provider,
        model=analysis.model,
        template_version=analysis.template_version,
        output=AnalystOutput(
            summary=analysis.summary,
            observed_evidence=analysis.observed_evidence,
            interpretation=analysis.interpretation,
            investigation_steps=analysis.investigation_steps,
            caveats=analysis.caveats,
            confidence=analysis.confidence,
        ),
    )
