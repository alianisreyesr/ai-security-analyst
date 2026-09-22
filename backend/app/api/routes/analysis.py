from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.analysis import AnalysisRunRequest, AnalysisRunResponse, ThreatSummary
from app.services.threat_analysis import analyze_latest_events

router = APIRouter(prefix="/api/v1/analysis", tags=["analysis"])


@router.post("/run", response_model=AnalysisRunResponse)
def run_analysis(
    payload: AnalysisRunRequest,
    db: Session = Depends(get_db),
) -> AnalysisRunResponse:
    threats = analyze_latest_events(db, limit=payload.limit)
    return AnalysisRunResponse(
        analyzed_event_limit=payload.limit,
        threats=[
            ThreatSummary(
                id=threat.id,
                rule_id=threat.rule_id,
                title=threat.title,
                source_ip=threat.source_ip,
                risk_score=threat.risk_score,
                severity=threat.severity,
                event_ids=threat.event_ids,
                evidence=threat.evidence,
            )
            for threat in threats
        ],
    )
