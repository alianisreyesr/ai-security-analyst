from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.threat import Threat
from app.models.threat_review import ThreatReview
from app.schemas.reviews import (
    ThreatReviewCreate,
    ThreatReviewListResponse,
    ThreatReviewResponse,
)

router = APIRouter(prefix="/api/v1/threats", tags=["threat-reviews"])


@router.post(
    "/{threat_id}/reviews",
    response_model=ThreatReviewResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_review(
    threat_id: int,
    payload: ThreatReviewCreate,
    db: Session = Depends(get_db),
) -> ThreatReviewResponse:
    threat = db.scalar(select(Threat).where(Threat.id == threat_id))
    if threat is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat not found.",
        )

    review = ThreatReview(
        threat_id=threat.id,
        disposition=payload.disposition,
        rationale=payload.rationale,
        reviewer=payload.reviewer,
    )
    db.add(review)
    db.commit()
    db.refresh(review)

    return ThreatReviewResponse(
        id=review.id,
        threat_id=review.threat_id,
        disposition=review.disposition,
        rationale=review.rationale,
        reviewer=review.reviewer,
        created_at=review.created_at,
    )


@router.get(
    "/{threat_id}/reviews",
    response_model=ThreatReviewListResponse,
)
def list_reviews(
    threat_id: int,
    db: Session = Depends(get_db),
) -> ThreatReviewListResponse:
    threat = db.scalar(select(Threat).where(Threat.id == threat_id))
    if threat is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat not found.",
        )

    reviews = list(
        db.scalars(
            select(ThreatReview)
            .where(ThreatReview.threat_id == threat.id)
            .order_by(ThreatReview.created_at.asc(), ThreatReview.id.asc())
        )
    )

    return ThreatReviewListResponse(
        items=[
            ThreatReviewResponse(
                id=review.id,
                threat_id=review.threat_id,
                disposition=review.disposition,
                rationale=review.rationale,
                reviewer=review.reviewer,
                created_at=review.created_at,
            )
            for review in reviews
        ]
    )
