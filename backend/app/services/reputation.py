from datetime import UTC, datetime, timedelta
from ipaddress import ip_address

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.ip_reputation_cache import IpReputationCache
from app.schemas.threat_intel import ReputationResponse
from app.threat_intel.reputation import (
    DisabledReputationProvider,
    ReputationProvider,
    ReputationProviderError,
    get_reputation_provider,
)


def _ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def lookup_ip_reputation(
    db: Session,
    ip_value: str,
    provider: ReputationProvider | None = None,
) -> ReputationResponse:
    parsed_ip = ip_address(ip_value)
    normalized_ip = str(parsed_ip)

    if not parsed_ip.is_global:
        return ReputationResponse(
            ip_address=normalized_ip,
            status="not_applicable",
            scope="non_global",
            provider="local_scope",
            cached=False,
            verdict=None,
            details={
                "reason": "External reputation lookups are skipped for non-global addresses."
            },
        )

    try:
        selected_provider = provider or get_reputation_provider()
    except ReputationProviderError:
        selected_provider = DisabledReputationProvider()

    provider_name = getattr(selected_provider, "name", "unknown")
    if provider_name == "disabled":
        return ReputationResponse(
            ip_address=normalized_ip,
            status="unsupported",
            scope="global",
            provider=provider_name,
            cached=False,
            details={"reason": "Reputation provider is disabled."},
        )

    cache_key = f"{provider_name}:{normalized_ip}"
    now = datetime.now(UTC)
    cached = db.scalar(
        select(IpReputationCache).where(IpReputationCache.cache_key == cache_key)
    )
    if cached is not None and _ensure_utc(cached.expires_at) > now:
        return ReputationResponse(
            ip_address=normalized_ip,
            status="ok",
            scope="global",
            provider=cached.provider,
            cached=True,
            verdict=cached.verdict,
            score=cached.score,
            details=cached.details,
            retrieved_at=_ensure_utc(cached.retrieved_at),
        )

    try:
        result = selected_provider.lookup(normalized_ip)
    except ReputationProviderError:
        return ReputationResponse(
            ip_address=normalized_ip,
            status="unavailable",
            scope="global",
            provider=provider_name,
            cached=False,
            details={"reason": "Reputation provider lookup failed."},
        )

    expires_at = now + timedelta(seconds=settings.reputation_cache_ttl_seconds)

    if cached is None:
        cached = IpReputationCache(
            cache_key=cache_key,
            ip_address=normalized_ip,
            provider=result.provider,
            verdict=result.verdict,
            score=result.score,
            details=result.details,
            retrieved_at=now,
            expires_at=expires_at,
        )
        db.add(cached)
    else:
        cached.provider = result.provider
        cached.verdict = result.verdict
        cached.score = result.score
        cached.details = result.details
        cached.retrieved_at = now
        cached.expires_at = expires_at

    db.commit()
    db.refresh(cached)

    return ReputationResponse(
        ip_address=normalized_ip,
        status="ok",
        scope="global",
        provider=result.provider,
        cached=False,
        verdict=result.verdict,
        score=result.score,
        details=result.details,
        retrieved_at=now,
    )
