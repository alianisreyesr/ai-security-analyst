from sqlalchemy.orm import Session

from app.services.reputation import lookup_ip_reputation
from app.threat_intel.reputation import ReputationProviderError, ReputationResult


class CountingProvider:
    name = "fake-reputation"

    def __init__(self) -> None:
        self.calls = 0

    def lookup(self, ip_address: str) -> ReputationResult:
        self.calls += 1
        return ReputationResult(
            provider=self.name,
            verdict="suspicious",
            score=73,
            details={"ip": ip_address, "source": "synthetic"},
        )


class FailingProvider:
    name = "failing-reputation"

    def lookup(self, ip_address: str) -> ReputationResult:
        del ip_address
        raise ReputationProviderError("synthetic timeout")


def test_reputation_cache_prevents_repeat_lookup(db_session: Session) -> None:
    provider = CountingProvider()

    first = lookup_ip_reputation(db_session, "8.8.8.8", provider=provider)
    second = lookup_ip_reputation(db_session, "8.8.8.8", provider=provider)

    assert first.status == "ok"
    assert first.cached is False
    assert second.status == "ok"
    assert second.cached is True
    assert provider.calls == 1


def test_non_global_ip_skips_provider(db_session: Session) -> None:
    provider = CountingProvider()

    result = lookup_ip_reputation(db_session, "10.0.0.5", provider=provider)

    assert result.status == "not_applicable"
    assert result.scope == "non_global"
    assert provider.calls == 0


def test_provider_failure_is_non_blocking(db_session: Session) -> None:
    result = lookup_ip_reputation(
        db_session,
        "8.8.4.4",
        provider=FailingProvider(),
    )

    assert result.status == "unavailable"
    assert result.cached is False
    assert result.provider == "failing-reputation"
