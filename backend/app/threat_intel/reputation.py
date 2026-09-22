from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from app.core.config import settings


class ReputationProviderError(RuntimeError):
    pass


@dataclass(slots=True)
class ReputationResult:
    provider: str
    verdict: str
    score: int | None
    details: dict[str, Any]


class ReputationProvider(Protocol):
    name: str

    def lookup(self, ip_address: str) -> ReputationResult:
        ...


class DisabledReputationProvider:
    name = "disabled"

    def lookup(self, ip_address: str) -> ReputationResult:
        del ip_address
        raise ReputationProviderError("IP reputation provider is disabled.")


class CompatibleReputationProvider:
    name = "compatible_http"

    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout_seconds: float,
    ) -> None:
        if not base_url:
            raise ReputationProviderError(
                "REPUTATION_BASE_URL is required for compatible_http provider."
            )
        self.base_url = base_url
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds

    def lookup(self, ip_address: str) -> ReputationResult:
        headers: dict[str, str] = {"Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            with httpx.Client(timeout=self.timeout_seconds) as client:
                response = client.get(
                    self.base_url,
                    params={"ip": ip_address},
                    headers=headers,
                )
                response.raise_for_status()
                payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ReputationProviderError("IP reputation request failed.") from exc

        verdict = payload.get("verdict")
        score = payload.get("score")
        details = payload.get("details", {})

        if not isinstance(verdict, str):
            raise ReputationProviderError(
                "IP reputation provider returned an unsupported verdict."
            )
        if score is not None and not isinstance(score, int):
            raise ReputationProviderError(
                "IP reputation provider returned an unsupported score."
            )
        if not isinstance(details, dict):
            raise ReputationProviderError(
                "IP reputation provider returned unsupported details."
            )

        return ReputationResult(
            provider=self.name,
            verdict=verdict,
            score=score,
            details=details,
        )


def get_reputation_provider() -> ReputationProvider:
    provider_name = settings.reputation_provider.strip().lower()

    if provider_name == "disabled":
        return DisabledReputationProvider()

    if provider_name == "compatible_http":
        return CompatibleReputationProvider(
            base_url=settings.reputation_base_url,
            api_key=settings.reputation_api_key,
            timeout_seconds=settings.reputation_timeout_seconds,
        )

    raise ReputationProviderError(
        f"Unsupported reputation provider: {settings.reputation_provider}"
    )
