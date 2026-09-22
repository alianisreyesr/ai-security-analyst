from dataclasses import dataclass
from typing import Protocol

import httpx

from app.core.config import settings


class AIProviderError(RuntimeError):
    pass


@dataclass(slots=True)
class ProviderResponse:
    provider: str
    model: str
    content: str


class AIProvider(Protocol):
    name: str
    model: str

    def generate(self, messages: list[dict[str, str]]) -> ProviderResponse:
        ...


class DisabledProvider:
    name = "disabled"
    model = "none"

    def generate(self, messages: list[dict[str, str]]) -> ProviderResponse:
        del messages
        raise AIProviderError("AI provider is disabled.")


class CompatibleChatProvider:
    name = "compatible_chat"

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        timeout_seconds: float,
    ) -> None:
        if not base_url or not model:
            raise AIProviderError(
                "AI_BASE_URL and AI_MODEL are required for compatible_chat provider."
            )
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds

    def generate(self, messages: list[dict[str, str]]) -> ProviderResponse:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0,
            "response_format": {"type": "json_object"},
        }

        try:
            with httpx.Client(timeout=self.timeout_seconds) as client:
                response = client.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise AIProviderError("AI provider request failed.") from exc

        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise AIProviderError("AI provider returned an unsupported response shape.") from exc

        if not isinstance(content, str) or not content.strip():
            raise AIProviderError("AI provider returned empty content.")

        return ProviderResponse(
            provider=self.name,
            model=self.model,
            content=content,
        )


def get_ai_provider() -> AIProvider:
    provider_name = settings.ai_provider.strip().lower()

    if provider_name == "disabled":
        return DisabledProvider()

    if provider_name == "compatible_chat":
        return CompatibleChatProvider(
            base_url=settings.ai_base_url,
            api_key=settings.ai_api_key,
            model=settings.ai_model,
            timeout_seconds=settings.ai_timeout_seconds,
        )

    raise AIProviderError(f"Unsupported AI provider: {settings.ai_provider}")
