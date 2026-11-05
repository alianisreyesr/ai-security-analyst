import json
from collections.abc import Callable

import httpx
import pytest

from app.ai.providers import (
    AIProviderError,
    CompatibleChatProvider,
    DisabledProvider,
    get_ai_provider,
)
from app.core.config import settings
from app.threat_intel.reputation import (
    CompatibleReputationProvider,
    DisabledReputationProvider,
    ReputationProviderError,
    get_reputation_provider,
)

Handler = Callable[[httpx.Request], httpx.Response]


@pytest.fixture
def mock_http(monkeypatch: pytest.MonkeyPatch) -> Callable[[Handler], None]:
    real_client = httpx.Client

    def install(handler: Handler) -> None:
        def factory(**kwargs: object) -> httpx.Client:
            return real_client(transport=httpx.MockTransport(handler), **kwargs)

        monkeypatch.setattr(httpx, "Client", factory)

    return install


def _chat(**kwargs: object) -> CompatibleChatProvider:
    params: dict[str, object] = {
        "base_url": "https://llm.example/v1/",
        "api_key": "synthetic-key",
        "model": "synthetic-model",
        "timeout_seconds": 2.0,
    }
    params.update(kwargs)
    return CompatibleChatProvider(**params)  # type: ignore[arg-type]


def _completion(content: object) -> httpx.Response:
    return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})


# --- AI chat provider -------------------------------------------------------


def test_chat_provider_sends_expected_request(mock_http) -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = json.loads(request.content)
        return _completion("{}")

    mock_http(handler)

    result = _chat().generate([{"role": "user", "content": "hi"}])

    assert (result.provider, result.model, result.content) == (
        "compatible_chat",
        "synthetic-model",
        "{}",
    )
    assert seen["url"] == "https://llm.example/v1/chat/completions"
    assert seen["auth"] == "Bearer synthetic-key"
    body = seen["body"]
    assert isinstance(body, dict)
    assert body["temperature"] == 0
    assert body["messages"] == [{"role": "user", "content": "hi"}]


def test_chat_provider_omits_authorization_without_key(mock_http) -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        return _completion("ok")

    mock_http(handler)

    _chat(api_key="").generate([])

    assert seen["auth"] is None


@pytest.mark.parametrize(
    "handler",
    [
        lambda request: httpx.Response(500, json={}),
        lambda request: httpx.Response(200, content=b"not json"),
    ],
    ids=["http-error", "invalid-json"],
)
def test_chat_provider_wraps_transport_errors(mock_http, handler: Handler) -> None:
    mock_http(handler)

    with pytest.raises(AIProviderError, match="request failed"):
        _chat().generate([])


def test_chat_provider_wraps_connection_errors(mock_http) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timeout", request=request)

    mock_http(handler)

    with pytest.raises(AIProviderError, match="request failed"):
        _chat().generate([])


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (httpx.Response(200, json={"choices": []}), "unsupported response shape"),
        (httpx.Response(200, json={"nope": 1}), "unsupported response shape"),
        (httpx.Response(200, json=[1]), "unsupported response shape"),
        (_completion(None), "empty content"),
        (_completion("   "), "empty content"),
    ],
)
def test_chat_provider_rejects_bad_payloads(mock_http, response, message: str) -> None:
    mock_http(lambda request: response)

    with pytest.raises(AIProviderError, match=message):
        _chat().generate([])


def test_chat_provider_requires_url_and_model() -> None:
    with pytest.raises(AIProviderError):
        _chat(base_url="")
    with pytest.raises(AIProviderError):
        _chat(model="")


def test_get_ai_provider_selection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "ai_provider", " Disabled ")
    assert isinstance(get_ai_provider(), DisabledProvider)

    monkeypatch.setattr(settings, "ai_provider", "compatible_chat")
    monkeypatch.setattr(settings, "ai_base_url", "https://llm.example/v1")
    monkeypatch.setattr(settings, "ai_model", "m")
    provider = get_ai_provider()
    assert isinstance(provider, CompatibleChatProvider)
    assert provider.base_url == "https://llm.example/v1"

    monkeypatch.setattr(settings, "ai_provider", "other")
    with pytest.raises(AIProviderError, match="Unsupported"):
        get_ai_provider()


def test_disabled_ai_provider_raises() -> None:
    with pytest.raises(AIProviderError, match="disabled"):
        DisabledProvider().generate([])


# --- Reputation provider ----------------------------------------------------


def _rep(**kwargs: object) -> CompatibleReputationProvider:
    params: dict[str, object] = {
        "base_url": "https://rep.example/lookup",
        "api_key": "synthetic-key",
        "timeout_seconds": 2.0,
    }
    params.update(kwargs)
    return CompatibleReputationProvider(**params)  # type: ignore[arg-type]


def test_reputation_provider_parses_valid_response(mock_http) -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["ip"] = request.url.params["ip"]
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(
            200, json={"verdict": "malicious", "score": 91, "details": {"k": "v"}}
        )

    mock_http(handler)

    result = _rep().lookup("203.0.113.5")

    assert (result.provider, result.verdict, result.score) == (
        "compatible_http",
        "malicious",
        91,
    )
    assert result.details == {"k": "v"}
    assert seen == {"ip": "203.0.113.5", "auth": "Bearer synthetic-key"}


def test_reputation_provider_defaults_for_optional_fields(mock_http) -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"verdict": "unknown"})

    mock_http(handler)

    result = _rep(api_key="").lookup("203.0.113.5")

    assert result.score is None
    assert result.details == {}
    assert seen["auth"] is None


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(503, json={}),
        httpx.Response(200, content=b"<html>"),
    ],
    ids=["http-error", "invalid-json"],
)
def test_reputation_provider_wraps_errors(mock_http, response) -> None:
    mock_http(lambda request: response)

    with pytest.raises(ReputationProviderError, match="request failed"):
        _rep().lookup("203.0.113.5")


def test_reputation_provider_wraps_connection_errors(mock_http) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    mock_http(handler)

    with pytest.raises(ReputationProviderError, match="request failed"):
        _rep().lookup("203.0.113.5")


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"verdict": 3}, "verdict"),
        ({"verdict": "ok", "score": "high"}, "score"),
        ({"verdict": "ok", "details": [1]}, "details"),
        ([1, 2], "unsupported"),
        ("text", "unsupported"),
    ],
)
def test_reputation_provider_rejects_bad_payloads(
    mock_http, payload: object, message: str
) -> None:
    mock_http(lambda request: httpx.Response(200, json=payload))

    with pytest.raises(ReputationProviderError, match=message):
        _rep().lookup("203.0.113.5")


def test_reputation_provider_requires_base_url() -> None:
    with pytest.raises(ReputationProviderError, match="REPUTATION_BASE_URL"):
        _rep(base_url="")


def test_get_reputation_provider_selection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "reputation_provider", "disabled")
    provider = get_reputation_provider()
    assert isinstance(provider, DisabledReputationProvider)
    with pytest.raises(ReputationProviderError, match="disabled"):
        provider.lookup("203.0.113.5")

    monkeypatch.setattr(settings, "reputation_provider", "compatible_http")
    monkeypatch.setattr(settings, "reputation_base_url", "https://rep.example")
    assert isinstance(get_reputation_provider(), CompatibleReputationProvider)

    monkeypatch.setattr(settings, "reputation_provider", "nope")
    with pytest.raises(ReputationProviderError, match="Unsupported"):
        get_reputation_provider()
