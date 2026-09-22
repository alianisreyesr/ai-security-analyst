from dataclasses import dataclass
from hmac import compare_digest
from typing import Literal

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security.api_key import APIKeyHeader

from app.core.config import settings

Role = Literal["analyst", "admin"]


@dataclass(frozen=True, slots=True)
class Principal:
    name: str
    role: Role


api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def validate_security_configuration() -> None:
    if settings.auth_enabled and (
        not settings.analyst_api_key or not settings.admin_api_key
    ):
        raise RuntimeError(
            "AUTH_ENABLED requires both ANALYST_API_KEY and ADMIN_API_KEY."
        )

    if settings.app_env.lower() == "production" and not settings.auth_enabled:
        raise RuntimeError("Authentication must be enabled in production.")


def get_principal(
    request: Request,
    api_key: str | None = Security(api_key_header),
) -> Principal:
    if not settings.auth_enabled:
        principal = Principal(name="local-development", role="admin")
        request.state.principal = principal
        return principal

    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required.",
        )

    if settings.admin_api_key and compare_digest(api_key, settings.admin_api_key):
        principal = Principal(name="admin-api-key", role="admin")
    elif settings.analyst_api_key and compare_digest(api_key, settings.analyst_api_key):
        principal = Principal(name="analyst-api-key", role="analyst")
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
        )

    request.state.principal = principal
    return principal


def require_role(*allowed_roles: Role):
    def dependency(
        principal: Principal = Depends(get_principal),
    ) -> Principal:
        if principal.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role for this operation.",
            )
        return principal

    return dependency


require_analyst = require_role("analyst", "admin")
require_admin = require_role("admin")
