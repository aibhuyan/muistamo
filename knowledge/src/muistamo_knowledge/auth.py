"""Who is calling. Fails closed: any doubt refuses the request.

Until real authentication exists (Keycloak, PRD section 9), the only resolver besides deny_all
trusts development headers, and only when MUISTAMO_INSECURE_DEV_TENANT_HEADER=true.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from uuid import UUID


class Unauthenticated(Exception):
    pass


# Resolvers read request headers, so REST and MCP requests resolve callers identically.
Resolver = Callable[[Mapping[str, str]], tuple[UUID, str]]


def deny_all(_: Mapping[str, str]) -> tuple[UUID, str]:
    raise Unauthenticated("no authentication configured")


def _header(headers: Mapping[str, str], name: str) -> str:
    # HTTP header names are case-insensitive; not every mapping handed to us is.
    lowered = name.lower()
    return next((v for k, v in headers.items() if k.lower() == lowered), "")


def insecure_dev_headers(headers: Mapping[str, str]) -> tuple[UUID, str]:
    """Development only: anyone who can reach the service can claim any tenant and person."""
    try:
        tenant = UUID(_header(headers, "X-Muistamo-Tenant"))
    except ValueError as exc:
        raise Unauthenticated("missing or malformed X-Muistamo-Tenant") from exc
    actor = _header(headers, "X-Muistamo-Actor")
    if not actor:
        raise Unauthenticated("missing X-Muistamo-Actor")
    return tenant, "dev:" + actor
