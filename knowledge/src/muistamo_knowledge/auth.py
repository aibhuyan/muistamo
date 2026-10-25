"""Who is calling. Fails closed: any doubt refuses the request.

Until real authentication exists (Keycloak, PRD section 9), the only resolver besides deny_all
trusts development headers, and only when MUISTAMO_INSECURE_DEV_TENANT_HEADER=true.
"""

from __future__ import annotations

from collections.abc import Callable
from uuid import UUID

from fastapi import Request


class Unauthenticated(Exception):
    pass


Resolver = Callable[[Request], tuple[UUID, str]]


def deny_all(_: Request) -> tuple[UUID, str]:
    raise Unauthenticated("no authentication configured")


def insecure_dev_headers(request: Request) -> tuple[UUID, str]:
    """Development only: anyone who can reach the service can claim any tenant and person."""
    try:
        tenant = UUID(request.headers.get("X-Muistamo-Tenant", ""))
    except ValueError as exc:
        raise Unauthenticated("missing or malformed X-Muistamo-Tenant") from exc
    actor = request.headers.get("X-Muistamo-Actor", "")
    if not actor:
        raise Unauthenticated("missing X-Muistamo-Actor")
    return tenant, "dev:" + actor
