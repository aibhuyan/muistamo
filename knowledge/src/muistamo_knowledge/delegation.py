"""Asking the control plane to act for a person through their own agent (PR D).

HUMAN REVIEW REQUIRED (CLAUDE.md): a service-call credential and a bearer token. The request is
signed like the control plane's own calls to this service, but under a key derived for this
direction and tenant only (HMAC-SHA256 of "muistamo/v1 knowledge→control-plane\\n<tenant>" under
the tenant's service secret), with a single-use nonce. The control plane validates the person's
token again, decides at that moment whether their agent may act, and records it. The answer
carries a delegated Microsoft Graph token: it is used for one retrieval, never stored or logged.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

log = logging.getLogger(__name__)

DIRECTION = "muistamo/v1 knowledge→control-plane"
PATH = "/v1/internal/knowledge/delegations"
TIMEOUT = 4.0  # within the retrieval budget
MAX_RESPONSE = 64 * 1024
REFUSALS = {
    "token-invalid",
    "user-unlinked",
    "no-active-agent",
    "agent-ambiguous",
    "identity-not-ready",
    "exchange-refused",
    "evidence-unavailable",
}


def direction_key(secret: bytes, tenant: uuid.UUID) -> bytes:
    """The control plane's signature.DirectionKey for this direction and tenant."""
    return hmac.new(secret, f"{DIRECTION}\n{tenant}".encode(), hashlib.sha256).digest()


def sign(key: bytes, body: bytes, at: float | None = None) -> str:
    ts = str(int(time.time() if at is None else at))
    mac = hmac.new(key, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return f"t={ts},v1={mac}"


@dataclass(frozen=True)
class Delegation:
    """An issued delegation: who acts, for whom, within which packs, with which token."""

    instance: str
    agent_identity: uuid.UUID
    person: str
    packs: list[str]
    expires_at: datetime
    graph_token: str = field(repr=False)


@dataclass(frozen=True)
class Outcome:
    """A delegation, or why there is none (a refusal reason, not-configured or unavailable)."""

    delegation: Delegation | None
    reason: str | None = None


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


# Posts body to url with headers, returning (status, response body).
Transport = Callable[[str, bytes, dict[str, str], float], tuple[int, bytes]]


def _urllib(url: str, body: bytes, headers: dict[str, str], timeout: float) -> tuple[int, bytes]:
    # The URL is the operator's control plane, checked to be http(s) by DelegationClient.
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")  # noqa: S310
    # No redirects, and never an environment proxy: the body carries a bearer token.
    opener = urllib.request.build_opener(_NoRedirects(), urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, response.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code, exc.read(MAX_RESPONSE + 1)


class DelegationClient:
    """Signed delegation requests to one control plane."""

    def __init__(
        self,
        base_url: str,
        secret_for: Callable[[uuid.UUID], bytes | None],
        transport: Transport = _urllib,
    ) -> None:
        if not base_url.startswith(("https://", "http://")):
            raise ValueError("the control plane URL must be http(s)")
        self.url = base_url.rstrip("/") + PATH
        self._secret_for = secret_for
        self._transport = transport

    def request(self, tenant: uuid.UUID, user_token: str, instance: str | None = None) -> Outcome:
        """Ask for a delegation. Any failure is no delegation: fail closed, with its reason."""
        try:
            secret = self._secret_for(tenant)
        except Exception:  # noqa: BLE001 - no secret, no delegation
            log.warning("knowledge service secret unavailable", extra={"tenant": str(tenant)})
            return Outcome(None, "unavailable")
        if not secret:
            return Outcome(None, "not-configured")
        payload: dict[str, Any] = {"userToken": user_token, "nonce": secrets.token_hex(16)}
        if instance is not None:
            payload["instance"] = instance
        body = json.dumps(payload, separators=(",", ":")).encode()
        headers = {
            "Content-Type": "application/json",
            "X-Muistamo-Tenant": str(tenant),
            "X-Muistamo-Signature": sign(direction_key(secret, tenant), body),
        }
        try:
            status, raw = self._transport(self.url, body, headers, TIMEOUT)
        except Exception as exc:  # noqa: BLE001 - an unreachable control plane is no delegation
            log.warning(
                "delegation request failed",
                extra={"tenant": str(tenant), "error": type(exc).__name__},
            )
            return Outcome(None, "unavailable")
        if len(raw) > MAX_RESPONSE:
            return Outcome(None, "unavailable")
        try:
            answer = json.loads(raw)
        except ValueError:
            answer = None
        if status in (403, 503) and isinstance(answer, dict) and answer.get("reason") in REFUSALS:
            return Outcome(None, answer["reason"])
        if status == 501:
            return Outcome(None, "not-configured")
        if status != 200 or not isinstance(answer, dict):
            log.warning(
                "delegation answer refused", extra={"tenant": str(tenant), "status": status}
            )
            return Outcome(None, "unavailable")
        try:
            delegation = Delegation(
                instance=_text(answer["instance"]),
                agent_identity=uuid.UUID(_text(answer["agentIdentity"])),
                person=_text(answer["person"]),
                packs=[_text(p["name"]) for p in answer["packs"]],
                expires_at=datetime.fromisoformat(_text(answer["expiresAt"])),
                graph_token=_text(answer["graphToken"]),
            )
        except (KeyError, TypeError, ValueError):
            log.warning("delegation answer malformed", extra={"tenant": str(tenant)})
            return Outcome(None, "unavailable")
        if delegation.expires_at.tzinfo is None or delegation.expires_at <= datetime.now(
            delegation.expires_at.tzinfo
        ):
            return Outcome(None, "unavailable")
        return Outcome(delegation)


def _text(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("expected a non-empty string")
    return value
