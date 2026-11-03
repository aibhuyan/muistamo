"""Adversarial suite: service-call signatures bind method and path (docs/signature-plan.md).

HUMAN REVIEW REQUIRED (CLAUDE.md): cryptographic signing. Never skip or weaken.
"""

from __future__ import annotations

import json
import time

import pytest
from muistamo_knowledge import auth
from muistamo_knowledge.auth import Unauthenticated

pytestmark = pytest.mark.authz

SECRET = b"mks_test-only-not-a-secret-0123456789abcdef"
EXPIRE = "/v1/knowledge/internal/leaver-reviews/entra-leaver:r/expire"
# The control plane's signature.SignRequest gives the same bytes (internal/signature/v2_test.go).
V2_VECTOR = "06f5c6495ddb43878640ea4dbc89ff130059f4c155f9a8808832406e5dbacb44"


def headers(value: str) -> dict[str, str]:
    return {"X-Muistamo-Signature": value}


def test_v2_matches_the_control_planes_vector() -> None:
    assert auth.sign(SECRET, b"", 1700000000, method="POST", path=EXPIRE).endswith(
        ",v2=" + V2_VECTOR
    )


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", EXPIRE.replace("entra-leaver:r", "entra-leaver:s")),  # another review
        ("POST", EXPIRE.replace("/expire", "/cancel")),  # another call on it
        ("PUT", EXPIRE),  # another method
    ],
)
def test_a_signature_verifies_only_for_its_own_method_and_path(method, path) -> None:
    signed = headers(auth.sign(SECRET, b"", method="POST", path=EXPIRE))
    auth.verify_service(signed, b"", SECRET, "POST", EXPIRE)
    with pytest.raises(Unauthenticated):
        auth.verify_service(signed, b"", SECRET, method, path)


def test_a_v1_only_signature_is_refused_unless_the_overlap_is_on() -> None:
    v1_only = auth.sign(SECRET, b"", method="POST", path=EXPIRE).rsplit(",v2=", 1)[0]
    with pytest.raises(Unauthenticated):
        auth.verify_service(headers(v1_only), b"", SECRET, "POST", EXPIRE)
    auth.verify_service(headers(v1_only), b"", SECRET, "POST", EXPIRE, accept_v1=True)
    # Even with the overlap on, a present v2 must match: v1 is never a fallback for a bad v2.
    bad_v2 = v1_only + ",v2=" + "0" * 64
    with pytest.raises(Unauthenticated):
        auth.verify_service(headers(bad_v2), b"", SECRET, "POST", EXPIRE, accept_v1=True)


def test_a_signed_expiry_cannot_be_moved_to_another_review(world) -> None:
    """Over HTTP: a captured expiry for one review, replayed against another, is refused."""
    from fastapi.testclient import TestClient
    from muistamo_knowledge.app import create_app
    from muistamo_knowledge.leavers import Leavers, set_service_secret

    set_service_secret(world.db.owner_url, world.tenant, SECRET)
    leavers = Leavers(world.knowledge, auth.dev_identity)
    for person, review in (("a@example.invalid", "leave:a"), ("b@example.invalid", "leave:b")):
        world.client(person).post(
            "/v1/knowledge/personal/entries",
            json={"key": "k", "type": "fact", "title": "t", "body": "b"},
        )
        leavers.open(world.tenant, {"id": review, "person": {"email": person}, "deciders": []})
    client = TestClient(
        create_app(world.knowledge, auth.insecure_dev_headers), raise_server_exceptions=False
    )
    signed = auth.sign(
        SECRET, b"", method="POST", path="/v1/knowledge/internal/leaver-reviews/leave:a/expire"
    )
    replayed = client.post(
        "/v1/knowledge/internal/leaver-reviews/leave:b/cancel",
        content=b"",
        headers={"X-Muistamo-Tenant": str(world.tenant), "X-Muistamo-Signature": signed},
    )
    assert replayed.status_code == 401, replayed.text
    with world.knowledge.db.in_tenant(world.tenant) as cur:
        cur.execute("SELECT status FROM knowledge.leaver_reviews WHERE id = 'leave:b'")
        assert cur.fetchone()[0] == "open"
    # The genuine call still works.
    genuine = client.post(
        "/v1/knowledge/internal/leaver-reviews/leave:b/cancel",
        content=b"",
        headers={
            "X-Muistamo-Tenant": str(world.tenant),
            "X-Muistamo-Signature": auth.sign(
                SECRET,
                b"",
                method="POST",
                path="/v1/knowledge/internal/leaver-reviews/leave:b/cancel",
            ),
        },
    )
    assert genuine.status_code == 200 and json.loads(genuine.text)["outcome"] == "cancelled"


@pytest.mark.parametrize(
    "value",
    [
        "t=١٧٠٠٠٠٠٠٠٠,v2=" + "0" * 64,  # non-ASCII digits
        f"t={int(time.time())},v2=é" + "0" * 63,  # non-ASCII MAC, fresh: refused, not a 500
        "t=" + "9" * 40 + ",v2=" + "0" * 64,  # absurd timestamp
    ],
)
def test_malformed_headers_are_refused_not_errors(value) -> None:
    with pytest.raises(Unauthenticated):
        auth.verify_service(headers(value), b"", SECRET, "POST", EXPIRE)


@pytest.mark.parametrize("bad", ["\n", "\r", "\t", "\x00", "\x7f"])
def test_a_path_with_a_control_character_is_never_verified(bad) -> None:
    """Fields are newline-joined, and the path is the last before the body."""
    path = EXPIRE.replace("entra-leaver:r", f"entra-leaver:r{bad}x")
    signed = headers(auth.sign(SECRET, b"", method="POST", path=path))
    with pytest.raises(Unauthenticated):
        auth.verify_service(signed, b"", SECRET, "POST", path)


def _two_reviews(world):
    from fastapi.testclient import TestClient
    from muistamo_knowledge.app import create_app
    from muistamo_knowledge.leavers import Leavers, set_service_secret

    set_service_secret(world.db.owner_url, world.tenant, SECRET)
    leavers = Leavers(world.knowledge, auth.dev_identity)
    for person, review in (("a@example.invalid", "leave:a"), ("b@example.invalid", "leave:b")):
        world.client(person).post(
            "/v1/knowledge/personal/entries",
            json={"key": "k", "type": "fact", "title": "t", "body": "b"},
        )
        leavers.open(world.tenant, {"id": review, "person": {"email": person}, "deciders": []})
    with world.knowledge.db.in_tenant(world.tenant) as cur:
        cur.execute("UPDATE knowledge.leaver_reviews SET deadline = now() - interval '1 day'")
    return TestClient(
        create_app(world.knowledge, auth.insecure_dev_headers), raise_server_exceptions=False
    )


def _post(client, world, path: str, signature: str):
    return client.post(
        path,
        content=b"",
        headers={"X-Muistamo-Tenant": str(world.tenant), "X-Muistamo-Signature": signature},
    )


def _status(world, review: str) -> str:
    with world.knowledge.db.in_tenant(world.tenant) as cur:
        cur.execute("SELECT status FROM knowledge.leaver_reviews WHERE id = %s", (review,))
        return cur.fetchone()[0]


def test_an_expiry_for_one_review_cannot_purge_another(world) -> None:
    """The exact attack: a captured, signed expiry of review A, replayed as an expiry of B."""
    client = _two_reviews(world)
    a = "/v1/knowledge/internal/leaver-reviews/leave:a/expire"
    b = "/v1/knowledge/internal/leaver-reviews/leave:b/expire"
    captured = auth.sign(SECRET, b"", method="POST", path=a)
    assert _post(client, world, b, captured).status_code == 401
    assert _status(world, "leave:b") == "open"
    assert _post(client, world, a, captured).json()["outcome"] == "expired"


def test_the_signed_path_is_the_one_the_router_matched(world) -> None:
    """The control plane signs its request's decoded path; the service checks the decoded path
    it routed on, so characters the URL encodes still verify, and a control character never does."""
    client = _two_reviews(world)
    for review in ("leave:a?x", "leave:a#x", "leave:a%x", "leave:aé"):
        decoded = f"/v1/knowledge/internal/leaver-reviews/{review}/expire"
        from urllib.parse import quote

        wire = "/v1/knowledge/internal/leaver-reviews/" + quote(review, safe=":") + "/expire"
        res = _post(client, world, wire, auth.sign(SECRET, b"", method="POST", path=decoded))
        assert res.status_code == 404, (
            review,
            res.status_code,
            res.text,
        )  # verified; no such review
    wire = "/v1/knowledge/internal/leaver-reviews/leave:a%0Ax/expire"
    signed = auth.sign(
        SECRET, b"", method="POST", path="/v1/knowledge/internal/leaver-reviews/leave:ax/expire"
    )
    assert _post(client, world, wire, signed).status_code == 401


def test_the_overlap_flag_is_read_when_the_app_starts(world, monkeypatch, caplog) -> None:
    import logging

    from fastapi.testclient import TestClient
    from muistamo_knowledge.app import create_app

    _two_reviews(world)
    path = "/v1/knowledge/internal/leaver-reviews/leave:a/cancel"
    v1_only = auth.sign(SECRET, b"", method="POST", path=path).rsplit(",v2=", 1)[0]
    strict = TestClient(
        create_app(world.knowledge, auth.insecure_dev_headers), raise_server_exceptions=False
    )
    assert _post(strict, world, path, v1_only).status_code == 401
    monkeypatch.setenv("MUISTAMO_KNOWLEDGE_ACCEPT_V1_SIGNATURES", "true")
    overlap = TestClient(
        create_app(world.knowledge, auth.insecure_dev_headers), raise_server_exceptions=False
    )
    with caplog.at_level(logging.WARNING, logger="muistamo.knowledge"):
        assert _post(overlap, world, path, v1_only).status_code == 200
    assert any("v1-only" in r.getMessage() for r in caplog.records)


def test_no_signed_route_reads_a_query() -> None:
    """The query is not signed (docs/signature-plan.md): a signed route must never read one."""
    from muistamo_knowledge.app import create_app

    internal = [r for r in create_app(None).routes if "/internal/" in getattr(r, "path", "")]
    assert internal, "no internal routes found"
    for route in internal:
        assert not route.dependant.query_params, (route.path, route.dependant.query_params)
