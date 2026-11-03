"""Adversarial suite: service-call signatures bind method and path (docs/signature-plan.md).

HUMAN REVIEW REQUIRED (CLAUDE.md): cryptographic signing. Never skip or weaken.
"""

from __future__ import annotations

import json

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
