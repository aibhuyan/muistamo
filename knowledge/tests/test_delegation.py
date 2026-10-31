"""Delegated retrieval for Entra callers (PR D). HUMAN REVIEW REQUIRED: tokens and invariant 2."""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from muistamo_knowledge import auth
from muistamo_knowledge.connectors import InMemoryConnector, Principal
from muistamo_knowledge.delegation import (
    Delegation,
    DelegationClient,
    Outcome,
    direction_key,
    sign,
)

TENANT = uuid.UUID("11111111-1111-4111-8111-111111111111")
SECRET = b"obviously-fake-knowledge-secret"
PERSON = uuid.UUID("6f1c2a3b-0000-4000-8000-00000000000a")
OTHER = uuid.UUID("6f1c2a3b-0000-4000-8000-00000000000b")
REVIEWER = "reviewer-r@example.invalid"


def test_the_signing_key_matches_the_control_planes() -> None:
    # The same vector is asserted in control-plane/internal/signature/signature_test.go.
    key = direction_key(SECRET, TENANT)
    assert key.hex() == "1857a5c5dbdbb6187f7ab198a211d42b752236b2efbbaa9f4e19444924375ccf"
    assert sign(key, b"{}", 1700000000) == (
        "t=1700000000,v1=5e444998662526fd33a0cd6b5e3077cc315afeb5499b8c576da8e3db0092fac3"
    )


def graph_token(**claims) -> str:
    """An unsigned, JWT-shaped fake Graph token: only its claims are read here."""
    import base64

    def part(value: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()

    body = {
        "aud": "https://graph.microsoft.com",
        "scp": "Sites.Read.All",
        "oid": str(PERSON),
    } | claims
    return f"{part({'alg': 'RS256'})}.{part({k: v for k, v in body.items() if v is not None})}.obviously-fake"


GRAPH_TOKEN = graph_token()


def issued(**changes) -> dict:
    answer = {
        "instance": "analyst-person",
        "agentIdentity": str(uuid.uuid4()),
        "person": "HR-PERSON",
        "packs": [{"name": "finance"}],
        "graphToken": GRAPH_TOKEN,
        "expiresAt": (datetime.now(UTC) + timedelta(minutes=30)).isoformat(),
    }
    answer.update(changes)
    return answer


class Transport:
    def __init__(self, status: int = 200, answer: object = None, error: Exception | None = None):
        self.status, self.answer, self.error = status, answer, error
        self.sent: list[tuple[str, bytes, dict[str, str]]] = []

    def __call__(self, url: str, body: bytes, headers: dict[str, str], timeout: float):
        self.sent.append((url, body, headers))
        if self.error:
            raise self.error
        raw = self.answer if isinstance(self.answer, bytes) else json.dumps(self.answer).encode()
        return self.status, raw


def client(transport: Transport, secret: bytes | None = SECRET) -> DelegationClient:
    return DelegationClient("https://control-plane.example.invalid/", lambda _: secret, transport)


def test_a_request_is_signed_for_its_direction_and_tenant_with_a_fresh_nonce() -> None:
    transport = Transport(answer=issued())
    c = client(transport)
    outcome = c.request(TENANT, "obviously-fake-user-token")
    c.request(TENANT, "obviously-fake-user-token", instance="analyst-person")
    assert outcome.delegation is not None and outcome.delegation.packs == ["finance"]
    assert GRAPH_TOKEN not in repr(outcome)
    (url, body, headers), (_, second, _) = transport.sent
    assert url == "https://control-plane.example.invalid/v1/internal/knowledge/delegations"
    sent = json.loads(body)
    assert sent["userToken"] == "obviously-fake-user-token" and len(sent["nonce"]) == 32
    assert "instance" not in sent and json.loads(second)["instance"] == "analyst-person"
    assert sent["nonce"] != json.loads(second)["nonce"]
    assert headers["X-Muistamo-Tenant"] == str(TENANT)
    ts, mac = (p.split("=", 1)[1] for p in headers["X-Muistamo-Signature"].split(","))
    want = hmac.new(direction_key(SECRET, TENANT), ts.encode() + b"." + body, hashlib.sha256)
    assert hmac.compare_digest(mac, want.hexdigest())
    # Never the secret itself: that is the other direction's key.
    raw = hmac.new(SECRET, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    assert mac != raw


@pytest.mark.parametrize(
    ("transport", "secret", "reason"),
    [
        (Transport(403, {"reason": "user-unlinked"}), SECRET, "user-unlinked"),
        (Transport(403, {"reason": "no-active-agent"}), SECRET, "no-active-agent"),
        (Transport(503, {"reason": "evidence-unavailable"}), SECRET, "evidence-unavailable"),
        (Transport(403, {"reason": "made-up"}), SECRET, "unavailable"),
        (Transport(501, {"title": "Delegation is not configured"}), SECRET, "not-configured"),
        (Transport(500, {"title": "Internal error"}), SECRET, "unavailable"),
        # A well-formed delegation with any status but 200 is not an issue.
        (Transport(201, issued()), SECRET, "unavailable"),
        (Transport(500, issued()), SECRET, "unavailable"),
        # A well-formed but oversized answer is refused.
        (Transport(200, issued(person="x" * (64 * 1024))), SECRET, "unavailable"),
        (Transport(401, {"title": "Unauthorized"}), SECRET, "unavailable"),
        (Transport(200, b"not json"), SECRET, "unavailable"),
        (Transport(200, issued(graphToken="")), SECRET, "unavailable"),
        # Only a delegated person's Graph token is ever passed to a source.
        (Transport(200, issued(graphToken="obviously-fake-opaque")), SECRET, "unavailable"),
        (Transport(200, issued(graphToken=graph_token(scp=None))), SECRET, "unavailable"),
        (Transport(200, issued(graphToken=graph_token(scp=" "))), SECRET, "unavailable"),
        (
            Transport(200, issued(graphToken=graph_token(roles=["Sites.Read.All"]))),
            SECRET,
            "unavailable",
        ),
        (Transport(200, issued(graphToken=graph_token(idtyp="app"))), SECRET, "unavailable"),
        (Transport(200, issued(agentIdentity="not-a-uuid")), SECRET, "unavailable"),
        (Transport(200, issued(packs=[{"version": "1.x"}])), SECRET, "unavailable"),
        (Transport(200, issued(expiresAt="2020-01-01T00:00:00+00:00")), SECRET, "unavailable"),
        (Transport(200, issued(expiresAt="2999-01-01T00:00:00")), SECRET, "unavailable"),
        (Transport(200, b"x" * (64 * 1024 + 1)), SECRET, "unavailable"),
        (Transport(error=OSError("obviously fake outage")), SECRET, "unavailable"),
        (Transport(answer=issued()), None, "not-configured"),
    ],
)
def test_anything_but_a_well_formed_issue_is_no_delegation(transport, secret, reason) -> None:
    assert client(transport, secret).request(TENANT, "t") == Outcome(None, reason)


def test_the_control_plane_url_is_http_only() -> None:
    with pytest.raises(ValueError):
        DelegationClient("file:///etc/passwd", lambda _: SECRET)


# Retrieval with the database, the test connector and a fake control plane.


class FakeControlPlane:
    """Answers delegations by the caller's token: an Outcome per user, recording what it saw."""

    def __init__(self, outcomes: dict[uuid.UUID, Outcome]) -> None:
        self.outcomes = outcomes
        self.asked: list[tuple[uuid.UUID, str]] = []
        self.by_token: dict[str, uuid.UUID] = {}

    def request(self, tenant: uuid.UUID, user_token: str, instance: str | None = None) -> Outcome:
        self.asked.append((tenant, user_token))
        return self.outcomes[self.by_token[user_token]]


def delegation_for(packs: list[str], token: str = "obviously-fake-graph-token") -> Outcome:  # noqa: S107 - a fake fixture
    return Outcome(
        Delegation(
            instance="analyst-person",
            agent_identity=uuid.uuid4(),
            person="HR-PERSON",
            packs=packs,
            expires_at=datetime.now(UTC) + timedelta(minutes=30),
            graph_token=token,
        )
    )


def pack(name: str) -> dict:
    return {
        "apiVersion": "muistamo.dev/v1",
        "kind": "KnowledgePack",
        "metadata": {"name": name},
        "spec": {
            "layer": "role",
            "reviewers": ["dev:" + REVIEWER],
            "mergePolicy": {"requires": ["review"]},
        },
    }


class RecordingConnector(InMemoryConnector):
    def authorise(self, principal: Principal, external_ids: list[str]) -> set[str]:
        self.principals.append(principal)
        return super().authorise(principal, external_ids)


def setup(entra_world, documents: dict[str, list[dict]]) -> dict[str, RecordingConnector]:
    """Packs with one source each, documents readable by PERSON (as entra:<oid>)."""
    world = entra_world.world
    connectors: dict[str, RecordingConnector] = {}
    for name, docs in documents.items():
        connectors[name] = RecordingConnector(documents=docs)
        connectors[name].principals = []
    world.knowledge.connectors = {
        "test": lambda source, spec, tenant=None: connectors[spec["pack"]]
    }
    r = world.client(REVIEWER)
    for name, docs in documents.items():
        assert r.put(f"/v1/knowledge/packs/{name}", json=pack(name)).status_code == 201
        source = {
            "apiVersion": "muistamo.dev/v1",
            "kind": "KnowledgeSource",
            "metadata": {"name": f"{name}-site"},
            "spec": {"pack": name, "connector": "test", "test": {"documents": docs}},
        }
        assert r.put(f"/v1/knowledge/sources/{name}-site", json=source).status_code == 201
        assert r.post(f"/v1/knowledge/sources/{name}-site/sync").status_code == 200
    for c in connectors.values():
        c.calls.clear()
    return connectors


def doc(doc_id: str, reader: uuid.UUID) -> dict:
    return {
        "id": doc_id,
        "title": f"Quarterly {doc_id}",
        "body": "Quarterly figures.",
        "readers": [f"entra:{reader}"],
    }


def retrieve(entra_world, token: str, packs: str = "") -> dict:
    res = entra_world.client(token).get(
        "/v1/knowledge/retrieve", params={"q": "quarterly", "packs": packs, "limit": 50}
    )
    assert res.status_code == 200, res.text
    return res.json()


def documents(body: dict) -> set[str]:
    return {
        i["citation"]["externalId"] for i in body["items"] if i["citation"]["type"] == "document"
    }


def test_an_entra_caller_retrieves_as_their_agent_within_its_template(entra_world) -> None:
    connectors = setup(
        entra_world, {"finance": [doc("in-template", PERSON)], "legal": [doc("outside", PERSON)]}
    )
    token = entra_world.directory.token(PERSON)
    plane = FakeControlPlane({PERSON: delegation_for(["finance"])})
    plane.by_token[token] = PERSON
    entra_world.world.knowledge.delegations = plane
    body = retrieve(entra_world, token, "finance,legal")
    assert documents(body) == {"in-template"}
    assert body["coverage"]["packsOutsideAgentScope"] == ["legal"]
    assert body["coverage"]["delegation"] == {"status": "issued", "agent": "analyst-person"}
    assert connectors["legal"].calls == []
    # The source was asked with the delegated token, for this person.
    (principal,) = connectors["finance"].principals
    assert (
        principal.person == f"entra:{PERSON}"
        and principal.graph_token == "obviously-fake-graph-token"  # noqa: S105 - a fake fixture
    )
    assert "obviously-fake-graph-token" not in repr(principal)
    # The control plane was asked with the caller's own token, every request.
    assert plane.asked == [(entra_world.world.tenant, token)]
    # With no packs named, the template's packs are searched.
    body = retrieve(entra_world, token)
    assert documents(body) == {"in-template"} and "packsOutsideAgentScope" not in body["coverage"]
    assert len(plane.asked) == 2


@pytest.mark.parametrize(
    "reason", ["user-unlinked", "no-active-agent", "not-configured", "unavailable"]
)
def test_without_a_delegation_only_the_callers_own_layer_is_searched(entra_world, reason) -> None:
    connectors = setup(entra_world, {"finance": [doc("readable", PERSON)]})
    token = entra_world.directory.token(PERSON)
    plane = FakeControlPlane({PERSON: Outcome(None, reason)})
    plane.by_token[token] = PERSON
    entra_world.world.knowledge.delegations = plane
    person = entra_world.client(token)
    note = {
        "key": "quarterly-note",
        "type": "fact",
        "title": "Quarterly note",
        "body": "My quarterly note.",
    }
    assert person.post("/v1/knowledge/personal/entries", json=note).status_code == 201
    body = retrieve(entra_world, token, "finance")
    assert documents(body) == set()
    assert [i["citation"]["entryKey"] for i in body["items"]] == ["quarterly-note"]
    status = "unavailable" if reason in ("not-configured", "unavailable") else "refused"
    assert body["coverage"]["delegation"] == {"status": status, "reason": reason}
    assert body["coverage"]["sourcesUnavailable"] == body["coverage"]["sourcesQueried"]
    # No delegation is not the same as outside the template: the reason already says why.
    assert "packsOutsideAgentScope" not in body["coverage"]
    assert connectors["finance"].calls == []


def test_without_a_delegation_client_entra_callers_get_no_sources(entra_world) -> None:
    connectors = setup(entra_world, {"finance": [doc("readable", PERSON)]})
    body = retrieve(entra_world, entra_world.directory.token(PERSON), "finance")
    assert documents(body) == set()
    assert body["coverage"]["delegation"] == {"status": "unavailable", "reason": "not-configured"}
    assert connectors["finance"].calls == []


def test_development_callers_are_unchanged(entra_world) -> None:
    setup(
        entra_world,
        {
            "finance": [
                {
                    "id": "dev-doc",
                    "title": "Quarterly",
                    "body": "Quarterly.",
                    "readers": ["dev:a@example.invalid"],
                }
            ]
        },
    )
    res = entra_world.world.client("a@example.invalid").get(
        "/v1/knowledge/retrieve", params={"q": "quarterly", "packs": "finance"}
    )
    body = res.json()
    assert documents(body) == {"dev-doc"} and "delegation" not in body["coverage"]


def test_mcp_search_reports_the_delegation(entra_world) -> None:
    setup(entra_world, {"finance": [doc("in-template", PERSON)]})
    token = entra_world.directory.token(PERSON)
    plane = FakeControlPlane({PERSON: delegation_for(["finance"])})
    plane.by_token[token] = PERSON
    entra_world.world.knowledge.delegations = plane
    result = entra_world.mcp(
        token, "search_knowledge", {"query": "quarterly", "packs": ["finance"]}
    )
    content = result.structured_content
    assert content["coverage"]["delegation"]["status"] == "issued"
    assert [r["citation"]["externalId"] for r in content["results"]] == ["in-template"]


def test_the_bearer_is_kept_only_for_entra_callers() -> None:
    headers = {"Authorization": "Bearer obviously-fake"}
    assert auth.entra_bearer(f"entra:{PERSON}", headers) == "obviously-fake"
    assert auth.entra_bearer("dev:a@example.invalid", headers) is None
    assert auth.entra_bearer(f"entra:{PERSON}", {"Authorization": "Basic x"}) is None


def test_the_template_scope_is_reported_honestly(entra_world) -> None:
    from muistamo_knowledge.privacy import replace_officers

    world = entra_world.world
    setup(entra_world, {"finance": [doc("in-template", PERSON)]})
    replace_officers(world.db.owner_url, world.tenant, ["dev:dpo@example.invalid"])
    rules = pack("company-rules")
    rules["spec"] |= {"layer": "company", "mandatory": True}
    assert (
        world.client("dpo@example.invalid")
        .put("/v1/knowledge/packs/company-rules", json=rules)
        .status_code
        == 201
    )
    token = entra_world.directory.token(PERSON)
    plane = FakeControlPlane({PERSON: delegation_for(["finance", "renamed-away"])})
    plane.by_token[token] = PERSON
    world.knowledge.delegations = plane
    body = retrieve(entra_world, token, "finance,company-rules,finance,no-such-pack")
    # Mandatory packs are always in scope; a missing template pack is reported, not fatal; a
    # requested pack outside the template is reported without saying whether it exists.
    assert documents(body) == {"in-template"}
    assert body["coverage"]["packsOutsideAgentScope"] == ["no-such-pack"]
    assert body["coverage"]["packsUnavailable"] == ["renamed-away"]
    assert retrieve(entra_world, token)["coverage"]["packsUnavailable"] == ["renamed-away"]
    # An empty template searches no pack but the mandatory ones.
    plane.outcomes[PERSON] = delegation_for([])
    body = retrieve(entra_world, token, "finance")
    assert documents(body) == set() and body["coverage"]["packsOutsideAgentScope"] == ["finance"]


def test_pack_entries_outside_the_template_are_never_returned(entra_world) -> None:
    world = entra_world.world
    setup(entra_world, {"finance": [], "legal": []})
    a = world.client("a@example.invalid")
    for name in ("finance", "legal"):
        captured = a.post(
            "/v1/knowledge/personal/entries",
            json={
                "key": f"{name}-entry",
                "type": "fact",
                "title": "Quarterly",
                "body": "Quarterly.",
            },
        ).json()
        p = a.post(
            "/v1/knowledge/proposals",
            json={"pack": name, "entryIds": [captured["id"]], "summary": "s"},
        ).json()
        assert (
            world.client(REVIEWER)
            .post(
                f"/v1/knowledge/proposals/{p['id']}/decision",
                json={"decision": "approve", "reason": "ok"},
            )
            .status_code
            == 200
        )
    token = entra_world.directory.token(PERSON)
    plane = FakeControlPlane({PERSON: delegation_for(["finance"])})
    plane.by_token[token] = PERSON
    world.knowledge.delegations = plane
    for packs in ("finance,legal", "legal", ""):
        keys = {i["citation"].get("entryKey") for i in retrieve(entra_world, token, packs)["items"]}
        assert "legal-entry" not in keys, packs
    result = entra_world.mcp(token, "search_knowledge", {"query": "quarterly", "packs": ["legal"]})
    assert result.structured_content["results"] == []


def test_an_entra_caller_without_a_token_gets_no_development_scope(entra_world) -> None:
    from muistamo_knowledge.retrieval import Sources
    from muistamo_knowledge.service import Actor

    connectors = setup(entra_world, {"finance": [doc("readable", PERSON)]})
    world = entra_world.world
    world.knowledge.delegations = FakeControlPlane({})
    actor = Actor(tenant=world.tenant, name=f"entra:{PERSON}", request_id="no-bearer")
    body = Sources(world.knowledge).retrieve(actor, "quarterly", ["finance"])
    assert body["items"] == [] and body["coverage"]["delegation"]["reason"] == "unavailable"
    assert connectors["finance"].calls == []


def test_reads_record_the_agent_that_acted(entra_world) -> None:
    setup(entra_world, {"finance": [doc("in-template", PERSON)]})
    token = entra_world.directory.token(PERSON)
    plane = FakeControlPlane({PERSON: delegation_for(["finance"])})
    plane.by_token[token] = PERSON
    entra_world.world.knowledge.delegations = plane
    retrieve(entra_world, token, "finance")
    reads = entra_world.client(token).get("/v1/knowledge/reads").json()["items"]
    assert reads[0]["agent"] == "analyst-person" and reads[0]["person"] == f"entra:{PERSON}"
    dev = entra_world.world.client("a@example.invalid")
    dev.get("/v1/knowledge/retrieve", params={"q": "quarterly"})
    assert "agent" not in dev.get("/v1/knowledge/reads").json()["items"][0]


def test_a_slow_control_plane_is_no_delegation(entra_world, monkeypatch) -> None:
    import time as clock

    from muistamo_knowledge import retrieval

    connectors = setup(entra_world, {"finance": [doc("readable", PERSON)]})
    token = entra_world.directory.token(PERSON)

    class Slow:
        def request(self, tenant, user_token, instance=None):
            clock.sleep(1.0)
            return delegation_for(["finance"])

    entra_world.world.knowledge.delegations = Slow()
    monkeypatch.setattr(retrieval, "DELEGATION_TIMEOUT_SECONDS", 0.2)
    body = retrieve(entra_world, token, "finance")
    assert documents(body) == set() and body["coverage"]["delegation"]["reason"] == "unavailable"
    assert connectors["finance"].calls == []
