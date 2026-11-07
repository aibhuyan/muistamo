"""Adversarial suite: assistants cannot act as reviewer (maintainer decision, 2026-11-07).

Reviewer and admin actions are refused when the call comes through an assistant: a person who
reviews 'legal', working through an agent whose template is 'finance', or a prompt-injected
assistant, can neither read the review inbox nor approve, edit, roll back, verify, erase or decide
a leaver review. Reviewers act through Muistamo's console, a client app of kind 'console', as
themselves (no agent scope). Never skip or weaken.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from muistamo_knowledge import entra
from muistamo_knowledge.delegation import Delegation, Outcome
from muistamo_knowledge.privacy import replace_officers

pytestmark = pytest.mark.authz

REVIEWER = uuid.UUID("7e000000-0000-4000-8000-00000000000a")
AUTHOR = uuid.UUID("7e000000-0000-4000-8000-00000000000b")
CONSOLE = uuid.UUID("7e000000-0000-4000-8000-0000000c0501")
REFUSED = "not available through an assistant"


def pack(name: str) -> dict:
    return {
        "apiVersion": "muistamo.dev/v1",
        "kind": "KnowledgePack",
        "metadata": {"name": name},
        "spec": {
            "layer": "role",
            "reviewers": [f"entra:{REVIEWER}"],
            "mergePolicy": {"requires": ["review"]},
        },
    }


class Plane:
    def request(self, tenant, user_token: str, instance=None) -> Outcome:
        return Outcome(
            Delegation(
                instance="analyst-e-1",
                agent_identity=uuid.uuid4(),
                person="HR",
                packs=["finance"],
                expires_at=datetime.now(UTC) + timedelta(minutes=30),
                graph_token="obviously-fake-graph-token",  # noqa: S106 - a fake fixture
            )
        )


@pytest.fixture
def setup(entra_world):
    """'legal' is reviewed by REVIEWER, whose agent's template is 'finance'. The console is an
    allowed client of kind 'console'; conftest's assistant is of kind 'assistant'."""
    ew = entra_world
    world = ew.world
    entra.allow_assistant(world.db.owner_url, world.tenant, CONSOLE, "Muistamo console", "console")
    replace_officers(world.db.owner_url, world.tenant, [f"entra:{REVIEWER}"])
    world.knowledge.delegations = Plane()
    console = ew.client(ew.directory.token(REVIEWER, azp=str(CONSOLE)))
    assert console.put("/v1/knowledge/packs/legal", json=pack("legal")).status_code == 201
    author = ew.client(ew.directory.token(AUTHOR))
    entry = {"key": "k", "type": "fact", "title": "t", "body": "b"}
    captured = author.post("/v1/knowledge/personal/entries", json=entry).json()
    # The author's own agent may propose only within its template, so the proposal to 'legal'
    # is made through the console, as the author acting as themselves.
    author_console = ew.client(ew.directory.token(AUTHOR, azp=str(CONSOLE)))
    proposal = author_console.post(
        "/v1/knowledge/proposals",
        json={"pack": "legal", "entryIds": [captured["id"]], "summary": "s"},
    )
    assert proposal.status_code == 201, proposal.text
    return ew, proposal.json()["id"]


def through_assistant(ew):
    return ew.client(ew.directory.token(REVIEWER))


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("PUT", "/v1/knowledge/packs/legal", "pack"),
        ("POST", "/v1/knowledge/packs/legal/rollback", {"toVersion": "0.0.0", "reason": "x"}),
        (
            "POST",
            "/v1/knowledge/packs/legal/entries/k/verification",
            {"entryId": str(uuid.uuid4()), "reason": "x"},
        ),
        ("GET", "/v1/knowledge/verifications", None),
        ("GET", "/v1/knowledge/proposals?role=reviewer", None),
        (
            "POST",
            "/v1/knowledge/proposals/{proposal}/decision",
            {"decision": "approve", "reason": "x"},
        ),
        (
            "PUT",
            "/v1/knowledge/sources/legal-site",
            {
                "apiVersion": "muistamo.dev/v1",
                "kind": "KnowledgeSource",
                "metadata": {"name": "legal-site"},
                "spec": {"pack": "legal", "connector": "test", "test": {"documents": []}},
            },
        ),
        ("POST", "/v1/knowledge/sources/legal-site/sync", None),
        (
            "POST",
            "/v1/knowledge/privacy/erasures",
            {
                "id": str(uuid.uuid4()),
                "reason": "x",
                "subject": {"identities": ["dev:x@example.invalid"]},
            },
        ),
        ("GET", f"/v1/knowledge/privacy/erasures/{uuid.uuid4()}", None),
        (
            "POST",
            "/v1/knowledge/privacy/access",
            {"subject": {"identities": ["dev:x@example.invalid"]}},
        ),
        ("GET", "/v1/knowledge/leaver-reviews", None),
        ("GET", "/v1/knowledge/leaver-reviews/any", None),
        ("POST", "/v1/knowledge/leaver-reviews/any/decision", {"decision": "purge", "reason": "x"}),
        ("GET", "/v1/knowledge/events", None),
    ],
)
def test_reviewer_and_admin_actions_are_refused_through_an_assistant(
    setup, method, path, body
) -> None:
    ew, proposal = setup
    path = path.replace("{proposal}", proposal)
    payload = pack("legal") if body == "pack" else body
    res = through_assistant(ew).request(method, path, json=payload)
    assert res.status_code == 403, (method, path, res.status_code, res.text)


def test_the_console_reviewer_acts_as_themselves(setup) -> None:
    ew, proposal = setup
    console = ew.client(ew.directory.token(REVIEWER, azp=str(CONSOLE)))
    # Not agent-scoped: the reviewer reads the pack they review, outside their agent's template.
    assert console.get("/v1/knowledge/packs/legal").status_code == 200
    inbox = console.get("/v1/knowledge/proposals", params={"role": "reviewer"})
    assert [p["id"] for p in inbox.json()["items"]] == [proposal]
    decided = console.post(
        f"/v1/knowledge/proposals/{proposal}/decision", json={"decision": "approve", "reason": "ok"}
    )
    assert decided.status_code == 200, decided.text


def test_through_an_assistant_a_person_sees_only_their_own_proposals(setup) -> None:
    ew, proposal = setup
    author = ew.client(ew.directory.token(AUTHOR))
    assert author.get(f"/v1/knowledge/proposals/{proposal}").status_code == 200  # their own
    mine = author.get("/v1/knowledge/proposals", params={"role": "contributor"})
    assert [p["id"] for p in mine.json()["items"]] == [proposal]
    # The reviewer, through their assistant, cannot open someone else's proposal.
    assert through_assistant(ew).get(f"/v1/knowledge/proposals/{proposal}").status_code == 404


def test_a_client_of_any_other_kind_is_an_assistant(entra_world) -> None:
    """Fail closed: only kind 'console' acts as the person themselves."""
    import psycopg

    with pytest.raises(psycopg.errors.CheckViolation):
        entra.allow_assistant(
            entra_world.world.db.owner_url, entra_world.world.tenant, uuid.uuid4(), "X", "admin"
        )


@pytest.mark.parametrize(
    ("name", "kind", "through"),
    [
        ("entra:x", "assistant", True),
        ("entra:x", "console", False),
        ("entra:x", None, True),  # fail closed: no kind recorded is an assistant
        ("entra:x", "anything-else", True),
        ("dev:someone@example.invalid", None, False),
    ],
)
def test_only_the_console_kind_acts_as_the_person(name, kind, through) -> None:
    from muistamo_knowledge.service import Actor

    actor = Actor(tenant=uuid.uuid4(), name=name, request_id="r", client_kind=kind)
    assert actor.through_assistant is through
