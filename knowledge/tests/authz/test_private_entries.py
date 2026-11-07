"""Adversarial suite: private personal entries (D59, FR-1802, docs/d59-private-entries-plan.md).

A private entry is never proposed (by its author or by a leaver's decider), never shown or
counted in a leaver review, and purged with signed proof when the leaver review opens. It never
has a copy. Through an assistant an entry can only be made private: making it shared, or deleting
a private entry, needs the console. Personal-layer keys stay out of the evidence and the read log;
the evidence export is for privacy officers. Never skip or weaken.

HUMAN REVIEW REQUIRED (CLAUDE.md): a deletion path and an authorisation exception.
"""

from __future__ import annotations

import json
import uuid

import psycopg
import pytest
from fastapi.testclient import TestClient
from muistamo_knowledge import auth, entra
from muistamo_knowledge.app import create_app
from muistamo_knowledge.leavers import set_service_secret
from muistamo_knowledge.privacy import PERSONAL_DATA_TABLES, replace_officers, rows_mentioning

pytestmark = pytest.mark.authz

A, M, R, X, DPO = (
    "person-a@example.invalid",
    "manager-m@example.invalid",
    "reviewer-r@example.invalid",
    "someone-x@example.invalid",
    "dpo@example.invalid",
)
SECRET = b"mks_test-only-not-a-secret-0123456789abcdef"
BODY = "the-private-body-text-7f3a"
KEY = "complaint-about-manager"
PACK = {
    "apiVersion": "muistamo.dev/v1",
    "kind": "KnowledgePack",
    "metadata": {"name": "basics"},
    "spec": {"layer": "role", "reviewers": ["dev:" + R], "mergePolicy": {"requires": ["review"]}},
}


class Service:
    """Signed calls as the control plane's leaver workflow makes them (legacy, by email)."""

    def __init__(self, world):
        set_service_secret(world.db.owner_url, world.tenant, SECRET)
        self.client = TestClient(
            create_app(world.knowledge, auth.insecure_dev_headers), raise_server_exceptions=False
        )
        self.tenant = world.tenant

    def open(self, review_id: str, person: str = A):
        path = "/v1/knowledge/internal/leaver-reviews"
        raw = json.dumps(
            {
                "id": review_id,
                "person": {"email": person},
                "deciders": [{"email": M, "kind": "manager"}],
            }
        ).encode()
        return self.client.post(
            path,
            content=raw,
            headers={
                "X-Muistamo-Tenant": str(self.tenant),
                "X-Muistamo-Signature": auth.sign(SECRET, raw, method="POST", path=path),
                "Content-Type": "application/json",
            },
        )


@pytest.fixture
def on(world):
    """Private entries enabled, a pack, privacy officers and the leaver workflow's secret."""
    world.knowledge.private_entries = True
    replace_officers(world.db.owner_url, world.tenant, ["dev:" + DPO])
    assert world.client(R).put("/v1/knowledge/packs/basics", json=PACK).status_code == 201
    return Service(world)


def capture(client, key: str, private: bool = False, body: str | None = None) -> dict:
    res = client.post(
        "/v1/knowledge/personal/entries",
        json={
            "key": key,
            "type": "fact",
            "title": key,
            "body": body or f"{key} body",
            "private": private,
        },
    )
    assert res.status_code == 201, res.text
    return res.json()


def personal(client) -> dict[str, dict]:
    return {e["key"]: e for e in client.get("/v1/knowledge/personal/entries").json()["items"]}


def remaining(world, values: list[str]) -> dict[str, int]:
    """Per table, rows holding any of values (as whole JSON strings), evidence included."""
    out = {}
    with world.knowledge.db.in_tenant(world.tenant) as cur:
        for table in PERSONAL_DATA_TABLES:
            if n := len(rows_mentioning(cur, table, values)):
                out[table] = n
    return out


def evidence(world, action: str) -> list[dict]:
    with psycopg.connect(world.db.owner_url) as conn:
        rows = conn.execute(
            "SELECT after FROM knowledge.evidence_events WHERE tenant_id = %s AND action = %s"
            " ORDER BY seq",
            (world.tenant, action),
        ).fetchall()
    return [r[0] for r in rows]


def visibility(client, entry_id, private: bool):
    return client.patch(f"/v1/knowledge/personal/entries/{entry_id}", json={"private": private})


# The owner -------------------------------------------------------------------------------


def test_the_owner_sees_and_finds_their_private_entries(world, on) -> None:
    a = world.client(A)
    note = capture(a, KEY, private=True, body=BODY)
    assert note["private"] is True
    assert capture(a, "shared-note")["private"] is False
    mine = personal(a)
    assert mine[KEY]["private"] is True and mine["shared-note"]["private"] is False
    found = a.get("/v1/knowledge/retrieve", params={"q": BODY})
    assert found.status_code == 200 and BODY in found.text  # the person's own retrieval
    resolved = a.get("/v1/knowledge/resolve")
    assert resolved.status_code == 200 and BODY in resolved.text
    assert '"private"' not in resolved.text  # the flag is the personal list's alone
    assert personal(world.client(X)) == {}
    other = world.client(X).get("/v1/knowledge/retrieve", params={"q": BODY}).json()
    assert BODY not in json.dumps(other["items"])


def test_new_entries_are_shared_by_default(world, on) -> None:
    res = world.client(A).post(
        "/v1/knowledge/personal/entries",
        json={"key": "plain", "type": "fact", "title": "t", "body": "b"},
    )
    assert res.status_code == 201 and res.json()["private"] is False


def test_until_the_operator_enables_them_no_entry_becomes_private(world) -> None:
    """Rolling deploys: a server on older code would show a private entry at a leaver review, so
    writes of private stay refused until every server honours the flag."""
    assert world.knowledge.private_entries is False
    a = world.client(A)
    res = a.post(
        "/v1/knowledge/personal/entries",
        json={"key": "k", "type": "fact", "title": "t", "body": "b", "private": True},
    )
    assert res.status_code == 403
    note = capture(a, "k2")
    assert visibility(a, note["id"], True).status_code == 403
    assert personal(a)["k2"]["private"] is False
    tools = world.mcp(A)
    assert "remember" in tools
    refused = world.mcp(A, "remember", {"key": "q", "title": "t", "body": "b", "private": True})
    assert refused.is_error  # refused, never silently saved as shared
    assert "q" not in personal(a)


def test_only_the_owner_changes_the_flag(world, on) -> None:
    a = world.client(A)
    note = capture(a, "my-note")
    assert visibility(world.client(X), note["id"], True).status_code == 404
    assert personal(a)["my-note"]["private"] is False
    assert visibility(a, note["id"], True).json()["private"] is True
    assert visibility(a, note["id"], True).json()["private"] is True  # no change, no event
    assert visibility(a, note["id"], False).json()["private"] is False  # a dev caller
    assert evidence(world, "knowledge.entry.visibility-changed") == [
        {"private": True},
        {"private": False},
    ]


def test_an_entry_with_a_copy_in_a_proposal_cannot_become_private(world, on) -> None:
    a = world.client(A)
    note = capture(a, "my-note", body=BODY)
    proposed = a.post(
        "/v1/knowledge/proposals",
        json={"pack": "basics", "entryIds": [note["id"]], "summary": "s"},
    )
    assert proposed.status_code == 201
    res = visibility(a, note["id"], True)
    assert res.status_code == 409 and "proposed" in res.json()["detail"]
    assert personal(a)["my-note"]["private"] is False


# Evidence and the read log ---------------------------------------------------------------


def test_personal_keys_stay_out_of_the_evidence_and_the_read_log(world, on) -> None:
    a = world.client(A)
    note = capture(a, KEY, private=True, body=BODY)
    shared = capture(a, "shared-key-9c1d")
    assert a.get("/v1/knowledge/retrieve", params={"q": BODY}).status_code == 200
    assert world.mcp(A, "search_knowledge", {"query": BODY}).is_error is False
    # No key of any personal entry, no content, and no private flag at capture.
    assert remaining(world, [KEY, BODY, "shared-key-9c1d"]) == {"entries": 2}
    assert evidence(world, "knowledge.entry.captured")[-2:] == [
        {"type": "fact", "layer": "personal", "private": True},
        {"type": "fact", "layer": "personal", "private": False},
    ]
    with psycopg.connect(world.db.owner_url) as conn:
        reads = conn.execute(
            "SELECT citations FROM knowledge.reads WHERE tenant_id = %s", (world.tenant,)
        ).fetchall()
    assert reads and all(
        "entryKey" not in c for (cs,) in reads for c in cs if c.get("layer") == "personal"
    )
    assert note["id"] != shared["id"]


def test_the_evidence_export_is_for_privacy_officers_only(world, on) -> None:
    capture(world.client(A), KEY, private=True, body=BODY)
    for person in (M, A, X):
        assert world.client(person).get("/v1/knowledge/events").status_code == 403, person
    export = world.client(DPO).get("/v1/knowledge/events")
    assert export.status_code == 200 and export.json()["items"]
    assert KEY not in export.text and BODY not in export.text


# Never proposed --------------------------------------------------------------------------


def test_a_private_entry_is_never_proposed(world, on) -> None:
    a = world.client(A)
    note = capture(a, KEY, private=True, body=BODY)
    res = a.post(
        "/v1/knowledge/proposals",
        json={"pack": "basics", "entryIds": [note["id"]], "summary": "s"},
    )
    assert res.status_code == 404, res.text  # the same answer as for an entry that is not there
    assert remaining(world, [BODY]) == {"entries": 1}  # only the personal revision


def test_mcp_remember_private_and_no_tool_makes_it_shared(world, on) -> None:
    a = world.client(A)
    proposals = a.get("/v1/knowledge/proposals").json()["items"]
    saved = world.mcp(A, "remember", {"key": "quiet", "title": "t", "body": "b", "private": True})
    assert not saved.is_error, saved
    assert personal(a)["quiet"]["private"] is True
    assert a.get("/v1/knowledge/proposals").json()["items"] == proposals
    assert sorted(world.mcp(A)) == ["propose_knowledge", "remember", "search_knowledge"]


# The leaver review -----------------------------------------------------------------------


def test_the_decider_never_sees_or_counts_private_entries(world, on) -> None:
    a = world.client(A)
    capture(a, "shared-note")
    note = capture(a, KEY, private=True, body=BODY)
    opened = svc_open(on)
    assert opened.json()["entryCount"] == 1  # shared entries only
    got = world.client(M).get("/v1/knowledge/leaver-reviews/leaver-1:run-1")
    assert got.status_code == 200
    assert [e["key"] for e in got.json()["entries"]] == ["shared-note"]
    for leaked in (BODY, KEY, note["id"], "private"):
        assert leaked not in got.text, leaked
    merge = world.client(M).post(
        "/v1/knowledge/leaver-reviews/leaver-1:run-1/decision",
        json={
            "decision": "merge",
            "reason": "x",
            "pack": "basics",
            "entryIds": [note["id"]],
            "summary": "s",
        },
    )
    assert merge.status_code == 404, merge.text  # purged, and named like a missing entry
    assert BODY not in merge.text


def svc_open(svc, review_id: str = "leaver-1:run-1"):
    opened = svc.open(review_id)
    assert opened.status_code == 201, opened.text
    return opened


def test_opening_the_review_purges_private_entries_with_proof(world, on) -> None:
    a = world.client(A)
    capture(a, "shared-note")
    note = capture(a, KEY, private=True, body=BODY)
    capture(a, "my-other", private=True)
    svc_open(on)
    assert set(personal(a)) == {"shared-note"}  # gone at leaving, before any decision
    assert remaining(world, [BODY, KEY, "my-other body"]) == {}
    with psycopg.connect(world.db.owner_url) as conn:
        left = conn.execute(
            "SELECT count(*) FROM knowledge.entries WHERE tenant_id = %s AND id = %s",
            (world.tenant, note["id"]),
        ).fetchone()
    assert left == (0,)
    assert evidence(world, "knowledge.personal.private-purged") == [
        {"review": "leaver-1:run-1", "purgedPrivateEntries": 2}
    ]
    assert on.open("leaver-1:run-1").status_code == 200  # a repeat purges nothing more
    assert len(evidence(world, "knowledge.personal.private-purged")) == 1


def test_only_private_entries_look_exactly_like_an_empty_layer(world, on) -> None:
    a = world.client(A)
    capture(a, KEY, private=True, body=BODY)
    private_only = svc_open(on).json()
    empty = on.open("leaver-2:run-1", person=X)
    assert empty.status_code == 201
    ignore = ("id", "person", "openedAt", "closedAt", "deadline")

    def view(review):
        return {k: v for k, v in review.items() if k not in ignore}

    assert view(private_only) == view(empty.json())
    assert private_only["status"] == "closed" and private_only["outcome"] == "empty"
    assert personal(a) == {} and remaining(world, [BODY, KEY]) == {}
    assert evidence(world, "knowledge.personal.private-purged") == [
        {"review": "leaver-1:run-1", "purgedPrivateEntries": 1}
    ]


def test_the_flag_and_the_layer_cannot_change_while_frozen(world, on) -> None:
    a = world.client(A)
    shared = capture(a, "shared-note")
    svc_open(on)
    assert visibility(a, shared["id"], True).status_code == 409
    late = a.post(
        "/v1/knowledge/personal/entries",
        json={"key": "late", "type": "fact", "title": "t", "body": "b", "private": True},
    )
    assert late.status_code == 409
    assert personal(a) == {"shared-note": personal(a)["shared-note"]}
    assert personal(a)["shared-note"]["private"] is False


# Through an assistant: one way -----------------------------------------------------------

PERSON = uuid.UUID("7f000000-0000-4000-8000-00000000000a")
CONSOLE = uuid.UUID("7f000000-0000-4000-8000-0000000c0501")


@pytest.fixture
def clients(entra_world):
    ew = entra_world
    world = ew.world
    world.knowledge.private_entries = True
    entra.allow_assistant(world.db.owner_url, world.tenant, CONSOLE, "Muistamo console", "console")
    assistant = ew.client(ew.directory.token(PERSON))
    console = ew.client(ew.directory.token(PERSON, azp=str(CONSOLE)))
    return assistant, console


def test_an_assistant_can_make_an_entry_private_but_never_shared(clients) -> None:
    assistant, console = clients
    note = capture(assistant, "my-note")
    assert visibility(assistant, note["id"], True).status_code == 200
    refused = visibility(assistant, note["id"], False)
    assert refused.status_code == 403 and "console" in refused.json()["detail"]
    # Refused before any lookup: nothing to learn about which ids exist.
    assert visibility(assistant, uuid.uuid4(), False).status_code == 403
    assert personal(assistant)["my-note"]["private"] is True
    assert visibility(console, note["id"], False).status_code == 200
    assert personal(console)["my-note"]["private"] is False


def test_an_assistant_cannot_delete_a_private_entry(clients) -> None:
    """Delete and re-capture would make it shared: console only."""
    assistant, console = clients
    note = capture(assistant, "my-note", private=True)
    path = f"/v1/knowledge/personal/entries/{note['id']}"
    refused = assistant.delete(path)
    assert refused.status_code == 403 and "console" in refused.json()["detail"]
    assert "my-note" in personal(assistant)  # the delete was rolled back
    shared = capture(assistant, "shared-note")
    assert assistant.delete(f"/v1/knowledge/personal/entries/{shared['id']}").status_code == 204
    assert console.delete(path).status_code == 204


# Art 15 ----------------------------------------------------------------------------------


def test_the_access_export_includes_private_entries_for_the_person_and_officers(world, on) -> None:
    """The person's right of access covers their private entries, and a privacy officer can
    export them (the plan states this). Nobody else can."""
    capture(world.client(A), KEY, private=True, body=BODY)
    subject = {"subject": {"identities": ["dev:" + A], "email": A}}
    for person in (A, DPO):
        res = world.client(person).post("/v1/knowledge/privacy/access", json=subject)
        assert res.status_code == 200 and BODY in res.text, person
    assert world.client(M).post("/v1/knowledge/privacy/access", json=subject).status_code == 403


# Defence in depth: the filters hold even if a private row reached an open review ------------


def test_a_private_row_in_an_open_review_is_never_shown_or_merged(world, on) -> None:
    """The purge at opening normally leaves no private row to filter; this sets one directly
    (as the schema owner) to prove the review's own filters."""
    a = world.client(A)
    shared = capture(a, "shared-note", body=BODY)
    capture(a, "other-note")
    svc_open(on)
    with psycopg.connect(world.db.owner_url) as conn, conn.transaction():
        conn.execute("SELECT set_config('muistamo.tenant_id', %s, true)", (str(world.tenant),))
        conn.execute(
            "UPDATE knowledge.personal_entries SET private = true WHERE entry_id = %s",
            (shared["id"],),
        )
    got = world.client(M).get("/v1/knowledge/leaver-reviews/leaver-1:run-1")
    assert [e["key"] for e in got.json()["entries"]] == ["other-note"]
    assert BODY not in got.text
    merge = world.client(M).post(
        "/v1/knowledge/leaver-reviews/leaver-1:run-1/decision",
        json={
            "decision": "merge",
            "reason": "x",
            "pack": "basics",
            "entryIds": [shared["id"]],
            "summary": "s",
        },
    )
    assert merge.status_code == 404, merge.text


def test_the_review_count_excludes_private_rows_on_its_own(world, on, monkeypatch) -> None:
    from muistamo_knowledge.leavers import Leavers

    monkeypatch.setattr(Leavers, "_purge_private", lambda self, cur, person: 0)
    a = world.client(A)
    capture(a, "shared-note")
    capture(a, KEY, private=True)
    assert svc_open(on).json()["entryCount"] == 1
