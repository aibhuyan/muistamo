"""Decay and provenance (FR-307): entries a reviewer no longer vouches for are flagged, then
withheld, then removed; provenance explains how far to trust each entry. Time is moved with the
service's clock, never waited for."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
import pytest
from muistamo_knowledge.privacy import replace_officers

A, R, B, DPO = (
    "person-a@example.invalid",
    "reviewer-r@example.invalid",
    "bystander-b@example.invalid",
    "dpo@example.invalid",
)


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 1, 1, 9, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, days: float) -> None:
        self.now += timedelta(days=days)


def pack(name: str, layer: str = "role", every: int = 10, grace: int = 5, **spec) -> dict:
    return {
        "apiVersion": "muistamo.dev/v1",
        "kind": "KnowledgePack",
        "metadata": {"name": name},
        "spec": {
            "layer": layer,
            "reviewers": ["dev:" + R],
            "mergePolicy": {"requires": ["review"]},
            "decay": {"reviewEveryDays": every, "graceDays": grace},
            **spec,
        },
    }


def merge(
    world, pack_name: str, key: str, body: str, source: str | None = None, edit: str | None = None
):
    a = world.client(A)
    entry = {"key": key, "type": "fact", "title": key, "body": body}
    if source:
        entry["source"] = source
    captured = a.post("/v1/knowledge/personal/entries", json=entry).json()
    p = a.post(
        "/v1/knowledge/proposals",
        json={"pack": pack_name, "entryIds": [captured["id"]], "summary": "s"},
    ).json()
    decision = {"decision": "approve", "reason": "ok"}
    if edit:
        decision["edits"] = [{"key": key, "body": edit}]
    d = world.client(R).post(f"/v1/knowledge/proposals/{p['id']}/decision", json=decision)
    assert d.status_code == 200, d.text
    assert a.delete(f"/v1/knowledge/personal/entries/{captured['id']}").status_code == 204
    return d.json()


def resolved(world, person: str = A, packs: str = "") -> dict:
    res = world.client(person).get("/v1/knowledge/resolve", params={"packs": packs})
    assert res.status_code == 200, res.text
    return {i["entry"]["key"]: i for i in res.json()["items"]}


def queue(world, person: str = R) -> list[dict]:
    res = world.client(person).get("/v1/knowledge/verifications")
    assert res.status_code == 200, res.text
    return res.json()["items"]


def verification(world, pack_name: str, key: str, reason: str) -> dict:
    latest = world.client(R).get(f"/v1/knowledge/packs/{pack_name}").json()["latestVersion"]
    entries = (
        world.client(R).get(f"/v1/knowledge/packs/{pack_name}/versions/{latest}").json()["entries"]
    )
    entry_id = next(e["entry"]["id"] for e in entries if e["entry"]["key"] == key)
    return {"entryId": entry_id, "reason": reason}


def events(world, action: str) -> list:
    return [e for e in world.knowledge.events(world.actor(R), 0, 1000) if e.action == action]


@pytest.fixture
def clock(world) -> Clock:
    c = Clock()
    world.knowledge.clock = c
    return c


@pytest.fixture
def rules(world, clock):
    """A role pack, reviewed by R, whose confirmations last 10 days plus 5 days' grace."""
    assert world.client(R).put("/v1/knowledge/packs/rules", json=pack("rules")).status_code == 201
    merge(world, "rules", "expenses", "Claims over 500 EUR need a manager's approval.")
    return world


def test_an_entry_goes_current_then_due_then_expired(rules, clock) -> None:
    world = rules
    got = resolved(world, packs="rules")["expenses"]
    assert got["decay"]["status"] == "current"
    assert got["decay"]["verifiedBy"] == "dev:" + R
    assert got["decay"]["dueAt"].startswith("2026-01-11")
    assert got["decay"]["expiresAt"].startswith("2026-01-16")
    assert queue(world) == []

    # Due: still served, flagged, and queued for the pack's reviewers.
    clock.advance(10)
    got = resolved(world, packs="rules")["expenses"]
    assert got["decay"]["status"] == "due"
    assert [(v["pack"], v["entry"]["key"], v["decay"]["status"]) for v in queue(world)] == [
        ("rules", "expenses", "due")
    ]
    assert queue(world, B) == []  # not a reviewer of the pack

    # One second before the grace ends it is still served; at the end it is not.
    clock.advance(5 - 1 / 86400)
    assert "expenses" in resolved(world, packs="rules")
    clock.advance(1 / 86400)
    assert "expenses" not in resolved(world, packs="rules")


def test_an_expired_entry_is_withheld_everywhere_before_any_sweep(rules, clock) -> None:
    world = rules
    a = world.client(A)
    assert a.get(
        "/v1/knowledge/retrieve", params={"q": "manager approval", "packs": "rules"}
    ).json()["items"]
    clock.advance(15)
    assert "expenses" not in resolved(world, packs="rules")
    assert (
        a.get("/v1/knowledge/retrieve", params={"q": "manager approval", "packs": "rules"}).json()[
            "items"
        ]
        == []
    )
    mcp = world.mcp(A, "search_knowledge", {"query": "manager approval", "packs": ["rules"]})
    assert not mcp.is_error and mcp.structured_content["results"] == []
    # It is still in the pack until the sweep, and the reviewers see it as expired.
    latest = world.client(R).get("/v1/knowledge/packs/rules").json()["latestVersion"]
    version = world.client(R).get(f"/v1/knowledge/packs/rules/versions/{latest}").json()
    assert [e["entry"]["key"] for e in version["entries"]] == ["expenses"]
    assert [v["decay"]["status"] for v in queue(world)] == ["expired"]


def test_a_lower_layer_takes_over_an_expired_key(rules, clock) -> None:
    world = rules
    assert (
        world.client(R)
        .put("/v1/knowledge/packs/company-rules", json=pack("company-rules", "company", every=365))
        .status_code
        == 201
    )
    merge(
        world, "company-rules", "expenses", "Company default: claims over 1000 EUR need approval."
    )
    assert resolved(world, packs="rules,company-rules")["expenses"]["pack"] == "rules"
    clock.advance(15)
    assert resolved(world, packs="rules,company-rules")["expenses"]["pack"] == "company-rules"


def test_a_reviewer_confirms_an_entry_and_its_clock_restarts(rules, clock) -> None:
    world = rules
    clock.advance(12)
    res = world.client(R).post(
        "/v1/knowledge/packs/rules/entries/expenses/verification",
        json=verification(world, "rules", "expenses", "still policy"),
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["decay"]["status"] == "current" and body["decay"]["verifiedAt"].startswith(
        "2026-01-13"
    )
    assert queue(world) == []
    [ev] = events(world, "knowledge.entry.verified")
    assert ev.actor == "dev:" + R and ev.before["status"] == "due"
    assert ev.after["key"] == "expenses" and ev.after["reason"] == "still policy"
    # The clock really restarted: ten more days before it is due again.
    clock.advance(9)
    assert resolved(world, packs="rules")["expenses"]["decay"]["status"] == "current"


def test_an_expired_entry_can_still_be_confirmed_until_the_sweep(rules, clock) -> None:
    world = rules
    clock.advance(20)
    assert "expenses" not in resolved(world, packs="rules")
    res = world.client(R).post(
        "/v1/knowledge/packs/rules/entries/expenses/verification",
        json=verification(world, "rules", "expenses", "checked"),
    )
    assert res.status_code == 200, res.text
    assert resolved(world, packs="rules")["expenses"]["decay"]["status"] == "current"


def test_only_reviewers_other_than_the_contributor_confirm(world, clock) -> None:
    shared = pack("shared")
    shared["spec"]["reviewers"] = ["dev:" + R, "dev:" + A]
    assert world.client(R).put("/v1/knowledge/packs/shared", json=shared).status_code == 201
    merge(world, "shared", "k", "A's knowledge, approved by R.")
    url = "/v1/knowledge/packs/shared/entries/k/verification"
    # A reviews the pack but contributed the entry: vouching for oneself is no check.
    res = world.client(A).post(url, json=verification(world, "shared", "k", "mine"))
    assert res.status_code == 403 and "own entry" in res.text
    assert (
        world.client(B).post(url, json=verification(world, "shared", "k", "x")).status_code == 403
    )
    assert (
        world.client(R)
        .post(
            "/v1/knowledge/packs/shared/entries/nope/verification",
            json=verification(world, "shared", "k", "x"),
        )
        .status_code
        == 404
    )
    assert world.client(R).post(url, json=verification(world, "shared", "k", "")).status_code == 422
    assert events(world, "knowledge.entry.verified") == []
    assert (
        world.client(R).post(url, json=verification(world, "shared", "k", "ok")).status_code == 200
    )


def test_the_sweep_removes_expired_entries_and_rollback_restores_them(rules, clock) -> None:
    world = rules
    merge(world, "rules", "travel", "Book trains under 600 km.")
    clock.advance(8)
    # Confirm travel only, so that just expenses expires.
    assert (
        world.client(R)
        .post(
            "/v1/knowledge/packs/rules/entries/travel/verification",
            json=verification(world, "rules", "travel", "ok"),
        )
        .status_code
        == 200
    )
    clock.advance(8)
    before = world.client(R).get("/v1/knowledge/packs/rules").json()["latestVersion"]

    assert world.knowledge.sweep_decay(world.tenant) == {"rules": ["expenses"]}
    after = world.client(R).get("/v1/knowledge/packs/rules").json()["latestVersion"]
    version = world.client(R).get(f"/v1/knowledge/packs/rules/versions/{after}").json()
    assert version["parent"] == before and version["createdBy"] == "system:decay"
    assert "decay: expired unconfirmed (expenses)" in version["reason"]
    assert [e["entry"]["key"] for e in version["entries"]] == ["travel"]
    [expired] = events(world, "knowledge.entry.expired")
    assert expired.before["key"] == "expenses" and expired.after == {"removedIn": after}
    published = events(world, "knowledge.pack.version.published")[-1]
    assert expired.seq < published.seq  # evidence before the removal

    # Idempotent: nothing more to remove, no new version.
    assert world.knowledge.sweep_decay(world.tenant) == {}
    assert world.client(R).get("/v1/knowledge/packs/rules").json()["latestVersion"] == after
    assert queue(world) == []

    # Rolling back restores it, vouched for afresh by whoever rolled back.
    res = world.client(R).post(
        "/v1/knowledge/packs/rules/rollback", json={"toVersion": before, "reason": "still needed"}
    )
    assert res.status_code == 201, res.text
    got = resolved(world, packs="rules")
    assert got["expenses"]["decay"]["status"] == "current"
    assert got["expenses"]["decay"]["verifiedAt"] == clock.now.isoformat()
    # travel was not restored, so it keeps its own clock.
    assert got["travel"]["decay"]["verifiedAt"] != clock.now.isoformat()


def test_mandatory_packs_are_flagged_never_removed(world, clock) -> None:
    replace_officers(world.db.owner_url, world.tenant, ["dev:" + DPO])
    rules = pack("company-rules", "company", every=10, grace=0, mandatory=True)
    assert world.client(DPO).put("/v1/knowledge/packs/company-rules", json=rules).status_code == 201
    merge(world, "company-rules", "data-handling", "Client data stays in the EU vault.")
    clock.advance(400)

    got = resolved(world)["data-handling"]
    assert got["decay"]["status"] == "due" and "expiresAt" not in got["decay"]
    assert world.knowledge.sweep_decay(world.tenant) == {}
    assert "data-handling" in resolved(world)
    # Privacy officers see it and may confirm it, though they do not review the pack.
    [item] = queue(world, DPO)
    assert item["mandatory"] is True and item["decay"]["status"] == "due"
    res = world.client(DPO).post(
        "/v1/knowledge/packs/company-rules/entries/data-handling/verification",
        json=verification(world, "company-rules", "data-handling", "still the rule"),
    )
    assert res.status_code == 200, res.text
    assert resolved(world)["data-handling"]["decay"]["status"] == "current"


def test_provenance_is_explained_and_never_changes_ranking(world, clock) -> None:
    assert world.client(R).put("/v1/knowledge/packs/rules", json=pack("rules")).status_code == 201
    merge(
        world,
        "rules",
        "sourced",
        "Fiscal year ends 30 June.",
        source="https://intranet.example.invalid/finance",
        edit="The fiscal year ends on 30 June.",
    )
    merge(world, "rules", "bare", "Fiscal year planning starts in March.")
    got = resolved(world, packs="rules")
    assert got["sourced"]["provenance"] == {
        "score": 100,
        "factors": [
            {"factor": "reviewed", "points": 40},
            {"factor": "source", "points": 20},
            {"factor": "reviewer-edited", "points": 10},
            {"factor": "freshness", "points": 30},
        ],
    }
    assert got["bare"]["provenance"]["score"] == 70
    clock.advance(10)
    assert resolved(world, packs="rules")["bare"]["provenance"]["score"] == 50

    # A personal entry: nobody reviewed it and it does not decay.
    world.client(A).post(
        "/v1/knowledge/personal/entries",
        json={
            "key": "note",
            "type": "fact",
            "title": "note",
            "body": "My fiscal year note.",
            "source": "me",
        },
    )
    mine = resolved(world, packs="rules")["note"]
    assert mine["provenance"] == {"score": 20, "factors": [{"factor": "source", "points": 20}]}
    assert "decay" not in mine

    # Retrieval carries provenance but ranks by text relevance alone.
    items = (
        world.client(A)
        .get("/v1/knowledge/retrieve", params={"q": "fiscal year", "packs": "rules"})
        .json()["items"]
    )
    entries = [i for i in items if i["citation"]["type"] == "entry"]
    assert all("provenance" in i for i in entries)
    assert [i["score"] for i in entries] == sorted((i["score"] for i in entries), reverse=True)


def _backfill_sql() -> str:
    """The migration's backfill section: row security off, the insert, the count check."""
    sql = (Path(__file__).parents[1] / "migrations" / "0007_decay.sql").read_text(encoding="utf-8")
    start = sql.index("SET LOCAL row_security = off;")
    end = sql.index("SET LOCAL row_security = on;")
    return sql[start:end]


def test_the_migration_backfills_who_last_verified_each_entry(rules, clock) -> None:
    world = rules
    merge(world, "rules", "old-rule", "Approved long before decay existed.")
    with psycopg.connect(world.db.owner_url) as conn:
        # One entry was approved two years ago; the pack's review interval is 10 days.
        conn.execute(
            "UPDATE knowledge.proposals SET decided_at = now() - interval '2 years'"
            " WHERE id IN (SELECT proposal_id FROM knowledge.pack_version_entries WHERE key = 'old-rule')"
        )
        conn.execute("DELETE FROM knowledge.verifications")
        with conn.transaction():
            conn.execute(_backfill_sql())
        rows = dict(
            (r[0], r[1:])
            for r in conn.execute(
                "SELECT e.key, v.verified_by, v.verified_at = p.decided_at, v.reason,"
                " v.verified_at > now() - interval '10 days 1 minute'"
                " FROM knowledge.verifications v"
                " JOIN knowledge.pack_version_entries e ON e.tenant_id = v.tenant_id AND e.entry_id = v.entry_id"
                "  AND e.version = (SELECT latest_version FROM knowledge.packs WHERE name = e.pack)"
                " JOIN knowledge.proposals p ON p.tenant_id = e.tenant_id AND p.id = e.proposal_id"
            ).fetchall()
        )
    assert rows["expenses"] == ("dev:" + R, True, "merged (backfilled)", True)
    # The old entry does not expire the moment decay is switched on: it starts due, with grace.
    by, exact, reason, floored = rows["old-rule"]
    assert by == "dev:" + R and not exact and floored
    assert reason == "merged before decay existed (backfilled; due when decay began)"
    clock.now = datetime.now(UTC)
    got = resolved(world, B, packs="rules")
    assert got["old-rule"]["decay"]["status"] == "due"
    assert got["expenses"]["decay"]["status"] == "current"


def test_the_backfill_fails_loudly_rather_than_silently_skipping(rules) -> None:
    """A migration role that row-level security would filter must not 'succeed' with nothing
    backfilled: every published entry would then count as unverified and be withheld."""
    with psycopg.connect(rules.db.app_url) as conn:  # a role without BYPASSRLS
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="row-level security"):
            with conn.transaction():
                conn.execute(_backfill_sql())


def test_the_server_role_cannot_rewrite_or_delete_verifications(rules) -> None:
    with psycopg.connect(rules.db.app_url) as conn, conn.transaction():
        conn.execute("SELECT set_config('muistamo.tenant_id', %s, true)", (str(rules.tenant),))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("UPDATE knowledge.verifications SET verified_at = now()")
    with psycopg.connect(rules.db.app_url) as conn, conn.transaction():
        conn.execute("SELECT set_config('muistamo.tenant_id', %s, true)", (str(rules.tenant),))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("DELETE FROM knowledge.verifications")


def test_the_sweep_command_sweeps_named_tenants_and_fails_loudly(
    rules, clock, tmp_path, monkeypatch, capsys
) -> None:
    """The scheduled entry point, not just the method: the server role cannot list tenants (row-level
    security), so tenants are named, and an unknown one is an error, never a silent no-op."""
    from muistamo_knowledge import __main__ as cli
    from muistamo_knowledge import evidence

    world = rules
    key, pem = evidence.LocalKey.generate()
    (tmp_path / "k.key").write_bytes(pem)
    with psycopg.connect(world.db.owner_url) as conn:
        conn.execute(
            "INSERT INTO knowledge.evidence_signing_keys (key_id, algorithm, public_key) VALUES (%s, 'ed25519', %s)",
            (key.key_id, key.public_raw()),
        )
    monkeypatch.setenv("MUISTAMO_KNOWLEDGE_DATABASE_URL", world.db.app_url)
    monkeypatch.setenv("MUISTAMO_KNOWLEDGE_EVIDENCE_KEY_FILE", str(tmp_path / "k.key"))
    # The command runs on the wall clock: back-date the confirmation far enough to have expired.
    with psycopg.connect(world.db.owner_url) as conn:
        conn.execute(
            "UPDATE knowledge.verifications SET verified_at = verified_at - interval '10 years'"
        )

    monkeypatch.setattr(
        "sys.argv", ["muistamo_knowledge", "decay", "sweep", "--tenant", str(world.tenant)]
    )
    cli.main()
    assert (
        f'"removed": {{"rules": ["expenses"]}}, "tenant": "{world.tenant}"'
        in capsys.readouterr().out
    )

    unknown = "00000000-0000-4000-8000-000000000000"
    monkeypatch.setattr(
        "sys.argv",
        [
            "muistamo_knowledge",
            "decay",
            "sweep",
            "--tenant",
            str(world.tenant),
            "--tenant",
            unknown,
        ],
    )
    with pytest.raises(SystemExit) as exited:
        cli.main()
    assert "failed for 1 tenant" in str(exited.value.code)

    monkeypatch.setattr("sys.argv", ["muistamo_knowledge", "decay", "sweep"])
    with pytest.raises(SystemExit) as exited:
        cli.main()
    assert exited.value.code == 2  # --tenant is required


def test_confirmation_refuses_a_replaced_revision(rules, clock) -> None:
    clock.advance(10)
    [shown] = queue(rules)
    merge(rules, "rules", "expenses", "The replacement policy needs a fresh review.")
    res = rules.client(R).post(
        "/v1/knowledge/packs/rules/entries/expenses/verification",
        json={"entryId": shown["entry"]["id"], "reason": "checked the old policy"},
    )
    assert res.status_code == 409, res.text
    assert events(rules, "knowledge.entry.verified") == []


@pytest.mark.parametrize("person", [A, B])
def test_only_existing_reviewers_can_change_a_pack(rules, person) -> None:
    changed = pack("rules", every=100)
    changed["spec"]["reviewers"].append("dev:" + person)
    res = rules.client(person).put("/v1/knowledge/packs/rules", json=changed)
    assert res.status_code == 403, res.text
    assert (
        rules.client(R)
        .get("/v1/knowledge/packs/rules")
        .json()["document"]["spec"]["decay"]["reviewEveryDays"]
        == 10
    )


@pytest.mark.parametrize("every,grace", [(100, 5), (10, 100)])
def test_a_contributor_cannot_extend_their_own_decay_policy(world, clock, every, grace) -> None:
    shared = pack("shared", reviewers=["dev:" + A, "dev:" + R])
    assert world.client(R).put("/v1/knowledge/packs/shared", json=shared).status_code == 201
    merge(world, "shared", "expenses", "A's policy, independently reviewed by R.")
    clock.advance(16)
    assert "expenses" not in resolved(world, B, "shared")
    changed = pack("shared", every=every, grace=grace, reviewers=shared["spec"]["reviewers"])
    res = world.client(A).put("/v1/knowledge/packs/shared", json=changed)
    assert res.status_code == 403, res.text
    assert "expenses" not in resolved(world, B, "shared")
    # An independent reviewer can change the policy for the pack.
    assert world.client(R).put("/v1/knowledge/packs/shared", json=changed).status_code == 200
    assert "expenses" in resolved(world, B, "shared")


def test_rollback_cannot_renew_the_rollers_own_expired_entry(world, clock) -> None:
    shared = pack("shared", reviewers=["dev:" + A, "dev:" + R])
    assert world.client(R).put("/v1/knowledge/packs/shared", json=shared).status_code == 201
    merge(world, "shared", "expenses", "A's knowledge.")
    before = world.client(R).get("/v1/knowledge/packs/shared").json()["latestVersion"]
    clock.advance(16)
    assert world.knowledge.sweep_decay(world.tenant) == {"shared": ["expenses"]}
    res = world.client(A).post(
        "/v1/knowledge/packs/shared/rollback", json={"toVersion": before, "reason": "restore"}
    )
    assert res.status_code == 201, res.text
    assert "expenses" not in resolved(world, B, "shared")
    assert events(world, "knowledge.entry.verified") == []
    assert queue(world, A) == []


def test_expired_skills_are_withheld_from_historical_exports(rules, clock) -> None:
    version = rules.client(R).get("/v1/knowledge/packs/rules").json()["latestVersion"]
    clock.advance(16)
    for requested in ("latest", version):
        res = rules.client(R).get(f"/v1/knowledge/packs/rules/versions/{requested}/skills.zip")
        assert res.status_code == 409, res.text
        assert "expired" in res.text
    assert events(rules, "knowledge.pack.exported") == []


def test_the_migration_backfills_historical_revisions_once(rules, clock) -> None:
    merge(rules, "rules", "travel", "Take the train.")
    historical = rules.client(R).get("/v1/knowledge/packs/rules").json()["latestVersion"]
    merge(rules, "rules", "expenses", "The new expenses policy.")
    with psycopg.connect(rules.db.owner_url) as conn:
        conn.execute("DELETE FROM knowledge.verifications")
        with conn.transaction():
            conn.execute(_backfill_sql())
        assert conn.execute("SELECT count(*) FROM knowledge.verifications").fetchone()[0] == 3
    clock.now = datetime.now(UTC)
    res = rules.client(R).get(f"/v1/knowledge/packs/rules/versions/{historical}/skills.zip")
    assert res.status_code == 200, res.text


def test_rollback_renews_an_expired_entry_before_the_sweep(rules, clock) -> None:
    version = rules.client(R).get("/v1/knowledge/packs/rules").json()["latestVersion"]
    clock.advance(16)
    assert resolved(rules, B, "rules") == {}
    res = rules.client(R).post(
        "/v1/knowledge/packs/rules/rollback",
        json={"toVersion": version, "reason": "independently checked"},
    )
    assert res.status_code == 201, res.text
    assert resolved(rules, B, "rules")["expenses"]["decay"]["status"] == "current"
    [verified] = events(rules, "knowledge.entry.verified")
    assert verified.after["key"] == "expenses"


def test_self_extension_is_refused_for_historical_entries_too(world, clock) -> None:
    shared = pack("shared", reviewers=["dev:" + A, "dev:" + R])
    assert world.client(R).put("/v1/knowledge/packs/shared", json=shared).status_code == 201
    merge(world, "shared", "expenses", "A's knowledge.")
    historical = world.client(R).get("/v1/knowledge/packs/shared").json()["latestVersion"]
    clock.advance(16)
    world.knowledge.sweep_decay(world.tenant)
    changed = pack("shared", every=100, reviewers=shared["spec"]["reviewers"])
    res = world.client(A).put("/v1/knowledge/packs/shared", json=changed)
    assert res.status_code == 403, res.text
    assert world.client(R).put("/v1/knowledge/packs/shared", json=changed).status_code == 200
    assert (
        world.client(R)
        .get(f"/v1/knowledge/packs/shared/versions/{historical}/skills.zip")
        .status_code
        == 200
    )


@pytest.mark.parametrize("action", ["confirm", "sweep"])
def test_decay_writes_roll_back_if_their_evidence_fails(rules, clock, monkeypatch, action) -> None:
    clock.advance(16)
    latest = rules.client(R).get("/v1/knowledge/packs/rules").json()["latestVersion"]
    before = rules.knowledge.events(rules.actor(R), 0, 1000)
    original = rules.knowledge._evidence

    def fail(cur, actor, event, *args, **kwargs):
        if event in ("knowledge.entry.verified", "knowledge.entry.expired"):
            raise RuntimeError("evidence unavailable")
        return original(cur, actor, event, *args, **kwargs)

    monkeypatch.setattr(rules.knowledge, "_evidence", fail)
    if action == "confirm":
        res = rules.client(R).post(
            "/v1/knowledge/packs/rules/entries/expenses/verification",
            json=verification(rules, "rules", "expenses", "checked"),
        )
        assert res.status_code == 500
    else:
        with pytest.raises(RuntimeError, match="evidence unavailable"):
            rules.knowledge.sweep_decay(rules.tenant)
    assert rules.client(R).get("/v1/knowledge/packs/rules").json()["latestVersion"] == latest
    assert queue(rules)[0]["decay"]["status"] == "expired"
    assert rules.knowledge.events(rules.actor(R), 0, 1000) == before


@pytest.mark.parametrize(
    "payload", [{"reason": "checked"}, {"entryId": "invalid", "reason": "checked"}]
)
def test_confirmation_requires_an_immutable_revision(rules, payload) -> None:
    res = rules.client(R).post(
        "/v1/knowledge/packs/rules/entries/expenses/verification", json=payload
    )
    assert res.status_code == 422, res.text
    assert events(rules, "knowledge.entry.verified") == []
