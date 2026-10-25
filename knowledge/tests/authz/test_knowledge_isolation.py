"""Adversarial suite for the knowledge core. Never skip or weaken (CLAUDE.md invariants 1-3).

Person B and tenant B attack person A's personal layer, proposals and tenant data through the
API and through direct SQL as the knowledge service's own role.
"""

import uuid

import psycopg
import pytest
from muistamo_knowledge import auth
from muistamo_knowledge.leavers import Leavers, set_service_secret
from muistamo_knowledge.privacy import PERSONAL_DATA_TABLES, replace_officers, rows_mentioning

pytestmark = pytest.mark.authz

DPO = "dpo@example.invalid"
LEAVER = "leaver-l@example.invalid"
SEEDED_ERASURE = "6f1c2c1e-1d0b-4b0e-9a54-6a3f1c2b7d10"
SERVICE_SECRET = b"mks_tenant-1-test-only-not-a-secret-000000"

PACK = {
    "apiVersion": "muistamo.dev/v1",
    "kind": "KnowledgePack",
    "metadata": {"name": "equity-research-basics"},
    "spec": {
        "layer": "role",
        "reviewers": ["dev:reviewer-r@example.invalid"],
        "mergePolicy": {"requires": ["review"]},
    },
}
A, B, R = "person-a@example.invalid", "person-b@example.invalid", "reviewer-r@example.invalid"
TABLES = [
    "tenants",
    "packs",
    "entries",
    "personal_entries",
    "pack_versions",
    "proposals",
    "proposal_entries",
    "pack_version_entries",
    "evidence_heads",
    "evidence_events",
    "reads",
    "privacy_officers",
    "erasure_requests",
    "service_secrets",
    "leaver_reviews",
]


def entry(key: str, body: str) -> dict:
    return {"key": key, "type": "fact", "title": key, "body": body}


def seed(world) -> dict:
    """Person A has a personal entry and an open proposal in tenant 1."""
    a = world.client(A)
    assert a.put("/v1/knowledge/packs/equity-research-basics", json=PACK).status_code == 201
    private = a.post(
        "/v1/knowledge/personal/entries", json=entry("a-private", "A's private working note")
    ).json()
    proposed = a.post(
        "/v1/knowledge/personal/entries", json=entry("fiscal-year", "Ends 30 June.")
    ).json()
    proposal = a.post(
        "/v1/knowledge/proposals",
        json={"pack": "equity-research-basics", "entryIds": [proposed["id"]], "summary": "s"},
    ).json()
    # A second proposal is merged, so version tables hold rows for the SQL attacks to target.
    merged = a.post(
        "/v1/knowledge/personal/entries", json=entry("report-deadline", "Ten working days.")
    ).json()
    to_merge = a.post(
        "/v1/knowledge/proposals",
        json={"pack": "equity-research-basics", "entryIds": [merged["id"]], "summary": "s"},
    ).json()
    approved = world.client(R).post(
        f"/v1/knowledge/proposals/{to_merge['id']}/decision",
        json={"decision": "approve", "reason": "ok"},
    )
    assert approved.status_code == 200, approved.text
    # One recorded read, so the reads table holds rows for the SQL attacks to target.
    assert a.get("/v1/knowledge/retrieve", params={"q": "fiscal"}).status_code == 200
    # Both tenants have a privacy officer; tenant 1 has one completed erasure (of nobody).
    for tenant in (world.tenant, world.other_tenant):
        replace_officers(world.db.owner_url, tenant, ["dev:" + DPO])
    nobody = {"identities": ["dev:nobody@example.invalid"], "email": "nobody@example.invalid"}
    done = world.client(DPO).post(
        "/v1/knowledge/privacy/erasures",
        json={"id": SEEDED_ERASURE, "reason": "seed", "subject": nobody},
    )
    assert done.status_code == 201, done.text
    # Tenant 1 has a service secret and an open review of a leaver with a private entry.
    set_service_secret(world.db.owner_url, world.tenant, SERVICE_SECRET)
    note = world.client(LEAVER).post(
        "/v1/knowledge/personal/entries", json=entry("leaver-note", "The leaver's note")
    )
    assert note.status_code == 201, note.text
    opened = Leavers(world.knowledge, auth.dev_identity).open(
        world.tenant,
        {
            "id": "leaver:1",
            "person": {"email": LEAVER},
            "deciders": [{"email": R, "kind": "manager"}],
        },
    )
    assert opened[0]["status"] == "open"
    return {"private": private["id"], "proposed": proposed["id"], "proposal": proposal["id"]}


def test_personal_layer_is_private_to_its_owner(world) -> None:
    ids = seed(world)
    b = world.client(B)
    assert b.get("/v1/knowledge/personal/entries").json()["items"] == []
    assert b.delete(f"/v1/knowledge/personal/entries/{ids['private']}").status_code == 404
    stolen = b.post(
        "/v1/knowledge/proposals",
        json={"pack": "equity-research-basics", "entryIds": [ids["private"]], "summary": "s"},
    )
    assert stolen.status_code == 404
    resolved = b.get("/v1/knowledge/resolve").json()["items"]
    assert all(i["entry"]["key"] != "a-private" for i in resolved)
    # A's entry still exists for A.
    assert [
        e["key"] for e in world.client(A).get("/v1/knowledge/personal/entries").json()["items"]
    ] == ["a-private", "fiscal-year", "report-deadline"]


def test_proposals_are_visible_to_contributor_and_reviewers_only(world) -> None:
    ids = seed(world)
    b = world.client(B)
    assert b.get(f"/v1/knowledge/proposals/{ids['proposal']}").status_code == 404
    assert b.get("/v1/knowledge/proposals", params={"role": "reviewer"}).json()["items"] == []
    assert world.client(R).get(f"/v1/knowledge/proposals/{ids['proposal']}").status_code == 200


def test_only_other_reviewers_decide_and_roll_back(world) -> None:
    ids = seed(world)
    decide = {"decision": "approve", "reason": "x"}
    # A non-reviewer gets not-found, so the proposal's existence does not leak.
    assert (
        world.client(B)
        .post(f"/v1/knowledge/proposals/{ids['proposal']}/decision", json=decide)
        .status_code
        == 404
    )
    # The contributor is refused outright.
    assert (
        world.client(A)
        .post(f"/v1/knowledge/proposals/{ids['proposal']}/decision", json=decide)
        .status_code
        == 403
    )
    # A reviewer cannot approve their own proposal.
    r = world.client(R)
    own = r.post(
        "/v1/knowledge/personal/entries", json=entry("reviewer-note", "Reviewed things.")
    ).json()
    mine = r.post(
        "/v1/knowledge/proposals",
        json={"pack": "equity-research-basics", "entryIds": [own["id"]], "summary": "s"},
    ).json()
    assert r.post(f"/v1/knowledge/proposals/{mine['id']}/decision", json=decide).status_code == 403
    assert (
        world.client(B)
        .post(
            "/v1/knowledge/packs/equity-research-basics/rollback",
            json={"toVersion": "0.0.0", "reason": "x"},
        )
        .status_code
        == 403
    )
    assert (
        world.client(R).get("/v1/knowledge/packs/equity-research-basics").json()["latestVersion"]
        == "0.1.0"
    )


def test_tenants_are_isolated_through_the_api(world) -> None:
    seed(world)
    other = world.client(A, tenant=world.other_tenant)  # the same person name in another tenant
    assert other.get("/v1/knowledge/packs").json()["items"] == []
    assert other.get("/v1/knowledge/personal/entries").json()["items"] == []
    assert other.get("/v1/knowledge/proposals").json()["items"] == []
    assert other.get("/v1/knowledge/events").json()["items"] == []
    # Tenant A's published pack cannot be exported from another tenant.
    exported = other.get("/v1/knowledge/packs/equity-research-basics/versions/latest/skills.zip")
    assert exported.status_code == 404
    # The same pack name is independent per tenant.
    assert other.put("/v1/knowledge/packs/equity-research-basics", json=PACK).status_code == 201


def _exec(url: str, tenant: uuid.UUID | None, sql: str, *args) -> Exception | None:
    with psycopg.connect(url) as conn:
        try:
            with conn.transaction():
                if tenant:
                    conn.execute(
                        "SELECT set_config('muistamo.tenant_id', %s, true)", (str(tenant),)
                    )
                conn.execute(sql, args)
        except psycopg.Error as exc:
            return exc
    return None


def _count(url: str, tenant: uuid.UUID | None, sql: str, *args) -> int:
    with psycopg.connect(url) as conn, conn.transaction():
        if tenant:
            conn.execute("SELECT set_config('muistamo.tenant_id', %s, true)", (str(tenant),))
        return conn.execute(sql, args).fetchone()[0]


def test_app_role_sees_nothing_without_a_tenant(world) -> None:
    seed(world)
    for table in TABLES:
        assert _count(world.db.app_url, None, f"SELECT count(*) FROM knowledge.{table}") == 0, table
        assert _count(world.db.owner_url, None, f"SELECT count(*) FROM knowledge.{table}") > 0, (
            f"{table}: seed proves nothing"
        )


def test_app_role_cannot_reach_another_tenant_by_sql(world) -> None:
    seed(world)
    a, b = world.tenant, world.other_tenant
    for table in TABLES:
        column = "id" if table == "tenants" else "tenant_id"
        assert (
            _count(
                world.db.app_url,
                b,
                f"SELECT count(*) FROM knowledge.{table} WHERE {column} = %s",
                a,
            )
            == 0
        ), table
    attacks = {
        "plant a pack in A": (
            "INSERT INTO knowledge.packs (tenant_id, name, layer, reviewers, document)"
            " VALUES (%s, 'planted', 'role', ARRAY['x'], '{}')",
            a,
        ),
        "plant an entry in A": (
            "INSERT INTO knowledge.entries (tenant_id, id, key, type, title, body, data_class, contributor)"
            " VALUES (%s, gen_random_uuid(), 'k', 'fact', 't', 'b', 'internal', 'x')",
            a,
        ),
        "advance A's chain head": (
            "INSERT INTO knowledge.evidence_heads (tenant_id, seq, hash) VALUES (%s, 0, repeat('ab', 32))"
            " ON CONFLICT (tenant_id) DO UPDATE SET seq = 0",
            a,
        ),
    }
    for name, (sql, arg) in attacks.items():
        err = _exec(world.db.app_url, b, sql, arg)
        assert err is not None and "row-level security" in str(err), f"{name}: {err}"
    # UPDATE of A's rows under B's policy matches nothing.
    assert (
        _exec(
            world.db.app_url,
            b,
            "UPDATE knowledge.packs SET reviewers = ARRAY['dev:attacker'] WHERE tenant_id = %s",
            a,
        )
        is None
    )
    assert (
        _count(
            world.db.owner_url,
            None,
            "SELECT count(*) FROM knowledge.packs WHERE reviewers = ARRAY['dev:attacker']",
        )
        == 0
    )


def test_evidence_and_keys_cannot_be_rewritten_by_the_app_role(world) -> None:
    seed(world)
    for sql in (
        "UPDATE knowledge.evidence_events SET actor = 'x'",
        "DELETE FROM knowledge.evidence_events",
        "DELETE FROM knowledge.evidence_signing_keys",
        "INSERT INTO knowledge.evidence_signing_keys (key_id, algorithm, public_key) VALUES (repeat('a', 32), 'ed25519', decode(repeat('ab', 32), 'hex'))",
    ):
        err = _exec(world.db.app_url, world.tenant, sql)
        assert err is not None and "permission denied" in str(err), f"{sql}: {err}"


def test_services_cannot_reach_each_others_data(world) -> None:
    with psycopg.connect(world.db.owner_url) as conn:
        outside = conn.execute(
            "SELECT count(*) FROM pg_tables WHERE schemaname NOT IN ('knowledge', 'pg_catalog', 'information_schema')"
            " AND (has_table_privilege('muistamo_knowledge_app', format('%I.%I', schemaname, tablename), 'SELECT')"
            "   OR has_table_privilege('muistamo_knowledge_app', format('%I.%I', schemaname, tablename), 'INSERT'))"
        ).fetchone()[0]
        assert outside == 0, "the knowledge role can read or write tables outside its schema"
        assert (
            conn.execute(
                "SELECT has_schema_privilege('muistamo_app', 'knowledge', 'USAGE')"
            ).fetchone()[0]
            is False
        )
        inside = conn.execute(
            "SELECT count(*) FROM pg_tables WHERE schemaname = 'knowledge'"
            " AND has_table_privilege('muistamo_app', format('%I.%I', schemaname, tablename), 'SELECT')"
        ).fetchone()[0]
        assert inside == 0, "the control plane's role can read knowledge tables"


def _mentions(world, tenant: uuid.UUID) -> dict[str, int]:
    """Per table, tenant's rows naming person A, read as the server's role."""
    out = {}
    with world.knowledge.db.in_tenant(tenant) as cur:
        for table in PERSONAL_DATA_TABLES:
            if n := len(rows_mentioning(cur, table, ["dev:" + A, A])):
                out[table] = n
    return out


def test_privacy_requests_are_tenant_scoped(world) -> None:
    seed(world)
    # Person A also exists in tenant 2, so tenant 2's officer has a real target of its own.
    a2 = world.client(A, world.other_tenant)
    assert (
        a2.post("/v1/knowledge/personal/entries", json=entry("x", "tenant 2 note")).status_code
        == 201
    )
    before = _mentions(world, world.tenant)
    assert len(before) >= 4, before

    officer2 = world.client(DPO, world.other_tenant)
    subject = {"identities": ["dev:" + A], "email": A}
    done = officer2.post(
        "/v1/knowledge/privacy/erasures",
        json={"id": str(uuid.uuid4()), "reason": "DSR", "subject": subject},
    )
    assert done.status_code == 201, done.text
    assert done.json()["counts"]["personal_entries"] == 1  # tenant 2's note only
    assert _mentions(world, world.tenant) == before, "tenant 2's erasure reached tenant 1"

    # Tenant 2's officer cannot read tenant 1's proof or export tenant 1's records.
    assert officer2.get(f"/v1/knowledge/privacy/erasures/{SEEDED_ERASURE}").status_code == 404
    export = officer2.post("/v1/knowledge/privacy/access", json={"subject": subject}).json()
    for table, rows in export["sections"].items():
        assert all(r.get("tenant_id") != str(world.tenant) for r in rows), table

    # The definer function: tenant 2's setting reaches tenant 2 only; no setting, a free-form
    # pseudonym or a short subject is refused; the server role has no other way to rewrite.
    call = "SELECT knowledge.erase_subject(%s, %s, %s)"
    pseudonym = f"erased:{uuid.uuid4()}"
    assert _exec(world.db.app_url, world.other_tenant, call, ["dev:" + A], pseudonym, []) is None
    assert _mentions(world, world.tenant) == before
    for tenant, values, name in (
        (None, ["dev:" + A], pseudonym),
        (world.other_tenant, ["dev:" + A], "attacker-chosen"),
        (world.other_tenant, [], pseudonym),
        (world.other_tenant, ["a"], pseudonym),
    ):
        err = _exec(world.db.app_url, tenant, call, values, name, [])
        assert err is not None and "erase_subject" in str(err), (tenant, values, name, err)
    for stmt in (
        "UPDATE knowledge.entries SET contributor = 'x'",
        "UPDATE knowledge.erasure_requests SET reason = 'x'",
        "INSERT INTO knowledge.privacy_officers (tenant_id, officer) VALUES (current_setting('muistamo.tenant_id')::uuid, 'dev:self')",
    ):
        err = _exec(world.db.app_url, world.other_tenant, stmt)
        assert err is not None and "permission denied" in str(err), (stmt, err)


def test_leaver_reviews_and_service_secrets_are_tenant_scoped(world) -> None:
    seed(world)
    # Tenant 2's people, even one named as decider in tenant 1, cannot see tenant 1's review.
    r2 = world.client(R, world.other_tenant)
    assert r2.get("/v1/knowledge/leaver-reviews").json()["items"] == []
    assert r2.get("/v1/knowledge/leaver-reviews/leaver:1").status_code == 404
    decision = {"decision": "purge", "reason": "x"}
    assert (
        r2.post("/v1/knowledge/leaver-reviews/leaver:1/decision", json=decision).status_code == 404
    )
    # The frozen layer is still intact in tenant 1, and tenant 1's decider still sees it.
    assert world.client(R).get("/v1/knowledge/leaver-reviews/leaver:1").status_code == 200

    # Tenant 2's own service secret cannot reach tenant 1's review either.
    secret2 = b"mks_tenant-2-test-only-not-a-secret-000000"
    set_service_secret(world.db.owner_url, world.other_tenant, secret2)
    client = world.client(A)
    for path in (
        "/v1/knowledge/internal/leaver-reviews/leaver:1/expire",
        "/v1/knowledge/internal/leaver-reviews/leaver:1/cancel",
    ):
        res = client.post(
            path,
            content=b"",
            headers={
                "X-Muistamo-Tenant": str(world.other_tenant),
                "X-Muistamo-Signature": auth.sign(secret2, b""),
            },
        )
        assert res.status_code == 404, (path, res.status_code)
    with world.knowledge.db.in_tenant(world.tenant) as cur:
        cur.execute("SELECT status FROM knowledge.leaver_reviews WHERE id = 'leaver:1'")
        assert cur.fetchone()[0] == "open"

    # The server role reads its own tenant's secret only, and writes none.
    assert (
        _count(
            world.db.app_url,
            world.other_tenant,
            "SELECT count(*) FROM knowledge.service_secrets WHERE tenant_id = %s",
            world.tenant,
        )
        == 0
    )
    for stmt in (
        "UPDATE knowledge.service_secrets SET secret = decode(repeat('ab', 32), 'hex')",
        "INSERT INTO knowledge.service_secrets (tenant_id, secret) VALUES (current_setting('muistamo.tenant_id')::uuid, decode(repeat('ab', 32), 'hex'))",
    ):
        err = _exec(world.db.app_url, world.other_tenant, stmt)
        assert err is not None and "permission denied" in str(err), (stmt, err)
    err = _exec(
        world.db.app_url,
        world.other_tenant,
        "UPDATE knowledge.leaver_reviews SET status = 'closed', outcome = 'cancelled' WHERE tenant_id = %s",
        world.tenant,
    )
    assert err is None
    with world.knowledge.db.in_tenant(world.tenant) as cur:
        cur.execute("SELECT status FROM knowledge.leaver_reviews WHERE id = 'leaver:1'")
        assert cur.fetchone()[0] == "open", "tenant 2 closed tenant 1's review by SQL"
