"""Adversarial suite: only knowledge administrators create a pack (docs/knowledge-admins-plan.md,
migration 0015). Creating a pack names its reviewers, who decide what it says, and a template may
already name it: anyone else creating it would decide what that template's agents are told.
Changing a pack stays with its reviewers; mandatory packs with the privacy officers. Never skip
or weaken.

HUMAN REVIEW REQUIRED (CLAUDE.md): authorisation and the erasure path.
"""

from __future__ import annotations

import psycopg
import pytest
from muistamo_knowledge import service
from muistamo_knowledge.privacy import replace_officers

pytestmark = pytest.mark.authz

ADMIN, R, X, DPO = (
    "platform-admin@example.invalid",
    "knowledge-owner@example.invalid",
    "colleague-x@example.invalid",
    "dpo@example.invalid",
)
REFUSED = "only knowledge administrators can create a pack"


def pack(name: str = "finance", reviewers: list[str] | None = None, **spec) -> dict:
    return {
        "apiVersion": "muistamo.dev/v1",
        "kind": "KnowledgePack",
        "metadata": {"name": name},
        "spec": {
            "layer": spec.pop("layer", "role"),
            "reviewers": reviewers or ["dev:" + R],
            "mergePolicy": {"requires": ["review"]},
            **spec,
        },
    }


def applied(world) -> list:
    return [e for e in world.all_events() if e.action == "knowledge.pack.applied"]


@pytest.fixture
def admins(world):
    world.admins(ADMIN)
    replace_officers(world.db.owner_url, world.tenant, ["dev:" + DPO])
    return world


def test_a_colleague_cannot_create_a_pack_and_name_themselves_its_reviewer(admins) -> None:
    world = admins
    res = world.client(X).put("/v1/knowledge/packs/finance", json=pack(reviewers=["dev:" + X]))
    assert res.status_code == 403 and REFUSED in res.json()["detail"]
    assert world.client(X).get("/v1/knowledge/packs/finance").status_code == 404
    assert applied(world) == []


def test_an_administrator_creates_a_pack_for_its_knowledge_owners(admins) -> None:
    world = admins
    res = world.client(ADMIN).put("/v1/knowledge/packs/finance", json=pack())
    assert res.status_code == 201, res.text
    assert len(applied(world)) == 1
    # The knowledge owner named as reviewer changes it; the administrator, not a reviewer, cannot.
    changed = pack(reviewers=["dev:" + R, "dev:second-owner@example.invalid"])
    assert world.client(ADMIN).put("/v1/knowledge/packs/finance", json=changed).status_code == 403
    assert world.client(R).put("/v1/knowledge/packs/finance", json=changed).status_code == 200
    # Nor can a colleague, even with the administrator's document.
    assert world.client(X).put("/v1/knowledge/packs/finance", json=pack()).status_code == 403


def test_reapplying_an_identical_document_returns_it_unchanged(admins) -> None:
    """Idempotent re-applies (Terraform) return the stored pack, which anyone may read anyway."""
    world = admins
    assert world.client(ADMIN).put("/v1/knowledge/packs/finance", json=pack()).status_code == 201
    before = len(world.all_events())
    again = world.client(X).put("/v1/knowledge/packs/finance", json=pack())
    assert again.status_code == 200
    assert len(world.all_events()) == before


def test_mandatory_packs_stay_with_the_privacy_officers(admins) -> None:
    world = admins
    rules = pack("rules", layer="company", mandatory=True)
    res = world.client(ADMIN).put("/v1/knowledge/packs/rules", json=rules)
    assert res.status_code == 403 and "privacy officers" in res.json()["detail"]
    assert world.client(DPO).put("/v1/knowledge/packs/rules", json=rules).status_code == 201


def test_a_privacy_officer_who_is_no_administrator_cannot_create_an_ordinary_pack(admins) -> None:
    world = admins
    assert world.client(DPO).put("/v1/knowledge/packs/finance", json=pack()).status_code == 403


def test_administrators_are_per_tenant(admins) -> None:
    world = admins
    other = world.client(ADMIN, tenant=world.other_tenant)
    assert other.put("/v1/knowledge/packs/finance", json=pack()).status_code == 403


def test_with_no_administrators_nobody_creates_a_pack(world) -> None:
    """Fail closed: a tenant whose operator has named nobody."""
    for person in (ADMIN, R, X):
        assert (
            world.client(person).put("/v1/knowledge/packs/finance", json=pack()).status_code == 403
        )


def test_the_server_role_cannot_change_the_list(admins) -> None:
    world = admins
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with world.knowledge.db.in_tenant(world.tenant) as cur:
            cur.execute(
                "INSERT INTO knowledge.knowledge_admins (tenant_id, admin) VALUES (%s, %s)",
                (world.tenant, "dev:" + X),
            )
    with world.knowledge.db.in_tenant(world.tenant) as cur:
        assert service.is_knowledge_admin(cur, "dev:" + ADMIN)
        assert not service.is_knowledge_admin(cur, "dev:" + X)


def test_erasure_removes_the_administrator(admins) -> None:
    world = admins
    res = world.client(DPO).post(
        "/v1/knowledge/privacy/erasures",
        json={
            "id": "5a1e0000-0000-4000-8000-000000000001",
            "reason": "Art 17 request",
            "subject": {"identities": ["dev:" + ADMIN], "email": ADMIN},
        },
    )
    assert res.status_code in (200, 201), res.text
    with world.knowledge.db.in_tenant(world.tenant) as cur:
        assert not service.is_knowledge_admin(cur, "dev:" + ADMIN)
    assert world.client(ADMIN).put("/v1/knowledge/packs/finance", json=pack()).status_code == 403


def test_the_operator_command_replaces_the_list(world) -> None:
    import os
    import subprocess
    import sys

    def cli(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run(  # noqa: S603 - this test's own fixed command
            [sys.executable, "-m", "muistamo_knowledge", "tenant", "knowledge-admins", *args],
            env={**os.environ, "MUISTAMO_KNOWLEDGE_MIGRATE_DATABASE_URL": world.db.owner_url},
            capture_output=True,
            text=True,
            timeout=60,
        )

    done = cli(str(world.tenant), "dev:" + ADMIN)
    assert done.returncode == 0, done.stderr
    assert world.client(ADMIN).put("/v1/knowledge/packs/finance", json=pack()).status_code == 201
    assert cli(str(world.tenant), "dev:" + R).returncode == 0  # replaces, never appends
    assert (
        world.client(ADMIN).put("/v1/knowledge/packs/legal", json=pack("legal")).status_code == 403
    )
    assert cli("not-a-uuid", "dev:" + R).returncode != 0
    assert cli(str(world.tenant), "x\ny").returncode != 0  # the table refuses control characters
    assert cli(str(world.tenant), "alice@example.invalid").returncode != 0  # no scheme
    assert (
        cli(str(world.tenant), "dev:" + "x" * 317).returncode != 0
    )  # the table: at most 320 characters


def test_an_officer_cannot_turn_a_mandatory_pack_into_an_ordinary_one_alone(admins) -> None:
    """Otherwise an officer would create an ordinary pack in two calls: mandatory, then not."""
    world = admins
    rules = pack("finance", layer="company", mandatory=True)
    assert world.client(DPO).put("/v1/knowledge/packs/finance", json=rules).status_code == 201
    ordinary = pack("finance", reviewers=["dev:" + DPO])
    res = world.client(DPO).put("/v1/knowledge/packs/finance", json=ordinary)
    assert res.status_code == 403 and "knowledge administrator" in res.json()["detail"]
    stored = world.client(DPO).get("/v1/knowledge/packs/finance").json()
    assert stored["document"]["spec"]["mandatory"] is True
    world.admins(ADMIN, DPO)  # an officer who is also an administrator may
    assert world.client(DPO).put("/v1/knowledge/packs/finance", json=ordinary).status_code == 200


def test_the_server_role_can_neither_update_nor_delete_the_list(admins) -> None:
    world = admins
    for sql in (
        "UPDATE knowledge.knowledge_admins SET admin = 'dev:someone-else@example.invalid'",
        "DELETE FROM knowledge.knowledge_admins",
    ):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with world.knowledge.db.in_tenant(world.tenant) as cur:
                cur.execute(sql)


def test_every_table_that_can_hold_an_identity_is_classified(world) -> None:
    """A new table with a text column is personal data (access export, erasure scan) unless it
    is named here as holding none."""
    from muistamo_knowledge.privacy import PERSONAL_DATA_TABLES

    holds_no_identity = {
        "documents",  # copies of company documents (privacy.py says why)
        "evidence_heads",
        "evidence_signing_keys",
        "assistants",  # client apps and their display names
    }
    with psycopg.connect(world.db.owner_url) as conn:
        rows = conn.execute(
            "SELECT DISTINCT table_name FROM information_schema.columns"
            " WHERE table_schema = 'knowledge' AND data_type IN ('text', 'jsonb', 'ARRAY')"
        ).fetchall()
    tables = {r[0] for r in rows}
    unclassified = tables - set(PERSONAL_DATA_TABLES) - holds_no_identity
    assert unclassified == set(), unclassified
