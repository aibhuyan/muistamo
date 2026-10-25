"""Agent Skills export of published pack versions over HTTP (FR-312, E14.3)."""

import hashlib
import io
import zipfile

import psycopg
from muistamo_knowledge import evidence

A, R = "person-a@example.invalid", "reviewer-r@example.invalid"
PACK = {
    "apiVersion": "muistamo.dev/v1",
    "kind": "KnowledgePack",
    "metadata": {"name": "equity-research"},
    "spec": {"layer": "role", "reviewers": ["dev:" + R], "mergePolicy": {"requires": ["review"]}},
}


def merge(world, *entries) -> str:
    a, r = world.client(A), world.client(R)
    ids = [a.post("/v1/knowledge/personal/entries", json=e).json()["id"] for e in entries]
    proposal = a.post(
        "/v1/knowledge/proposals", json={"pack": "equity-research", "entryIds": ids, "summary": "s"}
    ).json()
    return r.post(
        f"/v1/knowledge/proposals/{proposal['id']}/decision",
        json={"decision": "approve", "reason": "ok"},
    ).json()["mergedVersion"]


def unzip(content: bytes) -> dict[str, str]:
    zf = zipfile.ZipFile(io.BytesIO(content))
    return {n: zf.read(n).decode() for n in zf.namelist()}


def test_export_matches_the_published_version(world) -> None:
    a = world.client(A)
    a.put("/v1/knowledge/packs/equity-research", json=PACK)
    assert (
        merge(
            world,
            {"key": "fiscal-year", "type": "fact", "title": "Fiscal year", "body": "Ends 30 June."},
            {
                "key": "dcf",
                "type": "skill",
                "title": "DCF valuation",
                "body": "Project and discount cash flows.",
            },
            {"key": "memo", "type": "example", "title": "Good memo", "body": "Short and cited."},
        )
        == "0.1.0"
    )
    # A personal entry that is never proposed must never be exported.
    a.post(
        "/v1/knowledge/personal/entries",
        json={"key": "private", "type": "fact", "title": "Mine", "body": "My private note."},
    )

    first = a.get("/v1/knowledge/packs/equity-research/versions/latest/skills.zip")
    assert first.status_code == 200 and first.headers["content-type"] == "application/zip"
    assert first.headers["x-muistamo-pack-version"] == "0.1.0"
    files = unzip(first.content)
    assert sorted(files) == [
        "equity-research-dcf/SKILL.md",
        "equity-research/SKILL.md",
        "equity-research/references/examples.md",
    ]
    assert "Ends 30 June." in files["equity-research/SKILL.md"]
    assert "Project and discount cash flows." in files["equity-research-dcf/SKILL.md"]
    assert all("My private note." not in text for text in files.values())

    # Identical bytes for the same version.
    again = a.get("/v1/knowledge/packs/equity-research/versions/0.1.0/skills.zip")
    assert again.content == first.content

    assert (
        merge(
            world,
            {
                "key": "fiscal-year",
                "type": "fact",
                "title": "Fiscal year",
                "body": "Ends 31 December now.",
            },
        )
        == "0.2.0"
    )
    latest = unzip(a.get("/v1/knowledge/packs/equity-research/versions/latest/skills.zip").content)
    assert "Ends 31 December now." in latest["equity-research/SKILL.md"]
    old = unzip(a.get("/v1/knowledge/packs/equity-research/versions/0.1.0/skills.zip").content)
    assert "Ends 30 June." in old["equity-research/SKILL.md"]

    with psycopg.connect(world.db.owner_url) as conn:
        rows = conn.execute(
            "SELECT after FROM knowledge.evidence_events WHERE action = 'knowledge.pack.exported' ORDER BY seq"
        ).fetchall()
    assert [r[0]["version"] for r in rows] == ["0.1.0", "0.1.0", "0.2.0", "0.1.0"]
    assert rows[0][0]["sha256"] == hashlib.sha256(first.content).hexdigest()
    assert all(
        "Ends 30 June" not in str(r[0]) for r in rows
    )  # evidence names the archive, not its content
    evidence.verify(
        world.knowledge.events(world.actor(A), 0, 1000), {world.key.key_id: world.key.public}
    )


def test_publish_hooks_fire_after_commit_and_never_undo_a_merge(world) -> None:
    world.client(A).put("/v1/knowledge/packs/equity-research", json=PACK)
    seen = []
    world.knowledge.on_publish.append(lambda actor, pack, version: seen.append((pack, version)))
    world.knowledge.on_publish.append(lambda actor, pack, version: 1 / 0)
    assert merge(world, {"key": "k", "type": "fact", "title": "t", "body": "Some fact."}) == "0.1.0"
    assert seen == [("equity-research", "0.1.0")]
    assert (
        world.client(A).get("/v1/knowledge/packs/equity-research").json()["latestVersion"]
        == "0.1.0"
    )


def test_nothing_published_and_unknown_versions(world) -> None:
    a = world.client(A)
    a.put("/v1/knowledge/packs/equity-research", json=PACK)
    assert (
        a.get("/v1/knowledge/packs/equity-research/versions/latest/skills.zip").status_code == 409
    )
    assert a.get("/v1/knowledge/packs/equity-research/versions/9.9.9/skills.zip").status_code == 404
    assert a.get("/v1/knowledge/packs/nope/versions/latest/skills.zip").status_code == 404
    merge(world, {"key": "k", "type": "fact", "title": "t", "body": "A fact."})
    rolled = world.client(R).post(
        "/v1/knowledge/packs/equity-research/rollback",
        json={"toVersion": "0.0.0", "reason": "empty"},
    )
    assert rolled.json()["version"] == "0.2.0"
    assert (
        a.get("/v1/knowledge/packs/equity-research/versions/latest/skills.zip").status_code == 409
    )  # no entries
