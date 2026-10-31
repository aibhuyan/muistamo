"""SharePoint connector hardening from review (PR D, part 2). HUMAN REVIEW REQUIRED."""

from __future__ import annotations

import io
import json
import uuid
import zipfile
from datetime import UTC, datetime, timedelta

import pytest
from muistamo_knowledge import sharepoint
from muistamo_knowledge.connectors import ConnectorUnavailable
from muistamo_knowledge.delegation import Delegation, Outcome

SITE = "https://contoso.sharepoint.com/sites/finance"
W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def connector(fake_graph, documents):
    directory, client = uuid.uuid4(), uuid.uuid4()
    graph = fake_graph(documents, directory, client)
    indexer = sharepoint.Indexer(directory, client, "obviously-fake-indexer-secret")
    return graph, sharepoint.SharePointConnector(SITE, ["Documents"], indexer, graph)


def _docx(xml: bytes) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        archive.writestr("word/document.xml", xml)
    return out.getvalue()


def _odd_zip(flag: int = 0, method: int = zipfile.ZIP_STORED) -> bytes:
    """A .docx whose only entry claims encryption (flag 1) or an unknown compression method."""
    raw = bytearray(_docx(b"<x/>"))
    for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        at = raw.index(signature)
        raw[at + offset : at + offset + 4] = flag.to_bytes(2, "little") + method.to_bytes(
            2, "little"
        )
    return bytes(raw)


def scripted(pages: dict[str, dict], drives=None):
    """A transport answering the indexer's site and drive calls, then the given URL suffixes."""

    def transport(method, url, headers, body, timeout):
        if "login.microsoftonline.com" in url:
            return 200, b'{"access_token":"indexer-token"}'
        if url.endswith("?$select=id"):
            return 200, b'{"id":"site-id"}'
        if url.endswith("/drives?$select=id,name"):
            return 200, json.dumps(
                drives or {"value": [{"id": "b!d", "name": "Documents"}]}
            ).encode()
        for suffix, page in pages.items():
            if url.endswith(suffix):
                return 200, json.dumps(page).encode()
        raise AssertionError(url)

    return sharepoint.SharePointConnector(
        SITE, None, sharepoint.Indexer(uuid.uuid4(), uuid.uuid4(), "s"), transport
    )


def test_an_unreadable_file_never_stops_the_sync(fake_graph) -> None:
    documents = [
        {"id": "encrypted", "name": "encrypted.docx", "body": "x", "readers": []},
        {"id": "exotic", "name": "exotic.docx", "body": "x", "readers": []},
        {"id": "big", "body": "x" * ((4 << 20) + (512 << 10)), "readers": []},
        {"id": "slow", "body": "x", "readers": []},
        {"id": "fine", "body": "Quarterly.", "readers": []},
    ]
    graph, c = connector(fake_graph, documents)
    original = c.transport

    def transport(method, url, headers, body, timeout):
        if url.endswith("/download/encrypted"):
            return 200, _odd_zip(flag=1)
        if url.endswith("/download/exotic"):
            return 200, _odd_zip(method=99)
        if url.endswith("/download/slow"):
            raise TimeoutError("obviously fake")
        return original(method, url, headers, body, timeout)

    c.transport = transport
    found = {d.external_id: d.body for d in c.list_documents()}
    # Every file is indexed; the unreadable ones by title only, so removals still apply.
    assert set(found) == {f"b!drive-1/{d['id']}" for d in documents}
    assert found["b!drive-1/fine"] == "Quarterly."
    assert found["b!drive-1/big"].startswith("x"), "a file under the limit is read whole"
    assert (
        found["b!drive-1/encrypted"] == found["b!drive-1/exotic"] == found["b!drive-1/slow"] == ""
    )


def test_drafts_are_indexed_by_title_only(fake_graph) -> None:
    documents = [
        {"id": "draft", "body": "Unpublished plan.", "readers": [], "publication": "checkout"},
        {"id": "published", "body": "Published plan.", "readers": []},
    ]
    graph, c = connector(fake_graph, documents)
    found = {d.external_id: d.body for d in c.list_documents()}
    assert found == {"b!drive-1/draft": "", "b!drive-1/published": "Published plan."}
    assert not any(url.endswith("/download/draft") for _, url in graph.calls)
    no_facet = {"size": 5, "@microsoft.graph.downloadUrl": "https://contoso.sharepoint.com/d/x"}
    assert c._text(no_facet, "a.txt") == "", "without a publication facet: title only"


def test_a_dtd_is_refused_in_any_encoding() -> None:
    for encoding in ("utf-8", "utf-16"):
        xml = (
            f'<?xml version="1.0" encoding="{encoding.upper()}"?>'
            '<!DOCTYPE w:document [<!ENTITY a "Quarterly">]>'
            f'<w:document xmlns:w="{W}"><w:body><w:p><w:r><w:t>&a;</w:t></w:r></w:p>'
            "</w:body></w:document>"
        ).encode(encoding)
        assert sharepoint.docx_text(_docx(xml)) == "", encoding
    plain = f'<w:document xmlns:w="{W}"><w:body><w:p><w:r><w:t>Fine</w:t></w:r></w:p></w:body></w:document>'
    assert sharepoint.docx_text(_docx(plain.encode("utf-16"))) == "Fine"


def test_a_later_deletion_of_a_repeated_item_wins() -> None:
    next_page = "https://graph.microsoft.com/v1.0/drives/b!d/root/delta?page=1"
    c = scripted(
        {
            "/root/delta": {
                "value": [{"id": "i", "name": "a.txt", "file": {}}],
                "@odata.nextLink": next_page,
            },
            "/root/delta?page=1": {
                "value": [
                    {"id": "i", "deleted": {}},
                    {"id": "j", "name": "b.txt", "file": {}},
                    {"id": "j", "name": "b2.txt", "file": {}},
                ]
            },
        }
    )
    assert [(d.external_id, d.title) for d in c.list_documents()] == [("b!d/j", "b2.txt")]


def test_more_libraries_than_one_page_is_refused_not_truncated() -> None:
    drives = {
        "value": [],
        "@odata.nextLink": "https://graph.microsoft.com/v1.0/sites/x/drives?$skiptoken=1",
    }
    with pytest.raises(ConnectorUnavailable):
        scripted({}, drives).list_documents()


@pytest.mark.parametrize(
    "site", ["https://contoso.sharepoint.com/sites/..", "https://contoso.sharepoint.com/sites/."]
)
def test_dot_segments_are_not_sites(site) -> None:
    with pytest.raises(ValueError):
        sharepoint.SharePointConnector(site, None, None)


def test_a_sync_the_source_cannot_answer_is_unavailable(world) -> None:
    def down(method, url, headers, body, timeout):
        return 503, b"{}"

    world.knowledge.connectors = {
        "sharepoint": sharepoint.factory_for(
            lambda t: sharepoint.Indexer(uuid.uuid4(), uuid.uuid4(), "s"), down
        )
    }
    r = world.client("reviewer-r@example.invalid")
    pack = {
        "apiVersion": "muistamo.dev/v1",
        "kind": "KnowledgePack",
        "metadata": {"name": "finance"},
        "spec": {
            "layer": "role",
            "reviewers": ["dev:reviewer-r@example.invalid"],
            "mergePolicy": {"requires": ["review"]},
        },
    }
    assert r.put("/v1/knowledge/packs/finance", json=pack).status_code == 201
    source = {
        "apiVersion": "muistamo.dev/v1",
        "kind": "KnowledgeSource",
        "metadata": {"name": "finance-site"},
        "spec": {"pack": "finance", "connector": "sharepoint", "sharepoint": {"siteUrl": SITE}},
    }
    assert r.put("/v1/knowledge/sources/finance-site", json=source).status_code == 201
    assert r.post("/v1/knowledge/sources/finance-site/sync").status_code == 503


def test_the_delegated_token_reaches_sharepoint_through_retrieval(entra_world, fake_graph) -> None:
    """In process, end to end: an Entra caller, the delegation's token, the real connector."""
    world = entra_world.world
    person, other = uuid.uuid4(), uuid.uuid4()
    docs = [
        {"id": "mine", "body": "Quarterly mine.", "readers": [f"entra:{person}"]},
        {"id": "theirs", "body": "Quarterly theirs.", "readers": [f"entra:{other}"]},
    ]
    directory, client = uuid.uuid4(), uuid.uuid4()
    graph = fake_graph(docs, directory, client)
    indexer = sharepoint.Indexer(directory, client, "obviously-fake-indexer-secret")
    world.knowledge.connectors = {"sharepoint": sharepoint.factory_for(lambda t: indexer, graph)}
    r = world.client("reviewer-r@example.invalid")
    pack = {
        "apiVersion": "muistamo.dev/v1",
        "kind": "KnowledgePack",
        "metadata": {"name": "finance"},
        "spec": {
            "layer": "role",
            "reviewers": ["dev:reviewer-r@example.invalid"],
            "mergePolicy": {"requires": ["review"]},
        },
    }
    assert r.put("/v1/knowledge/packs/finance", json=pack).status_code == 201
    source = {
        "apiVersion": "muistamo.dev/v1",
        "kind": "KnowledgeSource",
        "metadata": {"name": "finance-site"},
        "spec": {
            "pack": "finance",
            "connector": "sharepoint",
            "sharepoint": {"siteUrl": SITE, "libraries": ["Documents"]},
        },
    }
    assert r.put("/v1/knowledge/sources/finance-site", json=source).status_code == 201
    assert r.post("/v1/knowledge/sources/finance-site/sync").status_code == 200

    token_for: dict[str, str] = {}

    class Plane:
        def request(self, tenant, user_token, instance=None):
            expires = datetime.now(UTC) + timedelta(minutes=5)
            return Outcome(
                Delegation("agent", uuid.uuid4(), "HR", ["finance"], expires, token_for[user_token])
            )

    world.knowledge.delegations = Plane()
    token = entra_world.directory.token(person)

    def ids() -> set[str]:
        res = entra_world.client(token).get(
            "/v1/knowledge/retrieve", params={"q": "quarterly", "packs": "finance"}
        )
        return {
            i["citation"]["externalId"]
            for i in res.json()["items"]
            if i["citation"]["type"] == "document"
        }

    token_for[token] = f"delegated:entra:{person}"
    assert ids() == {"b!drive-1/mine"}
    # The source answers for whoever the delegated token names, so it must be the caller's.
    token_for[token] = f"delegated:entra:{other}"
    assert ids() == {"b!drive-1/theirs"}
    assert graph.tokens_asked == [f"entra:{person}", f"entra:{other}"]


def test_a_download_up_to_the_file_limit_is_read_whole() -> None:
    body = b"x" * (sharepoint.MAX_FILE)
    assert sharepoint._read(io.BytesIO(body), float("inf")) == body
    with pytest.raises(ConnectorUnavailable):
        sharepoint._read(io.BytesIO(b"x" * (sharepoint.MAX_RESPONSE + 1)), float("inf"))


def test_a_source_is_asked_about_the_best_candidates_only(world) -> None:
    from muistamo_knowledge import retrieval
    from muistamo_knowledge.connectors import InMemoryConnector

    docs = [
        {
            "id": f"doc-{n}",
            "title": "Quarterly",
            "body": "Quarterly.",
            "readers": ["dev:a@example.invalid"],
        }
        for n in range(retrieval.AUTHORISE_MAX_PER_SOURCE + 10)
    ]
    instance = InMemoryConnector(documents=docs)
    world.knowledge.connectors = {"test": lambda source, spec, tenant=None: instance}
    r = world.client("reviewer-r@example.invalid")
    pack = {
        "apiVersion": "muistamo.dev/v1",
        "kind": "KnowledgePack",
        "metadata": {"name": "finance"},
        "spec": {
            "layer": "role",
            "reviewers": ["dev:reviewer-r@example.invalid"],
            "mergePolicy": {"requires": ["review"]},
        },
    }
    assert r.put("/v1/knowledge/packs/finance", json=pack).status_code == 201
    source = {
        "apiVersion": "muistamo.dev/v1",
        "kind": "KnowledgeSource",
        "metadata": {"name": "s"},
        "spec": {"pack": "finance", "connector": "test", "test": {"documents": docs}},
    }
    assert r.put("/v1/knowledge/sources/s", json=source).status_code == 201
    assert r.post("/v1/knowledge/sources/s/sync").status_code == 200
    instance.calls.clear()
    world.client("a@example.invalid").get(
        "/v1/knowledge/retrieve", params={"q": "quarterly", "packs": "finance", "limit": 50}
    )
    ((_, asked),) = instance.calls
    assert len(asked) == retrieval.AUTHORISE_MAX_PER_SOURCE
