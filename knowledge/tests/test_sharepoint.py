"""The SharePoint connector (PR D, part 2). HUMAN REVIEW REQUIRED: invariant 1's connector."""

from __future__ import annotations

import io
import json
import uuid
import zipfile

import pytest
from muistamo_knowledge import sharepoint
from muistamo_knowledge.connectors import ConnectorUnavailable, Principal

SITE = "https://contoso.sharepoint.com/sites/finance"
DOCS = [
    {"id": "doc-a", "body": "Quarterly A.", "readers": ["dev:a"]},
    {"id": "doc-b", "body": "Quarterly B.", "readers": ["dev:b"]},
]
A = Principal("dev:a", "delegated:dev:a")


def connector(fake_graph, libraries=("Documents",), indexer=True, documents=DOCS):
    directory, client = uuid.uuid4(), uuid.uuid4()
    graph = fake_graph([dict(d, readers=list(d["readers"])) for d in documents], directory, client)
    idx = (
        sharepoint.Indexer(directory, client, "obviously-fake-indexer-secret") if indexer else None
    )
    return graph, sharepoint.SharePointConnector(
        SITE, list(libraries) if libraries else None, idx, graph
    )


def test_indexing_lists_the_chosen_libraries_with_their_text(fake_graph) -> None:
    graph, c = connector(fake_graph)
    documents = {d.external_id: d for d in c.list_documents()}
    assert set(documents) == {"b!drive-1/doc-a", "b!drive-1/doc-b"}
    a = documents["b!drive-1/doc-a"]
    assert a.body == "Quarterly A." and a.title == "doc-a.txt" and a.url == graph.web_url("doc-a")
    assert a.modified_at is not None
    # Both delta pages were read; the Archive library was never listed.
    assert sum(1 for _, url in graph.calls if "/root/delta" in url) == 2
    assert repr(c.indexer).count("obviously-fake-indexer-secret") == 0


def test_without_an_indexer_nothing_is_indexed_but_people_are_still_asked(fake_graph) -> None:
    _, c = connector(fake_graph, indexer=False)
    with pytest.raises(ConnectorUnavailable):
        c.list_documents()
    assert c.authorise(A, ["b!drive-1/doc-a", "b!drive-1/doc-b"]) == {"b!drive-1/doc-a"}


def test_authorisation_is_asked_only_with_the_delegated_token(fake_graph) -> None:
    graph, c = connector(fake_graph)
    for principal in (Principal("dev:a"), Principal("dev:a", "")):
        with pytest.raises(ConnectorUnavailable):
            c.authorise(principal, ["b!drive-1/doc-a"])
    # The indexer's token is refused by Graph's per-person check, and so withholds the source.
    with pytest.raises(ConnectorUnavailable):
        c.authorise(Principal("dev:a", "indexer-token"), ["b!drive-1/doc-a"])
    assert graph.tokens_asked == []


@pytest.mark.parametrize("status", [401, 429, 500, 503, 302])
def test_any_answer_but_allowed_or_denied_withholds_the_source(fake_graph, status) -> None:
    graph, c = connector(fake_graph)
    graph.batch_status = status
    with pytest.raises(ConnectorUnavailable):
        c.authorise(A, ["b!drive-1/doc-a"])


def test_large_requests_are_batched_and_unknown_items_denied(fake_graph) -> None:
    documents = [{"id": f"doc-{n}", "body": "x", "readers": ["dev:a"]} for n in range(45)]
    graph, c = connector(fake_graph, documents=documents)
    ids = [f"b!drive-1/doc-{n}" for n in range(45)] + ["b!drive-1/gone"]
    assert c.authorise(A, ids) == set(ids[:-1])
    assert sum(1 for method, url in graph.calls if url.endswith("/$batch")) == 3


def test_a_failed_batch_call_withholds_the_source_whatever_its_body() -> None:
    def transport(method, url, headers, body, timeout):
        return 500, json.dumps({"responses": [{"id": "0", "status": 200}]}).encode()

    c = sharepoint.SharePointConnector(SITE, None, None, transport)
    with pytest.raises(ConnectorUnavailable):
        c.authorise(A, ["b!drive-1/doc-a"])


@pytest.mark.parametrize(
    "answer",
    [
        {"responses": []},
        {"responses": [{"id": "0", "status": 200}, {"id": "0", "status": 200}]},
        {"responses": [{"id": "7", "status": 200}]},
        {"responses": [{"id": "x", "status": 200}]},
        {"responses": [{"id": "0", "status": "200"}]},
        {"value": []},
        "not an object",
    ],
)
def test_malformed_batch_answers_withhold_the_source(answer) -> None:
    def transport(method, url, headers, body, timeout):
        return 200, json.dumps(answer).encode()

    c = sharepoint.SharePointConnector(SITE, None, None, transport)
    with pytest.raises(ConnectorUnavailable):
        c.authorise(A, ["b!drive-1/doc-a"])


@pytest.mark.parametrize(
    "external_id",
    ["doc-a", "b!drive-1/../x", "b!drive-1/a/b", "b!drive-1/a?b", "/doc", "b!drive-1/"],
)
def test_unexpected_document_ids_are_never_sent(external_id) -> None:
    def transport(*_):
        raise AssertionError("sent")

    c = sharepoint.SharePointConnector(SITE, None, None, transport)
    with pytest.raises(ConnectorUnavailable):
        c.authorise(A, [external_id])


@pytest.mark.parametrize(
    "site",
    [
        "http://contoso.sharepoint.com/sites/finance",
        "https://contoso.sharepoint.com.attacker.invalid/sites/finance",
        "https://attacker.invalid/sites/finance",
        "https://user@contoso.sharepoint.com/sites/finance",
        "https://contoso.sharepoint.com:444/sites/finance",
        "https://contoso.sharepoint.com/sites/finance?x=1",
        "https://contoso.sharepoint.com/sites/finance/../other",
        "https://contoso.sharepoint.com/personal/someone",
    ],
)
def test_only_sharepoint_sites_are_accepted(site) -> None:
    with pytest.raises(ValueError):
        sharepoint.SharePointConnector(site, None, None)


def test_a_foreign_next_page_or_download_host_is_never_followed() -> None:
    calls = []

    def transport(method, url, headers, body, timeout):
        calls.append(url)
        if "login.microsoftonline.com" in url:
            return 200, b'{"access_token":"indexer-token"}'
        if url.endswith("?$select=id"):
            return 200, b'{"id":"site-id"}'
        if url.endswith("/drives?$select=id,name"):
            return 200, b'{"value":[{"id":"b!d","name":"Documents"}]}'
        if url.endswith("/root/delta"):
            item = {
                "id": "i",
                "name": "a.txt",
                "file": {},
                "size": 5,
                "@microsoft.graph.downloadUrl": "https://attacker.invalid/x",
            }
            return 200, json.dumps(
                {"value": [item], "@odata.nextLink": "https://attacker.invalid/next"}
            ).encode()
        raise AssertionError(url)

    c = sharepoint.SharePointConnector(
        SITE, None, sharepoint.Indexer(uuid.uuid4(), uuid.uuid4(), "s"), transport
    )
    with pytest.raises(ConnectorUnavailable):
        c.list_documents()
    assert not any("attacker.invalid" in url for url in calls)
    assert (
        c._text(
            {
                "size": 5,
                "publication": {"level": "published"},
                "@microsoft.graph.downloadUrl": "https://attacker.invalid/x",
            },
            "a.txt",
        )
        == ""
    )
    assert not any("attacker.invalid" in url for url in calls), "a foreign download host was called"


def test_only_the_drives_own_next_pages_are_followed() -> None:
    calls = []

    def transport(method, url, headers, body, timeout):
        calls.append(url)
        if "login.microsoftonline.com" in url:
            return 200, b'{"access_token":"indexer-token"}'
        if url.endswith("?$select=id"):
            return 200, b'{"id":"site-id"}'
        if url.endswith("/drives?$select=id,name"):
            return 200, b'{"value":[{"id":"b!d","name":"Documents"}]}'
        if url.endswith("/root/delta"):
            other = "https://graph.microsoft.com/v1.0/drives/b!other/root/delta?token=x"
            return 200, json.dumps({"value": [], "@odata.nextLink": other}).encode()
        raise AssertionError(url)

    indexer = sharepoint.Indexer(uuid.uuid4(), uuid.uuid4(), "s")
    c = sharepoint.SharePointConnector(SITE, None, indexer, transport)
    with pytest.raises(ConnectorUnavailable):
        c.list_documents()
    assert not any("b!other" in url for url in calls)


def _docx(xml: bytes) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        archive.writestr("word/document.xml", xml)
    return out.getvalue()


def test_docx_text_is_extracted_and_dtds_refused() -> None:
    w = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    body = f'<w:document xmlns:w="{w}"><w:body><w:p><w:r><w:t>Quarterly</w:t></w:r><w:r><w:t> plan</w:t></w:r></w:p><w:p><w:r><w:t>Second</w:t></w:r></w:p></w:body></w:document>'
    assert sharepoint.docx_text(_docx(body.encode())) == "Quarterly plan\nSecond"
    bomb = (
        b'<?xml version="1.0"?><!DOCTYPE w:document [<!ENTITY a "Quarterly">]>'
        b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        b"<w:body><w:p><w:r><w:t>&a;</w:t></w:r></w:p></w:body></w:document>"
    )
    assert sharepoint.docx_text(_docx(bomb)) == ""
    assert sharepoint.docx_text(b"not a zip") == ""


def test_indexer_credentials_come_from_their_own_files(tmp_path) -> None:
    tenant, directory, client = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    secret = tmp_path / "indexer.secret"
    secret.write_text("obviously-fake-indexer-secret\n")
    config = tmp_path / "indexers.json"
    config.write_text(
        json.dumps(
            {
                str(tenant): {
                    "directory": str(directory),
                    "clientId": str(client),
                    "secretFile": str(secret),
                }
            }
        )
    )
    found = sharepoint.load_indexers(str(config))
    assert found(tenant) == sharepoint.Indexer(directory, client, "obviously-fake-indexer-secret")
    assert found(uuid.uuid4()) is None
    secret.write_text("")
    with pytest.raises(ValueError):
        sharepoint.load_indexers(str(config))
