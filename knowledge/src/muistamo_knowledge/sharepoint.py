"""The SharePoint connector: release 1's one document source (FR-310; PR D, part 2).

HUMAN REVIEW REQUIRED (CLAUDE.md): invariant 1's connector, a credential and a fetch path.

- Indexing (list_documents) uses the tenant's indexer app: client credentials with read-only
  Sites.Selected, granted per site by an administrator. It lists every file of the site's
  document libraries through each drive's delta; the index is only candidates, and a document
  gone from the source is gone from the index at the next sync. Text is extracted from .txt,
  .md and .docx (standard library only); other files are indexed by title.
- Authorisation (authorise) never uses the indexer: it asks Graph, with the token the control
  plane delegated to the person's own agent for this request, whether that person can open each
  candidate right now ($batch, up to 20 per call). 200 is allowed and 403 or 404 denied; any
  other answer withholds the whole source (fail closed).
- Every call goes to graph.microsoft.com or the directory's token endpoint, never follows a
  redirect or an environment proxy, and is bounded in time and size. File contents come only
  from the pre-authenticated download link Graph returned for that item, and only from the
  configured site's own host, without any authorization header.
"""

from __future__ import annotations

import io
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from xml.etree import ElementTree
from xml.parsers import expat

from muistamo_knowledge.connectors import (
    Connector,
    ConnectorUnavailable,
    Principal,
    SourceDocument,
)

GRAPH = "https://graph.microsoft.com/v1.0"
LOGIN = "login.microsoftonline.com"
TIMEOUT = 10.0
MAX_FILE = 5 << 20
MAX_RESPONSE = MAX_FILE + (1 << 20)  # a file download, or any Graph answer
MAX_PAGES = 1000
BATCH = 20
TEXT_TYPES = (".txt", ".md")
# Drive and item ids are opaque but plain: letters, digits and a few marks ("b!..." drives).
_ID = re.compile(r"^[A-Za-z0-9!_-]{1,200}$")
_SITE_HOST = re.compile(r"^[a-z0-9-]{1,63}\.sharepoint\.com$")
_WORD = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


@dataclass(frozen=True)
class Indexer:
    """A tenant's indexer app: its directory, client id and secret (from the operator's file)."""

    directory: uuid.UUID
    client_id: uuid.UUID
    secret: str = field(repr=False)


# One HTTP exchange: (method, url, headers, body, timeout) → (status, body). Never redirects.
Transport = Callable[[str, str, dict[str, str], bytes | None, float], tuple[int, bytes]]


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


_opener = urllib.request.build_opener(_NoRedirects(), urllib.request.ProxyHandler({}))


def urllib_transport(
    method: str, url: str, headers: dict[str, str], body: bytes | None, timeout: float
) -> tuple[int, bytes]:
    if not url.startswith("https://"):
        raise ConnectorUnavailable("only https")
    request = urllib.request.Request(url, data=body, headers=headers, method=method)  # noqa: S310 - https only, checked above
    deadline = time.monotonic() + timeout
    try:
        with _opener.open(request, timeout=timeout) as response:
            status, reader = response.status, response
            return status, _read(reader, deadline)
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code, _read(exc, deadline)


def _read(reader: Any, deadline: float) -> bytes:
    body = b""
    while chunk := reader.read(65536):
        body += chunk
        if len(body) > MAX_RESPONSE:
            raise ConnectorUnavailable("response too large")
        if time.monotonic() > deadline:
            raise ConnectorUnavailable("response too slow")
    return body


def site_of(site_url: str) -> tuple[str, str]:
    """(host, server-relative path) of an https://<tenant>.sharepoint.com/sites/<site> URL."""
    parts = urllib.parse.urlsplit(site_url)
    path = parts.path.rstrip("/")
    if (
        parts.scheme != "https"
        or not _SITE_HOST.match(parts.hostname or "")
        or parts.port is not None
        or parts.username is not None
        or parts.query
        or parts.fragment
        or not re.fullmatch(r"/(sites|teams)/[A-Za-z0-9._-]{1,128}", path)
        or set(path.rsplit("/", 1)[1]) <= {"."}
    ):
        raise ValueError("siteUrl must be https://<tenant>.sharepoint.com/sites/<site>")
    return parts.hostname or "", path


@dataclass
class SharePointConnector:
    """One source: a SharePoint site, optionally limited to some document libraries."""

    site_url: str
    libraries: list[str] | None
    indexer: Indexer | None
    transport: Transport = urllib_transport
    name: str = "sharepoint"
    is_test: bool = False

    def __post_init__(self) -> None:
        self.host, self.path = site_of(self.site_url)

    # Graph -----------------------------------------------------------------------------------

    def _call(self, method: str, url: str, token: str, body: Any = None) -> tuple[int, Any]:
        if not url.startswith(GRAPH + "/"):
            raise ConnectorUnavailable("only Microsoft Graph")
        headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        status, raw = self.transport(method, url, headers, data, TIMEOUT)
        try:
            return status, json.loads(raw) if raw else None
        except ValueError as exc:
            raise ConnectorUnavailable("Graph answered with something other than JSON") from exc

    def _indexer_token(self) -> str:
        if self.indexer is None:
            raise ConnectorUnavailable("no SharePoint indexer is configured for this tenant")
        form = urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": str(self.indexer.client_id),
                "client_secret": self.indexer.secret,
                "scope": "https://graph.microsoft.com/.default",
            }
        ).encode()
        url = f"https://{LOGIN}/{self.indexer.directory}/oauth2/v2.0/token"
        status, raw = self.transport(
            "POST", url, {"Content-Type": "application/x-www-form-urlencoded"}, form, TIMEOUT
        )
        try:
            answer = json.loads(raw)
        except ValueError:
            answer = None
        token = answer.get("access_token") if isinstance(answer, dict) else None
        if (
            status != 200
            or not isinstance(token, str)
            or not token
            or any(c.isspace() for c in token)
        ):
            raise ConnectorUnavailable("the indexer could not authenticate")
        return token

    # Indexing ---------------------------------------------------------------------------------

    def list_documents(self) -> list[SourceDocument]:
        token = self._indexer_token()
        status, site = self._call("GET", f"{GRAPH}/sites/{self.host}:{self.path}?$select=id", token)
        if status != 200 or not isinstance(site, dict) or not isinstance(site.get("id"), str):
            raise ConnectorUnavailable("site not found or not granted to the indexer")
        site_id = urllib.parse.quote(site["id"], safe="")
        status, drives = self._call("GET", f"{GRAPH}/sites/{site_id}/drives?$select=id,name", token)
        if isinstance(drives, dict) and "@odata.nextLink" in drives:
            # More libraries than one page: refuse rather than silently index some of them.
            raise ConnectorUnavailable("too many document libraries to list in one page")
        if (
            status != 200
            or not isinstance(drives, dict)
            or not isinstance(drives.get("value"), list)
        ):
            raise ConnectorUnavailable("document libraries unavailable")
        documents: list[SourceDocument] = []
        for drive in drives["value"]:
            drive_id, name = drive.get("id"), drive.get("name")
            if not isinstance(drive_id, str) or not _ID.match(drive_id):
                raise ConnectorUnavailable("unexpected drive id")
            if self.libraries is not None and name not in self.libraries:
                continue
            documents += self._drive(token, drive_id)
        return documents

    def _drive(self, token: str, drive_id: str) -> list[SourceDocument]:
        first = f"{GRAPH}/drives/{drive_id}/root/delta"
        url: str | None = first
        # Delta may repeat an item; its last occurrence wins, and a deletion removes it.
        documents: dict[str, SourceDocument] = {}
        for _ in range(MAX_PAGES):
            if url is None:
                return list(documents.values())
            status, page = self._call("GET", url, token)
            if (
                status != 200
                or not isinstance(page, dict)
                or not isinstance(page.get("value"), list)
            ):
                raise ConnectorUnavailable("library listing unavailable")
            for item in page["value"]:
                if isinstance(item, dict) and isinstance(item.get("id"), str):
                    documents.pop(item["id"], None)
                document = self._document(drive_id, item)
                if document is not None:
                    documents[item["id"]] = document
            url = page.get("@odata.nextLink")
            # Only this drive's own delta pages are followed.
            if url is not None and (not isinstance(url, str) or not url.startswith(first + "?")):
                raise ConnectorUnavailable("unexpected next page")
        raise ConnectorUnavailable("library listing did not end")

    def _document(self, drive_id: str, item: Any) -> SourceDocument | None:
        if not isinstance(item, dict) or "file" not in item or "deleted" in item:
            return None
        item_id, title = item.get("id"), item.get("name")
        if not isinstance(item_id, str) or not _ID.match(item_id) or not isinstance(title, str):
            return None
        url = item.get("webUrl") if isinstance(item.get("webUrl"), str) else None
        modified = None
        if isinstance(item.get("lastModifiedDateTime"), str):
            try:
                modified = datetime.fromisoformat(
                    item["lastModifiedDateTime"].replace("Z", "+00:00")
                )
            except ValueError:
                modified = None
        return SourceDocument(
            external_id=f"{drive_id}/{item_id}",
            title=title,
            body=self._text(item, title),
            url=url,
            modified_at=modified,
        )

    def _text(self, item: dict[str, Any], title: str) -> str:
        """The file's text, or empty (indexed by title only). A file that cannot be read never
        stops the sync: removals from the source must still reach the index."""
        try:
            return self._read_text(item, title)
        except Exception:  # noqa: BLE001 - one unreadable file is title-only, never fatal
            return ""

    def _read_text(self, item: dict[str, Any], title: str) -> str:
        lowered = title.lower()
        if not lowered.endswith((*TEXT_TYPES, ".docx")):
            return ""
        # Only the published version's text: a library with drafts (minor versions) may show some
        # readers the published version only, and the download link is the current draft.
        publication = item.get("publication")
        if not isinstance(publication, dict) or publication.get("level") != "published":
            return ""
        size = item.get("size")
        link = item.get("@microsoft.graph.downloadUrl")
        if not isinstance(size, int) or size > MAX_FILE or not isinstance(link, str):
            return ""
        parts = urllib.parse.urlsplit(link)
        # A pre-authenticated link, only to this site's own host; never with a token.
        if parts.scheme != "https" or parts.hostname != self.host or parts.port is not None:
            return ""
        status, raw = self.transport("GET", link, {}, None, TIMEOUT)
        if status != 200 or len(raw) > MAX_FILE:
            return ""
        if lowered.endswith(".docx"):
            return docx_text(raw)
        return raw.decode("utf-8", errors="replace")

    # Authorisation -----------------------------------------------------------------------------

    def authorise(self, principal: Principal, external_ids: list[str]) -> set[str]:
        """Which of these the person can open now, asked with their agent's delegated token."""
        if not principal.graph_token:
            raise ConnectorUnavailable("no delegated token: SharePoint is asked only as the person")
        ids = []
        for external_id in external_ids:
            drive, _, item = external_id.partition("/")
            if not _ID.match(drive) or not _ID.match(item):
                raise ConnectorUnavailable("unexpected document id")
            ids.append((external_id, drive, item))
        allowed: set[str] = set()
        for start in range(0, len(ids), BATCH):
            chunk = ids[start : start + BATCH]
            requests = [
                {"id": str(n), "method": "GET", "url": f"/drives/{drive}/items/{item}?$select=id"}
                for n, (_, drive, item) in enumerate(chunk)
            ]
            status, answer = self._call(
                "POST", f"{GRAPH}/$batch", principal.graph_token, {"requests": requests}
            )
            if (
                status != 200
                or not isinstance(answer, dict)
                or not isinstance(answer.get("responses"), list)
            ):
                raise ConnectorUnavailable("SharePoint could not answer")
            seen: dict[str, int] = {}
            for response in answer["responses"]:
                if not isinstance(response, dict) or not isinstance(response.get("status"), int):
                    raise ConnectorUnavailable("malformed batch answer")
                rid = response.get("id")
                if (
                    not isinstance(rid, str)
                    or rid in seen
                    or not rid.isdigit()
                    or int(rid) >= len(chunk)
                ):
                    raise ConnectorUnavailable("malformed batch answer")
                seen[rid] = response["status"]
            if len(seen) != len(chunk):
                raise ConnectorUnavailable("incomplete batch answer")
            for n, (external_id, _, _) in enumerate(chunk):
                code = seen[str(n)]
                if code == 200:
                    allowed.add(external_id)
                elif code not in (403, 404):
                    # Throttled, unauthorised or failing: nothing from this source is trusted.
                    raise ConnectorUnavailable(f"SharePoint answered {code}")
        return allowed


def _refuse_doctype(*_: Any) -> None:
    raise ValueError("a DTD in a document body")


def docx_text(raw: bytes) -> str:
    """The paragraphs of a .docx document's body, from its XML. Anything unreadable is empty."""
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            info = archive.getinfo("word/document.xml")
            if info.file_size > MAX_FILE:
                return ""
            xml = archive.read(info)
        # A document body never declares a DTD: refused before parsing, in any encoding.
        scan = expat.ParserCreate()
        scan.StartDoctypeDeclHandler = _refuse_doctype
        scan.Parse(xml, True)
        root = ElementTree.fromstring(xml)  # noqa: S314 - DTDs refused by the scan above
    except Exception:  # noqa: BLE001 - encrypted, unsupported or malformed: no text
        return ""
    paragraphs = []
    for paragraph in root.iter(_WORD + "p"):
        paragraphs.append("".join(t.text or "" for t in paragraph.iter(_WORD + "t")))
    return "\n".join(p for p in paragraphs if p)


def factory_for(
    indexers: Callable[[uuid.UUID], Indexer | None], transport: Transport = urllib_transport
) -> Callable[[str, dict[str, Any], uuid.UUID], Connector]:
    """The SharePoint connector factory: each source's site, with its tenant's indexer."""

    def build(source: str, spec: dict[str, Any], tenant: uuid.UUID) -> Connector:
        config = spec.get("sharepoint") or {}
        if "siteUrl" not in config:
            raise ValueError("a SharePoint source needs spec.sharepoint.siteUrl")
        libraries = config.get("libraries")
        return SharePointConnector(
            site_url=config["siteUrl"],
            libraries=list(libraries) if libraries is not None else None,
            indexer=indexers(tenant),
            transport=transport,
        )

    return build


def load_indexers(path: str) -> Callable[[uuid.UUID], Indexer | None]:
    """Indexer apps from an operator's JSON file: {"<tenant>": {"directory", "clientId",
    "secretFile"}}. Secrets live in their own files, never in this one or in code."""
    with open(path, encoding="utf-8") as f:
        config = json.load(f)
    indexers: dict[uuid.UUID, Indexer] = {}
    for tenant, entry in config.items():
        with open(entry["secretFile"], encoding="utf-8") as f:
            secret = f.read().strip()
        if not secret:
            raise ValueError(f"empty indexer secret for tenant {tenant}")
        indexers[uuid.UUID(tenant)] = Indexer(
            directory=uuid.UUID(entry["directory"]),
            client_id=uuid.UUID(entry["clientId"]),
            secret=secret,
        )
    return indexers.get
