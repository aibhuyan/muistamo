"""A loopback fake of Entra ID, Microsoft Graph and one SharePoint site. Test use only.

It answers what Muistamo calls, as Microsoft would, and checks what it is sent: the blueprint's
credential for its own token and for an agent's exchange assertion (T1); the agent identity's
on-behalf-of exchange of a person's token, which it verifies; the employeeId lookup; agent
identity create/enable/disable; the indexer's site, library and delta reads; and per-person
$batch checks with the delegated token. It serves TLS for the real hostnames under a throwaway CA.
"""

from __future__ import annotations

import datetime
import json
import ssl
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

HOSTS = ("login.microsoftonline.com", "graph.microsoft.com", "contoso.sharepoint.com")
SITE = "https://contoso.sharepoint.com/sites/finance"
GRAPH_APP = "00000003-0000-0000-c000-000000000000"


# The assistant client app ("Claude") the e2e tenant allows; tokens name it as azp.
ASSISTANT = uuid.UUID("5a5a5a5a-0000-4000-8000-00000000c1a0")
# Muistamo's console, where a person (a reviewer, a manager) acts as themselves.
CONSOLE = uuid.UUID("5a5a5a5a-0000-4000-8000-0000000c0501")


def write_certificates(directory: str) -> tuple[str, str, str]:
    """A throwaway CA and a certificate for HOSTS. Returns (ca, cert, key) file paths."""
    now = datetime.datetime.now(datetime.UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "muistamo e2e throwaway CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=4))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOSTS[0])]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=4))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(h) for h in HOSTS]), critical=False
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    paths = (f"{directory}/ca.pem", f"{directory}/fake.pem", f"{directory}/fake.key")
    with open(paths[0], "wb") as f:
        f.write(ca.public_bytes(serialization.Encoding.PEM))
    with open(paths[1], "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(paths[2], "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    return paths


class Microsoft:
    """The fake's state, which the run inspects and changes (people, documents, readers)."""

    def __init__(
        self,
        directory: uuid.UUID,
        blueprint: uuid.UUID,
        blueprint_secret: str,
        indexer: uuid.UUID,
        indexer_secret: str,
    ) -> None:
        self.directory, self.blueprint, self.blueprint_secret = (
            directory,
            blueprint,
            blueprint_secret,
        )
        self.indexer, self.indexer_secret = indexer, indexer_secret
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "e2e-directory-key"
        self.users: list[dict[str, str]] = []  # {"id", "employeeId"}
        self.identities: dict[str, dict[str, Any]] = {}
        # library name -> documents {"id", "body", "readers": [oid]}
        self.libraries: dict[str, list[dict[str, Any]]] = {"Documents": [], "Legal": []}
        self.exchanges: list[tuple[str, str]] = []  # (agent identity, person oid)
        # Every on-behalf-of attempt, counted before any check, so a refused one still shows.
        self.exchange_attempts = 0
        # Every per-person $batch check: (person oid, item id, status).
        self.checks: list[tuple[str, str, int]] = []
        # Graph tokens this fake issued: token -> (agent identity, person oid, expiry).
        self.issued: dict[str, tuple[str, str, int]] = {}
        # The console's web sign-in (OpenID Connect code flow with PKCE): its confidential
        # client, the one redirect URI registered for it, single-use codes and refresh tokens.
        self.console_secret = "obviously-fake-console-secret"
        # The tenant's "Muistamo control plane" API app: console tokens for the control plane.
        self.control_plane_api = uuid.uuid4()
        self.console_redirect = ""  # set by the run once the console's port is known
        self.codes: dict[str, dict[str, Any]] = {}
        self.refresh_tokens: dict[str, str] = {}  # refresh token -> user oid
        self.disabled: set[str] = set()  # users whose next refresh is refused (invalid_grant)
        self.guests: set[str] = set()  # users who sign in as guests (acct = 1)
        # Users whose first console token (from the code) has already expired, so the console
        # must renew it before the first page: proves the renewed token reaches the render.
        self.expired_at_sign_in: set[str] = set()
        self.lock = threading.Lock()

    def user_token(self, oid: uuid.UUID, lifetime: int = 1800, azp: uuid.UUID = ASSISTANT) -> str:
        now = int(time.time())
        return jwt.encode(
            {
                "iss": f"https://login.microsoftonline.com/{self.directory}/v2.0",
                "aud": str(self.blueprint),
                "tid": str(self.directory),
                "oid": str(oid),
                "sub": f"e2e-{oid}",
                "ver": "2.0",
                "scp": "Knowledge.Read",
                "azp": str(azp),  # the assistant's client app that obtained the token
                "iat": now,
                "nbf": now - 30,
                "exp": now + lifetime,
            },
            self.key,
            algorithm="RS256",
            headers={"kid": self.kid},
        )

    def control_plane_token(self, oid: str) -> str:
        """A console token for the control plane's own API app (never the blueprint)."""
        now = int(time.time())
        return jwt.encode(
            {
                "iss": f"https://login.microsoftonline.com/{self.directory}/v2.0",
                "aud": str(self.control_plane_api),
                "tid": str(self.directory),
                "oid": oid,
                "sub": f"e2e-cp-{oid}",
                "ver": "2.0",
                "scp": "Registry.Console",
                "azp": str(CONSOLE),
                "iat": now,
                "nbf": now - 30,
                "exp": now + 1800,
            },
            self.key,
            algorithm="RS256",
            headers={"kid": self.kid},
        )

    def id_token(self, oid: str, nonce: str) -> str:
        now = int(time.time())
        return jwt.encode(
            {
                "iss": f"https://login.microsoftonline.com/{self.directory}/v2.0",
                "aud": str(CONSOLE),
                "tid": str(self.directory),
                "oid": oid,
                "sub": f"e2e-console-{oid}",
                "ver": "2.0",
                "nonce": nonce,
                "name": f"E2E person {oid[:8]}",
                "acct": 1 if oid in self.guests else 0,
                "iat": now,
                "nbf": now - 30,
                "exp": now + 3600,
            },
            self.key,
            algorithm="RS256",
            headers={"kid": self.kid},
        )

    def jwks(self) -> dict[str, Any]:
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        jwk.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        return {"keys": [jwk]}

    def _drive(self, drive_id: str) -> list[dict[str, Any]] | None:
        for name, documents in self.libraries.items():
            if drive_id == f"b!{name.lower()}":
                return documents
        return None


def serve(state: Microsoft, cert: str, key: str) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_: Any) -> None:
            return

        def _send(self, status: int, body: Any = None) -> None:
            raw = b"" if body is None else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _body(self) -> bytes:
            return self.rfile.read(int(self.headers.get("Content-Length") or 0))

        def _bearer(self) -> str:
            return (self.headers.get("Authorization") or "").removeprefix("Bearer ")

        def do_GET(self) -> None:
            with state.lock:
                self._route("GET", b"")

        def do_POST(self) -> None:
            body = self._body()
            with state.lock:
                self._route("POST", body)

        def do_PATCH(self) -> None:
            body = self._body()
            with state.lock:
                self._route("PATCH", body)

        def do_DELETE(self) -> None:
            with state.lock:
                self._route("DELETE", b"")

        def _route(self, method: str, body: bytes) -> None:
            host = (self.headers.get("Host") or "").split(":")[0]
            url = urlsplit(self.path)
            if host == "login.microsoftonline.com":
                return self._login(method, url, body)
            if host == "contoso.sharepoint.com":
                doc_id = url.path.rsplit("/", 1)[-1]
                if "Authorization" in self.headers:
                    return self._send(400, {"error": "a download link never takes a token"})
                for documents in state.libraries.values():
                    for d in documents:
                        if d["id"] == doc_id:
                            raw = d["body"].encode()
                            self.send_response(200)
                            self.send_header("Content-Length", str(len(raw)))
                            self.end_headers()
                            self.wfile.write(raw)
                            return None
                return self._send(404)
            if host == "graph.microsoft.com":
                return self._graph(method, url, body)
            return self._send(421)

        def _console_grant(self, grant: str, form: dict[str, str]) -> None:
            import base64
            import hashlib

            if form.get("client_secret") != state.console_secret:
                return self._send(401, {"error": "invalid_client"})
            if grant == "authorization_code":
                # Single use, bound to its redirect and its PKCE verifier.
                code = state.codes.pop(form.get("code", ""), None)
                verifier = form.get("code_verifier", "")
                challenge = (
                    base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
                    .rstrip(b"=")
                    .decode()
                )
                if (
                    code is None
                    or code["client"] != form.get("client_id")
                    or code["expires"] < time.time()
                    or form.get("redirect_uri") != code["redirect"]
                    or challenge != code["challenge"]
                ):
                    return self._send(400, {"error": "invalid_grant"})
                oid, id_token = code["oid"], state.id_token(code["oid"], code["nonce"])
            else:
                oid = state.refresh_tokens.get(form.get("refresh_token", ""), "")
                if not oid or oid in state.disabled:
                    return self._send(400, {"error": "invalid_grant"})
                id_token = None
            refresh = f"e2e-refresh-{uuid.uuid4().hex}"
            state.refresh_tokens[refresh] = oid
            # The same refresh token gives a token for another resource (Entra's behaviour).
            control_plane_scope = f"api://{state.control_plane_api}/Registry.Console"
            if grant == "refresh_token" and form.get("scope", "").split() == [control_plane_scope]:
                return self._send(
                    200,
                    {
                        "token_type": "Bearer",
                        "access_token": state.control_plane_token(oid),
                        "expires_in": 1800,
                        "refresh_token": refresh,
                        "scope": control_plane_scope,
                    },
                )
            answer = {
                "token_type": "Bearer",
                "access_token": state.user_token(
                    uuid.UUID(oid),
                    -60
                    if grant == "authorization_code" and oid in state.expired_at_sign_in
                    else 1800,
                    azp=CONSOLE,
                ),
                "expires_in": 1800,
                "refresh_token": refresh,
                "scope": f"api://{state.blueprint}/Knowledge.Read",
            }
            if id_token:
                answer["id_token"] = id_token
            return self._send(200, answer)

        def _redirect(self, location: str) -> None:
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _login(self, method: str, url, body: bytes) -> None:
            prefix = f"/{state.directory}"
            authority = f"https://login.microsoftonline.com/{state.directory}"
            if method == "GET" and url.path == f"{prefix}/discovery/v2.0/keys":
                return self._send(200, state.jwks())
            if method == "GET" and url.path == f"{prefix}/v2.0/.well-known/openid-configuration":
                return self._send(
                    200,
                    {
                        "issuer": f"{authority}/v2.0",
                        "authorization_endpoint": f"{authority}/oauth2/v2.0/authorize",
                        "token_endpoint": f"{authority}/oauth2/v2.0/token",
                        "jwks_uri": f"{authority}/discovery/v2.0/keys",
                        "end_session_endpoint": f"{authority}/oauth2/v2.0/logout",
                        "response_types_supported": ["code"],
                        "subject_types_supported": ["pairwise"],
                        "id_token_signing_alg_values_supported": ["RS256"],
                        "code_challenge_methods_supported": ["S256"],
                        "token_endpoint_auth_methods_supported": ["client_secret_post"],
                    },
                )
            if method == "GET" and url.path == f"{prefix}/oauth2/v2.0/authorize":
                # The person "signs in" as login_hint (the run picks who). Everything Entra would
                # check is checked: the client, its one registered redirect, code + S256, scope.
                q = {k: v[0] for k, v in parse_qs(url.query).items()}
                scope = q.get("scope", "").split()
                if (
                    q.get("client_id") != str(CONSOLE)
                    or q.get("redirect_uri") != state.console_redirect
                    or q.get("response_type") != "code"
                    or q.get("code_challenge_method") != "S256"
                    or len(q.get("code_challenge", "")) < 43
                    or "openid" not in scope
                    or f"api://{state.blueprint}/Knowledge.Read" not in scope
                    or not q.get("state")
                    or not q.get("nonce")
                    or not q.get("login_hint")
                ):
                    return self._send(400, {"error": "invalid_request"})
                code = f"e2e-code-{uuid.uuid4().hex}"
                state.codes[code] = {
                    "oid": q["login_hint"],
                    "nonce": q["nonce"],
                    "challenge": q["code_challenge"],
                    "redirect": q["redirect_uri"],
                    "client": q["client_id"],
                    "expires": time.time() + 600,
                }
                return self._redirect(f"{q['redirect_uri']}?code={code}&state={q['state']}")
            if method == "GET" and url.path == f"{prefix}/oauth2/v2.0/logout":
                return self._send(200, {"signedOut": True})
            if method != "POST" or url.path != f"{prefix}/oauth2/v2.0/token":
                return self._send(404)
            form = {k: v[0] for k, v in parse_qs(body.decode()).items()}
            grant, client = form.get("grant_type"), form.get("client_id")

            def bearer(token: str) -> None:
                self._send(200, {"access_token": token, "token_type": "Bearer", "expires_in": 3600})

            if client == str(CONSOLE) and grant in ("authorization_code", "refresh_token"):
                return self._console_grant(grant, form)
            if grant == "client_credentials" and client == str(state.indexer):
                if form.get("client_secret") != state.indexer_secret:
                    return self._send(401, {"error": "invalid_client"})
                return bearer("e2e-indexer-token")
            if grant == "client_credentials" and client == str(state.blueprint):
                if form.get("client_secret") != state.blueprint_secret:
                    return self._send(401, {"error": "invalid_client"})
                if form.get("scope") == "api://AzureADTokenExchange/.default":
                    return bearer("e2e-t1." + form["fmi_path"])
                return bearer("e2e-blueprint-token")
            if grant == "urn:ietf:params:oauth:grant-type:jwt-bearer":
                state.exchange_attempts += 1
                agent = client or ""
                if (
                    form.get("client_assertion") != "e2e-t1." + agent
                    or form.get("requested_token_use") != "on_behalf_of"
                ):
                    return self._send(401, {"error": "invalid_client"})
                identity = state.identities.get(agent)
                if identity is None or not identity["accountEnabled"]:
                    return self._send(400, {"error": "invalid_grant"})
                try:
                    person = jwt.decode(
                        form["assertion"],
                        state.key.public_key(),
                        algorithms=["RS256"],
                        audience=str(state.blueprint),
                    )
                except jwt.PyJWTError:
                    return self._send(400, {"error": "invalid_grant"})
                state.exchanges.append((agent, person["oid"]))
                expires = int(time.time()) + 3600
                graph = jwt.encode(
                    {
                        "aud": GRAPH_APP,
                        "tid": str(state.directory),
                        "oid": person["oid"],
                        "appid": agent,
                        "scp": "Sites.Read.All",
                        "exp": expires,
                    },
                    rsa.generate_private_key(public_exponent=65537, key_size=2048),
                    algorithm="RS256",
                )
                state.issued[graph] = (agent, person["oid"], expires)
                return bearer(graph)
            return self._send(400, {"error": "unsupported_grant_type"})

        def _graph(self, method: str, url, body: bytes) -> None:
            path, query, token = (
                unquote(url.path).removeprefix("/v1.0"),
                parse_qs(url.query),
                self._bearer(),
            )
            collection = "/servicePrincipals/microsoft.graph.agentIdentity"
            if path.startswith("/servicePrincipals") or path == "/users":
                if token != "e2e-blueprint-token":
                    return self._send(401, {"error": {"code": "InvalidAuthenticationToken"}})
                if path == "/users":
                    want = query["$filter"][0].removeprefix("employeeId eq '").removesuffix("'")
                    found = [u for u in state.users if u["employeeId"] == want]
                    return self._send(200, {"@odata.count": len(found), "value": found})
                if path == collection and method == "POST":
                    request = json.loads(body)
                    identity = {
                        "id": str(uuid.uuid4()),
                        "agentIdentityBlueprintId": str(state.blueprint),
                        "servicePrincipalType": "ServiceIdentity",
                        "tags": request["tags"],
                        "accountEnabled": False,
                    }
                    state.identities[identity["id"]] = identity
                    return self._send(201, identity)
                if path == collection and method == "GET":
                    tag = query.get("$filter", [""])[0]
                    found = [
                        i for i in state.identities.values() if any(t in tag for t in i["tags"])
                    ]
                    return self._send(200, {"@odata.count": len(found), "value": found})
                identity_id = path.removeprefix("/servicePrincipals/").removesuffix(
                    "/microsoft.graph.agentIdentity"
                )
                identity = state.identities.get(identity_id)
                if identity is None:
                    return self._send(404, {"error": {"code": "Request_ResourceNotFound"}})
                if method == "GET":
                    return self._send(200, identity)
                if method == "PATCH":
                    identity["accountEnabled"] = bool(json.loads(body)["accountEnabled"])
                    return self._send(204)
                if method == "DELETE":
                    del state.identities[identity_id]
                    return self._send(204)
            if path == "/$batch":
                return self._batch(token, json.loads(body))
            if token != "e2e-indexer-token":
                return self._send(401, {"error": {"code": "InvalidAuthenticationToken"}})
            if path == "/sites/contoso.sharepoint.com:/sites/finance":
                return self._send(200, {"id": "contoso.sharepoint.com,e2e,site"})
            if path == "/sites/contoso.sharepoint.com,e2e,site/drives":
                return self._send(
                    200, {"value": [{"id": f"b!{n.lower()}", "name": n} for n in state.libraries]}
                )
            if path.endswith("/root/delta"):
                drive_id = path.split("/")[2]
                documents = state._drive(drive_id)
                if documents is None:
                    return self._send(404)
                return self._send(
                    200,
                    {
                        "value": [
                            {
                                "id": d["id"],
                                "name": d["id"] + ".txt",
                                "file": {},
                                "size": len(d["body"]),
                                "webUrl": f"{SITE}/{drive_id}/{d['id']}.txt",
                                "publication": {"level": "published"},
                                "@microsoft.graph.downloadUrl": f"https://contoso.sharepoint.com/download/{d['id']}",
                            }
                            for d in documents
                        ]
                    },
                )
            return self._send(404)

        def _batch(self, token: str, request: dict[str, Any]) -> None:
            # Only a Graph token this fake issued by on-behalf-of exchange, unexpired, for an agent
            # identity that is still enabled: never the indexer's, the blueprint's, or a forgery.
            issued = state.issued.get(token)
            if issued is None or issued[2] <= time.time():
                return self._send(401, {"error": {"code": "InvalidAuthenticationToken"}})
            agent, oid, _ = issued
            identity = state.identities.get(agent)
            if identity is None or not identity["accountEnabled"]:
                return self._send(401, {"error": {"code": "InvalidAuthenticationToken"}})
            claims = {"oid": oid}
            responses = []
            for r in request["requests"]:
                _, drive_id, _, item = r["url"].split("?")[0].strip("/").split("/")
                documents = state._drive(drive_id) or []
                doc = next((d for d in documents if d["id"] == item), None)
                status = 404 if doc is None else 200 if claims["oid"] in doc["readers"] else 403
                state.checks.append((oid, item, status))
                responses.append({"id": r["id"], "status": status, "body": {}})
            return self._send(200, {"responses": responses})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
