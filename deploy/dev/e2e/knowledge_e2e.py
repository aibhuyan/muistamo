"""Start the knowledge service for the separate-binary end-to-end run. Test use only.

HUMAN REVIEW REQUIRED (AGENTS.md): like the control plane's e2e build tag, this launcher is never
shipped or used by `serve`. It replaces the HTTPS openers of the Entra key fetch and the
SharePoint connector with one that connects to a loopback fake of Microsoft's services
(MUISTAMO_E2E_MICROSOFT_ADDR), still verifying the real hostnames against the fake's throwaway CA
(MUISTAMO_E2E_MICROSOFT_CA) only, then runs `python -m muistamo_knowledge serve`.
"""

from __future__ import annotations

import http.client
import os
import socket
import ssl
import sys
import urllib.request

from muistamo_knowledge import __main__ as knowledge
from muistamo_knowledge import entra, sharepoint

HOST, _, PORT = os.environ["MUISTAMO_E2E_MICROSOFT_ADDR"].rpartition(":")
CONTEXT = ssl.create_default_context(cafile=os.environ["MUISTAMO_E2E_MICROSOFT_CA"])


class _Fake(http.client.HTTPSConnection):
    def connect(self) -> None:
        raw = socket.create_connection((HOST, int(PORT)), self.timeout)
        # The certificate must still name the real host the request is for.
        self.sock = CONTEXT.wrap_socket(raw, server_hostname=self.host)


class _FakeHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_Fake, req)


def _opener(no_redirects: type) -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        no_redirects(), urllib.request.ProxyHandler({}), _FakeHandler()
    )


entra._opener = _opener(entra._NoRedirects)
sharepoint._opener = _opener(sharepoint._NoRedirects)
print(
    f"E2E LAUNCHER: Microsoft services are a loopback fake at {HOST}:{PORT}; never deploy this",
    file=sys.stderr,
)
sys.argv = ["muistamo_knowledge", "serve"]
knowledge.main()
