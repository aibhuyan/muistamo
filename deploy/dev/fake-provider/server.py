"""Fake OpenAI-compatible provider for the dev gateway profile. Development only.

Answers POST /v1/chat/completions with a fixed reply and usage. It requires the provider key the
gateway injects from MUISTAMO_PROVIDER_KEY_FAKE and refuses anything else, including a Muistamo
virtual key the gateway should have stripped. It logs only the method, path and status of each
call, never headers or bodies, so `docker compose logs fake-provider` counts upstream calls.
"""

import http.server
import json
import os
import time

PROVIDER_KEY = os.environ["MUISTAMO_PROVIDER_KEY_FAKE"]

REPLY = {
    "id": "chatcmpl-dev",
    "object": "chat.completion",
    "model": "fake-model",
    "choices": [
        {
            "index": 0,
            "message": {"role": "assistant", "content": "fake reply"},
            "finish_reason": "stop",
        }
    ],
    "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
}


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("content-length") or 0)
        request = json.loads(self.rfile.read(length) or b"{}")
        if self.path != "/v1/chat/completions":
            self.send_error(404)
            return
        if self.headers.get("authorization") != "Bearer " + PROVIDER_KEY:
            self.send_error(401)
            return
        # Development only: a client asks for a provider error to exercise failed-call handling.
        fail = self.headers.get("x-fake-fail", "")
        if fail.isdigit() and 400 <= int(fail) <= 599:
            self.send_error(int(fail))
            return
        if request.get("stream"):
            self.stream(bool((request.get("stream_options") or {}).get("include_usage")))
            return
        body = json.dumps(REPLY).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def stream(self, include_usage: bool) -> None:
        """Six chunks a second apart, then usage last, so a client can abort mid-stream."""
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.end_headers()
        try:
            for i in range(6):
                delta = {"index": 0, "delta": {"content": f"word{i} "}}
                chunk = {
                    "id": "chatcmpl-dev",
                    "object": "chat.completion.chunk",
                    "model": "fake-model",
                    "choices": [delta],
                }
                self.wfile.write(b"data: " + json.dumps(chunk).encode() + b"\n\n")
                self.wfile.flush()
                time.sleep(1)
            if include_usage:
                last = {
                    "id": "chatcmpl-dev",
                    "object": "chat.completion.chunk",
                    "model": "fake-model",
                    "choices": [],
                    "usage": REPLY["usage"],
                }
                self.wfile.write(b"data: " + json.dumps(last).encode() + b"\n\n")
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
            print("upstream stream completed", flush=True)
        except (BrokenPipeError, ConnectionResetError):
            print("upstream stream aborted by the gateway", flush=True)

    def log_message(self, format: str, *args: object) -> None:
        print(
            f"upstream call {self.command} {self.path} {args[1] if len(args) > 1 else ''}",
            flush=True,
        )


if __name__ == "__main__":
    # All interfaces inside its container; the compose network publishes no port for it.
    http.server.ThreadingHTTPServer(("0.0.0.0", 18080), Handler).serve_forever()  # noqa: S104
