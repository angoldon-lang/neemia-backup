"""Local web UI + JSON API. Binds to 127.0.0.1 only. A random per-run API token embedded in the
served page protects the API against other local web pages (CSRF / DNS rebinding)."""
import json
import os
import secrets
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import backup, crypto, exporter, importers
from .store import Vault, VaultError

WEB = os.path.join(os.path.dirname(__file__), "web")
MAX_UPLOAD = 2 * 1024**3


def make_server(vault_path: str, port: int = 8765):
    vault = Vault(vault_path)
    api_token = secrets.token_urlsafe(24)

    class H(BaseHTTPRequestHandler):
        server_version = "AWV"

        def log_message(self, *a):
            pass

        def _send(self, code, body: bytes, ctype="application/json", extra=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code=200):
            self._send(code, json.dumps(obj, ensure_ascii=False).encode())

        def _host_ok(self):
            return self.headers.get("Host", "").split(":")[0] in ("127.0.0.1", "localhost")

        def _route(self, method):
            if not self._host_ok():
                return self._send(403, b"bad host", "text/plain")
            u = urllib.parse.urlparse(self.path)
            q = dict(urllib.parse.parse_qsl(u.query))
            if method == "GET" and u.path == "/":
                page = open(os.path.join(WEB, "index.html"), encoding="utf-8").read().replace("__API_TOKEN__", api_token)
                return self._send(200, page.encode(), "text/html; charset=utf-8")
            if not u.path.startswith("/api/"):
                return self._send(404, b"not found", "text/plain")
            if not secrets.compare_digest(self.headers.get("X-AWV-Token", ""), api_token):
                return self._json({"error": "unauthorized"}, 401)
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_UPLOAD:
                return self._json({"error": "upload too large"}, 413)
            raw = self.rfile.read(n) if n else b""
            try:
                return self._api(method, u.path[5:], q, raw)
            except crypto.WrongPassphrase:
                self._json({"error": "Wrong passphrase"}, 403)
            except (VaultError, importers.ImportError_, crypto.CorruptRecord) as e:
                self._json({"error": str(e)}, 400)
            except Exception as e:  # never leak a traceback with content
                self._json({"error": f"internal error: {type(e).__name__}"}, 500)

        def _api(self, method, path, q, raw):
            body = json.loads(raw) if raw and self.headers.get("Content-Type", "").startswith("application/json") else {}
            if path == "state":
                return self._json({"exists": vault.exists(), "unlocked": vault.unlocked})
            if path == "init":
                vault.init(body.get("passphrase", "")); return self._json({"ok": True})
            if path == "unlock":
                vault.unlock(body.get("passphrase", "")); return self._json({"ok": True})
            if path == "lock":
                vault.lock(); return self._json({"ok": True})
            vault.require_unlocked()
            if path == "status":
                snaps = backup.list_snapshots(vault)
                return self._json({"stats": vault.stats(), "snapshots": snaps, "tokens": vault.list_tokens(),
                                   "imports": vault.list_imports()[:10]})
            if path == "list":
                return self._json({"items": vault.list_items()})
            if path == "search":
                return self._json({"results": vault.search(q.get("q", ""))})
            if path == "conversation":
                return self._json(vault.get_conversation(q["id"]))
            if path == "file":
                meta, data = vault.get_item(q["id"])
                return self._send(200, data, "application/octet-stream",
                                  {"Content-Disposition": "attachment; filename*=UTF-8''" + urllib.parse.quote(meta.get("name", "file"))})
            if path == "import" and method == "POST":
                return self._json(importers.import_bytes(vault, q.get("filename", "upload"), raw, q.get("project", "")))
            if path == "verify":
                return self._json(vault.verify())
            if path == "snapshot" and method == "POST":
                return self._json(backup.create_snapshot(vault))
            if path == "export":
                data, info = exporter.build_package(vault, q.get("project") or None)
                return self._send(200, data, "application/zip", {"Content-Disposition": 'attachment; filename="awv-export.zip"'})
            if path == "revoke-tokens" and method == "POST":
                return self._json({"removed": vault.revoke_tokens()})
            if path == "token" and method == "POST":
                vault.save_token(body["provider"], body["token"]); return self._json({"ok": True})
            self._json({"error": "unknown endpoint"}, 404)

        def do_GET(self): self._route("GET")
        def do_POST(self): self._route("POST")

    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    srv.vault = vault
    srv.api_token = api_token
    return srv


def serve(vault_path, port=8765):
    srv = make_server(vault_path, port)
    print(f"AI Workspace Vault on http://127.0.0.1:{srv.server_address[1]}  (Ctrl+C to stop; works fully offline)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.vault.lock()
