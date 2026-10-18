"""Encrypted vault storage (SQLite). All content and metadata are AES-GCM encrypted;
only ids, kind, sizes, timestamps of import and keyed MACs are stored in clear."""
import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

from . import crypto

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS items (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, source_key TEXT NOT NULL UNIQUE,
  mac TEXT NOT NULL, meta BLOB NOT NULL, body BLOB NOT NULL,
  size INTEGER NOT NULL, imported_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tokens (provider TEXT PRIMARY KEY, blob BLOB NOT NULL, saved_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS imports (id TEXT PRIMARY KEY, at TEXT NOT NULL, report BLOB NOT NULL);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class VaultError(Exception):
    pass


class Vault:
    def __init__(self, path: str):
        self.path = path
        self._dk: bytes | None = None
        self._index: sqlite3.Connection | None = None
        self._lock = threading.RLock()

    # ---------- lifecycle ----------
    def exists(self) -> bool:
        return os.path.exists(self.path)

    @property
    def unlocked(self) -> bool:
        return self._dk is not None

    def _db(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, check_same_thread=False)
        db.row_factory = sqlite3.Row
        return db

    def init(self, passphrase: str, kdf: dict | None = None):
        if self.exists():
            raise VaultError("vault already exists")
        if len(passphrase) < crypto.MIN_PASSPHRASE:
            raise VaultError(f"passphrase must be at least {crypto.MIN_PASSPHRASE} characters")
        dk, header = crypto.new_wrapped_key(passphrase, kdf)
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        with self._lock, self._db() as db:
            db.executescript(SCHEMA)
            db.execute("INSERT INTO meta VALUES ('header', ?)", (json.dumps(header),))
            db.execute("INSERT INTO meta VALUES ('created', ?)", (now(),))
            db.execute("INSERT INTO meta VALUES ('format', '1')")
        os.chmod(self.path, 0o600)
        self._dk = dk
        self._build_index()

    def unlock(self, passphrase: str):
        if not self.exists():
            raise VaultError("vault not found")
        with self._lock:
            db = self._db()
            row = db.execute("SELECT value FROM meta WHERE key='header'").fetchone()
            db.close()
            if not row:
                raise VaultError("not a vault file")
            self._dk = crypto.unwrap_key(passphrase, json.loads(row["value"]))
            self._build_index()

    def lock(self):
        with self._lock:
            self._dk = None
            if self._index:
                self._index.close()
            self._index = None

    def change_passphrase(self, old: str, new: str):
        self.require_unlocked()
        if len(new) < crypto.MIN_PASSPHRASE:
            raise VaultError(f"passphrase must be at least {crypto.MIN_PASSPHRASE} characters")
        with self._lock, self._db() as db:
            header = json.loads(db.execute("SELECT value FROM meta WHERE key='header'").fetchone()["value"])
            crypto.unwrap_key(old, header)
            db.execute("UPDATE meta SET value=? WHERE key='header'", (json.dumps(crypto.rewrap_key(self._dk, new)),))

    def require_unlocked(self):
        if self._dk is None:
            raise VaultError("vault is locked")

    # ---------- records ----------
    def _enc(self, rid, kind, label, data: bytes) -> bytes:
        return crypto.seal(self._dk, data, f"{rid}|{kind}|{label}".encode())

    def _dec(self, rid, kind, label, blob: bytes) -> bytes:
        return crypto.unseal(self._dk, blob, f"{rid}|{kind}|{label}".encode())

    def add_item(self, kind: str, source: str, source_id: str, meta: dict, body: bytes) -> tuple[str, str]:
        """Returns (item_id, status) with status in added|unchanged|updated|kept_existing."""
        self.require_unlocked()
        skey = crypto.mac(self._dk, f"{source}\0{source_id}".encode())
        body_mac = crypto.mac(self._dk, body)
        with self._lock, self._db() as db:
            row = db.execute("SELECT id, mac, meta FROM items WHERE source_key=?", (skey,)).fetchone()
            if row and row["mac"] == body_mac:
                return row["id"], "unchanged"
            if row:
                old = json.loads(self._dec(row["id"], kind, "meta", row["meta"]))
                # never replace a fuller backup with a shorter one (e.g. provider truncated history)
                if meta.get("n_messages", 0) < old.get("n_messages", 0):
                    return row["id"], "kept_existing"
                rid, status = row["id"], "updated"
            else:
                rid, status = uuid.uuid4().hex, "added"
            meta = {**meta, "source": source, "source_id": source_id}
            db.execute(
                "INSERT OR REPLACE INTO items VALUES (?,?,?,?,?,?,?,?)",
                (rid, kind, skey, body_mac, self._enc(rid, kind, "meta", json.dumps(meta).encode()),
                 self._enc(rid, kind, "body", body), len(body), now()),
            )
        self._index_item(rid, meta, body)
        return rid, status

    def list_items(self, kind: str | None = None) -> list[dict]:
        self.require_unlocked()
        db = self._db()
        q = "SELECT id, kind, meta, size, imported_at FROM items" + (" WHERE kind=?" if kind else "")
        out = []
        for r in db.execute(q, (kind,) if kind else ()):
            m = json.loads(self._dec(r["id"], r["kind"], "meta", r["meta"]))
            out.append({"id": r["id"], "kind": r["kind"], "size": r["size"], "imported_at": r["imported_at"], **m})
        db.close()
        out.sort(key=lambda x: x.get("updated") or x.get("created") or "", reverse=True)
        return out

    def get_item(self, rid: str) -> tuple[dict, bytes]:
        self.require_unlocked()
        db = self._db()
        r = db.execute("SELECT * FROM items WHERE id=?", (rid,)).fetchone()
        db.close()
        if not r:
            raise VaultError("item not found")
        meta = json.loads(self._dec(rid, r["kind"], "meta", r["meta"]))
        meta.update(id=rid, kind=r["kind"], size=r["size"], imported_at=r["imported_at"])
        return meta, self._dec(rid, r["kind"], "body", r["body"])

    def get_conversation(self, rid: str) -> dict:
        meta, body = self.get_item(rid)
        return {**meta, **json.loads(body)}

    # ---------- search ----------
    def _build_index(self):
        if self._index:
            self._index.close()
        self._index = sqlite3.connect(":memory:", check_same_thread=False)
        self._index.execute(
            "CREATE VIRTUAL TABLE docs USING fts5(id UNINDEXED, kind UNINDEXED, title, project, text, "
            "tokenize='unicode61 remove_diacritics 2')")
        db = self._db()
        for r in db.execute("SELECT id, kind, meta, body FROM items"):
            try:
                meta = json.loads(self._dec(r["id"], r["kind"], "meta", r["meta"]))
                self._index_item(r["id"], meta, self._dec(r["id"], r["kind"], "body", r["body"]))
            except crypto.CorruptRecord:
                continue  # reported by verify()
        db.close()

    def _index_item(self, rid, meta, body: bytes):
        if not self._index:
            return
        text = ""
        is_conv = meta.get("n_messages") is not None
        if is_conv:
            try:
                text = "\n".join(m.get("text", "") for m in json.loads(body).get("messages", []))
            except ValueError:
                pass
        elif len(body) < 2_000_000 and (meta.get("mime", "").startswith("text/") or meta.get("name", "").endswith((".md", ".txt", ".json", ".csv", ".py", ".js", ".html"))):
            text = body.decode("utf-8", "ignore")
        with self._lock:
            self._index.execute("DELETE FROM docs WHERE id=?", (rid,))
            self._index.execute(
                "INSERT INTO docs VALUES (?,?,?,?,?)",
                (rid, "conversation" if is_conv else "file",
                 meta.get("title") or meta.get("name") or "", meta.get("project") or "", text))

    def search(self, query: str, limit: int = 50) -> list[dict]:
        self.require_unlocked()
        terms = [t.replace('"', "") for t in query.split() if t.strip()]
        if not terms:
            return []
        fts = " ".join(f'"{t}"*' for t in terms)
        with self._lock:
            rows = self._index.execute(
                "SELECT id, kind, title, project, snippet(docs, 4, '[[', ']]', '…', 14) FROM docs "
                "WHERE docs MATCH ? ORDER BY rank LIMIT ?", (fts, limit)).fetchall()
        return [{"id": r[0], "kind": r[1], "title": r[2], "project": r[3], "snippet": r[4]} for r in rows]

    # ---------- tokens (never in clear) ----------
    def save_token(self, provider: str, token: str):
        self.require_unlocked()
        with self._lock, self._db() as db:
            db.execute("INSERT OR REPLACE INTO tokens VALUES (?,?,?)",
                       (provider, self._enc(provider, "token", "blob", token.encode()), now()))

    def get_token(self, provider: str) -> str | None:
        self.require_unlocked()
        db = self._db()
        r = db.execute("SELECT blob FROM tokens WHERE provider=?", (provider,)).fetchone()
        db.close()
        return self._dec(provider, "token", "blob", r["blob"]).decode() if r else None

    def list_tokens(self) -> list[dict]:
        db = self._db()
        out = [{"provider": r["provider"], "saved_at": r["saved_at"]} for r in db.execute("SELECT * FROM tokens")]
        db.close()
        return out

    def revoke_tokens(self) -> int:
        """Delete all stored tokens and compact the file so freed pages are rewritten."""
        with self._lock:
            db = self._db()
            n = db.execute("DELETE FROM tokens").rowcount
            db.commit()
            db.execute("VACUUM")
            db.close()
        return n

    # ---------- import log ----------
    def log_import(self, report: dict):
        self.require_unlocked()
        rid = uuid.uuid4().hex
        with self._lock, self._db() as db:
            db.execute("INSERT INTO imports VALUES (?,?,?)",
                       (rid, now(), self._enc(rid, "import", "report", json.dumps(report).encode())))

    def list_imports(self) -> list[dict]:
        self.require_unlocked()
        db = self._db()
        out = [{"at": r["at"], **json.loads(self._dec(r["id"], "import", "report", r["report"]))}
               for r in db.execute("SELECT * FROM imports ORDER BY at DESC")]
        db.close()
        return out

    # ---------- integrity ----------
    def verify(self) -> dict:
        """Decrypt every record and recompute its keyed checksum."""
        self.require_unlocked()
        db = self._db()
        ok, bad = 0, []
        for r in db.execute("SELECT * FROM items"):
            try:
                self._dec(r["id"], r["kind"], "meta", r["meta"])
                body = self._dec(r["id"], r["kind"], "body", r["body"])
                if crypto.mac(self._dk, body) != r["mac"]:
                    raise crypto.CorruptRecord("checksum mismatch")
                ok += 1
            except crypto.CorruptRecord as e:
                bad.append({"id": r["id"], "kind": r["kind"], "error": str(e)})
        db.close()
        return {"checked": ok + len(bad), "ok": ok, "corrupt": bad, "healthy": not bad}

    def stats(self) -> dict:
        db = self._db()
        rows = db.execute("SELECT kind, COUNT(*) c, SUM(size) s FROM items GROUP BY kind").fetchall()
        db.close()
        return {r["kind"]: {"count": r["c"], "bytes": r["s"] or 0} for r in rows}


def open_unlocked_copy(src: Vault, path: str) -> Vault:
    """Open another vault file (e.g. a snapshot) with the session's key, for verification."""
    src.require_unlocked()
    v = Vault(path)
    v._dk = src._dk
    return v
