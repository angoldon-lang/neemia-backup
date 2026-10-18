"""Acceptance scenario: import -> encrypted vault -> incident (tokens removed) -> offline recovery -> export."""
import json
import os
import socket
import sys
import tempfile
import unittest
import urllib.request
import zipfile
import io
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))
from vault import backup, exporter, importers  # noqa: E402
from vault.crypto import WrongPassphrase  # noqa: E402
from vault.store import Vault  # noqa: E402
import make_fixtures as fx  # noqa: E402

FAST = {"n": 2**10, "r": 8, "p": 1}  # test-only; production default is n=2**15
PW = "correct horse battery"


class Acceptance(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "vault.db")
        self.v = Vault(self.path)
        self.v.init(PW, FAST)

    def test_full_scenario(self):
        # 1-2 import with integrity report
        r1 = importers.import_bytes(self.v, "export.zip", fx.chatgpt_zip())
        r2 = importers.import_bytes(self.v, "conversations.json", fx.claude_json())
        self.assertEqual((r1["format"], r1["added"], r1["messages"]), ("chatgpt", 1, 3))
        self.assertEqual(r1["attachments_missing"], ["Offerta Rossi SpA: perso.pdf"])
        self.assertFalse(r1["complete"])  # honest: one attachment was never in the export
        self.assertEqual((r2["format"], r2["added"]), ("claude", 1))
        self.assertTrue(r2["complete"])
        # idempotent re-import
        self.assertEqual(importers.import_bytes(self.v, "export.zip", fx.chatgpt_zip())["unchanged"], 1)
        self.v.save_token("chatgpt", "sk-SECRET-SESSION-TOKEN")
        snap = backup.create_snapshot(self.v)
        self.assertTrue(snap["verified"])
        # 3 nothing in clear on disk
        raw = open(self.path, "rb").read()
        for needle in (b"Zebra-42", b"Offerta Rossi", b"SECRET-SESSION", b"Kubernetes"):
            self.assertNotIn(needle, raw)
        # 4 incident: tokens removed, vault closed
        self.assertEqual(self.v.revoke_tokens(), 1)
        self.assertNotIn(b"SECRET-SESSION", open(self.path, "rb").read())
        self.v.lock()
        # 5 offline recovery: any network connect fails
        real = socket.socket.connect
        socket.socket.connect = lambda *a, **k: (_ for _ in ()).throw(OSError("offline"))
        try:
            with self.assertRaises(WrongPassphrase):
                Vault(self.path).unlock("wrong passphrase!!")
            v = Vault(self.path)
            v.unlock(PW)
            hits = v.search("zebra")  # prefix + case-insensitive, hits conversation and attached file
            self.assertEqual({h["kind"] for h in hits}, {"conversation", "file"})
            conv = next(i for i in v.list_items("conversation") if i["title"] == "Offerta Rossi SpA")
            c = v.get_conversation(conv["id"])
            self.assertEqual([m["role"] for m in c["messages"]], ["user", "assistant", "user"])
            att = c["messages"][0]["attachments"]
            self.assertTrue(att[0]["captured"] and not att[1]["captured"])
            self.assertIn("Zebra-42", v.get_item(att[0]["item_id"])[1].decode())
            self.assertTrue(v.verify()["healthy"])
            # 6 export reusable package
            data, info = exporter.build_package(v)
        finally:
            socket.socket.connect = real
        z = zipfile.ZipFile(io.BytesIO(data))
        names = z.namelist()
        self.assertTrue(any(n.endswith(".md") and n.startswith("conversations/") for n in names))
        self.assertIn("awv-package.json", names)
        self.assertEqual(info["conversations"], 2)
        # round trip into a brand new vault (the "other account/assistant")
        v2 = Vault(os.path.join(self.dir, "other.db"))
        v2.init(PW, FAST)
        r = importers.import_bytes(v2, "awv-package.json", z.read("awv-package.json"))
        self.assertEqual((r["format"], r["added"]), ("awv", 2))

    def test_corruption_detected(self):
        importers.import_bytes(self.v, "c.json", fx.claude_json())
        import sqlite3
        db = sqlite3.connect(self.path)
        body = bytearray(db.execute("SELECT body FROM items ORDER BY rowid LIMIT 1").fetchone()[0])
        body[20] ^= 1
        db.execute("UPDATE items SET body=? WHERE rowid=(SELECT MIN(rowid) FROM items)", (bytes(body),))
        db.commit(); db.close()
        res = self.v.verify()
        self.assertFalse(res["healthy"])
        self.assertEqual(len(res["corrupt"]), 1)

    def test_restore_snapshot(self):
        importers.import_bytes(self.v, "c.json", fx.claude_json())
        snap = backup.create_snapshot(self.v)
        importers.import_bytes(self.v, "export.zip", fx.chatgpt_zip())
        backup.restore_snapshot(self.v, snap["path"])
        v = Vault(self.path); v.unlock(PW)
        self.assertEqual(len(v.list_items("conversation")), 1)

    def test_change_passphrase(self):
        self.v.change_passphrase(PW, "another long passphrase")
        with self.assertRaises(WrongPassphrase):
            Vault(self.path).unlock(PW)
        Vault(self.path).unlock("another long passphrase")

    def test_shorter_reimport_never_overwrites(self):
        importers.import_bytes(self.v, "export.zip", fx.chatgpt_zip())
        trunc = json.loads(zipfile.ZipFile(io.BytesIO(fx.chatgpt_zip())).read("conversations.json"))
        trunc[0]["current_node"] = "n1"  # provider "forgot" later messages
        r = importers.import_bytes(self.v, "conversations.json", json.dumps(trunc).encode())
        self.assertEqual(r["kept_existing"], 1)

    def test_server_api_auth(self):
        from vault.server import make_server
        srv = make_server(os.path.join(self.dir, "srv.db"), 0)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{port}"
        with self.assertRaises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(base + "/api/state")
        self.assertEqual(e.exception.code, 401)
        req = urllib.request.Request(base + "/api/state", headers={"X-AWV-Token": srv.api_token})
        self.assertFalse(json.load(urllib.request.urlopen(req))["exists"])
        srv.shutdown()


if __name__ == "__main__":
    unittest.main()
