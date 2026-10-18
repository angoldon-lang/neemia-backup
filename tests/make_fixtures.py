"""Generate small synthetic provider exports for demos and tests:
   python tests/make_fixtures.py tests/fixtures"""
import io
import json
import os
import sys
import zipfile


def chatgpt_zip() -> bytes:
    def node(i, parent, role, text, t, children=(), meta=None):
        return {"id": i, "parent": parent, "children": list(children),
                "message": {"author": {"role": role}, "create_time": t, "metadata": meta or {},
                            "content": {"content_type": "text", "parts": [text]}}}
    conv = {"id": "c-offerta", "conversation_id": "c-offerta", "title": "Offerta Rossi SpA", "create_time": 1700000000,
            "update_time": 1700003600, "current_node": "n3", "mapping": {
                "root": {"id": "root", "parent": None, "children": ["n1"], "message": None},
                "n1": node("n1", "root", "user", "Prepara una offerta per migrazione cloud Zebra-42", 1700000001, ["n2"],
                           {"attachments": [{"id": "file-AAA111", "name": "capitolato.txt"},
                                            {"id": "file-GONE99", "name": "perso.pdf"}]}),
                "n2": node("n2", "n1", "assistant", "Ecco la bozza: fase 1 assessment, fase 2 migrazione.", 1700000002, ["n3"]),
                "n3": node("n3", "n2", "user", "Aggiungi prezzi e SLA", 1700000003)}}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("conversations.json", json.dumps([conv]))
        z.writestr("file-AAA111-capitolato.txt", "Capitolato: requisiti di migrazione Zebra-42")
        z.writestr("chat.html", "<html></html>")
    return buf.getvalue()


def claude_json() -> bytes:
    return json.dumps([{"uuid": "u-1", "name": "Architettura microservizi", "created_at": "2024-03-01T10:00:00Z",
                        "updated_at": "2024-03-01T11:00:00Z", "chat_messages": [
        {"uuid": "m1", "sender": "human", "text": "Disegna l'architettura Kubernetes", "created_at": "2024-03-01T10:00:00Z",
         "attachments": [{"file_name": "note.md", "extracted_content": "# Note\nUsare Helm"}], "files": []},
        {"uuid": "m2", "sender": "assistant", "text": "Propongo tre namespace e un ingress.", "created_at": "2024-03-01T10:01:00Z",
         "attachments": [], "files": []}]}]).encode()


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures"
    os.makedirs(out, exist_ok=True)
    open(os.path.join(out, "chatgpt-export.zip"), "wb").write(chatgpt_zip())
    open(os.path.join(out, "claude-conversations.json"), "wb").write(claude_json())
    print("fixtures written to", out)
