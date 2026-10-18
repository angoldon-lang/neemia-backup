"""Export portable work packages: Markdown (human / any AI assistant) + JSON (re-importable).

WARNING: exports are PLAINTEXT by design, so they can be used elsewhere."""
import io
import json
import re
import zipfile

from . import crypto
from .store import Vault

ROLE = {"user": "User", "assistant": "Assistant", "system": "System", "tool": "Tool"}


def slug(s: str, n=60) -> str:
    return (re.sub(r"[^\w\-. ]+", "", s, flags=re.U).strip().replace(" ", "-")[:n]) or "untitled"


def conv_markdown(c: dict) -> str:
    out = [f"# {c['title']}", ""]
    for k in ("project", "provider", "created", "updated"):
        if c.get(k):
            out.append(f"- **{k}**: {c[k]}")
    out.append("")
    for m in c["messages"]:
        out.append(f"## {ROLE.get(m['role'], m['role'].title())}" + (f"  \n*{m['time']}*" if m.get("time") else ""))
        out += ["", m["text"], ""]
        for a in m.get("attachments", []):
            out.append(f"- attachment: `{a['name']}`" + ("" if a.get("captured") or a.get("item_id") else " *(not captured)*"))
        if m.get("attachments"):
            out.append("")
    return "\n".join(out)


def build_package(vault: Vault, project: str | None = None) -> tuple[bytes, dict]:
    items = vault.list_items()
    if project:
        items = [i for i in items if i.get("project") == project]
    buf = io.BytesIO()
    manifest, convs, index = [], [], ["# AI Workspace Vault export", ""]
    used = set()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        def put(path, data: bytes):
            z.writestr(path, data)
            manifest.append({"path": path, "sha256": crypto.sha256(data), "bytes": len(data)})

        for it in items:
            if it["kind"] == "conversation":
                c = vault.get_conversation(it["id"])
                convs.append({"id": c["source_id"], **{k: c.get(k, "") for k in ("title", "project", "provider", "created", "updated")},
                              "messages": c["messages"]})
                path = f"conversations/{slug(c['project'] or 'no-project')}/{slug(c['title'])}-{it['id'][:8]}.md"
                put(path, conv_markdown(c).encode())
                index.append(f"- [{c['title']}]({path}) — {c['project'] or 'no project'} ({len(c['messages'])} messages)")
            else:
                _, body = vault.get_item(it["id"])
                path = f"files/{it['id'][:8]}-{slug(it['name'], 80)}"
                put(path, body)
                index.append(f"- file: [{it['name']}]({path})")
        put("INDEX.md", "\n".join(index).encode())
        put("awv-package.json", json.dumps({"format": "awv-export-v1", "conversations": convs},
                                           ensure_ascii=False, indent=1).encode())
        z.writestr("manifest.json", json.dumps({"files": manifest}, indent=1))
    return buf.getvalue(), {"conversations": len(convs), "files": len(items) - len(convs)}
