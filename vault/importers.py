"""Importers for manual provider exports (ChatGPT, Claude) and AWV's own export package.

Importers never touch the network and never extract archives to disk (no path traversal).
Each import returns an integrity report describing what was really captured and what the
export referenced but did not contain: only captured content is covered by the promise.
"""
import io
import json
import mimetypes
import posixpath
import zipfile
from datetime import datetime, timezone

from .store import Vault

MAX_ZIP_BYTES = 4 * 1024**3
SKIP_MEMBERS = {"chat.html", "user.json", "users.json", "message_feedback.json", "shared_conversations.json",
                "conversations.json", "projects.json", "memories.json"}


class ImportError_(Exception):
    pass


def _iso(v) -> str:
    if v is None:
        return ""
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(v, timezone.utc).isoformat(timespec="seconds")
    return str(v)


def _jload(data: bytes):
    try:
        return json.loads(data.decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError) as e:
        raise ImportError_(f"invalid JSON: {e}") from e


# ---------------- ChatGPT ----------------
def _chatgpt_text(content: dict, refs: list) -> str:
    ct = content.get("content_type")
    parts = content.get("parts") or []
    if ct == "code":
        return f"```{content.get('language', '')}\n{content.get('text', '')}\n```"
    out = []
    for p in parts:
        if isinstance(p, str):
            out.append(p)
        elif isinstance(p, dict):
            ptr = p.get("asset_pointer")
            if ptr:
                fid = ptr.rsplit("/", 1)[-1]
                refs.append({"name": f"image {fid}", "file_id": fid})
                out.append(f"[image: {fid}]")
            elif p.get("text"):
                out.append(p["text"])
    if not out and content.get("text"):
        out.append(content["text"])
    return "\n".join(out)


def _chatgpt_conv(c: dict) -> dict:
    mapping = c.get("mapping") or {}
    chain, node = [], c.get("current_node")
    seen = set()
    while node and node in mapping and node not in seen:
        seen.add(node)
        chain.append(mapping[node])
        node = mapping[node].get("parent")
    chain.reverse()
    if not chain:  # no current_node: fall back to time order
        chain = sorted(mapping.values(), key=lambda n: (n.get("message") or {}).get("create_time") or 0)
    msgs = []
    for n in chain:
        m = n.get("message")
        if not m:
            continue
        md = m.get("metadata") or {}
        role = (m.get("author") or {}).get("role", "unknown")
        if md.get("is_visually_hidden_from_conversation") or role == "system" and not (m.get("content") or {}).get("parts"):
            continue
        refs = [{"name": a.get("name") or a.get("id"), "file_id": a.get("id")} for a in md.get("attachments") or []]
        text = _chatgpt_text(m.get("content") or {}, refs)
        if not text.strip() and not refs:
            continue
        msgs.append({"role": role, "text": text, "time": _iso(m.get("create_time")), "attachments": refs})
    return {"title": c.get("title") or "Untitled", "project": "", "provider": "chatgpt",
            "created": _iso(c.get("create_time")), "updated": _iso(c.get("update_time")),
            "source_id": c.get("conversation_id") or c.get("id") or "", "messages": msgs}


# ---------------- Claude ----------------
def _claude_conv(c: dict, projects: dict, text_files: list) -> dict:
    msgs = []
    for m in c.get("chat_messages") or []:
        text = m.get("text") or "\n".join(b.get("text", "") for b in m.get("content") or [] if b.get("type") == "text")
        refs = []
        for a in m.get("attachments") or []:
            name = a.get("file_name") or "attachment.txt"
            content = a.get("extracted_content")
            ref = {"name": name, "file_id": None}
            if content:
                ref["inline_key"] = f"{m.get('uuid')}:{name}"
                text_files.append((ref["inline_key"], name, content))
            refs.append(ref)
        for f in m.get("files") or []:
            refs.append({"name": f.get("file_name") or f.get("file_uuid"), "file_id": f.get("file_uuid"),
                         "file_name": f.get("file_name")})
        role = {"human": "user"}.get(m.get("sender"), m.get("sender") or "unknown")
        if text.strip() or refs:
            msgs.append({"role": role, "text": text, "time": _iso(m.get("created_at")), "attachments": refs})
    return {"title": c.get("name") or "Untitled", "project": projects.get(c.get("project_uuid"), ""),
            "provider": "claude", "created": _iso(c.get("created_at")), "updated": _iso(c.get("updated_at")),
            "source_id": c.get("uuid") or "", "messages": msgs}


# ---------------- orchestration ----------------
def detect(convs) -> str:
    if isinstance(convs, dict) and convs.get("format") == "awv-export-v1":
        return "awv"
    if isinstance(convs, list) and convs:
        if "mapping" in convs[0]:
            return "chatgpt"
        if "chat_messages" in convs[0]:
            return "claude"
    if isinstance(convs, list) and not convs:
        return "empty"
    raise ImportError_("unrecognised export format (expected ChatGPT/Claude conversations.json or an AWV package)")


def import_bytes(vault: Vault, filename: str, data: bytes, project: str = "") -> dict:
    members: dict[str, bytes] = {}
    if zipfile.is_zipfile(io.BytesIO(data)):
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            if sum(i.file_size for i in z.infolist()) > MAX_ZIP_BYTES:
                raise ImportError_("archive too large")
            for i in z.infolist():
                if i.is_dir():
                    continue
                members[posixpath.normpath(i.filename).lstrip("/")] = z.read(i)
    else:
        members[filename or "conversations.json"] = data

    conv_key = next((k for k in members if posixpath.basename(k) == "conversations.json"), None)
    if conv_key is None:
        conv_key = next((k for k in members if k.endswith(".json")), None)
    if conv_key is None:
        raise ImportError_("no conversations.json found in the upload")
    raw = _jload(members[conv_key])
    fmt = detect(raw)

    report = {"file": filename, "format": fmt, "conversations_found": 0, "added": 0, "updated": 0,
              "unchanged": 0, "kept_existing": 0, "messages": 0, "files_stored": 0,
              "attachments_referenced": 0, "attachments_missing": [], "warnings": []}

    projects, text_files = {}, []
    if fmt == "awv":
        return _import_awv(vault, raw, report)

    pj = next((k for k in members if posixpath.basename(k) == "projects.json"), None)
    if pj:
        try:
            for p in _jload(members[pj]):
                projects[p.get("uuid")] = p.get("name", "")
                for d in p.get("docs") or []:
                    if d.get("content"):
                        _store_file(vault, report, "claude-project", f"{p.get('uuid')}:{d.get('uuid') or d.get('filename')}",
                                    d.get("filename") or "doc.txt", d["content"].encode(), p.get("name", ""))
        except ImportError_ as e:
            report["warnings"].append(f"projects.json ignored: {e}")

    convs = []
    for c in raw if fmt != "empty" else []:
        try:
            convs.append(_chatgpt_conv(c) if fmt == "chatgpt" else _claude_conv(c, projects, text_files))
        except Exception as e:  # keep going: one bad conversation must not lose the rest
            report["warnings"].append(f"skipped a conversation ({type(e).__name__}: {e})")
    report["conversations_found"] = len(raw) if fmt != "empty" else 0

    # store binary members first so conversations can link to them
    by_id: dict[str, str] = {}
    for key, content in members.items():
        base = posixpath.basename(key)
        if key == conv_key or base in SKIP_MEMBERS:
            continue
        iid = _store_file(vault, report, fmt, key, base, content, project)
        by_id[base] = iid
    inline_ids = {}
    for k, name, content in text_files:
        inline_ids[k] = _store_file(vault, report, fmt, "inline:" + k, name, content.encode(), project)

    for c in convs:
        sid = c.pop("source_id")
        if project and not c["project"]:
            c["project"] = project
        missing = 0
        for m in c["messages"]:
            for a in m["attachments"]:
                report["attachments_referenced"] += 1
                iid = inline_ids.get(a.get("inline_key"))
                if not iid and a.get("file_id"):
                    fid = a["file_id"]
                    iid = next((v for k, v in by_id.items() if fid in k or fid.replace("file_", "file-") in k), None)
                if not iid and a.get("file_name"):
                    iid = by_id.get(a["file_name"])
                a["item_id"], a["captured"] = iid, bool(iid)
                if not iid:
                    missing += 1
                    report["attachments_missing"].append(f"{c['title']}: {a['name']}")
        c["n_missing_attachments"] = missing
        meta = {k: c[k] for k in ("title", "project", "provider", "created", "updated")}
        meta.update(n_messages=len(c["messages"]), n_missing_attachments=missing)
        _, status = vault.add_item("conversation", fmt, sid or c["title"] + c["created"], meta,
                                   json.dumps({"messages": c["messages"]}, ensure_ascii=False).encode())
        report[status] += 1
        report["messages"] += len(c["messages"])
    _finish(vault, report)
    return report


def _store_file(vault, report, source, sid, name, content: bytes, project):
    mime = mimetypes.guess_type(name)[0] or "application/octet-stream"
    iid, status = vault.add_item("file", source, sid, {"name": name, "mime": mime, "project": project,
                                                         "created": ""}, content)
    if status in ("added", "updated"):
        report["files_stored"] += 1
    return iid


def _import_awv(vault, raw, report):
    for c in raw.get("conversations", []):
        meta = {k: c.get(k, "") for k in ("title", "project", "provider", "created", "updated")}
        msgs = c.get("messages", [])
        meta.update(n_messages=len(msgs), n_missing_attachments=0)
        _, st = vault.add_item("conversation", "awv", c.get("id") or c.get("title", ""), meta,
                               json.dumps({"messages": msgs}, ensure_ascii=False).encode())
        report[st] += 1
        report["messages"] += len(msgs)
    report["conversations_found"] = len(raw.get("conversations", []))
    _finish(vault, report)
    return report


def _finish(vault, report):
    report["complete"] = (report["conversations_found"] == report["added"] + report["updated"] +
                          report["unchanged"] + report["kept_existing"] and not report["attachments_missing"])
    vault.log_import(report)
