"""Snapshots of the (already encrypted) vault file, with sidecar checksum and verification."""
import hashlib
import json
import os
import shutil
import sqlite3
from datetime import datetime

from .store import Vault, VaultError, open_unlocked_copy


def snap_dir(vault: Vault) -> str:
    return os.path.join(os.path.dirname(os.path.abspath(vault.path)), "snapshots")


def _sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def create_snapshot(vault: Vault, dest_dir: str | None = None) -> dict:
    vault.require_unlocked()
    d = dest_dir or snap_dir(vault)
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, f"vault-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}.snap")
    src = sqlite3.connect(vault.path)
    dst = sqlite3.connect(path)
    src.backup(dst)  # consistent online copy
    dst.close()
    src.close()
    os.chmod(path, 0o600)
    check = open_unlocked_copy(vault, path).verify()
    info = {"path": path, "sha256": _sha(path), "bytes": os.path.getsize(path), "items": check["checked"],
            "verified": check["healthy"], "created": datetime.now().isoformat(timespec="seconds")}
    with open(path + ".json", "w") as f:
        json.dump(info, f, indent=2)
    return info


def list_snapshots(vault: Vault) -> list[dict]:
    d = snap_dir(vault)
    out = []
    if os.path.isdir(d):
        for n in sorted(os.listdir(d), reverse=True):
            if n.endswith(".snap.json"):
                with open(os.path.join(d, n)) as f:
                    out.append(json.load(f))
    return out


def restore_snapshot(vault: Vault, snapshot_path: str) -> str:
    """Replace the vault with a snapshot (the current file is kept as .pre-restore)."""
    meta = snapshot_path + ".json"
    if os.path.exists(meta):
        with open(meta) as f:
            if json.load(f)["sha256"] != _sha(snapshot_path):
                raise VaultError("snapshot checksum mismatch: file is damaged")
    vault.lock()
    keep = vault.path + ".pre-restore"
    if os.path.exists(vault.path):
        shutil.copy2(vault.path, keep)
    shutil.copy2(snapshot_path, vault.path)
    return keep
