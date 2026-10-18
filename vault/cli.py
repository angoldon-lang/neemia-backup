"""Command line interface: `awv` (or `python -m vault`)."""
import argparse
import getpass
import json
import os
import sys

from . import backup, exporter, importers
from .store import Vault, VaultError
from .crypto import WrongPassphrase, CorruptRecord

DEFAULT_PATH = os.environ.get("AWV_VAULT", os.path.join("my-vault", "vault.db"))


def _pass(args, confirm=False):
    p = os.environ.get("AWV_PASSPHRASE")
    if p:
        return p
    p = getpass.getpass("Vault passphrase: ")
    if confirm and getpass.getpass("Repeat passphrase: ") != p:
        sys.exit("passphrases differ")
    return p


def _open(args) -> Vault:
    v = Vault(args.vault)
    v.unlock(_pass(args))
    return v


def main(argv=None):
    ap = argparse.ArgumentParser(prog="awv", description="AI Workspace Vault")
    ap.add_argument("--vault", default=DEFAULT_PATH, help="vault file (default: %(default)s, or $AWV_VAULT)")
    sp = ap.add_subparsers(dest="cmd", required=True)
    sp.add_parser("init")
    p = sp.add_parser("import"); p.add_argument("file"); p.add_argument("--project", default="")
    p = sp.add_parser("search"); p.add_argument("query")
    sp.add_parser("list")
    p = sp.add_parser("show"); p.add_argument("id")
    sp.add_parser("verify")
    sp.add_parser("status")
    p = sp.add_parser("snapshot"); p.add_argument("--dest")
    p = sp.add_parser("restore"); p.add_argument("snapshot")
    p = sp.add_parser("export"); p.add_argument("out"); p.add_argument("--project")
    p = sp.add_parser("token-set"); p.add_argument("provider")
    sp.add_parser("revoke-tokens")
    p = sp.add_parser("serve"); p.add_argument("--port", type=int, default=8765)
    a = ap.parse_args(argv)

    try:
        if a.cmd == "init":
            Vault(a.vault).init(_pass(a, confirm=True)); print("vault created:", a.vault)
        elif a.cmd == "restore":
            print("previous vault kept as", backup.restore_snapshot(Vault(a.vault), a.snapshot))
        elif a.cmd == "revoke-tokens":
            print("tokens removed:", Vault(a.vault).revoke_tokens())  # no passphrase needed to destroy
        elif a.cmd == "serve":
            from .server import serve
            serve(a.vault, a.port)
        else:
            v = _open(a)
            if a.cmd == "import":
                with open(a.file, "rb") as f:
                    r = importers.import_bytes(v, os.path.basename(a.file), f.read(), a.project)
                print(json.dumps(r, indent=2, ensure_ascii=False))
            elif a.cmd == "search":
                for r in v.search(a.query):
                    print(f"{r['id'][:8]}  [{r['kind']}] {r['title']}  — {r['snippet']}")
            elif a.cmd == "list":
                for i in v.list_items("conversation"):
                    print(f"{i['id'][:8]}  {i['updated'][:10]}  {i['project'] or '-':15} {i['title']} ({i['n_messages']} msgs)")
            elif a.cmd == "show":
                full = next((i["id"] for i in v.list_items() if i["id"].startswith(a.id)), a.id)
                print(exporter.conv_markdown(v.get_conversation(full)))
            elif a.cmd == "verify":
                r = v.verify(); print(json.dumps(r, indent=2)); sys.exit(0 if r["healthy"] else 2)
            elif a.cmd == "status":
                print(json.dumps({"stats": v.stats(), "snapshots": len(backup.list_snapshots(v)),
                                  "tokens": v.list_tokens(), "imports": v.list_imports()[:5]}, indent=2, ensure_ascii=False))
            elif a.cmd == "snapshot":
                print(json.dumps(backup.create_snapshot(v, a.dest), indent=2))
            elif a.cmd == "export":
                data, info = exporter.build_package(v, a.project)
                with open(a.out, "wb") as f:
                    f.write(data)
                print(f"wrote {a.out}", info)
            elif a.cmd == "token-set":
                v.save_token(a.provider, getpass.getpass("Token (hidden): ")); print("stored encrypted")
    except (VaultError, WrongPassphrase, CorruptRecord, importers.ImportError_) as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
