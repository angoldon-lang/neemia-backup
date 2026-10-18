# AI Workspace Vault (AWV)

> *Mantieni accessibili e riutilizzabili i lavori salvati, anche quando il tuo account AI diventa inaccessibile.*

Prodotto di AD Consulting S.p.A. Prima versione (v0.1): vault cifrato **locale**, indipendente dai provider AI,
con importazione, ricerca offline, verifica d'integrità, snapshot ed esportazione portabile.
Nato per uso personale, con un'architettura pronta per SaaS/MSP (vedi `docs/ARCHITECTURE.md`).

**La promessa riguarda solo i contenuti effettivamente acquisiti e verificati.** AWV lo dichiara in modo esplicito:
ogni importazione produce un report che elenca ciò che l'export *citava ma non conteneva* (es. allegati mancanti).

## Requisiti
- Python ≥ 3.10 (testato su 3.13) con SQLite FTS5 (incluso nelle distribuzioni standard)
- Libreria `cryptography` ≥ 42
- Un browser moderno per la UI (nessuna connessione Internet necessaria)

## Installazione
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .            # installa il comando `awv` (in alternativa: pip install cryptography e usa `python -m vault`)
```

## Avvio rapido
```bash
export AWV_VAULT=./my-vault/vault.db     # opzionale (default: my-vault/vault.db)
awv init                                  # crea il vault (chiede la passphrase, min. 10 caratteri)
awv serve                                 # UI su http://127.0.0.1:8765 (solo localhost)
```
Nella UI: *Importa* un export (`.zip` o `conversations.json`) → *Stato backup* → ricerca globale in alto →
*Esporta* per il pacchetto riutilizzabile.

### Come ottenere gli export
- **ChatGPT**: Impostazioni → Controllo dei dati → Esporta dati → file `.zip` via email.
- **Claude**: Impostazioni → Privacy → Esporta dati → `.zip` / `conversations.json`.
- Pacchetto AWV (`awv-package.json`): reimportabile in un altro vault.

> Connettori live (API/Session Token): il vault sa già conservare token **cifrati** (`awv token-set`) e rimuoverli
> (`awv revoke-tokens`), ma la v0.1 non scarica dati dai provider: usa export manuali, più stabili e conformi ai termini d'uso.

## CLI
| Comando | Funzione |
|---|---|
| `awv init` | crea il vault |
| `awv import FILE [--project NOME]` | importa export ChatGPT/Claude/AWV, stampa il report d'integrità |
| `awv list` / `awv search TESTO` / `awv show ID` | consultazione (offline) |
| `awv verify` | decifra e ricontrolla il checksum di ogni elemento (exit 2 se corrotto) |
| `awv snapshot [--dest DIR]` | snapshot consistente e verificato (+ sidecar SHA-256) |
| `awv restore SNAPSHOT` | ripristina uno snapshot (il vault attuale resta come `.pre-restore`) |
| `awv export OUT.zip [--project P]` | pacchetto Markdown + JSON + manifest SHA-256 (**in chiaro**) |
| `awv token-set PROVIDER` / `awv revoke-tokens` | gestione token (cifrati / rimozione + VACUUM) |
| `awv status` | riepilogo di cosa è protetto |

La passphrase può essere fornita con `AWV_PASSPHRASE` (solo per automazioni/test).

## Verificare lo scenario di accettazione
Automatico (importa → cifra → incidente con rimozione token → recupero **senza rete** → esportazione → reimport):
```bash
python -m unittest discover -s tests -v
```
Manuale con dati di esempio:
```bash
python tests/make_fixtures.py tests/fixtures
export AWV_VAULT=/tmp/demo/vault.db AWV_PASSPHRASE="demo passphrase 123"
awv init
awv import tests/fixtures/chatgpt-export.zip    # nota: "attachments_missing" onesto
awv import tests/fixtures/claude-conversations.json
awv snapshot && awv verify
awv revoke-tokens                               # simula l'incidente: token rimossi
# scollega la rete, poi:
awv search zebra && awv show <id> && awv export /tmp/demo/pacchetto.zip
```

## Struttura
```
vault/crypto.py     KDF scrypt, AES-256-GCM, HKDF/HMAC
vault/store.py      vault SQLite cifrato, ricerca FTS5 in memoria, token, verifica
vault/importers.py  ChatGPT, Claude, pacchetto AWV + report d'integrità
vault/backup.py     snapshot / restore
vault/exporter.py   export Markdown + JSON + manifest
vault/server.py     API locale + UI (vault/web/index.html)
docs/               PRODUCT.md, ARCHITECTURE.md, SECURITY.md
tests/              scenario di accettazione
```

## Limiti noti della v0.1
Nessun connettore live; la ricerca indicizza in RAM dopo lo sblocco (vault molto grandi → più memoria);
file binari non indicizzati (PDF/immagini sono conservati ma non ricercabili); l'export è in chiaro per scelta;
nessun recupero passphrase (per design). Vedi `docs/` per la roadmap.
