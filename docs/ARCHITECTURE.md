# Architettura (CTO / Architect)
**Stack:** Python 3 + SQLite + `cryptography`; UI web statica servita in locale (nessun build step, nessuna dipendenza npm,
cross-platform, funziona offline). Scelto per essere leggero e verificabile; un wrapper Tauri/Electron può racchiudere la stessa UI.

Livelli: `importers` (formato provider → modello normalizzato) → `store.Vault` (unico punto di accesso a cifratura e DB) →
`backup`/`exporter`/`server`/`cli` (adattatori). Il modello normalizzato (conversazione = messaggi + allegati; file = blob) è
indipendente dal provider.

**Verso SaaS / MSP:** `Vault` è l'unica classe che parla con SQLite → sostituibile con un repository PostgreSQL
(id opachi e `source_key` univoco, adatti a una colonna `tenant_id`). Il modello a chiave dati avvolta (DK wrapped da KEK)
consente di avvolgere la DK per tenant con KMS/BYOK, recupero aziendale (key escrow opzionale) e condivisione MSP senza
ricifrare i record. Gli importers sono funzioni pure su bytes → eseguibili in worker asincroni. I connettori live saranno
plugin con la stessa interfaccia `import_bytes`.
