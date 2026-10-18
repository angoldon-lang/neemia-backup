# Sicurezza (Security Engineer)
- **Chiave:** passphrase → scrypt (N=2^15, r=8, p=1, salt 16 B) → KEK; la KEK avvolge (AES-256-GCM) una chiave dati casuale a 256 bit. Cambiare passphrase = riavvolgere la chiave, senza ricifrare.
- **Record:** AES-256-GCM, nonce casuale 96 bit, AAD = `id|tipo|campo` (impedisce di spostare cifrati tra righe/campi). Cifrati contenuti e metadati (titoli, progetti, nomi file).
- **Checksum:** HMAC-SHA256 con sotto-chiave HKDF (non rivela hash dei contenuti); `verify` decifra e ricontrolla tutto. Snapshot: verificati alla creazione + SHA-256 sidecar.
- **Token:** solo nel vault, cifrati; `revoke-tokens` li elimina e fa VACUUM. Mai in chiaro su disco (testato).
- **In chiaro in memoria** solo dopo lo sblocco (chiave + indice di ricerca); `lock` li scarta. Python non garantisce l'azzeramento della memoria.
- **UI locale:** bind 127.0.0.1, controllo header Host, token API casuale per esecuzione, CSP, nessuna risorsa esterna.
- **Import:** nessuna estrazione su disco (niente path traversal), limite dimensione archivio.
- **Limiti:** nessun recupero passphrase; l'export è volutamente in chiaro; malware su dispositivo sbloccato fuori modello. Copiare snapshot su un secondo supporto (regola 3-2-1).
