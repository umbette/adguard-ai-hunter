# Sentinel Core & Sentinel Shield — V1 Launch Checklist

Checklist operativa per il rilascio V1 zero-attrito (**P2.1 Chrome/Edge Extension** + **P2.2 Home Assistant Add-on / Docker**).

---

## P2.1 Chrome Web Store & Edge Add-ons (`Sentinel Shield v0.4.1`)

- **Pacchetto pronto:** [`sentinel-shield-v0.4.1.zip`](../sentinel-shield-v0.4.1.zip) compilato da [`extension/`](../extension/) con artefatti SSOT verificati da [`scripts/compile_ssot.py`](../scripts/compile_ssot.py).
- **Costo pubblicazione iniziale:** Chrome Web Store developer registration (`$5` una tantum), Microsoft Edge Add-ons (`€0`).

### Dichiarazione Permessi per la Review Google CWS
Usa queste motivazioni sintetiche nel form Privacy & Permissions della Chrome Developer Dashboard:

| Permesso | Stato | Motivazione Reviewer-Ready |
| :--- | :--- | :--- |
| `declarativeNetRequest` | Richiesto | Blocco 100% locale e zero-telemetry di domini phishing/C2 (`sentinel_ruleset`) e tracker di terze parti per prevenire dynamic pricing (`pricing_tracker_ruleset`), tramite regole statiche ed eccezioni per-tab (`action: "allow"`). |
| `webNavigation` | Richiesto | Intercetta in locale navigazioni top-level (`frameId === 0`) per verificare imitazioni di brand/omografi Punycode e mostrare la pagina informativa `pages/blocked.html` su blocchi DNR, senza trasmettere URL all'esterno. |
| `activeTab` | Richiesto | Legge esclusivamente il dominio del tab attivo quando l'utente apre il popup dell'estensione, per mostrare lo stato di sicurezza o consentire lo sblocco/pulizia cookie su richiesta esplicita. |
| `storage` | Richiesto | Salva localmente sul dispositivo preferenze scudi (`pricingShieldEnabled`, `cookieGuardEnabled`), eccezioni utente e badge tab di sessione. Nessuna sincronizzazione cloud esterna. |
| `cookies` + `<all_urls>` | **Opzionali (Opt-In)** | Richiesti *solo* se l'utente attiva esplicitamente **Cookie & Tracking Param Guard**, per rimuovere header `Cookie`/`Set-Cookie` di terze parti e pulire cookie di tracciamento su richiesta dal popup. |

### Dichiarazione Privacy ("Single Purpose & Zero Data Collection")
- **Single Purpose:** Protezione locale in tempo reale contro phishing lookalike/omografi, wallet drainer, tracciamento dynamic pricing e cookie di terze parti.
- **Data Collection:** **Zero raccolta dati.** Tutte le euristica (`BRANDS`, `DRAINER_PATTERNS`, `PUBLIC_SUFFIXES`, `BLOCKED_DOMAINS`, `BLOCKED_IPS`) vengono eseguite offline all'interno del Service Worker dell'estensione.

---

## P2.2 Home Assistant Add-on & Docker Release (`Sentinel Core`)

### Verifiche pre-rilascio prima del tag Git
1. Verifica SSOT e test automatici locali:
   ```bash
   cd /home/umbette/c:/Projects/Sentinel/code
   PYTHONPATH=. .venv/bin/python scripts/compile_ssot.py --check
   PYTHONPATH=. .venv/bin/pytest -q tests/
   node --test tests/test_extension_runtime.mjs
   ```
2. Controlla [`.env.example`](../.env.example) / [`config.example.yaml`](../config.example.yaml): nessuna credenziale reale o `data/*.db` inclusa nell'immagine Docker.
3. Build test immagine locale (se Docker Engine è attivo sull'host):
   ```bash
   docker build -t sentinel-core-test:0.4.1 .
   ```
