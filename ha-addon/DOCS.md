# Sentinel Core — Home Assistant Add-on

Difesa DNS locale, 15 scudi di privacy IoT, correlazione IP C2/malicious CDN-safe, Crypto Vault + Stanza Sterile, Zero-Trust Device Admission Control, Scan on Demand e console live integrata nativamente in Home Assistant Ingress (zero telemetria cloud).

---

## Caratteristiche Principali

- **Integrazione Nativa DNS:** Ispezione in streaming del querylog locale di AdGuard Home con regole granulari `$client=IP` e zero telemetria verso il cloud.
- **15 Scudi Specializzati IoT & Privacy:** Protezione deterministica per Smart TV (ACR), robot aspirapolvere (video/LiDAR), stampanti 3D (Maker IP Guard), console gaming (SysNAND safe), auto connesse (LexisNexis/Verisk), friggitrici/elettrodomestici smart, IP camera P2P, box TV Badbox, controllo genitori e reti ospiti.
- **Scudo Anti-Dynamic Pricing:** Neutralizzazione automatica delle reti di profilazione comportamentale e retargeting (Criteo, AppsFlyer, Adjust, Kochava, Hotjar, FullStory, SessionCam) per evitare rincari dinamici su voli e hotel.
- **Scan on Demand & Zero-Trust Admission Control:** Audit della rete in 4 vettori (port probing, UPnP IGD, backtracking 48h, DNS health score 0–100) e notifiche push istantanee alla connessione di nuovi dispositivi Wi-Fi.
- **Estensione Companion Browser (`Sentinel Shield` MV3):** Protezione endpoint fuori casa (phishing lookalike, Anti-Dynamic Pricing DNR a zero permessi e Cookie & Tracking Param Guard opt-in) disponibile in [`extension/`](https://github.com/umbette/sentinel/tree/main/extension).

---

## Configurazione

Configura i parametri visualmente dalla scheda **Configurazione** dell'Add-on in Home Assistant:

| Parametro | Descrizione | Default |
|---|---|---|
| `adguard_url` | URL dell'istanza AdGuard Home (usa `http://core-adguard:80` con l'Add-on ufficiale) | `http://core-adguard:80` |
| `adguard_username` | Nome utente amministratore di AdGuard | `admin` |
| `adguard_password` | Password amministratore di AdGuard | `""` |
| `gemini_api_key` | (Opzionale) Chiave API Google AI Studio per classificazione semantica | `""` |
| `notify_service` | Servizio di notifica Home Assistant (es. `notify.mobile_app_tuo_telefono`) | `notify.notify` |
| `admission_enabled` | Abilita il controllo Zero-Trust all'ingresso di nuovi dispositivi LAN | `false` |
| `quarantine_unapproved` | Isola automaticamente in DNS i nuovi dispositivi finché non vengono approvati | `false` |
| `notify_on_new_device` | Invia notifica push azionabile quando appare un nuovo dispositivo | `true` |

> In Ingress Home Assistant le chiamate API interne usano percorsi relativi `./api/...`; per accesso diretto standalone è supportata l'autenticazione via `SENTINEL_API_KEY`.
