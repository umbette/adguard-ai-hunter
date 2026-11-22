# Sentinel Core — Home Assistant Add-on

Protezione locale per l'intera rete domestica: scudo anti-dynamic pricing per i viaggi, crypto vault per wallet e dApp Web3, caregiver watchdog contro SMS/phishing ai familiari, e silenziamento della telemetria Smart TV/IoT con triage interattivo 1-click via Home Assistant Companion App.

---

## Caratteristiche Principali

- **Integrazione Nativa DNS:** Ispezione in streaming del querylog locale di AdGuard Home o resolver DNS.
- **Scudo Prezzi Dinamici:** Neutralizzazione automatica delle reti di profilazione e discriminazione tariffaria (Criteo, AppsFlyer, Adjust, Kochava, SessionCam).
- **Crypto Vault:** Protezione nodi RPC, contrasto a wallet drainer e phishing omografo IDN Punycode.
- **Caregiver & Family Watchdog:** Riconoscimento immediato di portali clone (Poste, banche, SPID, INPS, corrieri) con notifica istantanea per-device.
- **Device Fingerprinting & Friendly Names:** Riconoscimento automatico del tipo di dispositivo (es. `📺 Samsung Smart TV`, `📱 Smartphone Mamma`, `💻 Workstation`) leggendo le etichette client e reverse PTR.
- **Triage Interattivo su Smartphone:** Notifica push con pulsanti operativi immediati:
  - `[Blocca per 📺 Samsung Smart TV]` — applica regola mirata `$client=IP`.
  - `[Blocca per Tutta la Rete]` — blocca il dominio globalmente.
  - `[Ignora (30 giorni)]` — whitelist temporanea con scadenza automatica.

---

## Configurazione

Configura i parametri visualmente dalla scheda **Configurazione** dell'Add-on in Home Assistant:

| Parametro | Descrizione | Default |
|---|---|---|
| `adguard_url` | URL dell'istanza AdGuard Home (usa `http://core-adguard:80` se usi l'Add-on ufficiale) | `http://core-adguard:80` |
| `adguard_username` | Nome utente amministratore di AdGuard | `admin` |
| `adguard_password` | Password amministratore di AdGuard | `""` |
| `gemini_api_key` | (Opzionale) Chiave API Google AI Studio per classificazione semantica | `""` |
| `notify_service` | Servizio di notifica Home Assistant (es. `notify.mobile_app_tuo_telefono`) | `notify.notify` |
