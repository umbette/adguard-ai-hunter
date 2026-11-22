# AI Hunter — Home Assistant Add-on

Protezione locale da telemetria invasiva di Smart TV/dispositivi IoT e minacce DNS (DGA, botnet, C2), con triage interattivo 1-click sullo smartphone tramite Home Assistant Companion App.

---

## Caratteristiche Principali

- **Integrazione Nativa AdGuard Home:** Ispezione in streaming del querylog di AdGuard Home (`core-adguard`).
- **Device Fingerprinting & Friendly Names:** Riconoscimento automatico del nome del dispositivo (es. `📺 Samsung Smart TV (192.168.1.104)`, `💡 Reolink Cam Garage`) leggendo le etichette AdGuard e reverse PTR lookup.
- **Triage Interattivo su Smartphone:** Notifica push con pulsanti operativi:
  - `[Blocca per 📺 Samsung Smart TV]` — applica regola mirata `$client=192.168.1.104` in AdGuard.
  - `[Blocca per Tutta la Rete]` — blocca il dominio globalmente.
  - `[Ignora (30 giorni)]` — snooze automatico del dominio apex registrato (`*.samsung.com`).
- **Doppia Euristica Locale:** Shannon Entropy normalizzata per DGA + Velocity Burst Tracker per telemetria OEM.
- **AI Triage (Opzionale):** Analisi semantica tramite Gemini 2.5 Flash con fallback automatico a zero-dipendenza.

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
