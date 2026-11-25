# Sentinel — Guida Piattaforme (iOS, Android, Home Server, PC, Vecchi Dispositivi)

**Sentinel™** protegge tutta la rete domestica (**Sentinel Core**) e i browser fuori casa (**Sentinel Shield**):

---

## 1. Home Server & Domotica (Copertura Totale LAN Wi-Fi)

### Home Assistant Add-on Nativо
1. In Home Assistant: **Impostazioni ➔ Componenti aggiuntivi ➔ Store ➔ Menu (⋮) ➔ Repository**.
2. Aggiungi `https://github.com/umbette/sentinel` e installa **Sentinel Core** (`host_network: true`, console integrata in **Ingress**, notifiche mobili push azionabili).

### Docker Compose (Mini-PC, NAS, Unraid, CasaOS, Raspberry Pi)
```bash
git clone https://github.com/umbette/sentinel.git
cd sentinel/code && cp .env.example .env && cp config.example.yaml config.yaml
docker compose up -d
```

---

## 2. Smartphone Attivo del Proprietario (iPhone iOS & Android)

### PWA Console su Schermata Home
Apri la console Web Sentinel (`http://<ip-home-server>:8087/`) da **Safari (iOS)** o **Chrome (Android)** e seleziona **Aggiungi alla schermata Home**: il manifest PWA integrato installa la console come app nativa locale.

### Protezione DNS Cifrata su iPhone / iPad (`.mobileconfig`) anche su 4G/5G
Apple iOS supporta nativamente DNS cifrati **DoH (`HTTPS`)** o **DoT (`TLS`)** a livello di sistema operativo senza app VPN costose:
```bash
PYTHONPATH=. .venv/bin/python scripts/generate_ios_dns_profile.py \
  --doh-url "https://dns.casa-tua.ts.net/dns-query" \
  --server-ip "100.64.0.10" \
  --output sentinel-ios-dns.mobileconfig
```
Invia `sentinel-ios-dns.mobileconfig` su iPhone/iPad (AirDrop/email locale) ➔ **Impostazioni ➔ Profilo scaricato ➔ Installa**.

### Estensione Browser su iOS / macOS Safari & Android
* **iOS & macOS Safari Web Extension:** iPhone non accetta pacchetti `.zip` Chrome direttamente; converti l'estensione su Mac con lo strumento ufficiale Apple:
  ```bash
  ./scripts/export_ios_safari_extension.sh
  ```
* **Android:** compatibile con browser basati su Chromium MV3 che supportano estensioni (es. **Edge Canary / Kiwi / Quetta**) oppure via tunnel WireGuard split-tunnel verso casa (vedi [MOBILE_AND_AUTO_VPN_GUIDE.md](MOBILE_AND_AUTO_VPN_GUIDE.md)).

---

## 3. PC (Windows, macOS, Linux)

Installa **Sentinel Shield `0.4.1`** (`sentinel-shield-v0.4.1.zip` o cartella [`extension/`](../extension/)) su **Chrome, Edge o Brave** (zero permessi globali invasivi di default, blocco Phishing/Brand 47 domini, Bare-IP C2 guard, Anti-Dynamic Pricing DNR e Cookie Guard opt-in). Su macOS puoi compilarla anche per Safari con Xcode.

---

## 4. Vecchi Dispositivi (Vecchio Laptop Linux, Raspberry Pi, Armbian TV Box)

> **Nota tecnica trasparente:** per proteggere *tutta la rete di casa* a livello DNS, Sentinel necessita di un nodo Linux/ARM stabile collegato al router (Raspberry Pi, mini-PC, Armbian TV Box o vecchio portatile Linux). Uno smartphone Android non rootato **non** viene usato come gateway DNS di rete per evitare instabilità IP e limiti di Android senza root.

Installazione rapida su vecchio laptop Linux / Pi / TV Box Armbian:
```bash
chmod +x scripts/setup_old_device.sh
./scripts/setup_old_device.sh
```
