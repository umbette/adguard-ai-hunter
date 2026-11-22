# Sentinel

[![CI Test Suite](https://github.com/umbette/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/umbette/sentinel/actions/workflows/ci.yml)
[![Tests: 61 Passing](https://img.shields.io/badge/Tests-61%20Passing-brightgreen.svg)](tests/)
[![Shields: 14 Active](https://img.shields.io/badge/Shields-14%20Active-10b981.svg)](#-14-specialized-cyber-defense--privacy-shields)
[![Privacy: Zero--Telemetry](https://img.shields.io/badge/Privacy-Zero--Telemetry-blueviolet.svg)](#-zero-knowledge-device-catalog--1-click-unbreak)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Home Assistant Add-on](https://img.shields.io/badge/Home%20Assistant-Add--on%20Ready-blue?logo=home-assistant)](ha-addon/)
[![DNS Resolvers](https://img.shields.io/badge/DNS%20Resolvers-AdGuard%20%7C%20Pi--hole%20%7C%20Native-green)](https://adguard.com/adguard-home.html)
[![Manifest V3](https://img.shields.io/badge/Chrome%20Extension-Sentinel%20Shield-yellow?logo=google-chrome)](extension/)
[![Docker](https://img.shields.io/badge/Docker-Multi--Arch-2496ED?logo=docker)](Dockerfile)

**Autonomous Cyber Defense Console, 14 Hardware & IoT Privacy Shields, Dynamic Pricing Protection, Crypto Vault & Zero-Knowledge Unbreak Catalog for Home Assistant & Local DNS Resolvers.**

Sentinel is a 100% local-first, zero-cloud-telemetry network security watchdog, behavioral anomaly detector, and privacy console. It bridges your local DNS resolver (**AdGuard Home**, **Pi-hole**, or standalone) with your smart home automation (**Home Assistant**) to detect and neutralize real-world threats that static blocklists miss: predatory airline/hotel price discrimination, Web3 wallet drainers, deceptive family phishing SMS links, automotive driver profiling, and invasive smart gadget surveillance.

---

## 🌟 14 Specialized Cyber Defense & Privacy Shields

Sentinel operates an array of 14 deterministic, specialized hardware and software shields engineered to neutralize targeted data exfiltration without breaking device usability:

| Shield | Category | Scope & Protection Target |
| :--- | :--- | :--- |
| **🛡️ Anti-Dynamic Pricing** | Travel & Shopping | Blocks 18+ behavioral retargeting networks (Criteo, AppsFlyer, Adjust) to prevent airline/hotel ticket price gouging on repeat searches. |
| **🔐 Crypto & Web3 Vault** | Financial Defense | Whitelist enforcement for official blockchain RPC nodes (`infura.io`, `llamarpc.com`), IDN Punycode homograph unmasking, and wallet-drainer signatures. |
| **👵 Caregiver Anti-Phishing** | Family Protection | Intercepts deceptive delivery (Poste, BRT, DHL) and tax/banking phishing SMS links targeted at elderly relatives, with real-time push alerts. |
| **📺 Smart TV Stealth** | Living Room Privacy | Blocks Automatic Content Recognition (ACR) and audio sampling on Samsung Tizen and LG webOS TVs while keeping Netflix, YouTube, and Prime Video intact. |
| **🧹 Vacuum Camera & LiDAR Guard** | Smart Home IoT | Prevents interior floorplan uploads and camera video exfiltration to offshore clouds on Ecovacs, Roborock, and Dreame vacuums. |
| **🖨️ Bambu Lab & Maker IP Shield** | 3D Printing IP | Blocks cloud diagnostics and CAD print exfiltration while preserving full local network LAN control and camera streaming. |
| **🎮 Nintendo Switch 90DNS Guard** | Gaming Consoles | Built-in local implementation of 90DNS to protect modified consoles from Nintendo Superban (Error 2124-4007). |
| **🚗 Automotive Driving Telemetry** | Connected Vehicles | Neutralizes sneaky driving telematics and broker exfiltration (LexisNexis, Verisk, Otonomo) that inflate auto insurance premiums. |
| **🍳 Smart Kitchen & Appliance** | Kitchen Appliances | Silences telemetry, usage habit profiling, and ad SDKs embedded inside smart air fryers (Cosori, VeSync) and kitchen appliances. |
| **📷 Budget IP Camera P2P Isolation** | Security Cameras | Shuts down vulnerable P2P cloud relay channels (`iotcplatform.com`, `p2pcam.net`) on generic cameras while keeping local RTSP open. |
| **🧒 Youth Safeguard** | Child Safety | Blocks predatory videochats (Omegle/OmeTV clones), CSGO skin gambling, and generative AI nudify/deepfake platforms. |
| **📦 Badbox & Budget AOSP TV C2** | Factory Malware | Cuts Command & Control (C2) beaconing on sub-€150 Android TV boxes infected with Badbox/Peachpit residential proxy botnets. |
| **⚡ Gaming Latency Optimizer** | PC Gaming | Suppresses background launcher telemetries (Steam, Epic Games) that create micro-stutter and network jitter during competitive matches. |
| **🌙 Kids Bedtime Blackout** | Parental Controls | Scheduled evening DNS blackout for TikTok, Instagram, Roblox, and Discord on children's devices. |

---

## 🔓 Zero-Knowledge Device Catalog & 1-Click Unbreak

IoT devices (robot vacuums, connected cars, 3D printers, smart plugs) have two distinct traffic streams:
1. **Control Plane (Essential):** Mobile companion app authentication, pairing, cleaning start/stop, status synchronization (`api-app.*.ecouser.net`, `api-eu.roborock.com`, `owner-api.teslamotors.com`).
2. **Data Plane (Predatory):** Video uploads, LiDAR maps, driving broker profiling, and ad attribution (`datasink.*`, `telemetry.lexisnexis.com`).

Broad blocklists frequently break companion mobile apps when away from home. Sentinel solves this through an **open crowdsourced catalog and a 3-tier Zero-Knowledge unbreak system**:

```
+─────────────────────────────────────────────────────────────────────────────────+
|                        ZERO-KNOWLEDGE UNBREAK PIPELINE                          |
|                                                                                 |
|  [App Fails to Connect] ➔ [Open Sentinel Dashboard] ➔ [Click: 🔓 Sblocca]       |
|                                         │                                       |
|                                         ▼                                       |
|                  Tier 1: Instant Local 1-Click Self-Resolution                  |
|                  - Injects @@||domain^ into AdGuard Home in < 500ms             |
|                  - Zero bytes egressed to the internet                          |
|                                         │                                       |
|                                         ▼ (Optional)                            |
|                  Tier 2: Zero-Knowledge Community Reporting                     |
|                  - User clicks [ 📢 Condividi Fix ]                             |
|                  - Generates sanitized GitHub issue (NO IP, NO MAC, NO PII)     |
|                                         │                                       |
|                                         ▼                                       |
|                  Tier 3: Crowdsourced Catalog (device_profiles.yaml)            |
|                  - Merged into official repository                              |
|                  - Distributed globally to all Sentinel users via Git/Releases  |
+─────────────────────────────────────────────────────────────────────────────────+
```

* **Open Community Catalog:** Check [`sources/device_profiles.yaml`](sources/device_profiles.yaml) for verified device rules covering Ecovacs, Roborock, Dreame, Bambu Lab, Prusa, Cosori, Shelly, Tuya, Tesla, BMW, and Smart TVs.
* **100% Zero-Tracking Guarantee:** Sentinel contains **zero telemetry, zero phone-home pings, and zero analytics**. Community feedback is strictly voluntary, client-generated, and verified open source.

---

## 🚗 In-Car Projection & Mobile VPN Compatibility

Using full-tunnel WireGuard or OpenVPN while driving can trigger **Android Auto Communication Error 21** or wireless Apple CarPlay disconnects because local P2P Wi-Fi Direct sockets (`192.168.43.1`) are inadvertently captured by the VPN routing table.

* Read the complete technical guide and 30-second Split-Tunneling fix in **[docs/MOBILE_AND_AUTO_VPN_GUIDE.md](docs/MOBILE_AND_AUTO_VPN_GUIDE.md)**.

---

## 📊 Real-Time Cyber Defense Console

Sentinel includes a responsive, dark-mode web console running at `http://localhost:8087` (and embedded natively in Home Assistant sidebar via Ingress):

* **Brave Shields / Pi-hole Style Metrics:** Total DNS queries, Blocked threat ratio (%), Estimated € Dynamic Pricing savings, and active shield health.
* **Interactive Threat & Unbreak Center:** Live list of top intercepted domains with 1-click **[ 🔓 Sblocca ]** and **[ 📢 Segnala ]** buttons.
* **Network Device Leaderboard:** Contextual device icons and protection status across all network clients.

---

## 🏛️ System Architecture

```
+─────────────────────────────────────────────────────────────────────────────────+
|                                 HOME NETWORK                                    |
|                                                                                 |
|  [📱 Mobile]   [📺 Smart TV]   [🚗 Car App]   [🧹 Vacuum]   [🖨️ 3D Printer]       |
|        │             │               │              │               │           |
|        ▼             ▼               ▼              ▼               ▼           |
|  ┌───────────────────────────────────────────────────────────────────────────┐  |
|  │              LOCAL DNS RESOLVER (ADGUARD HOME / PI-HOLE)                  │  |
|  │  - Static Filter Blocklists (HaGeZi, OISD, Sentinel Community)            │  |
|  │  - 14 Hardware & IoT Shields (140+ targeted user rules)                   │  |
|  │  - Low-latency local cache (< 1.2ms)                                      │  |
|  └─────────────────────────────────────┬─────────────────────────────────────┘  |
|                                        │ Query Stream                           |
|                                        ▼                                        |
|  ┌───────────────────────────────────────────────────────────────────────────┐  |
|  │                         SENTINEL CORE ENGINE                              │  |
|  │  • Contextual Device Resolver (10+ categories)                            │  |
|  │  • Anti-Dynamic Pricing & Travel Protection                               │  |
|  │  • Crypto Vault & Punycode De-obfuscation                                 │  |
|  │  • Multi-Label Shannon Entropy ($H > 3.85$)                               │  |
|  │  • Zero-Knowledge Unbreak Engine (/api/unbreak)                           │  |
|  └───────────────────┬─────────────────────────────────┬─────────────────────┘  |
|                      │                                 │                        |
|                      ▼                                 ▼                        |
|  ┌──────────────────────────────────────┐  ┌─────────────────────────────────┐  |
|  │    HOME ASSISTANT INTEGRATION        │  │     CYBER DEFENSE DASHBOARD     │  |
|  │  - Push alerts on mobile companion   │  │  - Port 8087 / HA Ingress       │  |
|  │  - Interactive 1-click triage        │  │  - 1-Click Unbreak & Stats      │  |
|  └──────────────────────────────────────┘  └─────────────────────────────────┘  |
+─────────────────────────────────────────────────────────────────────────────────+
```

---

## 🚀 Installation & Deployment

### Option A: Home Assistant Add-on (Recommended)

1. In Home Assistant, navigate to **Settings** ➔ **Add-ons** ➔ **Add-on Store**.
2. Click the three dots (top right) ➔ **Repositories** ➔ Add:
   ```text
   https://github.com/umbette/sentinel
   ```
3. Select **Sentinel Core**, configure your DNS credentials, and click **Start**. The dashboard will appear directly in your Home Assistant sidebar via Ingress.

### Option B: Docker Compose (Standalone Server / Proxmox / Unraid)

```bash
git clone https://github.com/umbette/sentinel.git
cd sentinel
cp .env.example .env
cp config.example.yaml config.yaml
```

Configure `.env`:
```ini
ADGUARD_USERNAME=admin
ADGUARD_PASSWORD=your_password
HASS_TOKEN=your_home_assistant_token
HASS_NOTIFY_SERVICE=notify
GEMINI_API_KEY=your_gemini_api_key
DATA_DIR=/app/data
```

Launch with Docker Compose:
```bash
docker compose up -d
```

Access the Cyber Defense Console at `http://your-server-ip:8087`.

---

## 🧩 Companion Chrome Extension: Sentinel Shield (MV3)

For endpoint protection when traveling or using public Wi-Fi outside your home network, this repository includes **Sentinel Shield**, an ultra-lightweight Manifest V3 Chrome/Edge extension located in [`extension/`](extension/).

* **Declarative Net Request (DNR):** 0 host permissions required (`action: "block"`).
* **Zero Cloud Telemetry:** Operates 100% offline using a compiled snapshot of the Public Suffix List (8,700+ suffixes) and verified brand heuristics (23 financial, postal, and e-commerce brands).
* **1-Click Session Bypass:** Built-in collision-free unblocking for false positives.

To install in developer mode:
1. Open `chrome://extensions/` and enable **Developer mode**.
2. Click **Load unpacked** and select the [`extension/`](extension/) directory.

---

## 📡 Community Filter Blacklist

Sentinel compiles high-confidence IoCs and confirmed algorithmic threat domains into a standard DNS blocklist:

* **Filter URL:**  
  `https://raw.githubusercontent.com/umbette/sentinel/main/filters/threat_blacklist.txt`

Add this URL directly into your DNS resolver (Filters ➔ DNS Blocklists) for static upstream blocking.

---

## 🧪 Test Suite & Verification

The codebase is thoroughly validated by comprehensive automated test suites:

```bash
# Run Python backend unit & integration tests (55 tests)
PYTHONPATH=. .venv/bin/pytest -v tests/

# Run Manifest V3 sandboxed browser runtime tests (6 tests)
node --test tests/test_extension_runtime.mjs
```

**Total:** 61 passed in ~1.3s (100% pass rate).

---

## 📄 License

Distributed under the [MIT License](LICENSE). Contributions, bug reports, and device profile pull requests are welcome!
