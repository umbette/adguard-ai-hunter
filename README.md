# AI Hunter

[![CI Test Suite](https://github.com/umbette/adguard-ai-hunter/actions/workflows/ci.yml/badge.svg)](https://github.com/umbette/adguard-ai-hunter/actions/workflows/ci.yml)
[![Tests: 39 Passing](https://img.shields.io/badge/Tests-39%20Passing-brightgreen.svg)](tests/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Home Assistant Add-on](https://img.shields.io/badge/Home%20Assistant-Add--on%20Ready-blue?logo=home-assistant)](ha-addon/)
[![AdGuard Home](https://img.shields.io/badge/AdGuard%20Home-Supported-green?logo=adguard)](https://adguard.com/adguard-home.html)
[![Manifest V3](https://img.shields.io/badge/Chrome%20Extension-Manifest%20V3-yellow?logo=google-chrome)](extension/)
[![Docker](https://img.shields.io/badge/Docker-Multi--Arch-2496ED?logo=docker)](Dockerfile)

**Autonomous Smart Home Security, Anti-Dynamic Pricing, Crypto Vault & Threat Shield for AdGuard Home and Home Assistant.**

AI Hunter is a 100% local-first, zero-cloud-telemetry network watchdog and behavioral anomaly detector. It bridges your local DNS resolver (**AdGuard Home**) with your smart home automation (**Home Assistant**) to detect real-world threats that static blocklists miss: predatory airline/hotel price discrimination, Web3 wallet drainers, deceptive family phishing SMS links, and invasive Smart TV surveillance.

---

## 🌟 Key Protection Pillars

### 1. 🛡️ Anti-Dynamic Pricing & Travel Protection
Online booking engines, airlines, and hotel aggregators use behavioral retargeting and cross-app attribution networks to profile purchasing intent and increase fares dynamically when you search repeatedly.
* **Intercepts 18+ Profiling Networks:** Blocks data brokers including Criteo, AppsFlyer, Adjust, Kochava, Branch Metrics, Singular, SessionCam, QuantumMetric, and Demdex.
* **Per-Device Containment:** Flags tracking attempts specifically on booking devices (e.g., iPhone, MacBook) and deploys surgical rules (`||domain^$client=IP`) without breaking site functionality.

### 2. 🔐 Crypto Vault & Financial Shield
Protects high-value crypto wallets (MetaMask, Phantom, Ledger, Trezor), DeFi protocols (Uniswap, Curve, Aave), and digital banks (Revolut, Binance, Coinbase).
* **Official RPC Node Integrity:** Whitelist enforcement for verified blockchain RPC endpoints (`mainnet.infura.io`, `eth.llamarpc.com`, `cloudflare-eth.com`, `polygon-rpc.com`) prevents malicious RPC hijacking.
* **Unicode NFKD Homograph Detection:** Unmasks deceptive IDN Punycode mirror domains (e.g. `xn--uniswp-tta.org` -> `uniswáp.org`) before signatures are broadcast.
* **Wallet Drainer Regex Signatures:** Detects automated phishing kits (`claim-airdrop`, `connect-wallet`, `token-reward`, `ledger-live-update`).

### 3. 👵 Family & Caregiver Anti-Phishing Watchdog
Protects family members and elderly parents who are vulnerable to deceptive SMS, WhatsApp, and delivery phishing traps.
* **Zero-Trust Brand Spoofing Heuristics:** Blocks clones of national postal services (Poste Italiane, BRT, DHL, GLS), digital identity providers (SPID, Lepida, ArubaPEC), tax portals (Agenzia delle Entrate, INPS), and e-commerce platforms.
* **Contextual Push Notifications:** Generates real-time, device-labeled alerts on your mobile phone via Home Assistant Companion (*"🚨 Phishing attempt blocked on 📱 Galaxy A14 (Mamma)"*) with instant 1-click triage buttons.

### 4. 📺 Device Resolution & Smart TV Stealth
Standard DNS resolvers only show raw IP addresses (`192.168.1.45`), making device identification tedious.
* **Contextual Device Categorization:** Correlates AdGuard Home client registries and non-blocking reverse PTR lookups to tag queries with human-friendly device names and icons:
  * 📺 **Smart TV / Streaming Box**
  * 📱 **Smartphone / Tablet**
  * 💻 **Computer / Workstation**
  * 💡 **IoT / Smart Home Gadget**
* **ACR & Microphone Muting:** Blocks Automatic Content Recognition (ACR) telemetries on Samsung and LG TVs without interrupting Netflix, YouTube, or Prime Video playback.

### 5. ⚡ Local-First Behavioral Anomaly & DGA Detection
* **Multi-Label Shannon Entropy ($H > 3.85$):** Evaluates subdomain and domain core randomness in real-time streaming mode to intercept algorithmic domain generation (DGAs) used by malware and botnets.
* **Sliding Window Burst Tracking:** Detects anomalous high-frequency DNS query spikes from rogue IoT devices.
* **Gemini Flash Triage:** Asynchronous classification with strict JSON schemas and automatic heuristic fallback if offline.

---

## 🏛️ Architecture & Privacy Guarantees

```
+---------------------------------------------------------------------------------+
|                                 HOME NETWORK                                    |
|                                                                                 |
|  [📱 Mobile]   [📺 Smart TV]   [💻 PC]   [💡 IoT]                               |
|        │             │            │         │                                   |
|        ▼             ▼            ▼         ▼                                   |
|  ┌────────────────────────────────────────────────────────┐                     |
|  │                  ADGUARD HOME RESOLVER                 │                     |
|  │  - Static Filter Blocklists (HaGeZi, OISD, AI Hunter)  │                     |
|  │  - Low-latency local cache (< 1ms)                     │                     |
|  └───────────────────────────┬────────────────────────────┘                     |
|                              │ Query Log Stream                                 |
|                              ▼                                                  |
|  ┌────────────────────────────────────────────────────────┐                     |
|  │                   AI HUNTER DAEMON                     │                     |
|  │  • Device Resolver (Smart TV 📺 / Mobile 📱)           │                     |
|  │  • Anti-Dynamic Pricing Engine                         │                     |
|  │  • Crypto & Financial Vault                            │                     |
|  │  • Multi-Label Shannon Entropy ($H > 3.85$)            │                     |
|  └───────────────────────────┬────────────────────────────┘                     |
|                              │ Outbound WebSocket (No open ports)               |
|                              ▼                                                  |
|  ┌────────────────────────────────────────────────────────┐                     |
|  │                 HOME ASSISTANT CORE                    │                     |
|  │  - Rich Push Notification with Device Context          │                     |
|  │  - Interactive 1-Click Triage: [Blocca per 📺]         │                     |
|  └────────────────────────────────────────────────────────┘                     |
+---------------------------------------------------------------------------------+
```

* **100% Local-First & Zero Inbound Ports:** Communicates with Home Assistant over an authenticated outbound WebSocket (`ws://.../api/websocket`). No open inbound firewall ports required.
* **Transactional Read-Modify-Write Rule Injection:** Interacts with AdGuard Home via atomic `GET` -> patch -> `POST` cycles, ensuring custom user rules and standard blocklists are never overwritten.
* **Air-Gap Friendly:** Stores decisions locally in SQLite WAL mode (`hunter_decisions.db`).

---

## 🚀 Installation & Deployment

### Option A: Home Assistant Add-on (Recommended)

AI Hunter is packaged as an official multi-arch Home Assistant Add-on (`aarch64`, `amd64`, `armv7`).

1. In Home Assistant, navigate to **Settings** ➔ **Add-ons** ➔ **Add-on Store**.
2. Click the three dots (top right) ➔ **Repositories** ➔ Add:
   ```text
   https://github.com/umbette/adguard-ai-hunter
   ```
3. Select **AI Hunter**, configure your AdGuard credentials, and click **Start**.

### Option B: Docker Compose (Standalone Server / Proxmox / Unraid)

```bash
git clone https://github.com/umbette/adguard-ai-hunter.git
cd adguard-ai-hunter
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

---

## 🧩 Companion Chrome Extension: Hunter Shield (MV3)

For endpoint protection when traveling or using public Wi-Fi outside your home network, this repository includes **Hunter Shield**, an ultra-lightweight Manifest V3 Chrome/Edge extension located in [`extension/`](extension/).

* **Declarative Net Request (DNR):** 0 host permissions required (`action: "block"`).
* **Zero Cloud Telemetry:** Operates 100% offline using a compiled snapshot of the Public Suffix List (8,700+ suffixes) and verified brand heuristics (23 financial, postal, and e-commerce brands).
* **1-Click Session Bypass:** Built-in collision-free unblocking for false positives.

To install in developer mode:
1. Open `chrome://extensions/` and enable **Developer mode**.
2. Click **Load unpacked** and select the [`extension/`](extension/) directory.

---

## 📡 Community Filter Blacklist

AI Hunter compiles high-confidence IoCs and confirmed algorithmic threat domains into a standard AdGuard / uBlock Origin compatible blocklist:

* **Filter URL:**  
  `https://raw.githubusercontent.com/umbette/adguard-ai-hunter/main/filters/threat_blacklist.txt`

Add this URL directly into **AdGuard Home** (Filters ➔ DNS Blocklists) for static upstream blocking.

---

## 🧪 Test Suite & Verification

The codebase includes comprehensive unit, integration, and sandboxed browser tests:

```bash
# Run Python backend test suite (33 tests)
PYTHONPATH=. .venv/bin/pytest -v tests/

# Run Manifest V3 sandboxed browser runtime tests (6 tests)
node --test tests/test_extension_runtime.mjs
```

**Total:** 39 passed in ~1.3s.

---

## 📄 License

Distributed under the [MIT License](LICENSE). Contributions, bug reports, and whitelist pull requests are welcome!
