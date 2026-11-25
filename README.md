# Sentinel Core & Sentinel Shield

<div align="center">
  <img src="extension/icons/icon128.png" alt="Sentinel Official Logo" width="128" style="border-radius: 22px; margin-bottom: 14px;" />
  <h3>100% Local-First DNS Defense, IoT Privacy Console &amp; Zero-Telemetry MV3 Extension</h3>
  <p>
    <strong>Hardware-independent home &amp; endpoint cyber-defense bridging AdGuard Home / Pi-hole, Home Assistant, and Chrome/Edge MV3.</strong>
  </p>
  <p>
    <a href="https://umbette.github.io/sentinel/"><strong>🌐 Official Website</strong></a> •
    <a href="#-core-capabilities"><strong>🛡️ Core Capabilities</strong></a> •
    <a href="#-15-specialized-cyber-defense--privacy-shields"><strong>🔒 15 IoT Shields</strong></a> •
    <a href="#-installation--quick-start"><strong>🚀 Quick Start</strong></a> •
    <a href="#-companion-chrome-extension-sentinel-shield-041-mv3"><strong>🧩 MV3 Extension</strong></a>
  </p>
</div>

[![CI Test Suite](https://github.com/umbette/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/umbette/sentinel/actions/workflows/ci.yml)
[![Shields: 15 Active](https://img.shields.io/badge/Shields-15%20Active-10b981.svg)](#-15-specialized-cyber-defense--privacy-shields)
[![Privacy: Zero-Telemetry](https://img.shields.io/badge/Privacy-Zero--Telemetry-blueviolet.svg)](#-zero-knowledge-device-catalog--1-click-unbreak)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](LICENSE)
[![Hardware License: PolyForm NC](https://img.shields.io/badge/Hardware%20%26%20Appliances-Noncommercial-orange.svg)](LICENSE-COMMERCIAL-HARDWARE)
[![Home Assistant Add-on](https://img.shields.io/badge/Home%20Assistant-Add--on%20Ready-blue?logo=home-assistant)](ha-addon/)
[![Docker](https://img.shields.io/badge/Docker-Multi--Arch-2496ED?logo=docker)](Dockerfile)

---

## 🛡️ Core Capabilities

**Sentinel** protects your household LAN and browsers strictly on your own hardware (**zero cloud telemetry, zero phone-home pings, zero external accounts**):

* **Sentinel Core (`src/`):** Autonomous DNS anomaly daemon integrating with **AdGuard Home** and **Home Assistant** — combining Multi-Label Shannon Entropy DGA detection (`H > 3.85`), CDN-safe Malicious IP & DNS-answer correlation (`src/ip_intel.py`), Zero-Trust Device Admission Control, Scan on Demand network auditing, and a dark-mode Ingress/Web Cockpit on port `8087`.
* **15 Deterministic IoT & Privacy Shields:** Stops Smart TV ACR snooping, vacuum camera/LiDAR uploads, 3D printer cloud telemetry, Badbox/Peachpit AOSP C2 beacons, automotive driving brokers, and dynamic travel pricing trackers without breaking companion apps.
* **Sentinel Shield (`extension/` — Chrome/Edge MV3 `0.4.1`):** Zero-permission-by-default browser extension with Punycode/homograph & brand impersonation detection across 47 SSOT-compiled brands, bare-IP threat protection, Anti-Dynamic Pricing DNR ruleset, and opt-in Cookie & Tracking Param Guard.
* **Proactive Threat Intelligence (`scripts/proactive_miner.py`):** Compiles zero-trust domain & CDN-excluded C2 IP feeds with sliding TTLs and strict Public Suffix List / RFC 1123 sanitization.

---

## 🌟 15 Specialized Cyber Defense & Privacy Shields

Sentinel Shield operates 15 deterministic defense profiles engineered to neutralize targeted data exfiltration without breaking usability:

| Shield | Category | Scope & Protection Target |
| :--- | :--- | :--- |
| **🛡️ Anti-Dynamic Pricing** | Travel & Shopping | Blocks 18+ behavioral retargeting networks (Criteo, AppsFlyer, Adjust) to prevent airline/hotel ticket price gouging on repeat searches. |
| **🔐 Crypto & Web3 Vault** | Financial Defense | Whitelist enforcement for official blockchain RPC nodes (`infura.io`, `llamarpc.com`), IDN Punycode homograph unmasking, and wallet-drainer signatures. |
| **👵 Caregiver Anti-Phishing** | Family Protection | Intercepts deceptive delivery (Poste, BRT, DHL) and tax/banking phishing SMS links targeted at elderly relatives, with real-time push alerts. |
| **📺 Smart TV Stealth** | Living Room Privacy | Blocks Automatic Content Recognition (ACR) and audio sampling on Samsung Tizen and LG webOS TVs while keeping Netflix, YouTube, and Prime Video intact. |
| **🧹 Vacuum Camera & LiDAR Guard** | Smart Home IoT | Prevents interior floorplan uploads and camera video exfiltration to offshore clouds on Ecovacs, Roborock, and Dreame vacuums. |
| **🖨️ 3D Printer & Maker IP Guard** | 3D Printing & Makers | Silences cloud diagnostics and telemetry across major 3D printer brands (Bambu Lab, Creality, Anycubic) while preserving full local LAN control (MQTT, OctoPrint/Klipper, local slicing). |
| **🎮 Gaming Console Telemetry Guard** | Gaming Consoles | Local filtering of crash telemetry and diagnostic logs for Nintendo Switch (SysNAND safe), PS5, and Xbox without impacting multiplayer or eShop. |
| **🚗 Automotive Driving Telemetry** | Connected Vehicles | Neutralizes sneaky driving telematics and broker exfiltration (LexisNexis, Verisk, Otonomo) that inflate auto insurance premiums. |
| **🍳 Smart Kitchen & Appliance** | Kitchen Appliances | Silences telemetry, usage habit profiling, and ad SDKs embedded inside smart air fryers (Cosori, VeSync) and kitchen appliances. |
| **📷 Budget IP Camera P2P Isolation** | Security Cameras | Shuts down vulnerable P2P cloud relay channels (`iotcplatform.com`, `p2pcam.net`) on generic cameras while keeping local RTSP open. |
| **🧒 Youth Safeguard** | Child Safety | Blocks predatory videochats (Omegle/OmeTV clones), CSGO skin gambling, and generative AI platforms. |
| **📦 Badbox & Budget AOSP TV C2** | Factory Malware | Cuts Command & Control (C2) beaconing on sub-€150 Android TV boxes infected with Badbox/Peachpit residential proxy botnets. |
| **⚡ Gaming Latency Optimizer** | PC Gaming | Suppresses background launcher telemetries (Steam, Epic Games) that create micro-stutter and network jitter during competitive matches. |
| **🌙 Kids Bedtime Blackout** | Parental Controls | Scheduled evening DNS blackout for TikTok, Instagram, Roblox, and Discord on children's devices. |
| **🍕 Public Venue & Guest Policy** | Retail & Hospitality | Blocks bandwidth-saturating video ads, background cryptomining, and public abuse on guest Wi-Fi while pre-empting POS and food delivery orders. |

---

## 🔓 Zero-Knowledge Device Catalog & 1-Click Unbreak

IoT devices have two distinct traffic streams:
1. **Control Plane (Essential):** Mobile companion app authentication, pairing, cleaning start/stop, status synchronization.
2. **Data Plane (Predatory):** Video uploads, LiDAR maps, driving broker profiling, and ad attribution.

Sentinel solves over-blocking through an open crowdsourced catalog and a 3-tier Zero-Knowledge unbreak system:

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
* **100% Zero-Tracking Guarantee:** Sentinel contains **zero telemetry, zero phone-home pings, and zero analytics**.

---

## 🚗 In-Car Projection & Mobile VPN Compatibility

Using full-tunnel WireGuard or OpenVPN while driving can trigger **Android Auto Communication Error 21** or wireless Apple CarPlay disconnects because local P2P Wi-Fi Direct sockets (`192.168.43.1`) are captured by the VPN routing table.

* Read the complete technical guide and 30-second Split-Tunneling fix in **[docs/MOBILE_AND_AUTO_VPN_GUIDE.md](docs/MOBILE_AND_AUTO_VPN_GUIDE.md)**.

---

## 📊 Real-Time Cyber Defense Console & Scan on Demand

Sentinel includes a responsive, dark-mode web console running at `http://localhost:8087` (and embedded natively in Home Assistant sidebar via Ingress):

* **🔍 Scan on Demand & Network Exposure Audit:** Probes active LAN devices, checks exposed ports (Telnet 23, RTSP 554, HTTP 80/8080) and UPnP mappings, and calculates an overall **Network Health Score (0–100)**.
* **🔔 Zero-Trust Device Admission Control:** Instant push notification when an unknown device connects to the Wi-Fi for the first time with 1-click **[ ✅ Approva ]** or **[ ⛔ Isola ]**.
* **🏆 4-Vector Offenders Analytics:** Breaks down threats across **Brand**, **Device**, **Category**, and **Geography**.
* **Metrics & Unbreak Center:** Live list of top intercepted domains with 1-click unblock buttons.

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
|  │  - 15 Specialized Hardware, IoT & Venue Shields (140+ targeted rules)     │  |
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

## 🚀 Installation & Quick Start

### Option A: Home Assistant Add-on (Recommended)

1. In Home Assistant, navigate to **Settings** ➔ **Add-ons** ➔ **Add-on Store**.
2. Click the three dots (top right) ➔ **Repositories** ➔ Add:
   ```text
   https://github.com/umbette/sentinel
   ```
3. Select **Sentinel Core**, configure your AdGuard/Home Assistant options, and click **Start**.

### Option B: Docker Compose (Standalone Server / Proxmox / Unraid)

```bash
git clone https://github.com/umbette/sentinel.git
cd sentinel
cp .env.example .env
cp config.example.yaml config.yaml
docker compose up -d
```

Access the Cyber Defense Console at `http://your-server-ip:8087`.

---

## 🧩 Companion Chrome Extension: Sentinel Shield `0.4.1` (MV3)

For endpoint protection when traveling or using public Wi-Fi outside your home network, this repository includes **Sentinel Shield (`0.4.1`)**, an ultra-lightweight Manifest V3 Chrome/Edge extension located in [`extension/`](extension/).

* **Declarative Net Request (DNR) + Cookie Guard:** 0 always-on host permissions required for blocking (`pricing_trackers.json` + compact malicious domain ruleset), plus opt-in per-site Cookie Guard tracker stripping.
* **Single Source of Truth (`spec/`):** Syncs all 47 protected brands and wallet-drainer patterns from `spec/` alongside a compiled snapshot of the Public Suffix List (8,700+ suffixes).

---

## 🧪 Test Suite & Verification

The codebase is validated by automated test suites and Single Source of Truth checks:

```bash
# Verify SSOT sync (brands, drainer patterns, pricing DNR, and 15-shield parity)
PYTHONPATH=. .venv/bin/python scripts/compile_ssot.py --check

# Run Python backend unit, integration, and Selenium headless e2e tests
PYTHONPATH=. .venv/bin/pytest -v tests/

# Run Manifest V3 sandboxed browser runtime tests
node tests/test_extension_runtime.mjs
```

---

## 📱 Platforms, Mobile (iOS/Android), Desktop & Repurposed Linux Nodes

See **[docs/PLATFORMS_GUIDE.md](docs/PLATFORMS_GUIDE.md)** for full setup guides across:
* **Home Server & Domotica:** Home Assistant Add-on (`ha-addon/`) & Docker Compose.
* **Active Owner Smartphones (iOS & Android):** Installable PWA Console (`/manifest.json`), Apple `.mobileconfig` Encrypted DNS Generator (`scripts/generate_ios_dns_profile.py`), iOS/macOS Safari Web Extension converter (`scripts/export_ios_safari_extension.sh`), and WireGuard Android Auto Split-Tunneling ([MOBILE_AND_AUTO_VPN_GUIDE.md](docs/MOBILE_AND_AUTO_VPN_GUIDE.md)).
* **PC Browsers:** Chrome/Edge/Brave MV3 Extension (`sentinel-shield-v0.4.1.zip`).
* **Old Linux Laptops / Raspberry Pi / TV Boxes:** `./scripts/setup_old_device.sh`.

---

## ⚖️ Prior Art, Trademarks & Licensing (Hybrid Open-Core)

* **Original Concept & System Architecture:** Conceived, designed, and authored by **Umberto** (`umbette`) & contributors.
* **Prior Art & Defensive Disclosure:** **[docs/PRIOR_ART.md](docs/PRIOR_ART.md)** • **[CITATION.cff](CITATION.cff)** • **[TRADEMARKS.md](TRADEMARKS.md)** • **[SECURITY.md](SECURITY.md)**.
* **Software Core, Home Assistant Add-on & MV3 Extension:** Licensed under **[GNU AGPLv3](LICENSE)** (Anti-Tivoization & network copyleft).
* **Hardware Blueprints (`hardware/` Sentinel Drive) & OEM Appliances:** Governed by **[PolyForm Noncommercial License 1.0.0](LICENSE-COMMERCIAL-HARDWARE)** — free for personal home use; commercial hardware dongles, router boxes, or OEM appliances require a Commercial License from Umberto (`umbette`).
