# RePlug™ Ecosystem Architecture & Technical Prior Art

**Document Status:** Public Engineering Specification & Prior Art Record  
**Author & Owner:** Umberto (`umbette`)  
**Ecosystem:** RePlug™ (*Upcycled. Connected. Secure.*)  
**Core Pillars:** **Sentinel Shield** & **Nozzle Guardian**  

---

## 1. Thesis: Turning E-Waste into Sovereign Edge Appliances

Over five billion functional smartphones and tablets lie dormant in household drawers despite containing multi-core ARM SoCs, gigabytes of RAM, Wi-Fi/BLE stacks, MEMS accelerometers, ambient microphones, OLED/IPS touchscreens, and high-resolution macro optics. Meanwhile, consumers are sold single-purpose plastic smart-home gadgets powered by constrained MCUs that frequently rely on mandatory external cloud telemetry.

**RePlug™** establishes a unified local-first software architecture that converts dormant consumer hardware into sovereign domestic edge nodes with zero new plastic manufacturing.

```
+-----------------------------------------------------------------------------------+
|                        REPLUG™ UNIFIED LOCAL ARCHITECTURE                         |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|   [Dormant Phone / Tablet] ──(Local LAN / mDNS / IPP)──▶ [Printer / Home Devices] |
|          │                                                                        |
|          ├──▶ MODULE A: RePlug Sentinel Shield (Implemented in this Repo)         |
|          │      • 15 Deterministic Hardware & IoT Privacy Shields                 |
|          │      • AdGuard Home / Pi-hole & Home Assistant Bridge                  |
|          │      • Zero-Trust Device Admission & Scan-on-Demand Audit              |
|          │                                                                        |
|          ├──▶ MODULE B: RePlug Nozzle Guardian (Architecture & Prior Art)         |
|          │      • Idle-Window Tracking via Local IPP (RFC 8011)                   |
|          │      • Adaptive Ink-Crystallization Prevention (CISS / EcoTank)        |
|          │      • On-Device Camera Vision Check (Nozzle Test & 3D First Layer)    |
|          │                                                                        |
|          └──▶ SAFETY LAYER: Thermal Battery Safeguard ("Spicy Pillow Guard")      |
|                 • Enforces 50%–80% state-of-charge cycling via Home Assistant     |
|                   smart-plug control to prevent 24/7 lithium swelling hazards     |
+-----------------------------------------------------------------------------------+
```

---

## 2. Module 1: RePlug Sentinel Shield *(Production Core)*

Sentinel Shield acts as the local network defense plane (`src/` and `extension/`):
- **Behavioral DNS & Device Resolver:** Correlates local DNS query streams against device categories (`src/device_resolver.py`) to block telemetry, ACR TV tracking, automotive broker exfiltration, and dynamic pricing networks without breaking essential companion-app control paths.
- **Zero-Knowledge Unbreak Pipeline:** Allows instant local rule exemptions and sanitized, PII-free catalog contributions (`sources/device_profiles.yaml`).
- **Offline Endpoint Extension:** Manifest V3 browser defense (`extension/`) running offline with Public Suffix List domain matching and homograph detection.

---

## 3. Module 2: RePlug Nozzle Guardian *(Design & Prior Art)*

Inkjet tank printers (CISS / EcoTank) suffer irreversible printhead clogging when left idle for extended periods—particularly when owners travel—while deep manufacturer cleaning cycles waste significant ink and fill waste-ink pads prematurely. Similarly, 3D printers frequently fail during unattended early layers.

**Nozzle Guardian** eliminates the need for dedicated aftermarket hardware dongles by running natively on an upcycled phone positioned near the printer:

### 3.1 Adaptive IPP State Machine (Local Only)
1. **Zero-Driver Discovery:** Discovers printers on the local subnet via mDNS (`_ipp._tcp.local` / `_ipps._tcp.local`).
2. **Idle & Ink Polling:** Queries RFC 8011 IPP attributes (`printer-state`, `printer-up-time`, job timestamps, ink markers) without cloud APIs.
3. **Micro-Purge Scheduling:** Triggers ultra-low-volume scheduled maintenance test pages only when *both* criteria hold: true idle duration exceeds the dry-out threshold AND ink/head status warrants agitation (preventing wasteful fixed-schedule prints when the printer has been actively used).

### 3.2 On-Device Camera Vision Inspection
- **Nozzle Test Verification:** Using the smartphone's rear macro lens mounted facing the output tray, runs local contrast/edge alignment analysis on printed calibration patterns to detect missing jets before major print jobs or before vacation degradation.
- **3D Printer Sentinel:** Monitors bed adhesion and thermal anomalies during long prints, pushing instant encrypted local notifications (e.g., via Home Assistant / local webhook) on spaghetti/detachment detection.

---

## 4. Critical Safety Engineering: Thermal Battery Safeguard

Operating an older smartphone 24/7 while permanently plugged into a 5V charger holds lithium cells at 100% SoC under continuous heat—creating chemical degradation and battery swelling risks.

RePlug establishes a **software-hardware closed safety loop**:
1. The repurposed smartphone reads its own internal battery telemetry (`battery_level`, `battery_temperature_c`).
2. When paired with Home Assistant and an ordinary Wi-Fi/Zigbee smart plug already owned by the user, RePlug enforces a **50%–80% Duty-Cycle Charging Ceiling** (turns charging ON at ≤45–50%, turns OFF at 80%, and pauses immediately if internal thermal sensors exceed safety thresholds).
3. **Graceful Power-Loss Fallback:** If mains power drops, the healthy 50–80% reserve transitions automatically into **Blackout Beacon** mode—keeping network/alert sentinels alive for hours while signaling power loss cleanly.

---

## 5. Ambient Sentinel Roadmap

Building on the same local telemetry and Home Assistant bridge:
- **Blackout Beacon:** Utility outage detection + automated low-power emergency hallway flash LED + battery-backed alert relay.
- **Acoustic Sentry:** On-device lightweight audio event classification (smoke/CO alarm tonal detection, glass break, sump-pump anomaly) where raw microphone audio never leaves RAM.
- **Optical Meter OCR:** Periodic flash-assisted macro capture and local digit recognition for legacy analog water/gas meters.

---

## 6. Authorship & Prior Art Notice

This architecture, combining zero-cloud network privacy enforcement (`Sentinel Shield`) with upcycled smartphone IPP printer preservation (`Nozzle Guardian`) and closed-loop 50–80% battery swelling prevention, was authored by **Umberto (`umbette`)** in 2026 and committed publicly to [`github.com/umbette/sentinel`](https://github.com/umbette/sentinel) as open technical prior art.
