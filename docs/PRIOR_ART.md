# Sentinel™ — Defensive Publication & Technical Prior Art Record

**Document ID:** SNT-PRIOR-ART-2026-01  
**Author & Original Inventor:** Umberto (`umbette`)  
**First Public Release Lineage:** `https://github.com/umbette/sentinel` (`2026`)  
**Legal Purpose:** Defensive Publication establishing undeniable state of the art under **Article 54 EPC (European Patent Convention)** and **35 U.S.C. § 102 (U.S. America Invents Act)**, paired with Hybrid Open-Core copyright & hardware anti-cloning protections (`AGPL-3.0-only` + `PolyForm-Noncommercial-1.0.0`).

---

## 1. Protected Technical Innovations Disclosed & Timestamped Hereby

This public disclosure permanently bars third parties from obtaining valid patent monopolies over any software daemon, Home Assistant add-on, browser extension, OR turnkey hardware router/dongle implementing the following architectures authored by **Umberto (`umbette`)**:

1. **Control-Plane vs. Data-Plane Deterministic IoT Shield Matrix (`src/device_shield.py`, `sources/device_profiles.yaml`):**
   - 15 hardware-specific behavioral shields (Smart TV ACR, Vacuum LiDAR/Video, 3D Printers, Consoles, Connected Cars, P2P Cameras, Badbox AOSP C2, Dynamic Pricing, Guest Wi-Fi) preserving companion-app control channels while sinking predatory exfiltration endpoints via local `$client=IP` DNS rules.
   - Closed-loop **Zero-Knowledge Self-Resolution & Crowdsourced Unbreak Pipeline** (`src/dashboard.py`), never egressing user MACs, private IPs, or browsing history.

2. **CDN-Safe Malicious IP & DNS Answer Correlation (`src/ip_intel.py`, `scripts/proactive_miner.py`):**
   - Real-time inspection of local resolver DNS answer resource records (`answer` RRs) against curated dedicated C2 IP/CIDR threat feeds (Feodo Tracker, Spamhaus DROP/EDROP) while explicitly excluding shared multi-tenant CDNs (Cloudflare, Fastly, AWS CloudFront), public resolvers, and RFC 1918/CGNAT ranges to eliminate collateral web outages.

3. **Zero-Permission MV3 Phishing, Crypto Vault & Anti-Dynamic Pricing Engine (`spec/`, `extension/`):**
   - Single Source of Truth (`scripts/compile_ssot.py`) compiling 47 protected brands, Punycode IDN homograph decoders, Web3 drainer signatures, bare-IP phishing interception, 8,700+ PSL suffix guards, 70+ zero-permission DNR tracker rules, and per-tab opt-in Cookie/Tracking-Param Guard.

4. **Sentinel Drive™ Cabin DNS Gateway Dongle (`hardware/sentinel_drive/`):**
   - Plug-in OBD-II / USB vehicular Wi-Fi AP & local DNS filter isolating automotive telematics at the cabin network boundary while bypassing Android Auto Communication Error 21 and CarPlay VPN routing traps.

---

## 2. Hybrid Open-Core Commercial Anti-Cloning Policy

* **Core Daemon, 15 Shields, CLI, Home Assistant Add-on & MV3 Extension:** Licensed under **GNU AGPLv3** (`LICENSE`), forcing full source and installation-key disclosure (including Anti-Tivoization §6 and network copyleft) for anyone distributing appliances or cloud services.
* **Hardware Blueprints, Dongle Appliances & OEM Images (`hardware/`):** Strictly governed by **`PolyForm Noncommercial License 1.0.0`** (`LICENSE-COMMERCIAL-HARDWARE`).

> **No third party may manufacture, flash, bundle, or sell hardware dongles, routers, security boxes, or commercial services based on Sentinel without a signed Commercial OEM License from Umberto (`umbette`).**
