# Sentinel Drive™ — In-Car OBD-II / USB Privacy Gateway Appliance Blueprint

**License:** Governed by **PolyForm Noncommercial License 1.0.0** ([`../LICENSE`](../LICENSE)). Commercial manufacturing, resale, or bundled OEM firmware requires a signed Commercial OEM License from **Umberto (`umbette`)**.

---

## Architecture Summary

Modern connected vehicles transmit driving behavior telemetry (speed, harsh braking, nighttime travel, GPS location) over built-in cellular modems to data brokers (LexisNexis, Verisk, Otonomo), and interfere with phone VPN tunnels (causing Android Auto Communication Error 21 / CarPlay P2P failures).

**Sentinel Drive™** resolves this at the vehicle boundary without breaking CarPlay/Android Auto:
1. **Form Factor:** Ultra-compact single-board Linux / ESP32-S3 or Raspberry Pi Zero 2W powered via OBD-II 5V buck converter or console USB-A port.
2. **Function:** Creates an isolated cabin Wi-Fi AP + local DNS sinkhole pre-loaded with Sentinel Core automotive profiles (`sources/device_profiles.yaml`: preserving `owner-api.teslamotors.com` / `b2vapi.bmwgroup.com` Control Plane while null-routing telemetry broker endpoints).
3. **Prior Art:** First established publicly in [`github.com/umbette/sentinel`](https://github.com/umbette/sentinel) (`docs/MOBILE_AND_AUTO_VPN_GUIDE.md` and `docs/PRIOR_ART.md`).
