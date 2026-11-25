# Security Policy

## Our Zero-Telemetry Security Model

Sentinel Core and Sentinel Shield are designed around **100% local-first execution**:
- DNS inspection, behavioral anomaly scoring, and phishing heuristics execute strictly inside your local LAN or browser runtime.
- No browsing history, device MAC addresses, private IP allocations, or credential tokens are ever collected by upstream maintainers.
- Community filter updates (`filters/threat_blacklist.txt`) and device compatibility profiles (`sources/device_profiles.yaml`) are public, human-auditable files.

---

## Supported Versions

| Component | Version | Security Support |
| :--- | :--- | :--- |
| Sentinel Core Daemon | `0.4.1` (`src/`) | ✅ Active |
| Sentinel Shield MV3 Extension | `0.4.1` (`extension/`) | ✅ Active |

---

## Reporting a Vulnerability

If you discover a security vulnerability, authentication bypass in the web console, XSS, or bypass in the Sentinel Shield DNR/phishing rules:

1. **Please do NOT file a public GitHub issue** containing exploitable Proof-of-Concept payloads before remediation.
2. Use **GitHub Private Vulnerability Reporting** under the **Security** tab of [`github.com/umbette/sentinel`](https://github.com/umbette/sentinel/security) (or contact maintainer `umbette` directly).
3. Include affected component (`src/dashboard.py`, `extension/`, etc.), reproduction steps, and impact assessment.

We aim to acknowledge reports within **48 hours** and issue patched releases alongside automated regression tests.
