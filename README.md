# AI Hunter Daemon

[![CI Test Suite](https://github.com/umbette/ai-hunter/actions/workflows/ci.yml/badge.svg)](https://github.com/umbette/ai-hunter/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![AdGuard Home](https://img.shields.io/badge/AdGuard%20Home-Supported-green?logo=adguard)](https://adguard.com/adguard-home.html)
[![Gemini API](https://img.shields.io/badge/Google%20Gemini-Flash%20Powered-orange?logo=google)](https://ai.google.dev/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker)](Dockerfile)

Autonomous, lightweight DNS threat intelligence, DGA anomaly detector, and privacy auditor designed for **AdGuard Home** and **Home Assistant**.

Monitors DNS traffic in real-time streaming mode, performs multi-label Shannon entropy evaluation ($H > 3.85$) and velocity burst tracking, verifies anomalies with **Gemini Flash**, and dispatches actionable 1-click mobile push alerts via Home Assistant.

---

## Architecture Principles: 100% Local-First & Zero-Trust

1. **Air-Gapped Friendly:** No dynamic remote rule pulls. All configurations, whitelist exceptions, and thresholds are maintained locally in your own `config.yaml` and SQLite database.
2. **Transactional Read-Modify-Write Rule Injection:**
   - AdGuard Home's `/control/filtering/set_rules` API replaces the entire rule set.
   - AI Hunter executes a strict transactional Read-Modify-Write pattern (`GET status` -> inspect/append -> `POST set_rules`) ensuring user custom rules and standard blocklists are never wiped or corrupted.
3. **Zero Inbound Exposed Ports:**
   - Instead of exposing an inbound webhook port, AI Hunter establishes an outbound authenticated WebSocket connection to Home Assistant (`/api/websocket`).
   - Listens for interactive notification actions (`BLOCK_DEVICE`, `BLOCK_GLOBAL`, `IGNORE`).
4. **Multi-Label Shannon Entropy ($H > 3.85$) & Rate Burst Tracker:**
   - Analyzes subdomains and main domain labels independently to catch DGAs hidden in deep subdomains.
   - Tranco Top 10k apex domain bypass to avoid cloud CDN false positives.
   - Sliding-window token-bucket tracking for IoT telemetry beacons.
5. **Cloud Evaluation with Resilient Heuristic Fallback:**
   - Powered by Gemini Flash with Pydantic structured output.
   - If the external API is unreachable or times out, AI Hunter automatically falls back to local heuristic threat metadata without stalling the pipeline.
6. **Decision Persistence & Snooze Management:**
   - SQLite backed in WAL mode (`journal_mode=WAL`) at `/app/data/hunter_decisions.db`.
   - Supports apex wildcard domain matching (`*.domain.com`) and client-specific precedence over global rules.
   - 30-day snooze expiration for false-positive whitelisting with periodic automatic cleanup.
7. **Ultra-Low Resource Footprint:**
   - Bounded Docker container: `cpus: '0.2'`, `memory: 256M`.
   - Idle footprint: `< 20 MiB` RAM and `0.00%` CPU.

---

## Quick Start (Docker Compose)

### 1. Configuration
```bash
cp .env.example .env
cp config.example.yaml config.yaml
```
Edit `.env` with your credentials:
```ini
ADGUARD_USERNAME=admin
ADGUARD_PASSWORD=your_password
HASS_TOKEN=your_home_assistant_long_lived_access_token
HASS_NOTIFY_SERVICE=notify
GEMINI_API_KEY=your_gemini_api_key
DATA_DIR=/app/data
```

### 2. Launch Container
```bash
docker compose up -d
```

### 3. Verify Logs
```bash
docker logs -f ai-hunter
```

---

## Community Threat Blacklist (AdGuard Subscription)

This repository publishes a community-compiled, zero-trust validated threat & DGA blacklist formatted for **AdGuard Home** and **uBlock Origin**:

* **Filter URL:** `https://raw.githubusercontent.com/umbette/adguard-ai-hunter/main/filters/threat_blacklist.txt`

### How to Add in AdGuard Home:
1. Open AdGuard Home -> **Filters** -> **DNS blocklists**.
2. Click **Add blocklist** -> **Add a custom list**.
3. Name: `AI Hunter Community Blacklist`.
4. URL: `https://raw.githubusercontent.com/umbette/adguard-ai-hunter/main/filters/threat_blacklist.txt`.
5. Click **Save**.

All entries are strictly vetted through zero-trust guardrails (rejecting DNS rewrites and protecting top global infrastructure).

---

## Contributing

We welcome community feedback, pull requests, and whitelist recommendations!
- Check [CONTRIBUTING.md](CONTRIBUTING.md) for details on submitting standard PRs.

---

## License

Distributed under the [MIT License](LICENSE).

