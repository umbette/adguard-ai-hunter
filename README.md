# AI Hunter Daemon

[![CI Test Suite](https://github.com/your-username/ai-hunter/actions/workflows/ci.yml/badge.svg)](https://github.com/your-username/ai-hunter/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![AdGuard Home](https://img.shields.io/badge/AdGuard%20Home-Supported-green?logo=adguard)](https://adguard.com/adguard-home.html)
[![Gemini API](https://img.shields.io/badge/Google%20Gemini-Flash%20Powered-orange?logo=google)](https://ai.google.dev/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker)](Dockerfile)

Autonomous, lightweight DNS threat intelligence, DGA anomaly detector, and privacy auditor designed for **AdGuard Home** and **Home Assistant**.

Monitors DNS traffic in real-time streaming mode, performs multi-label Shannon entropy evaluation ($H > 3.85$) and velocity burst tracking, verifies anomalies with **Gemini Flash**, and dispatches actionable 1-click mobile push alerts via Home Assistant.

---

## Key Architecture & Features

1. **Transactional Read-Modify-Write Rule Injection:**
   - AdGuard Home's `/control/filtering/set_rules` API replaces the entire rule set.
   - AI Hunter executes a strict transactional Read-Modify-Write pattern (`GET status` -> inspect/append -> `POST set_rules`) ensuring user custom rules and standard blocklists are never wiped or corrupted.
2. **Zero Inbound Exposed Ports:**
   - Instead of exposing an inbound webhook port, AI Hunter establishes an outbound authenticated WebSocket connection to Home Assistant (`/api/websocket`).
   - Listens for interactive notification actions (`BLOCK_DEVICE`, `BLOCK_GLOBAL`, `IGNORE`).
3. **Multi-Label Shannon Entropy ($H > 3.85$) & Rate Burst Tracker:**
   - Analyzes subdomains and main domain labels independently to catch DGAs hidden in deep subdomains.
   - Tranco Top 10k apex domain bypass to avoid cloud CDN false positives.
   - Sliding-window token-bucket tracking for IoT telemetry beacons.
4. **Cloud Evaluation with Resilient Heuristic Fallback:**
   - Powered by Gemini Flash with Pydantic structured output.
   - If the external API is unreachable or times out, AI Hunter automatically falls back to local heuristic threat metadata without stalling the pipeline.
5. **Decision Persistence & Snooze Management:**
   - SQLite backed in WAL mode (`journal_mode=WAL`) at `/app/data/hunter_decisions.db`.
   - Supports apex wildcard domain matching (`*.domain.com`) and client-specific precedence over global rules.
   - 30-day snooze expiration for false-positive whitelisting with periodic automatic cleanup.
6. **Ultra-Low Resource Footprint:**
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

## Contributing & Automated Issue Resolution

We invite community members to contribute whitelist submissions, false-positive reports, and new detection heuristics!
- Check [CONTRIBUTING.md](CONTRIBUTING.md) for details.
- Comment `/auto-fix` or `/implement` on approved issues to trigger automated PR creation through GitHub Actions.

---

## License

Distributed under the [MIT License](LICENSE).
