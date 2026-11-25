#!/usr/bin/env bash
set -euo pipefail

# Sentinel Core Universal Setup for Repurposed Linux Nodes
# Targets: Old Linux Laptops, Raspberry Pi, Mini-PCs, and Armbian TV Boxes.
# Note: Non-rooted Android phones are intentionally excluded as LAN DNS gateways
# because gateway interception requires a stable Linux/Docker network stack.

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

echo "================================================="
echo "  Sentinel Core - Old Hardware / Home Node Setup"
echo "================================================="

if [ "$(uname -s)" != "Linux" ]; then
  echo "[!] Notice: Host-wide DNS gateway mode is designed for Linux hosts (or Docker Desktop)."
fi

if [ ! -d ".venv" ]; then
  echo "[1/4] Creating Python virtual environment..."
  python3 -m venv .venv
fi

echo "[2/4] Installing dependencies..."
.venv/bin/pip install --upgrade pip >/dev/null
.venv/bin/pip install -r requirements.txt

if [ ! -f ".env" ] && [ -f ".env.example" ]; then
  cp .env.example .env
  echo "[*] Created .env from .env.example (configure ADGUARD_USERNAME / ADGUARD_PASSWORD / SENTINEL_API_KEY)."
fi

if [ ! -f "config.yaml" ] && [ -f "config.example.yaml" ]; then
  cp config.example.yaml config.yaml
  echo "[*] Created config.yaml from config.example.yaml."
fi

echo "[3/4] Generating hardened user systemd unit..."
mkdir -p "$HOME/.config/systemd/user"
cat > "$HOME/.config/systemd/user/sentinel-core.service" <<EOF
[Unit]
Description=Sentinel Core Local DNS Defense Daemon
After=network-online.target

[Service]
Type=simple
WorkingDirectory=$PROJECT_DIR
EnvironmentFile=-$PROJECT_DIR/.env
Environment=PYTHONPATH=$PROJECT_DIR
ExecStart=$PROJECT_DIR/.venv/bin/python -m src.main
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF

echo "[4/4] Done! Enable & start with:"
echo "      systemctl --user daemon-reload && systemctl --user enable --now sentinel-core.service"
echo "      Console URL: http://127.0.0.1:8087"
