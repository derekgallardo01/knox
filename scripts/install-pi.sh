#!/usr/bin/env bash
# Knox installer for Raspberry Pi / Debian-based Linux.
# Run from the cloned repo root:  bash scripts/install-pi.sh
set -euo pipefail

echo "==> Installing system dependencies (Python, nmap, libpcap)..."
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip nmap libpcap0.8 git

echo "==> Creating virtualenv + installing Python deps..."
python3 -m venv .venv
./.venv/bin/pip install --upgrade pip
./.venv/bin/pip install -r requirements.txt

echo "==> Done. Next steps:"
echo "  1. Create your config:   cp .env.example .env   (then fill in router login etc.)"
echo "  2. Test it runs:         sudo ./.venv/bin/python -m knox scan"
echo "  3. Install the service:"
echo "       sudo cp scripts/knox.service /etc/systemd/system/knox.service"
echo "       # edit WorkingDirectory/ExecStart in the unit if this repo isn't /home/pi/knox"
echo "       sudo systemctl daemon-reload && sudo systemctl enable --now knox"
echo "  4. Watch it:             journalctl -u knox -f"
