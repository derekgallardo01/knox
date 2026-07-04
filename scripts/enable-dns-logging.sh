#!/usr/bin/env bash
# Enable Knox's DNS-logging resolver on a Raspberry Pi / Debian Linux.
#
# What it does:
#   1. Frees UDP/TCP port 53 by turning OFF systemd-resolved's stub listener
#      (Knox needs :53 to be the network's DNS server).
#   2. Repoints the Pi's OWN name resolution at an upstream so the Pi itself
#      keeps working while Knox binds :53.
#   3. Sets KNOX_DNS_SERVER=1 in .env.
#
# After running this, restart Knox (sudo systemctl restart knox) and then, on
# your ROUTER: set the DHCP DNS server to this Pi's IP, and add a secondary DNS
# (e.g. 1.1.1.1) as a fallback for when the Pi is down/rebooting.
#
# Run from the repo root:  bash scripts/enable-dns-logging.sh
set -euo pipefail

UPSTREAM="${KNOX_DNS_UPSTREAM:-1.1.1.1}"
ENV_FILE=".env"

if [ "$(id -u)" -ne 0 ]; then
  echo "This needs root (it stops the resolved stub + rewrites resolv.conf)."
  echo "Re-run:  sudo bash scripts/enable-dns-logging.sh"
  exit 1
fi

echo "==> Freeing port 53 (disabling systemd-resolved's stub listener)..."
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
  mkdir -p /etc/systemd/resolved.conf.d
  cat > /etc/systemd/resolved.conf.d/knox.conf <<EOF
# Managed by Knox scripts/enable-dns-logging.sh
# Stop resolved from binding :53 so Knox can be the network DNS server.
[Resolve]
DNSStubListener=no
EOF
  systemctl restart systemd-resolved
  echo "    systemd-resolved stub listener disabled."
else
  echo "    systemd-resolved not active -- assuming :53 is already free."
fi

echo "==> Pointing the Pi's own resolver at ${UPSTREAM} (so the Pi still resolves)..."
# resolv.conf is often a symlink to a resolved-managed file; replace it with a
# static one pointing straight at the upstream.
if [ -L /etc/resolv.conf ]; then rm -f /etc/resolv.conf; fi
cat > /etc/resolv.conf <<EOF
# Managed by Knox scripts/enable-dns-logging.sh
nameserver ${UPSTREAM}
EOF

echo "==> Setting KNOX_DNS_SERVER=1 in ${ENV_FILE}..."
if [ ! -f "$ENV_FILE" ]; then
  echo "    WARNING: no $ENV_FILE found -- create it first (cp .env.example .env)."
else
  if grep -qE '^[# ]*KNOX_DNS_SERVER=' "$ENV_FILE"; then
    sed -i -E 's|^[# ]*KNOX_DNS_SERVER=.*|KNOX_DNS_SERVER=1|' "$ENV_FILE"
  else
    printf '\nKNOX_DNS_SERVER=1\n' >> "$ENV_FILE"
  fi
  echo "    KNOX_DNS_SERVER=1"
fi

echo
echo "==> Verifying port 53 is now free:"
if ss -lunp 2>/dev/null | grep -q ':53 '; then
  echo "    STILL IN USE -- check 'sudo ss -lunp | grep :53' before starting Knox."
else
  echo "    port 53/udp is free."
fi

cat <<'DONE'

==> Done. Final steps:
  1. Restart Knox:        sudo systemctl restart knox
                          (or: sudo ./.venv/bin/python -m knox serve  to test)
  2. On your ROUTER (DHCP/LAN settings):
       - Primary DNS   -> this Pi's IP address
       - Secondary DNS -> 1.1.1.1   (fallback for when the Pi is down)
     Then renew leases (reboot the router or the clients) so devices pick it up.
  3. Watch it work:       journalctl -u knox -f
     and the dashboard Overview page will fill with per-device top domains.

To undo: delete /etc/systemd/resolved.conf.d/knox.conf, restore the resolv.conf
symlink (ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf), set
KNOX_DNS_SERVER=0, and restart systemd-resolved + knox.
DONE
