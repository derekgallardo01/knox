# Knox on a Raspberry Pi (24/7 deployment plan)

Run Knox on an always-on Pi so monitoring survives PC reboots and covers the
network round-the-clock. This is the plan — follow it whenever you get a Pi.

## Why a Pi
- **Always on**, low power (~3 W), silent.
- Lives **on the LAN**, so it sees everything (ARP, mDNS/DHCP, router API).
- Can become the **DNS logger** for the whole house (every device's domains),
  and — placed on / bridged to the IoT/Ring segment — extend coverage there.

## Hardware
- **Raspberry Pi 4 or 5** (2 GB+ is plenty). A Pi Zero 2 W works for light use.
- **microSD** (32 GB+) or USB SSD.
- **Wired Ethernet strongly preferred** — more reliable ARP sweeps + packet
  capture than Wi-Fi, and it can still see Wi-Fi clients via the router API.

## Install
1. Flash **Raspberry Pi OS Lite (64-bit)** with Raspberry Pi Imager. In the
   imager settings, enable SSH and set a hostname (e.g. `knox`).
2. SSH in, then:
   ```bash
   git clone https://github.com/derekgallardo01/knox.git
   cd knox
   bash scripts/install-pi.sh          # installs python, nmap, libpcap, deps
   cp .env.example .env                # then edit .env (router login, options)
   ```
   On Linux, scapy uses **libpcap** (installed by the script) — no Npcap needed.
3. Configure `.env` (same keys as on Windows): `KNOX_ROUTER_USER/PASSWORD`,
   `KNOX_PASSWORD` (dashboard login), `KNOX_WEB_HOST=0.0.0.0`, `KNOX_NTFY_TOPIC`,
   and optionally `KNOX_DNS_SERVER=1` / `KNOX_CAPTURE=1`.
4. Test: `sudo ./.venv/bin/python -m knox scan` (should list your LAN).
5. Install the service (runs at boot as root for raw sockets / port 53):
   ```bash
   sudo cp scripts/knox.service /etc/systemd/system/knox.service
   # edit WorkingDirectory/ExecStart paths in the unit if not /home/pi/knox
   sudo systemctl daemon-reload && sudo systemctl enable --now knox
   journalctl -u knox -f
   ```

## Notes / gotchas
- **One instance only** — turn off the Windows `KnoxMonitor` task (or point each
  at its own DB) so two Knoxes don't fight. Simplest: let the Pi be the one
  that runs 24/7.
- **DNS resolver on :53** — if you enable `KNOX_DNS_SERVER=1`, free port 53
  first: `sudo systemctl disable --now systemd-resolved` (or set it not to
  bind 53), then point your router's DHCP DNS at the Pi's IP.
- **Data/DB** lives in `knox/data/` on the SD card — back it up if you care about
  history; consider a USB SSD for heavy capture/bandwidth logging.
- **Remote access**: install **Tailscale** on the Pi too (`curl -fsSL
  https://tailscale.com/install.sh | sh && sudo tailscale up`) so you reach the
  dashboard from anywhere, same as the PC.

## Extending to the Ring / IoT network
If your Ring/IoT devices are on a separate SSID/VLAN Knox can't currently see,
a Pi is the fix: put it **on that segment** (second Wi-Fi/NIC or a switch port
on that VLAN), or make it the **DNS server** for it. With multi-subnet scanning
(`KNOX_SUBNETS=...`) one Pi can watch several segments it's connected to.
