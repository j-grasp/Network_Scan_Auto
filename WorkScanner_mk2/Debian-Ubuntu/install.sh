#!/bin/bash
# install.sh
# One-time setup script. Run with internet access BEFORE air-gapping the host.
# Must be run as root.
set -euo pipefail

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   Vulnerability Scanner — Installation Script        ║"
echo "║   Run with internet access BEFORE air-gapping        ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

if [ "$EUID" -ne 0 ]; then
  echo "[ERROR] Please run as root (sudo ./install.sh)"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── System packages ──────────────────────────────────────────
echo "[1/7] Installing system packages..."
apt-get update -qq
apt-get install -y nmap python3 python3-pip git nginx apache2-utils

# ── Python libraries ─────────────────────────────────────────
echo "[2/7] Installing Python libraries..."
pip3 install python-libnmap pyyaml jinja2 --break-system-packages

# ── Vulscan offline CVE database ─────────────────────────────
echo "[3/7] Installing vulscan + offline CVE databases..."
VULSCAN_DIR="/usr/share/nmap/scripts/vulscan"
if [ -d "$VULSCAN_DIR" ]; then
    echo "       vulscan already present — updating..."
    git -C "$VULSCAN_DIR" pull --quiet
else
    git clone --quiet https://github.com/scipag/vulscan "$VULSCAN_DIR"
fi
nmap --script-updatedb > /dev/null 2>&1 || true
echo "       Offline CVE databases available:"
ls "$VULSCAN_DIR"/*.csv 2>/dev/null | while read db; do
    echo "         - $(basename "$db")"
done

# ── Scanner_mk2 service account ───────────────────────────────────
echo "[4/7] Creating scanner_mk2 service account..."
if id "scanner_mk2" &>/dev/null; then
    echo "       User 'scanner_mk2' already exists."
else
    useradd -r -s /bin/false -d /opt/vulnscan scanner_mk2
fi

# ── Directory structure ───────────────────────────────────────
echo "[5/7] Setting up directories and copying files..."
mkdir -p /opt/vulnscan/templates /opt/vulnscan/logs /scans

cp "$SCRIPT_DIR/orchestrator.py"      /opt/vulnscan/
cp "$SCRIPT_DIR/report_generator.py"  /opt/vulnscan/
cp "$SCRIPT_DIR/config.yaml"          /opt/vulnscan/
cp "$SCRIPT_DIR/exclusions.yaml"      /opt/vulnscan/
cp "$SCRIPT_DIR/technical.html.j2"  /opt/vulnscan/templates/
cp "$SCRIPT_DIR/executive.html.j2"  /opt/vulnscan/templates/

chown -R scanner_mk2:scanner_mk2 /opt/vulnscan /scans
chmod 750 /opt/vulnscan /scans
chmod 640 /opt/vulnscan/config.yaml /opt/vulnscan/exclusions.yaml
chmod 750 /opt/vulnscan/orchestrator.py /opt/vulnscan/report_generator.py

# ── Nmap raw socket capability ───────────────────────────────
echo "[6/7] Granting nmap raw socket capability (no full root needed)..."
setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap

# ── Systemd units ─────────────────────────────────────────────
echo "[7/7] Installing and enabling systemd timer..."
cp "$SCRIPT_DIR/vuln-scan.timer"   /etc/systemd/system/
cp "$SCRIPT_DIR/vuln-scan.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now vuln-scan.timer

# ── Nginx report portal ───────────────────────────────────────
echo ""
echo "[nginx] Configuring internal report portal on port 8080..."
cp "$SCRIPT_DIR/vulnscan-nginx.conf" /etc/nginx/sites-available/vulnscan
ln -sf /etc/nginx/sites-available/vulnscan /etc/nginx/sites-enabled/vulnscan
rm -f /etc/nginx/sites-enabled/default

echo ""
echo "  Set the password for the report web portal:"
read -s -p "  Password for user 'analyst': " RPASS
echo ""
htpasswd -bc /etc/nginx/.htpasswd analyst "$RPASS"
nginx -t && systemctl enable --now nginx

# ── Reminder: edit configs ─────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   Installation Complete                               ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║                                                       ║"
echo "║  Installed:                                           ║"
echo "║  ✓ nmap + vulscan offline CVE databases               ║"
echo "║  ✓ python-libnmap, pyyaml, jinja2                    ║"
echo "║  ✓ scanner_mk2 service account (limited privileges)       ║"
echo "║  ✓ systemd timer: every Sunday at 23:00              ║"
echo "║  ✓ nginx report portal on :8080 with basic auth      ║"
echo "║                                                       ║"
echo "║  BEFORE air-gapping, complete these steps:           ║"
echo "║  1. Edit /opt/vulnscan/config.yaml                   ║"
echo "║     - Set your actual IP ranges per segment          ║"
echo "║  2. Edit /opt/vulnscan/exclusions.yaml               ║"
echo "║     - Add ALL OT/ICS/fragile device IPs              ║"
echo "║  3. Test: systemctl start vuln-scan.service           ║"
echo "║  4. Watch: journalctl -u vuln-scan.service -f         ║"
echo "║  5. Reports: http://<this-host>:8080                  ║"
echo "║  6. AIR-GAP the host                                  ║"
echo "║                                                       ║"
echo "║  Timer status: systemctl list-timers vuln-scan.timer  ║"
echo "╚══════════════════════════════════════════════════════╝"
