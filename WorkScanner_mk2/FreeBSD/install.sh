#!/bin/sh
# install.sh
# Run INSIDE the jail as root, with internet access, BEFORE air-gapping.
# Copy this entire vulnscan-freebsd directory into the jail first:
#
#   iocage exec vulnscan mkdir -p /tmp/vulnscan
#   cp -r /path/to/vulnscan-freebsd/* \
#     $(iocage get mountpoint vulnscan)/root/tmp/vulnscan/
#   iocage exec vulnscan sh /tmp/vulnscan/install.sh
# =============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   VulnScan — Jail Installation (FreeBSD/iocage)      ║"
echo "║   Run inside the jail, internet access required      ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] Must be run as root inside the jail."
    exit 1
fi

# ── Bootstrap pkg ────────────────────────────────────────────
echo "[1/8] Bootstrapping pkg..."
ASSUME_ALWAYS_YES=yes pkg bootstrap || true
pkg update -f

# ── Binary packages via pkg ───────────────────────────────────
# These are installed via pkg (binary) for speed.
# nmap, nginx, python, git — all well-maintained in FreeBSD ports tree.
echo "[2/8] Installing binary packages via pkg..."
pkg install -y \
    nmap \
    python311 \
    py311-pip \
    py311-sqlite3 \
    git \
    nginx \
    curl \
    bash

# Create /usr/local/bin/python3 symlink if not present
if [ ! -f /usr/local/bin/python3 ]; then
    ln -sf /usr/local/bin/python3.11 /usr/local/bin/python3
fi
if [ ! -f /usr/local/bin/pip3 ]; then
    ln -sf /usr/local/bin/pip3.11 /usr/local/bin/pip3
fi

# ── Python packages via pip ───────────────────────────────────
# python-libnmap, pyyaml, jinja2 not in ports as py311 variants
# on 15-CURRENT — install via pip inside a venv to stay clean.
echo "[3/8] Installing Python libraries via pip (venv)..."
python3 -m venv /opt/vulnscan/venv
/opt/vulnscan/venv/bin/pip install --upgrade pip
/opt/vulnscan/venv/bin/pip install python-libnmap pyyaml jinja2

# ── htpasswd via py-passlib (replaces apache2-utils) ─────────
# FreeBSD does not have a standalone htpasswd binary outside of
# apache24. We use passlib instead to generate the .htpasswd file.
echo "[4/8] Installing passlib for htpasswd generation..."
/opt/vulnscan/venv/bin/pip install passlib bcrypt

# ── Vulscan offline CVE database ─────────────────────────────
echo "[5/8] Installing vulscan + offline CVE databases..."
VULSCAN_DIR="/usr/local/share/nmap/scripts/vulscan"
if [ -d "$VULSCAN_DIR" ]; then
    echo "       Updating existing vulscan..."
    git -C "$VULSCAN_DIR" pull --quiet
else
    git clone --quiet https://github.com/scipag/vulscan "$VULSCAN_DIR"
fi
# Update nmap script database
nmap --script-updatedb > /dev/null 2>&1 || true
echo "       Offline CVE databases:"
ls "$VULSCAN_DIR"/*.csv | while read db; do
    echo "         - $(basename "$db")"
done

# ── Scanner service account ───────────────────────────────────
echo "[6/8] Creating scanner service account..."
if ! id scanner > /dev/null 2>&1; then
    pw useradd scanner \
        -d /opt/vulnscan \
        -s /usr/sbin/nologin \
        -c "Vulnerability Scanner Service Account" \
        -G wheel
fi

# ── Directory structure ───────────────────────────────────────
echo "[7/8] Setting up directories and deploying files..."
mkdir -p /opt/vulnscan/templates /opt/vulnscan/logs /scans

cp "${SCRIPT_DIR}/orchestrator.py"      /opt/vulnscan/
cp "${SCRIPT_DIR}/report_generator.py"  /opt/vulnscan/
cp "${SCRIPT_DIR}/config.yaml"          /opt/vulnscan/
cp "${SCRIPT_DIR}/exclusions.yaml"      /opt/vulnscan/
cp "${SCRIPT_DIR}/templates/"*.html.j2  /opt/vulnscan/templates/

chown -R scanner:scanner /opt/vulnscan /scans
chmod 750 /opt/vulnscan /scans
chmod 640 /opt/vulnscan/config.yaml /opt/vulnscan/exclusions.yaml
chmod 750 /opt/vulnscan/orchestrator.py /opt/vulnscan/report_generator.py

# ── Nginx configuration ───────────────────────────────────────
echo "[8/8] Configuring nginx..."
cp "${SCRIPT_DIR}/nginx.conf" /usr/local/etc/nginx/nginx.conf

# Generate htpasswd using passlib (no apache2-utils needed)
echo ""
echo "  Set the password for the report web portal (user: analyst):"
printf "  Password: "
stty -echo
read RPASS
stty echo
echo ""

/opt/vulnscan/venv/bin/python3 - <<PYEOF
from passlib.apache import HtpasswdFile
ht = HtpasswdFile("/usr/local/etc/nginx/.htpasswd", new=True)
ht.set_password("analyst", "${RPASS}")
ht.save()
print("  [✓] .htpasswd created.")
PYEOF

chmod 640 /usr/local/etc/nginx/.htpasswd
chown root:www /usr/local/etc/nginx/.htpasswd

# ── Enable nginx in rc.conf ───────────────────────────────────
sysrc nginx_enable="YES"
service nginx start || service nginx restart

# ── Install rc.d script for scanner (optional manual trigger) ─
cp "${SCRIPT_DIR}/rc.d/vulnscan" /usr/local/etc/rc.d/vulnscan
chmod 555 /usr/local/etc/rc.d/vulnscan

# ── Cron job for daily scan at 23:00 ─────────────────────────
echo "0 23 * * * root /opt/vulnscan/venv/bin/python3 /opt/vulnscan/orchestrator.py >> /opt/vulnscan/logs/cron.log 2>&1" \
    > /etc/cron.d/vulnscan
chmod 644 /etc/cron.d/vulnscan
service cron restart > /dev/null 2>&1 || true

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   Installation Complete                               ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║                                                       ║"
echo "║  Installed:                                           ║"
echo "║  ✓ nmap + vulscan offline CVE databases               ║"
echo "║  ✓ python3.11 venv (libnmap, pyyaml, jinja2)         ║"
echo "║  ✓ scanner service account                            ║"
echo "║  ✓ cron: daily scan at 23:00                         ║"
echo "║  ✓ nginx report portal on :8080                      ║"
echo "║                                                       ║"
echo "║  BEFORE air-gapping, complete these steps:           ║"
echo "║  1. Edit /opt/vulnscan/config.yaml                   ║"
echo "║     Set your actual IP ranges per segment            ║"
echo "║  2. Edit /opt/vulnscan/exclusions.yaml               ║"
echo "║     Add ALL OT/ICS/fragile device IPs                ║"
echo "║  3. Test scan:                                        ║"
echo "║     /opt/vulnscan/venv/bin/python3 \                 ║"
echo "║       /opt/vulnscan/orchestrator.py                  ║"
echo "║  4. Reports: http://<jail-ip>:8080                   ║"
echo "║  5. AIR-GAP the jail (remove internet access)        ║"
echo "╚══════════════════════════════════════════════════════╝"
