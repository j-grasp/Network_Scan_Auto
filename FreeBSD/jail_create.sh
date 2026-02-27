#!/bin/sh
# jail_create.sh
# Run on the FreeBSD HOST (not inside the jail) as root.
# Creates and configures the iocage jail for the vulnerability scanner.
#
# FreeBSD 15.x + iocage note:
# iocage may have stability issues on FreeBSD 15-CURRENT. If iocage
# fails, see the comments at the bottom of this script for a raw
# jail fallback using /etc/jail.conf directly.
# =============================================================

set -e

JAIL_NAME="vulnscan"
JAIL_IP="192.168.1.200"         # ← Change to a free IP on your LAN
JAIL_GATEWAY="192.168.1.1"      # ← Change to your gateway
JAIL_INTERFACE="em0"            # ← Change to your host NIC (ifconfig to check)
FREEBSD_RELEASE="15.0-RELEASE"  # Change if using a SNAPSHOT build

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   VulnScan — iocage Jail Creation (FreeBSD Host)     ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── Verify iocage is installed ───────────────────────────────
if ! command -v iocage > /dev/null 2>&1; then
    echo "[*] iocage not found. Installing via pkg..."
    pkg install -y py39-iocage || pkg install -y iocage
fi

# ── Activate iocage pool if not already done ─────────────────
echo "[*] Checking iocage ZFS pool activation..."
iocage activate $(zpool list -H -o name | head -1) || true

# ── Fetch FreeBSD release for jail base ──────────────────────
echo "[*] Fetching FreeBSD ${FREEBSD_RELEASE} base for jail..."
iocage fetch -r ${FREEBSD_RELEASE} || {
    echo "[!] Fetch failed. On FreeBSD 15-CURRENT, try fetching a SNAPSHOT:"
    echo "    iocage fetch -r 15.0-CURRENT --url http://ftp.freebsd.org/pub/FreeBSD/snapshots/amd64/amd64/"
    exit 1
}

# ── Create the jail ──────────────────────────────────────────
echo "[*] Creating jail: ${JAIL_NAME}..."
iocage create \
    -r ${FREEBSD_RELEASE} \
    -n ${JAIL_NAME} \
    ip4_addr="${JAIL_INTERFACE}|${JAIL_IP}/24" \
    defaultrouter="${JAIL_GATEWAY}" \
    allow_raw_sockets=1 \
    allow_socket_af=1 \
    sysvshm=new \
    sysvsem=new \
    sysvmsg=new \
    boot=on \
    resolver="nameserver 127.0.0.1" \
    notes="Air-gapped vulnerability scanner"

# ── allow.raw_sockets is critical ────────────────────────────
# This replaces Linux's setcap cap_net_raw. Without it, nmap
# cannot perform SYN scans (-sS) and falls back to connect
# scans (-sT). We set it here at the host level so the jail
# scanner user does not need root inside the jail for nmap.

echo "[*] Verifying raw socket permission..."
iocage get allow_raw_sockets ${JAIL_NAME}

# ── Start the jail ───────────────────────────────────────────
echo "[*] Starting jail..."
iocage start ${JAIL_NAME}

echo ""
echo "[✓] Jail '${JAIL_NAME}' created and started."
echo "    IP: ${JAIL_IP}"
echo "    Raw sockets: enabled (required for nmap SYN scans)"
echo ""
echo "    Next step — run install.sh inside the jail:"
echo "    iocage exec ${JAIL_NAME} sh /tmp/install.sh"
echo ""
echo "    To copy install files into the jail:"
echo "    iocage exec ${JAIL_NAME} mkdir -p /tmp/vulnscan"
echo "    cp -r /path/to/vulnscan-freebsd/* \\"
echo "      \$(iocage get mountpoint ${JAIL_NAME})/root/tmp/vulnscan/"
echo ""

# =============================================================
# FALLBACK: Raw jail config (if iocage fails on FreeBSD 15)
# =============================================================
# If iocage is broken on your FreeBSD 15 build, add this to
# /etc/jail.conf on the HOST and run: jail -c vulnscan
#
# vulnscan {
#     host.hostname = "vulnscan.local";
#     path = "/jails/vulnscan";
#     ip4.addr = em0|192.168.1.200/24;
#     exec.start = "/bin/sh /etc/rc";
#     exec.stop = "/bin/sh /etc/rc.shutdown";
#     allow.raw_sockets = 1;
#     allow.socket_af = 1;
#     mount.devfs;
# }
#
# Then bootstrap pkg inside the jail:
# pkg -j vulnscan install -y pkg
