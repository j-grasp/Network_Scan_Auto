# Automated Vulnerability Scanning System
### Technical Reference

**Classification: Internal — Security Team & Technical Leadership**

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Technology Stack — Decisions and Rationale](#technology-stack--decisions-and-rationale)
3. [Setup Guide — Ubuntu/Debian](#setup-guide--ubuntudebian)
4. [Setup Guide — FreeBSD iocage Jail](#setup-guide--freebsd-iocage-jail)
5. [Operational Reference](#operational-reference)
6. [File Reference](#file-reference)

---

## Architecture Overview

The system is a three-phase, parallel, air-gapped vulnerability scanner built on native Nmap with offline CVE correlation via the vulscan NSE script. It is orchestrated by a Python process scheduler, outputs tiered HTML and JSON reports, and serves results via a locally hosted nginx portal with HTTP Basic Auth.

```
Scheduler (systemd/cron)
        │
        ▼
orchestrator.py
  ├── Loads config.yaml (segments, tuning)
  ├── Loads exclusions.yaml (OT/ICS safety list)
  ├── Resolves all CIDRs → validated target lists
  └── ThreadPoolExecutor (N concurrent segment workers)
            │
            ├── Phase 1: nmap -sn          (host discovery)
            ├── Phase 2: nmap -sS -sV -O   (ports + services)
            └── Phase 3: nmap + vulscan    (offline CVE correlation)
                        │
                        ▼
              report_generator.py
                ├── executive_summary.html  (CISO/management)
                ├── technical_report.html   (security team)
                └── raw.json               (SIEM/ticketing)
```

### Three-Phase Scan Design

At enterprise scale (1000+ hosts across multiple segments), running a full vulnerability scan against all hosts simultaneously is both noisy and wasteful. The three-phase design separates concerns:

**Phase 1 — Host Discovery.** A fast ping sweep (`-sn`) identifies live hosts. On a typical enterprise network, 30–60% of IP space in any given subnet is unused. Skipping dead IPs before running expensive script-based scans significantly reduces total scan time.

**Phase 2 — Port and Service Enumeration.** Runs only against confirmed live hosts. Performs SYN scanning (`-sS`), service version detection (`-sV`), and OS fingerprinting (`-O`) against the top 1000 ports. Produces a full picture of the attack surface per host.

**Phase 3 — CVE Correlation.** Runs only against hosts with interesting open ports identified in Phase 2. Executes NSE vuln scripts and the vulscan script against an entirely offline CVE database. This is the most time-intensive phase and scoping it to relevant hosts is critical for performance.

### Parallel Execution Model

Segments are sorted by priority (configured in `config.yaml`) and submitted to a `ThreadPoolExecutor`. Up to `max_concurrent_segments` segments run simultaneously. With 6–20 segments and a default of 4 concurrent workers, all segments complete within a single overnight window without saturating the network.

---

## Technology Stack — Decisions and Rationale

### Nmap (native binary) vs python-nmap

**Chosen: Native nmap binary invoked via subprocess**

The previous implementation used `python-nmap`, a thin wrapper that calls nmap and parses basic output. It was replaced for two reasons. First, python-nmap exposes a limited subset of nmap's capability — it does not cleanly support NSE script execution, script argument passing, or fine-grained output control needed for CVE correlation. Second, calling nmap natively via `subprocess` gives full control over every flag, timing parameter, and output format, and produces XML output (`-oX`) which is parsed by `python-libnmap` with full fidelity.

**Alternatives considered:**
- `python-nmap` — rejected: insufficient NSE support, poor XML handling
- `masscan` — rejected: extremely fast but no service detection or scripting engine; would require a separate CVE correlation layer
- OpenVAS/Greenbone — rejected: excellent capability but requires a persistent daemon, database, and internet connectivity for feed updates; incompatible with air-gap requirement

---

### python-libnmap vs manual XML parsing

**Chosen: python-libnmap**

`python-libnmap` is a mature library specifically designed to parse nmap XML output into well-structured Python objects (`NmapReport`, `NmapHost`, `NmapService`). It handles edge cases in nmap's XML output that manual parsing with `xml.etree` or `lxml` would require significant engineering effort to replicate correctly.

**Note on `scripts_results`:** The library returns script results as tuples or dicts depending on version. The orchestrator handles all three possible formats defensively:
```python
for result in svc.scripts_results:
    if isinstance(result, (list, tuple)) and len(result) >= 2:
        scripts[result[0]] = result[1] if result[1] else ""
    elif isinstance(result, dict):
        scripts[result.get("id", "unknown")] = result.get("output", "")
```

---

### vulscan (offline NSE script) vs online CVE APIs

**Chosen: vulscan with locally cached CVE databases**

The air-gap requirement eliminates any solution that requires internet connectivity for CVE lookups. vulscan is an Nmap NSE script that queries a set of locally stored CSV vulnerability databases (including the NVD CVE feed, OSVDB, SecurityTracker, and others) and matches discovered service version strings against known vulnerable versions.

**Databases included (all offline, stored in `/usr/share/nmap/scripts/vulscan/` or `/usr/local/share/nmap/scripts/vulscan/`):**

| Database | Source |
|---|---|
| `cve.csv` | NVD CVE feed |
| `scipvuldb.csv` | SCIP vulnerability database |
| `osvdb.csv` | Open Source Vulnerability Database |
| `securitytracker.csv` | SecurityTracker |
| `xforce.csv` | IBM X-Force |
| `exploitdb.csv` | Exploit-DB |
| `openvas.csv` | OpenVAS NVT feed |

**Alternatives considered:**
- OpenVAS local scanner — rejected: requires persistent daemon and database synchronisation
- Trivy — rejected: container/image focused, not suitable for network host scanning
- Nessus — rejected: commercial, not open-source, requires internet for plugin updates

**Database update procedure (controlled, not automatic):** The vulscan databases must be updated periodically via `git pull` in the vulscan directory. This should be performed during a controlled maintenance window with temporary, monitored internet access, then the host re-air-gapped immediately. This is a deliberate operational decision — automatic updates would create an ongoing internet dependency incompatible with the air-gap posture.

---

### Jinja2 for report templating

**Chosen: Jinja2**

Reports are generated from Jinja2 templates (`executive.html.j2`, `technical.html.j2`) rather than string concatenation or a reporting framework. Jinja2 provides clean separation between data and presentation, supports template inheritance and filters, and produces self-contained HTML files that require no internet connection or CDN to render correctly. All CSS is inlined in the templates.

**Alternatives considered:**
- ReportLab (PDF) — rejected: PDF is less useful for interactive browsing of large host lists; HTML with collapsible sections is more navigable
- WeasyPrint (HTML to PDF) — possible future addition for print distribution; not required currently
- Direct string formatting — rejected: unmaintainable at the required output complexity

---

### systemd timer (Linux) vs crontab

**Chosen: systemd timer**

The original implementation used a bare crontab entry. systemd timers were chosen because they provide structured logging via `journald`, `Persistent=true` to catch missed runs (e.g. if the host was offline at the scheduled time), service dependency ordering via `After=network.target`, and easy status inspection via `systemctl`. Failed runs surface immediately in `journalctl` rather than silently producing empty output.

**FreeBSD equivalent:** systemd does not exist on FreeBSD. The FreeBSD implementation uses `/etc/cron.d/vulnscan` for scheduling (functionally equivalent to the original crontab but scoped to a dedicated file) and an `rc.d` script for nginx service management and on-demand manual scan triggering.

---

### nginx for report serving

**Chosen: nginx**

A lightweight nginx instance serves the `/scans` directory over the LAN. It was chosen over alternatives because it is available in all target OS package repositories, has a minimal resource footprint suitable for a dedicated scanning host, and supports HTTP Basic Auth natively via `.htpasswd`.

**Linux `.htpasswd` generation:** `apache2-utils` provides the `htpasswd` binary.

**FreeBSD `.htpasswd` generation:** `apache2-utils` is not available as a standalone package. The FreeBSD implementation uses Python's `passlib` library instead:
```python
from passlib.apache import HtpasswdFile
ht = HtpasswdFile("/usr/local/etc/nginx/.htpasswd", new=True)
ht.set_password("analyst", password)
ht.save()
```

**nginx config structure difference:**
- Linux: uses the `sites-available/sites-enabled` symlink pattern standard on Debian/Ubuntu
- FreeBSD: uses a single `/usr/local/etc/nginx/nginx.conf` file, which is the standard on FreeBSD

---

### Raw socket access — setcap vs iocage allow_raw_sockets

Nmap's SYN scan (`-sS`) requires raw socket access to craft TCP packets. On Linux, this is granted to the nmap binary via:
```bash
setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap
```
This allows the `scanner` service account to run SYN scans without being root.

FreeBSD does not have Linux capabilities (`setcap`). Raw socket access in a jail is controlled at the host level via the jail configuration parameter `allow_raw_sockets=1`, set when the jail is created via iocage:
```sh
iocage create ... allow_raw_sockets=1
```
Without this, nmap falls back to connect scans (`-sT`), which complete the TCP handshake and are more detectable and slower. `allow_raw_sockets=1` must be set on the **host**, not inside the jail.

---

### Python venv (FreeBSD only)

On FreeBSD, Python packages are installed into a virtual environment at `/opt/vulnscan/venv/` rather than system-wide. This avoids conflicts with FreeBSD's ports-managed Python packages and provides a clean, reproducible dependency environment. The orchestrator shebang and cron entry both reference the venv Python binary explicitly:
```
/opt/vulnscan/venv/bin/python3 /opt/vulnscan/orchestrator.py
```

On Linux (Debian/Ubuntu), packages are installed system-wide via pip with `--break-system-packages`, which is acceptable in a single-purpose scanning host context.

---

## Setup Guide — Ubuntu/Debian

### Prerequisites

- Ubuntu 22.04 LTS or Debian 12+ (bare metal or VM)
- Root access
- Internet access during installation only
- All files from the `vulnscan/` directory present on the host

### Step 1 — Prepare the host

Ensure the system is up to date before beginning:
```bash
sudo apt-get update && sudo apt-get upgrade -y
```

### Step 2 — Configure IP ranges

Before running the installer, edit `config.yaml` and replace the placeholder IP ranges with your actual network segments. Segments are processed in priority order — place your most critical segments (DMZ, server farms) at the top.

```yaml
networks:
  - label: "DMZ — Public Facing"
    priority: 1
    ranges:
      - 10.10.0.0/24   # ← replace with your actual range
```

### Step 3 — Configure exclusions

Edit `exclusions.yaml` and add every device that must never be scanned. Be exhaustive for OT/ICS devices. The scanner will abort entirely rather than risk scanning an excluded OT segment if this file cannot be parsed.

```yaml
excluded_hosts:
  - ip: 10.30.0.10
    label: "PLC — Assembly Line 1"
    reason: "Will fault under port scan."
```

### Step 4 — Run the installer

```bash
sudo sh install.sh
```

The installer performs the following actions in order:
1. Installs system packages: `nmap`, `python3`, `python3-pip`, `git`, `nginx`, `apache2-utils`
2. Installs Python libraries: `python-libnmap`, `pyyaml`, `jinja2`
3. Clones vulscan and its offline CVE databases to `/usr/share/nmap/scripts/vulscan/`
4. Creates the `scanner` service account
5. Deploys all files to `/opt/vulnscan/`
6. Grants nmap raw socket capability via `setcap`
7. Installs and enables the systemd timer (Sunday 23:00, or daily if reconfigured)
8. Configures nginx on port 8080 and prompts for the `analyst` portal password

### Step 5 — Test the scan manually

Before air-gapping, run a manual scan to confirm everything is working:
```bash
sudo systemctl start vuln-scan.service
```

Watch the output in real time:
```bash
journalctl -u vuln-scan.service -f
```

Reports will appear in `/scans/YYYY-MM-DD/` once complete.

### Step 6 — Verify the web portal

Open a browser on the scanning host or any LAN-connected machine:
```
http://<scanner-ip>:8080
```
Log in with username `analyst` and the password set during installation. You should see a directory listing of dated scan folders.

### Step 7 — Air-gap the host

Once the test scan has completed successfully and the portal is confirmed accessible:
- Remove or disable the internet-facing network interface or firewall rule
- Confirm no outbound routes remain to the internet
- The system will continue to operate indefinitely using only local data

### Changing scan schedule (daily vs weekly)

Edit the systemd timer:
```bash
sudo nano /etc/systemd/system/vuln-scan.timer
```

Weekly (Sunday 23:00):
```ini
OnCalendar=Sun 23:00:00
```

Daily (23:00 every night):
```ini
OnCalendar=*-*-* 23:00:00
```

Reload after any change:
```bash
sudo systemctl daemon-reload && sudo systemctl restart vuln-scan.timer
```

### Troubleshooting — Linux

**nginx 403 after correct password:**
```bash
sudo chmod 755 /scans
sudo chown -R scanner:www-data /scans
sudo find /scans -type f -exec chmod 644 {} \;
sudo find /scans -type d -exec chmod 755 {} \;
sudo chown root:www-data /etc/nginx/.htpasswd
sudo chmod 640 /etc/nginx/.htpasswd
sudo systemctl restart nginx
```

**nginx not listening on port 8080:**
```bash
sudo nginx -t                    # Check config for errors
sudo ss -tlnp | grep 8080        # Check if port is in use by another process
```

**Reset portal password:**
```bash
sudo htpasswd /etc/nginx/.htpasswd analyst
```

**Scan not running:**
```bash
systemctl list-timers vuln-scan.timer    # Check next scheduled run
journalctl -u vuln-scan.service -n 100  # Check last run logs
```

---

## Setup Guide — FreeBSD iocage Jail

### Prerequisites

- FreeBSD 15.x host with ZFS pool
- iocage installed (`pkg install iocage`)
- Root access on the host
- Internet access during installation only
- All files from the `vulnscan-freebsd/` directory present on the host

### FreeBSD 15 / iocage Compatibility Note

FreeBSD 15 is currently in CURRENT/development status. iocage depends on Python and jail APIs that may be in flux. If `iocage fetch` or `iocage create` fail, the `jail_create.sh` script contains a commented fallback section using raw `/etc/jail.conf` configuration which does not depend on iocage.

### Step 1 — Create the jail (on the FreeBSD host)

Edit `jail_create.sh` and set your environment-specific values:
```sh
JAIL_NAME="vulnscan"
JAIL_IP="192.168.1.200"        # Free IP on your LAN
JAIL_GATEWAY="192.168.1.1"     # Your LAN gateway
JAIL_INTERFACE="em0"           # Host NIC (check with: ifconfig)
```

Run on the host as root:
```sh
sh jail_create.sh
```

This creates the jail with `allow_raw_sockets=1` — this parameter is critical and must be set at the host level. It cannot be set from inside the jail and cannot be added after jail creation without recreating the jail.

### Step 2 — Copy files into the jail

```sh
# Get the jail's filesystem mountpoint
JAILROOT=$(iocage get mountpoint vulnscan)/root

# Create destination directory inside the jail
mkdir -p ${JAILROOT}/tmp/vulnscan

# Copy all files
cp -r /path/to/vulnscan-freebsd/* ${JAILROOT}/tmp/vulnscan/
```

### Step 3 — Configure IP ranges and exclusions

Before running the installer, edit the copies of `config.yaml` and `exclusions.yaml` that were copied into the jail:
```sh
nano ${JAILROOT}/tmp/vulnscan/config.yaml
nano ${JAILROOT}/tmp/vulnscan/exclusions.yaml
```
Replace all placeholder IP ranges and add your complete OT/ICS exclusion list.

### Step 4 — Run the installer inside the jail

```sh
iocage exec vulnscan sh /tmp/vulnscan/install.sh
```

The installer performs the following actions in order:
1. Bootstraps `pkg` if not already present
2. Installs binary packages via `pkg`: `nmap`, `python311`, `py311-pip`, `git`, `nginx`, `bash`
3. Creates a Python venv at `/opt/vulnscan/venv/`
4. Installs Python libraries into the venv: `python-libnmap`, `pyyaml`, `jinja2`, `passlib`, `bcrypt`
5. Clones vulscan to `/usr/local/share/nmap/scripts/vulscan/`
6. Creates the `scanner` service account via `pw useradd`
7. Deploys all files to `/opt/vulnscan/`
8. Installs nginx config to `/usr/local/etc/nginx/nginx.conf`
9. Generates `.htpasswd` via passlib and prompts for the `analyst` password
10. Enables nginx via `sysrc nginx_enable="YES"` and starts the service
11. Installs the `rc.d/vulnscan` script to `/usr/local/etc/rc.d/`
12. Writes the cron job to `/etc/cron.d/vulnscan` (daily at 23:00)

### Step 5 — Test the scan manually inside the jail

```sh
iocage exec vulnscan /opt/vulnscan/venv/bin/python3 /opt/vulnscan/orchestrator.py
```

Or using the rc.d script:
```sh
iocage exec vulnscan service vulnscan run
```

Monitor progress:
```sh
iocage exec vulnscan tail -f /scans/$(date +%Y-%m-%d)/scan.log
```

### Step 6 — Verify the web portal

```
http://<jail-ip>:8080
```

Log in with username `analyst` and the password set during installation.

### Step 7 — Air-gap the jail

Remove the jail's internet route or restrict outbound access at the host pf/ipfw firewall level. The scanner requires no internet connectivity after installation.

### Changing scan schedule (FreeBSD)

Edit the cron file inside the jail:
```sh
iocage exec vulnscan nano /etc/cron.d/vulnscan
```

Daily at 23:00 (default):
```
0 23 * * * root /opt/vulnscan/venv/bin/python3 /opt/vulnscan/orchestrator.py >> /opt/vulnscan/logs/cron.log 2>&1
```

Every Sunday at 23:00:
```
0 23 * * 0 root /opt/vulnscan/venv/bin/python3 /opt/vulnscan/orchestrator.py >> /opt/vulnscan/logs/cron.log 2>&1
```

Restart cron after changes:
```sh
iocage exec vulnscan service cron restart
```

### Troubleshooting — FreeBSD

**nmap SYN scan fails / falls back to connect scan:**
Confirm `allow_raw_sockets` is set on the host:
```sh
iocage get allow_raw_sockets vulnscan
```
If it returns `0`, the jail must be recreated with `allow_raw_sockets=1`. This cannot be changed on a running jail.

**iocage fails on FreeBSD 15-CURRENT:**
Use the raw jail fallback in `jail_create.sh`. Add the commented block to `/etc/jail.conf` on the host and run:
```sh
jail -c vulnscan
```
Then bootstrap pkg manually:
```sh
pkg -j vulnscan install -y pkg
```

**nginx 403:**
```sh
iocage exec vulnscan chmod 755 /scans
iocage exec vulnscan chown -R scanner:www /scans
iocage exec vulnscan service nginx restart
```

**Reset portal password inside the jail:**
```sh
iocage exec vulnscan /opt/vulnscan/venv/bin/python3 - <<'EOF'
from passlib.apache import HtpasswdFile
ht = HtpasswdFile("/usr/local/etc/nginx/.htpasswd")
ht.set_password("analyst", "yournewpassword")
ht.save()
EOF
```

---

## Operational Reference

### Manual scan trigger

**Linux:**
```bash
sudo systemctl start vuln-scan.service
```

**FreeBSD:**
```sh
iocage exec vulnscan service vulnscan run
```

### Log locations

| Log | Linux path | FreeBSD path |
|---|---|---|
| Scan output log | `/scans/YYYY-MM-DD/scan.log` | `/scans/YYYY-MM-DD/scan.log` |
| Cron/systemd log | `journalctl -u vuln-scan.service` | `/opt/vulnscan/logs/cron.log` |
| nginx access log | `/var/log/nginx/vulnscan_access.log` | `/var/log/nginx/vulnscan_access.log` |
| nginx error log | `/var/log/nginx/vulnscan_error.log` | `/var/log/nginx/vulnscan_error.log` |

### Updating the offline CVE database

This must be done during a controlled maintenance window with temporary internet access:

**Linux:**
```bash
git -C /usr/share/nmap/scripts/vulscan pull
```

**FreeBSD (inside jail):**
```sh
git -C /usr/local/share/nmap/scripts/vulscan pull
```

Re-air-gap immediately after the update is complete.

### Adding a new network segment

Edit `/opt/vulnscan/config.yaml` and add the segment with a priority number. No restart or reinstallation is required — the config is read fresh at each scan run.

### Adding an exclusion

Edit `/opt/vulnscan/exclusions.yaml` and add the IP or range. Changes take effect on the next scan run. For OT/ICS additions, test with a manual scan run before the next scheduled window.

---

## File Reference

| File | Purpose |
|---|---|
| `orchestrator.py` | Main scan engine — discovery, port scan, CVE correlation, parallelism |
| `report_generator.py` | Parses scan results, produces tiered HTML and JSON reports |
| `config.yaml` | Network segments, scan tuning parameters, output configuration |
| `exclusions.yaml` | Protected hosts — never scanned under any circumstance |
| `templates/executive.html.j2` | Jinja2 template for the executive summary report |
| `templates/technical.html.j2` | Jinja2 template for the technical detail report |
| `install.sh` | One-time installation script (Linux or FreeBSD) |
| `jail_create.sh` | *(FreeBSD only)* iocage jail creation with correct parameters |
| `vuln-scan.timer` | *(Linux only)* systemd timer unit |
| `vuln-scan.service` | *(Linux only)* systemd service unit |
| `rc.d/vulnscan` | *(FreeBSD only)* rc.d service script |
| `nginx.conf` | *(FreeBSD only)* nginx configuration (unified format) |
| `vulnscan-nginx.conf` | *(Linux only)* nginx site config (sites-available format) |
