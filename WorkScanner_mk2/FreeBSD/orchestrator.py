#!/usr/local/bin/python3
"""
orchestrator.py
Air-gapped enterprise vulnerability scan orchestrator.
FreeBSD 15 iocage jail | 6-20 segments | OT/ICS safe | Parallel execution

FreeBSD-specific notes vs Linux version:
- nmap binary: /usr/local/bin/nmap
- vulscan DB:  /usr/local/share/nmap/scripts/vulscan/
- No setcap — raw sockets granted via iocage allow_raw_sockets=1
- Logging goes to /opt/vulnscan/logs/ and scan output /scans/
- Python venv at /opt/vulnscan/venv/
"""

import os
import sys
import json
import logging
import ipaddress
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import yaml
from libnmap.parser import NmapParser

# FreeBSD binary paths
NMAP_BIN     = "/usr/local/bin/nmap"
VULSCAN_DIR  = "/usr/local/share/nmap/scripts/vulscan"
CONFIG_PATH  = "/opt/vulnscan/config.yaml"
EXCL_PATH    = "/opt/vulnscan/exclusions.yaml"
LOG_DIR      = "/opt/vulnscan/logs"
SCANS_DIR    = "/scans"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LOGGING
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def setup_logging(log_path: Path) -> logging.Logger:
    logger = logging.getLogger("vulnscan")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")

    fh = logging.FileHandler(log_path)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)

    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CONFIGURATION & EXCLUSION LOADING
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def load_yaml(path: str) -> dict:
    with open(path, "r") as f:
        data = yaml.safe_load(f)
    if data is None:
        raise ValueError(f"Empty or invalid YAML: {path}")
    return data


def build_exclusion_set(exclusions_cfg: dict,
                        logger: logging.Logger) -> set:
    excluded = set()
    strict = exclusions_cfg.get("validation_mode", "strict") == "strict"

    for entry in exclusions_cfg.get("excluded_hosts", []):
        try:
            if "ip" in entry:
                excluded.add(ipaddress.IPv4Address(entry["ip"]))
                logger.debug(f"Excluded: {entry['ip']} — {entry.get('reason','')}")
            elif "range" in entry:
                net = ipaddress.IPv4Network(entry["range"], strict=False)
                count = 0
                for ip in net.hosts():
                    excluded.add(ip)
                    count += 1
                logger.debug(f"Excluded range: {entry['range']} "
                             f"({count} hosts) — {entry.get('reason','')}")
        except Exception as e:
            msg = f"Failed to parse exclusion entry {entry}: {e}"
            if strict:
                logger.critical(msg)
                raise RuntimeError(msg)
            else:
                logger.warning(msg)

    logger.info(f"Exclusion list built: {len(excluded)} hosts protected.")
    return excluded


def validate_targets_against_exclusions(targets: list,
                                        exclusions: set,
                                        segment_label: str,
                                        logger: logging.Logger,
                                        is_ot: bool = False) -> list:
    safe    = []
    blocked = []
    for ip_str in targets:
        ip = ipaddress.IPv4Address(ip_str)
        if ip in exclusions:
            blocked.append(ip_str)
        else:
            safe.append(ip_str)

    if blocked:
        if is_ot:
            logger.critical(f"[{segment_label}] PRE-SCAN SAFETY: "
                            f"{len(blocked)} excluded hosts removed.")
            for h in blocked:
                logger.critical(f"  BLOCKED (OT): {h}")
        else:
            logger.warning(f"[{segment_label}] {len(blocked)} excluded "
                           f"hosts removed from target list.")
    return safe


def resolve_segment_targets(segment: dict,
                             exclusions: set,
                             logger: logging.Logger) -> list:
    targets = []
    for cidr in segment["ranges"]:
        net = ipaddress.IPv4Network(cidr, strict=False)
        for ip in net.hosts():
            if ipaddress.IPv4Address(str(ip)) not in exclusions:
                targets.append(str(ip))
    return targets


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# HELPERS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def safe_slug(label: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in label)[:40]


def write_target_file(targets: list, directory: str, name: str) -> str:
    path = os.path.join(directory, f"{name}.txt")
    with open(path, "w") as f:
        f.write("\n".join(targets))
    return path


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# NMAP EXECUTION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def run_nmap(args: list, logger: logging.Logger,
             label: str = "") -> bool:
    # Use explicit FreeBSD nmap path
    cmd = [NMAP_BIN] + args
    logger.debug(f"[{label}] {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=7200
        )
        if result.returncode != 0:
            logger.error(f"[{label}] nmap stderr: {result.stderr.strip()}")
            return False
        return True
    except subprocess.TimeoutExpired:
        logger.error(f"[{label}] nmap timed out after 2 hours.")
        return False
    except Exception as e:
        logger.error(f"[{label}] nmap failed: {e}")
        return False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# THREE-PHASE SCAN LOGIC
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def phase1_discovery(targets_file: str, out_xml: str,
                     cfg: dict, label: str,
                     logger: logging.Logger) -> list:
    p1 = cfg["scan_settings"]["phase1_discovery"]
    args = [
        "-sn",
        f"-{p1['timing']}",
        "--min-parallelism", str(p1["min_parallelism"]),
        "-iL", targets_file,
        "-oX", out_xml,
    ]
    success = run_nmap(args, logger, label)
    if not success or not Path(out_xml).exists():
        logger.error(f"[{label}] Phase 1 produced no output.")
        return []

    try:
        report = NmapParser.parse_fromfile(out_xml)
        live   = [h.address for h in report.hosts if h.is_up()]
    except Exception as e:
        logger.error(f"[{label}] Phase 1 parse failed: {e}")
        return []

    logger.info(f"[{label}] Phase 1: {len(live)} live hosts.")
    return live


def phase2_ports(live_file: str, out_xml: str,
                 cfg: dict, label: str,
                 logger: logging.Logger):
    p2 = cfg["scan_settings"]["phase2_ports"]
    args = [
        "-sS", "-sV",
        "--version-intensity", str(p2["version_intensity"]),
        f"-{p2['timing']}",
        "--max-rate", str(p2["max_rate"]),
        "--top-ports", str(p2["top_ports"]),
        "-iL", live_file,
        "-oX", out_xml,
    ]
    if p2.get("os_detection"):
        args.append("-O")

    success = run_nmap(args, logger, label)
    if not success or not Path(out_xml).exists():
        return [], None

    try:
        report = NmapParser.parse_fromfile(out_xml)
    except Exception as e:
        logger.error(f"[{label}] Phase 2 parse failed: {e}")
        return [], None

    interesting = [
        h.address for h in report.hosts
        if any(s.state == "open" for s in h.services)
    ]
    logger.info(f"[{label}] Phase 2: {len(interesting)} hosts with open ports.")
    return interesting, report


def phase3_vulns(interesting_file: str, out_xml: str,
                 cfg: dict, label: str,
                 logger: logging.Logger):
    p3  = cfg["scan_settings"]["phase3_vulns"]
    db  = p3["vulscan_db"]
    args = [
        "-sV",
        "--script", f"vuln,{VULSCAN_DIR}/vulscan.nse",
        "--script-args", f"vulscandb={db}",
        f"-{p3['timing']}",
        "--max-rate", str(p3["max_rate"]),
        "-iL", interesting_file,
        "-oX", out_xml,
    ]
    success = run_nmap(args, logger, label)
    if not success or not Path(out_xml).exists():
        return None

    try:
        report = NmapParser.parse_fromfile(out_xml)
    except Exception as e:
        logger.error(f"[{label}] Phase 3 parse failed: {e}")
        return None

    logger.info(f"[{label}] Phase 3: CVE correlation complete.")
    return report


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# RESULT SERIALIZATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def serialize_report(report, segment_label: str) -> list:
    if report is None:
        return []
    hosts = []
    for host in report.hosts:
        services = []
        for svc in host.services:
            scripts = {}
            for result in svc.scripts_results:
                if isinstance(result, (list, tuple)) and len(result) >= 2:
                    scripts[result[0]] = result[1] if result[1] else ""
                elif isinstance(result, dict):
                    scripts[result.get("id", "unknown")] = result.get("output", "")
            services.append({
                "port":     svc.port,
                "protocol": svc.protocol,
                "state":    svc.state,
                "service":  svc.service,
                "product":  svc.banner,
                "scripts":  scripts,
            })
        hosts.append({
            "ip":       host.address,
            "hostname": host.hostnames[0] if host.hostnames else "",
            "status":   host.status,
            "os":       str(host.os_fingerprinted),
            "segment":  segment_label,
            "services": services,
        })
    return hosts


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SEGMENT SCAN WORKER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def scan_segment(segment: dict, cfg: dict, exclusions: set,
                 tmp_dir: str, logger: logging.Logger) -> dict:
    label    = segment["label"]
    slug     = safe_slug(label)
    is_ot    = segment.get("ot_segment", False)
    start_ts = datetime.now()

    logger.info(f"[{label}] "
                f"{'OT SEGMENT — extra safety active | ' if is_ot else ''}"
                f"Scan started.")

    raw_targets = resolve_segment_targets(segment, exclusions, logger)
    if not raw_targets:
        logger.warning(f"[{label}] No targets after exclusion filtering.")
        return {"label": label, "hosts": [], "error": "no_targets"}

    logger.info(f"[{label}] {len(raw_targets)} targets after exclusions.")

    # Phase 1
    targets_file = write_target_file(raw_targets, tmp_dir, f"{slug}_all")
    disc_xml     = os.path.join(tmp_dir, f"{slug}_disc.xml")
    live_hosts   = phase1_discovery(targets_file, disc_xml, cfg, label, logger)

    if not live_hosts:
        return {"label": label, "hosts": []}

    live_hosts = validate_targets_against_exclusions(
        live_hosts, exclusions, label, logger, is_ot=is_ot)

    live_file  = write_target_file(live_hosts, tmp_dir, f"{slug}_live")
    ports_xml  = os.path.join(tmp_dir, f"{slug}_ports.xml")

    # Phase 2
    interesting_ips, ports_report = phase2_ports(
        live_file, ports_xml, cfg, label, logger)

    if not interesting_ips:
        return {"label": label,
                "hosts": serialize_report(ports_report, label)}

    interesting_ips = validate_targets_against_exclusions(
        interesting_ips, exclusions, label, logger, is_ot=is_ot)

    interesting_file = write_target_file(
        interesting_ips, tmp_dir, f"{slug}_interesting")
    vuln_xml = os.path.join(tmp_dir, f"{slug}_vuln.xml")

    # Phase 3
    vuln_report = phase3_vulns(
        interesting_file, vuln_xml, cfg, label, logger)

    elapsed = (datetime.now() - start_ts).seconds // 60
    logger.info(f"[{label}] Complete in ~{elapsed} minutes.")

    return {
        "label": label,
        "hosts": serialize_report(
            vuln_report if vuln_report else ports_report, label)
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# MAIN
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def main():
    try:
        cfg      = load_yaml(CONFIG_PATH)
        excl_cfg = load_yaml(EXCL_PATH)
    except Exception as e:
        print(f"[FATAL] Cannot load configuration: {e}")
        sys.exit(1)

    scan_date  = datetime.now().strftime("%Y-%m-%d")
    output_dir = Path(SCANS_DIR) / scan_date
    output_dir.mkdir(parents=True, exist_ok=True)

    log_path = output_dir / "scan.log"
    logger   = setup_logging(log_path)
    logger.info("=" * 60)
    logger.info(f"Vulnerability scan started — {scan_date}")
    logger.info(f"Host: FreeBSD jail | nmap: {NMAP_BIN}")
    logger.info("=" * 60)

    try:
        exclusions = build_exclusion_set(excl_cfg, logger)
    except RuntimeError as e:
        logger.critical(f"Exclusion list failed. Aborting. {e}")
        sys.exit(2)

    networks = sorted(cfg["networks"], key=lambda s: s.get("priority", 99))
    logger.info(f"Segments to scan: {len(networks)}")
    for seg in networks:
        logger.info(f"  [{seg.get('priority','?')}] {seg['label']}"
                    f"{'  [OT]' if seg.get('ot_segment') else ''}")

    max_workers = cfg["scan_settings"]["parallelism"]["max_concurrent_segments"]
    all_results = []

    with tempfile.TemporaryDirectory() as tmp_dir:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(
                    scan_segment, seg, cfg, exclusions, tmp_dir, logger
                ): seg["label"]
                for seg in networks
            }
            for future in as_completed(futures):
                label = futures[future]
                try:
                    result = future.result()
                    all_results.append(result)
                    logger.info(f"[{label}] {len(result.get('hosts',[]))} hosts collected.")
                except Exception as e:
                    logger.error(f"[{label}] Worker failed: {e}", exc_info=True)
                    all_results.append({"label": label, "hosts": [], "error": str(e)})

    json_path = output_dir / "raw.json"
    with open(json_path, "w") as f:
        json.dump({
            "scan_date":    scan_date,
            "generated_at": datetime.now().isoformat(),
            "platform":     "FreeBSD jail",
            "segments":     all_results,
        }, f, indent=2)
    logger.info(f"Raw JSON: {json_path}")

    try:
        from report_generator import generate_reports
        generate_reports(all_results, scan_date, output_dir, logger)
    except Exception as e:
        logger.error(f"Report generation failed: {e}", exc_info=True)

    logger.info("=" * 60)
    logger.info("Scan complete.")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
