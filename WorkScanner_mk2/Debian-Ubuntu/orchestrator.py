#!/usr/bin/env python3
"""
orchestrator.py
Air-gapped enterprise vulnerability scan orchestrator.
Debian/Ubuntu | 6-20 segments | OT/ICS safe | Parallel execution
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
from typing import Optional

import yaml
from libnmap.parser import NmapParser


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
    """
    Parse exclusions.yaml into a flat set of IPv4Address objects.
    Raises on parse failure if validation_mode is 'strict'.
    """
    excluded = set()
    strict = exclusions_cfg.get("validation_mode", "strict") == "strict"

    for entry in exclusions_cfg.get("excluded_hosts", []):
        try:
            if "ip" in entry:
                excluded.add(ipaddress.IPv4Address(entry["ip"]))
                logger.debug(f"Excluded host: {entry['ip']} — {entry.get('reason','')}")
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
    """
    Final safety check immediately before each nmap invocation.
    Filters out any excluded IPs that may have slipped through.
    For OT segments, logs every excluded host individually.
    Returns the safe target list.
    """
    safe = []
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
                            f"{len(blocked)} excluded hosts removed from target list.")
            for h in blocked:
                logger.critical(f"  BLOCKED (OT): {h}")
        else:
            logger.warning(f"[{segment_label}] PRE-SCAN SAFETY: "
                           f"{len(blocked)} excluded hosts removed from target list.")

    return safe


def resolve_segment_targets(segment: dict,
                             exclusions: set,
                             logger: logging.Logger) -> list:
    """Expand CIDR ranges for a segment, removing exclusions."""
    targets = []
    for cidr in segment["ranges"]:
        net = ipaddress.IPv4Network(cidr, strict=False)
        for ip in net.hosts():
            if ipaddress.IPv4Address(str(ip)) not in exclusions:
                targets.append(str(ip))
    return targets


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TARGET FILE HELPERS
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
    cmd = ["nmap"] + args
    logger.debug(f"[{label}] nmap {' '.join(args)}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=7200          # 2hr per-phase hard timeout
        )
        if result.returncode != 0:
            logger.error(f"[{label}] nmap stderr: {result.stderr.strip()}")
            return False
        return True
    except subprocess.TimeoutExpired:
        logger.error(f"[{label}] nmap phase timed out after 2 hours.")
        return False
    except Exception as e:
        logger.error(f"[{label}] nmap failed to launch: {e}")
        return False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# THREE-PHASE SCAN LOGIC
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def phase1_discovery(targets_file: str, out_xml: str,
                     cfg: dict, label: str,
                     logger: logging.Logger) -> list:
    """Ping sweep. Returns list of confirmed live host IPs."""
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
        live = [h.address for h in report.hosts if h.is_up()]
    except Exception as e:
        logger.error(f"[{label}] Phase 1 XML parse failed: {e}")
        return []

    logger.info(f"[{label}] Phase 1 complete: {len(live)} live hosts.")
    return live


def phase2_ports(live_file: str, out_xml: str,
                 cfg: dict, label: str,
                 logger: logging.Logger):
    """
    Port + service + OS scan against live hosts.
    Returns (interesting_ips, full NmapReport).
    """
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
        logger.error(f"[{label}] Phase 2 XML parse failed: {e}")
        return [], None

    interesting = [
        h.address for h in report.hosts
        if any(s.state == "open" for s in h.services)
    ]
    logger.info(f"[{label}] Phase 2 complete: "
                f"{len(interesting)} hosts with open ports.")
    return interesting, report


def phase3_vulns(interesting_file: str, out_xml: str,
                 cfg: dict, label: str,
                 logger: logging.Logger):
    """CVE correlation via offline vulscan + NSE vuln scripts."""
    p3 = cfg["scan_settings"]["phase3_vulns"]
    args = [
        "-sV",
        "--script", "vuln,vulscan/vulscan.nse",
        "--script-args", f"vulscandb={p3['vulscan_db']}",
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
        logger.error(f"[{label}] Phase 3 XML parse failed: {e}")
        return None

    logger.info(f"[{label}] Phase 3 complete: CVE correlation done.")
    return report


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# RESULT SERIALIZATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def serialize_report(report, segment_label: str) -> list:
    """Convert a libnmap NmapReport to a JSON-serializable list."""
    if report is None:
        return []
    hosts = []
    for host in report.hosts:
        services = []
        for svc in host.services:
            scripts = {}
            for script_id, output in svc.scripts_results:
                scripts[script_id] = output
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
                 tmp_dir: str,
                 logger: logging.Logger) -> dict:
    """
    Full three-phase scan for a single network segment.
    Returns a dict ready for JSON serialization and report generation.
    """
    label    = segment["label"]
    slug     = safe_slug(label)
    is_ot    = segment.get("ot_segment", False)
    start_ts = datetime.now()

    logger.info(f"[{label}] {'OT SEGMENT — extra safety checks active | ' if is_ot else ''}"
                f"Scan started.")

    # Resolve targets
    raw_targets = resolve_segment_targets(segment, exclusions, logger)
    if not raw_targets:
        logger.warning(f"[{label}] No targets after exclusion filtering.")
        return {"label": label, "hosts": [], "error": "no_targets"}

    logger.info(f"[{label}] {len(raw_targets)} targets after exclusions.")

    # ── Phase 1: Discovery ───────────────────────────────────
    all_targets_file = write_target_file(raw_targets, tmp_dir, f"{slug}_all")
    disc_xml = os.path.join(tmp_dir, f"{slug}_disc.xml")
    live_hosts = phase1_discovery(all_targets_file, disc_xml, cfg, label, logger)

    if not live_hosts:
        logger.info(f"[{label}] No live hosts. Segment complete.")
        return {"label": label, "hosts": []}

    # OT belt-and-suspenders: re-validate live hosts before phase 2
    live_hosts = validate_targets_against_exclusions(
        live_hosts, exclusions, label, logger, is_ot=is_ot)

    live_file = write_target_file(live_hosts, tmp_dir, f"{slug}_live")
    ports_xml = os.path.join(tmp_dir, f"{slug}_ports.xml")

    # ── Phase 2: Port + Service Scan ─────────────────────────
    interesting_ips, ports_report = phase2_ports(
        live_file, ports_xml, cfg, label, logger)

    if not interesting_ips:
        logger.info(f"[{label}] No open ports. Returning phase 2 data.")
        return {
            "label": label,
            "hosts": serialize_report(ports_report, label)
        }

    # OT: re-validate again before phase 3
    interesting_ips = validate_targets_against_exclusions(
        interesting_ips, exclusions, label, logger, is_ot=is_ot)

    interesting_file = write_target_file(
        interesting_ips, tmp_dir, f"{slug}_interesting")
    vuln_xml = os.path.join(tmp_dir, f"{slug}_vuln.xml")

    # ── Phase 3: CVE Correlation ──────────────────────────────
    vuln_report = phase3_vulns(
        interesting_file, vuln_xml, cfg, label, logger)

    elapsed = (datetime.now() - start_ts).seconds // 60
    logger.info(f"[{label}] All phases complete in ~{elapsed} minutes.")

    return {
        "label": label,
        "hosts": serialize_report(
            vuln_report if vuln_report else ports_report, label)
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# MAIN
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def main():
    config_path     = "/opt/vulnscan/config.yaml"
    exclusions_path = "/opt/vulnscan/exclusions.yaml"

    # Load configs
    try:
        cfg      = load_yaml(config_path)
        excl_cfg = load_yaml(exclusions_path)
    except Exception as e:
        print(f"[FATAL] Cannot load configuration: {e}")
        sys.exit(1)

    # Set up output directory
    scan_date  = datetime.now().strftime("%Y-%m-%d")
    output_dir = Path(cfg["output"]["base_directory"]) / scan_date
    output_dir.mkdir(parents=True, exist_ok=True)

    log_path = output_dir / "scan.log"
    logger   = setup_logging(log_path)
    logger.info("=" * 60)
    logger.info(f"Vulnerability scan started — {scan_date}")
    logger.info("=" * 60)

    # Build exclusions — abort entirely on failure (strict mode)
    try:
        exclusions = build_exclusion_set(excl_cfg, logger)
    except RuntimeError as e:
        logger.critical(f"Exclusion list failed to load. "
                        f"Aborting to protect OT/ICS devices. {e}")
        sys.exit(2)

    # Sort segments by priority
    networks = sorted(
        cfg["networks"],
        key=lambda s: s.get("priority", 99)
    )
    logger.info(f"Segments to scan: {len(networks)}")
    for seg in networks:
        logger.info(f"  [{seg.get('priority','?')}] {seg['label']}"
                    f"{'  [OT SEGMENT]' if seg.get('ot_segment') else ''}")

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
                    host_count = len(result.get("hosts", []))
                    logger.info(f"[{label}] Collected: {host_count} hosts.")
                except Exception as e:
                    logger.error(f"[{label}] Worker exception: {e}",
                                 exc_info=True)
                    all_results.append({
                        "label": label,
                        "hosts": [],
                        "error": str(e)
                    })

    # Save raw JSON
    json_path = output_dir / "raw.json"
    payload   = {
        "scan_date":    scan_date,
        "generated_at": datetime.now().isoformat(),
        "segments":     all_results,
    }
    with open(json_path, "w") as f:
        json.dump(payload, f, indent=2)
    logger.info(f"Raw JSON saved: {json_path}")

    # Generate reports
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
