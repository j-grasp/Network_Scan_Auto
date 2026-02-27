#!/usr/bin/env python3
"""
report_generator.py
Produces tiered HTML reports from scan results.
All output is self-contained — zero external dependencies at render time.
"""

import json
from pathlib import Path
from jinja2 import Environment, FileSystemLoader


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CVE EXTRACTION & SEVERITY CLASSIFICATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def classify_severity(text: str) -> str:
    t = text.lower()
    if any(k in t for k in ["critical", "cvss: 9", "cvss: 10", "cvss:9", "cvss:10"]):
        return "CRITICAL"
    if any(k in t for k in ["high", "cvss: 7", "cvss: 8", "cvss:7", "cvss:8"]):
        return "HIGH"
    if any(k in t for k in ["medium", "cvss: 5", "cvss: 6", "cvss:5", "cvss:6"]):
        return "MEDIUM"
    if any(k in t for k in ["low", "cvss: 3", "cvss: 4", "cvss:3", "cvss:4"]):
        return "LOW"
    return "INFO"


def extract_cves(scripts: dict) -> list:
    """Return list of {cve_id, detail, severity, script} from NSE output."""
    cves = []
    seen = set()
    for script_name, output in (scripts or {}).items():
        if not output:
            continue
        for line in output.splitlines():
            if "CVE-" in line:
                parts = line.split()
                cve_id = next(
                    (p.strip("(),") for p in parts if p.startswith("CVE-")),
                    "CVE-UNKNOWN"
                )
                key = f"{cve_id}:{script_name}"
                if key in seen:
                    continue
                seen.add(key)
                cves.append({
                    "cve_id":   cve_id,
                    "detail":   line.strip(),
                    "severity": classify_severity(line),
                    "script":   script_name,
                })
    return sorted(cves, key=lambda c: SEVERITY_ORDER.index(c["severity"]))


def build_summary(segments: list) -> dict:
    total_hosts      = 0
    hosts_with_vulns = 0
    open_port_count  = 0
    severity_counts  = {s: 0 for s in SEVERITY_ORDER}

    for seg in segments:
        for host in seg.get("hosts", []):
            total_hosts += 1
            host_has_vuln = False
            for svc in host.get("services", []):
                if svc.get("state") == "open":
                    open_port_count += 1
                for cve in extract_cves(svc.get("scripts", {})):
                    severity_counts[cve["severity"]] += 1
                    host_has_vuln = True
            if host_has_vuln:
                hosts_with_vulns += 1

    return {
        "total_hosts":         total_hosts,
        "hosts_with_findings": hosts_with_vulns,
        "open_ports":          open_port_count,
        "severity_counts":     severity_counts,
    }


def build_segment_summaries(segments: list) -> list:
    summaries = []
    for seg in segments:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for host in seg.get("hosts", []):
            for svc in host.get("services", []):
                for cve in extract_cves(svc.get("scripts", {})):
                    counts[cve["severity"]] += 1
        summaries.append({
            "label":           seg["label"],
            "host_count":      len(seg.get("hosts", [])),
            "severity_counts": counts,
            "error":           seg.get("error"),
        })
    return summaries


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ENTRY POINT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def generate_reports(segments_data: list, scan_date: str,
                     output_dir: Path, logger):

    summary           = build_summary(segments_data)
    segment_summaries = build_segment_summaries(segments_data)

    severity_descriptions = {
        "CRITICAL": "Immediate exploitation likely. Patch or isolate within 24 hours.",
        "HIGH":     "Significant risk. Remediate within 7 days.",
        "MEDIUM":   "Moderate risk. Schedule remediation within 30 days.",
        "LOW":      "Low risk. Address in next maintenance cycle.",
        "INFO":     "Informational. Review and assess applicability.",
    }

    template_dir = Path("/opt/vulnscan/templates")
    env = Environment(loader=FileSystemLoader(str(template_dir)),
                      autoescape=True)
    env.globals["extract_cves"]       = extract_cves
    env.globals["classify_severity"]  = classify_severity

    context_exec = {
        "scan_date":             scan_date,
        "summary":               summary,
        "segments":              segment_summaries,
        "severity_descriptions": severity_descriptions,
        "severity_order":        SEVERITY_ORDER,
    }

    context_tech = {
        "scan_date":      scan_date,
        "summary":        summary,
        "segments":       segments_data,
        "severity_order": SEVERITY_ORDER,
    }

    for template_name, out_name, context in [
        ("executive.html.j2", "executive_summary.html", context_exec),
        ("technical.html.j2", "technical_report.html",  context_tech),
    ]:
        try:
            tmpl = env.get_template(template_name)
            html = tmpl.render(**context)
            out  = output_dir / out_name
            out.write_text(html, encoding="utf-8")
            logger.info(f"Report written: {out}")
        except Exception as e:
            logger.error(f"Failed to render {template_name}: {e}",
                         exc_info=True)
