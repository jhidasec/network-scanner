#!/usr/bin/env python3
"""
Network Scanner - All Stages: Host Discovery + Port Scanner + Banner Grabber
                              + Report Generator + CVE Correlator
Author: You
Purpose: Full reconnaissance pipeline from host discovery to CVE correlation
AUTHORIZED USE ONLY - Only scan networks you own or have explicit permission to scan
"""

import socket
import ipaddress
import threading
import ssl
import sys
import json
import re
import time
import urllib.request
import urllib.parse
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

# Database layer — optional, gracefully skipped if unavailable
try:
    from db import save_scan, init_db
    DB_AVAILABLE = True
except ImportError:
    DB_AVAILABLE = False

# Stage 6 — PDF report (requires: pip install reportlab)
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                     Table, TableStyle, HRFlowable,
                                     KeepTogether, PageBreak)
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# ─── STAGE 1 CONFIGURATION ────────────────────────────────────────────────────

# Multiple probe ports — host is considered alive if ANY of these respond.
#   22   — SSH, open on virtually every Linux VM by default
#   80   — HTTP, common on routers, printers, web servers, IoT devices
#   443  — HTTPS, common on modern web servers and appliances
#   445  — SMB, almost always open on Windows machines internally
PROBE_PORTS = [22, 80, 443, 445]

TIMEOUT_S1  = 0.5
MAX_THREADS = 100

live_hosts = []
lock = threading.Lock()

AUTHORIZED_NETWORKS = [
    "192.168.1.0/24",
    "192.168.0.0/24",
    "10.0.0.0/24",
    "172.16.0.0/24",
    "192.168.226.0/24",
    "192.168.200.0/24",
]

# ─── STAGE 2 CONFIGURATION ────────────────────────────────────────────────────

TIMEOUT_S2 = 1.0

COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    135:  "RPC",
    139:  "NetBIOS",
    443:  "HTTPS",
    445:  "SMB",
    993:  "IMAPS",
    995:  "POP3S",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

# ─── STAGE 3 CONFIGURATION ────────────────────────────────────────────────────

TIMEOUT_S3 = 3.0

HTTP_PORTS = {80, 8080, 8443, 443}

BINARY_PROTOCOL_PORTS = {53, 135, 139, 445, 3389}

# ─── STAGE 4 CONFIGURATION ────────────────────────────────────────────────────

REPORTS_DIR = Path.home() / "projects" / "network-scanner" / "reports"

# ─── STAGE 5 CONFIGURATION ────────────────────────────────────────────────────

NVD_API_BASE         = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_LIMIT_DELAY = 6
MAX_CVES_PER_PORT    = 5

SKIP_BANNERS = {
    "",
    "No readable banner (binary protocol)",
    "No banner (timeout waiting for response)",
    "Connected but no banner received",
    "HTTP service (no Server header)",
    "HTTPS service (no Server header)",
}

# ─── AUTHORIZATION ────────────────────────────────────────────────────────────

def is_authorized(network):
    """Check if the target network is in our authorized list."""
    return network in AUTHORIZED_NETWORKS


# ─── STAGE 1: HOST DISCOVERY ──────────────────────────────────────────────────

def probe_host(ip):
    """
    Try to connect to a single host on multiple probe ports concurrently.
    If ANY port responds (success or refused), the host is alive.

    threading.Event() acts as a flag — the first thread to find the host
    alive sets it, and all other threads check it before connecting.
    This prevents unnecessary work once we know the host is up.
    """
    found = threading.Event()

    def try_port(port):
        # If another thread already found this host alive, don't bother
        if found.is_set():
            return
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT_S1)
            result = sock.connect_ex((str(ip), port))
            sock.close()

            # 0 = connected
            # 111 = connection refused on Linux (host is up, port is closed)
            # 10061 = connection refused on Windows (same meaning)
            if result in (0, 111, 10061):
                if not found.is_set():
                    found.set()
                    with lock:
                        live_hosts.append(str(ip))
                        print(f"  [+] Host UP: {ip} (port {port} responded)")

        except socket.timeout:
            pass
        except Exception:
            pass

    # Launch one thread per probe port, all running simultaneously
    threads = []
    for port in PROBE_PORTS:
        t = threading.Thread(target=try_port, args=(port,))
        t.daemon = True
        t.start()
        threads.append(t)

    # Wait for all probe threads before moving to next host
    for t in threads:
        t.join()


def discover_hosts(network_range):
    """
    Scan all hosts in a network range using multiple threads.
    Returns the list of live host IPs — handoff to Stage 2.
    """
    print(f"\n[*] Starting host discovery on {network_range}")
    print(f"[*] Probe ports: {PROBE_PORTS} | Timeout: {TIMEOUT_S1}s | "
          f"Threads: {MAX_THREADS}\n")

    network = ipaddress.ip_network(network_range, strict=False)
    hosts   = list(network.hosts())
    print(f"[*] Scanning {len(hosts)} hosts...\n")

    threads = []
    for ip in hosts:
        while threading.active_count() > MAX_THREADS:
            pass
        t = threading.Thread(target=probe_host, args=(ip,))
        t.daemon = True
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    return live_hosts


# ─── STAGE 2: PORT SCANNER ────────────────────────────────────────────────────

def scan_port(host, port, timeout=TIMEOUT_S2):
    """
    Attempt a TCP full connect to host:port and return its state.
    Returns a tuple: (host, port, status)
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                return (host, port, "open")
            else:
                return (host, port, "closed")
    except socket.timeout:
        return (host, port, "filtered")
    except socket.error:
        return (host, port, "filtered")


def scan_host_ports(host, ports=COMMON_PORTS, timeout=TIMEOUT_S2,
                    max_workers=50):
    """
    Scan all target ports on a single host concurrently.
    Returns a dict with open/closed/filtered port lists.
    """
    results = {
        "host":      host,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "open":      [],
        "closed":    [],
        "filtered":  []
    }

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(scan_port, host, port, timeout): port
            for port in ports
        }

        for future in as_completed(future_to_port):
            try:
                _, port, status = future.result()
                service = ports[port]
                if status == "open":
                    results["open"].append((port, service))
                elif status == "closed":
                    results["closed"].append((port, service))
                else:
                    results["filtered"].append((port, service))
            except Exception as e:
                port = future_to_port[future]
                print(f"  [!] Error scanning port {port} on {host}: {e}")

    for status in ("open", "closed", "filtered"):
        results[status].sort(key=lambda x: x[0])

    return results


def run_port_scan(discovered_hosts, ports=COMMON_PORTS, host_workers=10):
    """
    Run port scans across all live hosts from Stage 1.
    Returns a dict keyed by host IP.
    """
    total       = len(discovered_hosts)
    all_results = {}

    print(f"\n[*] Starting port scan on {total} live host(s)")
    print(f"[*] Scanning {len(ports)} ports per host | Timeout: {TIMEOUT_S2}s\n")
    print("-" * 50)

    with ThreadPoolExecutor(max_workers=host_workers) as executor:
        future_to_host = {
            executor.submit(scan_host_ports, host, ports): host
            for host in discovered_hosts
        }

        completed = 0
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            try:
                result = future.result()
                all_results[host] = result
                completed += 1
                open_count = len(result["open"])
                print(f"  [{completed}/{total}] {host} — {open_count} open port(s)")
            except Exception as e:
                print(f"  [!] Failed to scan {host}: {e}")
                completed += 1

    return all_results


# ─── STAGE 3: BANNER GRABBER ──────────────────────────────────────────────────

def grab_banner(host, port, timeout=TIMEOUT_S3):
    """
    Attempt to retrieve a service banner from host:port.
    Always returns a string — never None, never raises.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))

            # HTTPS — requires TLS wrap before sending
            if port in (443, 8443):
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with context.wrap_socket(sock,
                                         server_hostname=host) as tls_sock:
                    tls_sock.send(b"HEAD / HTTP/1.0\r\nHost: " +
                                  host.encode() + b"\r\n\r\n")
                    response = tls_sock.recv(1024).decode("utf-8",
                                                          errors="ignore")
                for line in response.split("\r\n"):
                    if line.lower().startswith("server:"):
                        return line.strip()
                first_line = response.split("\r\n")[0].strip()
                return first_line if first_line else \
                    "HTTPS service (no Server header)"

            # Plain HTTP — send HEAD request to trigger response
            elif port in HTTP_PORTS:
                sock.send(b"HEAD / HTTP/1.0\r\nHost: " +
                          host.encode() + b"\r\n\r\n")
                response = sock.recv(1024).decode("utf-8", errors="ignore")
                for line in response.split("\r\n"):
                    if line.lower().startswith("server:"):
                        return line.strip()
                first_line = response.split("\r\n")[0].strip()
                return first_line if first_line else \
                    "HTTP service (no Server header)"

            # Binary protocol ports — quick recv, no waiting
            elif port in BINARY_PROTOCOL_PORTS:
                sock.settimeout(1.0)
                try:
                    banner_bytes = sock.recv(1024)
                    if banner_bytes:
                        return "No readable banner (binary protocol)"
                except socket.timeout:
                    pass
                return "No readable banner (binary protocol)"

            # Passive ports — service speaks first (SSH, FTP, SMTP etc.)
            else:
                banner_bytes = sock.recv(1024)
                banner = banner_bytes.decode("utf-8",
                                             errors="replace").strip()
                if not banner:
                    return "Connected but no banner received"
                non_printable = sum(1 for c in banner
                                    if not c.isprintable() or c == "?")
                if len(banner) > 0 and non_printable / len(banner) > 0.3:
                    return "No readable banner (binary protocol)"
                return banner.split("\n")[0].strip()

    except socket.timeout:
        return "No banner (timeout waiting for response)"
    except ConnectionRefusedError:
        return "Connection refused (port closed since scan)"
    except ssl.SSLError as e:
        return f"TLS error: {str(e)[:50]}"
    except Exception as e:
        return f"Error: {str(e)[:50]}"


def grab_host_banners(host, open_ports, timeout=TIMEOUT_S3):
    """Grab banners from all open ports on a single host."""
    banners = {}
    for port, service in open_ports:
        print(f"  [~] Grabbing banner: {host}:{port} ({service})")
        banner = grab_banner(host, port, timeout)
        banners[port] = banner
        print(f"  [+] {host}:{port} → {banner}")
    return banners


def run_banner_grab(port_scan_results, timeout=TIMEOUT_S3):
    """Run banner grabbing across all hosts from Stage 2 results."""
    print("\n[*] Starting banner grabbing")
    print("-" * 50)

    for host, data in sorted(port_scan_results.items()):
        open_ports = data.get("open", [])
        if not open_ports:
            print(f"  [-] {host} — no open ports to grab banners from")
            data["banners"] = {}
            continue
        print(f"\n  [*] {host} — grabbing {len(open_ports)} banner(s)")
        data["banners"] = grab_host_banners(host, open_ports, timeout)

    return port_scan_results


# ─── STAGE 5: CVE CORRELATOR ──────────────────────────────────────────────────

def parse_banner_to_query(banner, service):
    """
    Extract a clean software name + version from a raw banner string.
    Returns a search string like 'OpenSSH 10.2p1' or None.
    """
    if not banner or banner in SKIP_BANNERS:
        return None

    if "OpenSSH" in banner:
        match = re.search(r"OpenSSH[_\s]([\d]+\.[\d]+(?:p[\d]+)?)", banner)
        if match:
            return f"OpenSSH {match.group(1)}"

    if "Apache" in banner:
        match = re.search(r"Apache/([\d]+\.[\d]+\.?[\d]*)", banner)
        if match:
            return f"Apache HTTP Server {match.group(1)}"

    if "nginx" in banner:
        match = re.search(r"nginx/([\d]+\.[\d]+\.?[\d]*)", banner)
        if match:
            return f"nginx {match.group(1)}"

    if "IIS" in banner or "Microsoft-IIS" in banner:
        match = re.search(r"IIS/([\d]+\.[\d]+)", banner)
        if match:
            return f"Microsoft IIS {match.group(1)}"

    if service == "FTP":
        for product in ["FileZilla", "ProFTPD", "vsftpd", "Pure-FTPd"]:
            if product in banner:
                match = re.search(
                    rf"{product}[_\s/]*([\d]+\.[\d]+\.?[\d]*)", banner)
                if match:
                    return f"{product} {match.group(1)}"

    if service == "SMTP":
        for product in ["Postfix", "Sendmail", "Exim", "Exchange"]:
            if product in banner:
                return product

    match = re.search(
        r"([A-Za-z][A-Za-z0-9\-]+)[/\s_]([\d]+\.[\d]+\.?[\d]*)", banner)
    if match:
        return f"{match.group(1)} {match.group(2)}"

    return None


def query_nvd(search_term):
    """
    Query the NVD API for CVEs matching a search term.
    Returns a list of CVE dicts sorted by score descending.
    """
    params = urllib.parse.urlencode({
        "keywordSearch":  search_term,
        "resultsPerPage": MAX_CVES_PER_PORT
    })
    url = f"{NVD_API_BASE}?{params}"

    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            raw  = response.read().decode("utf-8")
            data = json.loads(raw)

    except urllib.error.HTTPError as e:
        if e.code == 403:
            print(f"    [!] NVD rate limit hit — waiting 30 seconds")
            time.sleep(30)
            return query_nvd(search_term)
        print(f"    [!] NVD HTTP error {e.code} for '{search_term}'")
        return []
    except urllib.error.URLError as e:
        print(f"    [!] Cannot reach NVD API: {e.reason}")
        return []
    except json.JSONDecodeError:
        print(f"    [!] Invalid JSON from NVD for '{search_term}'")
        return []

    cves = []
    for vuln in data.get("vulnerabilities", []):
        cve_data    = vuln.get("cve", {})
        cve_id      = cve_data.get("id", "Unknown")
        descriptions = cve_data.get("descriptions", [])
        description  = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available"
        )
        if len(description) > 200:
            description = description[:197] + "..."

        score    = None
        severity = "Unknown"
        metrics  = cve_data.get("metrics", {})

        for cvss_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if cvss_key in metrics and metrics[cvss_key]:
                cvss_data = metrics[cvss_key][0]
                score     = cvss_data.get("cvssData", {}).get("baseScore")
                severity  = cvss_data.get("cvssData", {}).get(
                    "baseSeverity",
                    cvss_data.get("baseSeverity", "Unknown")
                )
                break

        cves.append({
            "id":          cve_id,
            "description": description,
            "severity":    severity.capitalize() if severity else "Unknown",
            "score":       score if score is not None else 0.0,
            "url":         f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        })

    cves.sort(key=lambda x: x["score"], reverse=True)
    return cves


def correlate_host_cves(host, data):
    """Run CVE lookups for all open ports on a single host."""
    open_ports = data.get("open", [])
    banners    = data.get("banners", {})
    cve_map    = {}

    for i, (port, service) in enumerate(open_ports):
        banner = banners.get(port, "")
        query  = parse_banner_to_query(banner, service)

        if not query:
            print(f"    [-] {host}:{port} ({service}) — "
                  f"no parseable version, skipping")
            cve_map[port] = []
            continue

        print(f"    [~] {host}:{port} ({service}) — "
              f"searching NVD for '{query}'")
        cves        = query_nvd(query)
        cve_map[port] = cves

        if cves:
            top = cves[0]
            print(f"    [+] Found {len(cves)} CVE(s) — "
                  f"Top: {top['id']} "
                  f"(CVSS {top['score']} {top['severity']})")
        else:
            print(f"    [-] No CVEs found for '{query}'")

        if i < len(open_ports) - 1:
            time.sleep(NVD_RATE_LIMIT_DELAY)

    return cve_map


def run_cve_correlation(enriched_results):
    """Run CVE correlation across all hosts. Adds 'cves' key to each host."""
    print("\n[*] Starting CVE correlation")
    print("[*] Querying NVD API — this will take a moment (rate limited)")
    print("-" * 50)

    for host, data in sorted(enriched_results.items()):
        open_ports = data.get("open", [])
        if not open_ports:
            data["cves"] = {}
            continue
        print(f"\n  [*] {host} — correlating {len(open_ports)} port(s)")
        data["cves"] = correlate_host_cves(host, data)

    return enriched_results


def print_cve_results(enriched_results):
    """Display CVE correlation results in the terminal."""
    print("\n" + "=" * 60)
    print("  CVE CORRELATION RESULTS")
    print("=" * 60)

    for host, data in sorted(enriched_results.items(),
                              key=lambda x: ipaddress.ip_address(x[0])):
        print(f"\n  Host: {host}")
        print("  " + "-" * 40)

        cve_map    = data.get("cves", {})
        open_ports = data.get("open", [])

        if not open_ports:
            print("  No open ports scanned")
            continue

        found_any = False
        for port, service in open_ports:
            cves = cve_map.get(port, [])
            if cves:
                found_any = True
                print(f"\n  Port {port} ({service}):")
                for cve in cves:
                    score = cve['score']
                    if score >= 9.0:
                        indicator = "[CRITICAL]"
                    elif score >= 7.0:
                        indicator = "[HIGH]    "
                    elif score >= 4.0:
                        indicator = "[MEDIUM]  "
                    else:
                        indicator = "[LOW]     "
                    print(f"    {indicator} {cve['id']} "
                          f"(CVSS {score}) — "
                          f"{cve['description'][:80]}...")

        if not found_any:
            print("  No CVEs found for any open ports")

    print("\n" + "=" * 60 + "\n")


# ─── STAGE 4: REPORT GENERATOR ────────────────────────────────────────────────

def prepare_report_data(enriched_results, network_range):
    """Convert enriched_results into a clean JSON-serializable structure."""
    report = {
        "metadata": {
            "tool":        "Network Scanner v0.5",
            "network":     network_range,
            "scan_date":   datetime.now().strftime("%Y-%m-%d"),
            "scan_time":   datetime.now().strftime("%H:%M:%S"),
            "total_hosts": len(enriched_results),
        },
        "hosts": {}
    }

    total_open = 0

    for host, data in enriched_results.items():
        open_ports     = data.get("open", [])
        filtered_ports = data.get("filtered", [])
        banners        = data.get("banners", {})
        cves           = data.get("cves", {})
        total_open    += len(open_ports)

        report["hosts"][host] = {
            "scan_time": data.get("scan_time", ""),
            "open_ports": [
                {
                    "port":    port,
                    "service": service,
                    "banner":  banners.get(port, ""),
                    "cves":    cves.get(port, [])
                }
                for port, service in open_ports
            ],
            "filtered_ports": [
                {"port": port, "service": service}
                for port, service in filtered_ports
            ],
            "summary": {
                "open_count":     len(open_ports),
                "filtered_count": len(filtered_ports),
            }
        }

    report["metadata"]["total_open_ports"] = total_open
    return report


def generate_json_report(report_data):
    """Write the report dict to a timestamped JSON file."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = REPORTS_DIR / f"scan_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(report_data, f, indent=4)
    print(f"  [+] JSON report saved: {filename}")
    return filename


def generate_html_report(report_data):
    """Generate a styled HTML report from the scan data."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = REPORTS_DIR / f"scan_{timestamp}.html"

    meta  = report_data["metadata"]
    hosts = report_data["hosts"]

    host_cards = ""

    for host, data in sorted(hosts.items(),
                              key=lambda x: ipaddress.ip_address(x[0])):
        open_ports     = data["open_ports"]
        filtered_ports = data["filtered_ports"]

        # ── Open ports table ──────────────────────────────────────────────
        if open_ports:
            port_rows = ""

            for p in open_ports:
                banner_text  = p["banner"] if p["banner"] else "—"
                banner_class = "banner-text" if p["banner"] else "no-banner"

                # Build CVE rows if any exist for this port
                cves     = p.get("cves", [])
                cve_html = ""
                if cves:
                    cve_items = ""
                    for cve in cves:
                        score = cve["score"]
                        if score >= 9.0:
                            badge_class = "sev-critical"
                        elif score >= 7.0:
                            badge_class = "sev-high"
                        elif score >= 4.0:
                            badge_class = "sev-medium"
                        else:
                            badge_class = "sev-low"
                        cve_items += f"""
                        <div class="cve-item">
                            <a href="{cve['url']}" class="cve-id"
                               target="_blank">{cve['id']}</a>
                            <span class="cve-badge {badge_class}">
                                CVSS {cve['score']}
                            </span>
                            <span class="cve-desc">{cve['description']}</span>
                        </div>"""
                    cve_html = (f'<div class="cve-list">'
                                f'{cve_items}</div>')

                cve_row = (
                    f"<tr><td colspan='3'>{cve_html}</td></tr>"
                    if cve_html else ""
                )

                port_rows += f"""
                <tr>
                    <td class="port-num">{p['port']}</td>
                    <td class="service">{p['service']}</td>
                    <td class="{banner_class}">{banner_text}</td>
                </tr>{cve_row}"""

            open_table = f"""
            <table class="port-table">
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Banner</th>
                    </tr>
                </thead>
                <tbody>{port_rows}
                </tbody>
            </table>"""

        else:
            open_table = '<p class="no-findings">No open ports found</p>'

        # ── Filtered ports ────────────────────────────────────────────────
        if filtered_ports:
            filtered_list = ", ".join(
                f"{p['port']} ({p['service']})" for p in filtered_ports
            )
            filtered_section = (f'<p class="filtered-list">'
                                 f'Filtered: {filtered_list}</p>')
        else:
            filtered_section = ""

        # ── Risk badge ────────────────────────────────────────────────────
        dangerous      = {21, 23, 445, 3389, 5900}
        open_port_nums = {p["port"] for p in open_ports}
        has_dangerous  = bool(dangerous & open_port_nums)

        risk_class = ("risk-high"   if has_dangerous else
                      "risk-medium" if open_ports else "risk-low")
        risk_label = ("Review Recommended" if has_dangerous else
                      "Open Ports Present" if open_ports else
                      "Minimal Exposure")

        host_cards += f"""
        <div class="host-card">
            <div class="host-header">
                <div class="host-ip">{host}</div>
                <div class="host-meta">Scanned: {data['scan_time']}</div>
                <div class="risk-badge {risk_class}">{risk_label}</div>
            </div>
            <div class="host-body">
                <div class="section-label">Open Ports
                    <span class="count-badge">
                        {data['summary']['open_count']}
                    </span>
                </div>
                {open_table}
                {filtered_section}
            </div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Scan Report — {meta['network']}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: #0d1117; color: #e6edf3;
            padding: 2rem; line-height: 1.6;
        }}
        .report-header {{
            border-bottom: 1px solid #30363d;
            padding-bottom: 1.5rem; margin-bottom: 2rem;
        }}
        .report-title {{
            font-size: 1.8rem; font-weight: 600;
            color: #58a6ff; margin-bottom: 0.5rem;
        }}
        .report-meta {{
            display: flex; gap: 2rem; color: #8b949e;
            font-size: 0.9rem; flex-wrap: wrap;
        }}
        .meta-item span {{ color: #e6edf3; font-weight: 500; }}
        .summary-bar {{
            display: flex; gap: 1rem;
            margin-bottom: 2rem; flex-wrap: wrap;
        }}
        .summary-stat {{
            background: #161b22; border: 1px solid #30363d;
            border-radius: 8px; padding: 1rem 1.5rem;
            text-align: center; min-width: 140px;
        }}
        .summary-stat .number {{
            font-size: 2rem; font-weight: 700; color: #58a6ff;
        }}
        .summary-stat .label {{
            font-size: 0.8rem; color: #8b949e;
            text-transform: uppercase; letter-spacing: 0.05em;
        }}
        .host-card {{
            background: #161b22; border: 1px solid #30363d;
            border-radius: 10px; margin-bottom: 1.5rem;
            overflow: hidden;
        }}
        .host-header {{
            background: #1c2128; padding: 1rem 1.5rem;
            display: flex; align-items: center; gap: 1rem;
            flex-wrap: wrap; border-bottom: 1px solid #30363d;
        }}
        .host-ip {{
            font-size: 1.1rem; font-weight: 600;
            color: #58a6ff; font-family: monospace;
        }}
        .host-meta {{ color: #8b949e; font-size: 0.85rem; flex: 1; }}
        .risk-badge {{
            padding: 0.25rem 0.75rem; border-radius: 20px;
            font-size: 0.8rem; font-weight: 600;
        }}
        .risk-high {{
            background: #3d1a1a; color: #f85149;
            border: 1px solid #f85149;
        }}
        .risk-medium {{
            background: #1a2d1a; color: #3fb950;
            border: 1px solid #3fb950;
        }}
        .risk-low {{
            background: #1a1a2d; color: #8b949e;
            border: 1px solid #30363d;
        }}
        .host-body {{ padding: 1.5rem; }}
        .section-label {{
            font-size: 0.8rem; text-transform: uppercase;
            letter-spacing: 0.08em; color: #8b949e;
            margin-bottom: 0.75rem;
            display: flex; align-items: center; gap: 0.5rem;
        }}
        .count-badge {{
            background: #21262d; border: 1px solid #30363d;
            border-radius: 10px; padding: 0.1rem 0.5rem;
            font-size: 0.75rem; color: #58a6ff;
        }}
        .port-table {{
            width: 100%; border-collapse: collapse;
            font-size: 0.9rem; margin-bottom: 1rem;
        }}
        .port-table th {{
            text-align: left; padding: 0.5rem 1rem;
            background: #21262d; color: #8b949e;
            font-size: 0.8rem; text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .port-table td {{
            padding: 0.6rem 1rem;
            border-bottom: 1px solid #21262d;
        }}
        .port-table tr:last-child td {{ border-bottom: none; }}
        .port-table tr:hover td {{ background: #1c2128; }}
        .port-num {{
            font-family: monospace; color: #58a6ff; width: 80px;
        }}
        .service   {{ color: #e6edf3; width: 120px; }}
        .banner-text {{
            font-family: monospace; color: #3fb950; font-size: 0.85rem;
        }}
        .no-banner {{ color: #484f58; font-style: italic; }}
        .filtered-list {{
            font-size: 0.82rem; color: #8b949e; margin-top: 0.5rem;
        }}
        .no-findings {{
            color: #484f58; font-style: italic; font-size: 0.9rem;
        }}
        .cve-list {{
            padding: 0.5rem 1rem 0.75rem 1rem;
            background: #0d1117; border-top: 1px solid #21262d;
        }}
        .cve-item {{
            display: flex; align-items: flex-start;
            gap: 0.5rem; padding: 0.35rem 0;
            border-bottom: 1px solid #161b22; flex-wrap: wrap;
        }}
        .cve-item:last-child {{ border-bottom: none; }}
        .cve-id {{
            font-family: monospace; font-size: 0.82rem;
            color: #58a6ff; text-decoration: none;
            white-space: nowrap; min-width: 160px;
        }}
        .cve-id:hover {{ text-decoration: underline; }}
        .cve-badge {{
            padding: 0.1rem 0.5rem; border-radius: 10px;
            font-size: 0.75rem; font-weight: 600; white-space: nowrap;
        }}
        .sev-critical {{ background: #3d1a1a; color: #f85149; }}
        .sev-high     {{ background: #2d1f0e; color: #d29922; }}
        .sev-medium   {{ background: #1a2d1a; color: #3fb950; }}
        .sev-low      {{ background: #1a1a2d; color: #8b949e; }}
        .cve-desc {{
            font-size: 0.82rem; color: #8b949e; line-height: 1.4;
        }}
        .footer {{
            margin-top: 3rem; padding-top: 1rem;
            border-top: 1px solid #30363d;
            color: #484f58; font-size: 0.8rem; text-align: center;
        }}
    </style>
</head>
<body>
    <div class="report-header">
        <div class="report-title">Network Scan Report</div>
        <div class="report-meta">
            <div class="meta-item">
                Target: <span>{meta['network']}</span>
            </div>
            <div class="meta-item">
                Date: <span>{meta['scan_date']}</span>
            </div>
            <div class="meta-item">
                Time: <span>{meta['scan_time']}</span>
            </div>
            <div class="meta-item">
                Tool: <span>{meta['tool']}</span>
            </div>
        </div>
    </div>
    <div class="summary-bar">
        <div class="summary-stat">
            <div class="number">{meta['total_hosts']}</div>
            <div class="label">Hosts Found</div>
        </div>
        <div class="summary-stat">
            <div class="number">{meta['total_open_ports']}</div>
            <div class="label">Open Ports</div>
        </div>
    </div>
    {host_cards}
    <div class="footer">
        Generated by Network Scanner v0.5 — AUTHORIZED USE ONLY
    </div>
</body>
</html>"""

    with open(filename, "w") as f:
        f.write(html)

    print(f"  [+] HTML report saved: {filename}")
    return filename


# ─── STAGE 6: CLIENT PDF REPORT ──────────────────────────────────────────────

# Risk scoring helpers
DANGEROUS_PORTS = {
    21:   ("FTP",    "Unencrypted file transfer — credentials sent in plaintext."),
    23:   ("Telnet", "Unencrypted remote access — highly dangerous, replace with SSH."),
    445:  ("SMB",    "Windows file sharing — common ransomware entry point."),
    3389: ("RDP",    "Remote Desktop — brute-force target, should not be internet-facing."),
    5900: ("VNC",    "Remote desktop — often misconfigured and exposed without auth."),
    1433: ("MSSQL",  "Database port exposed — should never be internet-facing."),
    3306: ("MySQL",  "Database port exposed — should never be internet-facing."),
}

RECOMMENDATIONS = {
    21:   "Disable FTP. Use SFTP or SCP instead. If FTP is required, restrict to internal network only.",
    23:   "Disable Telnet immediately. Replace with SSH (port 22) for all remote access.",
    445:  "Restrict SMB to internal network only. Ensure Windows is fully patched (EternalBlue/MS17-010).",
    3389: "Place RDP behind a VPN. Enable Network Level Authentication. Consider disabling if not needed.",
    5900: "Disable VNC or place behind VPN. Ensure strong password is set if VNC must remain active.",
    1433: "Firewall MSSQL port from external access. Use encrypted connections and strong sa password.",
    3306: "Firewall MySQL port from external access. Use strong credentials and bind to localhost.",
    22:   "Ensure SSH uses key-based authentication. Disable root login. Consider non-standard port.",
    80:   "Redirect HTTP to HTTPS. Ensure web server software is fully patched.",
    8080: "Non-standard HTTP port — verify this service is intentional and patch web server software.",
    8443: "Verify this HTTPS service is intentional and using a valid certificate.",
    25:   "Ensure SMTP relay is restricted. Open relays are exploited for spam campaigns.",
}

def _score_host(open_ports):
    """
    Calculate a simple risk score for a host based on its open ports.
    Returns (score 0-100, label, color_hex).
    Score weights: dangerous ports = 25pts each (cap 75), any open port = 10pts base.
    CVEs found add additional weight.
    """
    if not open_ports:
        return 5, "Minimal", "#3fb950"
    score = 10  # base for having any open ports
    port_nums = {p["port"] for p in open_ports}
    dangerous_found = port_nums & set(DANGEROUS_PORTS.keys())
    score += min(len(dangerous_found) * 25, 75)
    # CVEs bump the score
    for p in open_ports:
        for cve in p.get("cves", []):
            if cve["score"] >= 9.0:
                score = min(score + 20, 100)
            elif cve["score"] >= 7.0:
                score = min(score + 10, 100)
    score = min(score, 100)
    if score >= 70:
        return score, "High Risk", "#f85149"
    elif score >= 40:
        return score, "Medium Risk", "#d29922"
    else:
        return score, "Low Risk", "#3fb950"


def _pdf_styles():
    """Return a dict of named ParagraphStyles for the PDF report."""
    N = colors.HexColor("#0f1f38")   # navy
    A = colors.HexColor("#2d7dd2")   # accent blue
    G = colors.HexColor("#c9a84c")   # gold
    W = colors.white
    T = colors.HexColor("#1a1a2e")   # dark text
    M = colors.HexColor("#5a6a82")   # muted

    def S(name, **kw):
        return ParagraphStyle(name, **kw)

    return {
        "h1":      S("h1",  fontSize=20, textColor=N,  fontName="Helvetica-Bold",
                     leading=26, spaceBefore=18, spaceAfter=6),
        "h2":      S("h2",  fontSize=13, textColor=A,  fontName="Helvetica-Bold",
                     leading=17, spaceBefore=14, spaceAfter=5),
        "h3":      S("h3",  fontSize=11, textColor=N,  fontName="Helvetica-Bold",
                     leading=15, spaceBefore=10, spaceAfter=4),
        "body":    S("body",fontSize=10, textColor=T,  fontName="Helvetica",
                     leading=15, spaceBefore=3,  spaceAfter=3),
        "muted":   S("muted",fontSize=9, textColor=M,  fontName="Helvetica",
                     leading=13, spaceBefore=2,  spaceAfter=2),
        "mono":    S("mono",fontSize=9,  textColor=colors.HexColor("#2d7dd2"),
                     fontName="Courier", leading=13),
        "white_bold": S("wb",fontSize=10,textColor=W,  fontName="Helvetica-Bold",
                        leading=14, alignment=TA_CENTER),
        "white_sm":   S("ws",fontSize=8, textColor=colors.HexColor("#c8d8ea"),
                        fontName="Helvetica", leading=12, alignment=TA_CENTER),
        "th":      S("th",  fontSize=9,  textColor=W,  fontName="Helvetica-Bold",
                     leading=13, alignment=TA_LEFT),
        "td":      S("td",  fontSize=9,  textColor=T,  fontName="Helvetica",
                     leading=13),
        "td_mono": S("tdm", fontSize=9,  textColor=colors.HexColor("#2d7dd2"),
                     fontName="Courier", leading=13),
        "rec":     S("rec", fontSize=9,  textColor=colors.HexColor("#1a1a2e"),
                     fontName="Helvetica", leading=13, leftIndent=8),
        "cover_title": S("ct", fontSize=38, textColor=W, fontName="Helvetica-Bold",
                         leading=44, alignment=TA_LEFT),
        "cover_sub":   S("cs", fontSize=14, textColor=G, fontName="Helvetica",
                         leading=20, alignment=TA_LEFT),
        "cover_body":  S("cb", fontSize=10,
                         textColor=colors.HexColor("#c8d8ea"),
                         fontName="Helvetica", leading=16, alignment=TA_LEFT),
        "disclaimer":  S("disc", fontSize=8, textColor=M, fontName="Helvetica-Oblique",
                         leading=12, alignment=TA_CENTER),
    }


def _header_footer(canvas, doc):
    """Page header and footer drawn on every page after the cover."""
    if doc.page == 1:
        _draw_cover_bg(canvas)
        return
    canvas.saveState()
    w, h = letter
    NAVY  = colors.HexColor("#0f1f38")
    ACCENT= colors.HexColor("#2d7dd2")
    GOLD  = colors.HexColor("#c9a84c")
    WHITE = colors.white

    # Header bar
    canvas.setFillColor(NAVY)
    canvas.rect(0, h - 32, w, 32, fill=1, stroke=0)
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawString(0.5*inch, h - 21, "NETWORK SECURITY AUDIT REPORT")
    canvas.setFont("Helvetica", 8)
    target = getattr(doc, "_scan_target", "")
    canvas.drawRightString(w - 0.5*inch, h - 21,
                           f"Target: {target}  |  CONFIDENTIAL")

    # Footer
    canvas.setFillColor(NAVY)
    canvas.rect(0, 0, w, 24, fill=1, stroke=0)
    canvas.setFillColor(GOLD)
    canvas.rect(0, 0, w * 0.35, 3, fill=1, stroke=0)
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica", 7)
    canvas.drawString(0.5*inch, 8,
                      "Generated by Network Scanner v0.5  |  AUTHORIZED USE ONLY")
    canvas.setFont("Helvetica-Bold", 7)
    canvas.drawRightString(w - 0.5*inch, 8, f"Page {doc.page}")
    canvas.restoreState()


def _draw_cover_bg(canvas):
    """Draw the dark cover page background."""
    w, h = letter
    NAVY  = colors.HexColor("#0f1f38")
    BLUE  = colors.HexColor("#1a3a6b")
    GOLD  = colors.HexColor("#c9a84c")
    ACCENT= colors.HexColor("#2d7dd2")
    canvas.saveState()
    canvas.setFillColor(NAVY)
    canvas.rect(0, 0, w, h, fill=1, stroke=0)
    # Decorative circles
    canvas.setFillColor(BLUE)
    canvas.circle(w - 0.8*inch, h - 0.8*inch, 2.4*inch, fill=1, stroke=0)
    canvas.setFillColor(colors.HexColor("#0d1a2e"))
    canvas.circle(w - 0.3*inch, h - 0.3*inch, 1.4*inch, fill=1, stroke=0)
    # Accent lines
    canvas.setFillColor(GOLD)
    canvas.rect(0.5*inch, 1.6*inch, 0.05*inch, 5*inch, fill=1, stroke=0)
    canvas.setFillColor(ACCENT)
    canvas.rect(0, 0.5*inch, w * 0.5, 0.03*inch, fill=1, stroke=0)
    canvas.setFillColor(GOLD)
    canvas.rect(0, 0.5*inch, w * 0.2, 0.03*inch, fill=1, stroke=0)
    # Footer strip
    canvas.setFillColor(colors.HexColor("#0a1628"))
    canvas.rect(0, 0, w, 0.5*inch, fill=1, stroke=0)
    canvas.setFillColor(colors.HexColor("#8899aa"))
    canvas.setFont("Helvetica", 7)
    canvas.drawString(0.5*inch, 0.18*inch,
                      "AUTHORIZED USE ONLY  |  Confidential")
    canvas.restoreState()


def generate_pdf_report(report_data, consultant_name="Your Name",
                        consultant_contact="your@email.com"):
    """
    Stage 6: Generate a client-facing PDF audit report from report_data.
    report_data is the dict produced by prepare_report_data().
    Returns the Path of the saved PDF file.
    """
    if not REPORTLAB_AVAILABLE:
        print("  [!] reportlab not installed — skipping PDF report.")
        print("  [!] Install with: pip install reportlab")
        return None

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = REPORTS_DIR / f"audit_report_{timestamp}.pdf"

    meta  = report_data["metadata"]
    hosts = report_data["hosts"]
    ST    = _pdf_styles()

    NAVY   = colors.HexColor("#0f1f38")
    ACCENT = colors.HexColor("#2d7dd2")
    GOLD   = colors.HexColor("#c9a84c")
    RED    = colors.HexColor("#f85149")
    YELLOW = colors.HexColor("#d29922")
    GREEN  = colors.HexColor("#3fb950")
    WHITE  = colors.white
    LIGHT  = colors.HexColor("#e8f1fb")
    BORDER = colors.HexColor("#d0dce9")
    BG_ROW = colors.HexColor("#f4f7fc")

    doc = SimpleDocTemplate(
        str(filename), pagesize=letter,
        leftMargin=0.65*inch, rightMargin=0.65*inch,
        topMargin=0.55*inch,  bottomMargin=0.45*inch,
    )
    doc._scan_target = meta.get("network", "")

    story = []

    # ── COVER ──────────────────────────────────────────────────────────────
    story.append(Spacer(1, 1.5*inch))
    story.append(Paragraph("Network Security", ST["cover_sub"]))
    story.append(Paragraph("Audit Report", ST["cover_title"]))
    story.append(Spacer(1, 0.15*inch))
    story.append(Paragraph(f"Target Network: {meta['network']}", ST["cover_sub"]))
    story.append(Spacer(1, 0.25*inch))
    story.append(HRFlowable(width="100%", thickness=0.8,
                             color=colors.HexColor("#2d4a6b"), spaceAfter=16))
    story.append(Paragraph(
        f"Scan Date: {meta['scan_date']}  &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"Hosts Assessed: {meta['total_hosts']}  &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"Open Ports Found: {meta['total_open_ports']}",
        ST["cover_body"]))
    story.append(Spacer(1, 0.5*inch))

    # Cover stat cards
    all_open = []
    for h_data in hosts.values():
        all_open.extend(h_data.get("open_ports", []))
    all_cves = [c for p in all_open for c in p.get("cves", [])]
    critical_cves = sum(1 for c in all_cves if c["score"] >= 9.0)
    high_cves     = sum(1 for c in all_cves if 7.0 <= c["score"] < 9.0)
    dangerous_exposed = sum(
        1 for h in hosts.values()
        for p in h.get("open_ports", [])
        if p["port"] in DANGEROUS_PORTS
    )

    def stat_cell(val, label):
        return [Paragraph(str(val), ST["white_bold"]),
                Paragraph(label,    ST["white_sm"])]

    stat_data = [[stat_cell(meta["total_hosts"],  "Hosts\nFound"),
                  stat_cell(meta["total_open_ports"], "Open\nPorts"),
                  stat_cell(dangerous_exposed,    "Dangerous\nServices"),
                  stat_cell(len(all_cves),        "CVEs\nFound"),
                  stat_cell(critical_cves,        "Critical\nCVEs")]]

    stat_table = Table(stat_data,
                       colWidths=[1.36*inch]*5)
    stat_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,-1), colors.HexColor("#1a3a6b")),
        ("TOPPADDING",    (0,0),(-1,-1), 12),
        ("BOTTOMPADDING", (0,0),(-1,-1), 10),
        ("LINEAFTER",     (0,0),(3,-1),  0.5, colors.HexColor("#2d5080")),
        ("BOX",           (0,0),(-1,-1), 0.5, colors.HexColor("#2d5080")),
        ("BACKGROUND",    (4,0),(4,-1),
         colors.HexColor("#3d1a1a") if critical_cves > 0
         else colors.HexColor("#1a3a6b")),
        ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
    ]))
    story.append(stat_table)
    story.append(Spacer(1, 0.35*inch))
    story.append(Paragraph(
        f"Prepared by: {consultant_name}  &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"{consultant_contact}",
        ST["cover_body"]))
    story.append(PageBreak())

    # ── EXECUTIVE SUMMARY ──────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", ST["h1"]))
    story.append(HRFlowable(width="100%", thickness=1.5,
                             color=ACCENT, spaceAfter=8))

    # Overall risk determination
    high_risk_hosts   = []
    medium_risk_hosts = []
    for ip, h_data in hosts.items():
        score, label, _ = _score_host(h_data.get("open_ports", []))
        if label == "High Risk":
            high_risk_hosts.append(ip)
        elif label == "Medium Risk":
            medium_risk_hosts.append(ip)

    if high_risk_hosts:
        overall = "HIGH"
        overall_color = RED
        summary_text = (
            f"This assessment identified <b>{len(high_risk_hosts)} high-risk "
            f"host(s)</b> on the {meta['network']} network. Dangerous services "
            f"are exposed that could allow an attacker to gain unauthorized access, "
            f"exfiltrate data, or deploy ransomware. Immediate action is recommended "
            f"on the findings marked Critical and High in this report."
        )
    elif medium_risk_hosts:
        overall = "MEDIUM"
        overall_color = YELLOW
        summary_text = (
            f"This assessment identified {meta['total_hosts']} host(s) on the "
            f"{meta['network']} network with open ports requiring review. No "
            f"critically dangerous services were detected, but several findings "
            f"increase the attack surface and should be addressed within 30 days."
        )
    else:
        overall = "LOW"
        overall_color = GREEN
        summary_text = (
            f"This assessment found {meta['total_hosts']} host(s) on the "
            f"{meta['network']} network. No high-risk services were detected. "
            f"The network presents a minimal external attack surface based on "
            f"the ports and services observed during this scan."
        )

    risk_row = [[
        Paragraph("OVERALL RISK RATING", ST["white_bold"]),
        Paragraph(overall, ParagraphStyle(
            "risk_val", fontSize=22, textColor=overall_color,
            fontName="Helvetica-Bold", leading=26, alignment=TA_CENTER)),
    ]]
    risk_t = Table(risk_row, colWidths=[2.5*inch, 4.7*inch])
    risk_t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(0,-1), NAVY),
        ("BACKGROUND",    (1,0),(1,-1), colors.HexColor("#1c2535")),
        ("TOPPADDING",    (0,0),(-1,-1), 14),
        ("BOTTOMPADDING", (0,0),(-1,-1), 14),
        ("LEFTPADDING",   (0,0),(-1,-1), 14),
        ("BOX",           (0,0),(-1,-1), 0.5, BORDER),
        ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
    ]))
    story.append(risk_t)
    story.append(Spacer(1, 0.12*inch))
    story.append(Paragraph(summary_text, ST["body"]))
    story.append(Spacer(1, 0.18*inch))

    # Key findings bullets
    story.append(Paragraph("Key Findings", ST["h2"]))
    if dangerous_exposed > 0:
        story.append(Paragraph(
            f"&#8226; <b>{dangerous_exposed} dangerous service(s)</b> detected "
            f"(FTP, Telnet, RDP, SMB, VNC, or exposed databases). "
            f"These are the highest-priority items to address.", ST["body"]))
    if len(all_cves) > 0:
        story.append(Paragraph(
            f"&#8226; <b>{len(all_cves)} CVE(s)</b> correlated across open services "
            f"({critical_cves} Critical, {high_cves} High). "
            f"Review CVE details in the findings section.", ST["body"]))
    if meta["total_open_ports"] > 0:
        story.append(Paragraph(
            f"&#8226; <b>{meta['total_open_ports']} open port(s)</b> found across "
            f"{meta['total_hosts']} host(s). Each open port is a potential entry "
            f"point — close or restrict any that are not actively needed.",
            ST["body"]))

    # Remediation priority box
    story.append(Spacer(1, 0.1*inch))
    prio_data = [[
        Paragraph("Priority", ST["th"]),
        Paragraph("Action", ST["th"]),
        Paragraph("Timeframe", ST["th"]),
    ]]
    if high_risk_hosts:
        prio_data.append([
            Paragraph("CRITICAL", ParagraphStyle("crit", fontSize=9,
                textColor=RED, fontName="Helvetica-Bold", leading=13)),
            Paragraph("Restrict or disable dangerous services on high-risk hosts", ST["td"]),
            Paragraph("24–48 hours", ST["td"]),
        ])
    if len(all_cves) > 0:
        prio_data.append([
            Paragraph("HIGH", ParagraphStyle("high", fontSize=9,
                textColor=YELLOW, fontName="Helvetica-Bold", leading=13)),
            Paragraph("Patch software with known CVEs — prioritize Critical/High scores", ST["td"]),
            Paragraph("1–2 weeks", ST["td"]),
        ])
    prio_data.append([
        Paragraph("MEDIUM", ParagraphStyle("med", fontSize=9,
            textColor=GREEN, fontName="Helvetica-Bold", leading=13)),
        Paragraph("Review all open ports — close anything not actively required", ST["td"]),
        Paragraph("30 days", ST["td"]),
    ])
    prio_t = Table(prio_data, colWidths=[1.1*inch, 4.5*inch, 1.6*inch])
    prio_t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,0),  NAVY),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [WHITE, BG_ROW]),
        ("TOPPADDING",    (0,0),(-1,-1), 7),
        ("BOTTOMPADDING", (0,0),(-1,-1), 7),
        ("LEFTPADDING",   (0,0),(-1,-1), 10),
        ("RIGHTPADDING",  (0,0),(-1,-1), 10),
        ("GRID",          (0,0),(-1,-1), 0.4, BORDER),
        ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
    ]))
    story.append(KeepTogether([
        Paragraph("Remediation Priorities", ST["h2"]),
        prio_t
    ]))
    story.append(PageBreak())

    # ── HOST-BY-HOST FINDINGS ──────────────────────────────────────────────
    story.append(Paragraph("Detailed Findings", ST["h1"]))
    story.append(HRFlowable(width="100%", thickness=1.5,
                             color=ACCENT, spaceAfter=8))
    story.append(Paragraph(
        "The following section details findings for each host discovered "
        "during the scan. Dangerous services are highlighted in red. "
        "CVE details are included where version information was available.",
        ST["body"]))
    story.append(Spacer(1, 0.15*inch))

    for ip in sorted(hosts.keys(),
                     key=lambda x: ipaddress.ip_address(x)):
        h_data     = hosts[ip]
        open_ports = h_data.get("open_ports", [])
        score, risk_label, risk_color = _score_host(open_ports)

        # Host header card
        host_header = [[
            Paragraph(ip, ParagraphStyle(
                "ip", fontSize=14, textColor=WHITE,
                fontName="Helvetica-Bold", leading=18)),
            Paragraph(
                f"Scanned: {h_data.get('scan_time','')}<br/>"
                f"{len(open_ports)} open port(s)",
                ParagraphStyle("hm", fontSize=8,
                    textColor=colors.HexColor("#8899cc"),
                    fontName="Helvetica", leading=12)),
            Paragraph(risk_label, ParagraphStyle(
                "rl", fontSize=10, fontName="Helvetica-Bold",
                textColor=colors.HexColor(risk_color)
                if isinstance(risk_color, str) else risk_color,
                leading=14, alignment=TA_RIGHT)),
        ]]
        host_t = Table(host_header, colWidths=[2.2*inch, 3.5*inch, 1.5*inch])
        host_t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,-1), NAVY),
            ("TOPPADDING",    (0,0),(-1,-1), 10),
            ("BOTTOMPADDING", (0,0),(-1,-1), 10),
            ("LEFTPADDING",   (0,0),(-1,-1), 12),
            ("RIGHTPADDING",  (0,0),(-1,-1), 12),
            ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
            ("LINEBELOW",     (0,0),(-1,-1), 2,
             colors.HexColor(risk_color)
             if isinstance(risk_color, str) else risk_color),
        ]))
        story.append(host_t)

        if not open_ports:
            story.append(Paragraph(
                "No open ports detected on this host during the scan.",
                ST["muted"]))
            story.append(Spacer(1, 0.15*inch))
            continue

        # Ports table
        port_rows = [[
            Paragraph("Port", ST["th"]),
            Paragraph("Service", ST["th"]),
            Paragraph("Banner / Version", ST["th"]),
            Paragraph("Risk", ST["th"]),
        ]]
        for p in open_ports:
            port_num = p["port"]
            is_dangerous = port_num in DANGEROUS_PORTS
            risk_cell = Paragraph(
                "⚠ Dangerous" if is_dangerous else "Review",
                ParagraphStyle("rc", fontSize=8,
                    textColor=RED if is_dangerous else YELLOW,
                    fontName="Helvetica-Bold", leading=12)
            ) if open_ports else Paragraph("—", ST["td"])

            banner = p.get("banner", "") or "—"
            port_rows.append([
                Paragraph(str(port_num), ST["td_mono"]),
                Paragraph(p.get("service", ""), ST["td"]),
                Paragraph(banner[:60] + ("..." if len(banner) > 60 else ""),
                          ST["td_mono"]),
                risk_cell,
            ])

        ports_t = Table(port_rows,
                        colWidths=[0.7*inch, 1.1*inch, 3.8*inch, 1.1*inch])
        ports_t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,0),  colors.HexColor("#1c2535")),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [WHITE, BG_ROW]),
            ("TOPPADDING",    (0,0),(-1,-1), 6),
            ("BOTTOMPADDING", (0,0),(-1,-1), 6),
            ("LEFTPADDING",   (0,0),(-1,-1), 8),
            ("RIGHTPADDING",  (0,0),(-1,-1), 8),
            ("GRID",          (0,0),(-1,-1), 0.4, BORDER),
            ("VALIGN",        (0,0),(-1,-1), "TOP"),
        ]))
        story.append(ports_t)

        # Recommendations for dangerous ports on this host
        recs = []
        for p in open_ports:
            if p["port"] in RECOMMENDATIONS:
                recs.append((p["port"], p["service"],
                             RECOMMENDATIONS[p["port"]]))
        if recs:
            rec_rows = [[
                Paragraph("Port", ST["th"]),
                Paragraph("Recommendation", ST["th"]),
            ]]
            for port_num, service, rec_text in recs:
                rec_rows.append([
                    Paragraph(f"{port_num}\n({service})",
                              ParagraphStyle("recport", fontSize=9,
                                  textColor=ACCENT, fontName="Courier",
                                  leading=13, alignment=TA_CENTER)),
                    Paragraph(rec_text, ST["rec"]),
                ])
            rec_t = Table(rec_rows, colWidths=[0.9*inch, 6.3*inch])
            rec_t.setStyle(TableStyle([
                ("BACKGROUND",    (0,0),(-1,0),  colors.HexColor("#1f2d1f")),
                ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.HexColor("#f0f7f0"),
                                                   WHITE]),
                ("TOPPADDING",    (0,0),(-1,-1), 6),
                ("BOTTOMPADDING", (0,0),(-1,-1), 6),
                ("LEFTPADDING",   (0,0),(-1,-1), 8),
                ("RIGHTPADDING",  (0,0),(-1,-1), 8),
                ("GRID",          (0,0),(-1,-1), 0.4, BORDER),
                ("VALIGN",        (0,0),(-1,-1), "TOP"),
                ("LINEBEFORE",    (0,0),(0,-1),  3, GREEN),
            ]))
            story.append(KeepTogether([
                Spacer(1, 0.06*inch),
                Paragraph("Recommendations", ST["h3"]),
                rec_t,
            ]))

        # CVEs for this host
        host_cves = [
            (p["port"], p["service"], c)
            for p in open_ports
            for c in p.get("cves", [])
        ]
        if host_cves:
            cve_rows = [[
                Paragraph("CVE ID", ST["th"]),
                Paragraph("Port", ST["th"]),
                Paragraph("CVSS", ST["th"]),
                Paragraph("Severity", ST["th"]),
                Paragraph("Description", ST["th"]),
            ]]
            for port_num, service, cve in sorted(
                    host_cves, key=lambda x: x[2]["score"], reverse=True):
                s = cve["score"]
                if s >= 9.0:
                    sev_color = RED
                elif s >= 7.0:
                    sev_color = YELLOW
                elif s >= 4.0:
                    sev_color = GREEN
                else:
                    sev_color = colors.HexColor("#8b949e")

                cve_rows.append([
                    Paragraph(cve["id"], ParagraphStyle(
                        "cveid", fontSize=8, textColor=ACCENT,
                        fontName="Courier", leading=12)),
                    Paragraph(f"{port_num}\n({service})",
                              ParagraphStyle("cveport", fontSize=8,
                                  textColor=colors.HexColor("#5a6a82"),
                                  fontName="Courier", leading=12,
                                  alignment=TA_CENTER)),
                    Paragraph(str(s), ParagraphStyle(
                        "cvss", fontSize=10, textColor=sev_color,
                        fontName="Helvetica-Bold", leading=14,
                        alignment=TA_CENTER)),
                    Paragraph(cve["severity"], ParagraphStyle(
                        "sev", fontSize=8, textColor=sev_color,
                        fontName="Helvetica-Bold", leading=12,
                        alignment=TA_CENTER)),
                    Paragraph(cve["description"][:120] + (
                        "..." if len(cve["description"]) > 120 else ""),
                        ST["muted"]),
                ])
            cve_t = Table(cve_rows,
                          colWidths=[1.3*inch, 0.75*inch, 0.6*inch,
                                     0.75*inch, 3.8*inch])
            cve_t.setStyle(TableStyle([
                ("BACKGROUND",    (0,0),(-1,0),  colors.HexColor("#1c1a2e")),
                ("ROWBACKGROUNDS",(0,1),(-1,-1), [WHITE, colors.HexColor("#f7f4fc")]),
                ("TOPPADDING",    (0,0),(-1,-1), 6),
                ("BOTTOMPADDING", (0,0),(-1,-1), 6),
                ("LEFTPADDING",   (0,0),(-1,-1), 8),
                ("RIGHTPADDING",  (0,0),(-1,-1), 8),
                ("GRID",          (0,0),(-1,-1), 0.4, BORDER),
                ("VALIGN",        (0,0),(-1,-1), "TOP"),
                ("LINEBEFORE",    (0,0),(0,-1),  3,
                 colors.HexColor("#8b5cf6")),
            ]))
            story.append(KeepTogether([
                Spacer(1, 0.06*inch),
                Paragraph("CVE Correlations", ST["h3"]),
                cve_t,
            ]))

        story.append(Spacer(1, 0.25*inch))

    # ── APPENDIX: SCOPE & METHODOLOGY ─────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("Scope &amp; Methodology", ST["h1"]))
    story.append(HRFlowable(width="100%", thickness=1.5,
                             color=ACCENT, spaceAfter=8))
    story.append(Paragraph(
        f"This assessment was conducted against the <b>{meta['network']}</b> "
        f"network on <b>{meta['scan_date']}</b> using Network Scanner v0.6. "
        f"The following techniques were employed:", ST["body"]))
    story.append(Spacer(1, 0.08*inch))

    method_items = [
        ("Host Discovery",
         "TCP connect probes on ports 22, 80, 443, and 445 to identify "
         "live hosts. A host is considered active if any probe port "
         "responds — including connection refused responses."),
        ("Port Scanning",
         "TCP full-connect scan against 19 commonly exploited ports per host. "
         "Ports are classified as open, closed, or filtered based on "
         "connection response."),
        ("Banner Grabbing",
         "Service banners collected from all open ports to identify software "
         "names and version numbers. HTTP/HTTPS services queried with HEAD "
         "requests; passive services listened for initial banner data."),
        ("CVE Correlation",
         "Service version strings parsed and queried against the National "
         "Vulnerability Database (NVD) API v2.0. Up to 5 CVEs returned per "
         "service, sorted by CVSS score descending."),
        ("Scope Limitation",
         "This scan covers TCP ports only. UDP services, web application "
         "vulnerabilities, authentication weaknesses, and physical security "
         "are outside the scope of this assessment."),
    ]
    meth_rows = [[Paragraph("Technique", ST["th"]),
                  Paragraph("Description", ST["th"])]]
    for tech, desc in method_items:
        meth_rows.append([
            Paragraph(tech, ParagraphStyle("mtech", fontSize=9,
                textColor=ACCENT, fontName="Helvetica-Bold", leading=13)),
            Paragraph(desc, ST["td"]),
        ])
    meth_t = Table(meth_rows, colWidths=[1.5*inch, 5.7*inch])
    meth_t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,0),  NAVY),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [WHITE, BG_ROW]),
        ("TOPPADDING",    (0,0),(-1,-1), 7),
        ("BOTTOMPADDING", (0,0),(-1,-1), 7),
        ("LEFTPADDING",   (0,0),(-1,-1), 10),
        ("RIGHTPADDING",  (0,0),(-1,-1), 10),
        ("GRID",          (0,0),(-1,-1), 0.4, BORDER),
        ("VALIGN",        (0,0),(-1,-1), "TOP"),
    ]))
    story.append(meth_t)
    story.append(Spacer(1, 0.2*inch))
    story.append(Paragraph(
        "This report was prepared for the exclusive use of the authorized "
        "client. The findings reflect the state of the assessed network at "
        "the time of the scan only. Network configurations change — "
        "periodic reassessment is recommended.",
        ST["disclaimer"]))

    doc.build(story,
              onFirstPage=_header_footer,
              onLaterPages=_header_footer)

    print(f"  [+] PDF audit report saved: {filename}")
    return filename


def generate_reports(enriched_results, network_range,
                     generate_pdf=True,
                     consultant_name="Your Name",
                     consultant_contact="your@email.com"):
    """Generate JSON, HTML, and (optionally) PDF client audit report."""
    print("\n[*] Generating reports")
    print("-" * 50)
    report_data = prepare_report_data(enriched_results, network_range)
    json_path   = generate_json_report(report_data)
    html_path   = generate_html_report(report_data)
    pdf_path    = None
    if generate_pdf:
        print("\n[*] Generating client PDF report (Stage 6)")
        pdf_path = generate_pdf_report(report_data, consultant_name,
                                       consultant_contact)
    print(f"\n[*] Reports saved to: {REPORTS_DIR}")
    return json_path, html_path, pdf_path


# ─── OUTPUT ───────────────────────────────────────────────────────────────────

def print_discovery_results():
    """Display Stage 1 summary."""
    print("\n" + "=" * 50)
    print(f"  SCAN COMPLETE — {len(live_hosts)} host(s) discovered")
    print("=" * 50)
    if live_hosts:
        sorted_hosts = sorted(live_hosts,
                               key=lambda ip: ipaddress.ip_address(ip))
        for host in sorted_hosts:
            print(f"  [+] {host}")
    else:
        print("  [-] No live hosts found")
    print("=" * 50)


def print_port_results(results, show_closed=False):
    """Display Stage 2 results per host."""
    print("\n" + "=" * 60)
    print("  PORT SCAN RESULTS")
    print("=" * 60)

    for host, data in sorted(results.items(),
                              key=lambda x: ipaddress.ip_address(x[0])):
        print(f"\n  Host: {host}  |  Scanned: {data['scan_time']}")
        print("  " + "-" * 40)
        if data["open"]:
            print("  OPEN:")
            for port, service in data["open"]:
                print(f"    {port:<6} {service}")
        else:
            print("  No open ports found")
        if data["filtered"]:
            print("  FILTERED:")
            for port, service in data["filtered"]:
                print(f"    {port:<6} {service}")
        if show_closed and data["closed"]:
            print("  CLOSED:")
            for port, service in data["closed"]:
                print(f"    {port:<6} {service}")

    print("\n" + "=" * 60 + "\n")


def print_banner_results(port_scan_results):
    """Display Stage 3 banner grabbing results."""
    print("\n" + "=" * 60)
    print("  BANNER GRAB RESULTS")
    print("=" * 60)

    for host, data in sorted(port_scan_results.items(),
                              key=lambda x: ipaddress.ip_address(x[0])):
        print(f"\n  Host: {host}")
        print("  " + "-" * 40)
        banners    = data.get("banners", {})
        open_ports = data.get("open", [])
        if not open_ports:
            print("  No open ports — nothing to banner grab")
            continue
        for port, service in open_ports:
            banner = banners.get(port, "Not attempted")
            print(f"  {port:<6} {service:<12} {banner}")

    print("\n" + "=" * 60 + "\n")


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    import argparse

    # argparse is Python's standard library for handling command line arguments.
    # It automatically generates --help output and handles errors cleanly.
    parser = argparse.ArgumentParser(
        prog="scanner.py",
        description="Network Scanner v0.5 — AUTHORIZED USE ONLY",
        epilog="Only scan networks you own or have explicit permission to scan."
    )

    # Positional argument — required, no flag needed
    # python3 scanner.py 192.168.226.0/24
    parser.add_argument(
        "network",
        nargs="?",          # Makes it optional so we can prompt if missing
        help="Target network range in CIDR notation (e.g. 192.168.1.0/24)"
    )

    # Optional flag — custom output directory
    # python3 scanner.py 192.168.226.0/24 --output ~/scans/engagement1
    parser.add_argument(
        "--output", "-o",
        metavar="DIR",
        help="Directory to save reports (default: ~/projects/network-scanner/reports)"
    )

    # Optional flag — skip CVE correlation for faster scans
    # python3 scanner.py 192.168.226.0/24 --no-cve
    parser.add_argument(
        "--no-cve",
        action="store_true",    # Flag only, no value needed — True if present
        help="Skip CVE correlation (faster scans, no NVD queries)"
    )

    # Optional flag — show closed ports in terminal output
    parser.add_argument(
        "--show-closed",
        action="store_true",
        help="Show closed ports in port scan results"
    )

    # Optional flag — skip PDF report generation
    parser.add_argument(
        "--no-pdf",
        action="store_true",
        help="Skip PDF client audit report generation"
    )

    # Optional flags — consultant info for PDF cover page
    parser.add_argument(
        "--name",
        metavar="NAME",
        default="Your Name",
        help="Your name for the PDF report cover (default: 'Your Name')"
    )
    parser.add_argument(
        "--contact",
        metavar="EMAIL",
        default="your@email.com",
        help="Your contact info for the PDF report cover"
    )

    args = parser.parse_args()

    print("""
╔══════════════════════════════════════╗
║      NETWORK SCANNER v0.6            ║
║      Stage 1: Host Discovery         ║
║      Stage 2: Port Scanner           ║
║      Stage 3: Banner Grabber         ║
║      Stage 4: Report Generator       ║
║      Stage 5: CVE Correlator         ║
║      Stage 6: Client PDF Report      ║
║      AUTHORIZED USE ONLY             ║
╚══════════════════════════════════════╝
    """)

    # Get network range — from arg or prompt
    if args.network:
        network_range = args.network
    else:
        network_range = input(
            "[?] Enter network range (e.g. 192.168.226.0/24): ").strip()

    if not is_authorized(network_range):
        print(f"\n[!] ERROR: {network_range} is not in your authorized "
              f"targets list.")
        print("[!] Add it to AUTHORIZED_NETWORKS only if you own it.")
        print("[!] Unauthorized scanning is illegal. Exiting.\n")
        sys.exit(1)

    # Apply custom output directory if specified.
    # We modify the global REPORTS_DIR so all report functions
    # automatically use it without needing to pass it around.
    if args.output:
        global REPORTS_DIR
        REPORTS_DIR = Path(args.output).expanduser().resolve()
        print(f"[*] Output directory: {REPORTS_DIR}")

    # Stage 1 — host discovery
    found = discover_hosts(network_range)
    print_discovery_results()

    if not found:
        print("[-] No live hosts found. Exiting.\n")
        sys.exit(0)

    # Stage 2 — port scan
    port_results = run_port_scan(found)
    print_port_results(port_results, show_closed=args.show_closed)

    # Stage 3 — banner grab
    enriched_results = run_banner_grab(port_results)
    print_banner_results(enriched_results)

    # Stage 5 — CVE correlation (skippable with --no-cve)
    if args.no_cve:
        print("\n[*] Skipping CVE correlation (--no-cve flag set)")
        for host, data in enriched_results.items():
            data["cves"] = {}
    else:
        enriched_results = run_cve_correlation(enriched_results)
        print_cve_results(enriched_results)

    # Stage 4 — generate reports
    generate_reports(enriched_results, network_range,
                     generate_pdf=not args.no_pdf,
                     consultant_name=args.name,
                     consultant_contact=args.contact)
    # Save to database if available
    if DB_AVAILABLE:
        save_scan(enriched_results, network_range, client_id=None)
    else:
        print("[*] Database not configured — skipping db save")

if __name__ == "__main__":
    main()
