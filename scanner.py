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


def generate_reports(enriched_results, network_range):
    """Generate both JSON and HTML reports."""
    print("\n[*] Generating reports")
    print("-" * 50)
    report_data = prepare_report_data(enriched_results, network_range)
    json_path   = generate_json_report(report_data)
    html_path   = generate_html_report(report_data)
    print(f"\n[*] Reports saved to: {REPORTS_DIR}")
    return json_path, html_path


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
    print("""
╔══════════════════════════════════════╗
║      NETWORK SCANNER v0.5            ║
║      Stage 1: Host Discovery         ║
║      Stage 2: Port Scanner           ║
║      Stage 3: Banner Grabber         ║
║      Stage 4: Report Generator       ║
║      Stage 5: CVE Correlator         ║
║      AUTHORIZED USE ONLY             ║
╚══════════════════════════════════════╝
    """)

    if len(sys.argv) == 2:
        network_range = sys.argv[1]
    else:
        network_range = input(
            "[?] Enter network range (e.g. 192.168.226.0/24): ").strip()

    if not is_authorized(network_range):
        print(f"\n[!] ERROR: {network_range} is not in your authorized "
              f"targets list.")
        print("[!] Add it to AUTHORIZED_NETWORKS only if you own it.")
        print("[!] Unauthorized scanning is illegal. Exiting.\n")
        sys.exit(1)

    # Stage 1 — host discovery
    found = discover_hosts(network_range)
    print_discovery_results()

    if not found:
        print("[-] No live hosts found. Exiting.\n")
        sys.exit(0)

    # Stage 2 — port scan
    port_results = run_port_scan(found)
    print_port_results(port_results, show_closed=False)

    # Stage 3 — banner grab
    enriched_results = run_banner_grab(port_results)
    print_banner_results(enriched_results)

    # Stage 5 — CVE correlation
    enriched_results = run_cve_correlation(enriched_results)
    print_cve_results(enriched_results)

    # Stage 4 — generate reports (runs after CVE data is ready)
    generate_reports(enriched_results, network_range)


if __name__ == "__main__":
    main()
