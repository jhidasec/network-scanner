# Network Scanner

A modular Python network reconnaissance tool built for security research and 
home lab practice. Performs host discovery, port scanning, service banner 
grabbing, CVE correlation, and generates professional HTML/JSON reports.

> **AUTHORIZED USE ONLY** — Only scan networks you own or have explicit 
> written permission to scan. Unauthorized scanning is illegal.

## Features

- **Stage 1 — Host Discovery:** Multi-port TCP probe sweep across a network 
  range. Detects live hosts even when common ports are filtered.
- **Stage 2 — Port Scanner:** Concurrent TCP full-connect scan across 19 
  common ports. Categorizes results as open, closed, or filtered.
- **Stage 3 — Banner Grabber:** Protocol-aware service banner retrieval. 
  Handles passive services (SSH, FTP), active services (HTTP/HTTPS), and 
  binary protocols (SMB, RDP, RPC).
- **Stage 4 — Report Generator:** Outputs timestamped JSON (machine-readable) 
  and styled HTML (human-readable) reports.
- **Stage 5 — CVE Correlator:** Parses service banners to extract version 
  strings and queries the NVD API for known CVEs with CVSS scores.
- **Stage 6 — Client PDF Report:** Generates a professional client-facing 
  audit report with executive summary, risk ratings, per-host findings, 
  CVE tables, recommendations, and scope documentation. Requires `reportlab`.
## Requirements

- Python 3.10+
- Kali Linux or any Debian-based system
- No external dependencies for Stages 1–5 — uses Python standard library only
- `reportlab` (optional) for Stage 6 PDF client reports:
```bash
  pip install reportlab --break-system-packages
```

## Usage
```bash
# Basic scan
python3 scanner.py 192.168.1.0/24

# Full scan with PDF client report
python3 scanner.py 192.168.1.0/24 --name "Your Name" --contact "you@email.com"

# Skip CVE correlation (faster)
python3 scanner.py 192.168.1.0/24 --no-cve

# Skip PDF report generation
python3 scanner.py 192.168.1.0/24 --no-pdf

# Custom output directory
python3 scanner.py 192.168.1.0/24 --output ~/engagements/client1

# Show closed ports in terminal output
python3 scanner.py 192.168.1.0/24 --show-closed
```

The target network must be added to the `AUTHORIZED_NETWORKS` 
list in the script before scanning.

## Output

Reports are saved to `~/projects/network-scanner/reports/` as:
- `scan_YYYYMMDD_HHMMSS.json`
- `scan_YYYYMMDD_HHMMSS.html`
- `audit_report_YYYYMMDD_HHMMSS.pdf` *(client-facing, requires reportlab)*

## Project Structure
```
network-scanner/
├── scanner.py        # Main scanner — all 5 stages
└── reports/          # Generated scan reports (gitignored)
```

## Legal

This tool is intended for authorized penetration testing and security research 
only. The author assumes no liability for misuse. Always obtain written 
permission before scanning any network.
## Part of the jhidasec toolkit

- [Network Scanner](https://github.com/jhidasec/network-scanner) — host 
  discovery, port scanning, banner grabbing, CVE correlation
- [Email Security Checker](https://github.com/jhidasec/email-security-checker) 
  — SPF, DKIM, DMARC analysis with bulk checking and PDF reports
- [SMB Security Assessment](https://github.com/jhidasec/smb-security-assessment) 
  — field assessment tool with CIS Controls alignment and PDF reporting
