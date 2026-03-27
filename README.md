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
- No external dependencies — uses Python standard library only

## Usage
```bash
python3 scanner.py 192.168.1.0/24
```

The target network must be added to the `AUTHORIZED_NETWORKS` list in the 
script before scanning.

## Output

Reports are saved to `~/projects/network-scanner/reports/` as:
- `scan_YYYYMMDD_HHMMSS.json`
- `scan_YYYYMMDD_HHMMSS.html`

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
