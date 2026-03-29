# Stage 7 — Web Technology Fingerprinting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Stage 7 to `scanner.py` that fingerprints web technologies (server, language, framework, CMS) on hosts with port 80 or 443 open, and surfaces the results in the terminal output, JSON report, and HTML report.

**Architecture:** Two pure parsing functions (`_match_header_sigs`, `_match_body_sigs`) feed into `fingerprint_web_tech` which makes a single `GET /` request per host. `run_web_fingerprint` orchestrates across all hosts and mutates `enriched_results` in-place, adding a `web_tech` list. The existing report functions are updated to include this new field.

**Tech Stack:** Python 3.10+ stdlib only — `urllib.request`, `ssl`, `re` (all already imported in `scanner.py`)

---

## File Map

| File | Change |
|---|---|
| `scanner.py` | Add Stage 7 config, 5 new functions, update `prepare_report_data`, `generate_html_report`, and `main` |
| `tests/test_web_fingerprint.py` | New — unit tests for the two pure parsing functions |

---

### Task 1: Signature config + `_match_header_sigs` + tests

**Files:**
- Modify: `scanner.py` (after `SKIP_BANNERS` block, around line 121)
- Create: `tests/test_web_fingerprint.py`

- [ ] **Step 1: Create the tests directory and test file with a failing test**

```bash
mkdir -p tests
```

Create `tests/test_web_fingerprint.py`:

```python
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import _match_header_sigs


def test_nginx_server_header():
    headers = {"server": "nginx/1.24.0"}
    assert "nginx" in _match_header_sigs(headers)


def test_apache_server_header():
    headers = {"server": "Apache/2.4.57 (Debian)"}
    assert "Apache" in _match_header_sigs(headers)


def test_php_version_extracted():
    headers = {"x-powered-by": "PHP/8.1.2"}
    result = _match_header_sigs(headers)
    assert "PHP/8.1.2" in result


def test_aspnet_header():
    headers = {"x-powered-by": "ASP.NET"}
    assert "ASP.NET" in _match_header_sigs(headers)


def test_express_header():
    headers = {"x-powered-by": "Express"}
    assert "Express.js" in _match_header_sigs(headers)


def test_drupal_via_x_drupal_cache():
    headers = {"x-drupal-cache": "HIT"}
    assert "Drupal" in _match_header_sigs(headers)


def test_php_via_session_cookie():
    headers = {"set-cookie": "PHPSESSID=abc123; path=/"}
    assert "PHP" in _match_header_sigs(headers)


def test_java_via_session_cookie():
    headers = {"set-cookie": "JSESSIONID=xyz; Path=/"}
    assert "Java" in _match_header_sigs(headers)


def test_laravel_via_cookie():
    headers = {"set-cookie": "laravel_session=encrypted; path=/"}
    assert "Laravel" in _match_header_sigs(headers)


def test_wordpress_via_link_header():
    headers = {"link": '<https://example.com/wp-json/>; rel="https://api.w.org/"'}
    assert "WordPress" in _match_header_sigs(headers)


def test_empty_headers_returns_empty_set():
    assert _match_header_sigs({}) == set()


def test_unknown_headers_ignored():
    headers = {"x-custom-header": "some-value"}
    assert _match_header_sigs(headers) == set()


if __name__ == "__main__":
    import unittest
    # Run as: python3 tests/test_web_fingerprint.py
    results = []
    for name, fn in [(k, v) for k, v in globals().items() if k.startswith("test_")]:
        try:
            fn()
            results.append(f"  PASS  {name}")
        except Exception as e:
            results.append(f"  FAIL  {name}: {e}")
    print("\n".join(results))
    failed = sum(1 for r in results if "FAIL" in r)
    print(f"\n{len(results) - failed}/{len(results)} passed")
```

- [ ] **Step 2: Run the test to verify it fails (function doesn't exist yet)**

```bash
python3 -m pytest tests/test_web_fingerprint.py -v 2>&1 | head -30
```

Expected: `ImportError: cannot import name '_match_header_sigs' from 'scanner'`

- [ ] **Step 3: Add the Stage 7 config block and `_match_header_sigs` to `scanner.py`**

Insert after the `SKIP_BANNERS` block (after line 121), before the `# ─── AUTHORIZATION` line:

```python
# ─── STAGE 7 CONFIGURATION ────────────────────────────────────────────────────

# Header signatures: {lowercase_header_name: [(regex_pattern, label_or_None), ...]}
# label=None means use the regex match text directly as the label (e.g. "PHP/8.1.2")
WEB_HEADER_SIGS = {
    "server": [
        (r"Apache",         "Apache"),
        (r"nginx",          "nginx"),
        (r"Microsoft-IIS",  "IIS"),
        (r"LiteSpeed",      "LiteSpeed"),
    ],
    "x-powered-by": [
        (r"PHP/[\d.]+",     None),       # None → use matched text, e.g. "PHP/8.1.2"
        (r"ASP\.NET",       "ASP.NET"),
        (r"Express",        "Express.js"),
    ],
    "x-drupal-cache":  [(r".*",            "Drupal")],
    "x-generator":     [(r"Drupal",        "Drupal")],
    "set-cookie": [
        (r"PHPSESSID",          "PHP"),
        (r"JSESSIONID",         "Java"),
        (r"ASP\.NET_SessionId", "ASP.NET"),
        (r"laravel_session",    "Laravel"),
    ],
    "link": [(r"api\.w\.org", "WordPress")],
}

# Body signatures: [(regex_pattern, label), ...] applied to first 8 KB of body
WEB_BODY_SIGS = [
    (r"/wp-content/|/wp-includes/",          "WordPress"),
    (r"/sites/default/files/",               "Drupal"),
    (r"Drupal\.settings",                    "Drupal"),
    (r"/administrator/index\.php",           "Joomla"),
    (r"Mage\.Cookies",                       "Magento"),
    (r"__NEXT_DATA__",                       "Next.js"),
    (r"__nuxt",                              "Nuxt.js"),
    (r"data-reactroot|data-reactid",         "React"),
    (r"ng-version",                          "Angular"),
    (r"<meta[^>]+generator[^>]+WordPress",   "WordPress"),
    (r"<meta[^>]+generator[^>]+Drupal",      "Drupal"),
    (r"<meta[^>]+generator[^>]+Joomla",      "Joomla"),
    (r"(?i)jquery",                          "jQuery"),
    (r"(?i)<link[^>]+bootstrap",             "Bootstrap"),
]

TIMEOUT_S7 = 3.0
BODY_READ_LIMIT = 8192   # 8 KB — enough for meta tags and script paths


def _match_header_sigs(headers):
    """
    Match a dict of HTTP response headers against WEB_HEADER_SIGS.

    headers: dict of {lowercase_header_name: header_value_string}
    Returns a set of technology label strings.
    """
    found = set()
    for header_name, patterns in WEB_HEADER_SIGS.items():
        value = headers.get(header_name, "")
        if not value:
            continue
        for pattern, label in patterns:
            m = re.search(pattern, value, re.IGNORECASE)
            if m:
                found.add(m.group(0) if label is None else label)
    return found
```

- [ ] **Step 4: Run the tests and verify they all pass**

```bash
python3 -m pytest tests/test_web_fingerprint.py -v
```

Expected: 12 tests, all PASS

- [ ] **Step 5: Commit**

```bash
git add scanner.py tests/test_web_fingerprint.py
git commit -m "feat: Stage 7 - add header signature config and _match_header_sigs"
```

---

### Task 2: `_match_body_sigs` + tests

**Files:**
- Modify: `scanner.py` (add function after `_match_header_sigs`)
- Modify: `tests/test_web_fingerprint.py` (add new test functions)

- [ ] **Step 1: Add body tests to `tests/test_web_fingerprint.py`**

Append these functions to the file (before the `if __name__ == "__main__"` block):

```python
from scanner import _match_body_sigs


def test_wordpress_wp_content_path():
    body = '<link rel="stylesheet" href="/wp-content/themes/twentytwenty/style.css">'
    assert "WordPress" in _match_body_sigs(body)


def test_wordpress_meta_generator():
    body = '<meta name="generator" content="WordPress 6.4.2" />'
    assert "WordPress" in _match_body_sigs(body)


def test_drupal_settings():
    body = "var drupalSettings = {}; Drupal.settings = {};"
    assert "Drupal" in _match_body_sigs(body)


def test_nextjs_data_tag():
    body = '<script id="__NEXT_DATA__" type="application/json">{"page":"/","query":{}}</script>'
    assert "Next.js" in _match_body_sigs(body)


def test_react_data_root():
    body = '<div data-reactroot="" id="root"></div>'
    assert "React" in _match_body_sigs(body)


def test_angular_ng_version():
    body = '<app-root _nghost-abc ng-version="17.0.0"></app-root>'
    assert "Angular" in _match_body_sigs(body)


def test_jquery_script_tag():
    body = '<script src="/assets/jquery.min.js"></script>'
    assert "jQuery" in _match_body_sigs(body)


def test_bootstrap_link_tag():
    body = '<link rel="stylesheet" href="/css/bootstrap.min.css">'
    assert "Bootstrap" in _match_body_sigs(body)


def test_bootstrap_not_matched_in_body_text():
    # "bootstrap" in plain text (not a <link> tag) should NOT match
    body = "<p>We bootstrap our app on startup.</p>"
    assert "Bootstrap" not in _match_body_sigs(body)


def test_joomla_administrator_path():
    body = '<a href="/administrator/index.php">Admin</a>'
    assert "Joomla" in _match_body_sigs(body)


def test_empty_body_returns_empty_set():
    assert _match_body_sigs("") == set()


def test_plain_html_no_signatures():
    body = "<html><body><h1>Hello World</h1></body></html>"
    assert _match_body_sigs(body) == set()
```

- [ ] **Step 2: Run the new tests to verify they fail**

```bash
python3 -m pytest tests/test_web_fingerprint.py -v -k "body"
```

Expected: `ImportError: cannot import name '_match_body_sigs' from 'scanner'`

- [ ] **Step 3: Add `_match_body_sigs` to `scanner.py` immediately after `_match_header_sigs`**

```python
def _match_body_sigs(body):
    """
    Match HTML body text against WEB_BODY_SIGS.

    body: string containing the first 8 KB of the HTTP response body
    Returns a set of technology label strings.
    """
    found = set()
    for pattern, label in WEB_BODY_SIGS:
        if re.search(pattern, body):
            found.add(label)
    return found
```

- [ ] **Step 4: Run all tests**

```bash
python3 -m pytest tests/test_web_fingerprint.py -v
```

Expected: 24 tests, all PASS

- [ ] **Step 5: Commit**

```bash
git add scanner.py tests/test_web_fingerprint.py
git commit -m "feat: Stage 7 - add _match_body_sigs with body signature matching"
```

---

### Task 3: `fingerprint_web_tech`, `run_web_fingerprint`, `print_web_tech_results`

**Files:**
- Modify: `scanner.py` (add 3 functions after `_match_body_sigs`)

- [ ] **Step 1: Add `fingerprint_web_tech` to `scanner.py` after `_match_body_sigs`**

```python
def fingerprint_web_tech(host, open_port_nums):
    """
    Make a single GET / request to the host and return a sorted list of
    detected web technologies.

    Tries HTTPS (port 443) first with SSL verification disabled (self-signed
    certs are common in home labs). Falls back to HTTP (port 80).
    Returns [] if neither port is open or if the request fails.

    open_port_nums: set of integer port numbers open on this host
    """
    if 443 in open_port_nums:
        use_ssl = True
    elif 80 in open_port_nums:
        use_ssl = False
    else:
        return []

    try:
        scheme = "https" if use_ssl else "http"
        url    = f"{scheme}://{host}/"
        req    = urllib.request.Request(
            url, headers={"User-Agent": "NetworkScanner/0.7"}
        )

        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            resp_ctx = urllib.request.urlopen(req, timeout=TIMEOUT_S7,
                                              context=ctx)
        else:
            resp_ctx = urllib.request.urlopen(req, timeout=TIMEOUT_S7)

        with resp_ctx as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body    = resp.read(BODY_READ_LIMIT).decode("utf-8", errors="ignore")

        tech = _match_header_sigs(headers) | _match_body_sigs(body)
        return sorted(tech)

    except Exception:
        return []
```

- [ ] **Step 2: Add `run_web_fingerprint` immediately after `fingerprint_web_tech`**

```python
def run_web_fingerprint(enriched_results):
    """
    Stage 7: fingerprint web technologies on all hosts with port 80 or 443 open.

    Mutates enriched_results in-place: adds a 'web_tech' key (list of strings)
    to every host entry. Hosts without port 80/443 get web_tech=[].
    Returns enriched_results.
    """
    web_hosts = [
        host for host, data in enriched_results.items()
        if any(p in {80, 443} for p, _ in data.get("open", []))
    ]

    print(f"\n{'=' * 60}")
    print(f"[Stage 7] Web Technology Fingerprinting")
    print(f"{'=' * 60}")

    if not web_hosts:
        print("  No HTTP/HTTPS hosts found — skipping\n")
        for data in enriched_results.values():
            data["web_tech"] = []
        return enriched_results

    print(f"  Scanning {len(web_hosts)} HTTP/HTTPS host(s)...\n")

    for host, data in enriched_results.items():
        open_port_nums  = {p for p, _ in data.get("open", [])}
        data["web_tech"] = fingerprint_web_tech(host, open_port_nums)

    return enriched_results
```

- [ ] **Step 3: Add `print_web_tech_results` immediately after `run_web_fingerprint`**

```python
def print_web_tech_results(enriched_results):
    """Print Stage 7 fingerprint results to the terminal."""
    for host in sorted(enriched_results,
                       key=lambda x: ipaddress.ip_address(x)):
        data = enriched_results[host]
        tech = data.get("web_tech", [])
        is_web_host = any(
            p in {80, 443} for p, _ in data.get("open", [])
        )
        if not is_web_host:
            continue
        if tech:
            print(f"  {host}: {', '.join(tech)}")
        else:
            print(f"  {host}: No web technologies detected")
    print()
```

- [ ] **Step 4: Verify the functions are importable and callable**

```bash
python3 -c "
from scanner import fingerprint_web_tech, run_web_fingerprint, print_web_tech_results
# Smoke test: no open web ports → returns []
result = fingerprint_web_tech('127.0.0.1', {22, 25})
assert result == [], f'Expected [], got {result}'
print('OK: fingerprint_web_tech returns [] for non-web host')
"
```

Expected: `OK: fingerprint_web_tech returns [] for non-web host`

- [ ] **Step 5: Commit**

```bash
git add scanner.py
git commit -m "feat: Stage 7 - add fingerprint_web_tech, run_web_fingerprint, print_web_tech_results"
```

---

### Task 4: Wire Stage 7 into `main()` and `prepare_report_data`

**Files:**
- Modify: `scanner.py`

- [ ] **Step 1: Add Stage 7 call to `main()` between Stage 3 and Stage 5**

Find this block in `main()` (around line 1868):

```python
    # Stage 3 — banner grab
    enriched_results = run_banner_grab(port_results)
    print_banner_results(enriched_results)

    # Stage 5 — CVE correlation (skippable with --no-cve)
```

Replace with:

```python
    # Stage 3 — banner grab
    enriched_results = run_banner_grab(port_results)
    print_banner_results(enriched_results)

    # Stage 7 — web technology fingerprinting
    enriched_results = run_web_fingerprint(enriched_results)
    print_web_tech_results(enriched_results)

    # Stage 5 — CVE correlation (skippable with --no-cve)
```

- [ ] **Step 2: Update the startup banner in `main()` to include Stage 7**

Find:

```python
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
```

Replace with:

```python
    print("""
╔══════════════════════════════════════╗
║      NETWORK SCANNER v0.7            ║
║      Stage 1: Host Discovery         ║
║      Stage 2: Port Scanner           ║
║      Stage 3: Banner Grabber         ║
║      Stage 4: Report Generator       ║
║      Stage 5: CVE Correlator         ║
║      Stage 6: Client PDF Report      ║
║      Stage 7: Web Tech Fingerprint   ║
║      AUTHORIZED USE ONLY             ║
╚══════════════════════════════════════╝
    """)
```

- [ ] **Step 3: Add `web_tech` to `prepare_report_data`**

Find in `prepare_report_data` (around line 647):

```python
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
```

Replace with:

```python
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
            },
            "web_tech": data.get("web_tech", []),
        }
```

- [ ] **Step 4: Verify `prepare_report_data` includes `web_tech` correctly**

```bash
python3 -c "
from scanner import prepare_report_data
fake_results = {
    '192.168.1.1': {
        'open': [(80, 'HTTP')],
        'filtered': [],
        'banners': {},
        'cves': {},
        'scan_time': '10:00:00',
        'web_tech': ['nginx', 'WordPress'],
    }
}
report = prepare_report_data(fake_results, '192.168.1.0/24')
host = report['hosts']['192.168.1.1']
assert host['web_tech'] == ['nginx', 'WordPress'], f'Got: {host[\"web_tech\"]}'
print('OK: web_tech included in report data')
"
```

Expected: `OK: web_tech included in report data`

- [ ] **Step 5: Commit**

```bash
git add scanner.py
git commit -m "feat: Stage 7 - wire into main pipeline and report data"
```

---

### Task 5: Update HTML report with web tech badges

**Files:**
- Modify: `scanner.py` (`generate_html_report` function)

- [ ] **Step 1: Add CSS for tech badges in `generate_html_report`**

Find the CSS block inside `generate_html_report` that contains `.risk-badge` styles. It will look like:

```python
        .risk-badge { ...
```

Add these rules immediately after the `.risk-badge` block (the exact location is inside the `html = f"""..."""` string — find `.filtered-list` and add after it):

Search for this CSS in the HTML template string:

```css
        .filtered-list { color: #888; font-size: 0.85em; margin-top: 6px; }
```

Add immediately after it:

```css
        .web-tech-section { margin-top: 10px; }
        .web-tech-label { font-size: 0.75em; font-weight: 600; color: #5a6a82;
                          text-transform: uppercase; letter-spacing: 0.05em;
                          margin-right: 8px; }
        .tech-badge { display: inline-block; background: #e8f0fe; color: #1a73e8;
                      border: 1px solid #c5d8fb; border-radius: 12px;
                      font-size: 0.78em; font-weight: 600; padding: 2px 10px;
                      margin: 2px 3px 2px 0; }
```

- [ ] **Step 2: Add web tech section to each host card in `generate_html_report`**

In the host card loop, find the line where `host_cards` is assembled (around line 783). The current template ends like:

```python
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
```

Before building the `host_cards +=` f-string, add this block to compute the web tech section:

```python
        # ── Web tech section ──────────────────────────────────────────────
        web_tech = data.get("web_tech", [])
        if web_tech:
            badges = "".join(
                f'<span class="tech-badge">{t}</span>' for t in web_tech
            )
            web_tech_section = (
                f'<div class="web-tech-section">'
                f'<span class="web-tech-label">Web Technologies</span>'
                f'{badges}</div>'
            )
        else:
            web_tech_section = ""
```

Then update the `host_cards +=` f-string to include `{web_tech_section}`:

```python
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
                {web_tech_section}
            </div>
        </div>"""
```

- [ ] **Step 3: Verify the HTML report generates without errors**

```bash
python3 -c "
from scanner import generate_html_report
fake_report = {
    'metadata': {
        'tool': 'Network Scanner v0.7',
        'network': '192.168.1.0/24',
        'scan_date': '2026-03-29',
        'scan_time': '10:00:00',
        'total_hosts': 1,
        'total_open_ports': 1,
    },
    'hosts': {
        '192.168.1.1': {
            'scan_time': '10:00:00',
            'open_ports': [{'port': 80, 'service': 'HTTP', 'banner': 'nginx', 'cves': []}],
            'filtered_ports': [],
            'summary': {'open_count': 1, 'filtered_count': 0},
            'web_tech': ['nginx', 'WordPress', 'jQuery'],
        }
    }
}
path = generate_html_report(fake_report)
content = open(path).read()
assert 'tech-badge' in content, 'tech-badge CSS class missing from HTML'
assert 'nginx' in content, 'nginx badge missing from HTML'
assert 'WordPress' in content, 'WordPress badge missing from HTML'
print(f'OK: HTML report generated with web tech badges at {path}')
"
```

Expected: `OK: HTML report generated with web tech badges at ~/projects/...`

- [ ] **Step 4: Run the full test suite to confirm nothing is broken**

```bash
python3 -m pytest tests/test_web_fingerprint.py -v
```

Expected: 24 tests, all PASS

- [ ] **Step 5: Commit**

```bash
git add scanner.py
git commit -m "feat: Stage 7 - add web tech badges to HTML report"
```
