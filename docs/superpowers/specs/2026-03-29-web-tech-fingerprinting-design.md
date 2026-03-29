# Stage 7 — Web Technology Fingerprinting

**Date:** 2026-03-29
**Status:** Approved

## Overview

Add Stage 7 to `scanner.py` that fingerprints web technologies on hosts with port 80 or 443 open. It makes a single `GET /` request per host and inspects both response headers and HTML body for technology signatures. No new dependencies — reuses `urllib`, `ssl`, and `re` already imported.

## Goals

- Identify the web server, language/runtime, framework, and CMS for each HTTP/HTTPS host
- Integrate cleanly with existing JSON and HTML report output
- Be easy for the student to extend with new signatures

## Architecture

Stage 7 runs after Stage 3 (banner grabbing) in the main pipeline. It operates only on hosts that have port 80 or 443 in their open ports list.

### Signature Database

A module-level dict of two categories:

**Header signatures** — `{header_name: [(regex_pattern, label), ...]}`

| Header | Pattern | Label |
|---|---|---|
| `Server` | `Apache` | Apache |
| `Server` | `nginx` | nginx |
| `Server` | `Microsoft-IIS` | IIS |
| `Server` | `LiteSpeed` | LiteSpeed |
| `X-Powered-By` | `PHP/([\d.]+)` | PHP (with version) |
| `X-Powered-By` | `ASP\.NET` | ASP.NET |
| `X-Powered-By` | `Express` | Express.js |
| `X-Drupal-Cache` | `.*` | Drupal |
| `X-Generator` | `Drupal` | Drupal |
| `Set-Cookie` | `PHPSESSID` | PHP |
| `Set-Cookie` | `JSESSIONID` | Java |
| `Set-Cookie` | `ASP\.NET_SessionId` | ASP.NET |
| `Set-Cookie` | `laravel_session` | Laravel |
| `Link` | `api\.w\.org` | WordPress |

**Body signatures** — `[(regex_pattern, label), ...]` applied to the first 8 KB of the response body:

| Pattern | Label |
|---|---|
| `/wp-content/` or `/wp-includes/` | WordPress |
| `/sites/default/files/` | Drupal |
| `Drupal\.settings` | Drupal |
| `/administrator/index\.php` | Joomla |
| `Mage\.Cookies` | Magento |
| `__NEXT_DATA__` | Next.js |
| `__nuxt` | Nuxt.js |
| `data-reactroot\|data-reactid` | React |
| `ng-version` | Angular |
| `<meta[^>]+generator[^>]+WordPress` | WordPress |
| `<meta[^>]+generator[^>]+Drupal` | Drupal |
| `<meta[^>]+generator[^>]+Joomla` | Joomla |
| `jquery` (case-insensitive) | jQuery |
| `bootstrap` (case-insensitive, in `<link`) | Bootstrap |

### Data Flow

```
Stage 3 results (host → open ports + banners)
        │
        ▼
Stage 7: for each host with port 80 or 443 open
        │  GET / on port 443 (SSL), fallback to port 80
        │  Read response headers + first 8 KB of body
        │  Match header signatures → tech list
        │  Match body signatures → tech list
        │  Deduplicate
        ▼
Add web_tech: ["nginx", "PHP", "WordPress"] to host entry
        │
        ▼
Existing JSON + HTML report (already reads host entry dict)
```

### Key Implementation Details

- **Port preference:** try 443 first with SSL, fall back to 80 if 443 is not open
- **Timeout:** 3 seconds (same order as Stage 3)
- **Body read limit:** 8 KB — enough to catch meta tags and script paths, avoids large downloads
- **Deduplication:** use a set internally, convert to sorted list for output
- **Graceful failure:** if the HTTP request fails for any host, set `web_tech: []` and continue — never crash the pipeline
- **Version extraction:** for `X-Powered-By: PHP/8.1.2`, capture the version and store as `"PHP/8.1.2"` not just `"PHP"`

## Output Format

Each host dict gains one new key:

```json
{
  "ip": "192.168.1.10",
  "open_ports": [...],
  "banners": {...},
  "web_tech": ["nginx", "PHP/8.1.2", "WordPress", "jQuery"]
}
```

In the HTML report, add a **Web Technologies** row to each host's findings table when `web_tech` is non-empty, displaying the list as comma-separated badges.

In the terminal output, print a `[Stage 7]` summary line per host showing detected tech, consistent with the existing stage output style.

## Scope

- Single `GET /` request per host — no crawling, no form submission, no authenticated requests
- No new files — all code added to `scanner.py`
- No new dependencies
- Does not modify Stage 3 — runs independently after it

## Out of Scope

- Favicon hash matching (separate enhancement)
- Technology version detection beyond what headers provide
- JavaScript execution or dynamic page rendering
