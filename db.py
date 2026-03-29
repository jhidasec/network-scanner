#!/usr/bin/env python3
"""
Network Scanner — Database Layer
Handles all PostgreSQL operations for storing and querying scan results.
Provides diff reporting between scans and multi-client management.
"""

import json
import sys
from datetime import datetime
from pathlib import Path

try:
    import psycopg2
    import psycopg2.extras
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False

# ─── CONNECTION CONFIG ────────────────────────────────────────────────────────
# In production you'd load these from environment variables.
# For lab use, hardcoded is fine.
DB_CONFIG = {
    "host":     "localhost",
    "port":     5432,
    "dbname":   "scanner_db",
    "user":     "scanner_user",
    "password": "scannerpass123"
}


def get_connection():
    """
    Return a live PostgreSQL connection.
    Called at the start of every database operation — connections are
    short-lived and closed after each operation to avoid leaks.
    """
    if not PSYCOPG2_AVAILABLE:
        print("[!] psycopg2 not installed. Run:")
        print("    pip install psycopg2-binary --break-system-packages")
        sys.exit(1)

    try:
        conn = psycopg2.connect(**DB_CONFIG)
        return conn
    except psycopg2.OperationalError as e:
        print(f"[!] Database connection failed: {e}")
        print("[!] Is PostgreSQL running? Try: sudo systemctl start postgresql")
        sys.exit(1)


# ─── SCHEMA CREATION ──────────────────────────────────────────────────────────

def init_db():
    """
    Create all tables if they don't exist.
    Safe to run multiple times — IF NOT EXISTS prevents overwriting data.
    Call this once on first run or after a fresh install.
    """
    conn = get_connection()
    cur  = conn.cursor()

    # clients table — one row per business you're monitoring
    cur.execute("""
        CREATE TABLE IF NOT EXISTS clients (
            id            SERIAL PRIMARY KEY,
            name          TEXT NOT NULL,
            contact_email TEXT,
            network_range TEXT NOT NULL,
            notes         TEXT,
            created_at    TIMESTAMP DEFAULT NOW()
        )
    """)

    # scans table — one row per scan run
    # client_id can be NULL for ad-hoc scans not tied to a client
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id               SERIAL PRIMARY KEY,
            client_id        INTEGER REFERENCES clients(id) ON DELETE SET NULL,
            network_range    TEXT NOT NULL,
            scan_date        TIMESTAMP NOT NULL,
            total_hosts      INTEGER DEFAULT 0,
            total_open_ports INTEGER DEFAULT 0,
            scanner_version  TEXT DEFAULT 'v0.6',
            notes            TEXT
        )
    """)

    # hosts table — one row per live host per scan
    cur.execute("""
        CREATE TABLE IF NOT EXISTS hosts (
            id            SERIAL PRIMARY KEY,
            scan_id       INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            ip_address    TEXT NOT NULL,
            scan_time     TIMESTAMP,
            open_count    INTEGER DEFAULT 0,
            filtered_count INTEGER DEFAULT 0,
            risk_level    TEXT DEFAULT 'low'
        )
    """)

    # ports table — one row per open port per host
    # cves stored as JSONB — preserves your existing CVE dict structure exactly
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ports (
            id          SERIAL PRIMARY KEY,
            host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            port_number INTEGER NOT NULL,
            service     TEXT,
            status      TEXT DEFAULT 'open',
            banner      TEXT,
            cves        JSONB DEFAULT '[]'::jsonb
        )
    """)

    # Index on ip_address for fast host lookups across scans
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_hosts_ip
        ON hosts(ip_address)
    """)

    # Index on scan_id for fast per-scan queries
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_ports_host
        ON ports(host_id)
    """)

    conn.commit()
    cur.close()
    conn.close()
    print("[*] Database initialized successfully")


# ─── CLIENT MANAGEMENT ────────────────────────────────────────────────────────

def add_client(name, network_range, contact_email="", notes=""):
    """
    Register a new client in the database.
    Returns the new client's ID.
    """
    conn = get_connection()
    cur  = conn.cursor()

    cur.execute("""
        INSERT INTO clients (name, contact_email, network_range, notes)
        VALUES (%s, %s, %s, %s)
        RETURNING id
    """, (name, contact_email, network_range, notes))

    client_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()

    print(f"[+] Client '{name}' added with ID {client_id}")
    return client_id


def list_clients():
    """Return all clients as a list of dicts."""
    conn = get_connection()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute("""
        SELECT c.id, c.name, c.contact_email, c.network_range, c.created_at,
               COUNT(s.id) as scan_count
        FROM clients c
        LEFT JOIN scans s ON s.client_id = c.id
        GROUP BY c.id
        ORDER BY c.name
    """)

    clients = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(r) for r in clients]


# ─── SAVING SCAN RESULTS ──────────────────────────────────────────────────────

def save_scan(enriched_results, network_range, client_id=None,
              scanner_version="v0.6"):
    """
    Save a complete scan result set to the database.

    enriched_results is the dict returned by run_cve_correlation() —
    the same structure that Stage 4 uses for HTML/JSON reports.
    We reuse it directly so nothing in the scanner needs to change.

    Returns the scan_id of the saved scan.
    """
    conn = get_connection()
    cur  = conn.cursor()

    # Count totals for the scan-level summary row
    total_hosts      = len(enriched_results)
    total_open_ports = sum(
        len(data.get("open", []))
        for data in enriched_results.values()
    )

    # Insert the scan record
    cur.execute("""
        INSERT INTO scans
            (client_id, network_range, scan_date, total_hosts,
             total_open_ports, scanner_version)
        VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING id
    """, (client_id, network_range, datetime.now(),
          total_hosts, total_open_ports, scanner_version))

    scan_id = cur.fetchone()[0]

    # Insert each host and its ports
    for ip, data in enriched_results.items():
        open_ports     = data.get("open", [])
        filtered_ports = data.get("filtered", [])
        banners        = data.get("banners", {})
        cves           = data.get("cves", {})

        # Determine risk level using same logic as HTML report
        dangerous      = {21, 23, 445, 3389, 5900}
        open_port_nums = {p[0] for p in open_ports}
        has_dangerous  = bool(dangerous & open_port_nums)

        risk_level = ("high"   if has_dangerous else
                      "medium" if open_ports else "low")

        # Parse scan_time string back to datetime
        try:
            scan_time = datetime.strptime(
                data.get("scan_time", ""),
                "%Y-%m-%d %H:%M:%S"
            )
        except ValueError:
            scan_time = datetime.now()

        # Insert host row
        cur.execute("""
            INSERT INTO hosts
                (scan_id, ip_address, scan_time, open_count,
                 filtered_count, risk_level)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (scan_id, ip, scan_time,
              len(open_ports), len(filtered_ports), risk_level))

        host_id = cur.fetchone()[0]

        # Insert one row per open port
        for port, service in open_ports:
            banner   = banners.get(port, "")
            cve_list = cves.get(port, [])

            cur.execute("""
                INSERT INTO ports
                    (host_id, port_number, service, status, banner, cves)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (host_id, port, service, "open",
                  banner, json.dumps(cve_list)))

        # Also insert filtered ports (useful for tracking firewall changes)
        for port, service in filtered_ports:
            cur.execute("""
                INSERT INTO ports
                    (host_id, port_number, service, status, banner, cves)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (host_id, port, service, "filtered", "", "[]"))

    conn.commit()
    cur.close()
    conn.close()

    print(f"[+] Scan saved to database (scan_id: {scan_id})")
    return scan_id


# ─── QUERYING ─────────────────────────────────────────────────────────────────

def get_scan_history(client_id=None, limit=10):
    """
    Return recent scans, optionally filtered by client.
    """
    conn = get_connection()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    if client_id:
        cur.execute("""
            SELECT s.*, c.name as client_name
            FROM scans s
            LEFT JOIN clients c ON c.id = s.client_id
            WHERE s.client_id = %s
            ORDER BY s.scan_date DESC
            LIMIT %s
        """, (client_id, limit))
    else:
        cur.execute("""
            SELECT s.*, c.name as client_name
            FROM scans s
            LEFT JOIN clients c ON c.id = s.client_id
            ORDER BY s.scan_date DESC
            LIMIT %s
        """, (limit,))

    scans = [dict(r) for r in cur.fetchall()]
    cur.close()
    conn.close()
    return scans


def get_scan_hosts(scan_id):
    """Return all hosts and their ports for a given scan."""
    conn = get_connection()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute("""
        SELECT h.*, 
               json_agg(
                   json_build_object(
                       'port',    p.port_number,
                       'service', p.service,
                       'status',  p.status,
                       'banner',  p.banner,
                       'cves',    p.cves
                   ) ORDER BY p.port_number
               ) as ports
        FROM hosts h
        LEFT JOIN ports p ON p.host_id = h.id
        WHERE h.scan_id = %s
        GROUP BY h.id
        ORDER BY h.ip_address
    """, (scan_id,))

    hosts = [dict(r) for r in cur.fetchall()]
    cur.close()
    conn.close()
    return hosts


def diff_scans(scan_id_old, scan_id_new):
    """
    Compare two scans and return what changed.

    This is the core value-add of the database layer — showing clients
    what changed between assessments. New open ports = new exposure.
    Closed ports = something was fixed or went down. New CVEs = new risk.

    Returns a dict with new_hosts, gone_hosts, and per-host port changes.
    """
    conn = get_connection()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    def get_host_ports(scan_id):
        """Helper — returns {ip: {port: {service, banner, status}}}"""
        cur.execute("""
            SELECT h.ip_address, p.port_number, p.service,
                   p.banner, p.status
            FROM hosts h
            JOIN ports p ON p.host_id = h.id
            WHERE h.scan_id = %s AND p.status = 'open'
        """, (scan_id,))
        result = {}
        for row in cur.fetchall():
            ip   = row["ip_address"]
            port = row["port_number"]
            if ip not in result:
                result[ip] = {}
            result[ip][port] = {
                "service": row["service"],
                "banner":  row["banner"],
            }
        return result

    old_data = get_host_ports(scan_id_old)
    new_data = get_host_ports(scan_id_new)

    cur.close()
    conn.close()

    old_hosts = set(old_data.keys())
    new_hosts = set(new_data.keys())

    diff = {
        "new_hosts":  list(new_hosts - old_hosts),   # hosts that appeared
        "gone_hosts": list(old_hosts - new_hosts),   # hosts that disappeared
        "changes":    {}                              # per-host port changes
    }

    # Check port changes on hosts present in both scans
    for ip in old_hosts & new_hosts:
        old_ports = set(old_data[ip].keys())
        new_ports = set(new_data[ip].keys())

        new_open    = new_ports - old_ports   # newly exposed ports
        now_closed  = old_ports - new_ports   # ports that closed

        if new_open or now_closed:
            diff["changes"][ip] = {
                "new_open": [
                    {"port": p, **new_data[ip][p]}
                    for p in sorted(new_open)
                ],
                "now_closed": [
                    {"port": p, **old_data[ip][p]}
                    for p in sorted(now_closed)
                ]
            }

    return diff


def find_exposed_service(port_number):
    """
    Find all hosts across all scans where a specific port was open.
    Useful for: 'show me every host that has RDP exposed'
    """
    conn = get_connection()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute("""
        SELECT h.ip_address, h.scan_time, h.risk_level,
               p.service, p.banner,
               s.network_range, s.scan_date,
               c.name as client_name
        FROM ports p
        JOIN hosts h ON h.id = p.host_id
        JOIN scans s ON s.id = h.scan_id
        LEFT JOIN clients c ON c.id = s.client_id
        WHERE p.port_number = %s AND p.status = 'open'
        ORDER BY s.scan_date DESC
    """, (port_number,))

    results = [dict(r) for r in cur.fetchall()]
    cur.close()
    conn.close()
    return results


def find_high_risk_hosts():
    """
    Return all hosts rated high risk from the most recent scan per network.
    Used for executive dashboard views.
    """
    conn = get_connection()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute("""
        SELECT DISTINCT ON (h.ip_address)
               h.ip_address, h.risk_level, h.open_count,
               s.scan_date, s.network_range,
               c.name as client_name
        FROM hosts h
        JOIN scans s ON s.id = h.scan_id
        LEFT JOIN clients c ON c.id = s.client_id
        WHERE h.risk_level = 'high'
        ORDER BY h.ip_address, s.scan_date DESC
    """)

    results = [dict(r) for r in cur.fetchall()]
    cur.close()
    conn.close()
    return results


# ─── PRINT HELPERS ────────────────────────────────────────────────────────────

def print_diff(diff):
    """Display diff report in the terminal."""
    print("\n" + "=" * 60)
    print("  SCAN DIFF REPORT")
    print("=" * 60)

    if diff["new_hosts"]:
        print(f"\n  NEW HOSTS ({len(diff['new_hosts'])}):")
        for ip in diff["new_hosts"]:
            print(f"    [+] {ip} — appeared since last scan")

    if diff["gone_hosts"]:
        print(f"\n  DISAPPEARED HOSTS ({len(diff['gone_hosts'])}):")
        for ip in diff["gone_hosts"]:
            print(f"    [-] {ip} — no longer responding")

    if diff["changes"]:
        print(f"\n  PORT CHANGES ({len(diff['changes'])} host(s)):")
        for ip, changes in diff["changes"].items():
            print(f"\n    {ip}:")
            for p in changes["new_open"]:
                print(f"      [+] Port {p['port']} ({p['service']}) "
                      f"— newly open")
            for p in changes["now_closed"]:
                print(f"      [-] Port {p['port']} ({p['service']}) "
                      f"— no longer open")

    if not any([diff["new_hosts"], diff["gone_hosts"], diff["changes"]]):
        print("\n  No changes detected between scans.")

    print("\n" + "=" * 60 + "\n")


def print_clients(clients):
    """Display client list in the terminal."""
    print("\n" + "=" * 60)
    print("  REGISTERED CLIENTS")
    print("=" * 60)
    if not clients:
        print("  No clients registered yet.")
        print("  Add one: python3 db.py --add-client")
    for c in clients:
        print(f"\n  [{c['id']}] {c['name']}")
        print(f"       Network:  {c['network_range']}")
        print(f"       Email:    {c['contact_email']}")
        print(f"       Scans:    {c['scan_count']}")
        print(f"       Added:    {c['created_at'].strftime('%Y-%m-%d')}")
    print("\n" + "=" * 60 + "\n")


# ─── CLI INTERFACE ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        prog="db.py",
        description="Network Scanner — Database Management"
    )
    parser.add_argument("--init",
        action="store_true",
        help="Initialize database tables")
    parser.add_argument("--add-client",
        action="store_true",
        help="Register a new client interactively")
    parser.add_argument("--list-clients",
        action="store_true",
        help="List all registered clients")
    parser.add_argument("--history",
        metavar="N",
        type=int,
        default=10,
        help="Show last N scans")
    parser.add_argument("--diff",
        nargs=2,
        metavar=("OLD_ID", "NEW_ID"),
        type=int,
        help="Compare two scans by ID")
    parser.add_argument("--find-port",
        metavar="PORT",
        type=int,
        help="Find all hosts with a specific port open")
    parser.add_argument("--high-risk",
        action="store_true",
        help="Show all high-risk hosts across all scans")

    args = parser.parse_args()

    if args.init:
        init_db()

    elif args.add_client:
        print("\n  Register New Client")
        print("  " + "-" * 30)
        name    = input("  Client name:     ").strip()
        network = input("  Network range:   ").strip()
        email   = input("  Contact email:   ").strip()
        notes   = input("  Notes (optional):").strip()
        add_client(name, network, email, notes)

    elif args.list_clients:
        clients = list_clients()
        print_clients(clients)

    elif args.history:
        scans = get_scan_history(limit=args.history)
        print(f"\n{'ID':<6} {'Date':<20} {'Network':<20} "
              f"{'Hosts':<8} {'Ports':<8} {'Client'}")
        print("-" * 75)
        for s in scans:
            client = s.get("client_name") or "Ad-hoc"
            print(f"{s['id']:<6} "
                  f"{str(s['scan_date'])[:19]:<20} "
                  f"{s['network_range']:<20} "
                  f"{s['total_hosts']:<8} "
                  f"{s['total_open_ports']:<8} "
                  f"{client}")

    elif args.diff:
        diff = diff_scans(args.diff[0], args.diff[1])
        print_diff(diff)

    elif args.find_port:
        results = find_exposed_service(args.find_port)
        print(f"\n  Hosts with port {args.find_port} open:")
        print("  " + "-" * 40)
        for r in results:
            client = r.get("client_name") or "Ad-hoc"
            print(f"  {r['ip_address']:<18} {r['service']:<12} "
                  f"{r['banner'][:40]:<42} [{client}]")

    elif args.high_risk:
        results = find_high_risk_hosts()
        print("\n  High Risk Hosts Across All Scans:")
        print("  " + "-" * 40)
        for r in results:
            client = r.get("client_name") or "Ad-hoc"
            print(f"  {r['ip_address']:<18} {r['open_count']} open ports  "
                  f"[{client}]  {str(r['scan_date'])[:10]}")

    else:
        parser.print_help()
