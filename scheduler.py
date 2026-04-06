#!/usr/bin/env python3
"""
Network Scanner — Scheduler
Manages automated recurring scans per client.
Integrates with cron for scheduling and mailer.py for delivery.
"""

import subprocess
import sys
import os
from pathlib  import Path
from datetime import datetime

# Import database functions
try:
    from db import get_connection, list_clients, add_client
    DB_AVAILABLE = True
except ImportError:
    DB_AVAILABLE = False

# Import mailer
try:
    from mailer import send_report
    MAILER_AVAILABLE = True
except ImportError:
    MAILER_AVAILABLE = False


# ─── PATHS ───────────────────────────────────────────────────────────────────

SCANNER_DIR  = Path(__file__).parent
SCANNER_PATH = SCANNER_DIR / "scanner.py"
REPORTS_DIR  = SCANNER_DIR / "reports"
LOG_PATH     = SCANNER_DIR / "scheduler.log"


# ─── LOGGING ─────────────────────────────────────────────────────────────────

def log(message):
    """
    Write a timestamped log entry to scheduler.log and print to terminal.
    When cron runs this script overnight, you need logs to see what happened.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry     = f"[{timestamp}] {message}"
    print(entry)

    with open(LOG_PATH, "a") as f:
        f.write(entry + "\n")


# ─── SCAN RUNNER ─────────────────────────────────────────────────────────────

def run_scan(client_id, client_name, network_range, contact_email,
             skip_cve=False, skip_pdf=False):
    """
    Run scanner.py for a specific client and return the PDF path.

    Uses subprocess to call scanner.py as a separate process —
    same as running it from the terminal, but triggered programmatically.
    stdout and stderr are captured to the log file.

    Returns the PDF path if generated, None otherwise.
    """
    log(f"Starting scan for client '{client_name}' ({network_range})")

    # Build output directory for this client's scans
    # Keeps each client's reports separated
    safe_name  = client_name.lower().replace(" ", "_")
    output_dir = REPORTS_DIR / safe_name
    output_dir.mkdir(parents=True, exist_ok=True)

    # Build the scanner command
    cmd = [
        sys.executable,          # python3
        str(SCANNER_PATH),
        network_range,
        "--output", str(output_dir),
        "--name",    "Jeffrey Hidalgo",
        "--contact", "jhida.sec@gmail.com",
        "--client-id", str(client_id),
    ]

    if skip_cve:
        cmd.append("--no-cve")
    if skip_pdf:
        cmd.append("--no-pdf")

    log(f"Running: {' '.join(cmd)}")

    try:
        # Run the scanner — capture output to log
        # timeout=3600 means give up after 1 hour (handles hung scans)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600
        )

        # Write scanner output to log
        if result.stdout:
            for line in result.stdout.strip().split("\n"):
                log(f"  {line}")
        if result.stderr:
            for line in result.stderr.strip().split("\n"):
                log(f"  [stderr] {line}")

        if result.returncode != 0:
            log(f"[!] Scanner exited with code {result.returncode}")
            return None

        log(f"Scan complete for '{client_name}'")

        # Find the most recently created PDF in the output directory
        # This is what we'll attach to the email
        if not skip_pdf:
            pdfs = sorted(output_dir.glob("audit_report_*.pdf"),
                         key=lambda p: p.stat().st_mtime,
                         reverse=True)
            if pdfs:
                log(f"PDF report: {pdfs[0]}")
                return pdfs[0]
            else:
                log("[!] No PDF found in output directory")
                return None

        return None

    except subprocess.TimeoutExpired:
        log(f"[!] Scan timed out for '{client_name}' after 1 hour")
        return None
    except Exception as e:
        log(f"[!] Error running scan for '{client_name}': {e}")
        return None


# ─── EMAIL DELIVERY ───────────────────────────────────────────────────────────

def deliver_report(client_name, contact_email, network_range, pdf_path):
    """
    Send the PDF report to the client via email.
    Only called if mailer.py is available and a PDF was generated.
    """
    if not MAILER_AVAILABLE:
        log("[!] mailer.py not available — skipping email delivery")
        return False

    if not pdf_path or not Path(pdf_path).exists():
        log("[!] No PDF to send — skipping email delivery")
        return False

    if not contact_email:
        log("[!] No contact email for client — skipping delivery")
        return False

    log(f"Sending report to {contact_email}...")

    success = send_report(
        recipient_email = contact_email,
        client_name     = client_name,
        network_range   = network_range,
        pdf_path        = str(pdf_path)
    )

    if success:
        log(f"Report delivered to {contact_email}")
    else:
        log(f"[!] Failed to deliver report to {contact_email}")

    return success


# ─── FULL SCHEDULED RUN ───────────────────────────────────────────────────────

def scheduled_scan(client_id):
    """
    Full automated pipeline for a single client:
    1. Look up client details from database
    2. Run the scanner
    3. Email the PDF report

    This is what cron calls — one client ID per cron job entry.
    """
    if not DB_AVAILABLE:
        log("[!] Database not available — cannot look up client")
        return False

    # Look up client details from database
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("""
        SELECT id, name, contact_email, network_range
        FROM clients WHERE id = %s
    """, (client_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        log(f"[!] No client found with ID {client_id}")
        return False

    client_id, client_name, contact_email, network_range = row

    log(f"{'='*50}")
    log(f"Scheduled scan — Client: {client_name} | Network: {network_range}")
    log(f"{'='*50}")

    # Run the scan
    pdf_path = run_scan(
        client_id     = client_id,
        client_name   = client_name,
        network_range = network_range,
        contact_email = contact_email
    )

    # Deliver the report
    deliver_report(
        client_name   = client_name,
        contact_email = contact_email,
        network_range = network_range,
        pdf_path      = pdf_path
    )

    log(f"Scheduled run complete for '{client_name}'")
    return True


# ─── CRON MANAGEMENT ─────────────────────────────────────────────────────────

def add_cron_job(client_id, schedule="0 2 * * 1"):
    """
    Add a cron job for a client.

    Default schedule: every Monday at 2:00am
    Common schedules:
        "0 2 * * 1"     = weekly, Monday 2am
        "0 2 1 * *"     = monthly, 1st of month 2am
        "0 2 * * 1,4"   = twice weekly, Mon + Thu 2am

    Cron format: minute hour day month weekday
    """
    python_path  = sys.executable
    scheduler_path = str(Path(__file__).resolve())

    # The command cron will run
    cron_command = (f"{schedule} {python_path} {scheduler_path} "
                    f"--run {client_id} "
                    f">> {LOG_PATH} 2>&1")

    # Read existing crontab
    try:
        result = subprocess.run(
            ["crontab", "-l"],
            capture_output=True, text=True
        )
        existing = result.stdout
    except Exception:
        existing = ""

    # Check if this client already has a cron job
    if f"--run {client_id}" in existing:
        log(f"[!] Cron job for client {client_id} already exists")
        log("[!] Remove it first with --remove-cron")
        return False

    # Add the new job
    new_crontab = existing.rstrip() + f"\n{cron_command}\n"

    try:
        proc = subprocess.run(
            ["crontab", "-"],
            input=new_crontab,
            capture_output=True,
            text=True
        )
        if proc.returncode == 0:
            log(f"[+] Cron job added for client {client_id}")
            log(f"    Schedule: {schedule}")
            log(f"    Command:  {cron_command}")
            return True
        else:
            log(f"[!] Failed to add cron job: {proc.stderr}")
            return False
    except Exception as e:
        log(f"[!] Error adding cron job: {e}")
        return False


def remove_cron_job(client_id):
    """Remove the cron job for a specific client."""
    try:
        result = subprocess.run(
            ["crontab", "-l"],
            capture_output=True, text=True
        )
        existing = result.stdout
    except Exception:
        log("[!] No existing crontab")
        return False

    # Filter out lines containing this client's ID
    lines    = existing.split("\n")
    filtered = [l for l in lines
                if f"--run {client_id}" not in l]
    new_crontab = "\n".join(filtered)

    try:
        subprocess.run(
            ["crontab", "-"],
            input=new_crontab,
            capture_output=True,
            text=True
        )
        log(f"[+] Cron job removed for client {client_id}")
        return True
    except Exception as e:
        log(f"[!] Error removing cron job: {e}")
        return False


def list_cron_jobs():
    """Show all current cron jobs for the scanner."""
    try:
        result = subprocess.run(
            ["crontab", "-l"],
            capture_output=True, text=True
        )
        lines = [l for l in result.stdout.split("\n")
                 if "scheduler.py" in l]

        if not lines:
            print("\n  No scheduled scans configured.\n")
        else:
            print("\n  Scheduled Scans:")
            print("  " + "-" * 50)
            for line in lines:
                print(f"  {line}")
            print()
    except Exception as e:
        log(f"[!] Error reading crontab: {e}")


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        prog="scheduler.py",
        description="Network Scanner — Automated Scheduling"
    )
    parser.add_argument("--run",
        metavar="CLIENT_ID",
        type=int,
        help="Run a scheduled scan for a client (called by cron)")
    parser.add_argument("--add-schedule",
        metavar="CLIENT_ID",
        type=int,
        help="Add a cron job for a client")
    parser.add_argument("--schedule",
        metavar="CRON",
        default="0 2 * * 1",
        help="Cron schedule (default: '0 2 * * 1' = Monday 2am)")
    parser.add_argument("--remove-schedule",
        metavar="CLIENT_ID",
        type=int,
        help="Remove the cron job for a client")
    parser.add_argument("--list",
        action="store_true",
        help="List all scheduled scans")
    parser.add_argument("--test-run",
        metavar="CLIENT_ID",
        type=int,
        help="Run a scan now (same as scheduled but immediate)")

    args = parser.parse_args()

    if args.run:
        scheduled_scan(args.run)

    elif args.test_run:
        log(f"Manual test run for client {args.test_run}")
        scheduled_scan(args.test_run)

    elif args.add_schedule:
        add_cron_job(args.add_schedule, args.schedule)

    elif args.remove_schedule:
        remove_cron_job(args.remove_schedule)

    elif args.list:
        list_cron_jobs()

    else:
        parser.print_help()
