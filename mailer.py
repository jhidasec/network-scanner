#!/usr/bin/env python3
"""
Network Scanner — Email Delivery
Sends scan reports to clients automatically after each scan.
Loads credentials from .env — never hardcoded, never committed.
"""

import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text      import MIMEText
from email.mime.base      import MIMEBase
from email                import encoders
from pathlib              import Path
from datetime             import datetime


# ─── LOAD CREDENTIALS ────────────────────────────────────────────────────────

def load_env():
    """
    Load email credentials from .env file.
    .env is gitignored — credentials never appear in the public repo.

    Format:
        EMAIL_ADDRESS=jhida.sec@gmail.com
        EMAIL_PASSWORD=your_app_password_here
    """
    env_path = Path(__file__).parent / ".env"

    if not env_path.exists():
        print("[!] .env file not found")
        print("[!] Create it with EMAIL_ADDRESS and EMAIL_PASSWORD")
        return None, None

    creds = {}
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, val = line.split("=", 1)
                creds[key.strip()] = val.strip()

    email    = creds.get("EMAIL_ADDRESS")
    password = creds.get("EMAIL_PASSWORD")

    if not email or not password:
        print("[!] EMAIL_ADDRESS or EMAIL_PASSWORD missing from .env")
        return None, None

    return email, password


# ─── EMAIL BUILDER ────────────────────────────────────────────────────────────

def build_email(sender, recipient, client_name, network_range,
                scan_date, pdf_path, total_hosts, total_ports,
                dangerous_count):
    """
    Build a professional email with the PDF report attached.

    Returns a MIMEMultipart message object ready to send.
    """
    msg = MIMEMultipart()
    msg["From"]    = f"Jeffrey Hidalgo Security <{sender}>"
    msg["To"]      = recipient
    msg["Subject"] = (f"Network Security Audit Report — "
                      f"{network_range} — {scan_date}")

    # ── Plain text body ───────────────────────────────────────────────────────
    # Professional but readable — not overly formal.
    # Clients should be able to skim this in 30 seconds.
    if dangerous_count > 0:
        risk_summary = (f"{dangerous_count} high-risk service(s) were "
                        f"detected that require immediate attention.")
        action_line  = ("Please review the attached report and contact "
                        "me to discuss remediation steps.")
    else:
        risk_summary = ("No high-risk services were detected. The network "
                        "presents a low attack surface based on current "
                        "exposure.")
        action_line  = ("Please review the attached report. "
                        "Feel free to reach out with any questions.")

    body = f"""Hi {client_name},

Please find attached your network security audit report for {network_range}, conducted on {scan_date}.

SUMMARY
-------
Network Scanned:   {network_range}
Hosts Discovered:  {total_hosts}
Open Ports Found:  {total_ports}
Risk Assessment:   {risk_summary}

{action_line}

The full report is attached as a PDF. It includes:
  - Executive summary with overall risk rating
  - Per-host findings with open ports and service versions
  - CVE correlation for identified services
  - Specific remediation recommendations

This assessment covers TCP ports only. Web application testing, \
authenticated scanning, and physical security are outside the scope \
of this report. A more comprehensive assessment can be arranged \
separately.

Best regards,
Jeffrey Hidalgo
Security Consultant
jhida.sec@gmail.com

---
CONFIDENTIAL — This report is prepared exclusively for {client_name}.
Do not distribute without authorization.
AUTHORIZED USE ONLY — Scan conducted with explicit permission.
"""

    msg.attach(MIMEText(body, "plain"))

    # ── PDF Attachment ────────────────────────────────────────────────────────
    if pdf_path and Path(pdf_path).exists():
        with open(pdf_path, "rb") as f:
            attachment = MIMEBase("application", "octet-stream")
            attachment.set_payload(f.read())

        # Base64 encode the binary PDF for email transport
        encoders.encode_base64(attachment)

        # Set the filename that appears in the recipient's email client
        pdf_filename = Path(pdf_path).name
        attachment.add_header(
            "Content-Disposition",
            f"attachment; filename={pdf_filename}"
        )
        msg.attach(attachment)
        print(f"  [+] Attached: {pdf_filename}")
    else:
        print(f"  [!] PDF not found at {pdf_path} — sending without attachment")

    return msg


# ─── SEND EMAIL ───────────────────────────────────────────────────────────────

def send_report(recipient_email, client_name, network_range,
                pdf_path, total_hosts=0, total_ports=0,
                dangerous_count=0):
    """
    Send a scan report email to a client.

    Uses Gmail SMTP with TLS. Credentials loaded from .env.
    Never call this with hardcoded credentials.

    Returns True on success, False on failure.
    """
    sender, password = load_env()
    if not sender or not password:
        print("[!] Cannot send email — credentials not configured")
        return False

    scan_date = datetime.now().strftime("%Y-%m-%d")

    print(f"\n[*] Sending report to {recipient_email}")
    print(f"  [~] Building email for {client_name}...")

    msg = build_email(
        sender         = sender,
        recipient      = recipient_email,
        client_name    = client_name,
        network_range  = network_range,
        scan_date      = scan_date,
        pdf_path       = pdf_path,
        total_hosts    = total_hosts,
        total_ports    = total_ports,
        dangerous_count = dangerous_count
    )

    try:
        # Connect to Gmail's SMTP server on port 587 (TLS/STARTTLS)
        # Port 587 is the standard for authenticated email submission.
        # Port 465 uses SSL directly — both work, 587 is more universal.
        print(f"  [~] Connecting to Gmail SMTP...")
        with smtplib.SMTP("smtp.gmail.com", 587) as server:

            # EHLO identifies our client to the server
            server.ehlo()

            # STARTTLS upgrades the connection to encrypted TLS
            # Everything after this point is encrypted
            server.starttls()
            server.ehlo()

            # Authenticate with App Password
            # This is why we use App Passwords — your real Gmail
            # password never touches this script
            server.login(sender, password)

            # Send the message
            server.sendmail(sender, recipient_email, msg.as_string())

        print(f"  [+] Report sent successfully to {recipient_email}")
        return True

    except smtplib.SMTPAuthenticationError:
        print("[!] Authentication failed — check your App Password in .env")
        print("[!] Make sure 2-Step Verification is enabled on Gmail")
        return False

    except smtplib.SMTPException as e:
        print(f"[!] SMTP error: {e}")
        return False

    except Exception as e:
        print(f"[!] Failed to send email: {e}")
        return False


# ─── TEST ─────────────────────────────────────────────────────────────────────

def test_connection():
    """
    Test Gmail SMTP connection without sending a full email.
    Run this first to verify credentials work before live use.
    """
    sender, password = load_env()
    if not sender or not password:
        return False

    print(f"\n[*] Testing Gmail SMTP connection for {sender}...")
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(sender, password)
        print("[+] Connection successful — credentials are working")
        return True
    except smtplib.SMTPAuthenticationError:
        print("[!] Authentication failed — check App Password in .env")
        return False
    except Exception as e:
        print(f"[!] Connection failed: {e}")
        return False


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        prog="mailer.py",
        description="Network Scanner — Email Delivery"
    )
    parser.add_argument("--test",
        action="store_true",
        help="Test Gmail SMTP connection")
    parser.add_argument("--send",
        action="store_true",
        help="Send a report manually")
    parser.add_argument("--to",
        metavar="EMAIL",
        help="Recipient email address")
    parser.add_argument("--client",
        metavar="NAME",
        help="Client name for email body")
    parser.add_argument("--network",
        metavar="RANGE",
        help="Network range that was scanned")
    parser.add_argument("--pdf",
        metavar="PATH",
        help="Path to PDF report to attach")

    args = parser.parse_args()

    if args.test:
        test_connection()

    elif args.send:
        if not all([args.to, args.client, args.network, args.pdf]):
            print("[!] --send requires --to, --client, --network, --pdf")
        else:
            send_report(
                recipient_email = args.to,
                client_name     = args.client,
                network_range   = args.network,
                pdf_path        = args.pdf
            )
    else:
        parser.print_help()
