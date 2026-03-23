"""Verify email deliverability before tenant provisioning.

Checks DNS records (SPF, DKIM, DMARC) for the FROM_EMAIL domain and sends
a test email through the configured backend.

Usage:
    python -m app.cli.verify_email --to admin@example.com
"""

import argparse
import sys

import dns.resolver
import settings

# ---------------------------------------------------------------------------
# DNS record checks
# ---------------------------------------------------------------------------

# DKIM selectors to probe, keyed by backend name.
# Common selectors for well-known providers, plus generic fallbacks.
_DKIM_SELECTORS: dict[str, list[str]] = {
    "sendgrid": ["s1", "s2", "smtpapi"],
    "resend": ["resend"],
    "smtp": ["default", "selector1", "selector2", "google", "mail", "k1"],
}


def _domain_from_email(email: str) -> str:
    """Extract the domain part from an email address."""
    return email.rsplit("@", 1)[-1]


def _resolve_txt(name: str, timeout: float = 5.0) -> list[str]:
    """Resolve TXT records for *name*. Returns decoded strings or empty list."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        answers = resolver.resolve(name, "TXT")
        return [b"".join(rdata.strings).decode() for rdata in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout:
        return []


def check_spf(domain: str) -> tuple[str, str, str | None]:
    """Check for an SPF record on *domain*.

    Returns (status, message, record_or_None).
    status is one of PASS, WARN, MISSING.
    """
    records = _resolve_txt(domain)
    for record in records:
        if record.startswith("v=spf1"):
            return ("PASS", "SPF record found", record)
    return (
        "MISSING",
        "No SPF record. Mail servers cannot verify you are authorized to send "
        "from this domain. Recipients are more likely to mark messages as spam.",
        None,
    )


def check_dmarc(domain: str) -> tuple[str, str, str | None]:
    """Check for a DMARC record at _dmarc.<domain>.

    Returns (status, message, record_or_None).
    """
    records = _resolve_txt(f"_dmarc.{domain}")
    for record in records:
        if record.startswith("v=DMARC1"):
            # Extract the policy for reporting
            policy = "none"
            for part in record.split(";"):
                part = part.strip()
                if part.startswith("p="):
                    policy = part[2:]
                    break
            if policy == "none":
                return (
                    "WARN",
                    "DMARC record exists but policy is 'none' (monitoring only). "
                    "Consider setting p=quarantine or p=reject for enforcement.",
                    record,
                )
            return ("PASS", f"DMARC record found (policy: {policy})", record)
    return (
        "MISSING",
        "No DMARC record. Without DMARC, recipients cannot verify that SPF and DKIM "
        "align with your domain. This increases the chance of spoofing and spam filtering.",
        None,
    )


def check_dkim(domain: str, backend: str) -> tuple[str, str, list[str]]:
    """Check for DKIM records using selectors appropriate to *backend*.

    Returns (status, message, list_of_found_selectors).
    """
    selectors = _DKIM_SELECTORS.get(backend, _DKIM_SELECTORS["smtp"])
    found: list[str] = []
    for selector in selectors:
        name = f"{selector}._domainkey.{domain}"
        records = _resolve_txt(name)
        if records:
            found.append(selector)

    if found:
        return (
            "PASS",
            f"DKIM record(s) found for selector(s): {', '.join(found)}",
            found,
        )
    tried = ", ".join(selectors)
    return (
        "WARN",
        f"No DKIM records found (checked selectors: {tried}). "
        f"DKIM signing is usually configured at your email provider. "
        f"If your provider uses a different selector, this check may be a false negative.",
        found,
    )


# ---------------------------------------------------------------------------
# Email send test
# ---------------------------------------------------------------------------


def send_test_email(to_email: str) -> tuple[bool, str]:
    """Send a test email through the configured backend.

    Returns (success, detail_message).
    """
    from utils.email_backends import get_backend

    backend = get_backend()
    backend_name = settings.EMAIL_BACKEND.lower()

    subject = "WeftID — email verification test"
    html_body = (
        "<p>This is a test email from WeftID to verify that your email "
        "configuration is working correctly.</p>"
        "<p>If you received this message, email delivery is operational.</p>"
    )
    text_body = (
        "This is a test email from WeftID to verify that your email "
        "configuration is working correctly.\n\n"
        "If you received this message, email delivery is operational."
    )

    try:
        success = backend.send(to_email, subject, html_body, text_body)
    except Exception as exc:
        return False, f"{backend_name} backend raised an error: {exc}"

    if success:
        detail = f"Test email sent via {backend_name}"
        if backend_name == "smtp":
            tls_label = "STARTTLS" if settings.SMTP_TLS else "plain"
            detail += f" ({settings.SMTP_HOST}:{settings.SMTP_PORT}, {tls_label})"
        return True, detail

    return False, f"{backend_name} backend returned failure (check logs for details)"


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

_STATUS_SYMBOLS = {
    "PASS": "\u2714",  # ✔
    "WARN": "\u26a0",  # ⚠
    "MISSING": "\u2718",  # ✘
}


def _print_check(label: str, status: str, message: str, record: str | None = None) -> None:
    """Print a single check result."""
    symbol = _STATUS_SYMBOLS.get(status, "?")
    print(f"  {symbol} {label}: {status}")
    print(f"    {message}")
    if record:
        # Truncate very long records for readability
        display = record if len(record) <= 120 else record[:117] + "..."
        print(f"    Record: {display}")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(args: argparse.Namespace) -> int:
    """Run email verification checks. Returns exit code."""
    to_email = args.to
    domain = _domain_from_email(settings.FROM_EMAIL)
    backend = settings.EMAIL_BACKEND.lower()

    print(f"From address : {settings.FROM_EMAIL}")
    print(f"Domain       : {domain}")
    print(f"Backend      : {backend}")
    print(f"Recipient    : {to_email}")
    print()

    # --- DNS checks -------------------------------------------------------
    print("DNS checks")
    print("-" * 40)

    warnings = 0
    missing = 0

    spf_status, spf_msg, spf_record = check_spf(domain)
    _print_check("SPF", spf_status, spf_msg, spf_record)
    if spf_status == "WARN":
        warnings += 1
    elif spf_status == "MISSING":
        missing += 1

    dmarc_status, dmarc_msg, dmarc_record = check_dmarc(domain)
    _print_check("DMARC", dmarc_status, dmarc_msg, dmarc_record)
    if dmarc_status == "WARN":
        warnings += 1
    elif dmarc_status == "MISSING":
        missing += 1

    dkim_status, dkim_msg, _dkim_selectors_found = check_dkim(domain, backend)
    _print_check("DKIM", dkim_status, dkim_msg)
    if dkim_status == "WARN":
        warnings += 1
    elif dkim_status == "MISSING":
        missing += 1

    # --- Send test email ---------------------------------------------------
    print("Email delivery")
    print("-" * 40)

    email_ok, email_detail = send_test_email(to_email)
    if email_ok:
        print(f"  \u2714 {email_detail}")
    else:
        print(f"  \u2718 FAILED: {email_detail}")
    print()

    # --- Summary -----------------------------------------------------------
    issues: list[str] = []
    if warnings:
        issues.append(f"{warnings} warning{'s' if warnings != 1 else ''}")
    if missing:
        issues.append(f"{missing} missing record{'s' if missing != 1 else ''}")

    if email_ok:
        if issues:
            print(f"Email sent successfully. {', '.join(issues)}.")
        else:
            print("Email sent successfully. All DNS checks passed.")
        return 0
    else:
        if issues:
            print(f"Email delivery failed. {', '.join(issues)}.")
        else:
            print("Email delivery failed.")
        return 1


def cli() -> int:
    """Parse arguments and run verification."""
    parser = argparse.ArgumentParser(description="Verify email deliverability for WeftID")
    parser.add_argument(
        "--to",
        required=True,
        help="Recipient email address for the test message",
    )
    args = parser.parse_args()

    if "@" not in args.to:
        print("Error: invalid email address", file=sys.stderr)
        return 1

    return main(args)


if __name__ == "__main__":
    sys.exit(cli())
