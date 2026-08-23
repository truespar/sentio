#!/usr/bin/env python3
"""Minimal SMTP client for exercising a running Sentio stack from the host.

Standalone and dependency-free - useful on its own, not just from run-e2e.sh:

    # plain inbound delivery to the MX listener
    scripts/e2e/smtp-send.py --port 2525 \
        --from alice@sender.test --to support@inbound.test \
        --subject 'hello' --body 'test body'

    # authenticated submission
    scripts/e2e/smtp-send.py --port 5587 --starttls \
        --auth-user someuser --auth-pass secret \
        --from alice@sender.test --to bob@elsewhere.test --subject hi

Exits 0 on a delivered message, 1 on any SMTP-level rejection, printing the
server's reply so failures are diagnosable rather than just "it didn't work".
"""
import argparse
import smtplib
import sys
import uuid
from email.message import EmailMessage
from email.utils import formatdate, make_msgid


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=2525)
    ap.add_argument("--from", dest="sender", required=True)
    ap.add_argument("--to", dest="rcpt", required=True, action="append",
                    help="repeatable")
    ap.add_argument("--subject", default="sentio e2e")
    ap.add_argument("--body", default="sentio e2e test body")
    ap.add_argument("--header", action="append", default=[],
                    metavar="NAME:VALUE", help="extra header, repeatable")
    ap.add_argument("--auth-user")
    ap.add_argument("--auth-pass")
    ap.add_argument("--starttls", action="store_true")
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    msg = EmailMessage()
    msg["From"] = args.sender
    msg["To"] = ", ".join(args.rcpt)
    msg["Subject"] = args.subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="e2e.test")
    # Correlation id so a test can find exactly its own message in a shared sink.
    msg["X-Sentio-E2E"] = uuid.uuid4().hex
    for h in args.header:
        name, _, value = h.partition(":")
        msg[name.strip()] = value.strip()
    msg.set_content(args.body)

    try:
        with smtplib.SMTP(args.host, args.port, timeout=args.timeout) as s:
            if args.verbose:
                s.set_debuglevel(1)
            s.ehlo()
            if args.starttls:
                s.starttls()
                s.ehlo()
            if args.auth_user:
                s.login(args.auth_user, args.auth_pass or "")
            s.send_message(msg, from_addr=args.sender, to_addrs=args.rcpt)
    except smtplib.SMTPResponseException as e:
        detail = e.smtp_error.decode(errors="replace") if isinstance(
            e.smtp_error, bytes) else e.smtp_error
        print(f"SMTP {e.smtp_code}: {detail}", file=sys.stderr)
        return 1
    except (OSError, smtplib.SMTPException) as e:
        print(f"connection failed: {e}", file=sys.stderr)
        return 1

    # Consumed by run-e2e.sh to correlate this send with what the sink received.
    print(msg["X-Sentio-E2E"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
