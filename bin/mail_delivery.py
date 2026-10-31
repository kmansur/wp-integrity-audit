"""Explicit, TLS-verified SMTP delivery of customer-only PDF reports."""
from __future__ import annotations
import configparser
from email.message import EmailMessage
from email.utils import parseaddr
from pathlib import Path
import re
import smtplib
import ssl
import stat


class MailDeliveryError(RuntimeError):
    """Safe operational failure without disclosing SMTP credentials."""


def _address(value: str) -> str:
    display, address = parseaddr(value)
    if (display or address != value or len(value) > 254 or
            not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_\x60{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}", value)
            or "\r" in value or "\n" in value):
        raise MailDeliveryError("Invalid sender or recipient address")
    return address


def _private_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise MailDeliveryError("SMTP configuration file must be a regular non-symlink file")
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise MailDeliveryError("SMTP configuration file must not be accessible by group or others")


def send_management_report(case: Path, recipient: str, config_path: Path) -> None:
    """Send only a completed management PDF through verified TLS transport."""
    _private_file(config_path)
    config = configparser.ConfigParser(interpolation=None)
    try:
        if not config.read(config_path, encoding="utf-8") or "smtp" not in config:
            raise MailDeliveryError("Missing SMTP configuration section")
        section = config["smtp"]
        host = section.get("host", "").strip()
        port = section.getint("port")
        security = section.get("security", "").strip().lower()
        sender = _address(section.get("from_address", "").strip())
        recipient = _address(recipient)
        username = section.get("username", "").strip()
        secret_path = Path(section.get("password_file", "")).expanduser()
        if not host or not 1 <= port <= 65535 or security not in ("starttls", "ssl"):
            raise MailDeliveryError("Invalid SMTP host, port or TLS mode")
        _private_file(secret_path)
        password = secret_path.read_text(encoding="utf-8").rstrip("\r\n")
        if not username or not password:
            raise MailDeliveryError("SMTP credentials are required")
        pdf = case / "management-report.pdf"
        if pdf.is_symlink() or not pdf.is_file():
            raise MailDeliveryError("A completed management PDF is required for email")
        with pdf.open("rb") as stream:
            payload = stream.read()
        if not payload.startswith(b"%PDF-"):
            raise MailDeliveryError("Management PDF is invalid")
        message = EmailMessage()
        message["From"] = sender
        message["To"] = recipient
        message["Subject"] = "WordPress integrity audit - management report"
        message.set_content("Attached is the management report for the WordPress audit. Please contact the responsible technical team for interpretation.")
        message.add_attachment(payload, maintype="application", subtype="pdf", filename="management-report.pdf")
        tls = ssl.create_default_context()
        if security == "ssl":
            with smtplib.SMTP_SSL(host, port, timeout=20, context=tls) as smtp:
                smtp.login(username, password)
                smtp.send_message(message)
        else:
            with smtplib.SMTP(host, port, timeout=20) as smtp:
                smtp.ehlo()
                smtp.starttls(context=tls)
                smtp.ehlo()
                smtp.login(username, password)
                smtp.send_message(message)
    except (configparser.Error, OSError, ValueError, UnicodeError, smtplib.SMTPException, ssl.SSLError) as error:
        raise MailDeliveryError("SMTP configuration or delivery failed; check restricted server logs") from None
