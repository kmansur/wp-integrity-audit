"""Envio SMTP explícito do relatório PDF do cliente com TLS verificado."""
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
    """Erro operacional sem exposição de credenciais SMTP."""


def _address(value: str) -> str:
    display, address = parseaddr(value)
    if (display or address != value or len(value) > 254 or
            not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_\x60{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}", value)
            or "\r" in value or "\n" in value):
        raise MailDeliveryError("Endereço de remetente ou destinatário inválido")
    return address


def _private_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise MailDeliveryError("O arquivo de configuração SMTP deve ser regular e não pode ser link simbólico")
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise MailDeliveryError("O arquivo de configuração SMTP não pode ser acessível a grupo ou outros usuários")


def send_management_report(case: Path, recipient: str, config_path: Path) -> None:
    """Enviar somente o PDF gerencial concluído utilizando TLS verificado."""
    _private_file(config_path)
    config = configparser.ConfigParser(interpolation=None)
    try:
        if not config.read(config_path, encoding="utf-8") or "smtp" not in config:
            raise MailDeliveryError("Seção SMTP ausente na configuração")
        section = config["smtp"]
        host = section.get("host", "").strip()
        port = section.getint("port")
        security = section.get("security", "").strip().lower()
        sender = _address(section.get("from_address", "").strip())
        recipient = _address(recipient)
        username = section.get("username", "").strip()
        secret_path = Path(section.get("password_file", "")).expanduser()
        if not host or not 1 <= port <= 65535 or security not in ("starttls", "ssl"):
            raise MailDeliveryError("Servidor, porta ou modalidade TLS inválidos")
        _private_file(secret_path)
        password = secret_path.read_text(encoding="utf-8").rstrip("\r\n")
        if not username or not password:
            raise MailDeliveryError("As credenciais SMTP são obrigatórias")
        pdf = case / "management-report.pdf"
        if pdf.is_symlink() or not pdf.is_file():
            raise MailDeliveryError("É necessário um PDF gerencial concluído para enviar o e-mail")
        with pdf.open("rb") as stream:
            payload = stream.read()
        if not payload.startswith(b"%PDF-"):
            raise MailDeliveryError("O PDF gerencial é inválido")
        message = EmailMessage()
        message["From"] = sender
        message["To"] = recipient
        message["Subject"] = "Auditoria de integridade WordPress - relatório gerencial"
        message.set_content("Segue em anexo o relatório gerencial da auditoria de integridade do WordPress. Em caso de dúvidas sobre os resultados, entre em contato com a equipe técnica responsável.")
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
        raise MailDeliveryError("Falha na configuração ou no envio SMTP; verifique os logs restritos do servidor") from None
