"""Envio SMTP explícito do relatório PDF do cliente com TLS verificado."""
from __future__ import annotations
import configparser
import os
import socket
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


def _ler_regular_limitado(path: Path, limite: int, *, privado: bool = False) -> bytes:
    """Ler arquivo regular sem seguir links simbólicos, com limite de tamanho."""
    try:
        descritor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descritor, "rb") as arquivo:
            metadados = os.fstat(arquivo.fileno())
            if not stat.S_ISREG(metadados.st_mode) or metadados.st_size > limite:
                raise MailDeliveryError("Arquivo do envio inválido ou acima do limite permitido")
            if privado and metadados.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise MailDeliveryError("Arquivo confidencial com permissões excessivas")
            conteudo = arquivo.read(limite + 1)
            if len(conteudo) > limite:
                raise MailDeliveryError("Arquivo do envio acima do limite permitido")
            return conteudo
    except OSError as error:
        raise MailDeliveryError("Não foi possível abrir um arquivo do envio com segurança") from error


def _erro_smtp(error: Exception) -> str:
    """Detalhar a etapa sem revelar endereços internos, credenciais ou respostas completas."""
    if isinstance(error, smtplib.SMTPAuthenticationError):
        return f"Autenticação SMTP recusada (código {error.smtp_code}); confira usuário e senha"
    if isinstance(error, smtplib.SMTPNotSupportedError):
        return "O servidor SMTP não oferece o recurso TLS ou autenticação exigido"
    if isinstance(error, ssl.SSLCertVerificationError):
        return "Validação do certificado TLS SMTP falhou; confira DNS, certificado e relógio"
    if isinstance(error, ssl.SSLError):
        return "Falha na negociação TLS com o servidor SMTP"
    if isinstance(error, smtplib.SMTPRecipientsRefused):
        return "O servidor SMTP recusou o destinatário"
    if isinstance(error, smtplib.SMTPSenderRefused):
        return f"O servidor SMTP recusou o remetente (código {error.smtp_code})"
    if isinstance(error, smtplib.SMTPResponseException):
        return f"O servidor SMTP retornou erro (código {error.smtp_code})"
    if isinstance(error, (socket.timeout, TimeoutError)):
        return "Tempo limite excedido na comunicação SMTP"
    if isinstance(error, socket.gaierror):
        return "Não foi possível resolver o nome DNS do servidor SMTP"
    if isinstance(error, ConnectionRefusedError):
        return "Conexão SMTP recusada; confira servidor, porta e firewall"
    if isinstance(error, OSError):
        return "Falha de rede ou conexão com o servidor SMTP"
    if isinstance(error, (configparser.Error, ValueError, UnicodeError)):
        return "Configuração SMTP inválida; confira campos, codificação e porta"
    if isinstance(error, smtplib.SMTPException):
        return "Falha de protocolo ou autenticação no servidor SMTP"
    return "Falha desconhecida na comunicação SMTP"


def send_management_report(case: Path, recipient: str, config_path: Path) -> None:
    """Enviar PDF gerencial via TLS verificado; sucesso indica aceite SMTP, não entrega."""
    _private_file(config_path)
    config = configparser.ConfigParser(interpolation=None)
    try:
        config.read_string(_ler_regular_limitado(config_path, 64 * 1024, privado=True).decode("utf-8"))
        if "smtp" not in config:
            raise MailDeliveryError("Seção [smtp] ausente na configuração")
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
        if not secret_path.is_absolute():
            raise MailDeliveryError("A senha SMTP exige caminho absoluto")
        _private_file(secret_path)
        password = _ler_regular_limitado(secret_path, 4096, privado=True).decode("utf-8").rstrip("\r\n")
        if not username or not password:
            raise MailDeliveryError("As credenciais SMTP são obrigatórias")
        pdf = case / "management-report.pdf"
        if pdf.is_symlink() or not pdf.is_file():
            raise MailDeliveryError("É necessário um PDF gerencial concluído para enviar o e-mail")
        payload = _ler_regular_limitado(pdf, 20 * 1024 * 1024)
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
                recusados = smtp.send_message(message)
        else:
            with smtplib.SMTP(host, port, timeout=20) as smtp:
                smtp.ehlo()
                if not smtp.has_extn("starttls"):
                    raise MailDeliveryError("O servidor não anunciou STARTTLS; envio cancelado sem transmitir credenciais")
                smtp.starttls(context=tls)
                smtp.ehlo()
                smtp.login(username, password)
                recusados = smtp.send_message(message)
        if recusados:
            raise MailDeliveryError("O servidor SMTP recusou um ou mais destinatários")
    except MailDeliveryError:
        raise
    except (configparser.Error, OSError, ValueError, UnicodeError, smtplib.SMTPException, ssl.SSLError) as error:
        raise MailDeliveryError(_erro_smtp(error)) from None
