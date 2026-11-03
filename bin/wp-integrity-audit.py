#!/usr/bin/env python3
"""WordPress incident audit and recovery for Debian/Ubuntu (Python implementation).

Read-only by default for the WordPress installation. Local evidence files are
always written. Mutating modes require explicit interactive confirmation.
No WordPress PHP code or WP-CLI commands are executed.
"""
from __future__ import annotations

import argparse
import contextlib
import csv
import io
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import component_versions
import report_export
import mail_delivery
import re
import secrets
import shutil
import stat
import subprocess
import tarfile
import tempfile
import urllib.parse
import urllib.request
import zipfile

VERSION = "0.22.1"
IOC = re.compile(r"SC_ADV_BEGIN|--sc-cli|--sc-succ|trace-inspector-pad|cipher-feeder|_sc_fpc|sc_cron_guard|sc_persist_manifest|sc_own_manifest|function ceya")
PATTERN_NAMES = (".sc_", ".gr_", ".gk_", ".kk_", ".wp-object-cache")
SCRIPT_EXTENSIONS = {".php", ".phtml", ".phar", ".inc", ".php5", ".php7", ".php8", ".pht", ".phps"}
GENERIC_WEB_SHELL = re.compile(
    rb"eval\s*\(\s*base64_decode\s*\(|gzinflate\s*\(\s*base64_decode\s*\("
    rb"|(?:assert|eval)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b"
    rb"|(?:system|shell_exec|passthru)\s*\(\s*\$_(?:GET|POST|REQUEST)\b",
    re.I)

SENSITIVE = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*[^\s,;]+")
LONG_VALUE = re.compile(r"(?<![\w])[A-Za-z0-9_/-]{40,}(?![\w])")
# Never apply arbitrary high-entropy redaction to filesystem paths: it
# destroys evidentiary context and makes file identification impossible.
DB_KEY = re.compile(r"""define\s*\(\s*['"](?P<name>DB_NAME|DB_USER|DB_PASSWORD|DB_HOST)['"]\s*,\s*(?P<quote>['"])(?P<value>(?:\\.|(?!(?P=quote)).)*)(?P=quote)\s*\)""", re.S)
SQL_TABLE_PREFIX = re.compile(r"\$table_prefix\s*=\s*['\"]([A-Za-z0-9_]+)['\"]")

class AuditError(RuntimeError):
    """A precondition, integrity, or safety check failed."""

def redact(value: object) -> str:
    """Best-effort redaction. Never distribute reports without manual review."""
    value = str(value)
    value = SENSITIVE.sub(lambda m: m.group(1) + "=[REDACTED]", value)
    value = LONG_VALUE.sub("[LONG_VALUE_REDACTED]", value)
    value = re.sub(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)", "[IP_REDACTED]", value)
    return value[:240]

def sanitize_relative_path(path: str) -> str:
    """Preserve relative evidence paths while masking explicit sensitive values."""
    value = SENSITIVE.sub(lambda m: m.group(1) + "=[REDACTED]", path)
    value = re.sub(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)", "[IP_REDACTED]", value)
    return value.replace("|", "/").replace("\n", " ").replace("\r", " ")



def safe_option_name(value: str) -> str:
    """Preserve exact WordPress option identifiers without entropy masking."""
    return value.replace("\n", " ").replace("\r", " ").replace("|", "/")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            digest.update(block)
    return digest.hexdigest()

def ensure_private_dir(path: Path) -> Path:
    """Reject symlink case roots and ensure only the owner can enter."""
    if path.is_symlink():
        raise AuditError(f"Refusing symlink directory: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
    return path.resolve()

def write_private(path: Path, text: str) -> None:
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(text)

def run(argv: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Execute a fixed argument vector, never through a shell."""
    return subprocess.run(argv, check=True, text=True, **kwargs)

def ask(message: str) -> None:
    if not sys.stdin.isatty() or input(message + " [type YES]: ").strip() != "YES":
        raise AuditError("Operator confirmation denied")

def parse_wordpress(path: Path) -> tuple[dict[str, str], str]:
    """Parse only literal wp-config.php values; do not evaluate PHP."""
    data = path.read_text(encoding="utf-8", errors="replace")
    values = {m.group("name"): m.group("value").replace("\\'", "'").replace('\\\"', '"').replace("\\\\", "\\") for m in DB_KEY.finditer(data)}
    if any(k not in values for k in ("DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST")):
        raise AuditError("wp-config.php uses unsupported/nonliteral database defines")
    prefix = SQL_TABLE_PREFIX.search(data)
    if not prefix:
        raise AuditError("Unsupported wp-config.php table prefix")
    return values, prefix.group(1)

def validate_site(target: Path) -> Path:
    target = target.resolve(strict=True)
    if not target.is_dir() or target.is_symlink() or not all(
        (target / name).exists() for name in ("wp-content", "wp-admin", "wp-includes", "wp-load.php", "wp-config.php")
    ):
        raise AuditError("Target is not a complete WordPress installation")
    return target

def iter_files(root: Path):
    """Do not follow symlinked directories or escape the source tree."""
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if not (Path(directory) / name).is_symlink()]
        for name in files:
            path = Path(directory) / name
            if path.is_file() and not path.is_symlink():
                yield path

def known_upload_guard(path: Path) -> bool:
    """Accept only an exact, minimal WordPress directory-listing guard."""
    try:
        return (path.is_file() and not path.is_symlink() and path.stat().st_size <= 64
                and path.read_bytes() in (b"<?php\n// Silence is golden.\n",
                                          b"<?php\r\n// Silence is golden.\r\n"))
    except OSError:
        return False


REVIEWED_METFORM_CACHE_SHA256 = {
    "wp-content/uploads/metform/cache/icons/font-awesome-38edd54e30815111.php":
        "232e3228a29927ce62cdd282c81e1327a6022abe92f4d529d94888dfbade1766",
}


def reviewed_metform_cache(relative: str, path: Path) -> bool:
    """Validate a specifically reviewed artifact by its complete SHA-256 digest."""
    expected = REVIEWED_METFORM_CACHE_SHA256.get(relative)
    return bool(expected and not path.is_symlink() and path.is_file()
                and sha256(path) == expected)


def metform_icon_cache_candidate(relative: str, path: Path) -> bool:
    """Recognize a bounded cache header; do not certify the remainder."""
    if not re.fullmatch(r"wp-content/uploads/metform/cache/icons/font-awesome-[a-f0-9]{16}\.php", relative):
        return False
    try:
        if path.is_symlink() or not path.is_file() or not 64 <= path.stat().st_size <= 8388608:
            return False
        with path.open("rb") as stream:
            head = stream.read(4096).decode("utf-8", "replace")
        return bool(re.match(
            r"(?is)\s*<\?php\s*/\*.*?Generated\s+by\s+MetForm.*?\*/\s*"
            r"defined\s*\(\s*['\"]ABSPATH['\"]\s*\)\s*\|\|\s*exit\s*;\s*"
            r"return\s+(?:array\s*\(|\[)", head))
    except OSError:
        return False


def classify_file(relative: str, name: str, text: str, indicator: str | None) -> tuple[str, str]:
    """Classify evidence conservatively, with explicit legitimate guard cases.

    Plugin ownership is contextual evidence, not a cryptographic validation.
    A known guard file is classified as validated only when its expected
    minimal structure is present and no known strong IOC has been detected.
    """
    normalized = "/" + relative
    if normalized.startswith("/wp-content/wflogs/"):
        return ("CONFIGURACAO_PLUGIN_SEGURANCA_REQUER_VALIDACAO",
                "Wordfence configuration; historic strings do not establish execution")
    if "/wp-content/uploads/sucuri/" in normalized and not indicator and (
            "exit(0)" in text or "datastore=" in text):
        return ("LEGITIMO_VALIDADO", "Recognized Sucuri datastore guard pattern")
    if normalized.startswith("/wp-content/uploads/simple-history-logs-") and name == "index.php" and not indicator and "Silence is golden" in text:
        return ("LEGITIMO_VALIDADO", "Recognized Simple History guard pattern")
    if normalized == "/wp-content/uploads/wpforms/cache/index.php" and not indicator and "404 Not Found" in text:
        return ("LEGITIMO_VALIDADO", "Recognized WPForms cache guard pattern")
    if indicator:
        return ("IOC_REQUER_VALIDACAO", "Known family indicator detected; inspect source and context")
    if normalized.startswith("/wp-content/uploads/"):
        return ("PHP_UPLOAD_REQUER_VALIDACAO", "Executable extension in uploads; not proof of infection")
    return ("ARQUIVO_SUSPEITO_REQUER_VALIDACAO", "Suspicious filename requires manual review")


def file_audit(target: Path, case: Path) -> list[dict]:
    """Inspect known IOC filenames and all script content in bounded chunks."""
    findings: list[dict] = []
    for path in iter_files(target):
        relative = path.relative_to(target).as_posix()
        name = path.name
        unusual = name.startswith(PATTERN_NAMES) or name == "trace-inspector-pad.php" or "cipher-feeder" in name
        upload_php = relative.startswith("wp-content/uploads/") and path.suffix.lower() in SCRIPT_EXTENSIONS
        hidden_php = (path.suffix.lower() in (".php", ".phtml", ".phar") and
                      any(part.startswith(".") and part not in (".", "..", ".well-known")
                          for part in Path(relative).parts[:-1]))
        match = None
        snippet = ""
        safe_text = ""
        generic_match = False
        if path.suffix.lower() in SCRIPT_EXTENSIONS:
            try:
                with path.open("rb") as stream:
                    overlap = b""
                    while chunk := stream.read(65536):
                        sample = overlap + chunk
                        decoded = sample.decode("utf-8", "replace")
                        if not safe_text:
                            safe_text = decoded[:4096]
                        match = IOC.search(decoded)
                        if GENERIC_WEB_SHELL.search(sample):
                            generic_match = True
                        if match:
                            snippet = redact(decoded[max(0, match.start() - 40):match.end() + 60])
                            break
                        overlap = sample[-256:]
            except OSError:
                continue
        if not (unusual or upload_php or hidden_php or match or generic_match):
            continue
        classification, reason = classify_file(relative, name, safe_text, match.group(0) if match else None)
        if upload_php and not match and name == "index.php" and known_upload_guard(path):
            classification, reason = "LEGITIMO_VALIDADO", "Exact WordPress directory-listing guard content"
        elif upload_php and not match and metform_icon_cache_candidate(relative, path):
            classification, reason = "CACHE_PLUGIN_REQUER_VALIDACAO", "MetForm icon cache candidate; origin and complete content not verified"
        if generic_match and not match:
            classification, reason = "WEB_SHELL_HEURISTIC_REQUIRES_REVIEW", "Potential dynamic execution or obfuscation pattern"
        if upload_php and not match and not generic_match and reviewed_metform_cache(relative, path):
            classification, reason = "LEGITIMO_VALIDADO", "Exact SHA-256 matches reviewed MetForm cache artifact; not plugin-wide trust"
        if hidden_php and not match and not generic_match and classification == "ARQUIVO_SUSPEITO_REQUER_VALIDACAO":
            classification, reason = "PHP_DIRETORIO_OCULTO_REQUER_VALIDACAO", "PHP within hidden directory"
        if relative.startswith("wp-content/wflogs/"):
            snippet = ""  # Wordfence configuration may contain secrets.
        try:
            findings.append({
                "path": relative, "sha256": sha256(path), "size": path.stat().st_size,
                "classification": classification, "reason": reason,
                "indicator": match.group(0) if match else ("filename" if unusual else "upload PHP"),
                "snippet": snippet,
            })
        except OSError:
            continue
    write_private(case / "file-evidence.json", json.dumps(findings, indent=2, ensure_ascii=False))
    return findings



def akismet_access_guard(content: str) -> bool:
    """Validate deny-by-default rules with scoped static-asset exceptions."""
    lines = [x.strip() for x in content.splitlines() if x.strip() and not x.lstrip().startswith("#")]
    if not lines or len(lines) > 80:
        return False
    stack = []
    deny = False
    grant = False
    for line in lines:
        module = re.fullmatch(r'<IfModule\s+!?([A-Za-z0-9_.]+)\s*>', line, re.I)
        files = re.fullmatch(r'<FilesMatch\s+"([^"]{1,200})"\s*>', line, re.I)
        if module:
            if module.group(1).lower() not in ("mod_authz_core.c", "mod_access_compat.c"):
                return False
            stack.append("module")
        elif files:
            pattern = files.group(1)
            # Permit only patterns referencing static extensions, never PHP/CGI.
            if not re.search(r"css|js|png|jpe?g|gif|svg|webp", pattern, re.I):
                return False
            if re.search(r"php|phtml|phar|cgi|\\\.pl\\b|\\\.sh\\b|(?<!\\)\.\*", pattern, re.I):
                return False
            if re.search(r"[^A-Za-z0-9@\\.^$|()?+*\[\]{}-]", pattern):
                return False
            stack.append("assets")
        elif line.lower() in ("</ifmodule>", "</filesmatch>"):
            expected = "module" if line.lower() == "</ifmodule>" else "assets"
            if not stack or stack[-1] != expected:
                return False
            stack.pop()
        elif re.fullmatch(r"(?:Require\s+all\s+denied|Deny\s+from\s+all|Order\s+(?:allow,deny|deny,allow))", line, re.I):
            if "assets" in stack:
                return False
            deny = True
        elif re.fullmatch(r"(?:Require\s+all\s+granted|Allow\s+from\s+all)", line, re.I):
            if "assets" not in stack:
                return False
            grant = True
        else:
            return False
    return deny and grant and not stack


def configuration_audit(target: Path, case: Path) -> list[dict]:
    """Read-only configuration inventory. Never export configuration contents.

    Audit files inside the WordPress tree only. A metadata presence or generic
    configuration hash is not proof of compromise.
    """
    names = {".htaccess", ".user.ini", "php.ini", "php5.ini", "php7.ini",
             "php8.ini", ".htpasswd", "web.config", "user.ini"}
    findings = []
    for path in iter_files(target):
        relative = path.relative_to(target).as_posix()
        if path.name not in names:
            continue
        try:
            info = path.stat()
            # Detect relevant directives without recording values, URLs or secrets.
            patterns = {
                "HANDLER_OVERRIDE": r"(?im)^\s*(?:AddHandler|SetHandler)\b",
                "PHP_CONFIGURATION_OVERRIDE": r"(?im)^\s*(?:php_value|php_flag)\b",
                "PHP_AUTO_PREPEND_APPEND": r"(?im)\b(?:auto_prepend_file|auto_append_file)\b",
                "REWRITE_TO_EXTERNAL_URL": r"(?im)^\s*RewriteRule\s+\S+\s+https?://",
                "PHP_UPLOAD_ACCESS_RULE": r"(?im)<FilesMatch\b[^>]*\.(?:php|phtml)",
                "ACCESS_OVERRIDE": r"(?im)^\s*Require\s+all\s+granted\b",
            }
            indicators = []
            if info.st_size <= 1048576 and path.name != ".htpasswd":
                with path.open("r", encoding="utf-8", errors="replace") as stream:
                    content = stream.read()
                indicators = [key for key, pattern in patterns.items() if re.search(pattern, content)]
            classification = ("CONFIGURACAO_REQUER_VALIDACAO" if indicators
                              else "CONFIGURACAO_INVENTARIADA_SEM_INDICADOR")
            if (relative == "wp-content/plugins/akismet/.htaccess"
                    and info.st_size <= 1048576 and akismet_access_guard(content)):
                classification = "CONFIGURACAO_LEGITIMA_VALIDADA"
                indicators = []
            findings.append({
                "indicators": indicators,
                "path": relative,
                "classification": classification,
                "source": "filesystem",
                "size": info.st_size,
                "sha256": sha256(path),
                "mode": oct(stat.S_IMODE(info.st_mode)),
                "reason": "Configuration file inventory; content intentionally withheld",
            })
        except OSError:
            continue
    write_private(case / "configuration-evidence.json",
                  json.dumps(findings, indent=2, ensure_ascii=False))
    return findings



def core_integrity_audit(target: Path, case: Path, checksum_manifest: dict | None = None) -> dict:
    """Compare installed core files with official WordPress checksums.

    The installation is never modified. A checksum manifest can be supplied
    by synthetic tests; production retrieves from api.wordpress.org HTTPS.
    """
    version_file = target / "wp-includes" / "version.php"
    if version_file.is_symlink() or not version_file.is_file():
        result = {"status": "UNAVAILABLE", "reason": "Missing or linked version.php", "findings": []}
        write_private(case / "core-integrity.json", json.dumps(result, indent=2))
        return result
    text = version_file.read_text(encoding="utf-8", errors="replace")[:65536]
    version_match = re.search(r"\$wp_version\s*=\s*['\"]([0-9]+(?:\.[0-9]+){1,3})['\"]", text)
    if not version_match:
        result = {"status": "UNAVAILABLE", "reason": "Version cannot be safely parsed", "findings": []}
        write_private(case / "core-integrity.json", json.dumps(result, indent=2))
        return result
    version = version_match.group(1)
    if checksum_manifest is None:
        params = urllib.parse.urlencode({"version": version, "locale": "en_US"})
        request = urllib.request.Request(
            "https://api.wordpress.org/core/checksums/1.0/?" + params,
            headers={"User-Agent": "wp-integrity-audit/" + VERSION})
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                if urllib.parse.urlparse(response.geturl()).hostname != "api.wordpress.org":
                    raise AuditError("Untrusted core checksum endpoint")
                checksum_manifest = json.load(response)
        except (OSError, ValueError, AuditError) as exc:
            result = {"status": "UNAVAILABLE", "version": version,
                      "reason": "Official checksum retrieval failed", "findings": []}
            write_private(case / "core-integrity.json", json.dumps(result, indent=2))
            return result
    checksums = checksum_manifest.get("checksums") if isinstance(checksum_manifest, dict) else None
    if not isinstance(checksums, dict) or not checksums:
        result = {"status": "UNAVAILABLE", "version": version, "reason": "Missing checksum manifest", "findings": []}
        write_private(case / "core-integrity.json", json.dumps(result, indent=2))
        return result
    findings = []
    checked = 0
    for name, expected in sorted(checksums.items()):
        # Plugins, local configs and content are never treated as core.
        if (not isinstance(name, str) or not isinstance(expected, str)
                or not re.fullmatch(r"[0-9a-fA-F]{32}", expected)):
            continue
        parts = Path(name).parts
        if (Path(name).is_absolute() or ".." in parts or
                name.startswith("wp-content/") or name == "wp-config.php"):
            continue
        path = target / name
        if path.is_symlink() or not path.is_file():
            findings.append({"path": name, "classification": "CORE_AUSENTE_REQUER_REVISAO"})
            continue
        digest = hashlib.md5()
        try:
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1048576), b""):
                    digest.update(chunk)
        except OSError:
            findings.append({"path": name, "classification": "CORE_INACESSIVEL_REQUER_REVISAO"})
            continue
        checked += 1
        if digest.hexdigest().lower() != expected.lower():
            findings.append({"path": name, "classification": "CORE_MODIFICADO_REQUER_REVISAO",
                             "sha256": sha256(path)})
    result = {"status": "COMPLETE" if checked else "INCOMPLETE", "version": version,
              "locale": "en_US", "algorithm": "MD5 (WordPress official checksums)",
              "checked_files": checked, "findings": findings,
              "note": "Locale-specific files or valid customizations may differ; a mismatch is not proof of compromise."}
    write_private(case / "core-integrity.json", json.dumps(result, indent=2))
    return result

def host_persistence_inventory(case: Path, roots: list[Path]) -> list[dict]:
    """Bounded Linux persistence metadata collection, without reading secrets."""
    findings = []
    allowed = ("/etc/cron", "/etc/crontab", "/etc/systemd/system", "/etc/php",
               "/etc/apache2", "/etc/profile", "/etc/bash.bashrc",
               "/etc/rc.local", "/etc/ld.so.preload", "/etc/sudoers.d", "/var/spool/cron")
    for root in roots:
        root = Path(root)
        if not any(str(root) == prefix or str(root).startswith(prefix + ".") or
                   str(root).startswith(prefix + "/") for prefix in allowed):
            raise AuditError("Disallowed host inventory root")
        if root.is_symlink() or not root.exists():
            continue
        candidates = [root] if root.is_file() else iter_files(root)
        for file in candidates:
            try:
                info = file.stat()
                # Scan bounded text for explicit family IOCs; never export file content.
                indicator = False
                if info.st_size <= 1048576:
                    with file.open("rb") as stream:
                        indicator = bool(IOC.search(stream.read().decode("utf-8", "replace")))
                findings.append({"path": str(file), "size": info.st_size,
                                 "mode": oct(stat.S_IMODE(info.st_mode)),
                                 "sha256": sha256(file), "source": "host_metadata",
                                 "classification": ("HOST_INDICATOR_REQUIRES_INVESTIGATION" if indicator
                                                    else "INVENTARIADO_SEM_INDICADOR")})
            except OSError:
                continue
    write_private(case / "host-persistence.json", json.dumps(findings, indent=2))
    return findings


def wordpress_persistence_inventory(target: Path, case: Path) -> list[dict]:
    """Inventory mu-plugins and WordPress drop-ins without executing PHP."""
    dropins = {"advanced-cache.php", "db.php", "object-cache.php", "sunrise.php",
               "maintenance.php", "fatal-error-handler.php", "php-error.php"}
    records = []
    content = target / "wp-content"
    for path in iter_files(content):
        relative = path.relative_to(target).as_posix()
        if not (relative.startswith("wp-content/mu-plugins/") or
                (path.parent == content and path.name in dropins)):
            continue
        try:
            records.append({"path": relative, "sha256": sha256(path),
                            "size": path.stat().st_size,
                            "classification": "WORDPRESS_PERSISTENCE_REQUIRES_CONTEXT",
                            "reason": "MU-plugin or drop-in inventory; not proof of compromise"})
        except OSError:
            continue
    write_private(case / "wordpress-persistence.json",
                  json.dumps(records, indent=2, ensure_ascii=False))
    return records


def recent_file_timeline(target: Path, case: Path, days: int = 30) -> list[dict]:
    """Metadata-only timeline, bounded to files changed in the last N days."""
    now = dt.datetime.now(dt.timezone.utc).timestamp()
    cutoff = now - days * 86400
    records = []
    for path in iter_files(target):
        try:
            info = path.stat()
            if max(info.st_mtime, info.st_ctime) < cutoff:
                continue
            records.append({"path": path.relative_to(target).as_posix(),
                            "mtime_utc": dt.datetime.fromtimestamp(info.st_mtime, dt.timezone.utc).isoformat(),
                            "ctime_utc": dt.datetime.fromtimestamp(info.st_ctime, dt.timezone.utc).isoformat(),
                            "size": info.st_size,
                            "classification": "RECENT_FILE_METADATA"})
        except (OSError, OverflowError, ValueError):
            continue
    records.sort(key=lambda x: x["mtime_utc"], reverse=True)
    write_private(case / "timeline.json", json.dumps({"window_days": days,
        "timestamp_note": "ctime is metadata-change time, not creation time",
        "records": records}, indent=2, ensure_ascii=False))
    return records


def process_audit(case: Path) -> list[str]:
    result = run(["ps", "-eo", "pid=,ppid=,user=,args="], capture_output=True).stdout
    matches = [redact(line) for line in result.splitlines() if any(x in line for x in ("--sc-cli", "--sc-succ", "cipher-feeder", ".gr_"))]
    write_private(case / "process-evidence.json", json.dumps(matches, indent=2))
    return matches

def attach_evidence_ids(files: list[dict], database: list[dict] | None,
                        db_name: str | None, db_prefix: str | None) -> None:
    """Attach deterministic per-case evidence references and SQL provenance."""
    for index, entry in enumerate(files, 1):
        entry["evidence_id"] = f"FILE-{index:03d}"
        entry["source"] = "filesystem"
    for index, entry in enumerate(database or [], 1):
        entry["evidence_id"] = f"DB-{index:03d}"
        entry["source"] = "database"
        entry["database"] = db_name
        kind = entry.get("kind", "")
        suffix = ("users" if kind == "suspicious_users" else
                  "usermeta" if kind in ("session_rows", "application_password_rows") else "options")
        entry["source_table"] = (db_prefix or "") + suffix
        entry["source_column"] = ("user_login" if suffix == "users" else
                                  "meta_key" if suffix == "usermeta" else "option_value")


def audit_status(files: list[dict], processes: list[str],
                 database: list[dict] | None) -> tuple[str, int, dict]:
    """Conservative audit outcomes; do not interpret historical references as activity."""
    count = lambda kind: sum(
        int(x["length"]) if kind in ("session_rows", "application_password_rows")
        else int(x.get("state") not in ("ABSENT", "NOT_FOUND"))
        for x in (database or []) if x.get("kind") == kind)
    summary = {
        "confirmed_family_residues": count("family_option"),
        "historical_references": count("historical_cache"),
        "informational_records": count("session_rows") + count("application_password_rows"),
        "active_database_markers": sum(count(k) for k in ("marker_option", "cron_marker", "active_plugins_marker")),
        "validated_legitimate_files": sum(x.get("classification") == "LEGITIMO_VALIDADO" for x in files),
        "security_configuration_review": sum(x.get("classification") == "CONFIGURACAO_PLUGIN_SEGURANCA_REQUER_VALIDACAO" for x in files),
        "confirmed_compromised_files": 0,  # Heuristic file matches are not forensic confirmation.
        "file_indicators_requiring_review": sum(x.get("classification") in ("IOC_REQUER_VALIDACAO", "ARQUIVO_SUSPEITO_REQUER_VALIDACAO", "PHP_UPLOAD_REQUER_VALIDACAO", "PHP_DIRETORIO_OCULTO_REQUER_VALIDACAO", "CACHE_PLUGIN_REQUER_VALIDACAO", "WEB_SHELL_HEURISTIC_REQUIRES_REVIEW") for x in files),
        "suspicious_processes": len(processes),
    }
    if database is None:
        return "AUDITORIA_INCOMPLETA", 40, summary
    # Heuristic markers alone cannot establish executed compromise.
    # Reserve exit 20 for independently confirmed execution evidence.
    if summary["active_database_markers"] or summary["suspicious_processes"]:
        return "AUDITORIA_INCOMPLETA", 40, summary
    if summary["confirmed_family_residues"]:
        return "RESIDUOS_REQUEREM_LIMPEZA", 10, summary
    if summary["file_indicators_requiring_review"]:
        return "AUDITORIA_INCOMPLETA", 40, summary
    return "SEM_MARCADOR_EXPLICITO", 0, summary


def optional_probe_review(case: Path) -> list[str]:
    """Surface failures of requested optional probes without overriding residues."""
    issues = []
    core = case / "core-integrity.json"
    if core.is_file():
        with core.open(encoding="utf-8") as stream:
            record = json.load(stream)
        if record.get("status") != "COMPLETE":
            issues.append("Core checksum verification unavailable or incomplete")
        if record.get("findings"):
            issues.append(f"Core discrepancies requiring review: {len(record['findings'])}")
    host = case / "host-persistence.json"
    if host.is_file():
        with host.open(encoding="utf-8") as stream:
            records = json.load(stream)
        if not isinstance(records, list):
            issues.append("Invalid host persistence inventory")
        elif any(item.get("classification") == "HOST_INDICATOR_REQUIRES_INVESTIGATION" for item in records):
            issues.append("External host persistence indicators require investigation")
    return issues


def supplementary_evidence(case: Path) -> tuple[dict, list, list]:
    """Load metadata only; keep detailed host inventory in internal evidence."""
    def read(name, fallback):
        path = case / name
        if not path.is_file() or path.is_symlink():
            return fallback
        return json.loads(path.read_text(encoding="utf-8"))
    core = read("core-integrity.json", {})
    configs = read("configuration-evidence.json", [])
    host = read("host-persistence.json", [])
    if not isinstance(core, dict) or not isinstance(configs, list) or not isinstance(host, list):
        raise AuditError("Malformed supplementary evidence")
    return core, configs, host


def traduzir_estado(valor: object) -> str:
    """Traduz somente a apresentação, preservando códigos e contratos JSON."""
    estados = {
        "NOT DETERMINED": "NÃO DETERMINADO",
        "REVIEW REQUIRED": "REVISÃO NECESSÁRIA",
        "LOW — no known indicators found": "BAIXO — nenhum indicador conhecido encontrado",
        "EXECUTED": "EXECUTADA",
        "NOT EXECUTED": "NÃO EXECUTADA",
        "COMPLETE": "CONCLUÍDA",
        "INCOMPLETE": "INCOMPLETA",
        "SKIPPED": "IGNORADA",
        "UNAVAILABLE": "INDISPONÍVEL",
    }
    return estados.get(str(valor), str(valor))


def customer_findings(files, database, configs, components):
    """Provide a redacted item-by-item explanation suitable for a customer."""
    lines = ["", "## Achados detalhados e evidências correspondentes", "",
             "Os achados registram observações técnicas, sem atribuir autoria ao incidente.",
             "Valores privados do banco de dados, credenciais, conteúdo integral de configurações e comandos internos foram omitidos.", ""]
    items = []
    for entry in database or []:
        if entry.get("state") in ("ABSENT", "NOT_FOUND") or entry.get("kind") in ("session_rows", "application_password_rows"):
            continue
        kind = entry.get("kind")
        # Metadados de cron representam inventário; não são um indicador de ataque.
        if kind == "cron_metadata":
            continue
        description = ("Referência histórica ao incidente, sem comprovação de execução ativa de código."
                       if kind == "historical_cache" else
                       "Resíduo no banco de dados compatível com um padrão do incidente; valide antes de qualquer correção."
                       if kind == "family_option" else
                       "Indicador relacionado ao incidente no banco de dados que exige investigação.")
        items.append((entry.get("evidence_id", "DB-UNASSIGNED"), "Banco de dados", entry.get("name"),
                      entry.get("state"), description, entry.get("sha256")))
    for entry in files:
        if entry.get("classification") != "LEGITIMO_VALIDADO":
            items.append((entry.get("evidence_id", "FILE-UNASSIGNED"), "Arquivos",
                          sanitize_relative_path(entry.get("path", "")), entry.get("classification"),
                          "Indicador estático em arquivo que exige revisão; a detecção não comprova execução.",
                          entry.get("sha256")))
    for entry in configs:
        if entry.get("classification") in ("CONFIGURACAO_REQUER_VALIDACAO", "CONFIGURACAO_PLUGIN_SEGURANCA_REQUER_VALIDACAO"):
            items.append((entry.get("evidence_id", "CONFIG-UNASSIGNED"), "Configuração",
                          sanitize_relative_path(entry.get("path", "")), entry.get("classification"),
                          "Diretiva de configuração cuja finalidade e autorização precisam ser confirmadas.",
                          entry.get("sha256")))
    for entry in (components or {}).get("components", []):
        state = entry.get("state")
        if state in ("CORE_DESATUALIZADO", "PLUGIN_ORIGEM_NAO_CONFIRMADA_REQUER_REVISAO",
                     "PLUGIN_VERSAO_NAO_IDENTIFICADA", "PLUGIN_REQUER_REVISAO",
                     "TEMA_REQUER_REVISAO", "TEMA_NAO_ENCONTRADO_NO_REPOSITORIO",
                     "CORE_MODIFICADO_REQUER_REVISAO", "CORE_AUSENTE_REQUER_REVISAO",
                     "PLUGIN_COM_ARQUIVOS_MODIFICADOS", "TEMA_COM_ARQUIVOS_MODIFICADOS",
                     "PLUGIN_OFICIAL_DESATUALIZADO", "TEMA_OFICIAL_DESATUALIZADO"):
            explanation = ("Atualização disponível; a versão desatualizada não comprova comprometimento."
                           if state.endswith("DESATUALIZADO") else
                           "Origem oficial não confirmada. Verifique fornecedor, licença, pacote e hash; isso não comprova malware."
                           if state in ("PLUGIN_ORIGEM_NAO_CONFIRMADA_REQUER_REVISAO", "TEMA_NAO_ENCONTRADO_NO_REPOSITORIO") else
                           "Não foi possível identificar a versão instalada; verifique o pacote manualmente."
                           if state == "PLUGIN_VERSAO_NAO_IDENTIFICADA" else
                           "Uma divergência de integridade exige comparação com uma versão confiável.")
            versao_local = entry.get("local_version") or "não identificada"
            versao_oficial = entry.get("official_version") or "não disponível"
            detalhe = (f"Versão instalada: {versao_local}; versão de referência: {versao_oficial}. "
                       "O SHA-256, quando disponível, refere-se apenas ao arquivo principal, não ao pacote inteiro. ")
            items.append((entry.get("component_id", "COMPONENT-UNASSIGNED"), "Componente",
                          entry.get("slug"), state, detalhe + explanation, entry.get("main_file_sha256")))
    for identifier, kind, subject, state, explanation, digest in items:
        # Não misturar manutenção ou referências históricas com indicadores do incidente.
        if state == "RESIDUO_FAMILIA_REQUER_LIMPEZA":
            natureza = "INDICADOR RESIDUAL DO INCIDENTE"
            conclusao = "Compatível com indicador conhecido; exige confirmação e avaliação técnica."
        elif state == "HISTORICAL_REFERENCE":
            natureza = "REFERÊNCIA HISTÓRICA"
            conclusao = "Registro histórico; não comprova execução ativa nem persistência."
        elif state in ("CORE_DESATUALIZADO", "PLUGIN_OFICIAL_DESATUALIZADO", "TEMA_OFICIAL_DESATUALIZADO"):
            natureza = "MANUTENÇÃO / ATUALIZAÇÃO"
            conclusao = "Versão anterior à referência consultada; não comprova comprometimento."
        elif kind == "Componente" and state in ("PLUGIN_ORIGEM_NAO_CONFIRMADA_REQUER_REVISAO",
                "TEMA_NAO_ENCONTRADO_NO_REPOSITORIO", "PLUGIN_VERSAO_NAO_IDENTIFICADA",
                "PLUGIN_REQUER_REVISAO", "TEMA_REQUER_REVISAO"):
            natureza = "PROCEDÊNCIA / VERSÃO NÃO CONFIRMADA"
            conclusao = "Informações insuficientes para confirmar procedência ou equivalência de versão."
        else:
            natureza = "VERIFICAÇÃO DE SEGURANÇA PENDENTE"
            conclusao = "Achado técnico sujeito a validação contextual; execução maliciosa não demonstrada."
        risk = ("PRIORIDADE ALTA — indicador residual do incidente" if state == "RESIDUO_FAMILIA_REQUER_LIMPEZA" else
                "MÉDIA — item executável ou divergência de integridade que exige validação" if kind in ("Arquivos", "Configuração") or state in ("CORE_MODIFICADO_REQUER_REVISAO", "PLUGIN_COM_ARQUIVOS_MODIFICADOS") else
                "MÉDIA — origem ou manutenção do componente exige revisão" if kind == "Componente" else
                "DEPENDENTE DO CONTEXTO — indicador histórico ou não confirmado")
        clean = lambda value: str(value or "não disponível").replace("\r", " ").replace("\n", " ")[:250]
        lines.extend(["### " + clean(identifier) + " - " + clean(kind), "",
                      "- Item: " + clean(subject),
                      "- Classificação: " + clean(state),
                      "- Natureza do achado: " + natureza,
                      "- Conclusão da evidência: " + conclusao,
                      "- Explicação: " + explanation,
                      "- Prioridade de revisão: " + risk + " (não comprova comprometimento ativo)",
                      "- SHA-256 da evidência: " + clean(digest),
                      "- Verificação: revise a evidência indicada com a equipe técnica responsável.", ""])
    if not items:
        lines.extend(["Nenhuma ocorrência individual que exija revisão foi registrada nas verificações selecionadas.", ""])
    lines.extend(["## Sobre a indisponibilidade do site", "",
                  "Este relatório registra indicadores de segurança observados. Não identifica o responsável pelo incidente nem comprova, isoladamente, a data e a causa de eventual indisponibilidade.",
                  "Retirar o site do ar é uma decisão de contenção independente, que exige justificativa, proporcionalidade e autorização documentadas.",
                  "As evidências detalhadas da infraestrutura estão preservadas no relatório técnico de acesso restrito.", ""])
    return lines


def create_evidence_manifest(case: Path) -> dict:
    """Hash regular private case files without following symlinks."""
    records = []
    for path in sorted(case.rglob("*")):
        if path.is_symlink() or not path.is_file() or path.name == "evidence-manifest.json":
            continue
        records.append({"file": path.relative_to(case).as_posix(), "sha256": sha256(path),
                        "size_bytes": path.stat().st_size})
    result = {"schema_version": 1, "algorithm": "SHA-256",
              "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "scope": "case evidence files at time of manifest creation",
              "files": records, "limitations": "Local hashes establish integrity after capture, not the truth of their contents or who handled them."}
    write_private(case / "evidence-manifest.json", json.dumps(result, indent=2))
    return result


def verify_evidence_manifest(case: Path) -> dict:
    """Check case contents against recorded SHA-256 without modifying case files."""
    if case.is_symlink() or not case.is_dir():
        raise AuditError("Case directory is missing or symlinked")
    manifest = case / "evidence-manifest.json"
    if manifest.is_symlink() or not manifest.is_file():
        raise AuditError("Case evidence manifest is unavailable")
    source = json.loads(manifest.read_text(encoding="utf-8"))
    if source.get("algorithm") != "SHA-256" or not isinstance(source.get("files"), list):
        raise AuditError("Unsupported evidence manifest")
    differences = []
    expected_files = set()
    for entry in source["files"]:
        relative = entry.get("file")
        if not isinstance(relative, str) or not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise AuditError("Unsafe evidence manifest path")
        if relative in expected_files:
            raise AuditError("Duplicate evidence manifest path")
        expected_files.add(relative)
        path = case / relative
        if path.is_symlink() or not path.is_file():
            differences.append({"file": relative, "result": "MISSING_OR_LINKED"})
        elif path.stat().st_size != entry.get("size_bytes") or sha256(path) != entry.get("sha256"):
            differences.append({"file": relative, "result": "MODIFIED"})
    excluded = {"evidence-manifest.json", "evidence-bundle.tar.gz", "evidence-bundle.sha256"}
    current = {path.relative_to(case).as_posix() for path in case.rglob("*")
               if path.is_file() and not path.is_symlink() and path.relative_to(case).as_posix() not in excluded}
    for extra in sorted(current - expected_files):
        differences.append({"file": extra, "result": "UNLISTED_AFTER_CAPTURE"})
    return {"status": "MATCH" if not differences else "DIFFERENCES_FOUND",
            "checked": len(expected_files), "differences": differences,
            "limitations": "A matching local manifest does not authenticate the collector or independently prove the time of collection."}


def bundle_case_evidence(case: Path) -> Path:
    """Package restricted evidence atomically after a sensitive-file preflight."""
    archive = case / "evidence-bundle.tar.gz"
    digest_path = case / "evidence-bundle.sha256"
    if archive.exists() or archive.is_symlink() or digest_path.exists() or digest_path.is_symlink():
        raise AuditError("Refusing to overwrite an existing evidence bundle")
    manifest = case / "evidence-manifest.json"
    if manifest.is_symlink() or not manifest.is_file():
        raise AuditError("Evidence manifest must exist before packaging")
    paths = [path for path in sorted(case.rglob("*"))
             if path.is_file() and not path.is_symlink() and path not in (archive, digest_path)]
    if any(path.name == "mysql-client.cnf" for path in paths):
        raise AuditError("Refusing to package a database credential file")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix=".evidence-bundle-", suffix=".tmp",
                                         dir=case, delete=False) as stream:
            temporary = Path(stream.name)
        with tarfile.open(temporary, "w:gz") as output:
            for path in paths:
                output.add(path, arcname=path.relative_to(case).as_posix(), recursive=False)
        temporary.chmod(0o600)
        os.replace(temporary, archive)
        write_private(digest_path, sha256(archive) + "  evidence-bundle.tar.gz\n")
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return archive


def incident_containment_note(case: Path, domain: str) -> None:
    """Do not fabricate an incident timeline or outage authorization."""
    content = ("# Registro de contenção do incidente (preenchimento pelo responsável)\\n\\n"
               f"- Domínio: {domain}\\n"
               "- Site retirado do ar: NÃO VERIFICADO NESTA AUDITORIA\\n"
               "- Início e término da indisponibilidade: NÃO DOCUMENTADOS\\n"
               "- Responsável pela decisão de contenção: NÃO DOCUMENTADO\\n"
               "- Autorização da decisão: NÃO DOCUMENTADA\\n"
               "- Impacto e abrangência operacional: NÃO DOCUMENTADOS\\n"
               "- Evidências que justificam a contenção: consultar os achados individuais em report.md\\n"
               "- Critérios para reativação: EXIGEM APROVAÇÃO DO RESPONSÁVEL\\n\\n"
               "Este modelo não comprova indisponibilidade nem autorização para interromper o serviço.\\n")
    write_private(case / "incident-containment-record.md", content)


def make_report(case: Path, mode: str, findings: list[dict], processes: list[str],
                database: list[dict] | None = None, db_name: str | None = None, db_prefix: str | None = None) -> None:
    """Generate a precise coverage statement and evidence-based technical opinion."""
    audited = database is not None
    attach_evidence_ids(findings, database, db_name, db_prefix)
    status, exit_code, summary = audit_status(findings, processes, database)
    optional_issues = optional_probe_review(case)
    core, configurations, host_records = supplementary_evidence(case)
    core_count = len(core.get("findings", []))
    config_count = sum(x.get("classification") == "CONFIGURACAO_REQUER_VALIDACAO" for x in configurations)
    config_inventoried = len(configurations)
    summary["plugin_security_configuration_review"] = summary["security_configuration_review"]
    summary["security_configuration_review"] = config_count
    host_indicators = sum(x.get("classification") == "HOST_INDICATOR_REQUIRES_INVESTIGATION" for x in host_records)
    host_review = sum(x.get("classification") == "HOST_PERSISTENCE_REQUIRES_CONTEXT" for x in host_records)
    host_known = sum(x.get("classification") == "COMPONENTE_DE_SEGURANCA_CONHECIDO" for x in host_records)
    host_unclassified = len(host_records) - host_indicators - host_review - host_known
    host_legitimate = host_known + host_unclassified
    persistence_risk = ("NOT DETERMINED" if not (case / "host-persistence.json").is_file()
                        else "REVIEW REQUIRED" if host_indicators or host_review
                        else "LOW — no known indicators found")
    summary["host_known_security_components"] = host_known
    summary["host_unclassified_inventory"] = host_unclassified
    summary["host_persistence_indicators"] = host_indicators
    summary["persistence_risk"] = persistence_risk
    admin_path = case / "administrator-inventory.json"
    admin_coverage = json.loads(admin_path.read_text()) if admin_path.is_file() and not admin_path.is_symlink() else None
    summary["administrator_inventory"] = {"coverage": admin_coverage.get("coverage"), "count": admin_coverage.get("count")} if admin_coverage else {"coverage": "NOT EXECUTED", "count": None}
    for index, item in enumerate(core.get("findings", []), 1):
        item["evidence_id"] = f"CORE-{index:03d}"
    for index, item in enumerate(configurations, 1):
        item["evidence_id"] = f"CONFIG-{index:03d}"
    for index, item in enumerate(host_records, 1):
        item["evidence_id"] = f"HOST-{index:03d}"
    case_match = re.fullmatch(r"(.+)-(\d{8}T\d{6}Z-[a-f0-9]{6})", case.name)
    domain, case_id = (case_match.group(1), case_match.group(2)) if case_match else (case.name, case.name)
    if optional_issues and exit_code == 0:
        status, exit_code = "AUDITORIA_INCOMPLETA", 40
    status_detail = ("RESIDUOS_REQUEREM_LIMPEZA_E_CORE_REQUER_REVISAO"
                     if status == "RESIDUOS_REQUEREM_LIMPEZA" and core_count else status)
    component_path = case / "component-version-evidence.json"
    component_result = json.loads(component_path.read_text()) if component_path.is_file() else None
    summary["component_versions"] = component_result["summary"] if component_result else None
    summary["component_coverage"] = component_result["coverage"] if component_result else {"local": "SKIPPED", "official": "SKIPPED"}
    critical_component_review = bool(component_result and any(
        item.get("state") in ("CORE_MODIFICADO_REQUER_REVISAO", "CORE_AUSENTE_REQUER_REVISAO",
                              "PLUGIN_COM_ARQUIVOS_MODIFICADOS", "TEMA_COM_ARQUIVOS_MODIFICADOS")
        for item in component_result["components"]))
    summary["critical_component_review"] = critical_component_review
    component_review = bool(component_result and any(item.get("state") in (
        "PLUGIN_ORIGEM_NAO_CONFIRMADA_REQUER_REVISAO", "PLUGIN_VERSAO_NAO_IDENTIFICADA",
        "PLUGIN_PREMIUM_REQUER_FONTE_CONFIAVEL", "TEMA_NAO_ENCONTRADO_NO_REPOSITORIO",
        "TEMA_REQUER_REVISAO", "PLUGIN_REQUER_REVISAO") for item in component_result["components"]))
    outdated_core = bool(component_result and component_result["summary"].get("core_outdated"))
    summary["component_review_required"] = component_review
    summary["core_outdated"] = outdated_core
    review_pending = bool(config_count or component_review or outdated_core or critical_component_review)
    summary["review_pending"] = review_pending
    # Precedence: independent compromise > known residues > active/heuristic review
    # > file-integrity review > ordinary version/provenance review > clean.
    # An existing residue or active-indicator status must not be silently erased.
    if critical_component_review:
        if exit_code == 0:
            status, exit_code = "AUDITORIA_INCOMPLETA", 40
        status_detail = "CORE_OR_COMPONENT_INTEGRITY_REQUIRES_REVIEW"
    elif review_pending and exit_code == 0:
        status, exit_code = "REVISAO_NECESSARIA", 40
        status_detail = "NON_MALWARE_REVIEW_FINDINGS"
    summary["status_priority"] = ("known_residues" if exit_code == 10 else
                                  "confirmed_compromise" if exit_code == 20 else
                                  "integrity_review" if critical_component_review else
                                  "review_pending" if review_pending else
                                  "other")
    write_private(case / "report.json", json.dumps({
        "schema_version": 1, "tool_version": VERSION,
        "tool_sha256": sha256(Path(__file__)), "mode": mode,
        "collected_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": status, "status_detail": status_detail,
        "exit_code": exit_code, "summary": summary,
        "optional_probe_review": optional_issues,
        "domain": domain, "case_id": case_id,
        "core_discrepancies": core_count, "configuration_review_count": config_count,
        "host_persistence_indicators": host_indicators, "host_persistence_review": host_review,
        "persistence_risk": persistence_risk,
        "database": db_name if audited else None,
        "table_prefix": db_prefix if audited else None,
        "database_audited": audited,
        "database_credentials_exposed": False,
    }, indent=2, ensure_ascii=False))
    # Persist a normalized audit summary for fleet-wide CSV aggregation.
    csv_stream = io.StringIO()
    writer = csv.writer(csv_stream)
    writer.writerow(["domain", "case_id", "status", "exit_code", "family_residues",
                     "historical_references", "informational_records",
                     "active_database_markers", "file_review", "suspicious_processes",
                     "release_recommended", "tool_version"])
    writer.writerow([domain, case_id, status, exit_code, summary["confirmed_family_residues"],
                     summary["historical_references"], summary["informational_records"],
                     summary["active_database_markers"],
                     summary["file_indicators_requiring_review"], summary["suspicious_processes"],
                     "NO", VERSION])
    write_private(case / "report.csv", csv_stream.getvalue())
    write_private(case / "evidence-index.json", json.dumps({
        "files": [{"id": entry["evidence_id"], "path": sanitize_relative_path(entry["path"]),
                   "classification": entry["classification"]} for entry in findings],
        "database": [{"id": entry["evidence_id"], "name": entry.get("name"),
                      "table": entry["source_table"], "column": entry["source_column"],
                      "state": entry.get("state")} for entry in (database or [])],
        "core": [{"id": x["evidence_id"], "path": x.get("path"),
                  "classification": x.get("classification")} for x in core.get("findings", [])],
        "config": [{"id": x["evidence_id"], "path": x.get("path"),
                    "classification": x.get("classification")} for x in configurations],
        "host": [{"id": x["evidence_id"], "classification": x.get("classification")}
                 for x in host_records],
        "processes": [{"id": f"PROC-{i:03d}", "source": "process"}
                      for i, _ in enumerate(processes, 1)],
    }, indent=2, ensure_ascii=False))
    lines = [
        "# Auditoria de Integridade WordPress", "",
        "## Resumo executivo", "",
        f"- Situação final: **{status}**",
        f"- Situação detalhada: **{status_detail}**",
        f"- Código de saída: **{exit_code}**",
        f"- Resíduos da família investigada: **{summary['confirmed_family_residues']}**",
        f"- Referências históricas: **{summary['historical_references']}**",
        f"- Registros informativos: **{summary['informational_records']}**",
        f"- Indicadores ativos no banco de dados: **{summary['active_database_markers']}**",
        f"- Arquivos confirmados como comprometidos: **{summary['confirmed_compromised_files']}**",
        f"- Padrões de arquivos legítimos validados: **{summary['validated_legitimate_files']}**",
        f"- Configurações de segurança pendentes de validação: **{summary['security_configuration_review']}**",
        f"- Processos suspeitos: **{summary['suspicious_processes']}**",
        f"- Divergências no núcleo do WordPress: **{core_count}**",
        f"- Arquivos de configuração pendentes de análise: **{config_count}**",
        f"- Indicadores de persistência externa: **{host_indicators}**",
        f"- Registros do inventário do servidor: **{len(host_records)}** (segurança conhecida: {host_known}; não classificados: {host_unclassified}; suspeitos: {host_indicators}; revisão: {host_review})",
        *[f"- Problema em verificação opcional: {issue}" for issue in optional_issues],
        "- Recomendação para reativação: **LIBERAÇÃO NÃO RECOMENDADA**",
        "", "## Dados da auditoria", "",
        f"- Versão: `{VERSION}`", f"- SHA-256 da ferramenta: `{sha256(Path(__file__))}`", f"- Modo: `{mode}`",
        f"- Data e hora (UTC): {dt.datetime.now(dt.timezone.utc).isoformat()}",
        f"- Ocorrências em arquivos: {len(findings)}", f"- Ocorrências em processos: {len(processes)}",
        f"- Auditoria do banco de dados: **{'EXECUTADA' if audited else 'NÃO EXECUTADA'}**",
        f"- Avaliação do banco de dados: {'VERIFICAÇÕES DIRECIONADAS CONCLUÍDAS' if audited else 'NÃO AVALIADO'}",
        f"- Cópia SQL do banco de dados: {'REALIZADA' if (case / 'database-before.sql').is_file() else 'NÃO REALIZADA'}",
        f"- Cópia dos arquivos do site: {'REALIZADA' if (case / 'site-before.tar.gz').is_file() else 'NÃO REALIZADA'}",
        "", "## Evidências do sistema de arquivos", "",
        "| Caminho relativo | Classificação | SHA-256 |",
        "|---|---|---|",
    ]
    for finding in findings:
        # Preserve actual relative file paths, including long directory names.
        path = sanitize_relative_path(finding["path"])
        lines.append(f"| `{path}` | {finding['classification']} | {finding['sha256']} |")
    if audited:
        lines.extend(["", "## Evidências do banco de dados", "",
                      f"- Banco de dados: `{safe_option_name(db_name or 'UNKNOWN')}`",
                      f"- Tabela de opções: `{(db_prefix or '')}options`",
                      f"- Tabela de metadados dos usuários: `{(db_prefix or '')}usermeta`", "",
                      "| Tipo | Nome | Quantidade/tamanho | Situação |",
                      "|---|---|---|---|"])
        for item in database:
            lines.append(f"| {item['kind']} | {item.get('name', '(not supplied)')} | {item['length']} | {item.get('state','')} |")
        lines.extend(["", "### Detalhes das evidências", ""])
        for item in database:
            if not item.get("sha256"):
                continue
            lines.extend([
                f"#### `{item['name']}`", "",
                f"- SHA-256: `{item['sha256']}`",
                f"- Tamanho do valor: {item['value_length_bytes']} bytes",
                f"- Classificação: `{item['value_classification']}`",
                f"- Evidência sem dados sigilosos: `{item['safe_excerpt']}`",
                f"- Valor interpretado: `{item['safe_excerpt'] if item.get('value_classification') == 'ESCALAR_TEXTO_NUMERO_NAO_CODIFICADO' else '[NOT_EXPOSED]'}`",
                f"- Trecho decodificado: `{item['decoded_excerpt']}`",
                *([f"- Coleta (UTC): `{item['collected_at_utc']}`",
                   f"- Indicadores conhecidos no cron: {len(item['indicator_matches'])}"]
                  if item.get("kind") == "cron_metadata" else []), "",
            ])
    lines.extend(["", "## Integridade do núcleo do WordPress", "",
                  f"- Status: `{summary['component_coverage'].get('core', core.get('status', 'NOT EXECUTED'))}`",
                  f"- Divergências: **{core_count}**", ""])
    for item in core.get("findings", []):
        lines.append(f"- `{sanitize_relative_path(item.get('path', ''))}`: "
                     f"`{item.get('classification', 'REVIEW')}`")
    if any(item.get("path") == "wp-includes/version.php" for item in core.get("findings", [])):
        lines.append("- Priority revisão: `wp-includes/version.php` difere da referência; isso isoladamente não comprova a presença de malware.")
    lines.extend(["", "## Inventário de configurações do WordPress", "",
                  f"- Arquivos de configuração pendentes de análise: **{config_count}**", "",
                  "| Caminho relativo | Classificação | SHA-256 |", "|---|---|---|"])
    for item in configurations:
        lines.append(f"| `{sanitize_relative_path(item.get('path', ''))}` | "
                     f"{item.get('classification', 'REVIEW')} | `{item.get('sha256', '')}` |")
    lines.extend(["", "## Resumo da persistência externa", "",
                  f"- Indicadores suspeitos: **{host_indicators}**",
                  f"- Itens legítimos ou de inventário: **{host_legitimate}**",
                  f"- Itens que exigem revisão: **{host_review}**",
                  "- Os caminhos completos do servidor permanecem no arquivo técnico interno host-persistence.json.", ""])
    lines.extend(["", "## Parecer técnico", ""])
    critical = [x for x in findings if x["classification"] == "IOC_REQUER_VALIDACAO"]
    if audited:
        def positive(kind: str) -> int:
            return sum(item.get("state") not in ("NOT_FOUND", "ABSENT")
                       for item in database if item["kind"] == kind)
        lines.extend([
            f"- Resíduos da família investigada: **{positive('family_option')}**.",
            f"- Referências históricas: **{positive('historical_cache')}**.",
            f"- Registros informativos: **{sum(int(item['length']) for item in database if item['kind'] in ('session_rows', 'application_password_rows'))}**.",
            f"- Indicadores ativos no banco de dados: **{positive('marker_option') + positive('cron_marker') + positive('active_plugins_marker')}**.",
            f"- Registros informativos de sessões: **{sum(int(item['length']) for item in database if item['kind'] == 'session_rows')}**.",
        ])
    lines.append(f"- Arquivos que exigem investigação de indicadores: **{len(critical)}**.")
    lines.append(f"- Processos compatíveis com indicadores: **{len(processes)}**.")
    if not audited:
        lines.append("- **O banco de dados não foi auditado. Não é possível concluir sobre persistência, cron, sessões ou administradores.**")
    else:
        def total(kind: str) -> int:
            return sum(int(x["length"]) if kind in ("session_rows", "application_password_rows") else (x.get("state") != "NOT_FOUND")
                       for x in database if x["kind"] == kind)
        family = total("family_option")
        lines.append(f"- Resíduos em opções e transientes: **{family}**.")
        lines.append(f"- Administradores com nomes suspeitos: **{total('suspicious_users')}**.")
        lines.append(f"- Sessões armazenadas do WordPress: **{total('session_rows')}**.")
        lines.append(f"- Referências históricas no cache de atualização de plugins: **{total('historical_cache')}**; isso não comprova execução ativa.")
        for kind, name in (("cron_marker", "cron"), ("active_plugins_marker", "active_plugins")):
            lines.append(f"- Indicadores conhecidos em `{name}`: **{total(kind)}**.")
        if family or total("marker_option") or total("cron_marker") or total("active_plugins_marker"):
            lines.append("- **Persistem indicadores de comprometimento no banco de dados; não declare esta instalação segura.**")
        else:
            lines.append("- Nenhum dos indicadores pesquisados foi encontrado no banco de dados; isso não certifica a integridade do site.")
    if audited:
        lines.extend(["", "### Agendamento dinâmico do WordPress (cron)", "",
                      "O WordPress modifica o agendamento cron automaticamente. Alterações isoladas no hash ou tamanho não comprovam comprometimento.",
                      "Analise conjuntamente os indicadores identificados e o momento da coleta.", ""])
    lines.extend(["", "## Recomendação para reativação", "",
                  "**LIBERAÇÃO NÃO RECOMENDADA**",
                  "A auditoria não autoriza, por si só, a reativação. O responsável técnico deve validar a recuperação, "
                  "a integridade das evidências, as verificações de persistência e os backups antes de autorizar a liberação.", ""])
    lines.extend(["", "## Legenda das classificações", "",
                  "- `RESIDUO_FAMILIA_REQUER_LIMPEZA`: resíduo de uma família de indicadores de incidente no banco de dados.",
                  "- `HISTORICAL_REFERENCE`: referência histórica em cache, sem comprovação de execução.",
                  "- `LEGITIMO_VALIDADO`: padrão reconhecido de proteção de plugin, sem validação criptográfica.",
                  "- `CONFIGURACAO_PLUGIN_SEGURANCA_REQUER_VALIDACAO`: configuração de segurança que exige análise contextual.",
                  "- `PRESENT`: registro informativo presente.",
                  "- `NOT_FOUND`: verificação executada sem registros correspondentes.",
                  "", "## Limitações", "",
                  "A classificação de arquivos de proteção de plugins utiliza padrões conhecidos e não comprova a integridade dos pacotes.",
                  "A ausência de achados não comprova que o site esteja seguro. Revise as evidências antes de compartilhar os relatórios."])
    write_private(case / "technical-report.md", "\n".join(lines) + "\n")
    management = [
        "# Auditoria de Integridade WordPress — Relatório Gerencial", "",
        f"- Domínio: `{domain}`",
        f"- Identificação do caso: `{case_id}`",
        f"- Situação final: **{status}**",
        f"- Código de saída: **{exit_code}**",
        f"- Resíduos da família investigada: **{summary['confirmed_family_residues']}**",
        f"- Referências históricas: **{summary['historical_references']}**",
        f"- Registros informativos: **{summary['informational_records']}**",
        f"- Indicadores ativos no banco de dados: **{summary['active_database_markers']}**",
        f"- Processos suspeitos: **{summary['suspicious_processes']}**",
        f"- Divergências do núcleo do WordPress que exigem revisão: **{core_count}**",
        f"- Inventário de administradores: **{traduzir_estado(summary['administrator_inventory']['coverage'])}** (quantidade: {summary['administrator_inventory']['count'] if summary['administrator_inventory']['count'] is not None else 'não determinada'})",
        f"- Arquivos de configuração do WordPress que exigem revisão: **{config_count}**",
        f"- Indicadores de persistência externa: **{host_indicators}**",
        f"- Registros do servidor que exigem revisão: **{host_review}**",
        "", "## Visão geral dos riscos", "",
        f"- Risco do banco de dados: **{'ALTO' if summary['confirmed_family_residues'] or summary['active_database_markers'] else 'BAIXO — nenhum indicador pesquisado encontrado no banco de dados' if audited else 'NÃO DETERMINADO'}**",
        f"- Risco dos arquivos: **{'REVISÃO NECESSÁRIA' if summary['file_indicators_requiring_review'] else 'BAIXO PARA OS INDICADORES PESQUISADOS'}**",
        f"- Risco do núcleo do WordPress: **{'MÉDIO — REVISÃO NECESSÁRIA' if core_count else 'MÉDIO — versão desatualizada; somas de verificação oficiais validadas' if component_result and component_result['summary'].get('core_outdated') and component_result['coverage'].get('core') == 'EXECUTED' else 'NENHUMA DIVERGÊNCIA EXPLÍCITA IDENTIFICADA' if component_result and component_result['coverage'].get('core') == 'EXECUTED' else 'NÃO DETERMINADO'}**",
        f"- Risco de persistência externa: **{traduzir_estado(persistence_risk)}**",
        "- A ausência de indicadores conhecidos não comprova ausência de persistência.",
        "", "## Recomendação", "",
        "**REATIVAÇÃO DEPENDE DE REVISÃO TÉCNICA**" if exit_code else "**SEM INDICADORES EXPLÍCITOS; REATIVAÇÃO AINDA EXIGE APROVAÇÃO TÉCNICA**",
        "Resolva as pendências identificadas e valide a segurança do ambiente antes da reativação." if exit_code else "Não foram encontrados os indicadores pesquisados; isso não garante que o site esteja livre de comprometimento.",
        "", "## Abrangência da auditoria", "",
        f"- Auditoria do banco de dados: {'EXECUTADA' if audited else 'NÃO EXECUTADA'}",
        f"- Verificação do núcleo: {traduzir_estado(summary['component_coverage'].get('core', core.get('status', 'NOT EXECUTED')))}",
        f"- Cópia SQL do banco de dados: {'REALIZADA' if (case / 'database-before.sql').is_file() else 'NÃO REALIZADA'}",
        f"- Cópia dos arquivos do site: {'REALIZADA' if (case / 'site-before.tar.gz').is_file() else 'NÃO REALIZADA'}",
        "", "As evidências detalhadas da infraestrutura estão preservadas no relatório técnico interno.", "",
    ]
    management.extend(customer_findings(findings, database, configurations, component_result))
    write_private(case / "report.md", "\n".join(management) + "\n")


@contextlib.contextmanager
def database_client(config: dict[str, str], case: Path):
    """MySQL CLI reads password from a private option file, not argv or env."""
    cnf = case / "mysql-client.cnf"
    def escape(v: str) -> str:
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'
    write_private(cnf, "[client]\n" + "".join(f"{key}={escape(config[key])}\n" for key in ("host", "user", "password")))
    try:
        yield str(cnf)
    finally:
        cnf.unlink(missing_ok=True)

def query_db(option_file: str, dbname: str, sql: str) -> list[list[str]]:
    proc = run(["mysql", f"--defaults-extra-file={option_file}", "--batch", "--skip-column-names", dbname],
               input=sql, capture_output=True)
    return [line.split("\t") for line in proc.stdout.splitlines()]

def component_db_metadata(option_file: str, dbname: str, prefix: str):
    """Read only plugin/theme selection options, never execute serialized data."""
    options = sql_identifier(prefix + "options")
    sql = (f"SELECT option_name, HEX(option_value) FROM {options} "
           "WHERE option_name IN ('active_plugins','template','stylesheet') "
           "AND LENGTH(option_value) < 65536;")
    rows = query_db(option_file, dbname, sql)
    values = {}
    for row in rows:
        if len(row) == 2:
            try:
                values[row[0]] = bytes.fromhex(row[1]).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                continue
    encoded = values.get("active_plugins", "")
    # Serialized PHP string slots only; never use eval or unserialize.
    active = set()
    for length, name in re.findall(r's:(\d+):"([^"]{1,300})";', encoded):
        if len(name.encode("utf-8")) == int(length) and "/" in name and ".." not in name:
            active.add(name)
    return active, values.get("template"), values.get("stylesheet")


def admin_account_inventory(option_file: str, dbname: str, prefix: str, case: Path) -> dict:
    """Inventory administrator role candidates without exporting account names."""
    users, meta = sql_identifier(prefix + "users"), sql_identifier(prefix + "usermeta")
    key = prefix + "capabilities"
    # SQL string is derived solely from the validated table prefix.
    sql = (f"SELECT u.ID, SHA2(u.user_login,256), u.user_registered "
           f"FROM {users} u JOIN {meta} m ON m.user_id=u.ID "
           f"WHERE m.meta_key='{key}' AND m.meta_value LIKE '%administrator%' "
           f"ORDER BY u.ID LIMIT 1000;")
    try:
        rows = query_db(option_file, dbname, sql)
        if any(len(row) != 3 or not row[0].isdigit() or
               not re.fullmatch(r"[A-Fa-f0-9]{64}", row[1]) for row in rows):
            raise AuditError("Unexpected administrator query output")
        result = {"coverage": "EXECUTED", "count": len(rows),
                  "truncated": len(rows) == 1000,
                  "limitations": "Serialized role substring match; multisite super administrators are not covered. Presence is not evidence of compromise.",
                  "accounts": [{"id": int(row[0]), "login_sha256": row[1],
                                "registered": row[2][:25]} for row in rows]}
    except (AuditError, OSError, subprocess.CalledProcessError):
        result = {"coverage": "UNAVAILABLE", "count": None, "accounts": [],
                  "limitations": "Account-role inventory query unavailable; no absence claim can be made."}
    write_private(case / "administrator-inventory.json",
                  json.dumps(result, indent=2, ensure_ascii=False))
    return result


def sql_identifier(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_]+", value):
        raise AuditError("Invalid SQL identifier")
    return "`" + value + "`"

def database_audit(option_file: str, dbname: str, prefix: str, case: Path,
                   post: bool = False) -> list[dict]:
    """Collect targeted SQL metadata without exporting option values.

    Every mandatory query must succeed, otherwise the entire audit fails.
    Explicit zero-count rows document what was checked, rather than silently
    passing missing checks off as no findings.
    """
    options, users, meta = (sql_identifier(prefix + v) for v in ("options", "users", "usermeta"))
    statements = [
        ("suspicious_users", f"SELECT user_login, LENGTH(user_login) FROM {users} WHERE user_login REGEXP '^(admin|administrator|backup)_[0-9a-f]{{6}}$'"),
        ("family_option", f"SELECT option_name, LENGTH(option_value) FROM {options} WHERE option_name LIKE 'sc#_%' ESCAPE '#' OR option_name LIKE '_transient_sc#_%' ESCAPE '#' OR option_name LIKE '_transient_timeout_sc#_%' ESCAPE '#'"),
        ("marker_option", f"SELECT option_name, LENGTH(option_value) FROM {options} WHERE option_name NOT IN ('cron','active_plugins','SimplePluginLogger_plugin_info_before_update') AND (option_value LIKE '%cipher-feeder%' OR option_value LIKE '%sc_cron_guard%' OR option_value LIKE '%sc_persist_manifest%' OR option_value LIKE '%trace-inspector-pad%')"),
        ("historical_cache", f"SELECT option_name, LENGTH(option_value) FROM {options} WHERE option_name='SimplePluginLogger_plugin_info_before_update' AND option_value LIKE '%trace-inspector-pad%'"),
        ("cron_marker", f"SELECT option_name, LENGTH(option_value) FROM {options} WHERE option_name='cron' AND (option_value LIKE '%cipher-feeder%' OR option_value LIKE '%sc_cron_guard%' OR option_value LIKE '%sc_cron_fetch%' OR option_value LIKE '%sc_persist_manifest%')"),
        ("active_plugins_marker", f"SELECT option_name, LENGTH(option_value) FROM {options} WHERE option_name='active_plugins' AND (option_value LIKE '%trace-inspector-pad%' OR option_value LIKE '%cipher-feeder%' OR option_value LIKE '%sc_cron_guard%')"),
        ("session_rows", f"SELECT 'session_tokens', COUNT(*) FROM {meta} WHERE meta_key='session_tokens'"),
        ("application_password_rows", f"SELECT 'application_passwords', COUNT(*) FROM {meta} WHERE meta_key LIKE '%application_passwords'"),
    ]
    # Fetch SHA-256, exact byte length, and a bounded HEX-encoded prefix.
    # Hex keeps tabs/newlines out of the MySQL batch protocol.
    # No unmasked database values are persisted in generated reports.
    detail_query = (f"SELECT option_name, OCTET_LENGTH(option_value), "
                    f"SHA2(option_value,256), HEX(LEFT(option_value,2048)) FROM {options} "
                    f"WHERE option_name LIKE 'sc#_%' ESCAPE '#' "
                    f"OR option_name LIKE '_transient_sc#_%' ESCAPE '#' "
                    f"OR option_name LIKE '_transient_timeout_sc#_%' ESCAPE '#' "
                    f"OR option_name IN ('SimplePluginLogger_plugin_info_before_update','cron','active_plugins') "
                    f"OR option_value LIKE '%cipher-feeder%' OR option_value LIKE '%sc_cron_guard%' "
                    f"OR option_value LIKE '%sc_persist_manifest%' OR option_value LIKE '%trace-inspector-pad%';")
    details = {}
    for row in query_db(option_file, dbname, detail_query):
        if len(row) != 4 or not re.fullmatch(r"[0-9a-fA-F]{64}", row[2]):
            raise AuditError("Invalid evidence hash row returned by MySQL")
        try:
            excerpt = bytes.fromhex(row[3]).decode("utf-8", "replace")
        except ValueError as error:
            raise AuditError("Malformed encoded database evidence") from error
        details[row[0]] = {"sha256": row[2], "value_length_bytes": int(row[1]),
                           "value_prefix": excerpt}
    findings = []
    for kind, sql in statements:
        rows = query_db(option_file, dbname, sql + ";")
        if kind in ("session_rows", "application_password_rows"):
            if len(rows) != 1 or len(rows[0]) < 2 or not rows[0][1].isdigit():
                raise AuditError(f"Invalid database count for {kind}")
            findings.append({"kind": kind, "name": kind, "length": rows[0][1],
                             "state": "PRESENT" if int(rows[0][1]) else "ABSENT"})
        elif rows:
            for row in rows:
                if len(row) < 2:
                    raise AuditError(f"Malformed database audit row for {kind}")
                name = row[0]
                meta = details.get(name, {})
                prefix_value = meta.get("value_prefix", "")
                if prefix_value.startswith(("a:", "s:", "O:", "i:", "b:", "d:")):
                    classification = "PHP_SERIALIZED_NOT_DESERIALIZED"
                elif prefix_value.startswith(("{", "[")):
                    classification = "JSON_OR_STRUCTURED_TEXT"
                elif re.fullmatch(r"[0-9A-Fa-f]{12,}", prefix_value):
                    classification = "HEX_CANDIDATE"
                elif re.fullmatch(r"[A-Za-z0-9+/]{12,}={0,2}", prefix_value):
                    classification = "BASE64_CANDIDATE"
                else:
                    classification = "PLAIN_OR_UNKNOWN"
                # Display scalar values only for two exact, known numeric
                # indicators. Never expose generic sc_* values or cache data.
                scalar_name = name in ("_transient_sc_spread_interval",
                                       "_transient_timeout_sc_spread_interval")
                scalar_safe = (kind == "family_option" and scalar_name and
                               bool(re.fullmatch(r"[0-9]{1,20}", prefix_value)) and
                               meta.get("value_length_bytes") == len(prefix_value))
                if scalar_safe:
                    classification = "ESCALAR_TEXTO_NUMERO_NAO_CODIFICADO"
                # Only approved IOC tokens or explicitly allowlisted numeric
                # values may be displayed; do not print arbitrary DB data.
                known_tokens = ("cipher-feeder", "sc_cron_guard", "sc_cron_fetch",
                                "sc_persist_manifest", "trace-inspector-pad")
                safe_tokens = [token for token in known_tokens if token in prefix_value]
                findings.append({
                    "kind": kind, "name": safe_option_name(name), "length": row[1],
                    "state": ("HISTORICAL_REFERENCE" if kind == "historical_cache"
                              else "RESIDUO_FAMILIA_REQUER_LIMPEZA" if kind == "family_option"
                              else "REVIEW"),
                    "sha256": meta.get("sha256"),
                    "value_length_bytes": meta.get("value_length_bytes"),
                    "value_classification": classification if meta else "NOT_AVAILABLE",
                    "safe_excerpt": (prefix_value if scalar_safe else
                                     "[OMITTED_BY_POLICY]" if kind == "historical_cache"
                                     else ", ".join(safe_tokens) if safe_tokens else "[OMITTED_BY_POLICY]"),
                    "decoded_excerpt": "[OMITTED_BY_POLICY]",
                })
        else:
            findings.append({"kind": kind, "name": "(none)", "length": "0", "state": "NOT_FOUND"})
    cron_info = details.get("cron")
    if cron_info:
        findings.append({
            "kind": "cron_metadata", "name": "cron",
            "length": str(cron_info["value_length_bytes"]), "state": "INFORMATIONAL",
            "sha256": cron_info["sha256"],
            "value_length_bytes": cron_info["value_length_bytes"],
            "value_classification": "DYNAMIC_WORDPRESS_CRON",
            "safe_excerpt": "[NOT_EXPOSED]",
            "decoded_excerpt": "[NOT_EXPOSED]",
            "collected_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "indicator_matches": [x["name"] for x in findings if x["kind"] == "cron_marker" and x.get("state") != "NOT_FOUND"],
        })
    write_private(case / ("database-post-audit.json" if post else "database-evidence.json"),
                  json.dumps(findings, indent=2))
    return findings


def snapshot(target: Path, case: Path, option_file: str, dbname: str) -> None:
    """Mandatory recovery backup (not generated for read-only audit modes)."""
    tarpath = case / "site-before.tar.gz"
    with tarfile.open(tarpath, "w:gz", dereference=False) as archive:
        archive.add(target, arcname="site", recursive=True)
    os.chmod(tarpath, 0o600)
    # Read each archived regular file through the decompressor; merely
    # listing tar headers does not detect a corrupt compressed file body.
    with tarfile.open(tarpath, "r:gz") as archive:
        for member in archive:
            if not member.isfile():
                continue
            stream = archive.extractfile(member)
            if stream is None:
                raise AuditError("Unreadable archived regular file")
            with stream:
                while stream.read(1048576):
                    pass
    write_private(case / "site-before.sha256", sha256(tarpath) + "  site-before.tar.gz\n")
    dump = case / "database-before.sql"
    descriptor = os.open(dump, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        subprocess.run(["mysqldump", f"--defaults-extra-file={option_file}", "--single-transaction",
                        "--quick", "--hex-blob", "--no-tablespaces", dbname], stdout=stream, check=True)
    if dump.stat().st_size == 0:
        raise AuditError("Empty database dump")
    write_private(case / "database-before.sha256", sha256(dump) + "  database-before.sql\n")

def safe_zip_extract(archive: zipfile.ZipFile, dest: Path) -> None:
    """Reject path traversal, symlinks, special members and decompression bombs."""
    total = 0
    for entry in archive.infolist():
        name = entry.filename.replace("\\", "/")
        parts = name.split("/")
        mode = (entry.external_attr >> 16) & 0o170000
        if (name.startswith("/") or any(x == ".." for x in parts)
                or mode not in (0, stat.S_IFREG, stat.S_IFDIR)):
            raise AuditError("Unsafe ZIP member")
        total += entry.file_size
        if entry.file_size > 200_000_000 or total > 500_000_000 or len(archive.infolist()) > 10000:
            raise AuditError("ZIP size limit exceeded")
    for entry in archive.infolist():
        name = entry.filename.replace("\\", "/")
        member = dest.joinpath(*[p for p in name.split("/") if p and p != "."])
        if entry.is_dir():
            member.mkdir(parents=True, exist_ok=True)
        else:
            member.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(entry) as source, member.open("xb") as output:
                shutil.copyfileobj(source, output)

def wp_org_metadata(kind: str, slug: str) -> dict:
    endpoint = ("plugins" if kind == "plugin" else "themes")
    action = "plugin_information" if kind == "plugin" else "theme_information"
    params = urllib.parse.urlencode({"action": action, "request[slug]": slug})
    request = urllib.request.Request(f"https://api.wordpress.org/{endpoint}/info/1.2/?{params}",
                                     headers={"User-Agent": f"wp-integrity-audit/{VERSION}"})
    with urllib.request.urlopen(request, timeout=25) as response:
        data = json.load(response)
    if not isinstance(data, dict) or data.get("error") or not data.get("download_link"):
        raise AuditError(f"Unavailable/unofficial {kind}: {slug}")
    return data

def official_sync(target: Path, stage: Path, case: Path) -> None:
    """Stage official components; premium/custom components fail closed."""
    log = []
    for kind, subdir in (("plugin", "plugins"), ("theme", "themes")):
        root = target / "wp-content" / subdir
        if not root.is_dir():
            continue
        for item in sorted(root.iterdir()):
            if not item.is_dir() or item.is_symlink() or item.name.startswith("."):
                continue
            metadata = wp_org_metadata(kind, item.name)
            url = metadata["download_link"]
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme != "https" or parsed.hostname not in ("downloads.wordpress.org", "wordpress.org"):
                raise AuditError("Untrusted WordPress package host")
            with urllib.request.urlopen(url, timeout=60) as response:
                # urllib follows redirects; validate the final destination too.
                final = urllib.parse.urlparse(response.geturl())
                if final.scheme != "https" or final.hostname not in ("downloads.wordpress.org", "wordpress.org"):
                    raise AuditError("WordPress package redirected outside trusted HTTPS hosts")
                data = response.read(50_000_001)
            if len(data) > 50_000_000:
                raise AuditError("Download exceeds configured size limit")
            with tempfile.TemporaryDirectory(prefix="wp-zip-", dir=case) as tmp:
                path = Path(tmp)
                package = path / "package.zip"
                package.write_bytes(data)
                with zipfile.ZipFile(package) as archive:
                    safe_zip_extract(archive, path / "extract")
                extracted = path / "extract"
                candidate = extracted / item.name
                if not candidate.is_dir():
                    dirs = [p for p in extracted.iterdir() if p.is_dir()]
                    if len(dirs) != 1:
                        raise AuditError("Unexpected component archive layout")
                    candidate = dirs[0]
                destination = stage / subdir / item.name
                if destination.exists():
                    shutil.rmtree(destination)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copytree(candidate, destination, symlinks=False)
            log.append({"kind": kind, "slug": item.name, "version": metadata.get("version"),
                        "sha256": hashlib.sha256(data).hexdigest()})
    write_private(case / "official-components.json", json.dumps(log, indent=2))

def validate_source(source: Path, target: Path) -> Path:
    source = source.resolve(strict=True)
    if not source.is_dir() or source == target / "wp-content" or target in source.parents:
        raise AuditError("Source must be an independent clean directory")
    # shutil.copytree follows symlinks unless explicitly forbidden.
    # Reject special files and symlinks BEFORE copying any untrusted source.
    for directory, dirs, files in os.walk(source, followlinks=False):
        for name in dirs + files:
            member = Path(directory) / name
            mode = member.lstat().st_mode
            if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                raise AuditError(f"Clean source has symlink or special file: {member}")
    for path in iter_files(source):
        if path.name.startswith(PATTERN_NAMES) or "cipher-feeder" in path.name or path.name == "trace-inspector-pad.php":
            raise AuditError(f"Known IOC filename in clean source: {path}")
        if path.suffix.lower() in (".php", ".inc", ".phtml", ".phar"):
            with path.open("rb") as stream:
                overlap = b""
                while chunk := stream.read(65536):
                    sample = overlap + chunk
                    if IOC.search(sample.decode("utf-8", "replace")):
                        raise AuditError(f"Known IOC in proposed clean source: {path}")
                    overlap = sample[-256:]
    return source

def stage_files(target: Path, source: Path, case: Path, replace: bool, sync: bool) -> Path:
    """Build stage on same filesystem to support rename-based cutover."""
    stage = Path(tempfile.mkdtemp(prefix=".wp-content-stage-", dir=target.parent))
    try:
        shutil.copytree(source, stage, dirs_exist_ok=True, symlinks=False)
        if sync:
            official_sync(target, stage, case)
        if not replace and any((stage / part).is_dir() and list((stage / part).iterdir())
                               for part in ("plugins", "themes")):
            raise AuditError("Source has plugins/themes; explicitly specify --replace-plugins-themes")
        # Re-check the entire stage, including official downloads.
        validate_source(stage, target)
        return stage
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise

def post_recovery_blockers(database: list[dict], files: list[dict],
                           processes: list[str]) -> list[str]:
    """Return active post-recovery indicators; ignore absent and informational rows."""
    blockers = []
    active_kinds = {"family_option", "marker_option", "cron_marker", "active_plugins_marker"}
    for item in database:
        if item.get("kind") in active_kinds and item.get("state") not in ("NOT_FOUND", "ABSENT"):
            blockers.append("database:" + str(item.get("kind")))
    if any(item.get("classification") == "IOC_REQUER_VALIDACAO" for item in files):
        blockers.append("file_ioc")
    if processes:
        blockers.append("process_ioc")
    return blockers


def swap_files(target: Path, stage: Path, case: Path) -> Path:
    old = target / "wp-content"
    # Quarantine MUST remain outside the HTTP document root.
    quarantine = target.parent / f".{target.name}.wp-content-quarantine-{case.name}"
    if quarantine.exists():
        raise AuditError("Quarantine path already exists")
    old.rename(quarantine)
    try:
        stage.rename(old)
    except BaseException:
        quarantine.rename(old)
        raise
    write_private(case / "quarantine-path.txt", str(quarantine) + "\n")
    return quarantine

def sql_cleanup(option_file: str, dbname: str, prefix: str, case: Path) -> None:
    """Remove known family option rows and tokens, retaining serialized cron/plugins.

    For active_plugins/cron with suspicious markers, stop instead of deleting
    entire serialized options. A targeted parser/remediator is required.
    """
    opt, meta = (sql_identifier(prefix + name) for name in ("options", "usermeta"))
    suspicious = query_db(option_file, dbname,
        f"SELECT option_name FROM {opt} WHERE option_name IN ('active_plugins','cron') "
        "AND (option_value LIKE '%cipher-feeder%' OR option_value LIKE '%trace-inspector-pad%' "
        "OR option_value LIKE '%sc_cron_guard%' OR option_value LIKE '%sc_persist_manifest%' "
        "OR option_value LIKE '%sc_cron_fetch%');")
    if suspicious:
        write_private(case / "manual-serialized-cleanup.json", json.dumps(suspicious))
        raise AuditError("Malicious markers in serialized cron/active_plugins; refusing destructive deletion")
    sql = (f"START TRANSACTION;\n"
           f"DELETE FROM {meta} WHERE meta_key='session_tokens' OR meta_key LIKE '%application_passwords';\n"
           f"DELETE FROM {opt} WHERE option_name LIKE 'sc#_%' ESCAPE '#' "
           f"OR option_name LIKE '_transient_sc#_%' ESCAPE '#' "
           f"OR option_name LIKE '_transient_timeout_sc#_%' ESCAPE '#';\n"
           f"COMMIT;\n")
    query_db(option_file, dbname, sql)

def rotate_salts(path: Path) -> None:
    """Atomically rewrite literal auth keys without executing wp-config.php."""
    if path.is_symlink():
        raise AuditError("Refusing to rewrite symlinked wp-config.php")
    keys = ("AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY",
            "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT")
    data = path.read_text(encoding="utf-8")
    for key in keys:
        pattern = re.compile(r"(define\s*\(\s*['\"]" + key + r"['\"]\s*,\s*)['\"][^'\"\r\n]*['\"](\s*\)\s*;)")
        data, count = pattern.subn(lambda m: m.group(1) + "'" + secrets.token_urlsafe(48) + "'" + m.group(2), data, count=1)
        if count != 1:
            raise AuditError(f"Missing/nonliteral WordPress salt: {key}")
    descriptor, temp = tempfile.mkstemp(prefix=".wp-config-", dir=path.parent)
    try:
        original = path.stat()
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temp, original.st_uid, original.st_gid)
        # Never retain permissions broader than owner/group read access.
        os.chmod(temp, stat.S_IMODE(original.st_mode) & 0o640)
        os.replace(temp, path)
    finally:
        Path(temp).unlink(missing_ok=True)

def preflight_recovery_sources(target: Path, core_source: Path | None) -> None:
    """Validate core source and literal salts BEFORE database/file changes."""
    config = target / "wp-config.php"
    if config.is_symlink():
        raise AuditError("Recovery cannot rewrite a symlinked wp-config.php")
    data = config.read_text(encoding="utf-8", errors="replace")
    for key in ("AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY",
                "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT"):
        pattern = re.compile(r"define\s*\(\s*['\\\"]" + key +
                             r"['\\\"]\s*,\s*['\\\"][^'\\\"\r\n]*['\\\"]\s*\)\s*;")
        if not pattern.search(data):
            raise AuditError(f"Missing/nonliteral salt in wp-config.php: {key}")
    if core_source is None:
        return
    core_source = core_source.resolve(strict=True)
    if core_source == target or target in core_source.parents or core_source in target.parents:
        raise AuditError("Core source must be independent of the target")
    if not all((core_source / x).exists() for x in ("wp-admin", "wp-includes", "wp-load.php")):
        raise AuditError("Invalid core source")
    for directory, dirs, files in os.walk(core_source, followlinks=False):
        for name in dirs + files:
            mode = (Path(directory) / name).lstat().st_mode
            if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                raise AuditError("Core source contains symlinks or special files")


def sync_core(source: Path, target: Path) -> None:
    source = source.resolve(strict=True)
    if source == target or target in source.parents or source in target.parents:
        raise AuditError("Clean WordPress core must be independent of the target")
    if not all((source / x).exists() for x in ("wp-admin", "wp-includes", "wp-load.php")):
        raise AuditError("Invalid core source")
    for directory, dirs, files in os.walk(source, followlinks=False):
        for name in dirs + files:
            mode = (Path(directory) / name).lstat().st_mode
            if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                raise AuditError("Core source contains symlinks or special files")
    for dirname in ("wp-admin", "wp-includes"):
        shutil.copytree(source / dirname, target / dirname, dirs_exist_ok=True, symlinks=False)
    for path in source.iterdir():
        if path.is_file() and (path.suffix == ".php" or path.name in ("license.txt", "readme.html")):
            shutil.copy2(path, target / path.name)

def compare_components(target: Path, source: Path, case: Path) -> None:
    """Compare production and incoming component directories by category."""
    report = {}
    for name in ("plugins", "themes"):
        production = target / "wp-content" / name
        incoming = source / name
        a = {p.name for p in production.iterdir() if p.is_dir()} if production.is_dir() else set()
        b = {p.name for p in incoming.iterdir() if p.is_dir()} if incoming.is_dir() else set()
        report[name] = {"production_only": sorted(a - b), "source_only": sorted(b - a), "shared": sorted(a & b)}
    write_private(case / "components-comparison.json", json.dumps(report, indent=2))


def elementor_asset_audit(target: Path, case: Path) -> None:
    """Inventory generated CSS/font assets without modifying site content."""
    root = target / "wp-content" / "uploads" / "elementor"
    results = {}
    for name, extensions in (("css", (".css",)), ("google-fonts", (".css", ".woff", ".woff2"))):
        folder = root / name
        results[name] = sum(p.suffix.lower() in extensions for p in iter_files(folder)) if folder.is_dir() else 0
    write_private(case / "elementor-assets.json", json.dumps(results, indent=2))


def upload_permissions_audit(target: Path, case: Path) -> None:
    """Record owner/mode; unsafe guessed recursive ownership changes are omitted."""
    root = target / "wp-content" / "uploads"
    if root.is_dir():
        st = root.stat()
        write_private(case / "uploads-metadata.json",
                      json.dumps({"uid": st.st_uid, "gid": st.st_gid, "mode": oct(stat.S_IMODE(st.st_mode))}, indent=2))


def compare_cases(old_case: Path, new_case: Path, output: Path) -> dict:
    """Compare immutable case evidence by semantic identity, not ephemeral IDs."""
    def load(case: Path, name: str):
        case = case.resolve(strict=True)
        if not case.is_dir() or case.is_symlink():
            raise AuditError("Comparison source must be an existing case directory")
        file = case / name
        if file.is_symlink() or not file.is_file():
            raise AuditError(f"Missing or symlinked case evidence: {name}")
        with file.open(encoding="utf-8") as stream:
            return json.load(stream)
    old_real, new_real = old_case.resolve(strict=True), new_case.resolve(strict=True)
    requested_output = output.resolve()
    if (requested_output == old_real or requested_output == new_real or
            old_real in requested_output.parents or new_real in requested_output.parents):
        raise AuditError("Comparison output must be outside both source cases")
    old_summary, new_summary = load(old_case, "report.json"), load(new_case, "report.json")
    if not old_summary.get("database_audited") or not new_summary.get("database_audited"):
        raise AuditError("Comparison requires two complete database audits")
    if old_summary.get("database") != new_summary.get("database"):
        raise AuditError("Refusing comparison across different database names")
    def keys(case: Path, name: str, source: str):
        items = load(case, name)
        if not isinstance(items, list):
            raise AuditError("Invalid case evidence schema")
        result = {}
        for item in items:
            key = (item.get("path") if source == "file" else
                   (item.get("kind"), item.get("name")))
            if not key or (source != "file" and not all(key)):
                raise AuditError("Malformed comparison evidence key")
            fingerprint = item.get("sha256") or item.get("state") or item.get("classification")
            result[key] = fingerprint
        return result
    outcomes = {}
    for label, filename in (("files", "file-evidence.json"), ("database", "database-evidence.json")):
        before = keys(old_case, filename, label[:-1] if label == "files" else "database")
        after = keys(new_case, filename, label[:-1] if label == "files" else "database")
        stringify = lambda value: value if isinstance(value, str) else ":".join(value)
        outcomes[label] = {
            "removed": sorted(stringify(k) for k in before.keys() - after.keys()),
            "added": sorted(stringify(k) for k in after.keys() - before.keys()),
            "changed": sorted(stringify(k) for k in before.keys() & after.keys()
                              if before[k] != after[k]),
            "unchanged_count": sum(before[k] == after[k] for k in before.keys() & after.keys()),
        }
    # Compare version/provenance evidence when both historical cases include it.
    if all((case / "component-version-evidence.json").is_file() and
           not (case / "component-version-evidence.json").is_symlink()
           for case in (old_case, new_case)):
        def component_keys(case: Path) -> dict:
            document = load(case, "component-version-evidence.json")
            if not isinstance(document, dict) or not isinstance(document.get("components"), list):
                raise AuditError("Invalid historical component evidence")
            index = {}
            for component in document["components"]:
                kind, slug = component.get("type"), component.get("slug")
                if not isinstance(kind, str) or not isinstance(slug, str) or not kind or not slug:
                    raise AuditError("Invalid historical component identity")
                index[kind + ":" + slug] = (component.get("local_version"), component.get("state"),
                                             component.get("main_file_sha256"))
            return index
        previous, current = component_keys(old_case), component_keys(new_case)
        outcomes["components"] = {
            "removed": sorted(previous.keys() - current.keys()),
            "added": sorted(current.keys() - previous.keys()),
            "changed": sorted(key for key in previous.keys() & current.keys()
                              if previous[key] != current[key]),
            "unchanged_count": sum(previous[key] == current[key]
                                   for key in previous.keys() & current.keys()),
        }
    report = {
        "schema_version": 1,
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "old_status": old_summary.get("status"),
        "new_status": new_summary.get("status"),
        "database": old_summary.get("database"),
        "diff": outcomes,
        "note": "Changed hashes or dynamic cron values alone do not establish compromise or remediation.",
    }
    ensure_private_dir(output)
    write_private(output / "comparison.json", json.dumps(report, indent=2, ensure_ascii=False))
    lines = ["# WordPress Audit Case Comparison", "",
             f"- Previous status: `{report['old_status']}`",
             f"- Current status: `{report['new_status']}`",
             "- Comparison is read-only for the source cases.", ""]
    for category, differences in outcomes.items():
        lines += [f"## {category.title()}", ""]
        for change in ("added", "removed", "changed"):
            lines += [f"### {change.title()} ({len(differences[change])})", ""]
            lines += [f"- `{v}`" for v in differences[change]]
        lines += [f"- Unchanged: {differences['unchanged_count']}", ""]
    lines += ["## Interpretation", "", report["note"], "",
              "Release decisions require independent review; this comparison never approves reopening.", ""]
    write_private(output / "comparison.md", "\n".join(lines))
    return report


def mark_incomplete_case(case: Path, skipped: list[str]) -> None:
    """Never report zero explicit markers as complete after requested omissions."""
    report_file = case / "report.json"
    document = json.loads(report_file.read_text(encoding="utf-8"))
    document["omitted_checks"] = skipped
    if document.get("exit_code") == 0:
        document["status"] = "AUDITORIA_INCOMPLETA"
        document["exit_code"] = 40
    write_private(report_file, json.dumps(document, indent=2, ensure_ascii=False))
    for markdown in (case / "report.md", case / "technical-report.md"):
        previous = markdown.read_text(encoding="utf-8")
        previous += "\n## Omitted checks\n\n" + "\n".join(f"- {name}" for name in skipped) + "\n"
        if document["exit_code"] == 40:
            previous = previous.replace("Final status: **SEM_MARCADOR_EXPLICITO**",
                                        "Final status: **AUDITORIA_INCOMPLETA**", 1)
            previous = previous.replace("Exit code: **0**", "Exit code: **40**", 1)
        write_private(markdown, previous)
    csv_file = case / "report.csv"
    rows = list(csv.reader(csv_file.read_text(encoding="utf-8").splitlines()))
    if len(rows) == 2 and "status" in rows[0]:
        rows[1][rows[0].index("status")] = document["status"]
        rows[1][rows[0].index("exit_code")] = str(document["exit_code"])
        data = io.StringIO()
        csv.writer(data).writerows(rows)
        write_private(csv_file, data.getvalue())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Auditoria de Integridade WordPress (Python)")
    modes = parser.add_mutually_exclusive_group()
    for opt in ("audit", "audit-db", "audit-db-post", "apply-files", "apply-db", "recover"):
        modes.add_argument("--" + opt, dest="mode", action="store_const", const=opt)
    parser.set_defaults(mode="audit")
    parser.add_argument("target", nargs="?", type=Path)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--core-source", type=Path)
    parser.add_argument("--domain-label")
    parser.add_argument("--db-host")
    parser.add_argument("--replace-plugins-themes", action="store_true")
    parser.add_argument("--official-sync", action="store_true")
    parser.add_argument("--case-root", type=Path, default=Path("/var/lib/wp-integrity-audit/cases"),
                        help="Diretório das evidências (padrão: /var/lib/wp-integrity-audit/cases)")
    # A normal audit enables every available passive probe.
    # Mutating operations always require separate explicit mode and confirmation.
    parser.add_argument("--skip-version-check", action="store_true", help="Desativa a verificação de versões do núcleo, dos plugins e dos temas")
    parser.add_argument("--offline", action="store_true", help="Desativa consultas externas ao WordPress.org")
    parser.add_argument("--bundle-evidence", action="store_true", help="Cria arquivo TAR privado com evidências forenses (dados sensíveis)")
    parser.add_argument("--verify-case", type=Path, help="Verifica o manifesto de um caso existente sem analisar o WordPress")
    parser.add_argument("--email-to", help="Envia o PDF gerencial ao destinatário informado")
    parser.add_argument("--config", "--smtp-config", dest="smtp_config", type=Path,
                        default=Path("/etc/wp-integrity-audit/config.cfg"),
                        help="Configuração SMTP privada (padrão: /etc/wp-integrity-audit/config.cfg)")
    parser.add_argument("--pdf-report", action="store_true", help="Exporta o relatório gerencial em PDF (requer reportlab)")
    parser.add_argument("--show-report", action="store_true", help="Exibe o relatório gerencial no terminal")
    parser.add_argument("--no-show-report", action="store_true", help="Não exibe o relatório gerencial no terminal")
    parser.add_argument("--official-compare", action="store_true", help="Explicitly enable official comparison")
    parser.add_argument("--skip-core", action="store_true", help="Skip official WordPress Core checksum comparison")
    parser.add_argument("--skip-host-persistence", action="store_true", help="Skip Linux persistence metadata inventory")
    parser.add_argument("--skip-db", "--files-only", dest="skip_db", action="store_true",
                        help="Ignora a verificação do banco de dados; a auditoria ficará incompleta")
    parser.add_argument("--skip-files", action="store_true", help="Skip WordPress file scanning")
    parser.add_argument("--skip-config", action="store_true", help="Skip configuration metadata scanning")
    parser.add_argument("--skip-processes", action="store_true", help="Skip process indicator scanning")
    parser.add_argument("--skip-elementor", action="store_true", help="Skip Elementor asset checks")
    parser.add_argument("--compare", nargs=2, metavar=("OLD_CASE", "NEW_CASE"), type=Path,
                        help="Compara dois diretórios de casos existentes sem analisar um site em produção")
    parser.add_argument("--compare-output", type=Path,
                        help="Diretório privado para resultados da comparação")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    if args.verify_case:
        if args.target is not None or args.compare or args.mode != "audit" or args.bundle_evidence or args.pdf_report:
            parser.error("--verify-case must be used alone without a target or report options")
        return args
    if args.compare:
        if args.target is not None or args.email_to or args.mode != "audit" or args.skip_db or args.source or args.core_source or args.skip_core or args.skip_host_persistence or args.skip_files or args.skip_config or args.skip_processes or args.skip_elementor or args.skip_version_check or args.offline or args.official_compare:
            parser.error("--compare cannot be combined with a target or audit/recovery options")
        return args
    if args.email_to and (args.compare or args.verify_case or args.mode != "audit"):
        parser.error("Email delivery requires a normal read-only audit")
    if args.compare_output:
        parser.error("--compare-output requires --compare")
    if args.target is None:
        parser.error("TARGET is required")
    disabled = (args.skip_db or args.skip_core or args.skip_host_persistence or
                args.skip_files or args.skip_config or args.skip_processes or args.skip_elementor or args.skip_version_check)
    if disabled and args.mode != "audit":
        parser.error("--skip-* switches are valid only with --audit")
    if args.mode in ("apply-files", "recover") and not args.source:
        parser.error("--source is required for file replacement")
    if args.core_source and args.mode != "recover":
        parser.error("--core-source is only valid with --recover")
    if args.official_sync and args.mode not in ("apply-files", "recover"):
        parser.error("--official-sync requires file replacement")
    return args

def present_management_report(case: Path, *, show: bool = False,
                              no_show: bool = False, tty: bool | None = None) -> None:
    """Display only the management report on TTY; never leak it to pipelines."""
    path = case / "report.md"
    print(f"Management report: {path}")
    interactive = sys.stdout.isatty() if tty is None else tty
    if no_show or not interactive:
        return
    if not path.is_file() or path.is_symlink():
        print("Management report unavailable", file=sys.stderr)
        return
    print("\n--- start of report ---")
    print(path.read_text(encoding="utf-8"), end="\n")
    print("--- end of report ---")


def main() -> int:
    # Protect backup and report files from their first byte of creation.
    os.umask(0o077)
    args = parse_args()
    if args.verify_case:
        verdict = verify_evidence_manifest(args.verify_case)
        print(json.dumps(verdict, indent=2))
        return 0 if verdict["status"] == "MATCH" else 40
    if args.compare:
        output = args.compare_output or (Path.cwd() / "wp-audit-comparison")
        compare_cases(args.compare[0], args.compare[1], output)
        print(f"Comparison created at {output}")
        return 0
    if args.mode in ("apply-files", "apply-db", "recover"):
        raise AuditError("Mutating modes are disabled pending verified upload, ownership and rollback safety")
    target = validate_site(args.target)
    proposed_case_root = args.case_root.resolve()
    if proposed_case_root == target or target in proposed_case_root.parents:
        raise AuditError("Forensic case root must be outside the WordPress document root")
    case_root = ensure_private_dir(args.case_root)
    lock = case_root / ".audit.lock"
    with lock.open("a+") as lockfile:
        fcntl.flock(lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
        timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        label = re.sub(r"[^A-Za-z0-9._-]", "_", args.domain_label or target.parent.name)
        case = ensure_private_dir(case_root / f"{label}-{timestamp}-{secrets.token_hex(3)}")
        print(f"Version {VERSION}; mode={args.mode}; case={case}")
        is_audit = args.mode == "audit"
        files = [] if is_audit and args.skip_files else file_audit(target, case)
        if is_audit:
            wordpress_persistence_inventory(target, case)
            recent_file_timeline(target, case)
        if not (is_audit and args.skip_config):
            configuration_audit(target, case)
        if is_audit and not args.skip_host_persistence:
            if sys.platform != "linux":
                raise AuditError("Host persistence inventory is supported only on Linux")
            host_persistence_inventory(case, [Path(p) for p in ("/etc/crontab", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/systemd/system", "/etc/php", "/etc/apache2",
                          "/etc/profile.d", "/etc/rc.local", "/etc/ld.so.preload",
                          "/etc/sudoers.d", "/var/spool/cron")])
        if not (is_audit and args.skip_elementor):
            elementor_asset_audit(target, case)
        processes = [] if is_audit and args.skip_processes else process_audit(case)
        omitted = [name for name, skipped in (("files", args.skip_files), ("config", args.skip_config),
                   ("core", args.skip_core), ("host_persistence", args.skip_host_persistence),
                   ("elementor", args.skip_elementor), ("processes", args.skip_processes),
                   ("database", args.skip_db), ("version_check", args.skip_version_check)) if skipped]
        if is_audit and args.skip_db:
            if args.skip_version_check:
                component_versions.write_skipped(case)
            else:
                component_versions.audit(target, case, offline=args.offline, skip_core=args.skip_core)
            make_report(case, args.mode, files, processes)
            component_versions.append_management_section(case)
            mark_incomplete_case(case, omitted)
            incident_containment_note(case, label)
            if args.pdf_report or args.email_to:
                report_export.export_management_pdf(case)
            if args.email_to:
                mail_delivery.send_management_report(case, args.email_to, args.smtp_config)
            create_evidence_manifest(case)
            if args.bundle_evidence:
                bundle_case_evidence(case)
            print("Auditoria concluída; banco de dados NÃO ANALISADO")
            present_management_report(case, show=args.show_report, no_show=args.no_show_report)
            return 40
        config, prefix = parse_wordpress(target / "wp-config.php")
        dbname = config["DB_NAME"]
        if not re.fullmatch(r"[A-Za-z0-9_]+", dbname):
            raise AuditError("Unsupported database name")
        with database_client({"host": args.db_host or config["DB_HOST"],
                              "user": config["DB_USER"], "password": config["DB_PASSWORD"]}, case) as cnf:
            if args.mode in ("audit", "audit-db", "audit-db-post"):
                database = database_audit(cnf, dbname, prefix, case, post=args.mode == "audit-db-post")
                if is_audit:
                    admin_account_inventory(cnf, dbname, prefix, case)
                    if args.skip_version_check:
                        component_versions.write_skipped(case)
                    else:
                        installed_plugins, template, stylesheet = component_db_metadata(cnf, dbname, prefix)
                        component_versions.audit(target, case, offline=args.offline, skip_core=args.skip_core,
                                                 active_plugins=installed_plugins, template=template,
                                                 stylesheet=stylesheet)
                make_report(case, args.mode, files, processes, database, dbname, prefix)
                if is_audit:
                    component_versions.append_management_section(case)
                if omitted:
                    mark_incomplete_case(case, omitted)
                if is_audit:
                    incident_containment_note(case, label)
                    if args.pdf_report or args.email_to:
                        report_export.export_management_pdf(case)
                    if args.email_to:
                        mail_delivery.send_management_report(case, args.email_to, args.smtp_config)
                    create_evidence_manifest(case)
                    if args.bundle_evidence:
                        bundle_case_evidence(case)
                with (case / "report.json").open(encoding="utf-8") as stream:
                    outcome = json.load(stream)
                print("Auditoria concluída: status=" + outcome["status"] + "; código de saída=" + str(outcome["exit_code"]))
                present_management_report(case, show=args.show_report, no_show=args.no_show_report)
                return outcome["exit_code"]
            if os.geteuid() != 0:
                raise AuditError("Recovery requires root; audit does not")
            if args.mode == "recover" and processes:
                raise AuditError("Matching suspicious processes are still active; isolate the host first")
            if args.mode == "recover":
                preflight_recovery_sources(target, args.core_source)
            if (target / "wp-content").is_symlink():
                raise AuditError("Cannot safely replace symlinked wp-content")
            print("Recovery modifies files and/or database; independent verified backup is required.")
            ask("Confirm site isolation and independent backup")
            snapshot(target, case, cnf, dbname)
            stage = None
            if args.mode in ("apply-files", "recover"):
                source = validate_source(args.source, target)
                compare_components(target, source, case)
                stage = stage_files(target, source, case,
                                    args.replace_plugins_themes or args.official_sync, args.official_sync)
            try:
                if args.mode in ("apply-db", "recover"):
                    # Preflight serialized database options before changing files.
                    opt = sql_identifier(prefix + "options")
                    sql = (f"SELECT option_name FROM {opt} WHERE option_name IN ('active_plugins','cron') "
                           "AND (option_value LIKE '%cipher-feeder%' OR option_value LIKE '%trace-inspector-pad%' "
                           "OR option_value LIKE '%sc_cron_guard%' OR option_value LIKE '%sc_persist_manifest%' "
                           "OR option_value LIKE '%sc_cron_fetch%');")
                    if query_db(cnf, dbname, sql):
                        raise AuditError("Serialized WordPress options require manual, targeted remediation")
                ask("Confirm all planned site/database modifications")
            except BaseException:
                # Staging may already exist when operator declines or SQL
                # preflight fails. Never abandon an untracked working copy.
                if stage is not None:
                    shutil.rmtree(stage, ignore_errors=True)
                raise
            quarantine = None
            database_started = False
            try:
                if stage is not None:
                    quarantine = swap_files(target, stage, case)
                    stage = None
                if args.mode in ("apply-db", "recover"):
                    # A failed SQL client may have committed before raising.
                    database_started = True
                    sql_cleanup(cnf, dbname, prefix, case)
                if args.mode == "recover":
                    if args.core_source:
                        sync_core(args.core_source, target)
                    rotate_salts(target / "wp-config.php")
                upload_permissions_audit(target, case)
                # Perform an independent post-operation collection. Preserve
                # pre-change evidence before file_audit replaces the JSON.
                (case / "file-evidence.json").rename(case / "file-evidence-before.json")
                post_files = file_audit(target, case)
                post_processes = process_audit(case)
                database = database_audit(cnf, dbname, prefix, case, post=True)
                make_report(case, args.mode, post_files, post_processes, database, dbname, prefix)
                if args.mode == "recover":
                    # Findings remain findings, not proof; require manual
                    # containment review before declaring recovery complete.
                    if post_recovery_blockers(database, post_files, post_processes):
                        raise AuditError("Post-recovery indicators remain; keep the site isolated")
            except BaseException:
                # File rollback is safe only before any database modification.
                # Once the DB was changed, retain evidence and require an
                # operator-controlled recovery from the verified snapshots.
                if quarantine is not None and not database_started:
                    current = target / "wp-content"
                    if current.exists():
                        failed = target.parent / ("." + target.name + ".wp-content.failed-" + case.name)
                        current.rename(failed)
                    quarantine.rename(current)
                raise
            finally:
                if stage is not None:
                    shutil.rmtree(stage, ignore_errors=True)
            print("Operação concluída. Revise os achados e valide o site antes de reativá-lo.")
            return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AuditError, report_export.PDFExportError, mail_delivery.MailDeliveryError, OSError, subprocess.CalledProcessError, ValueError, EOFError) as error:
        print(f"ERRO: {redact(error)}", file=sys.stderr)
        sys.exit(30)
