#!/usr/bin/env python3
"""WordPress incident audit and recovery for Debian/Ubuntu (Python implementation).

Read-only by default for the WordPress installation. Local evidence files are
always written. Mutating modes require explicit interactive confirmation.
No WordPress PHP code or WP-CLI commands are executed.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
import zipfile

VERSION = "0.2.0"
IOC = re.compile(r"SC_ADV_BEGIN|--sc-cli|--sc-succ|trace-inspector-pad|cipher-feeder|_sc_fpc|sc_cron_guard|sc_persist_manifest|sc_own_manifest|function ceya")
PATTERN_NAMES = (".sc_", ".gr_", ".gk_", ".kk_", ".wp-object-cache")
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
        upload_php = relative.startswith("wp-content/uploads/") and path.suffix.lower() in (".php", ".phtml", ".phar")
        match = None
        snippet = ""
        safe_text = ""
        if path.suffix.lower() in (".php", ".phtml", ".inc", ".phar"):
            try:
                with path.open("rb") as stream:
                    overlap = b""
                    while chunk := stream.read(65536):
                        sample = overlap + chunk
                        decoded = sample.decode("utf-8", "replace")
                        if not safe_text:
                            safe_text = decoded[:4096]
                        match = IOC.search(decoded)
                        if match:
                            snippet = redact(decoded[max(0, match.start() - 40):match.end() + 60])
                            break
                        overlap = sample[-256:]
            except OSError:
                continue
        if not (unusual or upload_php or match):
            continue
        classification, reason = classify_file(relative, name, safe_text, match.group(0) if match else None)
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


def process_audit(case: Path) -> list[str]:
    result = run(["ps", "-eo", "pid=,ppid=,user=,args="], capture_output=True).stdout
    matches = [redact(line) for line in result.splitlines() if any(x in line for x in ("--sc-cli", "--sc-succ", "cipher-feeder", ".gr_"))]
    write_private(case / "process-evidence.json", json.dumps(matches, indent=2))
    return matches

def make_report(case: Path, mode: str, findings: list[dict], processes: list[str],
                database: list[dict] | None = None, db_name: str | None = None, db_prefix: str | None = None) -> None:
    """Generate a precise coverage statement and evidence-based technical opinion."""
    audited = database is not None
    lines = [
        "# WordPress Integrity Audit", "",
        f"- Version: `{VERSION}`", f"- Tool SHA-256: `{sha256(Path(__file__))}`", f"- Mode: `{mode}`",
        f"- Timestamp (UTC): {dt.datetime.now(dt.timezone.utc).isoformat()}",
        f"- File findings: {len(findings)}", f"- Process findings: {len(processes)}",
        f"- Database audit: **{'EXECUTED' if audited else 'NOT EXECUTED'}**",
        f"- Database audit coverage: {'EXECUTED' if audited else 'NOT EVALUATED'}",
        "", "## Filesystem evidence", "",
        "| Relative path | Classification | SHA-256 |",
        "|---|---|---|",
    ]
    for finding in findings:
        # Preserve actual relative file paths, including long directory names.
        path = sanitize_relative_path(finding["path"])
        lines.append(f"| `{path}` | {finding['classification']} | {finding['sha256']} |")
    if audited:
        lines.extend(["", "## Database evidence", "",
                      f"- Database: `{safe_option_name(db_name or 'UNKNOWN')}`",
                      f"- Options table: `{(db_prefix or '')}options`",
                      f"- User metadata table: `{(db_prefix or '')}usermeta`", "",
                      "| Kind | Name | Count/size | State |",
                      "|---|---|---|---|"])
        for item in database:
            lines.append(f"| {item['kind']} | {item['name']} | {item['length']} | {item.get('state','')} |")
        lines.extend(["", "### Evidence details", ""])
        for item in database:
            if not item.get("sha256"):
                continue
            lines.extend([
                f"#### `{item['name']}`", "",
                f"- SHA-256: `{item['sha256']}`",
                f"- Value length: {item['value_length_bytes']} bytes",
                f"- Classification: `{item['value_classification']}`",
                f"- Safe evidence: `{item['safe_excerpt']}`",
                f"- Interpreted value: `{item['safe_excerpt'] if item.get('value_classification') == 'ESCALAR_TEXTO_NUMERO_NAO_CODIFICADO' else '[NOT_EXPOSED]'}`",
                f"- Decoded excerpt: `{item['decoded_excerpt']}`", "",
            ])
    lines.extend(["", "## Technical opinion", ""])
    critical = [x for x in findings if x["classification"] == "IOC_REQUER_VALIDACAO"]
    if audited:
        def positive(kind: str) -> int:
            return sum(item.get("state") not in ("NOT_FOUND", "ABSENT")
                       for item in database if item["kind"] == kind)
        lines.extend([
            f"- Confirmed family residues: **{positive('family_option')}**.",
            f"- Historical references: **{positive('historical_cache')}**.",
            f"- Informational records: **{sum(int(item['length']) for item in database if item['kind'] in ('session_rows', 'application_password_rows'))}**.",
            f"- Active database markers: **{positive('marker_option') + positive('cron_marker') + positive('active_plugins_marker')}**.",
            f"- Informational session records: **{sum(int(item['length']) for item in database if item['kind'] == 'session_rows')}**.",
        ])
    lines.append(f"- Files requiring IOC investigation: **{len(critical)}**.")
    lines.append(f"- Matching process indicators: **{len(processes)}**.")
    if not audited:
        lines.append("- **Database was not audited. No conclusion about database persistence, cron, sessions or administrators is supported.**")
    else:
        def total(kind: str) -> int:
            return sum(int(x["length"]) if kind in ("session_rows", "application_password_rows") else (x.get("state") != "NOT_FOUND")
                       for x in database if x["kind"] == kind)
        family = total("family_option")
        lines.append(f"- Family-specific option/transient residues: **{family}**.")
        lines.append(f"- Matching suspicious administrator naming pattern: **{total('suspicious_users')}**.")
        lines.append(f"- Stored WordPress session records: **{total('session_rows')}**.")
        lines.append(f"- Historical plugin update-cache references: **{total('historical_cache')}**; this is not evidence of active execution.")
        for kind, name in (("cron_marker", "cron"), ("active_plugins_marker", "active_plugins")):
            lines.append(f"- Known indicators in `{name}`: **{total(kind)}**.")
        if family or total("marker_option") or total("cron_marker") or total("active_plugins_marker"):
            lines.append("- **Known compromise-related database markers remain; do not declare this installation clean.**")
        else:
            lines.append("- No selected database IOC was observed; this is not a clean-site certification.")
    if audited:
        lines.extend(["", "### Dynamic WordPress cron option", "",
                      "WordPress modifies cron automatically; changes in hash or size alone do not indicate compromise.",
                      "Examine indicator matches and collection time together.", ""])
    lines.extend(["", "## Classification legend", "",
                  "- `RESIDUO_FAMILIA_REQUER_LIMPEZA`: family-specific database residue.",
                  "- `HISTORICAL_REFERENCE`: historic cache reference, not proof of execution.",
                  "- `LEGITIMO_VALIDADO`: recognized plugin guard pattern, not cryptographic verification.",
                  "- `CONFIGURACAO_PLUGIN_SEGURANCA_REQUER_VALIDACAO`: security plugin configuration needs contextual analysis.",
                  "- `PRESENT`: informational record exists.",
                  "- `NOT_FOUND`: check ran with no matching records.",
                  "", "## Limitations", "",
                  "Classification of plugin guard files is signature-based, not proof of package integrity.",
                  "No findings never establish that a site is clean. Review evidence before distributing reports."])
    write_private(case / "report.md", "\n".join(lines) + "\n")


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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="WordPress Integrity Audit (Python)")
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
    parser.add_argument("--case-root", type=Path, default=Path("/var/lib/wp-integrity-audit/cases"))
    parser.add_argument("--files-only", action="store_true", help="Skip SQL checks explicitly when using --audit")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    if args.target is None:
        parser.error("TARGET is required")
    if args.files_only and args.mode != "audit":
        parser.error("--files-only is valid only with --audit")
    if args.mode in ("apply-files", "recover") and not args.source:
        parser.error("--source is required for file replacement")
    if args.core_source and args.mode != "recover":
        parser.error("--core-source is only valid with --recover")
    if args.official_sync and args.mode not in ("apply-files", "recover"):
        parser.error("--official-sync requires file replacement")
    return args

def main() -> int:
    # Protect backup and report files from their first byte of creation.
    os.umask(0o077)
    args = parse_args()
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
        files = file_audit(target, case)
        elementor_asset_audit(target, case)
        processes = process_audit(case)
        if args.mode == "audit" and args.files_only:
            make_report(case, args.mode, files, processes)
            print(f"Filesystem-only audit complete: {len(files)} findings; database NOT EXECUTED")
            return 0
        config, prefix = parse_wordpress(target / "wp-config.php")
        dbname = config["DB_NAME"]
        if not re.fullmatch(r"[A-Za-z0-9_]+", dbname):
            raise AuditError("Unsupported database name")
        with database_client({"host": args.db_host or config["DB_HOST"],
                              "user": config["DB_USER"], "password": config["DB_PASSWORD"]}, case) as cnf:
            if args.mode in ("audit", "audit-db", "audit-db-post"):
                database = database_audit(cnf, dbname, prefix, case, post=args.mode == "audit-db-post")
                make_report(case, args.mode, files, processes, database, dbname, prefix)
                print(f"Database audit complete: {len(database)} findings")
                return 0
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
                    unresolved = [x for x in database if x["kind"] in
                                  ("family_option", "marker_option", "session_rows",
                                   "application_password_rows")]
                    outstanding = [x for x in post_files if
                                   x["classification"] == "IOC_REQUIRES_VALIDATION"]
                    if unresolved or outstanding or post_processes:
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
            print("Operation complete. Review findings and validate site before reopening.")
            return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AuditError, OSError, subprocess.CalledProcessError, ValueError, EOFError) as error:
        print(f"ERROR: {redact(error)}", file=sys.stderr)
        sys.exit(1)
