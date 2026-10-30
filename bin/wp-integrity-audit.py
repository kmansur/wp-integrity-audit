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

VERSION = "0.1.0"
IOC = re.compile(r"SC_ADV_BEGIN|--sc-cli|--sc-succ|trace-inspector-pad|cipher-feeder|_sc_fpc|sc_cron_guard|sc_persist_manifest|sc_own_manifest|function ceya")
PATTERN_NAMES = (".sc_", ".gr_", ".gk_", ".kk_", ".wp-object-cache")
SENSITIVE = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*[^\s,;]+")
LONG_VALUE = re.compile(r"(?<![\w])[A-Za-z0-9_/-]{40,}(?![\w])")
DB_KEY = re.compile(r"define\s*\(\s*['\"](?P<name>DB_NAME|DB_USER|DB_PASSWORD|DB_HOST)['\"]\s*,\s*(?P<quote>['\"])(?P<value>(?:\\\\.|[^'\"\\\\])*)(?P=quote)\s*\)", re.S)
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

def file_audit(target: Path, case: Path) -> list[dict]:
    """IOC discovery with bounded snippets; results are clues, not proof."""
    findings: list[dict] = []
    for path in iter_files(target):
        relative = path.relative_to(target).as_posix()
        name = path.name
        unusual = name.startswith(PATTERN_NAMES) or name == "trace-inspector-pad.php" or "cipher-feeder" in name
        upload_php = relative.startswith("wp-content/uploads/") and path.suffix.lower() in (".php", ".phtml", ".phar")
        text = ""
        if path.suffix.lower() in (".php", ".phtml", ".inc"):
            try:
                with path.open("rb") as stream:
                    text = stream.read(262144).decode("utf-8", "replace")
            except OSError:
                continue
        match = IOC.search(text)
        if not (unusual or upload_php or match):
            continue
        if "/wflogs/" in relative:
            classification = "SECURITY_PLUGIN_REVIEW"
        elif match or unusual:
            classification = "IOC_REQUIRES_VALIDATION"
        else:
            classification = "UPLOAD_SCRIPT_REVIEW"
        findings.append({
            "path": relative, "sha256": sha256(path), "size": path.stat().st_size,
            "classification": classification,
            "indicator": match.group(0) if match else ("filename" if unusual else "upload PHP"),
            "snippet": redact(text[max(0, match.start() - 50):match.end() + 90]) if match else ""
        })
    write_private(case / "file-evidence.json", json.dumps(findings, indent=2, ensure_ascii=False))
    return findings

def process_audit(case: Path) -> list[str]:
    result = run(["ps", "-eo", "pid=,ppid=,user=,args="], capture_output=True).stdout
    matches = [redact(line) for line in result.splitlines() if any(x in line for x in ("--sc-cli", "--sc-succ", "cipher-feeder", ".gr_"))]
    write_private(case / "process-evidence.json", json.dumps(matches, indent=2))
    return matches

def make_report(case: Path, mode: str, findings: list[dict], processes: list[str], database: list[dict] | None = None) -> None:
    """Client report contains metadata only; never embeds raw DB option values."""
    lines = [
        "# WordPress Integrity Audit", "", f"- Version: `{VERSION}`", f"- Mode: `{mode}`",
        f"- Timestamp (UTC): {dt.datetime.now(dt.timezone.utc).isoformat()}",
        f"- File findings: {len(findings)}", f"- Process findings: {len(processes)}",
        f"- Database findings: {len(database or [])}", "",
        "## File findings", "",
        "| Relative path | Classification | SHA-256 |",
        "|---|---|---|",
    ]
    for finding in findings:
        lines.append(f"| {redact(finding['path']).replace('|','/')} | {finding['classification']} | {finding['sha256']} |")
    if database is not None:
        lines.extend(["", "## Database findings (metadata only)", "", "| Kind | Name | Length |", "|---|---|---|"])
        for item in database:
            lines.append(f"| {redact(item['kind'])} | {redact(item['name'])} | {item['length']} |")
    lines.extend(["", "## Limitations", "", "Signature matches are not proof of compromise. No matches do not prove the site is clean.",
                  "Review all outputs for confidential information before external distribution."])
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

def database_audit(option_file: str, dbname: str, prefix: str, case: Path, post: bool = False) -> list[dict]:
    options, users, meta = (sql_identifier(prefix + v) for v in ("options", "users", "usermeta"))
    statements = [
        ("suspicious_users", f"SELECT user_login, LENGTH(user_login) FROM {users} WHERE user_login REGEXP '^(admin|administrator|backup)_[0-9a-f]{{6}}$'"),
        ("family_option", f"SELECT option_name, LENGTH(option_value) FROM {options} WHERE option_name LIKE 'sc#_%' ESCAPE '#' OR option_name LIKE '_transient_sc#_%' ESCAPE '#'"),
        ("marker_option", f"SELECT option_name, LENGTH(option_value) FROM {options} WHERE option_value LIKE '%cipher-feeder%' OR option_value LIKE '%sc_cron_guard%' OR option_value LIKE '%sc_persist_manifest%' OR option_value LIKE '%trace-inspector-pad%'"),
        ("session_rows", f"SELECT meta_key, COUNT(*) FROM {meta} WHERE meta_key='session_tokens' GROUP BY meta_key"),
        ("application_password_rows", f"SELECT meta_key, COUNT(*) FROM {meta} WHERE meta_key LIKE '%application_passwords' GROUP BY meta_key"),
    ]
    findings = []
    for kind, sql in statements:
        for row in query_db(option_file, dbname, sql + ";"):
            if len(row) >= 2:
                findings.append({"kind": kind, "name": redact(row[0]), "length": row[1]})
    write_private(case / ("database-post-audit.json" if post else "database-evidence.json"),
                  json.dumps(findings, indent=2))
    return findings

def snapshot(target: Path, case: Path, option_file: str, dbname: str) -> None:
    """Mandatory recovery backup (not generated for read-only audit modes)."""
    tarpath = case / "site-before.tar.gz"
    with tarfile.open(tarpath, "w:gz", dereference=False) as archive:
        archive.add(target, arcname="site", recursive=True)
    os.chmod(tarpath, 0o600)
    with tarfile.open(tarpath, "r:gz") as archive:
        archive.getmembers()
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
    for path in iter_files(source):
        if path.suffix.lower() in (".php", ".inc", ".phtml"):
            with path.open("rb") as stream:
                if IOC.search(stream.read(262144).decode("utf-8", "replace")):
                    raise AuditError(f"Known IOC in proposed clean source: {path}")
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
        for path in iter_files(stage):
            if path.suffix.lower() in (".php", ".phtml", ".inc"):
                with path.open("rb") as stream:
                    if IOC.search(stream.read(262144).decode("utf-8", "replace")):
                        raise AuditError("Known IOC found in staged content")
        return stage
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise

def swap_files(target: Path, stage: Path, case: Path) -> Path:
    old = target / "wp-content"
    quarantine = target / f"wp-content.quarantine-{case.name}"
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
        os.chmod(temp, stat.S_IMODE(original.st_mode))
        os.replace(temp, path)
    finally:
        Path(temp).unlink(missing_ok=True)

def sync_core(source: Path, target: Path) -> None:
    source = source.resolve(strict=True)
    if not all((source / x).exists() for x in ("wp-admin", "wp-includes", "wp-load.php")):
        raise AuditError("Invalid core source")
    for dirname in ("wp-admin", "wp-includes"):
        shutil.copytree(source / dirname, target / dirname, dirs_exist_ok=True, symlinks=False)
    for path in source.iterdir():
        if path.is_file() and (path.suffix == ".php" or path.name in ("license.txt", "readme.html")):
            shutil.copy2(path, target / path.name)

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
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    if args.target is None:
        parser.error("TARGET is required")
    if args.mode in ("apply-files", "recover") and not args.source:
        parser.error("--source is required for file replacement")
    if args.core_source and args.mode != "recover":
        parser.error("--core-source is only valid with --recover")
    if args.official_sync and args.mode not in ("apply-files", "recover"):
        parser.error("--official-sync requires file replacement")
    return args

def main() -> int:
    args = parse_args()
    target = validate_site(args.target)
    case_root = ensure_private_dir(args.case_root)
    lock = case_root / ".audit.lock"
    with lock.open("a+") as lockfile:
        fcntl.flock(lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
        timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        label = re.sub(r"[^A-Za-z0-9._-]", "_", args.domain_label or target.parent.name)
        case = ensure_private_dir(case_root / f"{label}-{timestamp}-{secrets.token_hex(3)}")
        print(f"Version {VERSION}; mode={args.mode}; case={case}")
        files = file_audit(target, case)
        processes = process_audit(case)
        if args.mode == "audit":
            make_report(case, args.mode, files, processes)
            print(f"Filesystem audit complete: {len(files)} findings")
            return 0
        config, prefix = parse_wordpress(target / "wp-config.php")
        dbname = config["DB_NAME"]
        if not re.fullmatch(r"[A-Za-z0-9_]+", dbname):
            raise AuditError("Unsupported database name")
        with database_client({"host": args.db_host or config["DB_HOST"],
                              "user": config["DB_USER"], "password": config["DB_PASSWORD"]}, case) as cnf:
            if args.mode in ("audit-db", "audit-db-post"):
                database = database_audit(cnf, dbname, prefix, case, post=args.mode == "audit-db-post")
                make_report(case, args.mode, files, processes, database)
                print(f"Database audit complete: {len(database)} findings")
                return 0
            if os.geteuid() != 0:
                raise AuditError("Recovery requires root; audit does not")
            print("Recovery modifies files and/or database; independent verified backup is required.")
            ask("Confirm site isolation and independent backup")
            snapshot(target, case, cnf, dbname)
            stage = None
            if args.mode in ("apply-files", "recover"):
                source = validate_source(args.source, target)
                stage = stage_files(target, source, case,
                                    args.replace_plugins_themes or args.official_sync, args.official_sync)
            if args.mode in ("apply-db", "recover"):
                # Preflight serialized database options before modifying filesystem.
                opt = sql_identifier(prefix + "options")
                sql = (f"SELECT option_name FROM {opt} WHERE option_name IN ('active_plugins','cron') "
                       "AND (option_value LIKE '%cipher-feeder%' OR option_value LIKE '%trace-inspector-pad%' "
                       "OR option_value LIKE '%sc_cron_guard%' OR option_value LIKE '%sc_persist_manifest%' "
                       "OR option_value LIKE '%sc_cron_fetch%');")
                if query_db(cnf, dbname, sql):
                    raise AuditError("Serialized WordPress options require manual, targeted remediation")
            ask("Confirm all planned site/database modifications")
            try:
                if stage is not None:
                    swap_files(target, stage, case)
                    stage = None
                if args.mode in ("apply-db", "recover"):
                    sql_cleanup(cnf, dbname, prefix, case)
                if args.mode == "recover":
                    if args.core_source:
                        sync_core(args.core_source, target)
                    rotate_salts(target / "wp-config.php")
                database = database_audit(cnf, dbname, prefix, case, post=True)
                make_report(case, args.mode, files, processes, database)
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
