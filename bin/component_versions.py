"""Passive WordPress component provenance and version inventory (no PHP execution)."""
from __future__ import annotations
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.wordpress.org"
VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){1,4}(?:[-+._][A-Za-z0-9.-]+)?$")
HEADERS = re.compile(r"(?im)^\s*(?:(?:/\*)?\s*\*?\s*)?(Plugin Name|Theme Name|Version|Template|Update URI|Plugin URI|Theme URI)\s*:\s*([^\r\n]{0,250})")
STATIC_ROOT = {"index.php", "wp-activate.php", "wp-blog-header.php", "wp-comments-post.php", "wp-config-sample.php",
               "wp-cron.php", "wp-links-opml.php", "wp-load.php", "wp-login.php", "wp-mail.php",
               "wp-settings.php", "wp-signup.php", "wp-trackback.php", "xmlrpc.php"}

def headers(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        return {}
    with path.open("rb") as handle:
        data = handle.read(16384).decode("utf-8-sig", "replace")
    return {key.lower().replace(" ", "_"): value.strip() for key, value in HEADERS.findall(data)}

def api_json(path: str, params: dict, *, timeout: int = 12) -> tuple[str, dict | None, str]:
    query = urllib.parse.urlencode(params)
    url = API + path + "?" + query
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "wp-integrity-audit/version-audit"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            endpoint = urllib.parse.urlparse(response.geturl())
            if endpoint.scheme != "https" or endpoint.hostname != "api.wordpress.org":
                return "API_UNAVAILABLE", None, url
            if response.status != 200:
                return "API_UNAVAILABLE", None, url
            raw = response.read(2_000_001)
            if len(raw) > 2_000_000:
                return "API_UNAVAILABLE", None, url
            data = json.loads(raw)
        if not isinstance(data, dict):
            return "API_UNAVAILABLE", None, url
        if "error" in data:
            return "NOT_FOUND_OFFICIAL_REPOSITORY", None, url
        return "SUCCESS", data, url
    except (OSError, ValueError, urllib.error.URLError, TimeoutError):
        return "API_UNAVAILABLE", None, url

def local_core(target: Path) -> dict:
    path = target / "wp-includes" / "version.php"
    result = {"component_id": "CORE-001", "type": "core", "slug": "wordpress", "local_version": None,
              "locale": "en_US", "official_version": None, "source": "local",
              "state": "CORE_CHECKSUM_INDISPONIVEL", "query_status": "SKIPPED", "findings": [],
              "query_url": None}
    if path.is_symlink() or not path.is_file():
        result["findings"] = [{"path": "wp-includes/version.php", "reason": "MISSING"}]
        result["state"] = "CORE_AUSENTE_REQUER_REVISAO"
        return result
    contents = path.read_text(encoding="utf-8", errors="replace")[:65536]
    version = re.search(r'\$wp_version\s*=\s*["\']([0-9][0-9.]*)["\']', contents)
    locale = re.search(r'\$wp_local_package\s*=\s*["\']([A-Za-z_]{2,15})["\']', contents)
    result["local_version"] = version.group(1) if version else None
    if locale:
        result["locale"] = locale.group(1)
    return result

def local_components(target: Path, kind: str, active_plugins: set[str] | None = None,
                     template: str | None = None, stylesheet: str | None = None) -> list[dict]:
    root = target / "wp-content" / ("plugins" if kind == "plugin" else "themes")
    if not root.is_dir() or root.is_symlink():
        return []
    result = []
    for entry in sorted(root.iterdir()):
        if entry.is_symlink() or not entry.is_dir() or not re.fullmatch(r"[A-Za-z0-9_.-]+", entry.name):
            continue
        if kind == "plugin":
            candidates = sorted(p for p in entry.glob("*.php") if p.is_file() and not p.is_symlink())
            parsed = [(p, headers(p)) for p in candidates]
            main, info = next(((p, h) for p, h in parsed if h.get("plugin_name")), (None, {}))
        else:
            main = entry / "style.css"
            info = headers(main)
        slug = entry.name
        name = info.get("plugin_name" if kind == "plugin" else "theme_name") or slug
        local_version = info.get("version") or None
        if local_version and not VERSION_RE.fullmatch(local_version):
            local_version = None
        parent = info.get("template") if kind == "theme" else None
        update_uri = info.get("update_uri", "")
        custom_uri = bool(update_uri and "wordpress.org" not in update_uri.lower())
        default_state = ("PLUGIN_REQUER_REVISAO" if kind == "plugin" else "TEMA_REQUER_REVISAO")
        if parent and kind == "theme":
            default_state = "TEMA_FILHO_CUSTOMIZADO"
        elif custom_uri:
            default_state = "PLUGIN_PREMIUM_REQUER_FONTE_CONFIAVEL" if kind == "plugin" else "TEMA_PREMIUM_REQUER_FONTE_CONFIAVEL"
        record = {"component_id": f'{"PLUGIN" if kind == "plugin" else "THEME"}-{len(result)+1:03d}',
                  "type": kind, "slug": slug, "name": name, "local_version": local_version,
                  "official_version": None, "source": "unknown", "state": default_state,
                  "query_status": "SKIPPED", "query_url": None,
                  "main_file": main.relative_to(target).as_posix() if main else None,
                  "main_file_sha256": hashlib.sha256(main.read_bytes()).hexdigest() if main and main.is_file() and not main.is_symlink() else None,
                  "active": (None if active_plugins is None else any(p.startswith(slug + "/") for p in active_plugins)) if kind == "plugin" else (slug == stylesheet),
                  "parent_theme": parent, "child_theme": bool(parent),
                  "update_uri_present": bool(update_uri)}
        result.append(record)
    return result

def compare_official(record: dict) -> None:
    kind = record["type"]
    slug = record["slug"]
    path = ("/plugins/info/1.2/" if kind == "plugin" else "/themes/info/1.2/")
    action = ("plugin_information" if kind == "plugin" else "theme_information")
    status, data, url = api_json(path, {"action": action, "request[slug]": slug})
    record["query_url"] = url
    if status == "API_UNAVAILABLE":
        record["query_status"] = status
        return
    if status == "NOT_FOUND_OFFICIAL_REPOSITORY" or not data or not data.get("version"):
        record["query_status"] = "NOT_FOUND_OFFICIAL_REPOSITORY"
        record["state"] = "PLUGIN_NAO_ENCONTRADO_NO_REPOSITORIO" if kind == "plugin" else "TEMA_NAO_ENCONTRADO_NO_REPOSITORIO"
        return
    official = str(data["version"])
    record["official_version"] = official
    record["source"] = "wordpress.org"
    if not record["local_version"]:
        record["state"] = "PLUGIN_REQUER_REVISAO" if kind == "plugin" else "TEMA_REQUER_REVISAO"
    elif official == record["local_version"]:
        record["query_status"] = "OFFICIAL_MATCH"
        record["state"] = "PLUGIN_OFICIAL_ATUAL" if kind == "plugin" else "TEMA_OFICIAL_ATUAL"
    else:
        record["query_status"] = "OFFICIAL_OUTDATED" if version_tuple(record["local_version"]) < version_tuple(official) else "OFFICIAL_MATCH"
        record["state"] = ("PLUGIN_OFICIAL_DESATUALIZADO" if kind == "plugin" else "TEMA_OFICIAL_DESATUALIZADO") if record["query_status"] == "OFFICIAL_OUTDATED" else ("PLUGIN_REQUER_REVISAO" if kind == "plugin" else "TEMA_REQUER_REVISAO")

def version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", value)[:5])

def check_core(target: Path, record: dict, offline: bool) -> None:
    if offline or not record["local_version"]:
        return
    status, data, url = api_json("/core/checksums/1.0/", {"version": record["local_version"], "locale": record["locale"]})
    record["query_url"] = url
    if status != "SUCCESS" or not data or not isinstance(data.get("checksums"), dict):
        record["query_status"] = "API_UNAVAILABLE"
        return
    checksums = data["checksums"]
    mismatch = []
    for relative, expected in checksums.items():
        if not isinstance(relative, str) or not re.fullmatch(r"[a-fA-F0-9]{32}", str(expected)):
            continue
        if (Path(relative).is_absolute() or ".." in Path(relative).parts or
                relative.startswith("wp-content/") or relative == "wp-config.php"):
            continue
        path = target / relative
        if not path.is_file() or path.is_symlink():
            mismatch.append({"path": relative, "reason": "MISSING"})
        elif hashlib.md5(path.read_bytes()).hexdigest() != expected.lower():
            mismatch.append({"path": relative, "reason": "MODIFIED"})
    names = set(checksums)
    for folder in ("wp-admin", "wp-includes"):
        for file in (target / folder).rglob("*"):
            if file.is_file() and not file.is_symlink():
                relative = file.relative_to(target).as_posix()
                if relative not in names and file.suffix.lower() in (".php", ".phtml", ".phar"):
                    mismatch.append({"path": relative, "reason": "EXTRA"})
    for file in target.glob("*.php"):
        if file.name not in names and file.name not in ("wp-config.php",):
            mismatch.append({"path": file.name, "reason": "EXTRA"})
    record["findings"] = mismatch
    record["official_version"] = record["local_version"]
    record["source"] = "wordpress.org"
    record["query_status"] = "OFFICIAL_MATCH"
    record["state"] = ("CORE_AUSENTE_REQUER_REVISAO" if any(f["reason"] == "MISSING" for f in mismatch) else
                       "CORE_MODIFICADO_REQUER_REVISAO" if mismatch else "CORE_VALIDADO")

def audit(target: Path, case: Path, *, offline: bool = False,
          active_plugins: set[str] | None = None, template: str | None = None,
          stylesheet: str | None = None) -> dict:
    core = local_core(target)
    plugins = local_components(target, "plugin", active_plugins, template, stylesheet)
    themes = local_components(target, "theme", active_plugins, template, stylesheet)
    online = not offline
    if online:
        check_core(target, core, False)
        for rec in plugins + themes:
            if rec["child_theme"] or rec["update_uri_present"]:
                rec["query_status"] = "PREMIUM_OR_CUSTOM_COMPONENT"
                continue
            compare_official(rec)
    records = [core] + plugins + themes
    coverage = {"local": "EXECUTED", "official": "SKIPPED" if offline else
                "UNAVAILABLE" if any(r["query_status"] == "API_UNAVAILABLE" for r in records)
                else "EXECUTED", "reason": "Offline mode" if offline else None,
                "status": "AUDITORIA_LOCAL_SEM_CONSULTA_OFICIAL" if offline else "EXECUTED"}
    result = {"coverage": coverage, "components": records,
              "summary": {"core_version": core["local_version"],
                          "plugins_checked": len(plugins), "themes_checked": len(themes),
                          "plugins_outdated": sum(r["state"] == "PLUGIN_OFICIAL_DESATUALIZADO" for r in plugins),
                          "themes_outdated": sum(r["state"] == "TEMA_OFICIAL_DESATUALIZADO" for r in themes),
                          "unlisted": sum(r["query_status"] == "NOT_FOUND_OFFICIAL_REPOSITORY" for r in records)}}
    (case / "component-version-evidence.json").write_text(json.dumps(result, indent=2, ensure_ascii=False))
    lines = ["# Component versions and provenance", "", f"- WordPress installed: {core['local_version'] or 'Unknown'}",
             f"- WordPress expected: {core['official_version'] or 'Not determined'}",
             f"- Core: {core['state']}", f"- Plugins checked: {len(plugins)}",
             f"- Plugins outdated: {result['summary']['plugins_outdated']}",
             f"- Themes checked: {len(themes)}", f"- Themes outdated: {result['summary']['themes_outdated']}",
             f"- Official consultation: {coverage['official']}", "",
             "| ID | Type | Name | Local | Official | Origin | Active | State |",
             "|---|---|---|---|---|---|---|---|"]
    for item in records:
        lines.append("| " + " | ".join(str(item.get(k) or "-").replace("|", "\\|").replace("\n", " ") for k in
                                     ("component_id", "type", "name", "local_version", "official_version", "source", "active", "state")) + " |")
    (case / "component-version-report.md").write_text("\n".join(lines) + "\n")
    with (case / "component-version-report.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=("component_id", "type", "slug", "name", "local_version",
                                                     "official_version", "source", "active", "state", "query_status"))
        writer.writeheader()
        writer.writerows({key: item.get(key) for key in writer.fieldnames} for item in records)
    return result


def write_skipped(case: Path) -> None:
    """Record explicitly reduced coverage without network or component access."""
    result = {"coverage": {"local": "SKIPPED", "official": "SKIPPED",
                           "reason": "--skip-version-check",
                           "status": "AUDITORIA_COM_COBERTURA_REDUZIDA"},
              "components": [], "summary": {}}
    (case / "component-version-evidence.json").write_text(json.dumps(result, indent=2))
    (case / "component-version-report.md").write_text(
        "# Component versions and provenance\n\nCoverage: AUDITORIA_COM_COBERTURA_REDUZIDA\n")
    (case / "component-version-report.csv").write_text(
        "component_id,type,slug,name,local_version,official_version,source,active,state,query_status\n")


def append_management_section(case: Path) -> None:
    """Keep the management overview consistent with detailed component evidence."""
    source = case / "component-version-evidence.json"
    if not source.is_file():
        return
    result = json.loads(source.read_text())
    coverage = result["coverage"]
    summary = result.get("summary", {})
    body = ["", "## Versões e componentes", "",
            f"- Status de cobertura: {coverage['status']}",
            f"- Verificação local de versões: {coverage['local']}",
            f"- Consulta oficial: {coverage['official']}",
            f"- Motivo da omissão: {coverage.get('reason') or 'None'}",
            f"- WordPress instalado: {summary.get('core_version') or 'Unknown'}",
            f"- Plugins verificados: {summary.get('plugins_checked', 0)}",
            f"- Plugins desatualizados: {summary.get('plugins_outdated', 0)}",
            f"- Temas verificados: {summary.get('themes_checked', 0)}",
            f"- Temas desatualizados: {summary.get('themes_outdated', 0)}",
            f"- Componentes não encontrados no repositório: {summary.get('unlisted', 0)}",
            "- Component detail: component-version-report.md", ""]
    for path in (case / "report.md", case / "technical-report.md"):
        if path.is_file():
            path.write_text(path.read_text() + "\n".join(body) + "\n")
