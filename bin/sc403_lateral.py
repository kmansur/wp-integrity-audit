"""Auditoria estrutural de exposição lateral entre instalações WordPress.

O módulo recebe somente raízes explicitamente autorizadas. Não segue links
simbólicos, não escreve nos sites, não testa escrita e não atribui infecção
apenas por UID compartilhado.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat


LIMITE_DIRETORIOS = 20000
LIMITE_PROCESSOS = 20000
WP_MARCADORES = ("wp-load.php", "wp-config.php", "wp-admin", "wp-includes")


def _modo(info: os.stat_result) -> dict:
    modo = stat.S_IMODE(info.st_mode)
    return {
        "modo": oct(modo),
        "uid": info.st_uid,
        "gid": info.st_gid,
        "gravavel_pelo_dono": bool(modo & 0o200),
        "gravavel_pelo_grupo": bool(modo & 0o020),
        "gravavel_por_outros": bool(modo & 0o002),
    }


def _seguro_raiz(raiz: Path) -> Path:
    if not raiz.is_absolute() or raiz.is_symlink():
        raise ValueError("raiz autorizada deve ser absoluta e não simbólica")
    real = raiz.resolve(strict=True)
    if real == Path("/") or len(real.parts) < 3:
        raise ValueError("raiz ampla demais; informe uma raiz de conta ou site")
    return real


def _encontrar_sites(raizes: list[Path]) -> tuple[list[Path], list[str]]:
    encontrados: list[Path] = []
    erros: list[str] = []
    visitados = 0
    for original in raizes:
        raiz = _seguro_raiz(original)
        for diretorio, pastas, _arquivos in os.walk(raiz, topdown=True, followlinks=False):
            caminho = Path(diretorio)
            pastas[:] = [p for p in pastas if not (caminho / p).is_symlink()]
            visitados += 1
            if visitados > LIMITE_DIRETORIOS:
                erros.append("LIMITE_DIRETORIOS_ATINGIDO")
                return encontrados, erros
            try:
                if all((caminho / marcador).exists() and not (caminho / marcador).is_symlink()
                       for marcador in WP_MARCADORES):
                    encontrados.append(caminho)
                    pastas[:] = []
            except OSError:
                erros.append(f"FALHA_LEITURA:{caminho}")
    unicos = sorted({p.resolve() for p in encontrados})
    return unicos, erros


def _processos_por_caminho(sites: list[Path]) -> list[dict]:
    resultados = []
    vistos = 0
    try:
        entradas = [p for p in Path("/proc").iterdir() if p.name.isdecimal()]
    except OSError:
        return [{"status": "INCOMPLETA", "motivo": "PROC_INDISPONIVEL"}]
    for pid_dir in entradas:
        vistos += 1
        if vistos > LIMITE_PROCESSOS:
            break
        try:
            cmd = (pid_dir / "cmdline").read_bytes()[:8192].replace(b"\0", b" ").decode("utf-8", "backslashreplace")
            uid = None
            for linha in (pid_dir / "status").read_text(errors="replace").splitlines():
                if linha.startswith("Uid:"):
                    uid = int(linha.split()[1]); break
            for site in sites:
                if str(site) in cmd:
                    resultados.append({"pid": int(pid_dir.name), "uid_efetivo": uid,
                                       "site": str(site), "estado": "PROCESSO_ASSOCIADO_INVENTARIADO"})
                    break
        except (OSError, ValueError):
            continue
    return resultados


def _pools_php_fpm(sites: list[Path]) -> list[dict]:
    """Lê somente rótulos de pools; não trata o arquivo como configuração executável."""
    registros = []
    for arquivo in sorted(Path("/etc/php").glob("*/fpm/pool.d/*.conf")):
        if arquivo.is_symlink() or not arquivo.is_file():
            continue
        try:
            linhas = arquivo.read_text(encoding="utf-8", errors="replace")[:262144].splitlines()
        except OSError:
            continue
        nome = next((linha.strip()[1:-1] for linha in linhas if linha.strip().startswith("[") and linha.strip().endswith("]")), None)
        usuario = next((linha.split("=", 1)[1].strip() for linha in linhas if linha.strip().startswith("user =")), None)
        grupo = next((linha.split("=", 1)[1].strip() for linha in linhas if linha.strip().startswith("group =")), None)
        listen = next((linha.split("=", 1)[1].strip() for linha in linhas if linha.strip().startswith("listen =")), None)
        associados = [str(site) for site in sites if str(site) in "\n".join(linhas)]
        registros.append({"arquivo": str(arquivo), "pool": nome, "usuario": usuario,
                          "grupo": grupo, "listen": listen,
                          "sites_associados_por_texto": associados,
                          "associacao": "ASSOCIADO_POR_TEXTO" if associados else "NAO_COMPROVADA"})
    return registros


def _diretorios_sensiveis(site: Path) -> list[dict]:
    resultados = []
    wp = site / "wp-content"
    candidatos = [wp / "uploads", wp / "mu-plugins", wp / "plugins", wp / "themes", wp]
    for caminho in candidatos:
        try:
            if caminho.is_symlink() or not caminho.is_dir():
                continue
            info = caminho.stat()
            dado = {"path": str(caminho), **_modo(info)}
            if caminho.name == "uploads":
                htaccess = caminho / ".htaccess"
                dado["php_bloqueado_por_htaccess"] = False
                if htaccess.is_file() and not htaccess.is_symlink():
                    texto = htaccess.read_text(encoding="utf-8", errors="replace")[:65536]
                    dado["php_bloqueado_por_htaccess"] = bool(
                        re.search(r"(?i)(?:require\s+all\s+denied|deny\s+from\s+all).*php|<FilesMatch[^>]*php", texto, re.S))
            resultados.append(dado)
        except OSError:
            resultados.append({"path": str(caminho), "estado": "LEITURA_INCOMPLETA"})
    return resultados


def auditar(raizes: list[Path]) -> dict:
    sites, erros = _encontrar_sites(raizes)
    registros = []
    for site in sites:
        try:
            info = site.stat()
            uid = info.st_uid
            registro = {"site": str(site), "proprietario": _modo(info),
                        "diretorios_sensiveis": _diretorios_sensiveis(site),
                        "classificacao": "EXPOSICAO_ESTRUTURAL_REQUER_CONTEXTO"}
            registros.append(registro)
        except OSError:
            erros.append(f"FALHA_STAT:{site}")
    uid_map: dict[int, list[str]] = {}
    for item in registros:
        uid_map.setdefault(item["proprietario"]["uid"], []).append(item["site"])
    compartilhados = [{"uid": uid, "sites": sorted(sites)} for uid, sites in uid_map.items() if len(sites) > 1]
    for item in registros:
        item["uid_compartilhado_entre_sites"] = any(item["site"] in grupo["sites"] for grupo in compartilhados)
    processos = _processos_por_caminho(sites)
    pools = _pools_php_fpm(sites)
    riscos = []
    for item in registros:
        if item["uid_compartilhado_entre_sites"]:
            riscos.append({"tipo": "UID_COMPARTILHADO", "site": item["site"],
                           "classificacao": "RISCO_ESTRUTURAL_NAO_PROVA_INFECCAO"})
        for diretorio in item["diretorios_sensiveis"]:
            if diretorio.get("gravavel_por_outros") or diretorio.get("gravavel_pelo_grupo"):
                riscos.append({"tipo": "DIRETORIO_GRAVAVEL_POR_TERCEIROS", "site": item["site"],
                               "path": diretorio["path"], "classificacao": "EXPOSICAO_ESTRUTURAL_REQUER_REVISAO"})
            if diretorio.get("path", "").endswith("/uploads") and not diretorio.get("php_bloqueado_por_htaccess", False):
                riscos.append({"tipo": "UPLOADS_SEM_BLOQUEIO_PHP_CONFIRMADO", "site": item["site"],
                               "path": diretorio["path"], "classificacao": "EXPOSICAO_ESTRUTURAL_REQUER_REVISAO"})
    return {"schema_version": 1, "cobertura": "COMPLETA" if not erros else "INCOMPLETA",
            "raizes_autorizadas": [str(p.resolve()) for p in raizes],
            "sites": registros, "uid_compartilhado": compartilhados,
            "processos_associados": processos, "pools_php_fpm": pools,
            "riscos": riscos, "erros": erros,
            "observacoes": [
                "UID compartilhado é risco estrutural e não comprova infecção.",
                "A ausência de um pool PHP-FPM associado não prova isolamento.",
                "Nenhum teste de escrita, execução ou alteração foi realizado.",
            ]}
