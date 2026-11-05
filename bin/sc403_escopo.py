"""Manifesto, grafo e simulação de escopo SC403.

Este módulo somente lê e valida dados. Não executa kill, ipcrm, SQL, cron,
systemd, Apache ou PHP-FPM. Campos ausentes significam ausência de autorização.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import argparse
from pathlib import Path
import re
import sys

OPERACOES = {"preservar", "quarentenar", "alterar", "sinalizar", "reiniciar", "remover"}
RECURSOS = ("processos", "shm", "sql", "arquivos", "cron", "systemd", "php")
ID_EXATO = re.compile(r"^[A-Za-z0-9_.:/@+-]+$")


class EscopoRecusado(ValueError):
    pass


def _ler_json(caminho: Path):
    if caminho.is_symlink() or not caminho.is_file() or caminho.stat().st_size > 16 * 1024 * 1024:
        raise EscopoRecusado("evidência de escopo ausente, simbólica ou acima do limite")
    try:
        return json.loads(caminho.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as erro:
        raise EscopoRecusado("JSON de escopo inválido") from erro


def _data_utc(valor: str) -> dt.datetime:
    try:
        data = dt.datetime.fromisoformat(valor.replace("Z", "+00:00"))
    except ValueError as erro:
        raise EscopoRecusado("data de autorização inválida") from erro
    if data.tzinfo is None:
        raise EscopoRecusado("data de autorização deve informar UTC")
    return data.astimezone(dt.timezone.utc)


def _identificador(valor, nome: str) -> str:
    if not isinstance(valor, str) or not valor or "*" in valor or "?" in valor or not ID_EXATO.fullmatch(valor):
        raise EscopoRecusado(f"identificador inválido ou amplo: {nome}")
    return valor


def validar(manifesto: dict, agora: dt.datetime | None = None) -> dict:
    if not isinstance(manifesto, dict) or manifesto.get("schema_version") != 1:
        raise EscopoRecusado("schema de manifesto não suportado")
    for campo in ("case_id", "identity", "evidence_manifest_sha256", "authorization", "resources", "operations"):
        if campo not in manifesto:
            raise EscopoRecusado(f"campo obrigatório ausente: {campo}")
    identidade = manifesto["identity"]
    obrigatorios = ("domain", "wordpress_path", "abspath", "owner_uid", "owner_gid",
                    "server_id", "boot_id", "pid_namespace", "ipc_namespace",
                    "database", "table_prefix", "related_sites")
    if not isinstance(identidade, dict) or any(campo not in identidade for campo in obrigatorios):
        raise EscopoRecusado("identidade incompleta")
    for campo in ("wordpress_path", "abspath"):
        caminho = identidade[campo]
        if not isinstance(caminho, str) or not caminho.startswith("/") or "\x00" in caminho:
            raise EscopoRecusado(f"caminho inválido: {campo}")
    if not isinstance(identidade["related_sites"], list):
        raise EscopoRecusado("related_sites deve ser lista explícita")
    if not isinstance(manifesto["evidence_manifest_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", manifesto["evidence_manifest_sha256"]):
        raise EscopoRecusado("hash do manifesto de evidências inválido")
    autorizacao = manifesto["authorization"]
    for campo in ("technical_responsible", "approval_id", "approved_at", "valid_until"):
        if not isinstance(autorizacao, dict) or not autorizacao.get(campo):
            raise EscopoRecusado(f"autorização incompleta: {campo}")
    agora = agora or dt.datetime.now(dt.timezone.utc)
    aprovado = _data_utc(autorizacao["approved_at"])
    validade = _data_utc(autorizacao["valid_until"])
    if validade <= aprovado or validade <= agora:
        raise EscopoRecusado("manifesto expirado ou janela inválida")
    if not isinstance(manifesto["operations"], list) or not manifesto["operations"]:
        raise EscopoRecusado("nenhuma operação autorizada explicitamente")
    for operacao in manifesto["operations"]:
        if not isinstance(operacao, str) or operacao not in OPERACOES:
            raise EscopoRecusado("operação não permitida")
    recursos = manifesto["resources"]
    if not isinstance(recursos, dict):
        raise EscopoRecusado("resources deve ser objeto")
    contagens = {}
    for tipo in RECURSOS:
        itens = recursos.get(tipo, [])
        if not isinstance(itens, list):
            raise EscopoRecusado(f"recurso {tipo} deve ser lista")
        for item in itens:
            if not isinstance(item, dict) or "id" not in item or "operation" not in item:
                raise EscopoRecusado(f"recurso {tipo} sem identidade/operação")
            _identificador(item["id"], f"{tipo}.id")
            if item["operation"] not in manifesto["operations"]:
                raise EscopoRecusado(f"operação não autorizada para {tipo}")
            if "*" in json.dumps(item, ensure_ascii=False):
                raise EscopoRecusado(f"curinga proibido em {tipo}")
        contagens[tipo] = len(itens)
    for campo in ("preconditions", "forbidden_operations"):
        if not isinstance(manifesto.get(campo), list):
            raise EscopoRecusado(f"{campo} deve ser lista")
    return {"valido": True, "expira_em": validade.isoformat(), "recursos": contagens,
            "operacoes": sorted(manifesto["operations"]), "execucao_habilitada": False}


def grafo(manifesto: dict) -> dict:
    validar(manifesto, agora=dt.datetime.fromtimestamp(0, tz=dt.timezone.utc))
    nos, arestas = [], []
    identidade = manifesto["identity"]
    for chave, valor in (("site", identidade["wordpress_path"]), ("banco", identidade["database"]),
                         ("uid", str(identidade["owner_uid"])), ("boot", identidade["boot_id"])):
        nos.append({"id": f"{chave}:{valor}", "tipo": chave})
    for site in identidade["related_sites"]:
        sid = f"site_relacionado:{site}"
        nos.append({"id": sid, "tipo": "site_relacionado"})
        arestas.append({"de": f"uid:{identidade['owner_uid']}", "para": sid, "relacao": "UID_COMPARTILHADO_POSSIVEL"})
    return {"schema_version": 1, "nos": nos, "arestas": arestas,
            "observacao": "Relações estruturais não comprovam comprometimento."}


def simular(manifesto: dict, estado_atual: dict) -> dict:
    validacao = validar(manifesto)
    divergencias = []
    esperado = manifesto["identity"]
    observado = estado_atual.get("identity", {}) if isinstance(estado_atual, dict) else {}
    for campo in ("server_id", "boot_id", "pid_namespace", "ipc_namespace", "wordpress_path", "database", "table_prefix"):
        if observado.get(campo) != esperado.get(campo):
            divergencias.append(f"IDENTIDADE_DIVERGENTE:{campo}")
    if estado_atual.get("evidence_manifest_sha256") != manifesto["evidence_manifest_sha256"]:
        divergencias.append("MANIFESTO_EVIDENCIAS_DIVERGENTE")
    return {"schema_version": 1, "simulacao": True, "executavel": False,
            "bloqueado": bool(divergencias), "divergencias": sorted(set(divergencias)),
            "validacao": validacao, "alteracoes_realizadas": False}


def gerar_proposta(caso: Path) -> dict:
    caso = caso.resolve(strict=True)
    ids = _ler_json(caso / "sc403-identifiers.json")
    manifesto = {"schema_version": 1, "case_id": caso.name,
                 "identity": {"domain": caso.name, "wordpress_path": ids.get("abspath", ""),
                              "abspath": ids.get("abspath", ""), "owner_uid": None, "owner_gid": None,
                              "server_id": "NAO_COLETADO", "boot_id": "NAO_COLETADO",
                              "pid_namespace": "NAO_COLETADO", "ipc_namespace": "NAO_COLETADO",
                              "database": "NAO_COLETADO", "table_prefix": "wp_", "related_sites": []},
                 "evidence_manifest_sha256": "0" * 64,
                 "authorization": {}, "resources": {tipo: [] for tipo in RECURSOS},
                 "operations": [], "preconditions": ["backup_restauravel", "identidade_confirmada"],
                 "forbidden_operations": ["escopo_amplo", "curinga", "execucao_php"],
                 "impact": "NAO_ESTIMADO", "plan_hash": None}
    return manifesto


def main() -> int:
    parser = argparse.ArgumentParser(description="Validar e simular escopo SC403 sem executar remediação")
    sub = parser.add_subparsers(dest="comando", required=True)
    pgerar = sub.add_parser("gerar")
    pgerar.add_argument("caso", type=Path)
    pvalidar = sub.add_parser("validar")
    pvalidar.add_argument("manifesto", type=Path)
    pgrafo = sub.add_parser("grafo")
    pgrafo.add_argument("manifesto", type=Path)
    psim = sub.add_parser("simular")
    psim.add_argument("manifesto", type=Path)
    psim.add_argument("estado", type=Path)
    args = parser.parse_args()
    if args.comando == "gerar":
        resultado = gerar_proposta(args.caso)
    elif args.comando == "validar":
        resultado = validar(_ler_json(args.manifesto))
    elif args.comando == "grafo":
        resultado = grafo(_ler_json(args.manifesto))
    else:
        resultado = simular(_ler_json(args.manifesto), _ler_json(args.estado))
    print(json.dumps(resultado, indent=2, ensure_ascii=False))
    return 40 if args.comando in {"validar", "simular"} and (resultado.get("bloqueado") or not resultado.get("valido", True)) else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EscopoRecusado, OSError, ValueError) as erro:
        print(f"ERRO: escopo recusado: {erro}", file=sys.stderr)
        raise SystemExit(30)
