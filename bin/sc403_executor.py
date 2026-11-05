"""Simulação independente do coordenador; nenhuma alteração é executada."""
from __future__ import annotations

import datetime as dt

import sc403_autorizacao
import sc403_identidade
from sc403_escopo import EscopoRecusado


def simular(manifesto: dict, estado_atual: dict, aprovacao: dict,
            politica, agora: dt.datetime | None = None) -> dict:
    """Valida autorização e observações reais antes de propor alterações."""
    bloqueios: list[str] = []
    try:
        autorizacao = sc403_autorizacao.validar_aprovacao(
            manifesto, aprovacao=aprovacao, politica=politica, agora=agora)
    except (EscopoRecusado, ValueError) as erro:
        bloqueios.append(f"AUTORIZACAO:{erro}")
        autorizacao = None
    observado = estado_atual.get("identity", {}) if isinstance(estado_atual, dict) else {}
    esperado = manifesto.get("identity", {})
    comparacao = sc403_identidade.comparar(esperado, observado)
    bloqueios.extend(comparacao["divergencias"])
    if estado_atual.get("evidence_manifest_sha256") != manifesto.get("evidence_manifest_sha256"):
        bloqueios.append("MANIFESTO_EVIDENCIAS_DIVERGENTE")
    if estado_atual.get("backup_restauravel") is not True:
        bloqueios.append("BACKUP_NAO_VALIDADO")
    if estado_atual.get("dependencias_resolvidas") is not True:
        bloqueios.append("DEPENDENCIAS_NAO_RESOLVIDAS")
    return {
        "schema_version": 1,
        "simulacao": True,
        "executavel": False,
        "bloqueado": bool(bloqueios),
        "divergencias": sorted(set(bloqueios)),
        "autorizacao": autorizacao,
        "identidade": comparacao,
        "alteracoes_propostas": [] if bloqueios else manifesto.get("resources", {}),
        "alteracoes_realizadas": False,
    }
