"""Registro de compensações planejadas; nenhuma restauração é executada."""
from __future__ import annotations


def plano_reversao(recurso: dict) -> dict:
    reversivel = bool(recurso.get("reversibilidade", False))
    return {"recurso": recurso.get("id"), "reversivel": reversivel,
            "estado": "COMPENSACAO_DISPONIVEL" if reversivel else "INTERVENCAO_MANUAL_NECESSARIA",
            "executado": False}
