"""Máquina de estados somente de simulação para remediação SC403."""
from __future__ import annotations

ESTADOS = ("DESCOBERTO", "PROPOSTO", "VALIDADO", "AUTORIZADO", "PREPARADO", "EXECUTANDO", "VERIFICADO",
           "BLOQUEADO", "DIVERGENTE", "FALHOU", "COMPENSACAO_PENDENTE", "COMPENSADO", "INTERVENCAO_MANUAL_NECESSARIA")


def simular(recurso: dict, autorizado: bool, identidade_compativel: bool, precondicoes: bool) -> dict:
    estado = "DESCOBERTO"
    if not autorizado or not identidade_compativel or not precondicoes:
        return {"estado": "BLOQUEADO", "executado": False,
                "motivos": ["autorizacao", "identidade", "precondicoes"]}
    estado = "AUTORIZADO"
    return {"estado": estado, "proximo": "PREPARADO", "executado": False,
            "observacao": "Simulação; executor destrutivo não habilitado."}
