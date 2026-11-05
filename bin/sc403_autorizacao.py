"""Política de aprovação do núcleo SC403; não autoriza execução real."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from sc403_escopo import EscopoRecusado, validar


def canonico(objeto: dict) -> bytes:
    return json.dumps(objeto, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def hash_plano(manifesto: dict) -> str:
    copia = json.loads(json.dumps(manifesto, ensure_ascii=False))
    copia.pop("approval", None)
    return hashlib.sha256(canonico(copia)).hexdigest()


def validar_aprovacao(manifesto: dict) -> dict:
    validacao = validar(manifesto)
    aprovacao = manifesto.get("approval")
    esperado = hash_plano(manifesto)
    if not isinstance(aprovacao, dict):
        raise EscopoRecusado("aprovação externa ausente")
    if aprovacao.get("plan_sha256") != esperado:
        raise EscopoRecusado("aprovação não corresponde ao plano canônico")
    for campo in ("signature", "key_id", "verified_by"):
        if not isinstance(aprovacao.get(campo), str) or not aprovacao[campo]:
            raise EscopoRecusado(f"aprovação sem {campo}")
    return {**validacao, "plano_sha256": esperado, "assinatura_presente": True,
            "assinatura_criptograficamente_verificada": False,
            "execucao_habilitada": False}
