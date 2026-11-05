"""Autorização criptográfica e independente para o núcleo SC403."""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
from pathlib import Path

from sc403_escopo import EscopoRecusado, validar

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # pragma: no cover
    InvalidSignature = None
    Ed25519PublicKey = None


def canonico(objeto: object) -> bytes:
    return json.dumps(objeto, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def hash_plano(manifesto: dict) -> str:
    copia = json.loads(json.dumps(manifesto, ensure_ascii=False))
    copia.pop("approval", None)
    return hashlib.sha256(canonico(copia)).hexdigest()


def _decodificar(valor: str, tamanho: int, nome: str) -> bytes:
    if not isinstance(valor, str):
        raise EscopoRecusado(f"{nome} inválido")
    try:
        bruto = base64.b64decode(valor.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError):
        try:
            bruto = bytes.fromhex(valor)
        except ValueError as erro:
            raise EscopoRecusado(f"{nome} não está em formato suportado") from erro
    if len(bruto) != tamanho:
        raise EscopoRecusado(f"tamanho de {nome} inválido")
    return bruto


def _data(valor: object, nome: str) -> dt.datetime:
    if not isinstance(valor, str):
        raise EscopoRecusado(f"{nome} inválido")
    try:
        resultado = dt.datetime.fromisoformat(valor.replace("Z", "+00:00"))
    except ValueError as erro:
        raise EscopoRecusado(f"{nome} inválido") from erro
    if resultado.tzinfo is None:
        raise EscopoRecusado(f"{nome} deve informar UTC")
    return resultado.astimezone(dt.timezone.utc)


def mensagem_assinada(manifesto: dict, aprovacao: dict) -> bytes:
    """Envelope canônico que a chave autorizadora deve assinar."""
    identidade = manifesto.get("identity", {})
    return canonico({
        "schema_version": 1,
        "plan_sha256": hash_plano(manifesto),
        "case_id": manifesto.get("case_id"),
        "server_id": identidade.get("server_id"),
        "approval_id": aprovacao.get("approval_id"),
        "approved_at": aprovacao.get("approved_at"),
        "valid_until": aprovacao.get("valid_until"),
        "key_id": aprovacao.get("key_id"),
    })


def _ler_politica(politica: dict | Path) -> dict:
    if isinstance(politica, Path):
        if politica.is_symlink() or not politica.is_file() or politica.stat().st_size > 1024 * 1024:
            raise EscopoRecusado("política de chaves ausente, simbólica ou acima do limite")
        try:
            politica = json.loads(politica.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeDecodeError) as erro:
            raise EscopoRecusado("política de chaves inválida") from erro
    if not isinstance(politica, dict) or politica.get("schema_version") != 1:
        raise EscopoRecusado("schema de política de chaves não suportado")
    if not isinstance(politica.get("keys"), dict):
        raise EscopoRecusado("política sem mapa de chaves")
    return politica


def validar_aprovacao(manifesto: dict, aprovacao: dict | None = None,
                      politica: dict | Path | None = None,
                      agora: dt.datetime | None = None,
                      usos: set[str] | None = None) -> dict:
    """Valida janela, host, chave confiável e assinatura Ed25519.

    A aprovação deve ser fornecida por arquivo independente; não se confia em
    um bloco ``approval`` embutido no manifesto.
    """
    validacao = validar(manifesto, agora=agora)
    if aprovacao is None:
        raise EscopoRecusado("aprovação externa ausente")
    if Ed25519PublicKey is None:
        raise EscopoRecusado("dependência cryptography indisponível para Ed25519")
    if not isinstance(aprovacao, dict):
        raise EscopoRecusado("aprovação inválida")
    obrigatorios = ("approval_id", "plan_sha256", "signature", "key_id",
                    "verified_by", "approved_at", "valid_until", "server_id")
    for campo in obrigatorios:
        if not isinstance(aprovacao.get(campo), str) or not aprovacao[campo]:
            raise EscopoRecusado(f"aprovação sem {campo}")
    esperado = hash_plano(manifesto)
    if aprovacao["plan_sha256"] != esperado:
        raise EscopoRecusado("aprovação não corresponde ao plano canônico")
    if aprovacao["server_id"] != manifesto["identity"].get("server_id"):
        raise EscopoRecusado("identidade do host divergente")
    aprovado = _data(aprovacao["approved_at"], "approved_at")
    validade = _data(aprovacao["valid_until"], "valid_until")
    momento = agora or dt.datetime.now(dt.timezone.utc)
    if validade <= aprovado or validade <= momento or aprovado > momento + dt.timedelta(minutes=5):
        raise EscopoRecusado("janela de autorização inválida ou expirada")
    if usos is not None and aprovacao["approval_id"] in usos:
        raise EscopoRecusado("aprovação já utilizada")
    if politica is None:
        raise EscopoRecusado("política de chaves autorizadoras ausente")
    registro = _ler_politica(politica)["keys"].get(aprovacao["key_id"])
    if not isinstance(registro, dict):
        raise EscopoRecusado("chave autorizadora desconhecida")
    permitidos = registro.get("server_ids", [])
    if permitidos and aprovacao["server_id"] not in permitidos:
        raise EscopoRecusado("chave não autorizada para este host")
    chave = _decodificar(registro.get("public_key"), 32, "chave pública")
    assinatura = _decodificar(aprovacao["signature"], 64, "assinatura")
    try:
        Ed25519PublicKey.from_public_bytes(chave).verify(assinatura, mensagem_assinada(manifesto, aprovacao))
    except InvalidSignature as erro:
        raise EscopoRecusado("assinatura Ed25519 inválida") from erro
    return {**validacao, "plano_sha256": esperado, "assinatura_presente": True,
            "assinatura_criptograficamente_verificada": True,
            "approval_id": aprovacao["approval_id"], "execucao_habilitada": False}
