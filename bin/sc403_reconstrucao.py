"""Interpretação conservadora do estado de reconstrução do SC 4.x.

Os valores recebidos são metadados SQL previamente limitados (nome, tamanho,
SHA-256 e prefixo hexadecimal). O módulo não executa PHP, não desserializa
valores e não transforma a existência de ``sc_*`` em comprometimento confirmado.
"""
from __future__ import annotations

import datetime as dt
import re


NOMES_EXATOS = (
    "sc_ini_fail", "sc_ini_dead", "sc_fetch_fails",
    "sc_last_recovery_check", "sc_last_fetch_ts",
    "sc_last_fetch_fail_ts", "sc_pad_off_ts",
)

PADROES = ("sc_reins_",)
_CONTADOR_DIA = re.compile(r"^(?P<dia>\d{1,12})\|(?P<contagem>\d{1,9})$")
_NUMERO = re.compile(r"^-?\d{1,20}$")


def _data_dia_utc(dia: int) -> str | None:
    try:
        return (dt.date(1970, 1, 1) + dt.timedelta(days=dia)).isoformat()
    except (OverflowError, ValueError):
        return None


def _timestamp_utc(valor: int) -> str | None:
    if valor < 946684800 or valor > 4102444800:
        return None
    try:
        return dt.datetime.fromtimestamp(valor, dt.timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _interpretar(nome: str, valor: str, coletado: dt.datetime) -> dict:
    resultado = {
        "nome": nome,
        "valor_observado": False,
        "classificacao": "ESTADO_RECONSTRUCAO_REQUER_REVISAO",
        "fato": "Opção relacionada a estado de reconstrução foi observada; o valor bruto não é exportado.",
        "hipotese": "A opção pode representar controle de retry, circuito de falha ou persistência; isso não prova execução atual.",
    }
    bruto = valor.strip()
    if nome.startswith(PADROES):
        match = _CONTADOR_DIA.fullmatch(bruto)
        if match:
            dia = int(match.group("dia"))
            contagem = int(match.group("contagem"))
            data = _data_dia_utc(dia)
            hoje = (coletado.astimezone(dt.timezone.utc).date() - dt.date(1970, 1, 1)).days
            resultado.update({
                "formato": "DIA_UTC_PIPE_CONTADOR",
                "dia_utc": dia,
                "data_utc": data,
                "contagem": contagem,
                "dia_comparacao": "ATUAL" if dia == hoje else "PASSADO" if dia < hoje else "FUTURO",
                "valor_observado": True,
                "fato": "Contador diário no formato reconhecido; a comparação foi feita somente com a data UTC da coleta.",
                "hipotese": "Contagem no dia atual pode indicar backoff ou limite de reconstrução, mas não demonstra que uma reconstrução ocorreu.",
            })
        else:
            resultado.update({"formato": "NAO_RECONHECIDO", "limitacao_valor": "formato não interpretado"})
        return resultado
    if _NUMERO.fullmatch(bruto):
        numero = int(bruto)
        timestamp = _timestamp_utc(numero) if ("ts" in nome or "recovery" in nome) else None
        resultado.update({
            "formato": "NUMERO",
            "valor_numerico": numero,
            "valor_observado": True,
        })
        if timestamp:
            resultado["timestamp_utc"] = timestamp
            resultado["fato"] = "Valor numérico interpretado como timestamp Unix UTC dentro de faixa plausível; a interpretação é limitada ao formato."
        return resultado
    resultado.update({"formato": "NAO_RECONHECIDO", "limitacao_valor": "valor não numérico ou não exportável"})
    return resultado


def analisar(rows: list[list[str]], coletado_utc: dt.datetime | None = None) -> dict:
    """Produz evidência estruturada sem copiar valores brutos para o caso."""
    coletado = coletado_utc or dt.datetime.now(dt.timezone.utc)
    indicadores = []
    erros = []
    for row in rows:
        if len(row) != 4:
            erros.append("linha SQL com quantidade inesperada de colunas")
            continue
        nome, comprimento, digest, hex_prefixo = row
        if not (re.fullmatch(r"[A-Za-z0-9_]{1,128}", nome)
                and comprimento.isdigit()
                and re.fullmatch(r"[0-9a-fA-F]{64}", digest)
                and re.fullmatch(r"[0-9a-fA-F]*", hex_prefixo)):
            erros.append("linha SQL com metadados inválidos")
            continue
        try:
            valor = bytes.fromhex(hex_prefixo).decode("utf-8", "replace")
        except ValueError:
            erros.append("prefixo hexadecimal inválido")
            continue
        item = _interpretar(nome, valor, coletado)
        item.update({
            "sha256": digest.lower(),
            "tamanho_bytes": int(comprimento),
            "prefixo_completo": len(bytes.fromhex(hex_prefixo)) == int(comprimento),
        })
        indicadores.append(item)
    return {
        "schema_version": 1,
        "cobertura": "COMPLETA" if not erros else "INCOMPLETA",
        "coletado_utc": coletado.isoformat(),
        "indicadores": indicadores,
        "erros": erros,
        "fatos_observados": len(indicadores),
        "hipoteses_nao_confirmadas": len(indicadores),
        "limitacoes": [
            "A ausência de uma opção não prova ausência de reconstrução.",
            "Contadores e timestamps podem ser gravados ou manipulados pelo próprio malware.",
            "A mudança do dia UTC pode alterar o comportamento sem que exista nova execução observada.",
            "Nenhum valor foi alterado, desserializado ou executado.",
        ],
    }


def e_indicador_reconstrucao(nome: str) -> bool:
    return nome in NOMES_EXATOS or any(nome.startswith(prefixo) for prefixo in PADROES)
