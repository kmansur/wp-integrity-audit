"""Detectores estáticos para a família SC 4.x (sem execução do WordPress).

Implementação independente, baseada no estudo público do projeto
ux2dev/wordpress-sc403-cleaner (GPL-2.0-or-later).
Referência: https://github.com/ux2dev/wordpress-sc403-cleaner

Não reutiliza scripts destrutivos; resultados exigem análise de contexto.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
from pathlib import Path

SAL = "93819"
PAPEIS = {
    "loader_visivel": ("htl", 8),
    "loader_oculto": ("ldr", 8),
    "diretorio": ("dir", 8),
    "nucleo": ("core", 8),
    "replica_zip": ("zip", 8),
    "instalador": ("inst", 8),
    "cache": ("oc", 8),
    "manifesto": ("own", 8),
    "guarda": ("g", 8),
    "opcao_payload": ("opt", 10),
    "chave_escrita": ("wk", 12),
    "atributo_js": ("js", 6),
}
OPCOES_PRIVADAS = (
    "sw_url", "sw_cached", "sw_config", "sw_config_sig", "srv_key",
    "page_cached", "js_cached", "src", "issued", "bp", "bu", "ic",
    "errors", "",
)
MARCADOR_FORTE = re.compile(
    rb"SC_ADV_BEGIN|SC_DB_BEGIN|SC_TH_BEGIN|SC_CORE_BOOT_VER|"
    rb"sc_payload_persistent|sc_own_manifest|SCV:[0-9]",
    re.I,
)


def raiz_normalizada(raiz: str | Path) -> str:
    """Preserva o ABSPATH literal: a barra final faz parte do cálculo."""
    valor = str(raiz).replace("\\", "/")
    if not valor.startswith("/") or "\x00" in valor:
        raise ValueError("ABSPATH deve ser absoluto e não conter NUL")
    return valor.rstrip("/") + "/"


def resumo_md5(texto: str) -> str:
    # MD5 é aqui parte da nomenclatura do malware, NÃO um hash de segurança.
    return hashlib.md5(texto.encode("utf-8")).hexdigest()


def identificadores(raiz: str | Path) -> dict:
    """Calcula identificadores da variante SCV:4.3.24 sem consultar rede/disco."""
    abspath = raiz_normalizada(raiz)
    papeis = {
        nome: resumo_md5(abspath + papel)[:tam]
        for nome, (papel, tam) in PAPEIS.items()
    }
    def endpoint(papel: str) -> int:
        h = resumo_md5(abspath + "ep" + papel)
        return 91000000 + int(h[:7], 16) % 8999999
    d = papeis
    arquivos = {
        "loader_visivel": f"wp-content/{d['loader_visivel']}.php",
        "loader_oculto": f"wp-content/.{d['loader_oculto']}.php",
        "diretorio": f"wp-content/.sc_{d['diretorio']}",
        "nucleo": f"wp-content/.sc_{d['diretorio']}/core_{d['nucleo']}.php",
        "replica_zip": f"wp-content/{d['replica_zip']}.zip",
        "instalador": f"wp-content/.sc_{d['diretorio']}/{d['instalador']}.php",
        "cache": f"wp-content/.wp-object-cache-{d['cache']}.dat",
        "cache_lkg": f"wp-content/.wp-object-cache-{d['cache']}.dat.lkg",
        "manifesto": f"wp-content/.sc_{d['diretorio']}/own_{d['manifesto']}.php",
        "guarda": f"wp-content/.g_{d['guarda']}.php",
    }
    opcoes = {
        nome or "(vazia)": resumo_md5(abspath + SAL + nome)[:12]
        for nome in OPCOES_PRIVADAS
    }
    return {
        "variante": "SCV:4.3.24",
        "abspath": abspath,
        "arquivos": arquivos,
        "opcoes": opcoes,
        "opcao_payload": d["opcao_payload"],
        "endpoint_sw": endpoint("sw"),
        "endpoint_instalador": endpoint("inst"),
        "atributo_js": "data-sc-" + d["atributo_js"],
        "chave_escrita": d["chave_escrita"],
    }


def decodificar_opcao(valor: bytes, limite: int = 65536) -> dict:
    """Base64(chave XOR de um byte + dados); nunca executa/deserializa PHP."""
    if len(valor) > (limite * 2) or not re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", valor):
        return {"estado": "FORMATO_NAO_SUPORTADO"}
    try:
        dado = base64.b64decode(valor, validate=True)
    except (binascii.Error, ValueError):
        return {"estado": "BASE64_INVALIDO"}
    if len(dado) < 2 or len(dado) > limite + 1:
        return {"estado": "TAMANHO_NAO_SUPORTADO"}
    chave = dado[0]
    resultado = bytes(byte ^ chave for byte in dado[1:])
    estrutura = resultado.startswith((b"a:", b"s:", b"i:", b"b:", b"N;", b"O:"))
    marcadores = sorted({m.group(0).decode("ascii", "replace") for m in MARCADOR_FORTE.finditer(resultado)})
    return {
        "estado": "DECODIFICADO",
        "formato_serializado_aparente": estrutura,
        "tamanho_decodificado": len(resultado),
        "sha256_decodificado": hashlib.sha256(resultado).hexdigest(),
        "marcadores": marcadores,
        "conteudo_omitido": True,
    }


def investigar_arquivos(raiz: Path, limite_por_arquivo: int = 8_388_608) -> list[dict]:
    """Inspeção exata dos caminhos derivados; não segue symlinks nem modifica arquivos."""
    dados = identificadores(raiz)
    encontrados = []
    for papel, relativo in dados["arquivos"].items():
        caminho = raiz / relativo
        try:
            if caminho.is_symlink() or not caminho.exists():
                continue
            if not (caminho.is_file() or caminho.is_dir()):
                continue
            info = caminho.stat()
            tamanho = info.st_size if caminho.is_file() else None
            hash_arquivo = None
            marcador = False
            if caminho.is_file() and tamanho <= limite_por_arquivo:
                h = hashlib.sha256()
                with caminho.open("rb") as entrada:
                    inicio = entrada.read(131072)
                    h.update(inicio)
                    marcador = bool(MARCADOR_FORTE.search(inicio))
                    while bloco := entrada.read(262144):
                        h.update(bloco)
                        if not marcador and MARCADOR_FORTE.search(bloco):
                            marcador = True
                hash_arquivo = h.hexdigest()
            encontrados.append({
                "path": relativo,
                "size": tamanho,
                "sha256": hash_arquivo,
                "classification": "IOC_REQUER_VALIDACAO" if marcador else "SC_CAMINHO_DERIVADO_REQUER_REVISAO",
                "reason": "Caminho derivado da variante SCV:4.3.24; confirmar conteúdo e procedência",
                "indicator": "sc403_abspath:" + papel,
                "confidence": "ALTA" if marcador else "MEDIA",
                "timestomp_93819": (int(info.st_mtime) % 100000 == 93819),
                "analise_conteudo_completa": hash_arquivo is not None,
            })
        except OSError:
            encontrados.append({
                "path": relativo, "classification": "SC_LEITURA_INCOMPLETA",
                "indicator": "sc403_abspath:" + papel, "confidence": "BAIXA",
            })
    return encontrados


def linhas_opcoes(rows: list[list[str]], dados: dict) -> list[dict]:
    """Normaliza a resposta SQL; nunca retorna valor original ou decodificado."""
    inverso = {valor: chave for chave, valor in dados["opcoes"].items()}
    inverso[dados["opcao_payload"]] = "payload"
    findings = []
    for row in rows:
        if len(row) != 4 or row[0] not in inverso:
            raise ValueError("Consulta de opções privadas retornou linha inesperada")
        nome, comprimento, sha_sql, hex_parcial = row
        if (not comprimento.isdigit() or not re.fullmatch(r"[0-9a-fA-F]{64}", sha_sql)
                or not re.fullmatch(r"[0-9a-fA-F]*", hex_parcial)):
            raise ValueError("Metadados inválidos de opção privada")
        bruto = bytes.fromhex(hex_parcial)
        valor_inteiro = len(bruto) == int(comprimento)
        decodificado = (decodificar_opcao(bruto) if valor_inteiro
                        else {"estado": "VALOR_TRUNCADO_REQUER_REVISAO"})
        findings.append({
            "kind": "sc403_derived_option",
            "name": nome,
            "length": comprimento,
            "state": "REVISAO_NECESSARIA",
            "sha256": sha_sql.lower(),
            "value_length_bytes": int(comprimento),
            "value_classification": "SC403_OPCAO_DERIVADA",
            "safe_excerpt": "[VALOR_OMITIDO]",
            "decoded_excerpt": "[VALOR_OMITIDO]",
            "confidence": "ALTA" if decodificado.get("marcadores") else "MEDIA",
            "papel": inverso[nome],
            "decodificacao": decodificado,
        })
    return findings
