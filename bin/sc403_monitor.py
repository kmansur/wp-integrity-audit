"""Monitoramento comparativo de casos SC, sem agendamento ou mutação.

O módulo reutiliza a validação de cadeia de custódia de ``sc403_reinfeccao``
e produz JSON estável para integração futura com Zabbix ou outro coletor.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import sc403_reinfeccao


def monitorar(anterior: Path, atual: Path) -> dict:
    comparacao = sc403_reinfeccao.comparar(anterior, atual)
    arquivos = comparacao["comparacao"]["arquivos"]
    opcoes = comparacao["comparacao"]["opcoes_sql"]
    novos = sorted(set(arquivos["novos"]))
    novas_opcoes = sorted(set(opcoes["novos"]))
    alterados = sorted(set(arquivos["hash_alterado"] + opcoes["hash_alterado"]))
    eventos = len(novos) + len(novas_opcoes) + len(alterados)
    if comparacao["processos_suspeitos_runtime_atual"] or comparacao["arquivos_zip_com_indicadores_sc"]:
        eventos += comparacao["processos_suspeitos_runtime_atual"]
        eventos += len(comparacao["arquivos_zip_com_indicadores_sc"])
    estado = "MUDANCA_REQUER_REVISAO" if eventos else "SEM_MUDANCA_NOS_INDICADORES_COMPARADOS"
    return {
        "schema_version": 1,
        "tipo": "MONITORAMENTO_COMPARATIVO_SC",
        "caso_anterior": comparacao["caso_anterior"],
        "caso_atual": comparacao["caso_atual"],
        "abspath": comparacao["abspath"],
        "estado": estado,
        "eventos_requerendo_revisao": eventos,
        "novos_arquivos": novos,
        "novas_opcoes_sql": novas_opcoes,
        "hashes_alterados": alterados,
        "processos_suspeitos_runtime": comparacao["processos_suspeitos_runtime_atual"],
        "zips_com_indicadores_sc": comparacao["arquivos_zip_com_indicadores_sc"],
        "cobertura_incompleta": comparacao["cobertura_incompleta"],
        "liberacao_autorizada": False,
        "agendamento_automatico": False,
        "nota": "Monitoramento comparativo não substitui investigação manual e não prova erradicação.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Comparar casos SC para monitoramento")
    parser.add_argument("--anterior", type=Path, required=True)
    parser.add_argument("--atual", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    resultado = monitorar(args.anterior, args.atual)
    if args.output:
        destino = args.output.absolute()
        if destino.is_symlink() or destino.parent.is_symlink():
            raise sc403_reinfeccao.ComparacaoRecusada("Saída simbólica não permitida")
        destino.parent.mkdir(parents=True, exist_ok=True)
        with destino.open("x", encoding="utf-8") as stream:
            json.dump(resultado, stream, indent=2, ensure_ascii=False)
    print(json.dumps(resultado, indent=2, ensure_ascii=False))
    return 40 if resultado["eventos_requerendo_revisao"] or resultado["cobertura_incompleta"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
