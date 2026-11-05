"""Comparação de identidades operacionais, sem controle de recursos."""
from __future__ import annotations


class IdentidadeDivergente(ValueError):
    pass


CAMPOS = ("server_id", "boot_id", "pid_namespace", "ipc_namespace", "wordpress_path", "database", "table_prefix")


def comparar(esperada: dict, observada: dict, campos=CAMPOS) -> dict:
    divergencias = [f"IDENTIDADE_DIVERGENTE:{campo}" for campo in campos
                    if esperada.get(campo) != observada.get(campo)]
    return {"compatível": not divergencias, "divergencias": divergencias}


def exigir(esperada: dict, observada: dict, campos=CAMPOS) -> None:
    resultado = comparar(esperada, observada, campos)
    if not resultado["compatível"]:
        raise IdentidadeDivergente(",".join(resultado["divergencias"]))
