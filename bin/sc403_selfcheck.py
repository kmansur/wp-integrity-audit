"""Auto-verificação segura das dependências locais do auditor."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import sys

MODULOS = ("component_versions", "sc403_forense", "sc403_shm", "sc403_plano", "sc403_monitor")


def verificar(base: Path) -> dict:
    base = Path(base).resolve()
    resultados = []
    for modulo in MODULOS:
        resultados.append({"item": f"modulo:{modulo}", "ok": importlib.util.find_spec(modulo) is not None})
    for programa in ("python3", "mysql", "mysqldump"):
        resultados.append({"item": f"programa:{programa}", "ok": shutil.which(programa) is not None,
                           "obrigatorio": programa == "python3"})
    script = base / "wp-integrity-audit.py"
    resultados.append({"item": "script_principal", "ok": script.is_file() and not script.is_symlink()})
    resultados.append({"item": "python_versao", "ok": sys.version_info >= (3, 10),
                       "versao": ".".join(map(str, sys.version_info[:3]))})
    obrigatorios = [x for x in resultados if x.get("obrigatorio", True)]
    return {"schema_version": 1, "status": "OK" if all(x["ok"] for x in obrigatorios) else "REVISAO_NECESSARIA",
            "somente_leitura": True, "resultados": resultados,
            "avisos": [x["item"] for x in resultados if not x["ok"] and not x.get("obrigatorio", True)],
            "observacao": "A auto-verificação não abre WordPress, não lê credenciais e não executa PHP."}
