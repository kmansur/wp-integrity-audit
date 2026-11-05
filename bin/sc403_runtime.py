"""Inventário de identidade de processos; não sinaliza nem controla processos."""
from __future__ import annotations

import os
from pathlib import Path


def processo(pid: int) -> dict:
    base = Path("/proc") / str(pid)
    if not base.is_dir() or base.is_symlink():
        return {"pid": pid, "estado": "AUSENTE"}
    try:
        status = (base / "status").read_text(errors="replace")
        uid = next((int(l.split()[1]) for l in status.splitlines() if l.startswith("Uid:")), None)
        cmd = (base / "cmdline").read_bytes()[:4096].replace(b"\0", b" ").decode("utf-8", "backslashreplace")
        exe = os.readlink(base / "exe")
        cwd = os.readlink(base / "cwd")
        return {"pid": pid, "uid_efetivo": uid, "cmd_hash": __import__("hashlib").sha256(cmd.encode()).hexdigest(),
                "exe": exe, "cwd": cwd, "estado": "INVENTARIADO"}
    except (OSError, ValueError):
        return {"pid": pid, "estado": "IDENTIDADE_INCOMPLETA"}
