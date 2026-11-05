"""Identidade operacional de recursos, sem controle ou sinalização."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path


class IdentidadeDivergente(ValueError):
    pass


CAMPOS = ("server_id", "boot_id", "pid_namespace", "ipc_namespace",
          "wordpress_path", "database", "table_prefix")


def comparar(esperada: dict, observada: dict, campos=CAMPOS) -> dict:
    divergencias = [f"IDENTIDADE_DIVERGENTE:{campo}" for campo in campos
                    if esperada.get(campo) != observada.get(campo)]
    return {"compatível": not divergencias, "divergencias": divergencias}


def exigir(esperada: dict, observada: dict, campos=CAMPOS) -> None:
    resultado = comparar(esperada, observada, campos)
    if not resultado["compatível"]:
        raise IdentidadeDivergente(",".join(resultado["divergencias"]))


def _namespace(base: Path, nome: str) -> str | None:
    try:
        return os.readlink(base / "ns" / nome)
    except OSError:
        return None


def _campos_ids(status: str, prefixo: str) -> tuple[int | None, int | None]:
    linha = next((x for x in status.splitlines() if x.startswith(prefixo)), "")
    valores = linha.split()[1:]
    try:
        return (int(valores[0]), int(valores[1])) if len(valores) >= 2 else (None, None)
    except ValueError:
        return None, None


def _starttime(stat: str) -> int | None:
    # comm pode conter espaços e parênteses; o último ')' delimita o campo 2.
    fechamento = stat.rfind(")")
    if fechamento < 0:
        return None
    campos = stat[fechamento + 1:].split()
    try:
        # Após o comm, campos[0] é o campo 3; starttime é o campo 22.
        return int(campos[19])
    except (IndexError, ValueError):
        return None


def processo(pid: int, proc_root: Path = Path("/proc")) -> dict:
    """Coleta identidade forte observável de um PID sem enviar sinais."""
    base = proc_root / str(pid)
    if not base.is_dir() or base.is_symlink():
        return {"pid": pid, "estado": "AUSENTE"}
    try:
        status = (base / "status").read_text(encoding="utf-8", errors="replace")
        uid_real, uid_efetivo = _campos_ids(status, "Uid:")
        gid_real, gid_efetivo = _campos_ids(status, "Gid:")
        cmd_bytes = (base / "cmdline").read_bytes()[:4096]
        cmd = cmd_bytes.replace(b"\0", b" ").decode("utf-8", "backslashreplace")
        stat_text = (base / "stat").read_text(encoding="utf-8", errors="replace")
        starttime = _starttime(stat_text)
        exe = os.readlink(base / "exe")
        cwd = os.readlink(base / "cwd")
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        cgroup = (base / "cgroup").read_text(encoding="utf-8", errors="replace")
        st = os.stat(base / "exe")
        return {
            "pid": pid,
            "ppid": int(stat_text[stat_text.rfind(")") + 1:].split()[1]),
            "uid_real": uid_real, "uid_efetivo": uid_efetivo,
            "gid_real": gid_real, "gid_efetivo": gid_efetivo,
            "boot_id": boot, "starttime_ticks": starttime,
            "pid_namespace": _namespace(base, "pid"),
            "ipc_namespace": _namespace(base, "ipc"),
            "exe": exe, "exe_dev": st.st_dev, "exe_inode": st.st_ino,
            "exe_size": st.st_size, "exe_mtime_ns": st.st_mtime_ns,
            "cwd": cwd, "cmd_hash": hashlib.sha256(cmd.encode()).hexdigest(),
            "cgroup_sha256": hashlib.sha256(cgroup.encode()).hexdigest(),
            "estado": "INVENTARIADO",
        }
    except (OSError, ValueError, IndexError):
        return {"pid": pid, "estado": "IDENTIDADE_INCOMPLETA"}
