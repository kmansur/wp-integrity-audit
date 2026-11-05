"""Inventário de runtime baseado em identidade forte; não controla processos."""
from __future__ import annotations

from pathlib import Path

from sc403_identidade import processo as _processo


def processo(pid: int, proc_root: Path = Path("/proc")) -> dict:
    return _processo(pid, proc_root=proc_root)
