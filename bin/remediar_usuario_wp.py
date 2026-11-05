#!/usr/bin/env python3
"""Remoção controlada de usuário WordPress sem executar PHP.

Só remove uma conta por ID, após verificar que não possui posts nem comentários.
Credenciais são lidas literalmente do wp-config.php por parser seguro e nunca
aparecem em argumentos, logs ou saída.
"""
from __future__ import annotations
import argparse
import ast
import json
import os
from pathlib import Path
import re
import subprocess
import sys

class Recusado(RuntimeError):
    pass

def parse_config(path: Path) -> tuple[dict[str, str], str]:
    if path.is_symlink() or not path.is_file():
        raise Recusado("wp-config.php ausente ou link simbólico")
    text = path.read_text(encoding="utf-8", errors="replace")
    values = {}
    for key in ("DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST"):
        match = re.search(r"define\s*\(\s*['\"]" + key + r"['\"]\s*,\s*(['\"])((?:\\.|(?!\1).)*)\1\s*\)", text)
        if not match:
            raise Recusado(f"{key} não encontrado em wp-config.php")
        try:
            values[key] = ast.literal_eval(match.group(1) + match.group(2) + match.group(1))
        except (SyntaxError, ValueError):
            raise Recusado(f"{key} possui expressão não literal")
    prefix = re.search(r"\$table_prefix\s*=\s*['\"]([A-Za-z0-9_]+)['\"]", text)
    if not prefix:
        raise Recusado("table_prefix ausente ou dinâmico")
    return values, prefix.group(1)

def ident(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_]+", value):
        raise Recusado("Identificador SQL inválido")
    return "`" + value + "`"

def main() -> int:
    p = argparse.ArgumentParser(description="Remoção hash/evidência de usuário WordPress")
    p.add_argument("--site", required=True, type=Path)
    p.add_argument("--case", required=True, type=Path)
    p.add_argument("--user-id", required=True, type=int)
    p.add_argument("--db-host", type=str)
    modes = p.add_mutually_exclusive_group(required=True)
    modes.add_argument("--dry-run", action="store_true")
    modes.add_argument("--apply", action="store_true")
    args = p.parse_args()
    if args.user_id <= 0:
        raise Recusado("ID inválido")
    config, prefix = parse_config(args.site / "wp-config.php")
    cnf = args.case / "mysql-user-remediation.cnf"
    args.case.mkdir(mode=0o700, parents=True, exist_ok=True)
    cnf.write_text("[client]\n" + "".join(f'{k}="{str(args.db_host or config[k]).replace(chr(34), chr(92)+chr(34)) if k == "DB_HOST" else str(config[k]).replace(chr(34), chr(92)+chr(34))}"\n' for k in ("DB_HOST", "DB_USER", "DB_PASSWORD")), encoding="utf-8")
    os.chmod(cnf, 0o600)
    users, meta, posts, comments = (ident(prefix + x) for x in ("users", "usermeta", "posts", "comments"))
    db = config["DB_NAME"]
    def q(sql: str):
        proc = subprocess.run(["mysql", f"--defaults-extra-file={cnf}", "--batch", "--skip-column-names", db], input=sql, text=True, capture_output=True, check=True)
        return [line.split("\t") for line in proc.stdout.splitlines()]
    rows = q(f"SELECT ID,SHA2(user_login,256),user_registered FROM {users} WHERE ID={args.user_id};")
    if len(rows) != 1 or len(rows[0]) != 3:
        raise Recusado("Usuário não encontrado ou resposta inválida")
    post_count = q(f"SELECT COUNT(*) FROM {posts} WHERE post_author={args.user_id};")[0][0]
    comment_count = q(f"SELECT COUNT(*) FROM {comments} WHERE user_id={args.user_id};")[0][0]
    meta_count = q(f"SELECT COUNT(*) FROM {meta} WHERE user_id={args.user_id};")[0][0]
    if post_count != "0" or comment_count != "0":
        raise Recusado("Usuário possui conteúdo; não remover automaticamente")
    result = {"user_id": args.user_id, "login_sha256": rows[0][1], "registered": rows[0][2],
              "posts": int(post_count), "comments": int(comment_count), "usermeta": int(meta_count),
              "state": "SIMULACAO" if args.dry_run else "REMOVIDO"}
    if args.apply:
        if os.geteuid() != 0:
            raise Recusado("Aplicação exige root")
        if not sys.stdin.isatty() or input("Confirme backup e remoção do usuário digitando REMOVER-USUARIO: ").strip() != "REMOVER-USUARIO":
            raise Recusado("Confirmação negada")
        q("START TRANSACTION;" + f"DELETE FROM {meta} WHERE user_id={args.user_id};DELETE FROM {users} WHERE ID={args.user_id};COMMIT;")
    (args.case / "user-removal-result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    cnf.unlink(missing_ok=True)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 40 if args.apply else 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Recusado, OSError, subprocess.CalledProcessError, ValueError) as exc:
        print("ERRO: remoção recusada por validação de segurança", file=sys.stderr)
        raise SystemExit(30) from exc
