# Modelo de autorização SC403

O modelo é JSON versionado. Campos ausentes significam ausência de autorização. Preencha somente após preservar as evidências e validar backup restaurável.

Campos essenciais:

- `case_id`, `identity` e `evidence_manifest_sha256`;
- `authorization.technical_responsible`, `approval_id`, `approved_at`, `valid_until`;
- `resources.processos`, `shm`, `sql`, `arquivos`, `cron`, `systemd` e `php`;
- `operations`, `preconditions`, `forbidden_operations`, `impact` e `plan_hash`.

Não use curingas. Não coloque senhas, salts, tokens ou comandos shell arbitrários no manifesto. A presença de uma operação `remover` ou `reiniciar` não habilita execução nesta versão.
