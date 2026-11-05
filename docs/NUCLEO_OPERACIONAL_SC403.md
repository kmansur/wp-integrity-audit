# Núcleo operacional SC403 — Entrega A

A versão 0.43.3 implementa somente a camada de autorização, identidade, diário, compensação declarativa, runtime de leitura e máquina de estados. Nenhum módulo executa operações de remediação.

## Componentes

- `sc403_autorizacao.py`: representação canônica e vínculo da aprovação ao hash do plano, com assinatura Ed25519 e política externa de chaves confiáveis.
- `sc403_identidade.py`: comparação de host, boot ID, namespaces, caminho, banco e prefixo.
- `sc403_journal.py`: diário JSONL append-only com cadeia SHA-256 verificável.
- `sc403_runtime.py`: inventário de processo sem sinalização.
- `sc403_executor.py`: máquina de estados de simulação.
- `sc403_rollback.py`: proposta de compensação, sem restauração automática.

## Limitações

O hash canônico não autentica sozinho o responsável. A aprovação precisa vir de mecanismo externo, com chave ou identidade verificável. PIDs, SHMIDs, bancos e serviços reais ainda não possuem executores habilitados. A próxima entrega deve começar por SQL seletivo e quarentena em laboratório descartável.
