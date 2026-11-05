# Comparativo técnico com `wordpress-sc403-cleaner`

## Escopo

Este documento registra o levantamento da referência pública `ux2dev/wordpress-sc403-cleaner` (GPL-2.0-or-later) contra a implementação independente do `wp-integrity-audit`. A referência foi estudada, mas seus scripts destrutivos não são executados nem copiados para este projeto.

## Cobertura já existente

| Área | Implementação atual | Limitação deliberada |
|---|---|---|
| Nomes derivados de `ABSPATH` | `bin/sc403_indicadores.py` | A nomenclatura isolada é revisão, não prova de execução. |
| Marcadores em PHP e webshell | `bin/wp-integrity-audit.py` | Heurísticas exigem contexto; componentes legítimos podem conter funções dinâmicas. |
| ZIPs e payloads | `bin/sc403_forense.py` | Inspeção limitada e sem extração executável. |
| Opções Base64/GZIP | `database_encoded_scan()` e `sc403_indicadores.py` | Decodificação apenas em memória; sem desserialização PHP insegura. |
| Cron e hooks aleatórios | `database_cron_structure_scan()` | Argumentos não são executados nem exportados. |
| `auto_prepend_file`/`auto_append_file` | `configuration_audit()` e `sc403_forense.py` | Registra categorias e hashes, não segredos ou conteúdo integral. |
| Memória System V | `bin/sc403_shm.py` | Inventário de kernel e dumps preservados são fontes separadas; nenhum `shmat` ativo ou `ipcrm`. |
| Logs e endpoints derivados | `bin/sc403_logs.py` | Exporta contagens e metadados, sem IPs, cookies ou URLs completas. |
| Service worker | `tools/sc403-browser-admin.js` | Operação manual no navegador, com confirmação dupla. |
| Recuperação | `bin/sc403_plano.py`, `sc403_preflight.py` e remediação seletiva | Não há killchain automática nem limpeza global. |

## Diferenças importantes da referência

Os scripts de referência incluem killchain, exclusões SQL amplas, reinicialização de pools, quarentena e vacinação. Essas ações não foram incorporadas automaticamente por risco de escopo compartilhado e perda de evidência. O projeto Python mantém auditoria somente leitura por padrão, confirmações explícitas e pré-condições fail-closed.

## Indicadores adicionados na versão 0.36.0

O módulo `bin/sc403_reconstrucao.py` registra, sem alterar o banco:

- `sc_reins_*` no formato diário `dia_utc|contagem`;
- `sc_ini_fail` e `sc_ini_dead`;
- `sc_fetch_fails`;
- `sc_last_recovery_check`, `sc_last_fetch_ts`, `sc_last_fetch_fail_ts` e `sc_pad_off_ts`.

A evidência `sc403-reinfection-state.json` separa fatos observados, hipóteses e limitações. Estados de reconstrução não são contados como comprometimento confirmado sem correlação independente.

## Licença e procedência

O projeto de referência declara GPL-2.0-or-later. A implementação deste repositório é independente, conserva apenas conceitos e indicadores necessários para defesa e mantém a atribuição documental. Não incorporar trechos de código da referência sem revisão de licença.

## Lacunas remanescentes

- Correlação temporal entre fontes ainda depende de documentação externa da coleta.
- A origem de um dump SHM não é autenticada pelo SHA-256 contido no próprio dump.
- Não há homologação integrada em clone com PHP-FPM, Apache/Nginx e MariaDB.
- A exposição lateral entre múltiplas instalações será tratada em versão posterior, com raízes autorizadas explicitamente.
