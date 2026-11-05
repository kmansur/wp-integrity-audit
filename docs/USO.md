# Guia de uso — WP Integrity Audit

Este guia descreve os principais comandos da versão atual. O comportamento padrão é somente leitura. A ferramenta não executa PHP encontrado no WordPress.

O núcleo de remediação exige uma aprovação Ed25519 externa e uma política de chaves confiáveis para simulação autorizada. A versão atual ainda não executa remediação real.

O host MySQL padrão é `187.120.197.140`. Substitua-o com `--db-host mysql.exemplo` quando o banco estiver em outro endereço.

## 1. Verificar versão e dependências

```bash
cd /opt/wp-integrity-audit
python3 bin/wp-integrity-audit.py --version
python3 bin/wp-integrity-audit.py --self-check
```

O `--self-check` verifica Python, módulos e ferramentas locais. Avisos sobre `mysql` ou `mysqldump` indicam que a auditoria SQL poderá ficar indisponível.

## 2. Auditoria completa de um site

```bash
python3 bin/wp-integrity-audit.py \
  /usr/local/www/data/exemplo/html \
  --domain-label exemplo.com.br \
  --db-host 187.120.197.140 \
  --case-root /var/lib/wp-integrity-audit/cases
```

Ao final, o comando informa o diretório privado do caso e exibe o relatório gerencial quando executado em terminal.

Arquivos principais do caso:

- `report.md`: parecer gerencial;
- `technical-report.md`: evidências técnicas;
- `report.json`: resultado estruturado e código de saída;
- `file-evidence.json`: achados de arquivos;
- `database-evidence.md`: evidências SQL resumidas;
- `sc403-recovery-plan.json`: plano não executável;
- `evidence-manifest.json`: hashes do caso.

## 3. Auditoria somente de arquivos

```bash
python3 bin/wp-integrity-audit.py \
  /usr/local/www/data/exemplo/html \
  --domain-label exemplo.com.br \
  --skip-db \
  --case-root /var/lib/wp-integrity-audit/cases
```

A cobertura ficará incompleta porque o banco não foi auditado.

## 4. Auditoria com banco e pós-verificação

```bash
python3 bin/wp-integrity-audit.py \
  /usr/local/www/data/exemplo/html \
  --domain-label exemplo.com.br \
  --case-root /var/lib/wp-integrity-audit/cases
```

Para uma auditoria SQL posterior, use o caso e os parâmetros suportados pelo ambiente. Nunca coloque senha diretamente na linha de comando; o auditor lê a configuração literal autorizada do `wp-config.php` ou de um arquivo privado de cliente MySQL.

## 5. PDF e envio por e-mail

```bash
python3 bin/wp-integrity-audit.py \
  /usr/local/www/data/exemplo/html \
  --domain-label exemplo.com.br \
  --pdf-report \
  --email-to destinatario@example.com \
  --config /etc/wp-integrity-audit/config.cfg
```

O envio utiliza somente o PDF gerencial. Nunca distribua o diretório completo do caso, pois ele pode conter evidências sensíveis.

## 6. Dumps System V preservados

```bash
python3 bin/wp-integrity-audit.py \
  /usr/local/www/data/exemplo/html \
  --domain-label exemplo.com.br \
  --sc-shm-dump-dir /root/evidencias-sc/shm
```

O diretório deve ser privado e conter somente dumps previamente preservados. O auditor não anexa, lê ou remove segmentos ativos.

## 7. Auditoria lateral entre instalações

```bash
python3 bin/wp-integrity-audit.py \
  /usr/local/www/data/exemplo/html \
  --domain-label exemplo.com.br \
  --sc-authorized-root /usr/local/www/data/conta-exemplo
```

Repita `--sc-authorized-root` para outras raízes explicitamente autorizadas. Não informe `/`, `/etc`, `/var` ou outra raiz ampla.

## 8. Persistência Linux, cron e systemd

```bash
python3 bin/wp-integrity-audit.py \
  /usr/local/www/data/exemplo/html \
  --domain-label exemplo.com.br \
  --sc-host-root /var/spool/cron \
  --sc-host-root /etc/cron.d
```

O inventário é somente leitura. Comandos Base64 encontrados são decodificados apenas em memória e nunca executados.

## 9. Comparar dois casos

```bash
python3 bin/sc403_reinfeccao.py \
  --anterior /var/lib/wp-integrity-audit/cases/CASE_ANTES \
  --atual /var/lib/wp-integrity-audit/cases/CASE_DEPOIS \
  --output /root/comparacao-sc403.json
```

Para monitoramento com JSON estável:

```bash
python3 bin/sc403_monitor.py \
  --anterior /var/lib/wp-integrity-audit/cases/CASE_ANTES \
  --atual /var/lib/wp-integrity-audit/cases/CASE_DEPOIS \
  --output /root/monitoramento-sc403.json
```

Código de saída `40` significa revisão necessária; não significa automaticamente reinfecção.

## 10. Manifesto de remediação — somente simulação

```bash
python3 bin/sc403_escopo.py gerar /var/lib/wp-integrity-audit/cases/CASE
python3 bin/sc403_escopo.py validar /root/sc403-remediation-scope.json
python3 bin/sc403_escopo.py grafo /root/sc403-remediation-scope.json
python3 bin/sc403_escopo.py simular \
  /root/sc403-remediation-scope.json \
  /root/estado-atual.json
```

A versão atual não executa `kill`, `ipcrm`, SQL, cron, systemd, Apache, PHP-FPM ou quarentena a partir desse manifesto.

## 11. Verificar integridade de um caso

```bash
python3 bin/wp-integrity-audit.py \
  --verify-case /var/lib/wp-integrity-audit/cases/CASE
```

O comando verifica os hashes do manifesto e não altera o caso.

## 12. Homologação sintética

```bash
python3 bin/sc403_homologacao.py
```

Executa somente uma fixture temporária, sem banco real, serviços reais ou PHP executável.

## Códigos de saída

- `0`: nenhuma pendência nos indicadores pesquisados;
- `10`: resíduos conhecidos que exigem tratamento;
- `20`: comprometimento confirmado por evidências independentes;
- `30`: erro operacional ou validação recusada;
- `40`: auditoria incompleta ou revisão necessária.

Ausência de indicadores não prova que o site está limpo ou pronto para liberação.
