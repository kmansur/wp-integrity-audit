# Procedimento operacional — recuperação assistida de WordPress comprometido pelo SC

**Versão de referência:** WP Integrity Audit 0.34.0  
**Público:** equipe técnica autorizada, em Debian/Ubuntu  
**Estado:** procedimento controlado de pré-validação; não é homologação de limpeza automática

## Objetivo e princípios

A família SC pode manter múltiplas cópias e mecanismos independentes de reinfecção em arquivos, banco, processos PHP, memória compartilhada e navegadores. Excluir arquivos em um WordPress ainda em execução não garante a erradicação e pode provocar a reconstrução dos artefatos.

No WH01, a investigação deve respeitar o isolamento entre os domínios hospedados. **Não execute `pkill` por usuário, `kill -9` em massa, `ipcrm` por proprietário, `rm -rf` em diretórios de clientes ou `DELETE` por prefixo de opção SQL.**

## Fase 1 — auditoria e preservação

1. Identificar exatamente o domínio, caminho real do WordPress, usuário Unix, pool PHP-FPM (quando aplicável) e banco SQL.
2. Autorizar a investigação, registrar a janela e documentar a decisão de contenção.
3. Preservar os dados existentes e as evidências de acesso antes de modificar arquivos ou sessões.
4. Executar a auditoria padrão:

```bash
cd /opt/wp-integrity-audit
python3 bin/wp-integrity-audit.py \\
  /usr/local/www/data/mpctelecom/html \\
  --domain-label mpctelecom.com.br \\
  --case-root /var/lib/wp-integrity-audit/cases
```

5. Examinar `report.json`, `technical-report.md`, `file-evidence.json`, `sc403-forense.json`, `sc403-sql-objects.json` e `sc403-recovery-plan.json`.
6. Guardar o manifesto de evidências fora do site. Não mover nem editar o caso antes de validar sua integridade.

## Evidências de memória compartilhada System V

Caso exista dump de memória já preservado por procedimento autorizado, sua análise é feita com o parâmetro opcional `--sc-shm-dump-dir`. Separe os dumps em um diretório `0700`, mantenha os hashes originais da coleta e documente a origem. O auditor não coleta segmentos ativos, não lê conteúdo SHM diretamente do kernel e não executa `ipcrm`.

Diferencie registros de `kernel.segmentos` (metadados do host) de `dumps.registros` (arquivos apresentados). Um `shmid` coincidente não prova que o dump foi obtido daquele segmento. Um cabeçalho `SCSHM1` com SHA-256 coerente e `SCV` também não prova autenticidade ou compromisso. A classificação `SHM_PAYLOAD_SCV_COMPATIVEL_REQUER_VALIDACAO` exige investigação humana e não autoriza indisponibilidade ou limpeza.

## Fase 2 — pré-validação atual

Aponte para o diretório exato do caso recém-gerado:

```bash
python3 bin/sc403_preflight.py \\
  --site /usr/local/www/data/mpctelecom/html \\
  --case /var/lib/wp-integrity-audit/cases/CASO_DA_AUDITORIA \\
  --output /root/preflight-sc403-mpctelecom.json
```

O retorno `40` significa pré-validação realizada com pendências; não é erro de execução nem autorização para remover qualquer arquivo. O retorno `30` significa falha de validação. Compare os hashes, os caminhos derivados e os PIDs suspeitos com as evidências originais.

## Fase 3 — confirmação externa da capacidade de recuperação

Documentar, com responsável identificado, antes de qualquer alteração:

- Backup externo completo do site e banco, validado por restauração em clone descartável.
- Capacidade de isolar somente o site afetado, sem interromper PHP, Apache, Nginx ou outros domínios do WH01.
- Atribuição de cada processo suspeito ao domínio afetado, com PID, usuário, PPID, horário de início, descritores e evidências preservados.
- Tratamento de persistências no banco e do WP-Cron com seletores exatos e verificação de integridade.
- Fonte limpa e confiável de plugins e temas, preservando customizações legítimas.
- Inventário de navegadores administrativos que possam conservar service workers maliciosos.
- Autorizações para alteração e plano de retorno à condição anterior.

## Fase 4 — operações assistidas já existentes

A quarentena seletiva aceita somente **artefatos específicos** e evidenciados por SHA-256. Sempre simule antes:

```bash
python3 bin/remediar_arquivos_wp.py \\
  --site /usr/local/www/data/mpctelecom/html \\
  --case /var/lib/wp-integrity-audit/cases/CASO_DA_AUDITORIA \\
  --file wp-content/mu-plugins/ARQUIVO_CONFIRMADO.php \\
  --dry-run
```

A execução de `--apply` não é etapa automática deste procedimento. Só deve ocorrer em clone homologado ou durante intervenção manual autorizada, com contenção confirmada e mecanismos de reinfecção neutralizados. A quarentena pontual não encerra processos nem revoga service workers.

A atualização de opções serializadas `cron` e `active_plugins` deve selecionar hooks e plugins **exatos**, nunca remover integralmente a opção por heurística. Mantenha evidências completas e backups restauráveis.

## Fase 5 — navegadores administrativos

Após preservar evidências e neutralizar os mecanismos do servidor, verificar em cada navegador autorizado a origem do WordPress. A rotina `tools/sc403-browser-admin.js` é de execução manual no console do navegador da origem afetada.

Ela exige o valor `endpoint_sw` do caso forense, mostra registros correspondentes e, se o operador digitar `REVOGAR` e confirmar, solicita a revogação **somente desses registros**.

A função `unregister()` não garante que abas já controladas deixem imediatamente de executar código. Encerrar sessões, revalidar a origem, investigar cache/storage, trocar credenciais e confirmar todos os dispositivos administrativos são passos separados. Evite limpar indiscriminadamente armazenamento de outros sistemas da mesma origem.

## Fase 5.1 — comparação formal da reinfecção

Depois de registrar um segundo caso completo e íntegro, é possível comparar os achados antes e depois sem tocar no WordPress:

```bash
python3 bin/sc403_reinfeccao.py \\
  --anterior /var/lib/wp-integrity-audit/cases/CASO_ANTES \\
  --atual /var/lib/wp-integrity-audit/cases/CASO_DEPOIS \\
  --output /root/reinfeccao-sc403.json
```

O comparador exige o mesmo ABSPATH, verifica os manifestos e identifica novos arquivos ou opções, persistências, mudanças de hash e indicadores SC em ZIPs. O código de saída 40 significa revisão requerida, inclusive sem novos achados. A decisão de reabrir permanece manual.

A recuperação assistida real também inclui nova verificação de processos e de ZIPs antes das alterações. Processo SC detectado, ZIP suspeito ou cobertura insuficiente causam bloqueio operacional. A existência de resultados limpos nesses testes não equivale à autorização de limpeza ou de liberação.

## Fase 6 — auditoria pós-remediação

1. Repetir a auditoria completa e guardar o novo caso.
2. Comparar os dois casos utilizando `--compare` conforme documentado no README.
3. Revisar arquivos recriados, novas opções SQL, processos ainda ativos, cron, triggers, eventos, rotinas e log de acessos.
4. Validar WordPress Core, plugins e temas contra fontes oficiais e revisar componentes premium/customizados individualmente.
5. Testar o funcionamento no clone e o plano de restauração.
6. Manter a decisão de reativação **manual, registrada e separada** da classificação técnica.

## Limites conhecidos

A versão 0.31.0 não possui neutralização automática completa de SC e não comprova o conteúdo de segmentos System V. O inventário SQL pode ser limitado pelas permissões do usuário. Regras YARA, caminhos derivados e timestamps, isoladamente, não são prova suficiente para alteração destrutiva.

**Crédito técnico:** estudo de [ux2dev/wordpress-sc403-cleaner](https://github.com/ux2dev/wordpress-sc403-cleaner), GPL-2.0-or-later. O projeto WP Integrity Audit utiliza implementação independente e preserva atribuição ao autor.
