# Auditoria de Integridade WordPress — branch Python

## Guia de uso

Os comandos principais, exemplos de auditoria, comparação, memória, persistência e simulação estão em [`docs/USO.md`](docs/USO.md).

## Versão 0.43.4 — host MySQL padrão configurável

O auditor usa `187.120.197.140` como host MySQL padrão. Para outro destino, informe `--db-host HOST_OU_IP`; nenhum segredo é aceito na linha de comando.

## Versão 0.43.3 — endurecimento do núcleo operacional

A Entrega A agora exige aprovação Ed25519 verificável por uma política externa de chaves, coleta identidade operacional mais forte de processos, grava diário com lock/fsync e executa simulação baseada no estado observado. Nenhum executor destrutivo foi habilitado.

## Versão 0.43.2 — correção da integração MySQL

A fixture sintética cobre todas as tabelas consultadas pelo scanner SQL. Falhas de consulta recebem diagnóstico sanitizado e não são interpretadas como ausência de indicadores.

## Versão 0.43.1 — guia de uso e núcleo operacional SC403

O núcleo adiciona validação de identidade, autorização vinculada ao hash canônico do plano, diário verificável, máquina de estados e simulação. A implementação não sinaliza processos, remove SHM, altera SQL/cron/systemd, reinicia serviços nem move arquivos.

Consulte `docs/NUCLEO_OPERACIONAL_SC403.md`. A assinatura/aprovação deve ser verificada por mecanismo externo; um hash isolado não prova quem autorizou a operação.

## Versão 0.42.1 — validação de caminhos e validade

Manifestos com componentes de caminho `..` ou expirados são recusados também durante a geração do grafo. Isso impede que uma futura etapa operacional interprete um alvo fora do escopo autorizado.

## Versão 0.42.0 — manifesto e simulação de remediação SC403

Gere e valide um escopo granular sem executar remediação:

```bash
python3 bin/sc403_escopo.py gerar /var/lib/wp-integrity-audit/cases/CASE
python3 bin/sc403_escopo.py validar sc403-remediation-scope.json
python3 bin/sc403_escopo.py grafo sc403-remediation-scope.json
python3 bin/sc403_escopo.py simular sc403-remediation-scope.json estado-atual.json
```

Cada alvo precisa de identidade e operação explícitas. A versão atual somente gera, valida e simula; nenhum recurso do servidor é alterado.

## Versão 0.41.3 — auto-verificação sem falso bloqueio

`--self-check` separa requisitos obrigatórios de avisos opcionais. Assim, uma instalação que executará apenas auditoria de arquivos pode registrar a ausência de `mysql`/`mysqldump` sem ocultar o diagnóstico. Opções de auditoria não podem ser combinadas com a auto-verificação.

## Versão 0.41.2 — limites de persistência

O inventário de `--sc-host-root` cobre somente arquivos elegíveis de cron, systemd, PHP, Apache e inicialização Linux, com limite de 20.000 arquivos. Raízes amplas, links simbólicos e excesso de arquivos deixam a cobertura incompleta.

## Versão 0.41.1 — integração de persistência autorizada

Use `--sc-host-root` para incluir raízes explicitamente autorizadas de cron/persistência no caso da auditoria. O resultado privado `sc403-host-persistence.json` aparece também nos relatórios e não executa os comandos encontrados.

## Versão 0.41.0 — auto-verificação e persistência Linux

Verifique dependências locais sem acessar um site:

```bash
python3 bin/wp-integrity-audit.py --self-check
```

Para inventariar uma cópia autorizada de cron/persistência, use o módulo somente leitura:

```bash
python3 -c 'import sys,json; sys.path.insert(0,"bin"); import sc403_host; print(json.dumps(sc403_host.auditar([__import__("pathlib").Path("/var/spool/cron")]), ensure_ascii=False, indent=2))'
```

O inventário calcula metadados e procura marcadores, podendo decodificar Base64 somente em memória. Não executa comandos, não altera cron/systemd e não acessa credenciais.

## Versão 0.40.1 — cobertura ampliada do monitoramento

Além de arquivos, opções SQL, processos e ZIPs, o monitoramento compara metadados de reconstrução, linha do tempo, exposição lateral, memória System V, persistência e processos. O JSON guarda somente contagens, cobertura, tamanho e SHA-256, nunca os valores brutos dessas evidências.

## Versão 0.40.0 — monitoramento comparativo

Compare dois casos preservados sem alterar os casos ou o WordPress:

```bash
python3 bin/sc403_monitor.py \
  --anterior /var/lib/wp-integrity-audit/cases/site-ANTES \
  --atual /var/lib/wp-integrity-audit/cases/site-AGORA \
  --output /root/monitoramento-site.json
```

O JSON informa novos arquivos/opções, hashes alterados, processos, ZIPs e cobertura incompleta, com código 40 quando há revisão. Não há agendamento automático, exclusão ou autorização de liberação.

## Versão 0.39.0 — homologação sintética

Execute a homologação sem informar um domínio real:

```bash
python3 bin/sc403_homologacao.py
```

Ela cria uma instalação WordPress sintética em diretório temporário, preserva o hash de um artefato de teste, gera o plano de recuperação e verifica que PHP, banco real e serviços nunca são executados ou alterados. O resultado aprovado ainda contém bloqueios e não autoriza liberação; a fixture não substitui ensaio restaurável com MySQL, Apache/Nginx e PHP-FPM.

## Versão 0.38.0 — coordenador de recuperação não executável

Cada auditoria gera, em área privada, `sc403-recovery-plan.json`. O plano organiza preservação, validação de backup, contenção por domínio, revisão de persistência, quarentena, banco/credenciais e verificação pós-recuperação. Ele registra pré-condições, responsável sugerido e condições de interrupção, mas não contém comandos destrutivos e não autoriza liberação.

## Versão 0.37.0 — exposição lateral entre instalações

Use `--sc-authorized-root` somente quando houver autorização explícita para a raiz informada. A opção pode ser repetida e executa uma investigação estrutural, sem escrever, executar PHP ou testar alterações nos sites:

```bash
python3 bin/wp-integrity-audit.py \
  /usr/local/www/data/site-principal/html \
  --domain-label exemplo.com.br \
  --sc-authorized-root /usr/local/www/data/conta-a \
  --sc-authorized-root /usr/local/www/data/conta-b
```

O arquivo privado `sc403-lateral-exposure.json` registra instalações WordPress encontradas, UID/GID, diretórios sensíveis, proteção de PHP em `uploads`, processos cujo comando contém o caminho do site e pools PHP-FPM somente quando a associação é observável na configuração. UID compartilhado, diretório gravável ou ausência de associação textual com um pool são riscos estruturais e não comprovam infecção. Para evitar escopo acidental, a ferramenta não aceita `/`, `/usr/local`, `/usr/local/www` ou outra raiz ampla como autorização implícita.

## Versão 0.36.0 — estado de reconstrução e correlação conservadora

A auditoria SQL identifica estados `sc_reins_*`, `sc_ini_*`, falhas de busca e timestamps de recuperação sem alterar ou executar seus valores. O arquivo privado `sc403-reinfection-state.json` separa fatos observados de hipóteses e compara contadores diários somente com a data UTC da coleta. A presença desses estados não é considerada comprometimento confirmado sem correlação independente.

O levantamento de cobertura da referência externa está em `docs/COMPARATIVO_SC403.md`.

A auditoria também registra `sc403-timeline.json`. Timestamps de arquivos, contadores e ocorrências em logs são mantidos com sua fonte e confiabilidade; mtime manipulável e ausência de horário não são convertidos em uma cronologia afirmativa. PHP grande com comentários/padding aparente e `mtime % 100000 == 93819` produzem revisão contextual, nunca comprometimento confirmado isoladamente.

## Versão 0.35.0 — evidências não confiáveis e proteção contra instruções inseridas

Todo conteúdo coletado durante a auditoria é tratado como dado não confiável. Frases encontradas em arquivos, banco de dados, logs ou dumps que tentem instruir um operador, uma IA ou o próprio auditor são registradas para revisão e nunca são obedecidas. Elas não alteram o escopo, não desativam verificações e não autorizam limpeza ou liberação.

## Versão 0.34.0 — evidências System V SHM com validação isolada

A v0.34.0 incorpora uma implementação independente da inspeção de memória compartilhada desenvolvida inicialmente no WH01, separando **inventário do kernel** de **arquivos forenses de dump**. Nenhum segmento em execução é anexado (`shmat`), lido ou removido; não são executados scripts PHP nem comandos `ipcrm`.

O parâmetro opcional `--sc-shm-dump-dir` aceita apenas um diretório privado (permissões `0700`) de dumps **já obtidos por procedimento forense autorizado**. Cada arquivo deve se chamar `shmid-NUMERO.bin`. O resultado aparece no arquivo privado `sc403-systemv-shm.json`, separado dos demais relatórios.

```bash
python3 bin/wp-integrity-audit.py \\
  /usr/local/www/data/mpctelecom/html \\
  --domain-label mpctelecom.com.br \\
  --case-root /var/lib/wp-integrity-audit/cases \\
  --sc-shm-dump-dir /root/evidencias-sc/shm
```

O módulo aceita no máximo 32 arquivos, até 16 MiB por arquivo e 64 MiB de conteúdo total; bloqueia links simbólicos, mudanças detectadas durante a leitura e diretórios de dump acessíveis a grupo ou terceiros. Registra somente metadados, SHA-256, validação do cabeçalho `SCSHM1`, tamanho, versão `SCV` e presença de marcadores adicionais. **Os bytes do payload não são copiados para o relatório.**

As classificações incluem:

- `SHM_SEGMENT_REQUER_CAPTURA`: metadado de segmento no kernel, sem leitura de seu conteúdo; não atribui comprometimento ao WordPress.
- `SHM_DUMP_FORMAT_INVALID`: dump não corresponde à estrutura declarada.
- `SHM_DUMP_REQUER_VALIDACAO`: estrutura, hash, tamanho, cauda ou indicadores insuficientes.
- `SHM_PAYLOAD_SCV_COMPATIVEL_REQUER_VALIDACAO`: conteúdo contém versão SCV e outro indicador estático, com estrutura e SHA-256 interno coerentes; **não comprova origem, autenticidade nem execução maliciosa.**

A presença de um `shmid` no nome de arquivo não prova que aquele dump veio do segmento homônimo no servidor. O valor SHA-256 presente no cabeçalho é fornecido pelo próprio produtor do dump e **não constitui autenticação externa**. Para comprovar procedência, preserve cadeia de custódia, registro do coletor autorizado, hash do arquivo integral e metadados da captura. Os registros de kernel e dumps são reportados separadamente, evitando contagem duplicada.

Os testes de regressão estão em `tests/test_sc403_shm.py`, com cenários sintéticos. A coleta de memória real e a erradicação coordenada continuam fora do escopo automático. A integração preserva o diretório de trabalho com alterações locais no WH01; a branch remota não deve ser aplicada por `git pull` naquele diretório enquanto houver conflitos.


## Versão 0.33.0 — validação pós-recuperação e consistência das evidências SC

Esta versão corrige uma falha de apresentação: diretórios derivados do SC e arquivos grandes podem ser inventariados **sem SHA-256 completo**. A ausência do hash é registrada como **NÃO CALCULADO** no relatório técnico, sem interromper a geração do parecer ou tratar a evidência como limpa.

O relatório gerencial passa a mostrar explicitamente a quantidade de **caminhos de arquivos/diretórios derivados da família SC** e **opções privadas derivadas do ABSPATH** que necessitam de revisão. Uma opção privada SC localizada no banco agora mantém a avaliação desse componente em **REVISÃO NECESSÁRIA**, mesmo sem outros indicadores. Esses nomes matematicamente derivados, isoladamente, não comprovam comprometimento.

### Verificação obrigatória após alterações assistidas

Além da verificação anterior à recuperação, os modos assistidos `--recover`, `--apply-db` e `--apply-files` realizam nova leitura de `/proc` e análise de ZIPs **após as alterações**. O resultado fica em `sc403-recovery-postcheck.json`, com eventuais bloqueios. A confirmação de recuperação não pode se basear apenas na ausência de indicadores anteriores à intervenção; processos e pacotes podem ser recriados durante a troca dos arquivos.

O parecer resultante não é automaticamente aprovado para liberação, e persistências ou cobertura incompleta geram revisão obrigatória. A verificação não encerra processos nem remove segmentos System V. No inventário SQL de triggers, eventos e rotinas, consultas que ultrapassem 1.000 registros são marcadas como **INCOMPLETA** e registram o tipo de objeto cujo limite foi atingido; a ausência de mais resultados não é interpretada como auditoria integral.

### Testes e compatibilidade

O arquivo `tests/test_sc403_relatorio_pos.py` acrescenta testes sintéticos para diretórios sem hash, opções privadas SC e indicadores pendentes após a recuperação. O GitHub Actions continua executando os testes SC em Python 3.10, 3.11 e 3.12 e passa a executar também a suíte geral em Python 3.11.

**Limitações:** a suíte automatizada não testa a erradicação real do SC em um clone comprometido; decisões sobre isolamento, backup restaurável, credenciais e navegadores continuam manuais. Não considere o código homologado para execução destrutiva em produção sem ensaios específicos.


## Versão 0.32.0 — detecção de reinfecção e bloqueio de recuperação

A versão 0.32.0 acrescenta um comparador independente de casos de auditoria e uma pré-checagem obrigatória antes de **qualquer operação real** de recuperação assistida pelos modos existentes.

### Comparar duas auditorias do mesmo site

`bin/sc403_reinfeccao.py` compara evidências de arquivos e banco de dados de dois casos íntegros, exige a mesma raiz `ABSPATH` e confere os manifestos SHA-256 de ambos os diretórios. Não altera WordPress, banco, casos nem processos.

```bash
python3 bin/sc403_reinfeccao.py \\
  --anterior /var/lib/wp-integrity-audit/cases/CASO_ANTES \\
  --atual /var/lib/wp-integrity-audit/cases/CASO_DEPOIS \\
  --output /root/comparacao-sc403.json
```

O resultado diferencia **novos indícios**, **indicadores persistentes**, **mudança de hash**, **ZIPs com indicadores SC** e **cobertura incompleta**; nunca autoriza reativação. A comparação do mesmo diretório de caso com ele próprio é recusada. Uma alteração de hash pode ser legítima e não é prova isolada de reinfecção. Mesmo duas auditorias aparentemente idênticas não demonstram erradicação. O retorno da comparação é `40` (revisão), ou `30` em caso de erro de segurança/validação.

Os diretórios dos casos devem permanecer privados; arquivos de evidência ausentes, adulterados, não inventariados, com links simbólicos ou vinculados a outro `ABSPATH` levam à recusa da comparação.

### Pré-checagem para a recuperação assistida

Nos modos `--apply-db`, `--apply-files` e `--recover`, **somente quando houver solicitação de execução real**, o auditor agora:

1. Inspeciona novamente processos Linux por `/proc`.
2. Analisa ZIPs potencialmente utilizados para reinstalar o SC, sem extração no disco.
3. Registra `sc403-recovery-precheck.json` no caso privado.
4. Recusa a operação se encontrar processo com indicador SC, ZIP suspeito ou cobertura incompleta.

O `--dry-run` continua disponível para planejamento, e os controles preexistentes de backup obrigatório, confirmação interativa, hashes e seletores exatos permanecem aplicáveis. Nenhum processo é encerrado e nenhum segmento de memória compartilhada é removido.

**Limitações:** o código não identifica automaticamente todos os navegadores comprometidos nem oferece erradicação automática confiável do SC; ainda são necessárias homologação em clone, revisão do banco, isolamento do domínio e validação humana. A ausência de um indicador não prova limpeza.

**Créditos:** pesquisa aberta de ux2dev, [wordpress-sc403-cleaner](https://github.com/ux2dev/wordpress-sc403-cleaner), sob GPL-2.0-or-later. Implementação Python independente, sem copiar rotinas destrutivas do projeto de referência.


Consulte também [Procedimento operacional de recuperação assistida do SC](docs/PROCEDIMENTO_RECUPERACAO_SC.md), com etapas de contenção por domínio, validação, quarentena, revisão de navegadores e auditoria posterior.

## Versão 0.31.0 — pré-validação e recuperação assistida SC

Esta versão acrescenta o comando independente `bin/sc403_preflight.py` para conferir, sem alterar a instalação, um **caso de auditoria completo já encerrado** contra o estado atual do site. A pré-validação:

- Exige caso privado com manifesto SHA-256 válido e caminho WordPress equivalente ao ABSPATH registrado.
- Revalida os hashes dos arquivos constantes em `file-evidence.json` com orçamento de leitura e proteção contra links simbólicos.
- Inspeciona processos Linux por `/proc` em busca de indicadores SC ou arquivos removidos ainda abertos.
- Declara explicitamente pendências de banco SQL, autorização, contenção, backup restaurável, sessões e navegadores. **Jamais autoriza uma recuperação automática**.
- Não modifica o caso original. É possível salvar o resultado em caminho independente com `--output`; arquivos existentes não são sobrescritos.

Exemplo após uma auditoria completa no WH01:

```bash
python3 bin/sc403_preflight.py \\
  --site /usr/local/www/data/mpctelecom/html \\
  --case /var/lib/wp-integrity-audit/cases/CASO_DA_AUDITORIA \\
  --output /root/sc403-preflight-mpctelecom.json
```

O comando retorna **40** quando produz um parecer de revisão (comportamento esperado) e **30** quando falha alguma pré-condição. A execução sem `--output` imprime somente o JSON. Não reutilize um caso antigo sem verificar as diferenças entre os hashes. A presença de backup ou contenção não é verificável por simples inspeção de arquivos: os bloqueios documentais não são considerados resolvidos automaticamente.

### Service workers: procedimento manual específico

`tools/sc403-browser-admin.js` foi adicionado para apoiar a **revogação pontual** do service worker associado à variante documentada. O operador deve executar o código manualmente no console de um navegador autorizado, dentro da origem do WordPress, após preservar evidências e isolar a execução no servidor. Informe o `endpoint_sw` de `sc403-identifiers.json`. O código lista apenas registros cujo `scriptURL` contém o identificador numérico exato `?p=...`, e exige `REVOGAR` e uma segunda confirmação para solicitar `unregister()`. Nenhum registro é revogado ao apenas inventariar.

Essa operação é **opcional, por navegador e por origem**. `unregister()` não encerra imediatamente abas controladas nem limpa automaticamente cache, cookies, senhas, credenciais, sessões ou todos os dispositivos de administradores. Não execute um limpador indiscriminado de armazenamento no WH01. A existência do mecanismo não é homologação de limpeza.

### Limites da recuperação

Os modos antigos de recuperação assistida continuam experimentais, protegidos por validações e confirmações. Esta versão **não incorpora a killchain de terceiros**, não mata processos, não executa `ipcrm`, não elimina opções SQL por prefixo e não implanta o neutralizador PHP no site. A recuperação de produção continua condicionada a clone, backup testado, isolamento e validação do responsável.

Agradecimento e referência de engenharia: **ux2dev**, [wordpress-sc403-cleaner](https://github.com/ux2dev/wordpress-sc403-cleaner), GPL-2.0-or-later. O pré-validador Python e a rotina JS foram desenvolvidos independentemente, usando os comportamentos publicados como referência.

### Testes

```bash
python3 -m unittest discover -s tests -p 'test_sc403_*.py' -v
python3 -m unittest discover -s tests -v
python3 -m compileall -q bin tests
python3 bin/wp-integrity-audit.py --version
```

O workflow `.github/workflows/sc-security-tests.yml` executa sintaxe e testes específicos em Python 3.10, 3.11 e 3.12, além de `node --check` na rotina JS. Esses testes não substituem ensaios integrados no WH01 e a recuperação em laboratório.


## Versão 0.30.0 — investigação forense complementar do SC

A versão 0.30.0 estende a análise estática do incidente em Debian/Ubuntu sem executar arquivos PHP do WordPress, remover registros SQL, matar processos ou limpar memória compartilhada.

Durante a auditoria completa (sem `--skip-db`), os resultados adicionais são preservados em:

- `sc403-forense.json`: ZIPs contendo marcadores em membros PHP, diretivas de configuração PHP sensíveis, processos associados ao caminho do site ou a indicadores da família, e inventário de segmentos System V;
- `sc403-sql-objects.json`: inventário limitado a nome, tipo e contexto de triggers, eventos e rotinas visíveis ao usuário SQL, sem copiar corpos SQL.

A análise de ZIP não extrai conteúdo em disco. Há limites de tamanho, número de entradas e orçamento de descompressão para evitar degradação do servidor. ZIPs não verificados e erros são tratados como pendências, nunca como prova de limpeza.

A inspeção de processos utiliza `/proc` e não persiste a linha de comando, pois ela pode conter senhas e tokens. Quando houver falta de permissão, a cobertura é marcada como parcial. A memória System V é **somente inventariada** por `ipcs -m`; a presença de segmentos, por si só, não demonstra infecção.

A consulta ao `information_schema` depende de permissões do usuário MySQL/MariaDB. Ausência de objetos visíveis não significa inexistência de objetos ocultos por permissões. A existência isolada de uma trigger também não é tratada como evidência de malware. A inspeção de ações SQL e sua procedência continua sendo uma etapa manual.

Pode-se acrescentar `--sc-access-log /var/log/apache2/access.log` ou repetir a opção para outros arquivos, inclusive `.gz`. A correlação dos endpoints derivados produz `sc403-http-logs.json`, apenas com contagens, sem linhas originais, IPs, cookies, User-Agent ou URLs completas. Há limites de arquivos, bytes e linhas; falhas produzem cobertura incompleta. Isso não substitui investigação dos navegadores dos administradores.

Além das evidências, a auditoria completa gera `sc403-recovery-plan.json`, um plano **não executável** que correlaciona arquivos, opções SQL, processos, arquivos ZIP, resultados YARA e endpoints derivados. O plano registra pendências e pré-condições para a recuperação coordenada; jamais autoriza liberação ou executa alterações.

Os novos achados são correlacionados com o relatório JSON e a política conservadora de liberação. `sc403-forense.json` permanece como evidência técnica privada; não é enviado automaticamente ao cliente.

**Créditos:** técnicas e metodologia inspiradas nos estudos abertos de [ux2dev/wordpress-sc403-cleaner](https://github.com/ux2dev/wordpress-sc403-cleaner) (GPL-2.0-or-later), e nas arquiteturas de monitoramento de [rfxn/linux-malware-detect](https://github.com/rfxn/linux-malware-detect) e análise estática de [nbs-system/php-malware-finder](https://github.com/nbs-system/php-malware-finder). Não foram incorporados seus scripts destrutivos ou bibliotecas externas. O código deste módulo é uma implementação independente.

A integração YARA é opcional: o projeto disponibiliza `rules/sc403_triagem.yar` como ponto de partida. Após revisar suas condições, copie as regras para `/etc/wp-integrity-audit/regras/sc403_triagem.yar` com permissões restritas e use `--sc-yara-rules /etc/wp-integrity-audit/regras/sc403_triagem.yar`. O scanner não instala o YARA nem copia regras automaticamente. Nunca carregue regras obtidas de terceiros sem validação; a ferramenta registra apenas nome da regra e caminho relativo, não trechos potencialmente sigilosos. Regras só são aceitas abaixo de `/etc/wp-integrity-audit`. Uma varredura YARA incompleta ou com correspondências impede o resultado limpo.

Limitações: não há ainda neutralização de service workers, inspeção do conteúdo de segmentos de memória, análise profunda de corpos SQL ou limpeza simultânea de persistências. A recuperação em produção continua **não homologada**.

Para validar:

```bash
python3 -m unittest discover -s tests -v
python3 bin/wp-integrity-audit.py --version
```


## Versão 0.29.0 — indicadores SC 4.x derivados do ABSPATH

A auditoria padrão integra o módulo Python `bin/sc403_indicadores.py`, que calcula, **sem executar PHP**, caminhos, chaves de opções e endpoints associados à variante documentada SCV:4.3.24. A checagem de arquivos derivados é somente leitura; opções derivadas são consultadas por nome exato e suas estruturas Base64/XOR são decodificadas **somente em memória**, com limites de tamanho, sem desserializar nem executar conteúdo.

Novas evidências privadas: `sc403-identifiers.json` (inclui endpoints derivados, sem acessá-los), `sc403-file-evidence.json` e `sc403-database-evidence.json`. Esses achados também integram o inventário principal, a contagem de revisão e os bloqueios pós-recuperação. Um caminho ou nome derivado isolado é um indicador que requer validação, **não comprovação suficiente de infecção nem autorização de exclusão**. A derivação depende do caminho `ABSPATH` exato; após migrações, também pode ser necessário investigar os caminhos históricos. Um valor SQL truncado recebe indicação explícita de revisão e nunca é considerado limpo.

Esta implementação é original e foi orientada pelo estudo técnico aberto de **ux2dev**, [wordpress-sc403-cleaner](https://github.com/ux2dev/wordpress-sc403-cleaner), disponibilizado sob **GPL-2.0-or-later**. Agradecemos ao autor pela publicação dos algoritmos e detalhes da família SC. Não foram incorporados os scripts de remoção em massa, encerramento genérico de processos, exclusão abrangente de opções ou limpeza indiscriminada de memória do projeto de referência.

A detecção matemática documentada refere-se à SCV:4.3.24, **não a todas as variantes SC**. A recuperação permanece experimental, assistida e sujeita a validação em clone. Próximas extensões previstas: investigação System V, service workers, motor YARA e monitoramento de reinfecção; **não estão implementadas nesta versão**.

Validação sugerida em Debian/Ubuntu:

```bash
python3 -m unittest discover -s tests -v
python3 bin/wp-integrity-audit.py --version
python3 bin/wp-integrity-audit.py /var/www/site/public_html --domain-label exemplo.com
```


## Diagnóstico de codificação — 0.24.1

Quando um comando externo devolve bytes não UTF-8 (por exemplo, `0xE1`), a ferramenta representa o octeto como `\\xe1` em vez de encerrar a auditoria com `UnicodeDecodeError`. As consultas ao MySQL solicitam `utf8mb4` explicitamente. O escape de bytes é uma representação técnica, **não** a recuperação definitiva da codificação original; ainda é necessário avaliar dados legados antes de concluir que não existem indicadores.

Para validar em Debian/Ubuntu:

```bash
python3 -m unittest discover -s tests -v
python3 bin/wp-integrity-audit.py --version
```

**Atenção ao versionamento:** esta correção foi integrada seletivamente à linha local 0.26.0. Não substitua uma instalação 0.26.0 por uma revisão remota 0.24.x; compare os commits e preserve as melhorias de segurança locais antes de atualizar servidores.


Ferramenta para auditoria de integridade e investigação de comprometimento em sites WordPress, destinada a servidores Debian e Ubuntu.

> **Estado de segurança:** versão de pré-lançamento. Os procedimentos de recuperação ainda não foram validados integralmente em cenários reais de WordPress/MySQL. Não utilize os modos de alteração em produção sem ensaios independentes de recuperação.

## Versão 0.26.0 — auditoria de payloads codificados

A auditoria de banco examina colunas textuais comuns em busca de valores Base64 válidos. Valores Base64 e Base64/GZIP são decodificados somente em memória, sem executar PHP, desserializar objetos ou gravar o conteúdo nos relatórios. O relatório registra a tabela, o registro, a cadeia de codificação, os tamanhos, os hashes e os marcadores identificados.

Payloads decodificados com marcadores confirmados podem ser selecionados explicitamente em uma recuperação assistida com `--remove-confirmed-encoded-db-payload`. Valores codificados sem marcador explícito permanecem em revisão manual; a ferramenta não os remove automaticamente.

Exemplo de auditoria somente leitura:

```bash
python3 bin/wp-integrity-audit.py /var/www/exemplo/public_html --audit-db
```

Exemplo de plano de remoção assistida, após backup externo validado e homologação:

```bash
python3 bin/wp-integrity-audit.py /var/www/exemplo/public_html --apply-db \
  --remove-confirmed-encoded-db-payload --dry-run
```



## Remediação seletiva — 0.24.0 (homologação controlada)

A remediação é **assistida** e deve começar em um clone descartável com backup externo restaurado e testado. O mecanismo não executa PHP para ler ou alterar opções serializadas.

### WP-Cron e ativação de plugins

Para simular a remoção de um **hook exato** do WP-Cron e a desativação de um plugin exato em `active_plugins`:

```bash
python3 bin/wp-integrity-audit.py /var/www/exemplo/public_html --apply-db \
  --remove-cron-hook sc_cron_guard \
  --deactivate-plugin trace-inspector-pad/trace-inspector-pad.php --dry-run
```

Após revisar `recovery-plan.json`, aprovar o isolamento e testar o backup, substitua `--dry-run` por `--recovery-approve`, **apenas no clone homologado**. A ferramenta exige confirmações interativas. Opções SQL são atualizadas com comparação de hash, preservando hooks e plugins não selecionados. Estruturas com objetos ou referências são recusadas e devem ser tratadas manualmente; não altere serialização PHP com SQL `REPLACE()` indiscriminado.

### Quarentena de malware WordPress

Use somente um caminho exato identificado como `IOC_REQUER_VALIDACAO` em `file-evidence.json`. O arquivo de evidência deve pertencer ao mesmo estado do site e ter SHA-256 idêntico:

```bash
python3 bin/remediar_arquivos_wp.py \
  --site /var/www/exemplo/public_html --case /var/lib/wp-integrity-audit/cases/CASO \
  --file wp-content/mu-plugins/trace-inspector-pad.php --dry-run
```

Após ensaiar, `--apply` permite quarentena privada de um único arquivo com cópia integral e hash. Não é uma limpeza em massa de pastas de plugins, nem um atestado de desinfecção.

### Persistência Linux

A ferramenta inspeciona o inventário `host-persistence.json` e somente admite arquivos **específicos** previamente sinalizados sob `/etc/cron.d/`, `/etc/profile.d/` ou unidades `.service`/`.timer` diretamente em `/etc/systemd/system/`. Para unidades systemd, a aplicação exige estado **inactive** e **disabled** verificado por `systemctl`; unidades ativas, habilitadas ou de estado indefinido são recusadas. Após uma quarentena systemd, a revisão de dependências e a necessidade de `systemctl daemon-reload` permanecem tarefas manuais. Exemplo de simulação:

```bash
python3 bin/remediar_persistencia_linux.py \
  --case /var/lib/wp-integrity-audit/cases/CASO \
  --file /etc/cron.d/ARQUIVO_CONFIRMADO --dry-run
```

A aplicação real é explícita por `--apply`, exige root e confirmação interativa, preserva cópia em `quarentena-linux` e não substitui investigação de systemd, cron de usuários, processos PHP, SSH e demais mecanismos de persistência. O serviço afetado deve ser avaliado fora da ferramenta. Sem uma evidência anterior com SHA-256 coincidente, a operação é recusada.

**Não interrompa nem exclua processos antes de preservar PID, comando, árvore de processos, hashes e evidências.** O bloqueio por processos suspeitos ativos na recuperação integral permanece inalterado. Depois da remediação, execute outra auditoria e somente libere o domínio após validação de integridade, funcionalidade, credenciais, backups e parecer técnico.

## Recuperação assistida — 0.23.0 (uso controlado)

A recuperação é **uma operação que modifica o site e/ou o banco**, diferente da auditoria padrão. Deve ser testada primeiro em um clone descartável, com isolamento prévio, janela de manutenção, autorização do responsável e backup externo **testado por restauração**. A ferramenta não considera limpeza completa sinônimo de reativação.

Para limpar opções do banco de dados identificadas e validadas individualmente, sem modificar os arquivos:

```bash
python3 bin/wp-integrity-audit.py /var/www/exemplo/public_html --apply-db --remove-db-option sc_exemplo --dry-run
python3 bin/wp-integrity-audit.py /var/www/exemplo/public_html --apply-db --remove-db-option sc_exemplo --recovery-approve
```

Para restaurar o `wp-content` completo a partir de um diretório independente, contendo `plugins/`, `themes/` e `uploads/` (o argumento aponta para o **conteúdo** de `wp-content`, não o diretório do WordPress completo):

```bash
python3 bin/wp-integrity-audit.py /var/www/exemplo/public_html --apply-files --source /backup/wordpress/wp-content-limpo --replace-plugins-themes --dry-run
python3 bin/wp-integrity-audit.py /var/www/exemplo/public_html --apply-files --source /backup/wordpress/wp-content-limpo --replace-plugins-themes --recovery-approve
```

Para combinar substituição de `wp-content` e remoção exata de opções, use `--recover` com `--source`, `--replace-plugins-themes` e um ou mais `--remove-db-option`. **Somente selecione nomes de opções após inspecionar e validar sua evidência**. O nome `sc_*` por si só não é autorização para exclusão, e opções serializadas como `cron` e `active_plugins` são bloqueadas.

`--dry-run` gera `recovery-plan.json` privado sem modificar o WordPress ou o banco. A aplicação real exige `--recovery-approve` e confirmações interativas, inclusive backup externo e isolamento. Antes de qualquer alteração a ferramenta grava `site-before.tar.gz`, `site-before.sha256`, `database-before.sql` e `database-before.sha256` no diretório do caso. O estágio de arquivos restaura proprietários e permissões de arquivos correspondentes; arquivos novos usam 0644 e diretórios novos usam 0755. A fonte limpa não pode conter nomes de diretórios associados a indicadores conhecidos. A cópia anterior de `wp-content` permanece em quarentena fora da raiz pública. **Não apague a quarentena nem os backups** antes de validação.

O retorno de uma recuperação aplicada permanece **40 (revisão pendente)**: ele registra que alterações foram executadas, mas não garante remediação completa. Execute nova auditoria em separado e valide o funcionamento antes de reativar.

Restrições deliberadas: não há limpeza genérica de registros serializados, exclusão automática de sessões, rotação de salts, sincronização automática do núcleo ou restauração automática de banco. Exclusões SQL por nomes múltiplos não são atômicas em conjunto. Ocorrendo falha após a primeira alteração, mantenha o site isolado e restaure os dados a partir dos backups validados sob supervisão. É indispensável verificar o estado dos arquivos, a execução do WordPress, a persistência no host e o banco antes de autorizar a reativação.

## Uso rápido

A auditoria padrão armazena as evidências em `/var/lib/wp-integrity-audit/cases/`. O parâmetro `--case-root` só é necessário para utilizar outro diretório.

```bash
python3 bin/wp-integrity-audit.py /var/www/exemplo/public_html --domain-label exemplo.com
python3 bin/wp-integrity-audit.py /var/www/exemplo/public_html --domain-label exemplo.com --case-root /backup/auditorias
```

## Envio do relatório gerencial por e-mail

A partir da versão **0.22.2**, a rotina de envio fornece diagnósticos seguros por categoria (DNS, conexão, TLS, autenticação ou recusa SMTP) e confirmação explícita quando o servidor SMTP aceita o e-mail. **Aceite SMTP não significa entrega na caixa de entrada**: em caso de não recebimento, verifique a fila e os logs do servidor, além de políticas antispam, SPF, DKIM e DMARC. Nunca inclua senhas, conteúdo da configuração ou logs SMTP completos em chamados públicos.

Antes de testar o envio, confira se o PDF pode ser gerado com a biblioteca opcional ReportLab, se `/etc/wp-integrity-audit/config.cfg` e o arquivo de senha estão protegidos com permissões `0600`, e se a porta e o modo TLS correspondem ao servidor SMTP. STARTTLS é obrigatório quando configurado, sem fallback inseguro. Não é necessário divulgar o conteúdo desses arquivos para diagnóstico.


O envio exige a opção `--email-to` e utiliza, por padrão, o arquivo privado `/etc/wp-integrity-audit/config.cfg`. Para escolher outro arquivo, utilize `--config`. A opção antiga `--smtp-config` continua aceita.

```bash
python3 bin/wp-integrity-audit.py /var/www/exemplo/public_html --domain-label exemplo.com --email-to cliente@exemplo.com
```

O arquivo de configuração e o arquivo separado com a senha SMTP devem permanecer fora do site, com permissões restritas (`0600`). O envio utiliza TLS validado. O relatório técnico e o conjunto completo de evidências **não** devem ser encaminhados ao cliente sem revisão e autorização.

## Relatórios em português

Na versão `0.22.1`, cada achado do relatório gerencial diferencia explicitamente **indicadores residuais do incidente**, **referências históricas**, **manutenção/atualização**, **procedência/versão não confirmada** e **verificações de segurança pendentes**. O texto informa o que a evidência permite concluir sem alegar comprometimento ativo por uma atualização pendente. Componentes com versão local divergente também são apresentados ao cliente para validação. Os estados do JSON e os códigos de saída permanecem preservados.


A versão `0.22.0` reforça as rotinas de exportação e envio: o arquivo `report.md` tem limite de **8 MiB** para geração PDF e o anexo PDF tem limite de **20 MiB** para envio SMTP. A configuração SMTP é limitada a **64 KiB** e deve permanecer privada. A senha SMTP deve estar em arquivo privado de caminho absoluto e tamanho máximo de **4 KiB**. As permissões dos arquivos confidenciais são verificadas também no descritor aberto. A abertura dos arquivos de entrada protegidos impede seguir links simbólicos. Falhas de validação cancelam a operação, sem enviar um documento inválido.

O CI dispõe de um job específico para testar ReportLab e PyMuPDF em Python 3.12, incluindo acentos e paginação. O modo de auditoria permanece somente leitura no WordPress; não utilize recuperação automatizada em produção. Antes de qualquer uso de e-mail com dados de clientes, valide o transporte SMTP em ambiente controlado e autorize o destinatário.


A versão `0.21.12` automatiza a inspeção dos cabeçalhos de plugins e temas, inclusive a versão declarada e o arquivo principal, sem executar PHP. O parser considera apenas o bloco de metadados e não confunde anotações posteriores, como `version: string,`, com a versão do plugin. O inventário `component-version-evidence.json` e o CSV registram `header_status`. Quando a versão local não pode ser verificada, a consulta oficial não a classifica como correspondente. A evidência informativa de cron continua no registro técnico, sem ser apresentada ao cliente como indicador de incidente sem confirmação.

A seção de componentes do relatório é produzida em português e os achados de versões mostram a instalada e a referência consultada. O SHA-256 apresentado para componentes representa o arquivo principal quando disponível, **não** uma verificação do pacote completo. Os identificadores estruturados permanecem inalterados; a auditoria continua somente leitura por padrão. Não é necessário executar manualmente `grep`, `find` ou o parser para identificar a versão de um plugin.


A versão `0.21.11` atualiza as asserções dos testes de integração MySQL para os relatórios em português, preservando os identificadores técnicos e as regras de auditoria. A liberação da próxima fase depende da aprovação integral do pipeline, incluindo a integração MySQL. Os modos de recuperação continuam experimentais e não homologados para produção.


A versão 0.21.10 também apresenta em português o registro de contenção do incidente. Esse registro não representa autorização de retirada do site do ar nem comprovação de indisponibilidade; exige preenchimento documental pelo responsável.


Na versão 0.21.9, o teste opcional do PDF verifica também a extração dos acentos e a paginação quando o pacote `PyMuPDF` (`fitz`) estiver disponível. A verificação isolada do mecanismo de PDF não substitui a auditoria de integração nem a inspeção visual de um relatório real. A ferramenta permanece em pré-lançamento.


Na versão 0.21.8, a geração do PDF prioriza fontes TrueType Unicode disponíveis no Debian/Ubuntu para representar corretamente os acentos. O teste opcional também gera um documento em português com várias páginas, mas não substitui a inspeção visual por um responsável técnico. Para habilitar o teste, instale ReportLab em um ambiente virtual isolado.


Na versão 0.21.7, três expectativas da suíte de testes foram alinhadas com a apresentação em português, sem modificar a lógica de auditoria. Na versão 0.21.6, foram corrigidas a prioridade dos achados de configuração e descrições do parecer técnico. Novos testes verificam essa apresentação e o mapeamento de estados. A aprovação para entrega ao cliente ainda depende dos testes em Debian/Ubuntu e da revisão visual de um PDF de auditoria real.


A versão 0.21.5 separa textos de apresentação dos valores estruturados (JSON) e traduz as evidências individuais. A versão 0.21.4 corrige rótulos mistos e asserções dos testes após a tradução. A versão 0.21.3 traduz os títulos, rótulos e principais explicações de `report.md` e `technical-report.md`, além do assunto e corpo do e-mail e da paginação do PDF. Códigos de classificação, valores de estado e identificadores de evidência permanecem inalterados para preservar integrações e permitir correlação técnica. Ainda é necessário revisar o restante das mensagens dinâmicas e executar testes automatizados e inspeção visual de PDFs reais.

## Idioma e compatibilidade

Os textos destinados ao operador e ao cliente devem ser apresentados em português do Brasil (`pt-BR`). Nomes de parâmetros, estruturas JSON, nomes de arquivos e chaves da configuração permanecem estáveis quando sua tradução quebraria a compatibilidade. Consulte o histórico de alterações em `CHANGELOG.md`.

---

## Documentação técnica histórica (tradução em andamento)

Python 3 implementation of the WordPress filesystem/database incident audit and recovery utility for Debian and Ubuntu.

> **Security status: pre-release; recovery has not been validated against real WordPress/MySQL test fixtures.** Do not deploy recovery modes on production until integration tests and restore drills pass.

## Requirements

- Python 3.10 or later, standard library only.
- Debian/Ubuntu with `ps` for process inventory.
- For database modes: `mysql` client.
- For recovery: `mysqldump`, sufficient storage, root privileges, independently verified backups, and a site in maintenance/isolation.
- Network access to WordPress.org only with `--official-sync`.

## Usage

```bash
python3 bin/wp-integrity-audit.py --help
python3 bin/wp-integrity-audit.py --audit /var/www/example/public_html
python3 bin/wp-integrity-audit.py --audit-db /var/www/example/public_html
python3 bin/wp-integrity-audit.py --audit-db-post /var/www/example/public_html
```

The legacy option set is preserved: `--audit`, `--audit-db`, `--audit-db-post`, `--apply-files`, `--apply-db`, `--recover`, `--source`, `--core-source`, `--domain-label`, `--db-host`, `--replace-plugins-themes`, `--official-sync` and `--version`. Optional `--case-root` overrides the default private evidence directory.

Examples for **isolated disaster-recovery rehearsal only**:

```bash
sudo python3 bin/wp-integrity-audit.py --apply-files /srv/fixture/wordpress --source /srv/fixtures/clean-wp-content
sudo python3 bin/wp-integrity-audit.py --apply-db /srv/fixture/wordpress
sudo python3 bin/wp-integrity-audit.py --recover /srv/fixture/wordpress --source /srv/fixtures/clean-wp-content --core-source /srv/fixtures/clean-wordpress
```

Mutating modes require interactive confirmations; no `--yes` bypass exists. Reports default to `/var/lib/wp-integrity-audit/cases` without any additional CLI argument; use `--case-root /other/path` only to override it. Case roots are created with restrictive permissions and are rejected inside the WordPress document root.

## Critical differences from the legacy Bash script

- No PHP execution or WP-CLI.
- Read-only database audits no longer create complete SQL/site backups; recovery does.
- MySQL secrets are stored in a temporary `0600` client configuration rather than placed on the command line or in environment variables.
- `active_plugins` and `cron` are **not deleted wholesale** if malicious markers are found. Recovery stops and requires specific manual remediation.
- ZIP packages are validated for path traversal, special entries and size limits. Package download redirects must remain on trusted HTTPS WordPress.org hosts.
- Automatic guessed ownership/permission mutations of uploads are replaced with metadata reporting.
- The original script-specific media path is not retained.
- Quarantined WordPress content is moved outside the site's document root, while confidential backups remain under the private case directory. Recovery validates literal WordPress authentication salts and optional clean-core sources before changes, then re-scans files/processes/database and refuses to declare success if recognized indicators remain. Operators still must independently verify backups and site operation.
- Recovery is **not atomic across the filesystem and database** and core replacement does not remove extraneous files. Use isolated fixtures and a controlled recovery plan.
- The staged replacement tree is rescanned in full before installation. If SQL modifications have started, an error never triggers automatic restoration of pre-change files because the database commit state may be uncertain; follow the documented manual restore procedure instead.

## Tests

```bash
python3 -m compileall -q bin tests
python3 -m unittest discover -s tests -v
```

GitHub Actions runs unit tests on Python 3.10–3.13 and a separate synthetic MySQL 8 integration job. These tests now include a disposable MySQL dump-and-restore verification, but remain insufficient to certify full live WordPress recovery, plugin compatibility and site availability.

## Security and privacy

Do not commit case directories, site backups, SQL dumps, credentials, client paths or private reports. Reports contain file paths and hashes; review them before sharing. [Security notes](SECURITY.md).

## Versioning

This rewrite starts at `0.2.0` (development/pre-release). It does not supersede or modify the historical Bash version `2026.10.28.18`. The Bash entry point was removed from this branch; the original remains available in Git history on `main`.

## Audit coverage (important)

`--audit` now performs **filesystem, process and database** checks by default and requires access to MySQL/MariaDB. If a database query fails, the audit fails rather than reporting zero findings. Use `--audit --files-only` to explicitly skip SQL; the report will say `Database audit: NOT EXECUTED` and `NOT EVALUATED`.

The database matrix checks family-specific options (`sc_*`), historical `SimplePluginLogger_plugin_info_before_update` references, serialized `cron` and `active_plugins` markers, WordPress sessions, application passwords and suspicious login patterns. Report conclusions are computed from the collected records, not from assumptions about the site. Known plugin guard files receive specific contextual classes; those classifications are **pattern recognition, not cryptographic proof of legitimacy**. Wordfence `wflogs` configuration contents are never excerpted.

Relative paths are preserved to support incident triage. Reports may still contain client-specific filenames and need review before disclosure.

The report's `Database findings` count includes only positive records, while every SQL check remains explicitly represented in `database-evidence.json`. Sensitive substrings in relative paths are masked without removing long, legitimate directory names.

## Detailed database evidence

The database report now records the literal database name and physical `<prefix>options`/`<prefix>usermeta` tables so an operator can locate records in phpMyAdmin. WordPress option identifiers such as `SimplePluginLogger_plugin_info_before_update` are preserved without length-based redaction. Family-specific options receive `RESIDUO_FAMILIA_REQUER_LIMPEZA`, while historical references retain `HISTORICAL_REFERENCE`.

For candidate option values, the tool collects full-value SHA-256, exact byte length and a limited encoding classification. Excerpts are restricted to recognized IOC tokens; arbitrary original or decoded database data is deliberately omitted because it can contain credentials and tokens. This is a safe-evidence compatibility choice rather than exact parity with the legacy Shell's unrestricted technical excerpts. Summaries distinguish confirmed family residues, historical references and informational WordPress sessions. Do not distribute detailed case JSON without review.

### Scalar IOC evidence and Markdown layout

Two exact, known family transient keys (`_transient_sc_spread_interval` and `_transient_timeout_sc_spread_interval`) can expose their complete value only when it consists exclusively of 1–20 decimal digits and the SQL byte length matches the extracted value. They receive `ESCALAR_TEXTO_NUMERO_NAO_CODIFICADO`. Other values, including arbitrary `sc_*` content, remain masked. Database findings are displayed as one intact summary table followed by separate per-record Markdown sections; no list entries are inserted inside a table.

## Audit-report release constraints

A completed targeted scan is **not** a production-release authorization. A dynamic WordPress cron entry is recorded as informational evidence (SHA-256, byte count, UTC collection time and recognized marker count) without treating ordinary hash changes as malware. The report displays the tool's own SHA-256 to tie output to a specific installed version. Values from non-allowlisted options remain masked.

Planned but not yet implemented: optional independently validated forensic dump, broader posts/postmeta and host-persistence collection, structured process/network inventory, CSV export, stable dedicated exit codes, module split and automated release decision. Until these features are validated, retain isolation and use human sign-off for site release.

Audit reports now explicitly state whether a database dump and full-file snapshot were performed. Pure audit modes leave both as `NOT PERFORMED`; snapshot generation remains limited to explicitly confirmed mutating recovery workflows. No forensic snapshot is implied by an ordinary read-only audit.

## Standardized audit results (pre-release)

The default audit creates `report.md` and `report.json`. Both include a final status and an executive summary, with separate family-residue, historical, informational, active-marker, file-pattern and process counters.

Audit exit codes: `0` means no known explicit markers under the completed targeted audit; `10` means family residues require remediation; `20` means independently confirmed compromise, including a process matching the incident family's execution markers; `30` means an audit/connection error; `40` means incomplete evidence, including an intentional `--files-only` run or indicators requiring investigation. These are process return codes, not shell error strings. Automation should not equate code 0 with permission to reopen a site.

The `report.json` contains high-level summary and result status only; detailed evidence remains in separately protected case files. This stage does not yet provide CSV consolidation, optional forensic dumps or a full host-persistence audit.

## Evidence indexing and CSV

Each case now includes `evidence-index.json` with deterministic `FILE-001` / `DB-001` references, SQL table/column provenance, and relative file paths. A one-row `report.csv` provides a privacy-conscious fleet-summary alongside `report.json` and `report.md`. Evidence IDs are unique within a case, not across different collections; use the case directory identifier as the namespace.

## Compare two complete audit cases

`python3 bin/wp-integrity-audit.py --compare OLD_CASE NEW_CASE --compare-output /var/lib/wp-integrity-audit/comparisons/review-001`

Comparison never scans or changes the live WordPress site. Both source cases must have complete database coverage and the same database name. Generates private `comparison.json` and `comparison.md` with added, removed and changed file/database evidence (using paths or option identifiers, not ephemeral evidence IDs). A changed cron hash is informational, not proof of compromise. The comparison does not authorize reopening a site.

## WordPress configuration inventory

Read-only audit modes now write `configuration-evidence.json` for configuration files inside the WordPress tree (`.htaccess`, `.user.ini`, `php.ini`, `web.config` and related names). Only relative paths, metadata, modes and SHA-256 values are collected; file contents are never exported. This inventory does not inspect host-wide Apache/PHP-FPM configuration, and a configuration file's presence does not demonstrate compromise.

Hidden-directory PHP files now receive `PHP_DIRETORIO_OCULTO_REQUER_VALIDACAO` unless stronger indicators apply. This is a contextual review flag, not a compromise finding; `.well-known` is excluded from the hidden-directory heuristic.

## Optional core integrity and host persistence metadata

`--audit --check-core TARGET` reads the installed `wp-includes/version.php` as plain text, requests official MD5 checksums over HTTPS from `api.wordpress.org`, and writes `core-integrity.json`. It does **not** execute PHP, invoke WP-CLI, download code archives or change core files. Missing or mismatched files are marked for manual review; official checksum comparisons assume `en_US`, so localized WordPress installations may legitimately differ. Checksum unavailability is explicitly recorded in JSON and must not be interpreted as integrity success.

`--audit --host-persistence TARGET` additionally inventories metadata (paths, SHA-256, sizes and modes) from selected Linux cron, systemd, PHP and Apache configuration locations. It writes `host-persistence.json`, never exports configuration bodies, and does not change or restart services. This is **not** a complete host-persistence investigation: per-user crontabs, running processes, deleted files, and external services require separate review. These probes are opt-in and available only in audit mode.

## Optional probe status integration

When `--check-core` is requested, unavailability or mismatches in official checksums are exposed in the executive summary and `report.json` (`optional_probe_review`). If there are no higher-priority family residues, these findings return status `AUDITORIA_INCOMPLETA` and exit code `40`. Existing confirmed family residues retain status `RESIDUOS_REQUEREM_LIMPEZA` (exit `10`), with optional issues listed alongside them. A clean checksum result is not proof of site integrity.

## Version 0.3.0: full passive audit by default

A normal invocation (`python3 bin/wp-integrity-audit.py /path/to/wordpress`) now runs all implemented passive scans: WordPress files, configuration metadata, Core checksum verification, Linux host-persistence metadata, Elementor asset checks, matching processes and SQL indicators. No remediation is performed. **The Core check contacts the official WordPress checksum API over HTTPS; use `--skip-core` in offline environments.** Disable unwanted checks with `--skip-core`, `--skip-host-persistence`, `--skip-db` (alias `--files-only`), `--skip-files`, `--skip-config`, `--skip-processes` or `--skip-elementor`. Skipped checks are documented in the case report and an otherwise clean report becomes `AUDITORIA_INCOMPLETA` (exit 40). Confirmed family residues continue to return exit 10.

**Important:** Host-persistence scans read selected /etc paths and may require filesystem permissions. File contents remain excluded from the host inventory. Destructive `--apply-files`, `--apply-db`, and `--recover` require explicit selection and interactive approval; they are never part of a default audit. The `--compare` workflow remains separately invoked.

## Report evidence reconciliation

The management summary now reports Core discrepancy counts, WordPress configuration review counts and external host IOC counts from the corresponding JSON evidence files. Core findings and WordPress-local configuration paths and SHA-256 hashes are listed in report.md. Host inventory file paths are excluded from its host-persistence summary and retained in the protected host-persistence.json for internal technical review.

report.json includes domain, case_id, core_discrepancies, configuration_review_count and host_persistence_indicators. The CSV keeps domain and case_id in separate columns. Ordinary host configuration files are classified INVENTARIADO_SEM_INDICADOR; only an explicit known family IOC match receives HOST_INDICATOR_REQUIRES_INVESTIGATION. A lack of matching known IOCs is not a guarantee of host integrity.

## Client-facing and internal reports

The case now generates `report.md` as a management-oriented summary without host paths, detailed infrastructure inventories, or vendor/product names. `technical-report.md` contains detailed WordPress Core discrepancies, local configuration paths and hashes, database evidence and classification notes. `host-persistence.json` remains internal-only; the reports show aggregate host counts. `report.json` contains separate `domain` and `case_id` fields and evidence-derived Core, configuration and host counters; `report.csv` also separates `domain` and `case_id`.

The host inventory classifies ordinary entries as `INVENTARIADO_SEM_INDICADOR` and only labels bounded recognized-family matches `HOST_INDICATOR_REQUIRES_INVESTIGATION`. Ordinary entries are not certified benign. The management risk overview is qualitative; it must not be used as a release authorization.

## Supplementary evidence consistency and triage

The JSON summary's `security_configuration_review` now includes WordPress configuration files actually flagged for review, matching `configuration_review_count`. Configuration files without recognized directive patterns are retained as `CONFIGURACAO_INVENTARIADA_SEM_INDICADOR`; relevant rules are recorded only as indicator *names*, never their potentially sensitive arguments. Inventory totals and review totals are different and must not be confused. The management risk assessment uses `LOW — no known indicators found` for a completed host inventory with no recognized IOC and `NOT DETERMINED` if the host inventory is unavailable. Neither implies that all persistence has been excluded.

Known BitNinja-associated host paths are labeled `COMPONENTE_DE_SEGURANCA_CONHECIDO` for inventory purposes only, not cryptographically authenticated. Their paths remain in private internal evidence, not in the management report. The `evidence-index.json` now includes Core, configuration, host and process evidence identifiers.

## Strict MetForm upload-cache triage

A PHP `index.php` under uploads is classified as `LEGITIMO_VALIDADO` only if its full contents match the exact `Silence is golden.` guard bytes (LF/CRLF); arbitrary PHP at this location remains reviewable. A `font-awesome-<16 lowercase hex>.php` file under `wp-content/uploads/metform/cache/icons/` with a PHP return-array header is classified as `CACHE_PLUGIN_REQUER_VALIDACAO`, **not** as verified plugin content. The full file and its generation mechanism remain unverified; this classification **still forces exit code 40** in an otherwise marker-free audit. File-name matches alone never certify integrity.

## Akismet access control and report consistency

The Akismet `wp-content/plugins/akismet/.htaccess` receives `LEGITIMO_VALIDADO` only when a narrow parser finds a deny-by-default policy with asset-scoped FilesMatch grants and no unrecognized directives or PHP-executable extensions. Other Akismet rules remain subject to manual review. The `security_configuration_review` count in JSON now matches the configuration review total; any plugin security-file review is recorded separately. The management database risk is `LOW — no selected database IOC` only if targeted SQL checks were executed without family residues or selected active markers. WordPress sessions are informational and are not by themselves an indicator of compromise.

A MetForm PHP return-array header and absence of a small set of known IOCs do not prove all 1.6 MB of cache data safe. Until verified against a trusted plugin implementation or a strict full-file parser, these caches remain `CACHE_PLUGIN_REQUER_VALIDACAO`.

## Guarded cache and Apache compatibility checks

The MetForm icon-cache recognizer accepts an expected generator comment followed by an `ABSPATH` exit guard and PHP `return array` header. This is still only `CACHE_PLUGIN_REQUER_VALIDACAO` and requires whole-file source verification; it never authorizes a clean status by itself. The Akismet `.htaccess` recognizer now supports nested `IfModule` blocks for Apache authorization compatibility while rejecting unknown directives, executable-extension grants and unscoped access grants. Unrecognized safe variations remain reviewable, rather than silently trusted.

MetForm cache recognition inspects only a bounded header for contextual classification; the separate full-file IOC scan still takes precedence. An apparent MetForm cache with a family indicator elsewhere in its contents must remain under investigation. Full source verification against the installed plugin generator is an outstanding prerequisite for trusted-cache classification.

## Recovery safeguards (0.4.0)

Post-recovery verification now evaluates actual active database marker states, known file IOCs and process indicators. Absent placeholders and ordinary WordPress session/application-password records do not by themselves fail the post-check. **Recovery remains experimental**: replacement ownership, upload preservation and exact-version sync must be proven in disposable tests before it is used on production sites. Do not infer that CI unit tests authorize recovery.

## 0.5.0 safety gate and generic scanning

The default read-only audit now recognizes a limited set of generic PHP webshell/obfuscation expressions and additional legacy script extensions. These are heuristic indicators requiring manual review. **All mutating modes are temporarily disabled** until end-to-end safety tests establish preservation of user uploads, Unix ownership, exact version synchronization and reliable rollback. No live recovery should be attempted with this build.

## Version 0.6.0: WordPress persistence and timeline

Full passive audits now write `wordpress-persistence.json`, an inventory of MU-plugins and selected drop-ins, including relative paths, hashes and byte sizes. They also write `timeline.json`, a 30-day metadata timeline based on filesystem mtime/ctime. The latter is **not a creation-time history**, and no script code is executed. Both sources are investigative context and do not imply compromise by presence alone. These inventories currently run with the default full audit and retain private-case permissions. Mutating modes are still disabled.

## Component version and provenance audit (0.7.0, experimental)

The default read-only audit inventories local WordPress Core, plugin and theme versions. `--offline` skips all external component-version requests but preserves local inventories. `--skip-version-check` skips this entire new component step and reports reduced coverage. `--official-compare` explicitly enables the default HTTPS comparison. New private case outputs are `component-version-evidence.json`, `component-version-report.md` and `component-version-report.csv`, using `CORE-001`, `PLUGIN-###` and `THEME-###` IDs. API failures are not interpreted as missing/unofficial components. The current implementation **does not yet correlate active plugins/themes with database options or verify plugin/theme package checksums**; treat provenance as preliminary, not cryptographic authenticity.

The version inventory also reads selected WordPress database option values (`active_plugins`, `template`, `stylesheet`) through the existing credential-protected read-only MySQL client. For official plugins, it optionally fetches small HTTPS checksum manifests for the *installed* version; executable packages are never fetched. A checksum mismatch is a review finding, not proof of malware. Plugin/Theme availability on WordPress.org cannot authenticate premium or custom code. The 0.7.0 feature remains pre-release until CI and disposable WordPress fixture testing passes.

WordPress Core version comparison also consults the official HTTPS version-check service; an outdated release is reported separately from checksum mismatches, which retain priority. Any API failure is reported as unavailable rather than as proof of a nonofficial component.

Officially listed plugins without a downloadable checksum manifest receive `PLUGIN_OFICIAL_SEM_CHECKSUM` when their installed version matches the official version. Missing manifests are not considered evidence of modification. The management report counts components flagged as premium/customized separately from unavailable API results.

All component-version evidence and generated report labels are in English. Read-only component results are supplementary and require validation on a disposable full WordPress test installation prior to production acceptance.

## 0.8.0 checksum hardening

Component-version scanning now streams file hashes in bounded 1 MiB blocks. It does not execute WordPress code or download executable packages, and refuses symlinks while hashing. Version inventory remains pre-release until full disposable WordPress scenario testing and explicit provenance/coverage acceptance are complete.

## 0.9.0 official plugin extra-file detection

When an official plugin checksum manifest is available, the component audit now reports executable files present in the plugin directory but absent from the manifest as `EXTRA_EXECUTABLE` evidence. These remain review findings, not malware confirmation. Plugins without an official manifest are not treated as infected merely because their origin cannot be verified.

## 0.10.0 manifest validation

Checksum verification requires usable file entries. A retrieved but empty or invalid checksum manifest is classified as unavailable, not a verified match. Audit remains passive and destructive recovery modes remain disabled.

## 0.11.0 official metadata API error classification

WordPress.org plugin/theme lookup HTTP 404 is recorded as `NOT_FOUND_OFFICIAL_REPOSITORY`; service errors and Core checksum errors remain `API_UNAVAILABLE`. These states never prove maliciousness or authenticate a premium/custom component.

## 0.12.0 coverage and provenance corrections

The technical Core coverage field now reflects `component-version-evidence.json`, and Core outdated counts are separate from plugin/theme counts. An officially unlisted plugin is recorded as `PLUGIN_ORIGEM_NAO_CONFIRMADA_REQUER_REVISAO`, not malware. Where the main plugin header has no readable version, the inventory preserves the version-unidentified condition rather than inventing a local release. `LEGITIMO_VALIDADO` for large PHP caches requires full trusted-source or structural verification; a plausible header alone is not enough.

## 0.13.0 verified artifact exceptions

A previously inspected MetForm cache artifact is allowlisted by its **full SHA-256 hash plus exact relative path**, not merely by a generator comment. The exception covers only that reviewed byte-identical file; any cache update produces a new digest and must be reviewed independently. This is local evidence-based classification, **not** certification by the MetForm publisher. Akismet configuration recognition allows deny-by-default legacy/modern Apache rules and static-asset-only `FilesMatch` exceptions. Broad grants are rejected.

The component management summary now separately counts plugins requiring source/version review (for example an unlisted Envato plugin or an unreadable Popup Maker version). These reviews do not, by themselves, assert malicious activity or change the audit exit code. A single previously inspected MetForm cache hash is the sole narrow exception; all changed bytes trigger renewed review.

## 0.14.0 terminal report display and review-aware status

After normal audit completion, `report.md` is printed on an interactive standard-output TTY and its case path is always shown. If stdout is redirected or piped, only the report path is printed, even with `--show-report`. `--no-show-report` takes priority over `--show-report`. The internal `technical-report.md` is never auto-displayed. Automation exit codes are unchanged: 0 no selected markers or unresolved reviews; 10 known residues; 20 independently confirmed compromise, including a matching family process; 30 execution error; 40 incomplete audit or unresolved review. Non-malware Core update, configuration and provenance/version review findings now yield `REVISAO_NECESSARIA` with exit 40; this does not indicate confirmed compromise.

Akismet static-asset allowlists are checked for executable file extensions, without rejecting harmless filename substrings such as `refresh`.

The component detail report includes manual review guidance for plugins absent from WordPress.org and for unreadable local plugin versions. It explicitly states that a repository miss is not evidence of malware and recommends verifying vendor origin, license, package and hash with the site owner.

## 0.15.0 customer-facing evidence narrative

The management `report.md` now contains an individual finding for each relevant database indicator, file/configuration review and Core/plugin/theme component requiring action. Each finding explains its meaning, recorded state and available SHA-256 evidence without publishing database values, credentials or technical commands. The separate technical report remains restricted. The management report does **not** automatically certify an outage justification or identify an attacker: the service interruption decision must be supported by its own contemporaneous authorization and incident-response record.

## 0.16.0 forensic evidence and containment record

Completed audits write `evidence-manifest.json`, containing SHA-256 hashes and byte sizes of ordinary private case evidence files, and `incident-containment-record.md`, an explicit operator-completion template. The tool never invents the outage timeline, containment authorization or an attacker's identity. A local hash manifest alone is not a tamper-proof or independently attested chain of custody; secure external retention and signed provenance remain necessary for legal/forensic-grade evidence.

## 0.17.0 optional customer PDF

Use `--pdf-report` to generate `management-report.pdf` from the customer-facing `report.md`. Optional dependency: `python3 -m pip install reportlab` in an isolated environment. PDF generation uses no network requests, does not ingest `technical-report.md`, escapes report content before paragraph rendering and restricts generated PDF permissions to owner-only. Without `reportlab`, the CLI fails with an explicit error instead of silently substituting another document. Do not publish the technical case directory.

## 0.18.0 administrator metadata inventory

A normal read-only audit additionally creates `administrator-inventory.json`, listing administrator role candidates as account IDs, SHA-256 pseudonyms and registration dates. Real login names are not exported. `UNAVAILABLE` is recorded if the SQL query cannot run; this is not mistaken for zero administrators. This is an inventory heuristic, not evidence that any user is malicious. Multisite roles and super administrators require further validation.

## 0.19.0 evidence verification and restricted packaging

Use `python3 bin/wp-integrity-audit.py --verify-case /path/to/case` to recompute file SHA-256 and detect missing/modified or unlisted post-capture files (0 for match; 40 for differences). Use `--bundle-evidence` during an audit to create an owner-only `evidence-bundle.tar.gz` plus `evidence-bundle.sha256`; the restricted archive includes internal technical details and **must not be given directly to a customer**. The management report and optional management PDF remain the appropriate customer deliverables. A hash manifest is not independent timestamping, authentication or a cryptographic signature.

The existing `--compare OLD_CASE NEW_CASE` flow also compares Core/plugin/theme component state when both cases have component evidence. Management findings display a calibrated review-priority description; these labels indicate triage urgency, not independent proof of active malware or attribution.

Evidence archive creation performs a sensitive-file preflight before writing, then atomically renames the private completed archive. A failed preflight does not intentionally leave a partial bundle.

The host persistence inventory includes additional Debian/Ubuntu cron, login-profile, preload and sudoers configuration paths. It hashes metadata without printing secret file contents. A filename containing a known security product's name is not sufficient to confer a trusted classification.

The test suite also includes a conditional PDF smoke test that renders a sample management report when `reportlab` is installed. An isolated environment with ReportLab is still required for pre-release PDF visual validation.

## 0.20.0 safe PDF publication

Management PDF generation now renders to an owner-private temporary file within the evidence case. Only a completed file with a valid `%PDF-` signature is atomically published as `management-report.pdf`; a rendering failure removes the temporary file and returns exit 30. The original `report.md` remains available. Optional ReportLab installation and visual review of the final PDF are still required.

## 0.21.1 default output and SMTP configuration paths

The evidence root defaults to `/var/lib/wp-integrity-audit/cases`; `--case-root` is an optional override. For explicitly requested email delivery, `--email-to recipient@example.com` now loads SMTP settings from `/etc/wp-integrity-audit/config.cfg` by default. Override with `--config /secure/custom.cfg`. The historical `--smtp-config` switch remains an alias for backward compatibility. The configuration and separate password file must be protected with owner-only permissions. No email is sent unless `--email-to` is supplied.

```bash
python3 bin/wp-integrity-audit.py /var/www/example/public_html --domain-label example.com
python3 bin/wp-integrity-audit.py /var/www/example/public_html --domain-label example.com --case-root /secure/audit-cases
python3 bin/wp-integrity-audit.py /var/www/example/public_html --domain-label example.com --email-to recipient@example.com
python3 bin/wp-integrity-audit.py /var/www/example/public_html --domain-label example.com --email-to recipient@example.com --config /secure/custom.cfg
```

## 0.21.0 optional SMTP delivery

To email the customer-only management PDF, run an ordinary audit with `--email-to recipient@example.com` (default configuration: `/etc/wp-integrity-audit/config.cfg`; optional override: `--config /secure/custom.cfg`). The PDF is generated automatically even without `--pdf-report`. See `config/smtp.example.cfg` for TLS settings; copy it outside the repository and WordPress document root, then use `chmod 600` on both the configuration and the separate SMTP password file. Only STARTTLS or implicit TLS with certificate verification is supported; credentials are never passed on command lines or written into report files. No message is sent without `--email-to`. Successful submission only confirms acceptance by the configured SMTP server, not delivery or reading. Errors return exit 30. Never send the private evidence bundle or technical report to the customer.
# Quarentena de componente e usuário

Após uma auditoria somente leitura, um componente associado ao incidente pode
ser preservado e isolado com `bin/remediar_arquivos_wp.py --directory`. O
comando exige o manifesto privado `component-directory-evidence.json`, hash
correspondente de cada arquivo, ausência de links simbólicos e confirmação
interativa. O diretório é apenas renomeado para fora do `wp-content`, portanto
a reversão é possível; nenhum PHP é executado.

Para um usuário WordPress sem posts ou comentários, use
`bin/remediar_usuario_wp.py --user-id ID --dry-run` e só depois `--apply` após
backup e isolamento. A ferramenta recusa automaticamente contas com conteúdo.

