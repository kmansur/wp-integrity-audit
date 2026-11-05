# Histórico de alterações

O projeto utiliza versionamento semântico. As mensagens e a documentação destinadas ao operador e ao cliente devem ser produzidas em português do Brasil.

## [Não publicado]

## [0.40.0] - 2026-11-04

### Monitoramento
- Adicionado `bin/sc403_monitor.py` para comparação recorrente de casos já preservados, com JSON estável para integração futura.
- O monitoramento identifica novos arquivos, novas opções SQL, hashes alterados, processos suspeitos, ZIPs com indicadores e cobertura incompleta.
- Nenhum agendamento é criado automaticamente e a saída nunca autoriza liberação.

## [0.39.0] - 2026-11-04

### Homologação
- Adicionado `bin/sc403_homologacao.py`, que cria uma fixture sintética descartável e verifica preservação de evidência, recusa de execução PHP, ausência de acesso a banco real e plano não executável.
- O teste não simula malware funcional nem declara erradicação; seus bloqueios e limitações são reportados explicitamente.

## [0.38.0] - 2026-11-04

### Recuperação assistida como plano
- O plano SC agora explicita etapas ordenadas, pré-condições, responsáveis, condições de interrupção e ações planejadas.
- O plano incorpora exposição lateral e memória System V como bloqueios de revisão quando houver cobertura incompleta ou riscos registrados.
- Todas as etapas permanecem declarativamente não executáveis; nenhum comando de limpeza, encerramento de processo ou alteração de serviço é emitido.

## [0.37.0] - 2026-11-04

### Adicionado
- Auditoria estrutural, somente leitura e limitada a raízes explicitamente autorizadas, para exposição lateral entre instalações WordPress.
- Inventário de proprietários UID/GID, diretórios sensíveis, proteção de PHP em `uploads`, processos associados por caminho e pools PHP-FPM quando a associação estiver comprovada no texto da configuração.
- Evidência privada `sc403-lateral-exposure.json`, com separação entre risco estrutural, possibilidade de propagação e comprometimento confirmado.
- Opção repetível `--sc-authorized-root` para solicitar a análise de uma ou mais raízes autorizadas.
- Testes de compartilhamento de UID e diretórios graváveis sem transformar esses sinais em prova de infecção.

### Segurança
- A auditoria lateral recusa raízes simbólicas, raízes amplas demais e limites de varredura excedidos.
- Não há testes de escrita, execução de PHP, alteração de permissões, reinício de serviços ou varredura irrestrita de `/usr/local/www/data`.

## [0.36.0] - 2026-11-04

### Estado de reconstrução do SC
- Adicionado `bin/sc403_reconstrucao.py` para identificar e interpretar, somente em leitura, contadores `sc_reins_*`, circuit breakers `sc_ini_*`, falhas de busca e timestamps de recuperação.
- Gerado `sc403-reinfection-state.json` com fatos observados, hipóteses, comparação do dia UTC e limitações explícitas.
- Estados de reconstrução não são tratados automaticamente como comprometimento confirmado.
- Atualizados relatório técnico, relatório gerencial e evidências SQL sem exportar valores brutos.
- Acrescentada revisão contextual de PHP grande com padding aparente e do resíduo de timestamp `mtime % 100000 == 93819`; nenhum dos dois sinais isolados confirma malware.
- Gerado `sc403-timeline.json` com fontes, horários observados, níveis de confiabilidade e eventos sem data inventada.
- Criado `docs/COMPARATIVO_SC403.md` com o levantamento da referência GPL-2.0-or-later e as funcionalidades não incorporadas por segurança.
- Adicionados testes para formatos válidos, formatos malformados e mudança de dia UTC.

## [0.35.0] - 2026-11-04

### Proteção contra instruções inseridas em evidências
- Conteúdo de arquivos, banco de dados, logs, processos e dumps é tratado explicitamente como dado não confiável.
- Adicionada detecção de frases que tentam alterar regras, suprimir achados ou manipular revisores/IA.
- Esses textos nunca alteram o escopo, desativam verificações ou autorizam limpeza; são registrados apenas como revisão.
- Relatórios técnico e gerencial passaram a documentar essa regra de segurança.
- Adicionados testes de regressão para instruções em inglês e português.

## [0.34.0] - 2026-11-04

### Auditoria forense de memória compartilhada System V
- Incorporado `bin/sc403_shm.py`, com inventário de metadados `/proc/sysvipc/shm` separado da análise de dumps previamente preservados. Nunca anexa, lê ou remove segmentos ativos.
- Adicionado `--sc-shm-dump-dir` somente no modo de auditoria; exige diretório privado e nomes `shmid-NUMERO.bin`, impondo limites por arquivo, total e quantidade.
- Inspeção exclusivamente estática do cabeçalho `SCSHM1`, extensão declarada, SHA-256 interno, versão `SCV`, indicadores adicionais e preenchimento final; nenhuma execução de PHP.
- Classificação conservadora `SHM_PAYLOAD_SCV_COMPATIVEL_REQUER_VALIDACAO`; hash interno e nome `shmid` não certificam origem ou comprovação de malware.
- Evidências segregadas em `sc403-systemv-shm.json`, com síntese no relatório técnico/gerencial e bloqueio de parecer limpo quando existirem dumps pendentes.
- Acrescentados testes sintéticos de integridade, limites, link simbólico, dump truncado e inventário independente para eliminar suposições sobre a posição dos registros.
- README atualizado com condições de uso e cadeia de custódia; mudanças locais não comitadas no WH01 permanecem preservadas.
- Atualizado `docs/PROCEDIMENTO_RECUPERACAO_SC.md` para explicitar a separação entre metadados de kernel e dumps, bem como os limites de autenticidade.

### Limitações
- Sem captura de memória ativa, operação `ipcrm`, encerramento de processos ou limpeza automática.
- Testes automatizados não substituem a homologação em clone e a comprovação externa da origem dos dumps.


## [0.33.0] - 2026-11-04

### Segurança e consistência dos relatórios
- Corrigido erro na geração do relatório técnico quando uma evidência derivada SC é um diretório ou arquivo sem hash completo. Agora apresenta `NÃO CALCULADO` em vez de interromper a auditoria.
- Resumo gerencial inclui a quantidade de caminhos e opções privadas SC derivados para revisão, sem considerá-los automaticamente comprometidos.
- Risco do banco deixa de ser rotulado como baixo quando há opções privadas SC derivadas detectadas.

### Validação pós-recuperação
- A recuperação assistida consulta novamente `/proc` e arquivos ZIP após as alterações; o resultado restrito é registrado em `sc403-recovery-postcheck.json`.
- Persistências encontradas ou falta de cobertura após a recuperação causam bloqueio/revisão no parecer, sem autorizar reativação.
- Incluídos testes sintéticos de relatórios sem hash, opções SC e pendências pós-recuperação.
- Inventário SQL de triggers, eventos e rotinas passa a reconhecer quando mais de 1.000 objetos são retornados, registrando `fontes_com_limite_atingido` e cobertura `INCOMPLETA`; adicionado teste de regressão.

### Testes
- Adicionado job de regressão completa em Python 3.11 ao workflow de segurança SC; mantidos testes SC em Python 3.10, 3.11 e 3.12.
- Testes integrados com WordPress comprometido e MariaDB/MySQL em clone ainda necessários para homologação de recuperação destrutiva.


## [0.32.0] - 2026-11-04

### Comparação forense de reinfecção
- Criado `bin/sc403_reinfeccao.py` para comparar duas auditorias do mesmo `ABSPATH`, validando manifestos SHA-256, classificações de arquivos e achados SQL sem executar PHP ou alterar os casos.
- Identificação de novos indicadores, indicadores persistentes, arquivos/opções com hash alterado e processos suspeitos, sempre com liberação automática desativada.
- Rejeição de casos adulterados, caminhos simbólicos, inventários inconsistentes, comparação do caso consigo mesmo e instalações distintas; resultados opcionais em JSON privado fora dos casos.
- Inclusão de ZIPs com indicadores SC na avaliação do caso posterior, com testes sintéticos de persistência em arquivos compactados.
- Incluídos testes sintéticos para integridade, instalações divergentes e persistência de IOC.

### Pré-checagem de segurança na recuperação
- Adicionada inspeção renovada de `/proc` e arquivos ZIP antes de operações de recuperação reais nos modos existentes.
- Operações interrompidas diante de execução suspeita, arquivos ZIP potencialmente persistentes ou verificação incompleta.
- Adicionada função `bloqueios_recuperacao()` e testes cobrindo ausência de achados, processo suspeito, ZIP suspeito e falta de cobertura.
- Gerado `sc403-recovery-precheck.json` no diretório privado do caso; simulações mantidas sem alterações.
- Atualizado `docs/PROCEDIMENTO_RECUPERACAO_SC.md` com comparação formal entre casos e checagens pré-recuperação.

### Limitações
- Comparação de auditorias e ausência de novos indicadores não comprovam erradicação.
- Rotinas destrutivas automáticas do SC não foram habilitadas; testes integrados em clone seguem obrigatórios.


## [0.31.0] - 2026-11-04

### Pré-validação conservadora da recuperação SC
- Criado `bin/sc403_preflight.py` para confrontar caso forense previamente coletado com o estado atual do WordPress, exclusivamente em leitura.
- Conferência de ABSPATH, manifesto SHA-256, hashes dos arquivos auditados, links simbólicos e indicadores de processos ativos, com limites de tamanho e orçamento de leitura.
- Rejeição explícita de links simbólicos também em componentes intermediários dos caminhos registrados no manifesto, com teste de regressão.
- Saída JSON opcional em caminho externo ao caso e à raiz pública; recusa sobrescrita e caminhos simbólicos de saída.
- Parecer de recuperação sempre bloqueado para ações automáticas, exigindo validação independente de banco, backup restaurável, isolamento, sessões e navegadores.
- Adicionados ensaios sintéticos de adulteração de evidências, troca de instalação, arquivos alterados, links simbólicos e PID suspeito.
- Criado `tools/sc403-browser-admin.js` para listar e revogar manualmente apenas registros de service worker com endpoint SC específico, mediante confirmação explícita, sem limpar armazenamento global.
- Incluído `sc-security-tests.yml` para validação automatizada de sintaxe e testes específicos em Python 3.10, 3.11 e 3.12, além de sintaxe JavaScript.
- Atualizados README e créditos ao trabalho público de ux2dev/wordpress-sc403-cleaner (GPL-2.0-or-later), sem incorporar seus procedimentos destrutivos.
- Adicionado `docs/PROCEDIMENTO_RECUPERACAO_SC.md` com procedimento operacional em português para recuperação assistida, segregação por domínio e critérios de liberação manual.

### Limitações
- Nenhuma neutralização automática de processos, memória System V, PHP-FPM, sessões, banco ou service workers.
- Resultado de pré-validação não constitui autorização de recuperação, limpeza comprovada ou liberação do site.
- Testes de integração com MySQL/MariaDB e de restauração em clones permanecem pré-condições de homologação de produção.


## [0.30.0] - 2026-11-04

### Investigação SC complementar
- Adicionado `bin/sc403_forense.py` com inspeção de conteúdo PHP em ZIPs sem extração, com limites de quantidade, tamanho e descompressão.
- Inventário estático de diretivas de configuração PHP, sem divulgar valores completos.
- Inventário de processos Linux por `/proc`, com pesquisa de indicadores da família e arquivos removidos ainda abertos; nenhuma leitura de conteúdo de memória ou encerramento de processos.
- Inventário de memória System V via `ipcs -m`, sem atribuir automaticamente os segmentos ao malware.
- Inventário de triggers, eventos e rotinas visíveis no MySQL/MariaDB, sem extrair corpos SQL.
- Integrados achados e problemas de cobertura à política conservadora de liberação; gerado `sc403-forense.json` e `sc403-sql-objects.json` em diretório privado.
- Incluídos testes de regressão com amostras PHP inertes, ZIP e processos simulados.
- Adicionada integração YARA opt-in (`--sc-yara-rules`) com regras locais confiáveis, execução limitada, sem expor conteúdo, e registro `sc403-yara.json`.
- Adicionado conjunto inicial de regras estáticas de triagem `rules/sc403_triagem.yar`, não ativado automaticamente e sujeito à avaliação de falsos positivos.
- Adicionada correlação opcional de endpoints SC em logs HTTP Apache/Nginx, inclusive gzip, com limites de leitura e saída agregada sem IPs ou URLs completas (`--sc-access-log`, `sc403-http-logs.json`).
- Incluídos testes sintéticos dos logs, incluindo contagem exata, privacidade e arquivo compactado.
- Adicionado `bin/sc403_plano.py` para gerar `sc403-recovery-plan.json`, com correlação dos indicadores e bloqueios à recuperação, sempre em modo não executável.
- Adicionados testes para validar que ausência de cobertura e achados pendentes nunca autorizam liberação automática.
- Corrigida distinção entre PID encerrado durante a varredura e erro de permissão de `/proc`; diretivas de carregamento PHP passam a exigir revisão.
- Créditos e limitações documentados, preservando somente leitura e remediação assistida.

### Pendências de homologação
- Executar suíte completa e testes de integração em Debian/Ubuntu com MySQL/MariaDB.
- Confirmar tolerância a limites em grandes instalações WordPress e revisar classificação de falsos positivos.
- Inspeção YARA e neutralização coordenada de persistências permanecem fora do escopo desta versão.


## [0.29.0] - 2026-11-04

### Detecção estática SCV:4.3.24 e atribuição
- Adicionado `bin/sc403_indicadores.py`, implementação independente baseada no estudo aberto de ux2dev/wordpress-sc403-cleaner (GPL-2.0-or-later), com crédito no código e README.
- Derivação, a partir do ABSPATH, de caminhos de arquivos, chaves privadas SQL e identificadores de endpoints da variante SCV:4.3.24.
- Inspeção somente leitura dos caminhos derivados, registro de SHA-256 e metadados de watermark quando possível; nenhum caminho derivado isolado autoriza remediação.
- Consulta SQL limitada aos identificadores derivados, sem exportar conteúdo bruto; decodificação Base64/XOR em memória, com limites e hashes de saída. Valores truncados são marcados para revisão.
- Adicionados `sc403-identifiers.json`, `sc403-file-evidence.json` e `sc403-database-evidence.json`, integração dos achados ao inventário e à decisão conservadora de liberação.
- Incluídos testes sintéticos de derivação, limites, indicadores em arquivos e não exposição de valores SQL.
- Mantidas as operações de recuperação existentes e sem incorporar comandos destrutivos de projetos externos.

### Limitações e homologação
- A detecção determinística atende à variante documentada SCV:4.3.24; não dispensa inspeção das demais persistências.
- Execução da suíte completa e ensaios reais de recuperação em Debian/Ubuntu ainda pendentes antes de homologação em produção.


## [0.28.0] - 2026-11-03

### Controles emergenciais de auditoria
- Adicionada inspeção estrutural do cron serializado para identificar hooks aleatórios com padrão de persistência, sem exportar argumentos.
- Achados passam a carregar nível de confiança explicável (`ALTA`, `MEDIA` ou `BAIXA`) nos artefatos privados.
- O lock ocupado gera `lock-status.json` e erro operacional claro, sem sugerir remoção manual do lock.
- Comparação antes/depois já disponível por `--compare` passa a ser parte documentada do fluxo pós-remediação.
- Incluído teste sintético do detector de hooks aleatórios; nenhuma rotina executa PHP ou callbacks do cron.

## [0.27.1] - 2026-11-03

### Contexto de bibliotecas legítimas
- Reduzido o peso da heurística comportamental em arquivos do Wordfence e na biblioteca oficial `wp-includes/ID3`, que legitimamente usam funções de rede, arquivos e parsing.
- IOC explícito, webshell genérico e divergência de checksum continuam prevalecendo nesses caminhos.
- Incluídos testes para impedir que a heurística genérica transforme bibliotecas conhecidas em falso positivo.

## [0.27.0] - 2026-11-03

### Detecção comportamental de variantes
- Adicionada análise combinada de mutação de arquivos, comunicação remota, execução dinâmica, montagem de strings escapadas e nomes de funções anômalos.
- A classificação exige múltiplos sinais independentes e aumenta o peso em `uploads`, `mu-plugins` e diretórios ocultos; um único padrão legítimo não gera quarentena.
- O resultado é `PHP_ANOMALIA_COMPORTAMENTAL_REQUER_REVISAO`, sem remoção automática e sem execução do conteúdo.
- Indicadores conhecidos continuam sendo correlacionados, mas a auditoria passa a detectar variantes que alteram nomes, strings e caminhos.
- Incluído teste de regressão para combinação de sinais e controle de limiar.

## [0.26.2] - 2026-11-03

### Detecção de persistência Kinetic Relay
- `kinetic-relay-live` passa a ser indicador explícito em `active_plugins` e em valores de opções.
- `sc_cron_recovery` e `e1v61n2r1im6t7_` passam a ser detectados como hooks de cron associados à família observada.
- Auditorias de `cron`, `active_plugins`, limpeza assistida e pré-validação de serialização usam os mesmos marcadores, evitando que a execução seja liberada após remover apenas uma opção auxiliar.
- Incluído teste de regressão para os três marcadores; nenhuma rotina executa o plugin ou o cron.

## [0.26.1] - 2026-11-03

### Referências reversíveis em opções do banco
- A auditoria passa a examinar opções de nome hexadecimal aleatório com valores curtos no formato de referência reversível.
- Referências como `5.1.2|php.xob-reggol-nevah` são interpretadas somente em memória como `haven-logger-box.php`, preservando o valor original limitado, hash, versão e classificação no relatório privado.
- A detecção é restrita a nomes hexadecimais, sufixo PHP e termos de componentes/incidente conhecidos; valores arbitrários não são classificados automaticamente.
- O achado gera `AUDITORIA_INCOMPLETA` (código 40), exige revisão de procedência e não autoriza remoção automática.
- Incluídos testes para detecção e rejeição de falsos positivos; nenhum PHP ou valor do banco é executado.

## [0.26.0] - 2026-11-03

### Detecção de payloads codificados no banco
- A auditoria somente leitura examina colunas textuais comuns do WordPress em busca de valores Base64 válidos.
- Valores Base64/GZIP são decodificados apenas em memória, sem desserialização ou execução, e registrados por tamanho, SHA-256, cadeia de codificação e marcadores técnicos.
- Payloads decodificados que contêm PHP ou indicadores da família passam a ser classificados como resíduos que exigem limpeza; valores codificados sem marcador explícito permanecem como revisão manual.
- O conteúdo bruto e o conteúdo decodificado não são gravados nos relatórios.
- O modo assistido aceita `--remove-confirmed-encoded-db-payload`, que seleciona somente opções da tabela de opções cujo payload decodificado contém marcadores confirmados; candidatos sem marcador continuam exigindo seleção nominal e revisão manual.
- Incluídos testes unitários para Base64, GZIP e rejeição de falsos candidatos.

## [0.24.1] - 2026-11-03

### Classificação de incidente e evidências de processo
- Processos que correspondem aos marcadores de execução da família passam a produzir `COMPROMETIMENTO_CONFIRMADO` (código 20), em vez de serem apresentados apenas como auditoria incompleta.
- Arquivos com IOC direto são correlacionados ao processo ativo e contabilizados como comprometidos confirmados no resumo.
- O risco de persistência passa a considerar indicadores ativos do WordPress, sem ser reduzido por uma varredura externa do host sem achados.
- O relatório técnico preserva o caminho do processo, mascarando somente segredos explícitos e endereços IP.
- Incluídos testes de regressão para classificação, risco e preservação do caminho.

### Correção de codificação na auditoria
- Execução de comandos externos com decodificação UTF-8 explícita e `backslashreplace`: bytes externos incompatíveis são representados como sequências `\\xNN`, sem perda silenciosa nem exceção `UnicodeDecodeError`.
- Consultas MySQL solicitam explicitamente `utf8mb4` ao cliente, reduzindo inconsistências dependentes do locale do sistema e de caracteres acentuados.
- Testes de regressão cobrem saída de subprocesso com byte Latin-1, inventário de processos com representações de octetos não UTF-8 e parâmetros de charset do cliente MySQL.
- Nenhuma alteração nos modos destrutivos, classificações de risco, geração de PDF ou política de envio de e-mail.
- A correção foi integrada seletivamente à linha 0.26.0 sem substituir as melhorias de segurança locais.

## [0.24.0] - 2026-11-03

### Remediação seletiva de WordPress e Linux
- Criado leitor e serializador restrito para opções PHP `cron` e `active_plugins`, sem executar PHP e sem usar `unserialize`; arrays e escalares canônicos são aceitos, objetos, referências e estruturas inesperadas são recusados.
- Adicionadas opções de linha de comando `--remove-cron-hook NOME` e `--deactivate-plugin PASTA/ARQUIVO.php` aos modos `--apply-db` e `--recover`. Seletores devem ser exatos, sem curingas, e a opção `--dry-run` gera plano sem expor valores completos.
- Alterações de opções serializadas usam verificação de SHA-256 anterior e posterior, com atualização SQL condicionada ao hash antigo; outras entradas de cron e plugins são preservadas.
- Criada quarentena pontual `bin/remediar_arquivos_wp.py` para um arquivo `wp-content` classificado como `IOC_REQUER_VALIDACAO` em evidência anterior, com conferência de SHA-256, cópia privada e exclusão do arquivo somente após validação; não remove diretórios ou plugins inteiros por heurística.
- Criada quarentena Linux `bin/remediar_persistencia_linux.py` para arquivos exatos de `/etc/cron.d`, `/etc/profile.d` e unidades `.service`/`.timer` diretamente em `/etc/systemd/system`, já classificados como `HOST_INDICATOR_REQUIRES_INVESTIGATION`, com hash conferido e cópia preservada. Unidades systemd somente são elegíveis se estiverem inativas e desabilitadas; `daemon-reload` e dependências exigem avaliação manual.
- Pré-validação de serialização rejeita o plano quando o conteúdo resultante ainda contém indicadores conhecidos, antes de atualizar o banco.
- Operações de quarentena são opt-in, exigem root e confirmação interativa; não matam processos nem executam arquivos suspeitos.
- Testes sintéticos e integração MySQL descartável verificam preservação de hooks legítimos, reindexação de plugins, recusas de serialização insegura, concorrência, hashes e quarentena.

### Limites e segurança
- Pré-lançamento para homologação em clone; **não executar alterações diretamente em produção sem backup restaurável e validação independente**.
- `cron`/plugins com objetos ou estruturas PHP não suportadas continuam bloqueados. Atualizações de duas opções não são transação atômica global; eventual falha exige recuperação supervisionada.
- Persistência em serviços systemd, tarefas do usuário, shell global, processos ativos, configuração PHP e banco não é removida automaticamente por heurística. A quarentena de cron.d/profile.d não assegura que processos já em memória foram encerrados.
- A remoção de um arquivo identificado como IOC não garante a desinfecção total de um plugin, do WordPress ou do host. É necessária auditoria pós-correção.


## [0.23.0] - 2026-11-03

### Recuperação assistida de arquivos e banco
- Reabilitados modos de recuperação assistida `--apply-files`, `--apply-db` e `--recover`, com `--dry-run` para simular e `--recovery-approve` mais duas confirmações interativas para operações efetivas.
- `--apply-files` e `--recover` exigem `--source` com um `wp-content` completo e previamente verificado, incluindo diretórios `plugins`, `themes` e `uploads`, e a opção explícita `--replace-plugins-themes`.
- A cópia limpa não pode ficar dentro do site nem abranger o diretório do site. Rejeitam-se arquivos especiais, symlinks, indicadores conhecidos e padrões genéricos de webshell.
- O estágio restaura UID/GID e permissões dos caminhos existentes; arquivos novos recebem modo 0644 e diretórios novos modo 0755. Escrita pública é removida. A troca de `wp-content` usa renomeação e mantém o conteúdo anterior em quarentena fora do document root.
- A fonte limpa rejeita nomes indicativos de incidente também em diretórios e bloqueia padrões conhecidos de webshell genérica.
- `--apply-db` e `--recover` utilizam somente `--remove-db-option NOME` (repetível), com nome exato, SHA-256 do valor no momento do planejamento e verificação antes de cada exclusão; nenhuma limpeza indiscriminada por prefixo `sc_*`.
- Nunca se apagam automaticamente sessões, senhas de aplicação, `cron`, `active_plugins`, opções centrais ou registros serializados, e não ocorre rotação implícita de salts.
- Operação real exige snapshot do site em TAR.GZ com leitura de validação e dump SQL com hash SHA-256 antes da primeira alteração, além de confirmação de isolamento e backup externo.
- Sempre ocorre auditoria após operações reais e relatório de pendências; indicadores remanescentes impedem declaração de sucesso.
- A opção `--core-source` e sincronização automática de pacotes oficiais permanecem bloqueadas, assim como envio SMTP durante recuperação.
- Testes unitários e integração MySQL cobrem seleção explícita, preservação de dados legítimos, fonte limpa e propriedade de arquivos.

### Cuidados e limites
- Pré-lançamento para utilização assistida; testar primeiro em clone descartável. A exclusão de múltiplas opções SQL é realizada em passos por nome e hash, **não é uma transação única**; uma falha pode exigir recuperação a partir do dump.
- O operador deve obter previamente cópia confiável completa de `wp-content` (não reutilizar arquivos potencialmente infectados sem investigação). A auditoria não remove automaticamente persistência no host, entradas de cron serializadas ou códigos maliciosos embutidos em opções complexas.
- Após aplicar alterações, o modo de recuperação retorna código **40 (revisão pendente)** até nova auditoria e liberação técnica; a aplicação não é apresentada como garantia de limpeza.
- A reativação não é automática e depende de aprovação técnica. A recuperação ainda não foi homologada em ambiente real de produção.


## [0.22.2] - 2026-11-03

### Diagnóstico e confirmação de envio SMTP
- As falhas SMTP passam a informar, sem expor segredos, a categoria operacional: resolução DNS, conexão recusada, tempo limite, negociação/certificado TLS, autenticação e remetente/destinatário recusado.
- STARTTLS configurado exige anúncio explícito da extensão antes da autenticação. Não há redução automática para comunicação sem criptografia.
- Respostas de recusa de destinatários do servidor SMTP deixam de ser consideradas sucesso.
- O terminal identifica a geração do PDF e apresenta confirmação explícita somente após o servidor SMTP aceitar a mensagem; aceitação não garante entrega na caixa postal.
- Novos testes de regressão usam servidores SMTP simulados, sem tráfego de rede real. Fluxos de auditoria e códigos de retorno permanecem inalterados.

### Homologação
- Executar teste real em destinatário autorizado após aprovação do pipeline. Verificar logs do servidor SMTP e políticas de entrega quando houver aceite sem recebimento.


## [0.22.1] - 2026-11-03

### Clareza das evidências gerenciais
- Cada ocorrência individual do relatório gerencial passa a indicar a natureza do achado e uma conclusão limitada ao que a evidência permite afirmar.
- Resíduos compatíveis com o incidente, referências históricas, manutenção de componentes e procedência/versão não confirmadas são diferenciados; atualizações pendentes não são tratadas como prova de malware.
- Incluídos na apresentação gerencial componentes com estado genérico de revisão de versão/procedência, preservando os estados estruturados utilizados no JSON.
- Novos testes de regressão verificam a distinção e asseguram que metadados informativos do cron não gerem alertas individuais.
- Não foram alterados mecanismos de recuperação, assinaturas de malware nem códigos de retorno.

### Limitações
- A natureza indicada é uma categorização do achado, não um certificado de segurança nem autorização de reativação.


## [0.22.0] - 2026-11-03

### Segurança operacional e homologação
- Leitura do relatório gerencial por descritor de arquivo com rejeição de links simbólicos e limite de 8 MiB para exportação PDF, reduzindo riscos de leitura não controlada.
- Leitura limitada a 20 MiB para o PDF anexado ao e-mail SMTP, 64 KiB para a configuração e 4 KiB para a senha SMTP, com verificação de arquivo regular e rejeição de symlinks. O arquivo de senha exige caminho absoluto, e arquivos privados têm permissões revalidadas no descritor aberto.
- Divergência de versão local superior à versão oficial não é mais marcada como correspondência: estado de consulta `OFFICIAL_VERSION_DIFFERENT_UNVERIFIED` exige revisão de procedência, sem afirmar comprometimento.
- Novos testes de regressão para arquivos acima do limite, links simbólicos, senha relativa e versões oficiais divergentes.
- Pipeline com job dedicado de validação PDF: ReportLab e PyMuPDF no Python 3.12, incluindo testes de paginação e acentuação quando disponíveis.

### Limitações
- Os modos de recuperação permanecem experimentais e não são homologados para produção.
- Ainda são necessários testes operacionais em Debian/Ubuntu reais, teste SMTP ponta a ponta em servidor controlado e avaliação de concorrência, permissões e cadeia de custódia sob condições adversas.


## [0.21.12] - 2026-11-03

### Correção do inventário de componentes
- O parser de cabeçalhos agora lê somente o bloco de metadados do plugin ou tema, evitando que anotações PHP posteriores substituam a versão declarada (caso real do Popup Maker).
- A leitura é limitada aos primeiros 8 KiB e não executa PHP. Versões inválidas ou ausentes recebem diagnóstico explícito `header_status` no JSON e no CSV.
- A consulta oficial identifica separadamente o componente encontrado cuja versão local não pôde ser validada (`OFFICIAL_COMPONENT_FOUND_VERSION_UNVERIFIED`), sem declarar correspondência de versões.
- Os relatórios de componentes e sua seção gerencial foram traduzidos para português; os identificadores JSON continuam estáveis.
- A evidência informativa de cron permanece nos dados técnicos, mas deixa de aparecer como suspeita individual no relatório gerencial quando não há indicadores.
- O relatório gerencial indica versões instalada e oficial e esclarece que o hash informado se refere apenas ao arquivo principal.
- Corrigido o fechamento do arquivo CSV em teste unitário e adicionadas quatro verificações de regressão.

### Validação pendente
- Confirmar aprovação do GitHub Actions e repetir a auditoria de leitura no ambiente Linux; não homologar recuperação em produção.

## [0.21.11] - 2026-11-03

### Correção de testes de integração
- Alinhadas 14 asserções dos testes MySQL aos rótulos existentes em português brasileiro, preservando verificações de dados estruturados, SHA-256 e classificações técnicas.
- Nenhuma regra de detecção, recuperação, exportação PDF, envio SMTP ou código de retorno foi alterado.
- Versão da ferramenta atualizada para `0.21.11`.

### Homologação
- A correção exige confirmação de todos os jobs do GitHub Actions, especialmente o de integração MySQL, antes de liberar a próxima fase.

## [0.21.10] - 2026-10-31

### Registro de incidente
- Traduzido o modelo `incident-containment-record.md` gerado para o operador, preservando a ressalva de que a auditoria não comprova a suspensão do serviço.
- Adaptado o teste de regressão da documentação de contenção para o português.

### Pendências de homologação
- Reexecutar testes no Linux e validar cenários MySQL/PDF. Não classificar como versão estável sem as validações.


## [0.21.9] - 2026-10-31

### Validação de documentos PDF
- Reforçado o teste multipágina: com PyMuPDF disponível, verificar a quantidade de páginas e a extração dos caracteres acentuados (`proteção`, `execução`, `conclusão`).
- Verificação isolada de ReportLab + DejaVu Sans + extração via PyMuPDF concluída; a suíte completa do repositório e os cenários reais permanecem pendentes.
- Não alteradas as regras de auditoria, o relatório estruturado JSON ou os códigos de retorno.


## [0.21.8] - 2026-10-31

### PDF e testes
- O gerador PDF prioriza DejaVu Sans ou Liberation Sans em Debian/Ubuntu, preservando uma alternativa quando as fontes não estão instaladas.
- Novo teste opcional com acentuação e múltiplas páginas, sem incluir evidências técnicas privadas.
- A inspeção visual com arquivo real e os testes em Linux ainda são necessários; não classificar esta versão como estável.


## [0.21.7] - 2026-10-31

### Testes
- Corrigidas três expectativas antigas da suíte de testes para validar os textos em português: divergências do núcleo, prioridade alta e verificação executada.
- Mantidas as verificações estruturadas existentes em `report.json` e o contrato dos códigos internos.
- Nenhuma alteração nas regras de detecção, classificação ou nos códigos de saída.

### Validação pendente
- Reexecutar a suíte de testes no Debian/Ubuntu; integração MySQL e geração real de PDF dependem dos ambientes opcionais.


## [0.21.6] - 2026-10-31

### Correções
- Corrigida a classificação de prioridade de arquivos de configuração no relatório para o cliente (comparação com o rótulo português `Configuração`).
- Traduzidos trechos restantes do parecer técnico relativos às sessões e referências históricas.
- Adicionados dois testes de regressão para proteger a apresentação em português e manter os códigos estruturados de persistência estáveis.

### Validação pendente
- Executar a suíte de testes no ambiente Linux e conferir o PDF gerado com casos reais, inclusive acentuação, quebras de linha e paginação.


## [0.21.5] - 2026-10-31

### Correções de internacionalização
- Restaurado o contrato de valores de `persistence_risk` no JSON; a tradução é aplicada apenas na apresentação do relatório.
- Traduzidas descrições e prioridades dos achados individuais e justificativas de indisponibilidade.
- Corrigidas asserções de teste ainda dependentes de textos antigos em inglês.
- Mantidas as classificações técnicas e os valores estruturados; testes de regressão aguardam nova execução no Linux.


## [0.21.4] - 2026-10-31

### Correções
- Corrigidas quatro asserções da suíte de testes que ainda esperavam títulos antigos em inglês após a tradução.
- Corrigidos rótulos mistos em português/inglês no relatório gerencial e no relatório técnico.
- Traduzidos valores de apresentação para risco e realização de verificações, sem modificar códigos internos e campos estruturados.
- Mantidos os testes de regressão como critério para validar a mudança no ambiente Debian/Ubuntu; execução remota ainda pendente.


## [0.21.3] - 2026-10-31

### Relatórios em português
- Tradução de 91 fragmentos de interface do gerador de relatórios: cabeçalhos, rótulos, legendas e orientações ao cliente e à equipe técnica.
- Preservação dos códigos de classificação, chaves estruturadas, nomes de evidências e estados internos para evitar quebra de integrações.
- A tradução ainda não é integral; continuam pendentes mensagens dinâmicas, revisão completa da documentação histórica, testes automatizados e inspeção visual de PDFs com acentuação.


## [0.21.2] - 2026-10-31

### Internacionalização (pt-BR)
- Tradução do assunto e do corpo dos e-mails enviados ao cliente.
- Tradução do título, da paginação e das mensagens de falha da exportação PDF.
- Tradução das mensagens de validação e falha de entrega SMTP.
- Tradução das opções de ajuda mais utilizadas e das principais mensagens de conclusão da auditoria.
- Tradução da política de segurança e dos comentários do arquivo de exemplo SMTP.
- Inclusão de instruções operacionais em português no início do README.
- Preservação de parâmetros de linha de comando, chaves SMTP e identificadores internos para evitar incompatibilidades.

### Pendente
- Revisão integral das demais mensagens do programa, conteúdo de relatórios e documentação histórica ainda em inglês, com testes de regressão e validação visual do PDF.


## [0.21.1] - 2026-10-31

### Changed
- Document the existing default evidence directory `/var/lib/wp-integrity-audit/cases` and retain optional `--case-root` overrides.
- Resolve SMTP configuration from `/etc/wp-integrity-audit/config.cfg` when `--email-to` is supplied, without requiring an additional configuration argument.
- Add `--config` as the preferred override and retain `--smtp-config` as a backward-compatible alias.
- Keep SMTP delivery strictly opt-in and preserve existing private-file permissions and verified TLS requirements.


### Audit report improvements
- Correct historical-cache excerpt handling after failed MySQL CI regression.
- Show interpreted values for two strictly allowlisted numeric transient options.
- Replace the aggregated database finding count with category-specific counts.
- Record the tool's SHA-256 in the report, explain dynamic WordPress cron behavior and add a classification legend.
- Extend MySQL integration tests for the report formatting and classification.
- Record a separate informational cron fingerprint with SHA-256, size, UTC capture time and known marker count, even when no IOC matches.
- Add an explicit `LIBERAÇÃO NÃO RECOMENDADA` release-gate warning to audit reports and a regression assertion.


## [0.2.0] - 2026-10-30 (pre-release)

### Changed
- Combined default audit now includes database checks. Use `--files-only` to omit them explicitly.
- Report coverage and technical conclusions distinguish historical references, active markers and unaudited areas.
- Context-aware classification for recognized plugin guards, retaining relative paths.
- Add regression coverage proving default audit fails closed without database configuration, rather than emitting misleading zero findings.



### Added
- Synthetic MySQL integration test that restores a generated SQL backup into a second isolated database and verifies WordPress fixture records.

### Fixed
- Remove temporary staged WordPress files if SQL preflight or operator confirmation fails, before any site modification.
- Add regression coverage for swap failure rollback and evidence-file permissions.
- Read archived file bodies to detect truncated or corrupted tar backups instead of checking headers alone.
- Scan complete staged content with the same full-file and filename IOC checks used for clean sources, including files downloaded during official component synchronization.
- Prevent automatic filesystem rollback after a database write has started, because a client error does not prove the transaction was rolled back.
- Add a regression test for malware markers after the first 256 KiB of staged PHP content.

## [0.1.0] - 2026-10-30 (Python branch; pre-release)

### Added
- Python 3.10+ implementation of CLI modes: `--audit`, `--audit-db`, `--audit-db-post`, `--apply-files`, `--apply-db`, and `--recover`.
- Incident IOC search, process inventory, metadata-only client reporting, SQL checks, snapshot/quarantine, core copy, official WordPress.org component downloads, salt rotation, Elementor inventory and component comparisons.
- Restrictive case-file permissions, protected temporary MySQL credentials, independent `--case-root`, unit tests, synthetic MySQL integration tests and CI checks.

### Changed
- Database audit no longer performs full backups; these are restricted to mutating operations.
- Potentially destructive removal of entire serialized `active_plugins`/`cron` options is replaced by fail-closed manual remediation.
- Unsafe inferred recursive uploads ownership changes are replaced by metadata-only auditing.
- Clean source symlinks and special files are rejected before copying.
- Quarantine and failed stage directories are moved outside the document root.
- Post-recovery file/process/database IOC scanning blocks a clean completion status when indicators remain.
- Password and salt rewriting refuses symlinked WordPress configuration and restricts file permissions.
- Tests cover synthetic database backups, full-file scanning, symlink handling and salt rotation.
- Forensic case roots inside a WordPress document root are rejected.
- WordPress.org package downloads now enforce the trusted HTTPS host after redirects.
- Recovery preflight validates literal WordPress salts and core-source paths before starting mutations.
- File scans read full PHP-like file content in bounded chunks, rather than checking only the first portion.

### Known limitations
- No production WordPress/MySQL integration validation or restore rehearsal completed.
- File and DB operations cannot form one atomic transaction; an operator-controlled restore remains necessary.
- The signature corpus is incident-specific; clean results do not certify a clean WordPress installation.
- Legacy Bash is retained in Git history on `main`; this branch has only the Python runtime.

## [Legacy baseline] - 2026-10-30

- Initial Bash implementation, original version `2026.10.28.18`.

### Audit coverage and classification
- Run targeted database inspection by default with `--audit`; add explicit `--files-only` for filesystem-only inspection.
- Distinguish skipped database analysis from zero findings and fail if mandatory database checks cannot execute.
- Inspect family-specific options, historical plugin-update cache, cron, active plugins, stored sessions, application passwords and suspicious administrator names.
- Recognize specific Sucuri, WPForms and Simple History guard patterns and quarantine Wordfence configuration snippets from the report.
- Preserve relative file paths, including long names, and generate an evidence-based technical opinion.
- Add fixture regressions for two family residues, historical references, cron, plugins and session counts.

- Count only positive database records in the report summary, retaining explicit `NOT_FOUND` and `ABSENT` checks in JSON; protect sensitive path fragments without destroying long filename context.

### Database evidence enrichment
- Preserve exact WordPress option names (including the SimplePluginLogger historic update cache) without entropy redaction.
- Include database name and physical options/usermeta table names in the client report.
- Distinguish `RESIDUO_FAMILIA_REQUER_LIMPEZA` from historical and informational evidence.
- Gather full-value SHA-256, byte length and bounded encoding metadata for candidate option records.
- Limit exported snippets to known IOC tokens; deliberately withhold arbitrary encoded/decoded content to avoid leaking credentials.
- Report separate counts for family residues, historical references and stored session records.
- Add database integration regression tests for naming, classification, checksums and report contents.

### Report clarity and safe scalar evidence
- Classify two allowlisted numeric `sc_*` transient keys as `ESCALAR_TEXTO_NUMERO_NAO_CODIFICADO` and show their safe scalar value only after strict length and digit validation.
- Keep arbitrary family options and credential-like values masked; include a regression fixture with a fake private token.
- Render SQL evidence details as individual Markdown sections after the completed summary table instead of breaking table layout.

- Remove duplicated database audit status from the client report and explicitly state whether SQL dump and file snapshot evidence were generated.

### Standardized operational results
- Add final result statuses, return codes, an executive Markdown summary, and a privacy-conscious `report.json`.
- Separate family, historical, informational, file-classification and process counters.
- Reserve `COMPROMETIMENTO_CONFIRMADO` / exit 20 for independently confirmed evidence; heuristic markers alone are incomplete investigations.
- Return 10 for family residues and 40 when the user intentionally omits database checks.
- Introduce regression coverage for the status contract, JSON summary and read-only CLI return codes.

### Case evidence indexing
- Repair previous CI failures caused by a missing explicit `NOT EVALUATED` label and incomplete synthetic evidence records.
- Generate deterministic per-case FILE/DB evidence identifiers and a separate JSON index with SQL table and column provenance.
- Generate a single-row CSV audit summary for fleet consolidation; add unit regression checks.

### Case comparison
- Add read-only `--compare OLD_CASE NEW_CASE` with optional `--compare-output`.
- Write private Markdown and JSON comparison reports identifying new, removed and changed file/database evidence.
- Reject comparisons with incomplete database audits or mismatched database names; add synthetic regression tests.

- Prevent comparison output directories from being created inside either source case; add regression test.

### Configuration evidence inventory
- Audit WordPress-tree `.htaccess`, `.user.ini`, `php.ini`, `web.config` and related files without executing or revealing their contents.
- Write `configuration-evidence.json` with relative paths, byte sizes, permissions and hashes.
- Add regression test to prevent config-content credential exposure.

- Add heuristic review classification for PHP scripts in hidden WordPress directories, excluding `.well-known`; include a synthetic unit test.

### Optional integrity and persistence probes
- Add `--check-core` to compare selected installed WordPress Core files to the official checksum API; results written to `core-integrity.json`.
- Add opt-in `--host-persistence` metadata inventory of selected Linux cron, systemd, PHP and Apache configuration directories.
- Treat unavailable checksum data, missing core files, and non-English locale differences as review items, never as evidence of confirmed compromise.
- Restrict optional probes to read-only audit mode; add synthetic manifest and host-root validation tests.

### Optional probe status integrity
- Include incomplete/mismatching WordPress Core checksum results in `report.json` and the executive summary.
- Assign exit `40` for otherwise clean cases with unresolved Core discrepancies, without overriding confirmed family residues (exit `10`).
- Add regression tests for both status precedences.

## [0.3.0] - 2026-10-30

### Changed
- Run all implemented passive audit probes by default: WordPress files, configuration metadata, official Core checksum verification, host persistence metadata, Elementor, process indicators and database checks.
- Replace opt-in `--check-core` / `--host-persistence` CLI with opt-out `--skip-core` / `--skip-host-persistence`; add `--skip-files`, `--skip-config`, `--skip-processes`, `--skip-elementor`, and `--skip-db` (alias `--files-only`).
- Preserve explicitly selected recovery workflows and interactive approval; no mutation in the normal audit path.
- Track omitted scopes in reports and return exit 40 for otherwise clean but incomplete audits.
- Add CLI-default and omitted-coverage regression tests.

### Evidence-driven report reconciliation
- Add detailed Core discrepancy and WordPress configuration inventory sections to Markdown, including priority review for wp-includes/version.php.
- Expose Core, configuration and host-persistence counts in JSON and executive summary.
- Separate domain and case_id in CSV and JSON.
- Classify ordinary host configuration files as INVENTARIADO_SEM_INDICADOR rather than indiscriminately labeling them suspicious; flag only recognized IOC patterns for investigation.
- Keep detailed host paths in internal JSON and omit infrastructure names from the Markdown host summary; add regression coverage.

### Management reporting and host IOC triage
- Split management `report.md` from detailed internal `technical-report.md`.
- Summarize Core differences and configuration review counts in both outputs; preserve detailed evidence only in the technical report.
- Keep product-specific host inventory paths in internal `host-persistence.json`; avoid generic suspicion labels for ordinary host files.
- Highlight explicit host indicators in optional probe review without overriding confirmed database residue status.
- Extend report and CSV tests for per-domain case identifiers and sanitized management summaries.

- Align the pre-existing technical-report security-configuration counter with the actual configuration inventory total.

- Add regression assertions that management reporting excludes internal host and WordPress Core file paths.

### Evidence consistency and triage
- Reconcile the management and JSON security-configuration counters, avoiding a zero result when configuration findings exist.
- Record explicit persistence risk level with a caution that no known IOC does not prove absence of host persistence.
- Distinguish recognized BitNinja security-product inventory, unclassified host configuration and explicit indicators.
- Detect security-relevant configuration directive categories without disclosing values, URLs or credentials.
- Extend the evidence index with CORE-, CONFIG-, HOST- and PROC- identifiers, and expand regression tests.

- Fix literal backslash escaping in directive patterns to ensure real Apache/PHP configuration directives are detected.

- Add an additive `status_detail` field for simultaneous family residues and Core discrepancies, preserving stable primary status and exit code.

### MetForm false-positive triage
- Recognize exact WordPress `Silence is golden.` directory guards in uploads.
- Add restricted `CACHE_PLUGIN_REQUER_VALIDACAO` classification for a MetForm Font Awesome cache candidate when its path and PHP return-array header match.
- Keep potential cache findings in required-review counts and return-code precedence; no blanket uploads exemption.
- Add synthetic guard, cache and unrelated PHP regression cases.

### Akismet and SQL risk improvements
- Fix newline escapes in the exact-upload-guard fixture that caused the prior multi-Python unit-test failure.
- Recognize narrowly constrained Akismet deny-by-default .htaccess asset access rules, with rejection tests for broad PHP grants.
- Eliminate duplicate security-configuration counts between JSON and Markdown.
- Show scoped low database risk when completed targeted checks find no selected database IOC; WordPress session rows remain informational.
- Keep MetForm icon caches under review until their full contents and trusted generator are verified.

- Match the observed guarded MetForm cache header with a generator comment and `ABSPATH` guard, preserving manual-review status.
- Support nested `IfModule` blocks in strict Akismet `.htaccess` access-rule recognition.
- Add synthetic regression tests for guarded headers, nested blocks and unsafe grants.

- Strengthen MetForm regression coverage: a plausible generated-cache header containing a known IOC later in the file must retain IOC classification, never legitimate-cache status.

- Align the previous MetForm synthetic cache fixture with the supported guarded-header grammar.

## [0.4.0] - 2026-10-30

### Fixed
- Prevent absent database placeholders and informational session/application-password rows from falsely blocking post-recovery verification.
- Block post-recovery success when files contain `IOC_REQUER_VALIDACAO`, fixing an inconsistent string constant.
- Parse Akismet Apache module names containing dots, including `mod_authz_core.c`.
- Add clean and contaminated post-recovery blocker regression tests.

### Safety
- Recovery remains experimental and requires disposable-environment acceptance tests for file ownership, upload carry-over and exact-version official synchronization before production use.

## [0.5.0] - 2026-10-30

### Security
- Disable `--apply-files`, `--apply-db` and `--recover` until ownership, uploads preservation, exact package versions and rollback are verified end-to-end in disposable fixtures.
- Extend read-only file inspection to `.php5`, `.php7`, `.php8`, `.pht` and `.phps` and add generic obfuscated/dynamic webshell heuristics. These remain review heuristics, not proof of compromise.
- Add synthetic test of generic PHP5 detection and unchanged incomplete-audit exit-code semantics.

## [0.6.0] - 2026-10-30

### Added
- Inventory WordPress mu-plugins and selected top-level drop-ins without executing code (`wordpress-persistence.json`).
- Record a 30-day filesystem metadata timeline (`timeline.json`), showing mtime and ctime without treating ctime as creation time.
- Add isolated regression tests for these inventories.

### Fixed
- Update the existing generic webshell test to expect the correct review classification for `eval($_GET[...])`.

### Limitations
- Timeline and persistence inventory are contextual evidence; their mere presence does not prove malicious activity. Recovery modes remain disabled pending safety homologation.

## [0.7.0] - 2026-10-30

### Added
- Passive Core, plugin and theme header/version inventory by default, with explicit `--skip-version-check`, `--offline` and `--official-compare` flags.
- WordPress.org HTTPS API queries with timeouts, bounded responses and separate API unavailable/not-found statuses.
- Core checksum comparison, missing/modified official paths and extra PHP in core directories and root; no PHP execution or package download.
- Plugin and theme main-file hashes, child theme template information and local metadata.
- Component JSON, Markdown and CSV evidence with stable CORE/PLUGIN/THEME identifiers and separate coverage reporting.
- Synthetic tests for offline isolation, child themes, API unavailability and changed Core hashes.

### Known limitations
- Plugin active state and active theme are not yet linked to read-only database options.
- Official plugin/theme full-tree checksums and provenance validation of premium components are not yet implemented.
- Component version results are additional evidence; complete release semantics and report integration require CI and real WordPress fixture validation.

### Continued in 0.7.0
- Correlate plugin activation and active parent/child theme with read-only `active_plugins`, `template` and `stylesheet` options (without PHP evaluation or unserialization).
- Verify WordPress.org plugin manifest MD5 checksums at the installed plugin version, without downloading plugin code; classify changed files as requiring review.
- Propagate critical Core/plugin integrity differences into incomplete-review exit semantics.
- Expand component report columns to include parent themes, query outcomes and provenance.

- Compare the locally validated Core version with the advertised latest WordPress.org version, preserving checksum mismatch as the higher-priority state.
- Add regression coverage for outdated Core and checksum-review precedence.

- Distinguish an officially listed plugin whose checksum manifest is missing from a genuinely modified plugin (`PLUGIN_OFICIAL_SEM_CHECKSUM`).
- Display premium/custom plugin and theme totals in the management report.
- Add regression tests for current and outdated WordPress.org plugin versions and unavailable plugin checksum manifests.

- Standardize generated component-management report headings and labels in English.

## [0.8.0] - 2026-10-30

### Security and reliability
- Stream SHA-256 and MD5 checksum validation in fixed-size chunks instead of reading whole WordPress component files into memory.
- Explicitly reject symlink targets in file digest helpers.
- Add large synthetic file and symlink regression tests.
- Maintain read-only audit behavior and disabled destructive modes pending recovery safety validation.

## [0.9.0] - 2026-10-30

### Added
- Detect additional executable PHP files absent from a successfully retrieved official WordPress.org plugin checksum manifest.
- Preserve conservative `PLUGIN_COM_ARQUIVOS_MODIFICADOS` review classification rather than asserting malware.
- Regression-test an official manifest with an unexpected executable file.

### Limitations
- The new extra-file detection applies only where a trustworthy official plugin manifest is available. Theme file provenance and complete disposable-site acceptance remain outstanding.

## [0.10.0] - 2026-10-30

### Security and correctness
- Reject unusable WordPress Core checksum manifests with no valid file entries rather than incorrectly declaring a checksum match.
- Require at least one usable plugin checksum entry before declaring plugin checksum validation successful.
- Record the number of checksum entries actually evaluated.
- Add a regression test for a traversal-only Core manifest.

## [0.11.0] - 2026-10-30

### Fixed
- Differentiate HTTP 404 for official plugin/theme metadata (component not found) from HTTP 5xx/transport errors (API unavailable).
- A Core checksum HTTP 404 remains unavailable, not a plugin/theme absence result.
- Add mocked HTTP failure regression cases without external requests.

## [0.12.0] - 2026-10-30

### Fixed
- Use the actual component checksum coverage in the technical report instead of reporting the retired separate Core probe as `NOT EXECUTED`.
- Expose independent `core_outdated` count, preserving plugin/theme outdated counts.
- Flag officially unlisted plugins as origin-unconfirmed review, and plugins without a parseable local version as version-unidentified.
- Add synthetic regression coverage for an installed Core release with verified checksums and a newer upstream release.

### Security
- The generated MetForm icon-cache header and the Akismet plugin path are not by themselves cryptographic proof of safe content. Continue requiring strict review before marking large PHP caches legitimate.

### Reviewed false-positive evidence (0.13.0)
- Recognize one previously inspected MetForm Font Awesome cache only when its exact file path and full SHA-256 digest match the case-specific reviewed artifact; no blanket trust of generated caches.
- Support Akismet legacy `Order Deny,Allow` alongside modern authorization modules and tightly scoped static assets.
- Continue treating changed MetForm caches as requiring review, and reject unscoped Akismet grants.

- Add a management counter for plugins requiring provenance/version review, separate from confirmed malware and outdated-version counts.
- Extend regression coverage for an exact reviewed cache SHA-256 matching versus a modified digest.

## [0.14.0] - 2026-10-30

### Added
- Show `report.md` automatically on an interactive standard-output terminal after audit completion.
- Add `--show-report` and `--no-show-report`; explicit suppression has priority and redirected output never prints the report body.
- Print the management report path without exposing the internal technical report.

### Fixed
- Set `REVISAO_NECESSARIA` with exit code 40 when Core updates, component provenance/version reviews, or configuration reviews remain outstanding, without claiming malware.
- Use component Core verification coverage in the technical report, avoiding the retired legacy probe's `NOT EXECUTED` label.
- Align management release recommendation with actual exit status.

### Tests
- Cover TTY/non-TTY behavior, explicit suppression and unresolved-component exit semantics.

- Fix overly broad Akismet static-asset extension screening: `refresh` filenames were incorrectly rejected because they contain the suffix `sh`. Only executable file extensions are disallowed.

- Include explicit non-malware provenance-review guidance for plugins missing from WordPress.org and missing-version guidance for locally unreadable plugin headers in component Markdown and CSV evidence.

## [0.15.0] - 2026-10-30

### Added
- Itemized, customer-facing management-report evidence with individual case IDs, findings, classifications, human-readable meaning and SHA-256 references.
- Separate documented technical observations from an independently authorized containment decision and avoid claiming incident attribution or exact outage cause.
- Redact raw database payloads, credentials and internal command details from the client-facing section.
- Regression test for evidence IDs and prevention of raw SQL value disclosure.

### Limitations
- Reports show what current read-only probes observed; they cannot independently prove who initiated an outage or that malware executed.

## [0.16.0] - 2026-10-30

### Added
- SHA-256 forensic case manifest for each regular evidence file captured in the private case directory, with individual sizes and explicit provenance limitations.
- Separate, deliberately unfilled incident-containment record template documenting the information the incident owner must supply to justify taking a website offline.
- Symlink-safe manifest traversal and tests proving the template cannot invent an outage or its decision maker.

### Security
- Read-only WordPress inspection remains the default; mutating modes stay disabled.
- The manifest records hashes of evidence files at the time it is generated and does not, on its own, establish an authenticated chain of custody.

## [0.17.0] - 2026-10-30

### Added
- Optional `--pdf-report` export of the customer-facing `report.md` to `management-report.pdf` in the private case directory.
- Page-numbered local PDF rendering with escaped report content and private file permissions.
- PDF export depends on optional `reportlab`; no network calls or automatic installation are performed.
- Regression test that missing optional dependencies produce a controlled failure without touching technical-report content.

### Limitations
- PDF rendering requires separate document-visual QA for long, real incident reports; the Markdown remains the authoritative editable management report.

## [0.18.0] - 2026-10-30

### Added
- Read-only administrator role-candidate inventory using role metadata from WordPress users/usermeta, pseudonymized SHA-256 login names and registration metadata.
- Explicit `UNAVAILABLE` account-coverage state rather than false zero counts when the database query fails.
- Regression tests for account pseudonymization and unavailable coverage.

### Limitations
- The role test is a serialized-value substring heuristic and does not validate authorization, prove compromise or cover multisite super administrators. The results are kept in restricted JSON evidence, not the customer-facing report.

## [0.19.0] - 2026-10-30

### Added
- `--verify-case CASE`: read-only SHA-256 verification of evidence listed in `evidence-manifest.json`, identifying missing, modified and post-capture unlisted files.
- `--bundle-evidence`: explicitly package private case evidence into `evidence-bundle.tar.gz` with an accompanying SHA-256 sidecar. The bundle contains sensitive technical material and must not be sent directly to a customer.
- Regression tests for manifest tampering, bundle permissions, credential-file exclusion and status precedence.

### Fixed
- Preserve confirmed-residue status (exit 10) when Core or component integrity reviews coexist; record concurrent integrity concerns without suppressing the primary incident finding.

### Limitations
- The bundle and manifest are unsigned; independent immutable storage and approved custody logs are necessary for legal-grade chain of custody.

- Extend existing case-to-case comparisons with Core/plugin/theme version, source-state and main-file hash changes when both cases contain component evidence.
- Include a calibrated review-priority label for each customer-facing finding; such labels do not assert active compromise.
- Add regression tests for historical plugin-version changes and review-priority wording.

- Create restricted evidence bundles via a temporary private file and atomic rename, rejecting credentials before creating any archive.

- Expand passive Debian/Ubuntu persistence inventory to include `/etc/profile.d`, `/etc/rc.local`, `/etc/ld.so.preload`, `/etc/sudoers.d` and `/var/spool/cron`.
- Eliminate automatic trusted-security-component classification based only on a `bitninja` substring in a filesystem path.

- Add a conditional real PDF smoke test that verifies PDF magic bytes and owner-only permissions when the optional ReportLab dependency is present.

## [0.20.0] - 2026-10-31

### Reliability
- Generate customer management PDFs in a private temporary file and atomically publish only after successful rendering and PDF header validation.
- Return the documented execution error code 30 for controlled PDF export errors rather than an uncaught traceback.
- Use a bounded five-byte signature read and remove partial temporary files on rendering failures.
- Add a regression test for missing management source and absence of partial PDFs.

### Operational limits
- PDF export remains optional and must be visually checked with real long incident reports before customer delivery.

## [0.21.0] - 2026-10-31

### Added
- Explicit `--email-to` and `--smtp-config` CLI switches to send only the customer management PDF after a read-only audit.
- External INI SMTP configuration with validated TLS (`starttls` or `ssl`) and a separate owner-only password file; credential values never belong in the repository.
- Non-secret sample `config/smtp.example.cfg`.
- Sender and recipient validation, safe email attachments, fail-closed TLS and controlled mail-delivery error handling.
- Regression tests for permissive SMTP file permissions and email header injection.

### Security
- Sending is always opt-in. SMTP errors return 30 and do not convert unresolved audit findings into success. An accepted SMTP submission does not guarantee mailbox delivery.

- Reject mail delivery options when running historical case comparison; email can only be triggered during an explicit audit.
## [0.24.2] - 2026-11-03

### Added
- Contextual validation for deny-only `.htaccess` protections used by uploads and common security/backup plugins; rules with handlers, rewrites or grants remain review findings.
- Complete hash-bound manifests for incident-associated plugin directories and reversible directory quarantine helper.
- `bin/remediar_usuario_wp.py` for exact-ID WordPress administrator removal, refusing accounts with authored posts or comments and preserving pseudonymous evidence.
- Explicit incident-family classification for `kinetic-relay-live` in component provenance reports.

### Safety
- Directory quarantine requires every regular file to match an existing private evidence manifest, rejects symlinks and is reversible by rename.
- User remediation never evaluates PHP, never accepts credentials on the command line and records only a login hash.

## [0.24.3] - 2026-11-03

### Fixed
- Preserve the explicit incident-family quarantine classification for `kinetic-relay-live` even when the official repository API returns not-found or incomplete metadata.
- Recognize narrowly scoped deny-only protection files under `wp-content/updraft` and WP Rocket cache paths without treating them as compromise indicators.

## [0.24.4] - 2026-11-03

### Fixed
- Recognize the standard Wordfence deny-only rewrite/fallback template as a legitimate security guard, while retaining review for handlers, grants and auto-prepend directives.

## [0.24.5] - 2026-11-03

### Security
- Detect the observed `Axiom Sentinel Snap`/`SCV:*` obfuscated component signature even when the malicious copy is renamed to a generic PHP filename such as `core_*.php`.

## [0.25.0] - 2026-11-03

### Security
- Add bounded, non-executing multi-signal PHP obfuscation detection.
- Classify files with at least three independent obfuscation indicators as `PHP_OFUSCACAO_REQUER_QUARENTENA`.
- Preserve the original file and hash in private evidence; no automatic deletion or quarantine is performed by audit mode.

## [0.25.1] - 2026-11-03

### Security
- Detect high-confidence WP Rocket license-bypass signatures, including deletion of license state and forged `valid_key.php` responses.
- Mark such files for reversible quarantine; audit mode remains non-mutating.

## [0.25.2] - 2026-11-03

### Fixed
- Permit the reversible quarantine helper to act on the new explicit PHP-obfuscation and premium-license-bypass classifications, still requiring exact evidence and hash equality.

## [0.37.0] - 2026-11-04

### Adicionado
- Auditoria estrutural, somente leitura e limitada a raízes explicitamente autorizadas, para exposição lateral entre instalações WordPress.
- Inventário de proprietários UID/GID, diretórios sensíveis, proteção de PHP em `uploads`, processos associados por caminho e pools PHP-FPM quando a associação estiver comprovada no texto da configuração.
- Evidência privada `sc403-lateral-exposure.json`, com separação entre risco estrutural, possibilidade de propagação e comprometimento confirmado.
- Opção repetível `--sc-authorized-root` para solicitar a análise de uma ou mais raízes autorizadas.
- Testes de compartilhamento de UID e diretórios graváveis sem transformar esses sinais em prova de infecção.

### Segurança
- A auditoria lateral recusa raízes simbólicas, raízes amplas demais e limites de varredura excedidos.
- Não há testes de escrita, execução de PHP, alteração de permissões, reinício de serviços ou varredura irrestrita de `/usr/local/www/data`.

