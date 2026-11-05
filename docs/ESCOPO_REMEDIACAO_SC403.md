# Escopo de remediação SC403

O arquivo `sc403-remediation-scope.json` é uma autorização granular de recursos, não uma ordem global. Cada processo, SHMID, registro SQL, arquivo, entrada cron, unidade systemd e serviço/pool PHP precisa de identidade própria e operação explícita.

Esta versão implementa somente geração, validação, grafo e simulação. Não executa `kill`, `ipcrm`, SQL, cron, systemd, Apache ou PHP-FPM.

## Fluxo

1. Gerar proposta a partir de um caso: `python3 bin/sc403_escopo.py gerar CASO`.
2. Revisar e preencher identidade, evidências, responsáveis, validade e recursos individuais.
3. Validar: `python3 bin/sc403_escopo.py validar sc403-remediation-scope.json`.
4. Gerar grafo de dependências: `python3 bin/sc403_escopo.py grafo sc403-remediation-scope.json`.
5. Simular contra uma coleta atual: `python3 bin/sc403_escopo.py simular MANIFESTO ESTADO`.

Manifesto expirado, adulterado, incompleto, com curinga, identidade divergente ou dependência não autorizada bloqueia a simulação.
