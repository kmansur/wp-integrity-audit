#!/usr/bin/env bash
#
# WordPress Integrity Audit — legacy incident-response implementation.
#
# SECURITY BOUNDARY:
#   --audit performs file/process inspection but creates private local reports.
#   --audit-db and --audit-db-post also archive the site and dump its database.
#   --apply-files, --apply-db and --recover MODIFY a WordPress installation.
#
# Do not use recovery modes on production until the documented destructive SQL,
# rollback, archive-extraction and secret-handling concerns have been resolved.
# Refer to docs/SECURITY_REVIEW.md before operating this tool.
#
# WH01 WordPress recovery helper. Audit-only by default; never executes PHP/WP-CLI.
set -Eeuo pipefail
umask 077
SCRIPT_VERSION='2026.10.28.18'
# Print the legacy CLI syntax. Note that the examples below contain a known
# filename typo; the actual script path is bin/wp-integrity-audit.sh.
usage(){ cat <<'EOF'
Uso:
 wp-integraty-audit.sh.sh --audit TARGET
 wp-integraty-audit.sh.sh --audit-db TARGET
 wp-integraty-audit.sh.sh --audit-db-post TARGET
 wp-integraty-audit.sh.sh --apply-files TARGET --source CLEAN_WP_CONTENT
 wp-integraty-audit.sh.sh --apply-files TARGET --source CLEAN_WP_CONTENT --replace-plugins-themes
 wp-integraty-audit.sh.sh --recover TARGET --source CLEAN_WP_CONTENT --official-sync
 wp-integraty-audit.sh.sh --apply-db TARGET
 wp-integraty-audit.sh.sh --recover TARGET --source CLEAN_WP_CONTENT --replace-plugins-themes
 wp-integraty-audit.sh.sh --recover TARGET --source CLEAN_WP_CONTENT --core-source CLEAN_WORDPRESS
 wp-integraty-audit.sh.sh --audit TARGET --domain-label DOMINIO
 wp-integraty-audit.sh.sh --audit-db TARGET --db-host HOST_OR_IP
 wp-integraty-audit.sh.sh --version
EOF
}
die(){ printf 'ERRO: %s\n' "$*" >&2; exit 1; }
log(){ printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
[[ $(id -u) -eq 0 ]] || die 'execute como root'
for c in sha256sum tar find python3 mysqldump mysql; do command -v "$c" >/dev/null || die "$c ausente"; done
command -v flock >/dev/null || die 'flock ausente'
# This lock is global across all target sites, preventing concurrent runs.
# The WH01-specific name and /tmp fallback are portability/security debt.
LOCK_PATH=/run/lock/wh01-wp-recover.lock
if ! ( : >> "$LOCK_PATH" ) 2>/dev/null; then LOCK_PATH=/tmp/wh01-wp-recover.lock; fi
exec 9>"$LOCK_PATH"
chmod 600 "$LOCK_PATH" 2>/dev/null || true
flock -n 9 || die 'já existe outra recuperação em execução'
MODE=--audit; TARGET=; SOURCE=; CORE_SOURCE=; DOMAIN_LABEL=; DB_HOST_OVERRIDE=; REPLACE_PLUGIN_THEMES=0; OFFICIAL_SYNC=0
while (($#)); do
  case "$1" in
    --audit|--audit-db|--audit-db-post|--apply-files|--apply-db|--recover) MODE=$1; shift;;
    --source) [[ $# -ge 2 ]] || die '--source sem valor'; SOURCE=$2; shift 2;;
    --core-source) [[ $# -ge 2 ]] || die '--core-source sem valor'; CORE_SOURCE=$2; shift 2;;
    --domain-label) [[ $# -ge 2 ]] || die '--domain-label sem valor'; DOMAIN_LABEL=$2; shift 2;;
    --db-host) [[ $# -ge 2 ]] || die '--db-host sem valor'; DB_HOST_OVERRIDE=$2; shift 2;;
    --replace-plugins-themes) REPLACE_PLUGIN_THEMES=1; shift;;
    --official-sync) OFFICIAL_SYNC=1; REPLACE_PLUGIN_THEMES=1; shift;;
    --help|-h) usage; exit 0;;
    --version) printf '%s\n' "$SCRIPT_VERSION"; exit 0;;
    *) [[ -z "$TARGET" ]] || die "argumento desconhecido: $1"; TARGET=$1; shift;;
  esac
done
[[ -n "$TARGET" ]] || { usage; exit 2; }
TARGET=$(cd "$TARGET" && pwd -P) || die 'target inválido'
if [[ ! -d "$TARGET/wp-content" || ! -d "$TARGET/wp-admin" || ! -d "$TARGET/wp-includes" || ! -f "$TARGET/wp-load.php" ]]; then
  die 'target não parece WordPress'
fi
if [[ ! -f "$TARGET/wp-config.php" ]]; then
  die 'WordPress reconhecido, mas wp-config.php ausente; restaure uma cópia confiável do wp-config.php antes da recuperação'
fi
if [[ "$MODE" == --apply-files || "$MODE" == --recover ]]; then
  [[ -n "$SOURCE" && -d "$SOURCE" ]] || die '--source deve apontar para wp-content limpo'
  SOURCE=$(cd "$SOURCE" && pwd -P)
  [[ "$SOURCE" != "$TARGET/wp-content" ]] || die 'source não pode ser o wp-content ativo'
fi
if [[ "$MODE" == --recover && -z "$CORE_SOURCE" && -d /root/wp-clean-7.1.3/wordpress ]]; then CORE_SOURCE=/root/wp-clean-7.1.3/wordpress; fi
if [[ -n "$CORE_SOURCE" ]]; then
  CORE_SOURCE=$(cd "$CORE_SOURCE" && pwd -P) || die 'core-source inválido'
  [[ -f "$CORE_SOURCE/wp-load.php" && -d "$CORE_SOURCE/wp-admin" && -d "$CORE_SOURCE/wp-includes" ]] || die 'core-source não parece WordPress'
  [[ "$(stat -c '%u:%g' "$CORE_SOURCE")" == '0:0' ]] || die 'core-source deve pertencer a root:root'
  if find "$CORE_SOURCE" -xdev -type f -perm /022 -print -quit | grep -q .; then die 'core-source possui arquivos graváveis por grupo/outros'; fi
fi
STAMP=$(date -u +%Y%m%dT%H%M%SZ); SAFE=$(basename "$TARGET" | tr -c 'A-Za-z0-9._-' '_')
[[ -n "$DOMAIN_LABEL" ]] || DOMAIN_LABEL=$(basename "$(dirname "$TARGET")")
DOMAIN_LABEL=$(printf '%s' "$DOMAIN_LABEL" | tr -c 'A-Za-z0-9._-' '_')
# The case root is hardcoded to a specific incident host. Files written here
# include sensitive reports and (for database modes) complete site/DB backups.
# Never expose this directory over HTTP or commit its contents to Git.
CASE=/root/incident-wh01-20261028/recovery-$SAFE-$STAMP; mkdir -m 700 "$CASE"
REPORT="$CASE/report.txt"; exec > >(tee -a "$REPORT") 2>&1
log "script-version=$SCRIPT_VERSION"
DOMAIN_REPORT="$CASE/RELATORIO-${DOMAIN_LABEL}.md"
MANAGEMENT_REPORT=/root/incident-wh01-20261028/RELATORIO-GERENCIAL-RECUPERACOES.csv
if [[ ! -e "$MANAGEMENT_REPORT" ]]; then printf 'timestamp_utc;dominio;target;modo;status;case\n' > "$MANAGEMENT_REPORT"; chmod 600 "$MANAGEMENT_REPORT"; fi
# Collect potential IOC file evidence and write Markdown.
# Redaction is heuristic rather than a proven de-identification boundary:
# external distribution REQUIRES manual review of the generated report.
write_client_file_evidence(){
  local out="$1" list="$CASE/client-file-list.txt"
  : > "$list"
  find "$TARGET" -xdev -type f \( -name '.sc_*' -o -name '.gr_*' -o -name '.gk_*' -o -name '.kk_*' -o -name '*cipher-feeder*' -o -name '.wp-object-cache*' -o -name 'trace-inspector-pad.php' \) -print 2>/dev/null >> "$list" || true
  grep -RIlE --binary-files=without-match --include='*.php' --include='*.phtml' --include='*.inc' "$IOC_RE" "$TARGET" 2>/dev/null >> "$list" || true
  find "$TARGET/wp-content/uploads" -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.phar' \) -print 2>/dev/null >> "$list" || true
  sort -u "$list" -o "$list"
  python3 - "$list" "$out" "$TARGET" <<'PY'
import hashlib, os, re, sys
listing, out, target = sys.argv[1:]
strong = ('SC_ADV_BEGIN','--sc-cli','--sc-succ','trace-inspector-pad','cipher-feeder','_sc_fpc','sc_cron_guard','sc_persist_manifest','sc_own_manifest','function ceya')
def redact(s):
    s=re.sub(r'(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*[^ ,;]+', r'\1=[REDACTED]', s)
    s=re.sub(r'(?i)(password|passwd|secret|token|api[_-]?key)";s:\d+:"[^"]*', r'\1";s:0:"[REDACTED]', s)
    s=re.sub(r'/usr/local/www/data/[^\s"\']+', '[CAMINHO_INTERNO_REDACTED]', s)
    s=re.sub(r'(?<![0-9])(?:\d{1,3}\.){3}\d{1,3}(?![0-9])', '[IP_REDACTED]', s)
    s=re.sub(r'(?i)\b(?:mysql|db|ftp|smtp)\.[A-Za-z0-9.-]+', '[HOST_REDACTED]', s)
    return s[:360]
rows=[]
with open(listing, encoding='utf-8', errors='replace') as fh:
    for p in fh:
        p=p.strip()
        if not p or not os.path.isfile(p): continue
        try: data=open(p,'rb').read()
        except OSError: continue
        text=data[:131072].decode('utf-8','replace')
        is_wflogs='/wp-content/wflogs/' in p.replace(os.sep,'/')
        hits=[x for x in strong if (x in text or x in os.path.basename(p)) and not (is_wflogs and x == 'trace-inspector-pad')]
        rel=os.path.relpath(p,target).replace(os.sep,'/')
        sucuri_path='/wp-content/uploads/sucuri/' in p.replace(os.sep,'/')
        simple_history_guard='/wp-content/uploads/simple-history-logs-' in p.replace(os.sep,'/') and os.path.basename(p)=='index.php'
        wpforms_guard='/wp-content/uploads/wpforms/cache/index.php' in p.replace(os.sep,'/')
        legit_reason=''
        if is_wflogs: cls='CONFIGURACAO_PLUGIN_SEGURANCA_REQUER_VALIDACAO'
        elif sucuri_path and ('exit(0)' in text or 'datastore=' in text) and not hits:
            cls='LEGITIMO_VALIDADO'; legit_reason='datastore protegido do plugin Sucuri'
        elif simple_history_guard and 'Silence is golden' in text and not hits:
            cls='LEGITIMO_VALIDADO'; legit_reason='arquivo de proteção do Simple History'
        elif wpforms_guard and '404 Not Found' in text and not hits:
            cls='LEGITIMO_VALIDADO'; legit_reason='arquivo de proteção do WPForms'
        elif hits: cls='COMPROMETIDO_CONFIRMADO'
        elif '/wp-content/uploads/' in p.replace(os.sep,'/'): cls='SUSPEITO_REQUER_REVISAO'
        else: cls='IOC_ARQUIVO_REQUER_REVISAO'
        snippet=''
        if not is_wflogs:
            for line in text.splitlines():
                if any(h in line for h in hits): snippet=redact(line.strip()); break
        elif os.path.basename(p) == 'config-synced.php':
            snippet='conteúdo de configuração sensível omitido; validar contra o plugin de segurança instalado'
        rows.append((cls,rel,len(data),hashlib.sha256(data).hexdigest(),hits,snippet,is_wflogs,legit_reason))
with open(out,'w',encoding='utf-8') as f:
    f.write('# Relatório de evidências de arquivos\n\nIOC significa *Indicator of Compromise* (indicador de comprometimento): evidência técnica que pode indicar malware ou persistência.\n\n')
    if not rows: f.write('Nenhum arquivo correspondente aos indicadores pesquisados foi encontrado nesta coleta. Isso não prova limpeza completa.\n')
    for cls,rel,size,digest,hits,snippet,is_wflogs,legit_reason in rows:
        indicators='configuração do plugin de segurança' if is_wflogs else (legit_reason if legit_reason else (', '.join(hits) if hits else 'PHP em uploads'))
        f.write(f'### {rel}\n\n- Classificação: **{cls}**\n- Tamanho: `{size}` bytes\n- SHA-256: `{digest}`\n- Indicadores: `{indicators}`\n')
        if snippet: f.write(f'- Trecho seguro (limitado e mascarado): `{snippet}`\n')
        f.write('\n')
PY
  chmod 600 "$out" "$list" 2>/dev/null || true
}
# Build management and client-facing summaries. The management CSV includes
# the original target and case paths; restrict access to the entire case root.
write_reports(){
  local status=$1
  write_client_file_evidence "$CASE/client-file-evidence.md"
  {
    echo "# Relatório gerencial de segurança — $DOMAIN_LABEL"
    echo
    echo "**Status:** $status  "
    echo "**Versão da auditoria:** $SCRIPT_VERSION  "
    echo "**Data da coleta:** $STAMP"
    echo
    echo '## Legenda de IOC'
    echo 'IOC significa Indicator of Compromise (indicador de comprometimento): evidência técnica que pode indicar malware ou persistência.'
    echo
    echo '## 1. Resumo executivo'
    echo
    echo 'Este relatório apresenta somente evidências técnicas do domínio analisado. Caminhos internos do servidor, IPs, hosts, usuários e credenciais não são incluídos.'
    echo
    echo '## 2. Evidências em arquivos'
    echo
    sed -n '1,260p' "$CASE/client-file-evidence.md"
    echo
    echo '## 3. Evidências no banco de dados'
    echo
    if [[ -f "$CASE/database-client-evidence.md" ]]; then
      cat "$CASE/database-client-evidence.md"
    else
      echo 'A auditoria detalhada do banco não foi executada nesta coleta.'
    fi
    echo
    echo '## 4. Processos e serviços'
    echo
    echo 'A análise considera apenas processos relacionados aos indicadores do incidente. Componentes legítimos de infraestrutura não são listados neste relatório do cliente.'
    echo
    echo '## 5. Limitações'
    echo
    echo 'A ausência de um indicador específico não prova limpeza total. Banco, persistência, uploads e credenciais devem ser validados antes da liberação.'
    echo
    echo '## 6. Recomendações'
    echo
    echo '1. Manter o domínio isolado até concluir a recuperação.'
    echo '2. Preservar os arquivos e evidências antes de qualquer remoção.'
    echo '3. Revisar arquivos classificados como COMPROMETIDO_CONFIRMADO ou SUSPEITO_REQUER_REVISAO.'
    echo '4. Trocar credenciais e regenerar salts após a contenção.'
    echo '5. Executar auditoria pós-recuperação antes de publicar o domínio.'
  } > "$DOMAIN_REPORT"
  printf '%s;%s;%s;%s;%s;%s\n' "$STAMP" "$DOMAIN_LABEL" "$TARGET" "$MODE" "$status" "$CASE" >> "$MANAGEMENT_REPORT"
}
if [[ -n "$CORE_SOURCE" ]]; then
  find "$CORE_SOURCE" -xdev -type f -print0 | sort -z | xargs -0 sha256sum > "$CASE/core-source.sha256"
fi
SWAPPED=0; DB_CHANGED=0; QUAR=; STAGE=; BACKUP_STATUS=NA
# Best-effort rollback, NOT an atomic recovery transaction. In particular,
# failure between moving the original wp-content and moving the stage can
# leave the original directory absent because SWAPPED is set only afterward.
rollback_files(){
  if [[ "$SWAPPED" == 1 && "$DB_CHANGED" == 0 && -n "$QUAR" && -d "$QUAR" && ! -d "$TARGET/wp-content" ]]; then
    log 'falha antes da alteração do banco; restaurando wp-content original'
    mv "$QUAR" "$TARGET/wp-content" || true
  fi
}
trap rollback_files ERR
AVAIL_KB=$(df -Pk "$TARGET" | awk 'NR==2 {print $4}')
USED_KB=$(du -sk "$TARGET" | awk '{print $1}')
[[ "$AVAIL_KB" =~ ^[0-9]+$ && "$USED_KB" =~ ^[0-9]+$ ]] || die 'não foi possível verificar espaço'
(( AVAIL_KB > USED_KB / 2 )) || die 'espaço livre insuficiente para backup/staging'
IOC_RE='SC_ADV_BEGIN|--sc-cli|--sc-succ|trace-inspector-pad|cipher-feeder|_sc_fpc|sc_cron_guard|sc_persist_manifest|sc_own_manifest|function ceya'
known_processes(){
  local line pid
  while IFS= read -r line; do
    pid=${line%% *}
    [[ "$pid" == "$$" ]] && continue
    case "$line" in
      *wp-content*|*--sc-cli*|*--sc-succ*|*.gr_*.php*|*cipher-feeder*) printf '%s\n' "$line";;
    esac
  done < <(ps -eo pid=,ppid=,user=,args=)
}
log "target=$TARGET mode=$MODE case=$CASE"
{
  echo '== IOCs =='
  find "$TARGET" -xdev -type f \( -name '.sc_*' -o -name '.gr_*' -o -name '.gk_*' -o -name '.kk_*' -o -name '*cipher-feeder*' -o -name '.wp-object-cache*' \) -print 2>/dev/null || true
  echo '== marcadores fortes em código =='
  grep -RIlE --binary-files=without-match --include='*.php' --include='*.phtml' --include='*.inc' "$IOC_RE" "$TARGET" 2>/dev/null \
    | grep -v '/wp-content/wflogs/config-synced\.php$' || true
  echo '== configurações legítimas de plugins de segurança (não IOC confirmado) =='
  [[ -f "$TARGET/wp-content/wflogs/config-synced.php" ]] && printf '%s\n' "$TARGET/wp-content/wflogs/config-synced.php" || true
  echo '== PHP em uploads (inclui arquivos de proteção legítimos) =='
  find "$TARGET/wp-content/uploads" -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.phar' \) -print 2>/dev/null || true
  echo '== processos =='
  known_processes || true
  echo '== administradores com nomes de família =='
  grep -RIlE --binary-files=without-match 'admin_[0-9a-f]{6}|administrator_[0-9a-f]{6}|backup_[0-9a-f]{6}' "$TARGET" 2>/dev/null \
    | grep -v '/wp-content/uploads/sucuri/' \
    | grep -v '/wp-content/wflogs/config-synced\.php$' || true
} | tee "$CASE/static-inventory.txt"
if [[ "$MODE" == --audit ]]; then log 'somente leitura; nada alterado'; write_reports AUDIT_OK; exit 0; fi
ask_yes(){ local a; printf '\n%s [s/N]: ' "$1"; read -r a; [[ "$a" =~ ^[sS]$ ]]; }
if [[ "$MODE" == --recover ]]; then
  ask_yes 'Confirme que o domínio está bloqueado e não há tráfego de usuários durante a recuperação.' || die 'recuperação cancelada'
  if known_processes | grep -q .; then
    die 'processo relacionado ao incidente está ativo; interrompa/isole antes da recuperação'
  fi
fi
log 'backup forense de arquivos e banco'
if tar --xattrs --acls --warning=no-file-changed -czf "$CASE/site-before.tar.gz" -C "$TARGET" . 2>"$CASE/tar-backup-warnings.txt"; then
  chmod 600 "$CASE/site-before.tar.gz"
  tar -tzf "$CASE/site-before.tar.gz" >/dev/null || die 'backup de arquivos inválido'
  BACKUP_STATUS=COMPLETO
else
  BACKUP_STATUS=INCOMPLETO_ARQUIVOS_EM_MUDANCA
  log 'aviso: o conteúdo mudou durante o backup; evidência parcial preservada em site-before.tar.gz'
  log "detalhes do tar: $CASE/tar-backup-warnings.txt"
  chmod 600 "$CASE/site-before.tar.gz" "$CASE/tar-backup-warnings.txt" 2>/dev/null || true
  case "$MODE" in
    --audit|--audit-db|--audit-db-post) ;;
    *) die 'backup forense incompleto; nenhuma alteração será feita';;
  esac
fi
# Read literal WordPress configuration constants without executing PHP.
# Dynamic or environment-driven wp-config.php definitions are not supported.
read_define(){
  python3 - "$TARGET/wp-config.php" "$1" <<'PY'
import re,sys
s=open(sys.argv[1],encoding='utf-8',errors='replace').read(); n=re.escape(sys.argv[2])
m=re.search(r"define\s*\(\s*['\"]"+n+r"['\"]\s*,\s*(?P<q>['\"])(?P<v>(?:\\\\.|(?!(?P=q)).)*)['\"]",s,re.S)
if not m: raise SystemExit(2)
raw=m.group('v'); q=m.group('q')
if q == "'":
    # Em string PHP simples, apenas \\ e \' são escapes semânticos.
    value=raw.replace("\\'", "'").replace("\\\\", "\\")
else:
    # Em string PHP dupla, preservar escapes válidos de PHP sem aplicar regras
    # diferentes às do arquivo de configuração.
    value=bytes(raw,'utf-8').decode('unicode_escape')
print(value,end='')
PY
}
# Set restrictive wp-config.php permissions; requires checking that the
# selected group actually matches the webserver's intended access model.
secure_wp_config(){
  local group_id group_name before after
  before=$(stat -c '%u:%g %a %U:%G' "$TARGET/wp-config.php")
  group_id=$(stat -c '%g' "$TARGET/wp-content")
  group_name=$(getent group "$group_id" | cut -d: -f1 || true)
  [[ -n "$group_name" ]] || group_name=$(stat -c '%G' "$TARGET/wp-content")
  chown "root:$group_name" "$TARGET/wp-config.php"
  chmod 640 "$TARGET/wp-config.php"
  after=$(stat -c '%u:%g %a %U:%G' "$TARGET/wp-config.php")
  printf 'wp-config-metadata-before=%s\nwp-config-metadata-after=%s\n' "$before" "$after" | tee "$CASE/wp-config-metadata.txt"
}
fix_upload_permissions(){
  local web_user web_group vhost_conf
  [[ -d "$TARGET/wp-content/uploads" ]] || return 0
  web_user=; web_group=; vhost_conf=
  while IFS= read -r conf; do
    local owner_line
    owner_line=$(awk -v root="$TARGET" '$0 ~ /DocumentRoot/ && index($0,root) {ok=1} ok && /AssignUserId/ {print $2" "$3; exit}' "$conf" 2>/dev/null || true)
    if [[ -n "$owner_line" ]]; then
      read -r web_user web_group <<< "$owner_line"
      vhost_conf=$conf
      break
    fi
  done < <(find /etc/apache2/sites-enabled /etc/httpd -type f \( -name '*.conf' -o -name '*.vhost' \) -print 2>/dev/null | sort)
  if [[ -z "$web_user" ]]; then
    web_user=$(basename "$(dirname "$TARGET")")
    web_group=$web_user
    if ! id "$web_user" >/dev/null 2>&1 || ! getent group "$web_group" >/dev/null 2>&1; then
      web_user=; web_group=
    fi
  fi
  if [[ -z "$web_user" || -z "$web_group" ]]; then
    log 'AssignUserId não encontrado; mantendo proprietário atual de uploads'
    return 0
  fi
  id "$web_user" >/dev/null 2>&1 || die "usuário do vhost inexistente: $web_user"
  getent group "$web_group" >/dev/null 2>&1 || die "grupo do vhost inexistente: $web_group"
  chown -R "$web_user:$web_group" "$TARGET/wp-content/uploads"
  find "$TARGET/wp-content/uploads" -type d -exec chmod 755 {} +
  find "$TARGET/wp-content/uploads" -type f -exec chmod 644 {} +
  printf 'uploads-owner=%s:%s\nvhost-config=%s\n' "$web_user" "$web_group" "$vhost_conf" | tee "$CASE/uploads-metadata.txt"
  log "permissões de uploads ajustadas para $web_user:$web_group"
}
# Download published WordPress.org components into a staging directory.
# Existing ZIP checks are incomplete (e.g., symlink/size/integrity policy);
# do not treat this as a fully trusted archive extraction implementation.
official_sync_components(){
  local stage=$1
  [[ "$OFFICIAL_SYNC" == 1 ]] || return 0
  log 'verificando plugins/temas no repositório oficial WordPress.org e baixando cópias limpas'
  python3 - "$TARGET" "$stage" "$CASE" <<'PY'
import hashlib, json, os, shutil, sys, tempfile, urllib.parse, urllib.request, zipfile
target, stage, case = sys.argv[1:]
report = os.path.join(case, 'official-component-check.txt')
download_dir = os.path.join(case, 'official-downloads'); os.makedirs(download_dir, mode=0o700)
rows=[]; failures=[]
def api(kind, slug):
    if kind == 'plugin':
        base='https://api.wordpress.org/plugins/info/1.2/'
        req='action=plugin_information&request[slug]='+urllib.parse.quote(slug)
    else:
        base='https://api.wordpress.org/themes/info/1.2/'
        req='action=theme_information&request[slug]='+urllib.parse.quote(slug)
    with urllib.request.urlopen(base+'?'+req, timeout=20) as r:
        return json.load(r)
def sync(kind, name):
    slug=os.path.basename(name)
    try: info=api(kind, slug)
    except Exception as e:
        failures.append(f'{kind}\t{slug}\tAPI_ERROR\t{e}'); return
    if not isinstance(info, dict) or info.get('error') or not info.get('name') or not info.get('download_link'):
        failures.append(f'{kind}\t{slug}\tNOT_OFFICIAL\t{info.get("error", "sem download_link") if isinstance(info,dict) else "resposta inválida"}'); return
    url=info['download_link']
    if not str(url).startswith('https://'): failures.append(f'{kind}\t{slug}\tNON_HTTPS\t{url}'); return
    try:
        data=urllib.request.urlopen(url, timeout=60).read()
        digest=hashlib.sha256(data).hexdigest()
        fn=os.path.join(download_dir, slug+'.zip'); open(fn,'wb').write(data)
        tmp=tempfile.mkdtemp(prefix='extract-', dir=case)
        with zipfile.ZipFile(fn) as z:
            for member in z.infolist():
                name=member.filename.replace('\\', '/')
                parts=[p for p in name.split('/') if p not in ('', '.')]
                if name.startswith('/') or any(p == '..' for p in parts):
                    raise ValueError('zip com caminho inseguro: '+member.filename)
                z.extract(member, tmp)
        entries=[x for x in os.listdir(tmp) if x not in ('.','..')]
        root=os.path.join(tmp, slug) if os.path.isdir(os.path.join(tmp,slug)) else (os.path.join(tmp,entries[0]) if len(entries)==1 and os.path.isdir(os.path.join(tmp,entries[0])) else tmp)
        dest=os.path.join(stage, 'plugins' if kind=='plugin' else 'themes', slug)
        if os.path.exists(dest): shutil.rmtree(dest)
        shutil.copytree(root, dest)
        rows.append(f'{kind}\t{slug}\tOFFICIAL\t{info.get("version","")}\t{digest}\t{url}')
        shutil.rmtree(tmp, ignore_errors=True)
    except Exception as e:
        failures.append(f'{kind}\t{slug}\tDOWNLOAD_ERROR\t{e}')
for kind in ('plugin','theme'):
    base=os.path.join(target,'wp-content', 'plugins' if kind=='plugin' else 'themes')
    if not os.path.isdir(base): continue
    for slug in sorted(x for x in os.listdir(base) if os.path.isdir(os.path.join(base,x)) and not x.startswith('.')):
        sync(kind, slug)
with open(report,'w',encoding='utf-8') as f:
    f.write('tipo\tslug\tstatus\tversão\tsha256\tdownload\n')
    f.write('\n'.join(rows)+'\n')
    if failures:
        f.write('\nFALHAS\n'+'\n'.join(failures)+'\n')
if failures:
    print('componentes não oficiais ou falha de download:')
    print('\n'.join(failures))
    raise SystemExit(3)
print(f'componentes oficiais sincronizados: {len(rows)}')
PY
  [[ -s "$CASE/official-component-check.txt" ]] || die 'relatório de componentes oficiais não criado'
}
official_preflight(){
  [[ "$OFFICIAL_SYNC" == 1 ]] || return 0
  log 'validando previamente todos os plugins/temas contra o repositório oficial'
  python3 - "$TARGET" "$CASE" <<'PY'
import json, os, sys, urllib.parse, urllib.request
target, case = sys.argv[1:]
report=os.path.join(case,'official-component-preflight.txt'); rows=[]; failures=[]
def check(kind, slug):
    base='https://api.wordpress.org/plugins/info/1.2/' if kind=='plugin' else 'https://api.wordpress.org/themes/info/1.2/'
    req='action='+('plugin_information' if kind=='plugin' else 'theme_information')+'&request[slug]='+urllib.parse.quote(slug)
    try:
        with urllib.request.urlopen(base+'?'+req, timeout=20) as r: info=json.load(r)
        if not isinstance(info,dict) or info.get('error') or not info.get('name') or not info.get('download_link'):
            raise ValueError(info.get('error','resposta sem componente oficial') if isinstance(info,dict) else 'resposta inválida')
        if not str(info['download_link']).startswith('https://'): raise ValueError('download_link não HTTPS')
        rows.append(f'{kind}\t{slug}\tOFFICIAL\t{info.get("version","")}\t{info.get("download_link","")}')
    except Exception as e: failures.append(f'{kind}\t{slug}\tNOT_OFFICIAL_OR_UNAVAILABLE\t{e}')
for kind, sub in (('plugin','plugins'),('theme','themes')):
    base=os.path.join(target,'wp-content',sub)
    if os.path.isdir(base):
        for slug in sorted(x for x in os.listdir(base) if os.path.isdir(os.path.join(base,x)) and not x.startswith('.')): check(kind,slug)
with open(report,'w',encoding='utf-8') as f:
    f.write('tipo\tslug\tstatus\tversão\tdownload\n'+'\n'.join(rows)+'\n')
    if failures: f.write('\nFALHAS\n'+'\n'.join(failures)+'\n')
if failures:
    print('\n'.join(failures)); raise SystemExit(3)
print(f'pré-validação oficial aprovada: {len(rows)} componentes')
PY
}
# Compare plugin/theme directory names only. This does not verify package
# signatures, content hashes, compatibility or functional correctness.
compare_package_components(){
  local stage=$1 current_file="$CASE/components-production.txt" package_file="$CASE/components-package.txt" diff_file="$CASE/components-comparison.txt"
  {
    find "$TARGET/wp-content/plugins" "$TARGET/wp-content/themes" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | sort -u
  } > "$current_file"
  {
    find "$SOURCE/plugins" "$SOURCE/themes" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | sort -u
  } > "$package_file"
  {
    echo "script-version=$SCRIPT_VERSION"
    echo "## presentes na produção e ausentes no pacote"
    comm -23 "$current_file" "$package_file" || true
    echo "## presentes no pacote e ausentes na produção"
    comm -13 "$current_file" "$package_file" || true
    echo "## interseção"
    comm -12 "$current_file" "$package_file" || true
  } > "$diff_file"
  cat "$diff_file"
  ask_yes 'Comparação concluída. Deseja prosseguir com a recuperação?' || die 'execução abortada após comparação de plugins/temas'
  log 'comparação confirmada; prosseguindo'
}
elementor_asset_audit(){
  local out="$CASE/elementor-assets-audit.txt" cssdir fontdir
  cssdir="$TARGET/wp-content/uploads/elementor/css"
  fontdir="$TARGET/wp-content/uploads/elementor/google-fonts"
  {
    echo "target=$TARGET"
    echo "uploads=$(stat -c '%U:%G %a' "$TARGET/wp-content/uploads" 2>/dev/null || echo missing)"
    echo "elementor_css_dir=$(stat -c '%U:%G %a' "$cssdir" 2>/dev/null || echo missing)"
    echo "elementor_fonts_dir=$(stat -c '%U:%G %a' "$fontdir" 2>/dev/null || echo missing)"
    echo "elementor_css_count=$(find "$cssdir" -maxdepth 1 -type f -name '*.css' 2>/dev/null | wc -l)"
    echo "elementor_font_count=$(find "$fontdir" -type f \( -name '*.css' -o -name '*.woff' -o -name '*.woff2' \) 2>/dev/null | wc -l)"
    for f in inter opensans poppins prompt; do
      [[ -f "$fontdir/css/$f.css" ]] && echo "font_css_$f=present" || echo "font_css_$f=missing"
    done
    [[ -f "$TARGET/video/Brisa_da_Mata_Araucaria.MP4" ]] && echo 'video_brisa=present' || echo 'video_brisa=missing'
  } | tee "$out"
}
# Replace eight literal WP authentication keys/salts using Python secrets.
# Failure handling is not atomic; a failed write may leave partial changes.
rotate_wp_salts(){
  python3 - "$TARGET/wp-config.php" <<'PY'
import re, secrets, sys
p=sys.argv[1]
s=open(p,encoding='utf-8',errors='replace').read()
keys=('AUTH_KEY','SECURE_AUTH_KEY','LOGGED_IN_KEY','NONCE_KEY','AUTH_SALT','SECURE_AUTH_SALT','LOGGED_IN_SALT','NONCE_SALT')
for key in keys:
    value=secrets.token_urlsafe(48)
    pat=r"(define\s*\(\s*['\"]"+re.escape(key)+r"['\"]\s*,\s*)['\"][^'\"]*['\"](\s*\)\s*;)"
    s,n=re.subn(pat,lambda m:m.group(1)+"'"+value+"'"+m.group(2),s,count=1)
    if n != 1:
        raise SystemExit(f'missing or non-literal {key}')
open(p,'w',encoding='utf-8').write(s)
PY
  chmod 640 "$TARGET/wp-config.php"
  log 'salts/chaves do WordPress regenerados; sessões antigas invalidadas'
  : > "$CASE/wp-salts-rotated.txt"
}
# Resolve DB settings from wp-config.php. Credentials subsequently appear in
# MYSQL_PWD/environment variables and in a temporary protected client file;
# privileged process inspection may still expose environment contents.
DB_NAME=$(read_define DB_NAME) || die 'DB_NAME não literal'
DB_USER=$(read_define DB_USER) || die 'DB_USER não literal'
DB_PASS=$(read_define DB_PASSWORD) || die 'DB_PASSWORD não literal'
DB_HOST=$(read_define DB_HOST) || die 'DB_HOST não literal'
if [[ -n "$DB_HOST_OVERRIDE" ]]; then
  [[ "$DB_HOST_OVERRIDE" =~ ^[A-Za-z0-9._:-]+$ ]] || die 'db-host inválido'
  DB_HOST_CONFIGURED=$DB_HOST
  DB_HOST=$DB_HOST_OVERRIDE
  printf 'db-host-override=%s configured-host=%s\n' "$DB_HOST" "$DB_HOST_CONFIGURED" | tee "$CASE/database-host-override.txt"
fi
printf 'db-target=%s db-user=%s db-host=%s\n' "$DB_NAME" "$DB_USER" "$DB_HOST" | tee "$CASE/database-connection-metadata.txt"
DB_PREFIX=$(awk -F"'" '/^[[:space:]]*\$table_prefix[[:space:]]*=/ {print $2; exit}' "$TARGET/wp-config.php")
[[ "$DB_PREFIX" =~ ^[A-Za-z0-9_]+$ ]] || die 'table_prefix inválido'
T_USERS="$DB_PREFIX""users"; T_META="$DB_PREFIX""usermeta"; T_OPTIONS="$DB_PREFIX""options"
CNF="$CASE/mysql.cnf"
cleanup(){ rm -f "$CNF" 2>/dev/null || true; }
trap cleanup EXIT
DB_HOST="$DB_HOST" DB_USER="$DB_USER" DB_PASS="$DB_PASS" CNF="$CNF" python3 - <<'PY'
import os
def esc(v):
    return (v.replace('\\', '\\\\').replace('\n', '\\n').replace('\r', '\\r')
             .replace('#', '\\#').replace(';', '\\;'))
with open(os.environ['CNF'], 'w', encoding='utf-8') as f:
    f.write('[client]\n')
    f.write('host=' + esc(os.environ['DB_HOST']) + '\n')
    f.write('user=' + esc(os.environ['DB_USER']) + '\n')
    f.write('password=' + esc(os.environ['DB_PASS']) + '\n')
PY
chmod 600 "$CNF"
# WARNING: The dump is a full database export, not just IOC evidence.
# Even database *audit* modes take this backup, which may contain credentials,
# user information and application secrets. Protect, retain and delete it
# according to an incident-specific evidence-handling policy.
MYSQL_PWD="$DB_PASS" mysqldump --host="$DB_HOST" --user="$DB_USER" --single-transaction --quick --hex-blob --no-tablespaces "$DB_NAME" > "$CASE/database-before.sql"
[[ -s "$CASE/database-before.sql" ]] || die 'dump do banco vazio ou não criado'
sha256sum "$CASE/database-before.sql" > "$CASE/database-before.sql.sha256"
if [[ "$MODE" == --audit-db-post ]]; then
  log 'auditoria pós-recuperação do banco (somente leitura)'
  MYSQL_PWD="$DB_PASS" mysql --host="$DB_HOST" --user="$DB_USER" -N -B "$DB_NAME" <<SQL | tee "$CASE/database-post-recovery-audit.txt"
SELECT 'family_options_remaining',COUNT(*) FROM $T_OPTIONS WHERE option_name LIKE 'sc#_%' ESCAPE '#' OR option_name LIKE '_transient_sc#_%' ESCAPE '#' OR option_name LIKE '_transient_timeout_sc#_%' ESCAPE '#';
SELECT 'malware_strings_remaining',COUNT(*) FROM $T_OPTIONS WHERE option_value LIKE '%cipher-feeder%' OR option_value LIKE '%sc_cron_guard%' OR option_value LIKE '%sc_persist_manifest%';
SELECT 'malware_option_detail',option_name,LENGTH(option_value),CASE WHEN option_value LIKE '%cipher-feeder%' THEN 'cipher-feeder' WHEN option_value LIKE '%sc_cron_guard%' THEN 'sc_cron_guard' WHEN option_value LIKE '%sc_persist_manifest%' THEN 'sc_persist_manifest' ELSE 'unknown' END FROM $T_OPTIONS WHERE option_value LIKE '%cipher-feeder%' OR option_value LIKE '%sc_cron_guard%' OR option_value LIKE '%sc_persist_manifest%';
SELECT 'active_plugins_option_present',COUNT(*) FROM $T_OPTIONS WHERE option_name='active_plugins';
SELECT 'cron_option_present',COUNT(*) FROM $T_OPTIONS WHERE option_name='cron';
SELECT 'session_tokens_remaining',COUNT(*) FROM $T_META WHERE meta_key='session_tokens';
SELECT 'application_passwords_remaining',COUNT(*) FROM $T_META WHERE meta_key='wp_application_passwords' OR meta_key LIKE '%application_passwords';
SQL
  if awk '$1 ~ /^(family_options_remaining|malware_strings_remaining|session_tokens_remaining|application_passwords_remaining)$/ && $2 != 0 {bad=1} END {exit bad}' "$CASE/database-post-recovery-audit.txt"; then
    log 'auditoria pós-recuperação sem indicadores'; write_reports AUDIT_DB_POST_OK
  else
    log 'indicadores ou tokens ainda presentes no banco'; write_reports AUDIT_DB_POST_FINDINGS
  fi
  rm -f "$CNF"
  exit 0
fi
MYSQL_PWD="$DB_PASS" mysql --host="$DB_HOST" --user="$DB_USER" -N -B "$DB_NAME" -e "SELECT ID,user_login,user_registered FROM $T_USERS WHERE user_login REGEXP '^(admin|administrator|backup)_[0-9a-f]{6}$';" > "$CASE/suspicious-admins.tsv" || true
cat > "$CASE/manual-actions-required.txt" <<EOF
MANUTENÇÃO MANUAL OBRIGATÓRIA

1. Trocar manualmente as senhas de todos os administradores suspeitos listados em suspicious-admins.tsv.
2. Revisar cada administrador e remover somente após confirmação do responsável pelo site.
3. No modo --recover, a ferramenta regenera automaticamente os oito salts/chaves do wp-config.php e desconecta todos os usuários; em --audit-db, faça isso manualmente antes da publicação.
4. No modo --recover, sessões e application passwords armazenados no WordPress são removidos; revogue também tokens de API, SMTP e integrações externas manualmente.
5. Revisar uploads antes de restaurá-los.
6. Validar Apache, PHP-FPM, cron e systemd separadamente.
7. No modo --recover, wp-config.php fica root:<grupo do conteúdo> com permissão 640.

Nenhum administrador suspeito é removido automaticamente por esta ferramenta.
EOF
if [[ "$MODE" == --audit-db ]]; then
  log 'auditoria somente leitura do banco'
  MYSQL_PWD="$DB_PASS" mysql --host="$DB_HOST" --user="$DB_USER" -N -B "$DB_NAME" <<SQL | tee "$CASE/database-readonly-audit.txt"
SELECT 'suspicious_users',ID,user_login,user_registered FROM $T_USERS WHERE user_login REGEXP '^(admin|administrator|backup)_[0-9a-f]{6}$';
SELECT 'family_options',option_name,LENGTH(option_value) FROM $T_OPTIONS WHERE option_name LIKE 'sc#_%' ESCAPE '#' OR option_name LIKE '_transient_sc#_%' ESCAPE '#' OR option_name LIKE '_transient_timeout_sc#_%' ESCAPE '#';
SELECT 'malware_strings_in_options',option_name,LENGTH(option_value) FROM $T_OPTIONS WHERE option_value LIKE '%cipher-feeder%' OR option_value LIKE '%sc_cron_guard%' OR option_value LIKE '%sc_persist_manifest%';
SELECT 'historical_cache_reference',option_name,LENGTH(option_value) FROM $T_OPTIONS WHERE option_name='SimplePluginLogger_plugin_info_before_update' AND option_value LIKE '%trace-inspector-pad%';
SELECT 'active_plugins_contains_family',option_name,LENGTH(option_value) FROM $T_OPTIONS WHERE option_name='active_plugins' AND option_value LIKE '%cipher-feeder%';
SELECT 'cron_contains_family',option_name,LENGTH(option_value) FROM $T_OPTIONS WHERE option_name='cron' AND (option_value LIKE '%sc_cron_fetch%' OR option_value LIKE '%sc_cron_guard%');
SELECT 'session_rows',COUNT(*) FROM $T_META WHERE meta_key='session_tokens';
SQL
  MYSQL_PWD="$DB_PASS" mysql --host="$DB_HOST" --user="$DB_USER" -N -B "$DB_NAME" <<SQL > "$CASE/database-client-evidence.raw"
SELECT 'family_option',option_name,LENGTH(option_value),SHA2(option_value,256),LEFT(REPLACE(REPLACE(REPLACE(option_value,CHAR(9),' '),CHAR(10),' '),CHAR(13),' '),2048) FROM $T_OPTIONS WHERE option_name LIKE 'sc#_%' ESCAPE '#' OR option_name LIKE '_transient_sc#_%' ESCAPE '#' OR option_name LIKE '_transient_timeout_sc#_%' ESCAPE '#' ORDER BY option_name;
SELECT 'marker_option',option_name,LENGTH(option_value),SHA2(option_value,256),LEFT(REPLACE(REPLACE(REPLACE(option_value,CHAR(9),' '),CHAR(10),' '),CHAR(13),' '),2048) FROM $T_OPTIONS WHERE (option_value LIKE '%cipher-feeder%' OR option_value LIKE '%sc_cron_guard%' OR option_value LIKE '%sc_cron_fetch%' OR option_value LIKE '%sc_persist_manifest%' OR option_value LIKE '%trace-inspector-pad%') AND NOT (option_name='SimplePluginLogger_plugin_info_before_update' AND option_value LIKE '%trace-inspector-pad%') ORDER BY option_name;
SELECT 'historical_cache',option_name,LENGTH(option_value),SHA2(option_value,256),LEFT(REPLACE(REPLACE(REPLACE(option_value,CHAR(9),' '),CHAR(10),' '),CHAR(13),' '),2048) FROM $T_OPTIONS WHERE option_name='SimplePluginLogger_plugin_info_before_update' AND option_value LIKE '%trace-inspector-pad%';
SELECT 'cron',option_name,LENGTH(option_value),SHA2(option_value,256),CASE WHEN option_value LIKE '%sc_cron_guard%' THEN 'marcador sc_cron_guard encontrado' WHEN option_value LIKE '%sc_cron_fetch%' THEN 'marcador sc_cron_fetch encontrado' ELSE 'nenhum marcador conhecido' END FROM $T_OPTIONS WHERE option_name='cron';
SELECT 'active_plugins',option_name,LENGTH(option_value),SHA2(option_value,256),CASE WHEN option_value LIKE '%trace-inspector-pad%' OR option_value LIKE '%cipher-feeder%' THEN 'referencia de familia encontrada' ELSE 'nenhuma referencia conhecida' END FROM $T_OPTIONS WHERE option_name='active_plugins';
SQL
  python3 - "$CASE/database-client-evidence.raw" "$CASE/database-client-evidence.md" "$DB_NAME" "$T_OPTIONS" "$T_META" <<'PY'
import base64, binascii, json, re, sys, urllib.parse
raw,out,db,options,meta=sys.argv[1:]
def safe(v):
    v=v.strip()
    v=re.sub(r'(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*[^ ,;]+', r'\1=[REDACTED]', v)
    v=re.sub(r'(?<![A-Za-z0-9])[A-Za-z0-9_-]{40,}(?![A-Za-z0-9])', '[REDACTED_LONG_VALUE]', v)
    return v[:240]
def encoded_excerpt(v):
    v=re.sub(r'(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*[^ ,;]+', r'\1=[REDACTED]', v.strip())
    if len(v) <= 180: return v
    return v[:120] + '...[TRECHO_TRUNCADO]...' + v[-40:]
def classify_and_decode(v):
    raw=v.strip()
    if raw == '': return ('vazio', '')
    if re.fullmatch(r'-?\d+(?:\.\d+)?', raw): return ('escalar texto/número (não codificado)', raw)
    if raw.startswith(('a:', 's:', 'i:', 'b:', 'd:', 'O:')):
        return ('serializado PHP (não desserializado por segurança)', 'estrutura PHP serializada preservada; conteúdo interno não executado')
    if raw[:1] in ('{','['):
        try:
            obj=json.loads(raw); return ('JSON', safe(json.dumps(obj,ensure_ascii=False,separators=(',',':'))))
        except Exception: pass
    if '%' in raw and re.search(r'%[0-9A-Fa-f]{2}', raw):
        dec=urllib.parse.unquote(raw)
        if dec != raw: return ('URL-encoded', safe(dec))
    if len(raw) >= 8 and len(raw) % 2 == 0 and re.fullmatch(r'[0-9A-Fa-f]+', raw):
        try:
            dec=bytes.fromhex(raw).decode('utf-8')
            return ('hexadecimal', safe(dec))
        except Exception: pass
    if len(raw) >= 12 and len(raw) % 4 == 0 and re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', raw):
        try:
            dec=base64.b64decode(raw,validate=True).decode('utf-8')
            return ('Base64', safe(dec))
        except Exception: pass
    return ('texto simples ou codificação não identificada', safe(raw))
desc={
 'family_option':'Option/transient com nome reservado pela família maliciosa; indica estado de propagação, recuperação ou persistência.',
 'marker_option':'Option cujo conteúdo contém marcador conhecido da família ou referência ao componente malicioso.',
 'historical_cache':'Cache/metadado histórico de atualização; a referência ao componente não prova execução nem atividade atual.',
 'cron':'Option cron serializada do WordPress; o resultado informa se há marcadores de tarefas maliciosas.',
 'active_plugins':'Lista serializada de plugins ativos; o resultado informa se a família aparece como ativa.'}
rows=[]
with open(raw,encoding='utf-8',errors='replace') as f:
 for line in f:
  p=line.rstrip('\n').split('\t')
  if p: rows.append(p)
with open(out,'w',encoding='utf-8') as f:
 f.write('# Evidências detalhadas do banco\n\n')
 f.write('## Legenda de IOC\n\n')
 f.write('IOC (Indicator of Compromise) significa indicador de comprometimento: evidência técnica que pode indicar malware ou persistência.\n\n')
 f.write(f'Banco de dados (nome): `{db}`  \nTabela principal (nome físico): `{options}`  \nTabela de metadados (nome físico): `{meta}`\n\n')
 f.write('Como localizar: no phpMyAdmin, selecione o banco pelo nome acima e abra a tabela física indicada. No MySQL, use `USE '+db+';` e consulte a tabela indicada.\n\n')
 f.write('Observação: o registro `cron` é atualizado automaticamente pelo WordPress; tamanho e SHA-256 podem variar entre coletas sem indicar reinfecção. A classificação considera os marcadores encontrados no conteúdo, não apenas a alteração do hash.\n\n')
 if not rows:
  f.write('Nenhum registro correspondente aos marcadores pesquisados foi encontrado nesta coleta.\n')
 else:
  for p in rows:
   kind=p[0] if p else 'unknown'; name=p[1] if len(p)>1 else ''; length=p[2] if len(p)>2 else ''; digest=p[3] if len(p)>3 else ''; snippet=p[4] if len(p)>4 else ''
   classification,decoded=classify_and_decode(snippet)
   if kind == 'historical_cache':
    classification = 'referência histórica em cache (não prova de execução)'
   f.write(f'### Registro: `{name}`\n\n')
   f.write(f'- Banco de dados: `{db}`\n- Tabela física: `{options}`\n- Categoria: `{kind}`\n- Tamanho do valor: `{length}` bytes\n- SHA-256 do valor: `{digest}`\n- Descritivo: {desc.get(kind,"Registro retornado pela auditoria somente leitura.")}\n')
   if snippet:
    f.write(f'- Classificação do valor: **{classification}**\n')
    f.write(f'- Trecho codificado/original (limitado): `{encoded_excerpt(snippet)}`\n')
    if decoded and classification not in ('texto simples ou codificação não identificada','escalar texto/número (não codificado)'):
     f.write(f'- Trecho decodificado (limitado/mascarado): `{decoded}`\n')
    elif classification == 'escalar texto/número (não codificado)':
     f.write(f'- Valor interpretado: `{decoded}` (não codificado)\n')
   f.write('\n')
 f.write('A auditoria foi somente leitura. Senhas, salts, tokens e valores longos foram mascarados ou não incluídos.\n')
PY
  chmod 600 "$CASE/database-client-evidence.raw" "$CASE/database-client-evidence.md" 2>/dev/null || true
  session_rows=$(awk -F '\t' '$1=="session_rows" {print $2; exit}' "$CASE/database-readonly-audit.txt" 2>/dev/null || printf 'não informado')
  suspicious_users=$(awk -F '\t' '$1=="suspicious_users" {n++} END {print n+0}' "$CASE/database-readonly-audit.txt" 2>/dev/null || printf '0')
  {
    printf '\n## Resumo adicional da auditoria\n\n'
    printf -- '- Sessões WordPress armazenadas (`session_tokens`): `%s` registro(s). A existência de sessão não prova comprometimento; a revogação é recomendada durante a recuperação.\n' "$session_rows"
    printf -- '- Administradores com padrão de nome suspeito: `%s` registro(s).\n' "$suspicious_users"
    family_count=$(awk -F '\t' '$1=="family_options" {n++} END {print n+0}' "$CASE/database-readonly-audit.txt" 2>/dev/null || printf '0')
    historical_count=$(awk -F '\t' '$1=="historical_cache_reference" {n++} END {print n+0}' "$CASE/database-readonly-audit.txt" 2>/dev/null || printf '0')
    malware_count=$(awk -F '\t' '$1=="malware_strings_in_options" {n++} END {print n+0}' "$CASE/database-readonly-audit.txt" 2>/dev/null || printf '0')
    cron_family=$(awk -F '\t' '$1=="cron_contains_family" {n++} END {print n+0}' "$CASE/database-readonly-audit.txt" 2>/dev/null || printf '0')
    active_family=$(awk -F '\t' '$1=="active_plugins_contains_family" {n++} END {print n+0}' "$CASE/database-readonly-audit.txt" 2>/dev/null || printf '0')
    [[ "$session_rows" =~ ^[0-9]+$ ]] || session_rows=0
    printf '\n## Parecer técnico automatizado\n\n'
    if (( family_count > 0 || malware_count > 0 || cron_family > 0 || active_family > 0 )); then
      printf '**PARECER: HÁ EVIDÊNCIAS DE RESÍDUOS OU MARCADORES DE COMPROMETIMENTO NO BANCO.**\n\n'
      (( family_count > 0 )) && printf -- '- Foram encontrados `%s` registro(s) com nomes reservados pela família maliciosa (`sc_*`).\n' "$family_count"
      (( malware_count > 0 )) && printf -- '- Foram encontrados `%s` registro(s) com marcadores explícitos no conteúdo das opções.\n' "$malware_count"
      (( cron_family > 0 )) && printf -- '- Há marcador da família na opção `cron`.\n'
      (( active_family > 0 )) && printf -- '- Há marcador da família na lista `active_plugins`.\n'
      printf -- '- Não liberar o domínio com base somente nesta auditoria; manter isolamento e executar limpeza aprovada após preservar o backup.\n'
    else
      printf '**PARECER: NÃO FORAM ENCONTRADOS MARCADORES EXPLÍCITOS DA FAMÍLIA NAS ÁREAS ANALISADAS.**\n\n'
      printf -- '- Isso não prova limpeza completa: arquivos, uploads, persistência e credenciais devem ser validados separadamente.\n'
    fi
    if (( historical_count > 0 )); then
      printf -- '- A referência em `SimplePluginLogger_plugin_info_before_update` foi classificada como cache histórico; ela não prova execução ativa e não é removida automaticamente.\n'
    fi
    if (( session_rows > 0 )); then
      printf -- '- Há sessão(ões) armazenada(s); recomenda-se revogá-las durante a recuperação.\n'
    fi
  } >> "$CASE/database-client-evidence.md"
  rm -f "$CASE/database-client-evidence.raw"
  log "evidências detalhadas do banco: $CASE/database-client-evidence.md"
  rm -f "$CNF"
  log "auditoria de banco concluída; nenhuma alteração SQL foi feita"; write_reports AUDIT_DB_OK
  exit 0
fi
# Site-content replacement is invasive. The supplied source must be verified
# independently; the IOC signature scan is not a complete trust check.
if [[ "$MODE" == --apply-files || "$MODE" == --recover ]]; then
  log 'validando fonte limpa'
  if grep -RIlE --binary-files=without-match --exclude='*.jpg' --exclude='*.png' --exclude='*.gif' "$IOC_RE" "$SOURCE" 2>/dev/null | tee "$CASE/source-ioc-hits.txt" | grep -q .; then die 'fonte contém IOCs; abortando'; fi
  STAGE=$(mktemp -d "$TARGET/../.wp-content.stage.XXXXXX"); chmod 700 "$STAGE"; cp -a "$SOURCE/." "$STAGE/"
  official_preflight || die 'domínio interrompido: existe plugin/tema não oficial ou indisponível'
  compare_package_components "$STAGE"
  official_sync_components "$STAGE" || die 'domínio interrompido: plugin/tema não oficial ou falha no repositório oficial'
  if grep -RIlE --binary-files=without-match "$IOC_RE" "$STAGE" 2>/dev/null | grep -q .; then die 'IOC encontrado no stage; abortando'; fi
  OWNER=$(stat -c '%u' "$TARGET/wp-content"); GROUP=$(stat -c '%g' "$TARGET/wp-content")
  chown -R "$OWNER:$GROUP" "$STAGE"; find "$STAGE" -type d -exec chmod 755 {} +; find "$STAGE" -type f -exec chmod 644 {} +
  {
    echo '## Inventário conservador de plugins e temas'
    echo '### Atuais'
    find "$TARGET/wp-content/plugins" "$TARGET/wp-content/themes" -mindepth 1 -maxdepth 1 -type d -printf '%p\n' 2>/dev/null | sort || true
    echo '### Fonte limpa'
    find "$STAGE/plugins" "$STAGE/themes" -mindepth 1 -maxdepth 1 -type d -printf '%p\n' 2>/dev/null | sort || true
  } > "$CASE/plugin-theme-inventory.txt"
  if [[ "$REPLACE_PLUGIN_THEMES" != 1 ]] && find "$STAGE" -mindepth 2 -maxdepth 2 -type d \( -path '*/plugins/*' -o -path '*/themes/*' \) -print -quit | grep -q .; then
    die 'fonte contém plugins/temas; use --replace-plugins-themes somente após revisar plugin-theme-inventory.txt'
  fi
  ask_yes 'Mover wp-content atual para quarentena e instalar a fonte limpa?' || die 'cancelado'
  QUAR="$TARGET/wp-content.infectado-$STAMP"; [[ ! -e "$QUAR" ]] || die 'quarentena já existe'
  mv "$TARGET/wp-content" "$QUAR"; mv "$STAGE" "$TARGET/wp-content"; STAGE=; SWAPPED=1
  find "$TARGET/wp-content" -type f -print0 | sort -z | xargs -0 sha256sum > "$CASE/wp-content-after.sha256"
  log "quarentena: $QUAR"
fi
if [[ -n "$CORE_SOURCE" && "$MODE" == --recover ]]; then
  command -v rsync >/dev/null || die 'rsync necessário para repor core'
  log 'repondo wp-admin/wp-includes e arquivos PHP do core, sem apagar arquivos customizados'
  rsync -a "$CORE_SOURCE/wp-admin/" "$TARGET/wp-admin/"
  rsync -a "$CORE_SOURCE/wp-includes/" "$TARGET/wp-includes/"
  find "$CORE_SOURCE" -maxdepth 1 -type f \( -name '*.php' -o -name 'license.txt' -o -name 'readme.html' \) -exec cp -p {} "$TARGET/" \;
fi
# HIGH-IMPACT SQL: the statements below delete complete active_plugins/cron
# option records on signature match, not individual serialized entries.
# This can disrupt plugins and scheduled jobs. Treat as unsafe for production
# remediation pending surgical rewriting, regression tests and restore drills.
if [[ "$MODE" == --apply-db || "$MODE" == --recover ]]; then
  log 'limpeza conservadora: remove sessões/IOCs e preserva plugins/cron legítimos'
  ask_yes 'Alterar o banco após o dump de backup?' || die 'cancelado'
  MYSQL_PWD="$DB_PASS" mysql --host="$DB_HOST" --user="$DB_USER" "$DB_NAME" <<SQL
START TRANSACTION;
DELETE FROM $T_META WHERE meta_key='session_tokens';
DELETE FROM $T_META WHERE meta_key='wp_application_passwords' OR meta_key LIKE '%application_passwords';
DELETE FROM $T_OPTIONS WHERE option_name LIKE 'sc#_%' ESCAPE '#' OR option_name LIKE '_transient_sc#_%' ESCAPE '#' OR option_name LIKE '_transient_timeout_sc#_%' ESCAPE '#';
DELETE FROM $T_OPTIONS WHERE option_name LIKE 'wpstg#_analytics_event#_%' ESCAPE '#' OR option_name IN ('_site_transient_update_plugins','_transient_update_plugins','_site_transient_timeout_update_plugins','_transient_timeout_update_plugins');
-- Preservar active_plugins e cron legítimos; eles só devem ser removidos se
-- a auditoria confirmar marcador explícito da família maliciosa.
DELETE FROM $T_OPTIONS WHERE option_name='active_plugins' AND (option_value LIKE '%cipher-feeder%' OR option_value LIKE '%trace-inspector-pad%' OR option_value LIKE '%sc_cron_guard%' OR option_value LIKE '%sc_persist_manifest%');
DELETE FROM $T_OPTIONS WHERE option_name='cron' AND (option_value LIKE '%cipher-feeder%' OR option_value LIKE '%sc_cron_guard%' OR option_value LIKE '%sc_persist_manifest%' OR option_value LIKE '%sc_cron_fetch%');
COMMIT;
SQL
  DB_CHANGED=1
  log 'auditoria pós-recuperação do banco'
  MYSQL_PWD="$DB_PASS" mysql --host="$DB_HOST" --user="$DB_USER" -N -B "$DB_NAME" <<SQL | tee "$CASE/database-post-recovery-audit.txt"
SELECT 'family_options_remaining',COUNT(*) FROM $T_OPTIONS WHERE option_name LIKE 'sc#_%' ESCAPE '#' OR option_name LIKE '_transient_sc#_%' ESCAPE '#' OR option_name LIKE '_transient_timeout_sc#_%' ESCAPE '#';
SELECT 'malware_strings_remaining',COUNT(*) FROM $T_OPTIONS WHERE option_value LIKE '%cipher-feeder%' OR option_value LIKE '%sc_cron_guard%' OR option_value LIKE '%sc_persist_manifest%';
SELECT 'malware_option_detail',option_name,LENGTH(option_value),CASE WHEN option_value LIKE '%cipher-feeder%' THEN 'cipher-feeder' WHEN option_value LIKE '%sc_cron_guard%' THEN 'sc_cron_guard' WHEN option_value LIKE '%sc_persist_manifest%' THEN 'sc_persist_manifest' ELSE 'unknown' END FROM $T_OPTIONS WHERE option_value LIKE '%cipher-feeder%' OR option_value LIKE '%sc_cron_guard%' OR option_value LIKE '%sc_persist_manifest%';
SELECT 'active_plugins_option_present',COUNT(*) FROM $T_OPTIONS WHERE option_name='active_plugins';
SELECT 'cron_option_present',COUNT(*) FROM $T_OPTIONS WHERE option_name='cron';
SELECT 'session_tokens_remaining',COUNT(*) FROM $T_META WHERE meta_key='session_tokens';
SELECT 'application_passwords_remaining',COUNT(*) FROM $T_META WHERE meta_key='wp_application_passwords' OR meta_key LIKE '%application_passwords';
SQL
  if awk '$1 ~ /^(family_options_remaining|malware_strings_remaining|session_tokens_remaining|application_passwords_remaining)$/ && $2 != 0 {bad=1} END {exit bad}' "$CASE/database-post-recovery-audit.txt"; then :; else die 'indicadores ou tokens ainda presentes no banco; manter domínio isolado'; fi
fi
if [[ "$MODE" == --recover ]]; then
  ask_yes 'Rotacionar salts/chaves do WordPress e invalidar sessões?' || die 'rotação de salts cancelada; recuperação interrompida'
  rotate_wp_salts
  secure_wp_config
elif [[ "$MODE" == --apply-db ]]; then
  log 'ajustando proprietário e permissão de wp-config.php'
  secure_wp_config
fi
if [[ "$MODE" == --apply-db || "$MODE" == --recover ]]; then
  fix_upload_permissions
fi
elementor_asset_audit
if [[ "$MODE" == --recover ]]; then
  log 'validação final dos indicadores no wp-content instalado'
  if grep -RIlE --binary-files=without-match --include='*.php' --include='*.phtml' --include='*.inc' "$IOC_RE" "$TARGET/wp-content" 2>/dev/null | tee "$CASE/final-ioc-hits.txt" | grep -q .; then
    die 'indicadores ainda presentes após recuperação; manter domínio isolado'
  fi
  if known_processes | grep -q .; then
    die 'processo relacionado ao incidente apareceu após recuperação'
  fi
  log 'validação final concluída; Apache não foi iniciado/recarregado pelo script'
fi
rm -f "$CNF"
write_reports APPLIED_OK
log "concluído; evidências em $CASE"