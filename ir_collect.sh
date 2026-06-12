#!/bin/zsh
# ============================================================================
# ir_collect.sh — macOS Incident Response Evidence Collector
# ----------------------------------------------------------------------------
# Target:     Network-isolated macOS host (Ventura+ / Sonoma / Sequoia)
# Threat:     Odyssey / Poseidon / AMOS macOS infostealer (ClickFix delivery)
# Author:     Khodaparastan
# Version:    3.0  (2026-06-12)  — configurable + CLI
# Invocation: sudo -E ./ir_collect.sh [options]   (run --help for details)
#
# Config precedence:  built-in defaults < ir_collect.conf < environment < CLI
# ============================================================================

set -u
setopt PIPE_FAIL EXTENDED_GLOB NULL_GLOB
zmodload zsh/datetime
zmodload zsh/zutil          # zparseopts

SCRIPT_NAME="${0:t}"
SCRIPT_VERSION="3.0"
SCRIPT_START_EPOCH=$EPOCHSECONDS

# ----------------------------------------------------------------------------
# Usage / version
# ----------------------------------------------------------------------------
usage() {
  cat <<EOF
${SCRIPT_NAME} v${SCRIPT_VERSION} — macOS IR evidence collector (Odyssey/AMOS)

USAGE
  sudo -E ${SCRIPT_NAME} [options]

PATHS / IDENTITY
  -o, --evidence-base DIR   Output root (must be external media)   [/Volumes/IR]
  -i, --case-id ID          Case identifier            [IR-<ts>-<host>]
  -u, --target-user USER    User to triage                  [\$SUDO_USER]
  -c, --config FILE         Config file to source   [<evidence-base>/ir_collect.conf]
  -I, --ioc-file FILE       Extra IOCs, one per line (# comments ok)

WINDOWS / SIZING
  -l, --lookback DUR        Unified-log lookback (e.g. 7d,30d)            [14d]
  -w, --window DAYS         mtime/btime change window                     [30]
      --pam-window DAYS     PAM modification lookback                     [90]
      --max-sample BYTES    Auto-capture size cap                  [52428800]
      --min-free GB         Free-space warning threshold                  [10]

SELECTION / BEHAVIOR
  -p, --phases "LIST"       Phases to run, space-separated      ["0 1 2 3 4 5 6 7 8"]
      --no-snapshot         Do NOT take/mount APFS snapshot (atime WILL change)
      --no-diagnostics      Skip large /var/db/diagnostics tarball
      --no-powermetrics     Skip live powermetrics sampler
      --no-full-disk        Skip whole-volume time-bracket find
      --no-lsof-all         Skip full 'lsof -nP'
      --no-bundle           Leave output uncompressed (no tar.gz)
      --color WHEN          auto | always | never                        [auto]

GENERAL
  -n, --dry-run             Resolve config, print plan, exit (no collection)
  -V, --version             Print version and exit
  -h, --help                This help

EXAMPLES
  sudo -E ${SCRIPT_NAME}                                   # full collection
  sudo -E ${SCRIPT_NAME} -p "0 1 4 8" --no-powermetrics    # fast triage
  sudo -E ${SCRIPT_NAME} -w 14 --max-sample \$((200*1024*1024)) \\
       -I /Volumes/IR/case/iocs.txt -o /Volumes/IR
  sudo -E ${SCRIPT_NAME} --dry-run                         # preview plan

Precedence: defaults < ir_collect.conf < environment < CLI flags.
Tool paths (/usr/bin/...) are intentionally fixed to resist PATH hijack.
EOF
}
version() { print -r -- "${SCRIPT_NAME} ${SCRIPT_VERSION}"; }

# ----------------------------------------------------------------------------
# Argument parsing  (CLI captured into o_* holders; applied AFTER conf/env)
# ----------------------------------------------------------------------------
local o_help o_version o_dryrun
local o_config o_base o_case o_user o_lookback o_ioc o_phases
local o_window o_pamwin o_maxsample o_minfree o_color
local o_nosnap o_nodiag o_nopm o_nofulldisk o_nolsof o_nobundle

zparseopts -D -E -F -- \
  {h,-help}=o_help \
  {V,-version}=o_version \
  {n,-dry-run}=o_dryrun \
  {c,-config}:=o_config \
  {o,-evidence-base}:=o_base \
  {i,-case-id}:=o_case \
  {u,-target-user}:=o_user \
  {l,-lookback}:=o_lookback \
  {I,-ioc-file}:=o_ioc \
  {p,-phases}:=o_phases \
  {w,-window}:=o_window \
  -pam-window:=o_pamwin \
  -max-sample:=o_maxsample \
  -min-free:=o_minfree \
  -color:=o_color \
  -no-snapshot=o_nosnap \
  -no-diagnostics=o_nodiag \
  -no-powermetrics=o_nopm \
  -no-full-disk=o_nofulldisk \
  -no-lsof-all=o_nolsof \
  -no-bundle=o_nobundle \
  || { print -u2 "$SCRIPT_NAME: invalid option (try --help)"; exit 2 }

(( $#o_help ))    && { usage; exit 0 }
(( $#o_version )) && { version; exit 0 }

# ----------------------------------------------------------------------------
# Configuration resolution
# ----------------------------------------------------------------------------
# 1) Locate conf (CLI -c > env IR_CONFIG > default under evidence base).
_pre_base="${o_base[-1]:-${EVIDENCE_BASE:-/Volumes/IR}}"
: ${IR_CONFIG:="${_pre_base}/ir_collect.conf"}
(( $#o_config )) && IR_CONFIG="${o_config[-1]}"
_IR_CONFIG_LOADED=""
[[ -r "$IR_CONFIG" ]] && { source "$IR_CONFIG"; _IR_CONFIG_LOADED=1 }

# 2) Defaults (env + conf already win via :=).
: ${EVIDENCE_BASE:=/Volumes/IR}
: ${LOG_LOOKBACK:=14d}
: ${TARGET_USER:=${SUDO_USER:-$USER}}
: ${CASE_ID:="IR-$(TZ=UTC strftime '%Y%m%d-%H%M%S' $EPOCHSECONDS)-$(hostname -s)"}

: ${MIN_FREE_GB:=10}
: ${MAX_SAMPLE_BYTES:=52428800}
: ${MACHO_MAX_SIZE:=50M}
: ${CHANGE_WINDOW_DAYS:=30}
: ${PAM_WINDOW_DAYS:=90}
: ${HIDDEN_DIR_MAXDEPTH:=3}
: ${HISTORY_TAIL_LINES:=500}
: ${LOG_HEAD_LINES:=300}
: ${VMMAP_HEAD_LINES:=100}
: ${FSEVENTS_FILE_LIMIT:=200}
: ${IOC_HIT_LIMIT:=100}

: ${DO_SNAPSHOT:=1}
: ${DO_DIAGNOSTICS_TAR:=1}
: ${DO_FSEVENTS_TAR:=1}
: ${DO_POWERMETRICS:=1}
: ${DO_FULL_DISK_SCAN:=1}
: ${DO_LSOF_ALL:=1}
: ${DO_BUNDLE:=1}
: ${PHASES:="0 1 2 3 4 5 6 7 8"}
: ${FORCE_COLOR:=auto}
: ${IOC_FILE:=""}

# 3) CLI overrides (highest precedence).
(( $#o_base ))      && EVIDENCE_BASE="${o_base[-1]}"
(( $#o_case ))      && CASE_ID="${o_case[-1]}"
(( $#o_user ))      && TARGET_USER="${o_user[-1]}"
(( $#o_lookback ))  && LOG_LOOKBACK="${o_lookback[-1]}"
(( $#o_ioc ))       && IOC_FILE="${o_ioc[-1]}"
(( $#o_phases ))    && PHASES="${o_phases[-1]}"
(( $#o_window ))    && CHANGE_WINDOW_DAYS="${o_window[-1]}"
(( $#o_pamwin ))    && PAM_WINDOW_DAYS="${o_pamwin[-1]}"
(( $#o_maxsample )) && MAX_SAMPLE_BYTES="${o_maxsample[-1]}"
(( $#o_minfree ))   && MIN_FREE_GB="${o_minfree[-1]}"
(( $#o_color ))     && FORCE_COLOR="${o_color[-1]}"
(( $#o_nosnap ))    && DO_SNAPSHOT=0
(( $#o_nodiag ))    && DO_DIAGNOSTICS_TAR=0
(( $#o_nopm ))      && DO_POWERMETRICS=0
(( $#o_nofulldisk )) && DO_FULL_DISK_SCAN=0
(( $#o_nolsof ))    && DO_LSOF_ALL=0
(( $#o_nobundle ))  && DO_BUNDLE=0

# Numeric sanity (set -u safe).
for _v in MIN_FREE_GB MAX_SAMPLE_BYTES CHANGE_WINDOW_DAYS PAM_WINDOW_DAYS \
          HIDDEN_DIR_MAXDEPTH HISTORY_TAIL_LINES LOG_HEAD_LINES \
          VMMAP_HEAD_LINES FSEVENTS_FILE_LIMIT IOC_HIT_LIMIT; do
  [[ "${(P)_v}" == <-> ]] || { print -u2 "$SCRIPT_NAME: $_v must be an integer (got '${(P)_v}')"; exit 2 }
done

# Target home (after TARGET_USER resolved).
TARGET_HOME="$(/usr/bin/dscl . -read "/Users/${TARGET_USER}" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
[[ -z "$TARGET_HOME" || ! -d "$TARGET_HOME" ]] && TARGET_HOME="/Users/${TARGET_USER}"

# Derived paths.
OUT="${EVIDENCE_BASE}/${CASE_ID}"
META="${OUT}/_meta"
LOG_FILE="${META}/run.log"; ERR_FILE="${META}/run.err"; MANIFEST="${META}/MANIFEST.sha256"
SRC=""; SNAP_MNT="${OUT}/_snapshot_root"
SCRIPT_START_ISO="$(TZ=UTC strftime '%Y-%m-%dT%H:%M:%SZ' $EPOCHSECONDS)"

# IOC list (defaults unless conf predefined) + IOC_FILE append.
(( ${+IOC_STRINGS} )) || IOC_STRINGS=(
  "faced31.com" "stratos37.com"
  "homebrewclubs.org" "homebrewfaq.org" "homebrewonline.org" "homebrewupdate.org"
  "Homebrewlub.com" "logmeln.com" "logmeeine.com" "tradingviewen.com"
  "sites-phantom.com" "filmoraus.com" "93.152.230.79" "195.82.147.38"
  "Kgvte6N4Ab73QPUcm-3iajAe2K8dLrWEzsysY8YZ3xQ"
  "ipbGT_eh94rq6jM2djVvrJLF7eC1_HFhhXRh6rlQVCE"
  "setup-555549446b661f7073483a219ad86bf9c0312e89"
  "ab15698009e532f4735792cd06a793f618769121"
  "498d82aab2ce9fc2ec1e7358d0aa83d8e02a031ac4a177549d07a26262c5193c"
  "xll1reccl6ecroh4" "/tmp/helper" "osalogging.zip" "expand 32-byte k"
  "com.finder.helper" "homebrew/update" "api/metrics/run"
)
if [[ -n "$IOC_FILE" && -r "$IOC_FILE" ]]; then
  IOC_STRINGS+=( ${(f)"$(/usr/bin/grep -vE '^\s*(#|$)' "$IOC_FILE")"} )
fi

(( ${+KNOWN_BAD_PATHS} )) || KNOWN_BAD_PATHS=(
  /tmp/helper /tmp/.helper /tmp/update /tmp/installer
  /tmp/osalogging.zip /tmp/out.zip /tmp/out /tmp/archive.zip
  /tmp/list /tmp/system_info.txt
  /private/tmp/helper /private/tmp/osalogging.zip
  /var/tmp/helper /var/tmp/out.zip
  /Users/Shared/helper /Users/Shared/.helper
  HOME/fg HOME/.fg HOME/Library/Caches/helper HOME/.helper HOME/.config/helper
  HOME/Library/LaunchAgents/com.finder.helper.plist
  /Library/LaunchAgents/com.finder.helper.plist
  /Library/LaunchDaemons/com.finder.helper.plist
  HOME/Library/LaunchAgents/com.apple.softwareupdate.plist
)
(( ${+PRUNE_DIRS} )) || PRUNE_DIRS=( /System /Library/Apple /private/var/folders
  /private/var/db /usr /bin /sbin )
(( ${+EXT_WALLETS} )) || typeset -A EXT_WALLETS=(
  nkbihfbeogaeaoehlefnkodbefgpgknn MetaMask
  bfnaelmomeimhlpmgjnjophhpkkoljpa Phantom
  dmkamcknogkgcdfhhbddcghachkejeap Keplr
  hnfanknocfeofbddgcijnmhnfnkdnaad Coinbase
  ejbalbakoplchlghecdalmeeeajnimhm MetaMask_Edge
  bhghoamapcdpbohphigoooaddinpkbai Authenticator
  aiifbnbfobpmeekipheeijimdpnlpgpp TerraStation
  fhbohimaelbohpjbbldcngcnapndodjp BinanceChain
  ibnejdfjmmkpcnlpebklmnkoeoihofec TronLink
  aeachknmefphepccionboohckonoeemg CoinPocket
  jblndlipeogpafnldhgmapagcccfchpi Kaikas
)

# ----------------------------------------------------------------------------
# Colors (NO_COLOR + --color aware)
# ----------------------------------------------------------------------------
_use_color() {
  [[ -n "${NO_COLOR:-}" ]] && return 1
  case "$FORCE_COLOR" in
    always) return 0 ;; never) return 1 ;; *) [[ -t 1 ]] ;;
  esac
}
if _use_color; then
  CR=$'\033[0;31m'; CG=$'\033[0;32m'; CY=$'\033[0;33m'
  CB=$'\033[0;34m'; CC=$'\033[0;36m'; CW=$'\033[1;37m'; CN=$'\033[0m'
else
  CR=''; CG=''; CY=''; CB=''; CC=''; CW=''; CN=''
fi

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
ts() {
  local now=$EPOCHREALTIME
  local frac="${now#*.}"; frac="${(r:3::0:)frac}"
  TZ=UTC strftime "%Y-%m-%dT%H:%M:%S.${frac}Z" "${now%.*}"
}
log() {
  local lvl="$1"; shift
  local msg="[$(ts)] [${lvl}] $*"
  case "$lvl" in
    INFO)  printf "%s%s%s\n" "$CB" "$msg" "$CN" ;;
    OK)    printf "%s%s%s\n" "$CG" "$msg" "$CN" ;;
    WARN)  printf "%s%s%s\n" "$CY" "$msg" "$CN" ;;
    ERR)   printf "%s%s%s\n" "$CR" "$msg" "$CN" ;;
    PHASE) printf "\n%s========== %s ==========%s\n" "$CW" "$*" "$CN" ;;
    *)     printf "%s\n" "$msg" ;;
  esac
  printf "%s\n" "$msg" >> "$LOG_FILE" 2>/dev/null
}
rp() { print -r -- "${SRC}$1"; }
run() {
  local desc="$1"; shift; local out="$1"; shift
  [[ "${1:-}" == "--" ]] && shift
  local cmd="$*"; log INFO "→ $desc"
  printf "\n### [%s] %s\n### cmd: %s\n" "$(ts)" "$desc" "$cmd" >> "$LOG_FILE"
  local rc=0
  if [[ -n "$out" ]]; then mkdir -p "${out:h}"; eval "$cmd" > "$out" 2>> "$ERR_FILE" || rc=$?
  else eval "$cmd" >> "$LOG_FILE" 2>> "$ERR_FILE" || rc=$?; fi
  printf "### exit=%d\n" "$rc" >> "$LOG_FILE"
  (( rc )) && log WARN "  (exit=$rc) $desc — see run.err"; return 0
}
runv() {
  local desc="$1" out="$2"; shift 2; log INFO "→ $desc"
  printf "\n### [%s] %s\n### argv: %s\n" "$(ts)" "$desc" "${(q)*}" >> "$LOG_FILE"
  local rc=0
  if [[ -n "$out" ]]; then mkdir -p "${out:h}"; "$@" > "$out" 2>> "$ERR_FILE" || rc=$?
  else "$@" >> "$LOG_FILE" 2>> "$ERR_FILE" || rc=$?; fi
  printf "### exit=%d\n" "$rc" >> "$LOG_FILE"
  (( rc )) && log WARN "  (exit=$rc) $desc — see run.err"; return 0
}
safe_cp() {
  local src="$1" dst="$2"
  [[ -e "$src" || -L "$src" ]] || { log WARN "skip (missing): $src"; return 0; }
  mkdir -p "${dst:h}"
  if /bin/cp -pPR "$src" "$dst" 2>>"$ERR_FILE"; then log OK "copied: $src"
  else log WARN "cp failed: $src"; fi
}
stat_meta() {
  local f="$1"
  [[ -e "$f" || -L "$f" ]] || { echo "MISSING: $f"; return; }
  /usr/bin/stat -f 'path=%N inode=%i mode=%Sp uid=%u(%Su) gid=%g(%Sg) size=%z blocks=%b atime=%Sa mtime=%Sm ctime=%Sc btime=%SB' \
    -t '%Y-%m-%dT%H:%M:%SZ' "$f" 2>/dev/null
  /usr/bin/xattr -l "$f" 2>/dev/null | sed 's/^/  xattr: /'
  /usr/bin/shasum -a 256 "$f" 2>/dev/null | sed 's/^/  sha256: /'
}
phase_enabled() { [[ " $PHASES " == *" $1 "* ]]; }

print_plan() {
  print -r -- "${CW}=== ${SCRIPT_NAME} v${SCRIPT_VERSION} — resolved plan ===${CN}"
  print -r -- "Config source : ${_IR_CONFIG_LOADED:+$IR_CONFIG}${_IR_CONFIG_LOADED:-built-in defaults}"
  print -r -- "Case ID       : $CASE_ID"
  print -r -- "Evidence base : $EVIDENCE_BASE  ->  $OUT"
  print -r -- "Target user   : $TARGET_USER  (home: $TARGET_HOME)"
  print -r -- "Phases        : $PHASES"
  print -r -- "Log lookback  : $LOG_LOOKBACK"
  print -r -- "Windows       : change=${CHANGE_WINDOW_DAYS}d pam=${PAM_WINDOW_DAYS}d hidden-depth=${HIDDEN_DIR_MAXDEPTH}"
  print -r -- "Sample cap    : $(( MAX_SAMPLE_BYTES / 1048576 )) MiB (macho<=${MACHO_MAX_SIZE})"
  print -r -- "Min free      : ${MIN_FREE_GB}G"
  print -r -- "Toggles       : snapshot=$DO_SNAPSHOT diag=$DO_DIAGNOSTICS_TAR fsevents=$DO_FSEVENTS_TAR powermetrics=$DO_POWERMETRICS fulldisk=$DO_FULL_DISK_SCAN lsof-all=$DO_LSOF_ALL bundle=$DO_BUNDLE"
  print -r -- "IOCs          : ${#IOC_STRINGS} (file: ${IOC_FILE:-none})"
  print -r -- "Color         : $FORCE_COLOR${NO_COLOR:+ (NO_COLOR set)}"
}

# ----------------------------------------------------------------------------
# Preflight
# ----------------------------------------------------------------------------
preflight() {
  log PHASE "PREFLIGHT"
  if [[ $EUID -ne 0 ]]; then log ERR "Must run as root (use: sudo -E $0)"; exit 1; fi
  if [[ ! -d "$EVIDENCE_BASE" ]]; then
    log ERR "EVIDENCE_BASE not found: $EVIDENCE_BASE"
    log ERR "Mount external media and re-run with -o /Volumes/<name>"; exit 1
  fi
  local base_dev root_dev
  base_dev=$(/bin/df "$EVIDENCE_BASE" | awk 'NR==2{print $1}')
  root_dev=$(/bin/df / | awk 'NR==2{print $1}')
  if [[ "$base_dev" == "$root_dev" ]]; then
    log ERR "EVIDENCE_BASE is on the local boot volume — refusing. Use external media."; exit 1
  fi
  local avail_gb; avail_gb=$(/bin/df -g "$EVIDENCE_BASE" | awk 'NR==2{print $4}'); avail_gb=${avail_gb:-0}
  log INFO "Available space on $EVIDENCE_BASE: ${avail_gb}G"
  (( avail_gb < MIN_FREE_GB )) && log WARN "Less than ${MIN_FREE_GB}G free; collection may be incomplete"

  mkdir -p "$OUT" "$META" || { log ERR "Cannot create $OUT"; exit 1; }
  : >| "$LOG_FILE"; : >| "$ERR_FILE"; : >| "$MANIFEST"

  log INFO "Config source:  ${_IR_CONFIG_LOADED:+$IR_CONFIG }${_IR_CONFIG_LOADED:-built-in defaults}"
  log INFO "Case ID:        $CASE_ID"
  log INFO "Output:         $OUT"
  log INFO "Target user:    $TARGET_USER  (home: $TARGET_HOME)"
  log INFO "Phases:         $PHASES"
  log INFO "Log lookback:   $LOG_LOOKBACK"
  log INFO "Windows:        change=${CHANGE_WINDOW_DAYS}d pam=${PAM_WINDOW_DAYS}d"
  log INFO "Sample cap:     $(( MAX_SAMPLE_BYTES / 1048576 )) MiB"
  log INFO "Toggles:        snapshot=$DO_SNAPSHOT diag=$DO_DIAGNOSTICS_TAR powermetrics=$DO_POWERMETRICS fulldisk=$DO_FULL_DISK_SCAN bundle=$DO_BUNDLE"
  log INFO "IOC count:      ${#IOC_STRINGS} (file: ${IOC_FILE:-none})"
  log INFO "Start (UTC):    $SCRIPT_START_ISO"
}

# ============================================================================
# PHASE 0 — Freeze, metadata, snapshot
# ============================================================================
phase0_freeze() {
  log PHASE "PHASE 0 — Freeze & metadata"
  local D="$OUT/00_freeze"; mkdir -p "$D"
  runv "Wall clock UTC"     "$D/clock_utc.txt"        date -u
  runv "Wall clock local"   "$D/clock_local.txt"      date
  runv "Uptime"             "$D/uptime.txt"           uptime
  runv "Kernel boot time"   "$D/boottime.txt"         sysctl kern.boottime
  runv "Hostname"           "$D/hostname.txt"         hostname
  runv "id"                 "$D/id.txt"               id
  runv "logged-in sessions" "$D/who.txt"              who
  runv "active terminals"   "$D/w.txt"                w
  runv "ifconfig"           "$D/ifconfig.txt"         ifconfig
  runv "network services"   "$D/network_services.txt" /usr/sbin/networksetup -listallnetworkservices

  if (( DO_SNAPSHOT )); then
    log INFO "Taking APFS local snapshot..."
    if /usr/bin/tmutil localsnapshot 2>>"$ERR_FILE"; then log OK "Local APFS snapshot created"
    else log WARN "tmutil localsnapshot failed (Time Machine disabled?)"; fi
    runv "List local snapshots" "$D/apfs_snapshots.txt" /usr/bin/tmutil listlocalsnapshots /
    mount_ro_snapshot
  else
    log WARN "DO_SNAPSHOT=0 — reading LIVE fs; atimes WILL be altered"
  fi
}
mount_ro_snapshot() {
  local snap
  snap=$(/usr/bin/tmutil listlocalsnapshots / 2>/dev/null | /usr/bin/tail -1 | /usr/bin/sed 's/.*\.//')
  if [[ -z "$snap" ]]; then log WARN "No snapshot — on-disk reads hit LIVE fs (atime altered)"; return 1; fi
  mkdir -p "$SNAP_MNT"
  if /sbin/mount_apfs -o ro,nobrowse -s "com.apple.TimeMachine.${snap}.local" / "$SNAP_MNT" 2>>"$ERR_FILE"; then
    SRC="$SNAP_MNT"; log OK "Snapshot mounted read-only at $SNAP_MNT — reads atime-safe"
  else log WARN "mount_apfs failed — on-disk reads hit LIVE fs (atime altered)"; return 1; fi
}
unmount_snapshot() {
  [[ -n "$SRC" ]] || return 0
  /sbin/umount "$SNAP_MNT" 2>>"$ERR_FILE" && log OK "Snapshot unmounted" || log WARN "umount $SNAP_MNT failed"
  rmdir "$SNAP_MNT" 2>/dev/null
}

# ============================================================================
# PHASE 1 — Volatile (LIVE)
# ============================================================================
phase1_volatile() {
  log PHASE "PHASE 1 — Volatile state"
  local D="$OUT/01_volatile"; mkdir -p "$D"
  runv "Process tree (wide)" "$D/ps_full.txt"  ps -Axwwo pid,ppid,uid,user,start,etime,stat,command
  runv "Process tree parent" "$D/ps_tree.txt"  ps -Axwwo pid,ppid,command
  runv "Process wchan"       "$D/ps_wchan.txt" ps -Axwwo pid,ppid,wchan,command
  run  "pgrep suspects"      "$D/pgrep_suspects.txt" -- \
    'for p in helper osascript curl zsh dscl security zip xattr; do echo "=== $p ==="; pgrep -alf "$p" 2>/dev/null; done'
  runv "lsof network"        "$D/lsof_net.txt" lsof -nP -i
  (( DO_LSOF_ALL )) && runv "lsof all files" "$D/lsof_all.txt" lsof -nP
  run  "lsof known-bad"      "$D/lsof_tmp.txt" -- \
    "lsof -nP 2>/dev/null | grep -E '/tmp/|/Users/Shared/|/private/tmp/'"
  runv "netstat all"         "$D/netstat_all.txt" netstat -anv
  runv "netstat routes"      "$D/route.txt"       netstat -rn
  runv "ARP table"           "$D/arp.txt"         arp -an
  runv "resolver state"      "$D/resolv.txt"      scutil --dns
  runv "proxy config"        "$D/proxies.txt"     scutil --proxy
  runv "pf ruleset"          "$D/pf_rules.txt"    pfctl -sr
  runv "pf full state"       "$D/pf_all.txt"      pfctl -sa
  runv "Loaded kexts"        "$D/kextstat.txt"    kextstat -l
  runv "System extensions"   "$D/systemextensions.txt" systemextensionsctl list

  log INFO "Enumerating suspect process details..."
  local suspect_pids
  suspect_pids=$(ps -Axwwo pid,command | awk '
    /\/tmp\/|\/private\/tmp\/|\/Users\/Shared\/|\/\.[a-z0-9]/ && $0 !~ /ir_collect/ {print $1}' | sort -u)
  if [[ -n "$suspect_pids" ]]; then
    {
      echo "=== Suspect PIDs ==="; echo "$suspect_pids"; echo
      local pid
      for pid in ${(f)suspect_pids}; do
        echo "=== PID $pid ==="
        ps -o pid,ppid,uid,user,start,etime,command -p "$pid" 2>/dev/null
        echo "--- lsof ---";          lsof -p "$pid" -nP 2>/dev/null
        echo "--- vmmap summary ---"; vmmap -summary "$pid" 2>/dev/null | head -${VMMAP_HEAD_LINES}
      done
    } > "$D/suspect_processes.txt"
    log WARN "Suspect processes found — see suspect_processes.txt"
  else echo "No suspect processes located" > "$D/suspect_processes.txt"; fi
}

# ============================================================================
# PHASE 2 — On-disk (via $SRC)
# ============================================================================
phase2_disk() {
  log PHASE "PHASE 2 — On-disk staging & artifacts"
  local D="$OUT/02_disk"; mkdir -p "$D/captured_samples"

  log INFO "Checking known-bad artifact paths..."
  local known_paths=( "${(@)KNOWN_BAD_PATHS//HOME/$TARGET_HOME}" )
  {
    local p sp sz
    for p in "${known_paths[@]}"; do
      sp="$(rp "$p")"
      if [[ -e "$sp" || -L "$sp" ]]; then
        echo "=== FOUND: $p ==="; stat_meta "$sp"
        /usr/bin/file -b "$sp" 2>/dev/null | sed 's/^/  file: /'; echo
        sz=$(/usr/bin/stat -f '%z' "$sp" 2>/dev/null); sz=${sz:-0}
        [[ -f "$sp" ]] && (( sz < MAX_SAMPLE_BYTES )) && safe_cp "$sp" "$D/captured_samples/${p#/}"
      fi
    done
  } > "$D/known_paths.txt"

  if (( DO_FULL_DISK_SCAN )); then
    log INFO "Time-bracket search (mtime OR btime <=${CHANGE_WINDOW_DAYS}d, single pass)..."
    /usr/bin/find "${SRC:-/}" -xdev \
      \( ${(j: -o :)${(@)PRUNE_DIRS/#/-path ${SRC}}} -o -path "$EVIDENCE_BASE" -o -path "$SNAP_MNT" \) -prune -o \
      -type f \( -mtime -${CHANGE_WINDOW_DAYS} -o -Btime -${CHANGE_WINDOW_DAYS} \) -print 2>/dev/null \
      > "$D/files_changed.txt"
  else
    echo "skipped (DO_FULL_DISK_SCAN=0)" > "$D/files_changed.txt"
    log INFO "Full-disk scan skipped (DO_FULL_DISK_SCAN=0)"
  fi

  log INFO "Mach-O hunt outside system paths..."
  /usr/bin/find "${SRC}/tmp" "${SRC}/private/tmp" "${SRC}/var/tmp" \
    "${SRC}/Users" "${SRC}/opt" "${SRC}/usr/local" \
    -xdev -type f ! -path '*/node_modules/*' ! -path '*/Library/Developer/*' \
    ! -path '*/Caches/com.apple.*' 2>/dev/null \
    -exec sh -c 'out=$(/usr/bin/file -b "$1" 2>/dev/null); case "$out" in Mach-O*) echo "$1|$out";; esac' _ {} \; \
    > "$D/machos_outside_system.txt"

  log INFO "Codesign verification of Mach-O hits..."
  {
    local f desc sz
    while IFS='|' read -r f desc; do
      [[ -z "$f" ]] && continue
      echo "================================================================"
      echo "FILE: ${f#$SRC}"; echo "TYPE: $desc"; stat_meta "$f"
      echo "--- codesign -dv ---";   /usr/bin/codesign -dv --verbose=4 "$f" 2>&1 | head -30
      echo "--- spctl ---";          /usr/sbin/spctl -a -vv "$f" 2>&1
      echo "--- otool -L ---";       /usr/bin/otool -L "$f" 2>/dev/null | head -20; echo
      sz=$(/usr/bin/stat -f '%z' "$f" 2>/dev/null); sz=${sz:-0}
      (( sz < MAX_SAMPLE_BYTES )) && safe_cp "$f" "$D/captured_samples/${${f#$SRC}#/}"
    done < "$D/machos_outside_system.txt"
  } > "$D/machos_verified.txt"

  log INFO "Archive hunt..."
  /usr/bin/find "${SRC}/tmp" "${SRC}/private/tmp" "${SRC}/var/tmp" \
    "${SRC}/Users/Shared" "$(rp "$TARGET_HOME")" \
    -xdev -type f \( -name '*.zip' -o -name '*.tar.gz' -o -name 'out' -o -name 'data' \) \
    -mtime -${CHANGE_WINDOW_DAYS} ! -path '*/Library/Caches/*' ! -path '*/node_modules/*' 2>/dev/null \
    > "$D/archives_recent.txt"
  {
    local a
    while read -r a; do
      [[ -f "$a" ]] || continue
      echo "=== ${a#$SRC} ==="; stat_meta "$a"
      echo "--- contents ---"; /usr/bin/unzip -l "$a" 2>/dev/null | head -80; echo
    done < "$D/archives_recent.txt"
  } > "$D/archives_inspected.txt"

  log INFO "Quarantine-xattr anomaly check..."
  {
    echo "# Executables/scripts in /tmp or Downloads (<=${CHANGE_WINDOW_DAYS}d) without com.apple.quarantine"
    local f ft
    /usr/bin/find "${SRC}/tmp" "${SRC}/private/tmp" "$(rp "$TARGET_HOME/Downloads")" \
      -xdev -type f -mtime -${CHANGE_WINDOW_DAYS} 2>/dev/null | while read -r f; do
        /usr/bin/xattr -lp com.apple.quarantine "$f" >/dev/null 2>&1 && continue
        ft=$(/usr/bin/file -b "$f" 2>/dev/null)
        case "$ft" in Mach-O*|*executable*|*script*) echo "MISSING_QUARANTINE: ${f#$SRC}  [$ft]";; esac
      done
  } > "$D/no_quarantine.txt"

  log INFO "Recent hidden directories under \$HOME..."
  /usr/bin/find "$(rp "$TARGET_HOME")" -maxdepth $HIDDEN_DIR_MAXDEPTH -type d -name '.[!.]*' \
    -mtime -${CHANGE_WINDOW_DAYS} ! -path '*/Library/*' 2>/dev/null > "$D/recent_hidden_dirs.txt"

  local sd ssd
  for sd in "$TARGET_HOME/fg" "$TARGET_HOME/.fg" "$TARGET_HOME/Library/.fg" \
            "$TARGET_HOME/.config/fg" "$TARGET_HOME/Library/data"; do
    ssd="$(rp "$sd")"; [[ -d "$ssd" ]] || continue
    log WARN "Suspect staging dir: $sd"
    {
      echo "=== STAGING DIR: $sd ==="; /bin/ls -laR "$ssd"; echo
      /usr/bin/find "$ssd" -type f -exec /usr/bin/stat -f '%N atime=%Sa mtime=%Sm size=%z' {} \;
    } >> "$D/staging_dirs.txt"
    safe_cp "$ssd" "$D/captured_samples/${sd#/}"
  done
}

# ============================================================================
# PHASE 3 — Persistence
# ============================================================================
phase3_persistence() {
  log PHASE "PHASE 3 — Persistence enumeration"
  local D="$OUT/03_persistence"; mkdir -p "$D"
  {
    local d
    for d in "$TARGET_HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons \
             /System/Library/LaunchAgents /System/Library/LaunchDaemons; do
      echo "=== DIR: $d ==="; /bin/ls -la@ "$(rp "$d")" 2>/dev/null; echo
    done
  } > "$D/launchd_dirs.txt"

  log INFO "Inspecting third-party LaunchAgents/Daemons..."
  {
    local d p prog sprog
    for d in "$TARGET_HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons; do
      [[ -d "$(rp "$d")" ]] || continue
      for p in "$(rp "$d")"/*.plist(N); do
        echo "=== PLIST: ${p#$SRC} ==="; stat_meta "$p"
        echo "--- contents ---"
        /usr/libexec/PlistBuddy -c "Print" "$p" 2>/dev/null || /bin/cat "$p"
        prog=$(/usr/libexec/PlistBuddy -c "Print :Program" "$p" 2>/dev/null)
        [[ -z "$prog" ]] && prog=$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:0" "$p" 2>/dev/null)
        if [[ -n "$prog" ]]; then
          sprog="$(rp "$prog")"
          if [[ -f "$sprog" ]]; then
            echo "--- program: $prog ---"; stat_meta "$sprog"
            /usr/bin/codesign -dv --verbose=4 "$sprog" 2>&1 | head -10
            /usr/sbin/spctl -a -vv "$sprog" 2>&1
          fi
        fi
        echo
      done
    done
  } > "$D/launchd_plists_inspected.txt"

  log INFO "Apple-impersonating plist check..."
  /usr/bin/find "$(rp "$TARGET_HOME/Library/LaunchAgents")" "$(rp /Library/LaunchAgents)" "$(rp /Library/LaunchDaemons)" \
    -type f \( -name 'com.apple.*' -o -name 'com.finder.*' \) 2>/dev/null | sed "s|^$SRC||" > "$D/apple_impersonators.txt"

  run  "launchctl list (user)" "$D/launchctl_user.txt"   -- "sudo -u $TARGET_USER launchctl list"
  runv "launchctl list (root)" "$D/launchctl_root.txt"   launchctl list
  run  "launchctl gui"         "$D/launchctl_gui.txt"    -- "launchctl print gui/$(id -u $TARGET_USER) 2>&1 | head -${LOG_HEAD_LINES}"
  run  "launchctl system"      "$D/launchctl_system.txt" -- "launchctl print system 2>&1 | head -${LOG_HEAD_LINES}"
  run  "osascript loginitems"  "$D/loginitems_osa.txt"   -- \
    "sudo -u $TARGET_USER osascript -e 'tell application \"System Events\" to get name of every login item'"
  run  "sfltool dumpbtm (user)" "$D/btm_user.txt"        -- "sudo -u $TARGET_USER sfltool dumpbtm"
  runv "sfltool dumpbtm (root)" "$D/btm_root.txt"        sfltool dumpbtm
  run  "user crontab"          "$D/crontab_user.txt"     -- "sudo -u $TARGET_USER crontab -l"
  runv "root crontab"          "$D/crontab_root.txt"     crontab -l
  run  "at jobs"               "$D/at_jobs.txt"          -- "ls -la /var/at/jobs 2>/dev/null"
  run  "periodic dirs"         "$D/periodic.txt"         -- "ls -la /etc/periodic*/ /etc/cron* 2>/dev/null"

  log INFO "Capturing shell init files..."
  {
    local rc
    for rc in "$TARGET_HOME/.zshenv" "$TARGET_HOME/.zprofile" "$TARGET_HOME/.zshrc" \
              "$TARGET_HOME/.zlogin" "$TARGET_HOME/.zlogout" \
              "$TARGET_HOME/.bash_profile" "$TARGET_HOME/.bashrc" \
              "$TARGET_HOME/.profile" "$TARGET_HOME/.bash_login" \
              /etc/zshenv /etc/zprofile /etc/zshrc /etc/zlogin /etc/profile /etc/bashrc; do
      [[ -f "$(rp "$rc")" ]] || continue
      echo "=== FILE: $rc ==="; stat_meta "$(rp "$rc")"; echo "--- contents ---"; /bin/cat "$(rp "$rc")"; echo
    done
  } > "$D/shell_rc_files.txt"

  log INFO "Searching shell init for suspect patterns..."
  /usr/bin/grep -nHE 'curl|wget|base64|eval|source.*http|/tmp/' \
    "$(rp "$TARGET_HOME")"/.zsh* "$(rp "$TARGET_HOME")"/.bash* "$(rp "$TARGET_HOME")"/.profile \
    "$(rp /etc)"/zsh* "$(rp /etc)"/bash* "$(rp /etc/profile)" 2>/dev/null | sed "s|^$SRC||" > "$D/shell_rc_suspects.txt"

  log INFO "Capturing SSH state..."
  {
    echo "=== ~/.ssh/ ==="; /bin/ls -la "$(rp "$TARGET_HOME/.ssh")/" 2>/dev/null; echo
    local f
    for f in "$TARGET_HOME/.ssh/authorized_keys" "$TARGET_HOME/.ssh/config" "$TARGET_HOME/.ssh/known_hosts"; do
      [[ -f "$(rp "$f")" ]] || continue
      echo "=== $f ==="; stat_meta "$(rp "$f")"; echo "--- contents ---"; /bin/cat "$(rp "$f")"; echo
    done
  } > "$D/ssh_state.txt"

  run "sudoers"            "$D/sudoers.txt"          -- "cat '$(rp /etc/sudoers)'"
  run "sudoers.d listing"  "$D/sudoers_d_ls.txt"     -- "ls -la '$(rp /etc/sudoers.d)/'"
  run "sudoers.d contents" "$D/sudoers_d.txt"        -- \
    "for f in '$(rp /etc/sudoers.d)'/*; do [ -f \"\$f\" ] && echo === \"\${f#$SRC}\" === && cat \"\$f\"; done"
  run "sudoers NOPASSWD"   "$D/sudoers_nopasswd.txt" -- \
    "grep -rE 'NOPASSWD|ALL=' '$(rp /etc/sudoers)' '$(rp /etc/sudoers.d)/' 2>/dev/null | sed 's|^$SRC||'"
  run "PAM dir listing"    "$D/pam_dir.txt"          -- "ls -la '$(rp /etc/pam.d)/'"
  run "PAM recent mods"    "$D/pam_recent.txt"       -- "find '$(rp /etc/pam.d)' -mtime -${PAM_WINDOW_DAYS} | sed 's|^$SRC||'"
  run "user LoginHook"     "$D/loginhook_user.txt"   -- "sudo -u $TARGET_USER defaults read com.apple.loginwindow LoginHook 2>&1"
  run "user LogoutHook"    "$D/logouthook_user.txt"  -- "sudo -u $TARGET_USER defaults read com.apple.loginwindow LogoutHook 2>&1"
  run "global loginwindow" "$D/loginwindow_global.txt" -- "defaults read /Library/Preferences/com.apple.loginwindow 2>&1"
  run "profiles (user)"    "$D/profiles_user.txt"    -- "sudo -u $TARGET_USER profiles list 2>&1"
  runv "profiles (system)" "$D/profiles_system.txt"  profiles list
  runv "profiles show -all" "$D/profiles_all.txt"    profiles show -all
  run "authdb login"       "$D/authdb_login.txt"     -- "security authorizationdb read system.login.console 2>&1"
  run "Dock persistent"    "$D/dock.txt"             -- \
    "sudo -u $TARGET_USER defaults read com.apple.dock persistent-apps 2>&1 | grep -A2 _CFURLString"

  log INFO "Enumerating browser extensions..."
  {
    local path prof
    for path in \
      "$TARGET_HOME/Library/Application Support/Google/Chrome/Default/Extensions" \
      "$TARGET_HOME/Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions" \
      "$TARGET_HOME/Library/Application Support/Microsoft Edge/Default/Extensions" \
      "$TARGET_HOME/Library/Application Support/Vivaldi/Default/Extensions" \
      "$TARGET_HOME/Library/Application Support/Arc/User Data/Default/Extensions" \
      "$TARGET_HOME/Library/Safari/Extensions"; do
      [[ -d "$(rp "$path")" ]] || continue
      echo "=== $path ==="; /bin/ls -la "$(rp "$path")" 2>/dev/null; echo
    done
    for prof in "$(rp "$TARGET_HOME/Library/Application Support/Firefox/Profiles")"/*(N); do
      [[ -d "$prof/extensions" ]] || continue
      echo "=== ${prof#$SRC}/extensions ==="; /bin/ls -la "$prof/extensions" 2>/dev/null; echo
    done
  } > "$D/browser_extensions.txt"
}

# ============================================================================
# PHASE 4 — Logs / FSEvents / history / TCC
# ============================================================================
phase4_logs() {
  log PHASE "PHASE 4 — Logs, FSEvents, history, TCC"
  local D="$OUT/04_logs"; mkdir -p "$D"

  log INFO "Collecting unified log archive (--last $LOG_LOOKBACK)..."
  /usr/bin/log collect --output "$D/unifiedlog.logarchive" --last "$LOG_LOOKBACK" 2>>"$ERR_FILE" \
    && log OK "unified log archive saved" || log WARN "log collect failed"

  if (( DO_DIAGNOSTICS_TAR )); then
    log INFO "Snapshotting /var/db/diagnostics & uuidtext..."
    /usr/bin/tar -czf "$D/diagnostics_raw.tgz" /var/db/diagnostics /var/db/uuidtext 2>/dev/null \
      && log OK "raw tracev3 saved" || log WARN "diagnostics tar failed"
  fi

  log INFO "Targeted unified log queries..."
  run "log: helper exec"       "$D/log_helper.txt" -- \
    "log show --style syslog --info --last $LOG_LOOKBACK --predicate '(process == \"helper\") OR (eventMessage CONTAINS \"/tmp/helper\") OR (eventMessage CONTAINS \"/tmp/update\")'"
  run "log: shell paste"       "$D/log_shell.txt"  -- \
    "log show --style syslog --info --last $LOG_LOOKBACK --predicate '(process == \"zsh\" OR process == \"Terminal\" OR process == \"iTerm2\" OR process == \"wezterm-gui\") AND (eventMessage CONTAINS \"curl\" OR eventMessage CONTAINS \"base64\" OR eventMessage CONTAINS \"eval\")'"
  run "log: curl"              "$D/log_curl.txt"   -- \
    "log show --style syslog --info --last $LOG_LOOKBACK --predicate 'process == \"curl\"'"
  run "log: osascript"         "$D/log_osascript.txt" -- \
    "log show --style syslog --info --last $LOG_LOOKBACK --predicate 'process == \"osascript\"'"
  run "log: osascript dialogs" "$D/log_osascript_dialog.txt" -- \
    "log show --style syslog --info --last $LOG_LOOKBACK --predicate 'process == \"osascript\" AND (eventMessage CONTAINS \"display dialog\" OR eventMessage CONTAINS \"hidden answer\")'"
  run "log: DNS/mDNS C2"       "$D/log_dns_c2.txt" -- \
    "log show --style syslog --info --last $LOG_LOOKBACK --predicate 'subsystem == \"com.apple.network\" OR subsystem == \"com.apple.mDNSResponder\"' | grep -iE 'faced31|stratos37|homebrew|logmel|tradingviewen|sites-phantom|filmoraus|93\\.152\\.230\\.79|195\\.82\\.147\\.38' || true"
  run "log: keychain"          "$D/log_keychain.txt" -- \
    "log show --style syslog --info --last $LOG_LOOKBACK --predicate 'subsystem == \"com.apple.securityd\" OR process == \"security\"'"
  run "log: Gatekeeper"        "$D/log_gatekeeper.txt" -- \
    "log show --style syslog --info --last $LOG_LOOKBACK --predicate 'process == \"syspolicyd\" OR process == \"amfid\" OR subsystem == \"com.apple.syspolicy\" OR subsystem == \"com.apple.xprotect\"'"
  run "log: TCC"               "$D/log_tcc.txt"    -- \
    "log show --style syslog --info --last $LOG_LOOKBACK --predicate 'subsystem == \"com.apple.TCC\" OR process == \"tccd\"'"

  log INFO "Snapshotting TCC databases..."
  /usr/bin/sqlite3 "$(rp "$TARGET_HOME/Library/Application Support/com.apple.TCC/TCC.db")" \
    "SELECT client,service,auth_value,datetime(last_modified,'unixepoch') ts FROM access ORDER BY last_modified DESC;" \
    > "$D/tcc_user.txt" 2>>"$ERR_FILE"
  /usr/bin/sqlite3 "$(rp "/Library/Application Support/com.apple.TCC/TCC.db")" \
    "SELECT client,service,auth_value,datetime(last_modified,'unixepoch') ts FROM access ORDER BY last_modified DESC;" \
    > "$D/tcc_system.txt" 2>>"$ERR_FILE"
  safe_cp "$(rp "$TARGET_HOME/Library/Application Support/com.apple.TCC/TCC.db")" "$D/TCC_user.db"
  safe_cp "$(rp "/Library/Application Support/com.apple.TCC/TCC.db")" "$D/TCC_system.db"

  /bin/ls -la /.fseventsd/ > "$D/fseventsd_list.txt" 2>>"$ERR_FILE"
  if (( DO_FSEVENTS_TAR )); then
    /usr/bin/tar -czf "$D/fseventsd_raw.tgz" /.fseventsd 2>/dev/null \
      && log OK "FSEvents snapshot saved" || log WARN "fseventsd tar failed (SIP?)"
  fi

  log INFO "Extracting FSEvents strings..."
  local strings_cmd
  if (( $+commands[strings] )); then strings_cmd=(/usr/bin/strings); else strings_cmd=(tr -cd '[:print:]\n'); fi
  /usr/bin/find /.fseventsd -type f -mtime -${CHANGE_WINDOW_DAYS} 2>/dev/null | head -${FSEVENTS_FILE_LIMIT} | \
    while read -r f; do /usr/bin/gunzip -c "$f" 2>/dev/null; done | "${strings_cmd[@]}" | /usr/bin/sort -u > "$D/fseventsd_strings.txt"
  /usr/bin/grep -iE '/tmp/helper|/fg/|osalogging|wallet|keychain|Cookies|/Users/Shared' \
    "$D/fseventsd_strings.txt" > "$D/fseventsd_iocs.txt" 2>/dev/null

  log INFO "Capturing shell histories..."
  {
    local h
    for h in "$TARGET_HOME/.zsh_history" "$TARGET_HOME/.zhistory" \
             "$TARGET_HOME/.bash_history" "$TARGET_HOME/.history" \
             "$TARGET_HOME/.local/share/fish/fish_history"; do
      [[ -f "$(rp "$h")" ]] || continue
      echo "=== FILE: $h ==="; stat_meta "$(rp "$h")"
      echo "--- contents (last ${HISTORY_TAIL_LINES} lines) ---"; /usr/bin/tail -${HISTORY_TAIL_LINES} "$(rp "$h")"; echo
    done
  } > "$D/shell_histories.txt"
  safe_cp "$(rp "$TARGET_HOME/.zsh_history")"  "$D/raw_zsh_history"
  safe_cp "$(rp "$TARGET_HOME/.bash_history")" "$D/raw_bash_history"
  /usr/bin/grep -nE 'curl.*\|.*zsh|curl.*\|.*bash|base64.*-[dD]|brewe?\.sh|brew\.org|brew\.click' \
    "$(rp "$TARGET_HOME/.zsh_history")" "$(rp "$TARGET_HOME/.bash_history")" 2>/dev/null | sed "s|^$SRC||" > "$D/paste_evidence.txt"

  run "QuickLook cache" "$D/quicklook.txt" -- "ls -la '$(rp "$TARGET_HOME/Library/Application Support/Quick Look")/' 2>&1"

  log INFO "Spotlight metadata (LIVE)..."
  /usr/bin/mdfind -onlyin /tmp 'kMDItemFSCreationDate >= $time.this_week' > "$D/mdfind_tmp.txt" 2>/dev/null
  sudo -u "$TARGET_USER" /usr/bin/mdfind -onlyin "$TARGET_HOME" 'kMDItemFSCreationDate >= $time.this_week' > "$D/mdfind_home.txt" 2>/dev/null
}

# ============================================================================
# PHASE 5 — Credential blast radius (all reads via $SRC)
# ============================================================================
phase5_secrets() {
  log PHASE "PHASE 5 — Credential blast radius"
  local D="$OUT/05_secrets"; mkdir -p "$D"
  log WARN "Enumerates secret LOCATIONS + atimes, NOT contents."

  run "Keychain list" "$D/keychains_list.txt" -- "sudo -u $TARGET_USER security list-keychains"
  sudo -u "$TARGET_USER" /usr/bin/security dump-keychain 2>/dev/null \
    | /usr/bin/awk '/"svce"|"acct"|0x00000007/ {print}' | /usr/bin/sort -u > "$D/keychain_items_NAMES_ONLY.txt"

  log INFO "Browser credential store metadata..."
  {
    echo "# atime > infection time + user not in browser => malware read it."; echo
    local bp f p prof
    for bp in \
      "$TARGET_HOME/Library/Application Support/Google/Chrome/Default" \
      "$TARGET_HOME/Library/Application Support/BraveSoftware/Brave-Browser/Default" \
      "$TARGET_HOME/Library/Application Support/Microsoft Edge/Default" \
      "$TARGET_HOME/Library/Application Support/Chromium/Default" \
      "$TARGET_HOME/Library/Application Support/Arc/User Data/Default" \
      "$TARGET_HOME/Library/Application Support/Vivaldi/Default" \
      "$TARGET_HOME/Library/Application Support/com.operasoftware.Opera" \
      "$TARGET_HOME/Library/Application Support/com.operasoftware.OperaGX"; do
      [[ -d "$(rp "$bp")" ]] || continue
      echo "=== BROWSER: $bp ==="
      for f in 'Login Data' 'Cookies' 'Web Data' 'History' 'Local State' 'Local Extension Settings' 'IndexedDB'; do
        p="$(rp "$bp/$f")"; [[ -e "$p" ]] && { stat_meta "$p"; echo; }
      done
    done
    for prof in "$(rp "$TARGET_HOME/Library/Application Support/Firefox/Profiles")"/*(N); do
      [[ -d "$prof" ]] || continue
      echo "=== FIREFOX: ${prof#$SRC} ==="
      for f in logins.json key4.db cookies.sqlite places.sqlite; do
        [[ -e "$prof/$f" ]] && { stat_meta "$prof/$f"; echo; }
      done
    done
    echo "=== SAFARI ==="
    for f in \
      "$TARGET_HOME/Library/Safari/Cookies.binarycookies" \
      "$TARGET_HOME/Library/Cookies/Cookies.binarycookies" \
      "$TARGET_HOME/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies" \
      "$TARGET_HOME/Library/Safari/History.db" \
      "$TARGET_HOME/Library/Keychains/login.keychain-db"; do
      p="$(rp "$f")"; [[ -e "$p" ]] && { stat_meta "$p"; echo; }
    done
  } > "$D/browser_credstores.txt"

  log INFO "Crypto wallet inspection..."
  {
    local w sw f
    for w in \
      "$TARGET_HOME/Library/Application Support/Electrum" \
      "$TARGET_HOME/Library/Application Support/Exodus" \
      "$TARGET_HOME/Library/Application Support/Coinomi" \
      "$TARGET_HOME/Library/Application Support/Atomic" \
      "$TARGET_HOME/Library/Application Support/Wasabi Wallet" \
      "$TARGET_HOME/Library/Application Support/Ledger Live" \
      "$TARGET_HOME/Library/Application Support/@trezor" \
      "$TARGET_HOME/Library/Application Support/Bitcoin" \
      "$TARGET_HOME/Library/Application Support/Ethereum" \
      "$TARGET_HOME/Library/Application Support/Monero" \
      "$TARGET_HOME/Library/Application Support/Binance" \
      "$TARGET_HOME/Library/Application Support/Tron" \
      "$TARGET_HOME/Library/Containers/com.electrum.electrum" \
      "$TARGET_HOME/.electrum" "$TARGET_HOME/.bitcoin" "$TARGET_HOME/.ethereum"; do
      sw="$(rp "$w")"; [[ -e "$sw" ]] || continue
      echo "=== WALLET: $w ==="; /bin/ls -la "$sw" 2>/dev/null
      /usr/bin/find "$sw" -type f \( -name '*wallet*' -o -name '*keys*' -o -name '*seed*' \
        -o -name '*.json' -o -name '*.dat' \) 2>/dev/null | while read -r f; do stat_meta "$f"; echo; done
    done
    local browser base id name p
    for browser in Chrome 'BraveSoftware/Brave-Browser' 'Microsoft Edge' Vivaldi; do
      base="$(rp "$TARGET_HOME/Library/Application Support/$browser/Default/Local Extension Settings")"
      [[ -d "$base" ]] || continue
      for id name in ${(kv)EXT_WALLETS}; do
        p="$base/$id"; [[ -d "$p" ]] || continue
        echo "=== EXT WALLET: $name ($id) in $browser ==="; /bin/ls -la "$p"
        /usr/bin/find "$p" -type f 2>/dev/null | while read -r f; do stat_meta "$f"; echo; done
      done
    done
  } > "$D/wallets.txt"

  log INFO "Developer secrets inspection..."
  {
    local f sf
    for f in \
      "$TARGET_HOME/.ssh"/id_* "$TARGET_HOME/.ssh/known_hosts" "$TARGET_HOME/.ssh/config" \
      "$TARGET_HOME/.aws/credentials" "$TARGET_HOME/.aws/config" "$TARGET_HOME/.aws/sso/cache"/* \
      "$TARGET_HOME/.azure"/* "$TARGET_HOME/.config/gcloud"/* "$TARGET_HOME/.config/gh/hosts.yml" \
      "$TARGET_HOME/.kube/config" "$TARGET_HOME/.docker/config.json" "$TARGET_HOME/.docker/contexts"/* \
      "$TARGET_HOME/.netrc" "$TARGET_HOME/.npmrc" "$TARGET_HOME/.yarnrc" "$TARGET_HOME/.pypirc" \
      "$TARGET_HOME/.cargo/credentials"* "$TARGET_HOME/.gitconfig" "$TARGET_HOME/.git-credentials" \
      "$TARGET_HOME/.gnupg"/* "$TARGET_HOME/.config/op"/* "$TARGET_HOME/.1password"/* \
      "$TARGET_HOME/Library/Application Support/Slack/storage"/* \
      "$TARGET_HOME/Library/Application Support/discord/Local Storage"/* \
      "$TARGET_HOME/Library/Application Support/Code/User/globalStorage"/* \
      "$TARGET_HOME/Library/Application Support/JetBrains"/*/options/security.xml; do
      sf="$(rp "$f")"; [[ -e "$sf" ]] || continue
      stat_meta "$sf"; echo
    done
  } > "$D/dev_secrets.txt"

  log INFO "Apple Notes inspection..."
  {
    local nd="$(rp "$TARGET_HOME/Library/Group Containers/group.com.apple.notes")"
    if [[ -d "$nd" ]]; then
      /bin/ls -la "$nd/"; echo
      local f; for f in "$nd/NoteStore.sqlite"*; do [[ -e "$f" ]] && { stat_meta "$f"; echo; }; done
    fi
  } > "$D/notes.txt"

  run "iCloud Keychain sync" "$D/icloud_kc.txt" -- "sudo -u $TARGET_USER defaults read MobileMeAccounts 2>&1 | grep -A2 KEYCHAIN_SYNC"

  log INFO "Password manager inspection..."
  {
    local pm spm
    for pm in \
      "$TARGET_HOME/Library/Containers/com.agilebits.onepassword7" \
      "$TARGET_HOME/Library/Containers/com.1password.1password" \
      "$TARGET_HOME/Library/Application Support/Bitwarden" \
      "$TARGET_HOME/Library/Application Support/dashlane" \
      "$TARGET_HOME/Library/Application Support/keeper" \
      "$TARGET_HOME/Library/Application Support/com.lastpass.LastPass"; do
      spm="$(rp "$pm")"; [[ -e "$spm" ]] || continue
      echo "=== $pm ==="; /bin/ls -la "$spm" 2>/dev/null; echo
    done
  } > "$D/password_managers.txt"
}

# ============================================================================
# PHASE 6 — Additional Mach-O sweep
# ============================================================================
phase6_samples() {
  log PHASE "PHASE 6 — Additional Mach-O sample collection"
  local D="$OUT/06_samples"; mkdir -p "$D"
  log INFO "Final sweep of suspect binary locations..."
  /usr/bin/find \
    "$(rp "$TARGET_HOME/Library/Application Support")" \
    "$(rp "$TARGET_HOME/.config")" "$(rp "$TARGET_HOME/.local")" \
    "${SRC}/Users/Shared" "${SRC}/opt" "${SRC}/tmp" "${SRC}/private/tmp" "${SRC}/var/tmp" \
    -xdev -type f -size -${MACHO_MAX_SIZE} 2>/dev/null | while read -r f; do
      local out sig
      out=$(/usr/bin/file -b "$f" 2>/dev/null)
      case "$out" in
        Mach-O*)
          sig=$(/usr/bin/codesign -dv "$f" 2>&1)
          if echo "$sig" | /usr/bin/grep -qE 'adhoc|revoked|not signed|invalid'; then
            echo "SUSPECT: ${f#$SRC}"; echo "  type: $out"; echo "$sig" | /usr/bin/sed 's/^/  sig: /'; echo
          fi ;;
      esac
  done > "$D/suspect_unsigned_machos.txt"
}

# ============================================================================
# PHASE 7 — System metadata (LIVE)
# ============================================================================
phase7_sysmeta() {
  log PHASE "PHASE 7 — System metadata & security posture"
  local D="$OUT/07_sysmeta"; mkdir -p "$D"
  runv "macOS version"   "$D/sw_vers.txt"        sw_vers
  runv "Kernel version"  "$D/uname.txt"          uname -a
  run  "Hardware info"   "$D/hardware.txt"       -- "system_profiler SPHardwareDataType"
  run  "Software info"   "$D/software.txt"       -- "system_profiler SPSoftwareDataType"
  run  "Installed apps"  "$D/installed_apps.txt" -- "system_profiler SPApplicationsDataType -detailLevel mini"
  run  "XProtect ver"    "$D/xprotect_version.txt" -- \
    "defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist CFBundleShortVersionString 2>&1"
  run  "XProtect Remediator" "$D/xprotect_remediator.txt" -- \
    "ls -la /Library/Apple/System/Library/CoreServices/XProtect.app 2>&1; defaults read /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist 2>&1"
  run  "MRT ver"         "$D/mrt_version.txt"    -- "defaults read /Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist 2>&1"
  run  "Gatekeeper"      "$D/gatekeeper.txt"     -- "spctl --status"
  run  "SIP status"      "$D/sip_status.txt"     -- "csrutil status"
  run  "AMFI boot args"  "$D/amfi.txt"           -- "nvram boot-args 2>&1"
  run  "MDM profiles"    "$D/mdm.txt"            -- "profiles status -type enrollment 2>&1"
  run  "FileVault"       "$D/filevault.txt"      -- "fdesetup status 2>&1"
  run  "App firewall"    "$D/firewall.txt"       -- \
    "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>&1; /usr/libexec/ApplicationFirewall/socketfilterfw --listapps 2>&1"
  run  "Disk list"       "$D/diskutil.txt"       -- "diskutil list"
  run  "APFS info"       "$D/apfs.txt"           -- "diskutil apfs list"
  run  "df"              "$D/df.txt"             -- "df -h"
  (( DO_POWERMETRICS )) && run "powermetrics" "$D/powermetrics.txt" -- \
    "powermetrics -i 1 -n 1 --samplers all 2>&1 | head -${VMMAP_HEAD_LINES}"
}

# ============================================================================
# PHASE 8 — Finalize
# ============================================================================
phase8_finalize() {
  log PHASE "PHASE 8 — Finalize: IOC sweep, manifest, bundle"
  local D="$OUT/08_final"; mkdir -p "$D"

  log INFO "Sweeping collected data for IOCs (fixed-string)..."
  {
    echo "# IOC hit report — generated $(ts)"; echo
    local ioc
    for ioc in "${IOC_STRINGS[@]}"; do
      echo "=== IOC: $ioc ==="
      /usr/bin/grep -rInF --binary-files=without-match \
        --exclude-dir=_meta --exclude='ioc_hits.txt' -- "$ioc" "$OUT" 2>/dev/null | head -${IOC_HIT_LIMIT}
      echo
    done
  } > "$D/ioc_hits.txt"
  local hit_count
  hit_count=$(/usr/bin/grep -cE '^[^#=[:space:]].*:[0-9]+:' "$D/ioc_hits.txt" 2>/dev/null); hit_count=${hit_count:-0}
  (( hit_count > 0 )) && log WARN "IOC hits: $hit_count lines — see 08_final/ioc_hits.txt" \
                      || log INFO "No IOC string hits (NOT proof of clean)"

  cat > "$D/COMPROMISE_DEPTH.md" <<EOF
# Compromise Depth Assessment — ${CASE_ID}
Generated: $(ts)

## Indicator checklist
- [ ] Stage-1 zsh wrapper executed (\`04_logs/log_shell.txt\`, \`paste_evidence.txt\`)
- [ ] Stage-2 beacon (\`04_logs/log_curl.txt\`, \`log_dns_c2.txt\`)
- [ ] /tmp/helper downloaded (\`02_disk/known_paths.txt\`)
- [ ] /tmp/helper executed (\`04_logs/log_helper.txt\`)
- [ ] password dialog (\`04_logs/log_osascript_dialog.txt\`)
- [ ] Keychain access by non-Apple proc (\`04_logs/log_keychain.txt\`)
- [ ] exfil POST (\`04_logs/log_curl.txt\`)
- [ ] persistence plist (\`03_persistence/launchd_plists_inspected.txt\`)
- [ ] sensitive atimes in window (\`05_secrets/*\`)

## Classification
| Pattern | Match? |
|---|---|
| Beacon only | |
| Stage-3 ran, no password capture | |
| Full compromise (Keychain captured) | |
| Persistent foothold | |
EOF

  log INFO "Building SHA-256 manifest..."
  ( cd "$OUT" && /usr/bin/find . -type f ! -path "./_meta/MANIFEST.sha256" -exec /usr/bin/shasum -a 256 {} + ) > "$MANIFEST"
  local file_count total_size
  file_count=$(/usr/bin/wc -l < "$MANIFEST"); file_count=${file_count// /}
  total_size=$(/usr/bin/du -sh "$OUT" | awk '{print $1}')
  log OK "Manifest: ${file_count} files, ${total_size}"

  cat > "$OUT/README.md" <<EOF
# IR Evidence Bundle — ${CASE_ID}
**Collected:** $(ts)  **Host:** $(hostname)  **User:** ${TARGET_USER}
**Version:** ${SCRIPT_VERSION}  **Lookback:** ${LOG_LOOKBACK}
**Read source:** $( [[ -n "$SRC" ]] && echo "read-only APFS snapshot (atime preserved)" || echo "LIVE filesystem (atime altered)" )
**Config:** ${_IR_CONFIG_LOADED:+$IR_CONFIG}${_IR_CONFIG_LOADED:-built-in defaults}  **Phases:** ${PHASES}

Verify: \`cd ${CASE_ID} && shasum -a 256 -c _meta/MANIFEST.sha256\`
Custody: full command log in \`_meta/run.log\`; errors in \`_meta/run.err\`.
EOF

  unmount_snapshot

  if (( DO_BUNDLE )); then
    log INFO "Creating compressed bundle..."
    local elapsed=$(( EPOCHSECONDS - SCRIPT_START_EPOCH ))
    log INFO "Total collection time: ${elapsed}s"
    if ! cd "$EVIDENCE_BASE"; then log ERR "cd $EVIDENCE_BASE failed — no bundle"; return 1; fi
    /usr/bin/tar -czf "${CASE_ID}.tar.gz" "$CASE_ID" 2>>"$ERR_FILE"
    /usr/bin/shasum -a 256 "${CASE_ID}.tar.gz" > "${CASE_ID}.tar.gz.sha256"
    log OK "Bundle: ${EVIDENCE_BASE}/${CASE_ID}.tar.gz"
    cat "${CASE_ID}.tar.gz.sha256"
  else
    log INFO "DO_BUNDLE=0 — output left uncompressed at $OUT"
  fi
}

# ============================================================================
# Main
# ============================================================================
main() {
  # Dry-run: show resolved plan and exit before any side effect.
  if (( $#o_dryrun )); then print_plan; exit 0; fi

  printf "\n%s macOS IR Evidence Collector v%s — Odyssey/AMOS %s\n\n" "$CW" "$SCRIPT_VERSION" "$CN"
  trap 'unmount_snapshot' EXIT INT TERM

  preflight
  phase_enabled 0 && phase0_freeze
  phase_enabled 1 && phase1_volatile
  phase_enabled 2 && phase2_disk
  phase_enabled 3 && phase3_persistence
  phase_enabled 4 && phase4_logs
  phase_enabled 5 && phase5_secrets
  phase_enabled 6 && phase6_samples
  phase_enabled 7 && phase7_sysmeta
  phase_enabled 8 && phase8_finalize

  printf "\n%s COLLECTION COMPLETE%s\n" "$CG" "$CN"
  printf " Output:   %s%s%s\n" "$CW" "$OUT" "$CN"
  (( DO_BUNDLE )) && printf " Bundle:   %s%s/%s.tar.gz%s\n" "$CW" "$EVIDENCE_BASE" "$CASE_ID" "$CN"
  printf " Run log:  %s%s%s\n\n" "$CW" "$LOG_FILE" "$CN"
}

main "$@"
