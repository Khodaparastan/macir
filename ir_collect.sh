#!/bin/zsh
# ============================================================================
# ir_collect.sh — macOS Incident Response Evidence Collector
# ----------------------------------------------------------------------------
# Target:     Network-isolated macOS host (Ventura+ / Sonoma / Sequoia)
# Threat:     Odyssey / Poseidon / AMOS macOS infostealer (ClickFix delivery)
# Author:     Khodaparastan
# Version:    2.0  (2026-06-12)   forensically-sound rewrite
# Invocation: sudo -E ./ir_collect.sh
#
# Phases:
#   0 Freeze & metadata (+ read-only APFS snapshot mount)
#   1 Volatile process / network state (LIVE)
#   2 On-disk staging & dropped artifacts        (via snapshot)
#   3 Persistence enumeration                     (files via snapshot; runtime live)
#   4 Unified log, FSEvents, shell history, TCC   (log/FSEvents live; reads via snapshot)
#   5 Credential & secret blast-radius            (via snapshot — atime preserved)
#   6 Mach-O sample sweep                         (via snapshot)
#   7 System metadata & security posture          (LIVE)
#   8 Finalize: IOC sweep, manifest, bundle
#
# Output preserved hashed (SHA-256), bundled as <CASE_ID>.tar.gz
# ============================================================================

set -u
setopt PIPE_FAIL EXTENDED_GLOB NULL_GLOB
zmodload zsh/datetime          # $EPOCHREALTIME + strftime, fork-free

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------
SCRIPT_VERSION="2.0"
SCRIPT_START_EPOCH=$EPOCHSECONDS

CASE_ID="${CASE_ID:-IR-$(TZ=UTC strftime '%Y%m%d-%H%M%S' $EPOCHSECONDS)-$(hostname -s)}"
EVIDENCE_BASE="${EVIDENCE_BASE:-/Volumes/IR}"
LOG_LOOKBACK="${LOG_LOOKBACK:-14d}"
TARGET_USER="${TARGET_USER:-${SUDO_USER:-$USER}}"
TARGET_HOME="$(/usr/bin/dscl . -read "/Users/${TARGET_USER}" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
[[ -z "$TARGET_HOME" || ! -d "$TARGET_HOME" ]] && TARGET_HOME="/Users/${TARGET_USER}"

OUT="${EVIDENCE_BASE}/${CASE_ID}"
META="${OUT}/_meta"
LOG_FILE="${META}/run.log"
ERR_FILE="${META}/run.err"
MANIFEST="${META}/MANIFEST.sha256"

# SRC = root prefix for ON-DISK reads. Set to the snapshot mountpoint once mounted
# so that reading evidence (file/cat/stat/hash) never updates atime on the LIVE fs.
SRC=""                          # "" means live "/"
SNAP_MNT="${OUT}/_snapshot_root"

SCRIPT_START_ISO="$(TZ=UTC strftime '%Y-%m-%dT%H:%M:%SZ' $EPOCHSECONDS)"

# Known IOCs for in-collection sweep (matched as FIXED strings)
IOC_STRINGS=(
  "faced31.com" "stratos37.com"
  "homebrewclubs.org" "homebrewfaq.org" "homebrewonline.org" "homebrewupdate.org"
  "Homebrewlub.com" "logmeln.com" "logmeeine.com" "tradingviewen.com"
  "sites-phantom.com" "filmoraus.com"
  "93.152.230.79" "195.82.147.38"
  "Kgvte6N4Ab73QPUcm-3iajAe2K8dLrWEzsysY8YZ3xQ"
  "ipbGT_eh94rq6jM2djVvrJLF7eC1_HFhhXRh6rlQVCE"
  "setup-555549446b661f7073483a219ad86bf9c0312e89"
  "ab15698009e532f4735792cd06a793f618769121"
  "498d82aab2ce9fc2ec1e7358d0aa83d8e02a031ac4a177549d07a26262c5193c"
  "xll1reccl6ecroh4" "/tmp/helper" "osalogging.zip" "expand 32-byte k"
  "com.finder.helper" "homebrew/update" "api/metrics/run"
)

# ----------------------------------------------------------------------------
# Colors & helpers
# ----------------------------------------------------------------------------
if [[ -t 1 ]]; then
  CR=$'\033[0;31m'; CG=$'\033[0;32m'; CY=$'\033[0;33m'
  CB=$'\033[0;34m'; CC=$'\033[0;36m'; CW=$'\033[1;37m'; CN=$'\033[0m'
else
  CR=''; CG=''; CY=''; CB=''; CC=''; CW=''; CN=''
fi

# Millisecond UTC timestamp — fork-free, BSD-date-independent.
ts() {
  local now=$EPOCHREALTIME           # e.g. 1765540000.123456
  local frac="${now#*.}"; frac="${(r:3::0:)frac}"   # pad/trim to 3 digits
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

# Resolve an absolute live path to its snapshot-backed copy (atime-safe).
rp() { print -r -- "${SRC}$1"; }

# run <desc> <out|""> -- <shell string...>   (eval; for pipelines/redirs/globs)
run() {
  local desc="$1"; shift
  local out="$1"; shift
  [[ "${1:-}" == "--" ]] && shift
  local cmd="$*"
  log INFO "→ $desc"
  printf "\n### [%s] %s\n### cmd: %s\n" "$(ts)" "$desc" "$cmd" >> "$LOG_FILE"
  local rc=0
  if [[ -n "$out" ]]; then
    mkdir -p "${out:h}"
    eval "$cmd" > "$out" 2>> "$ERR_FILE" || rc=$?
  else
    eval "$cmd" >> "$LOG_FILE" 2>> "$ERR_FILE" || rc=$?
  fi
  printf "### exit=%d\n" "$rc" >> "$LOG_FILE"
  (( rc )) && log WARN "  (exit=$rc) $desc — see run.err"
  return 0
}

# runv <desc> <out|""> <argv...>   (no eval — quoting-safe, fork-free)
runv() {
  local desc="$1" out="$2"; shift 2
  log INFO "→ $desc"
  printf "\n### [%s] %s\n### argv: %s\n" "$(ts)" "$desc" "${(q)*}" >> "$LOG_FILE"
  local rc=0
  if [[ -n "$out" ]]; then
    mkdir -p "${out:h}"
    "$@" > "$out" 2>> "$ERR_FILE" || rc=$?
  else
    "$@" >> "$LOG_FILE" 2>> "$ERR_FILE" || rc=$?
  fi
  printf "### exit=%d\n" "$rc" >> "$LOG_FILE"
  (( rc )) && log WARN "  (exit=$rc) $desc — see run.err"
  return 0
}

# safe_cp <src> <dst>  — copy preserving metadata, no symlink follow.
safe_cp() {
  local src="$1" dst="$2"
  [[ -e "$src" || -L "$src" ]] || { log WARN "skip (missing): $src"; return 0; }
  mkdir -p "${dst:h}"
  if /bin/cp -pPR "$src" "$dst" 2>>"$ERR_FILE"; then
    log OK "copied: $src"
  else
    log WARN "cp failed: $src"
  fi
}

# stat_meta <file> — timestamps + size + xattrs + hash, without "opening" via app.
stat_meta() {
  local f="$1"
  [[ -e "$f" || -L "$f" ]] || { echo "MISSING: $f"; return; }
  /usr/bin/stat -f 'path=%N inode=%i mode=%Sp uid=%u(%Su) gid=%g(%Sg) size=%z blocks=%b atime=%Sa mtime=%Sm ctime=%Sc btime=%SB' \
    -t '%Y-%m-%dT%H:%M:%SZ' "$f" 2>/dev/null
  /usr/bin/xattr -l "$f" 2>/dev/null | sed 's/^/  xattr: /'
  /usr/bin/shasum -a 256 "$f" 2>/dev/null | sed 's/^/  sha256: /'
}

# ----------------------------------------------------------------------------
# Preflight
# ----------------------------------------------------------------------------
preflight() {
  log PHASE "PREFLIGHT"

  if [[ $EUID -ne 0 ]]; then
    log ERR "Must run as root (use: sudo -E $0)"; exit 1
  fi
  if [[ ! -d "$EVIDENCE_BASE" ]]; then
    log ERR "EVIDENCE_BASE not found: $EVIDENCE_BASE"
    log ERR "Mount external media and re-run with EVIDENCE_BASE=/Volumes/<name>"; exit 1
  fi

  local base_dev root_dev
  base_dev=$(/bin/df "$EVIDENCE_BASE" | awk 'NR==2{print $1}')
  root_dev=$(/bin/df / | awk 'NR==2{print $1}')
  if [[ "$base_dev" == "$root_dev" ]]; then
    log ERR "EVIDENCE_BASE is on the local boot volume — refusing. Use external media."; exit 1
  fi

  local avail_gb
  avail_gb=$(/bin/df -g "$EVIDENCE_BASE" | awk 'NR==2{print $4}'); avail_gb=${avail_gb:-0}
  log INFO "Available space on $EVIDENCE_BASE: ${avail_gb}G"
  (( avail_gb < 10 )) && log WARN "Less than 10G free; collection may be incomplete"

  mkdir -p "$OUT" "$META" || { log ERR "Cannot create $OUT"; exit 1; }
  : >| "$LOG_FILE"; : >| "$ERR_FILE"; : >| "$MANIFEST"

  log INFO "Case ID:        $CASE_ID"
  log INFO "Output:         $OUT"
  log INFO "Target user:    $TARGET_USER"
  log INFO "Target home:    $TARGET_HOME"
  log INFO "Log lookback:   $LOG_LOOKBACK"
  log INFO "Script version: $SCRIPT_VERSION"
  log INFO "Start (UTC):    $SCRIPT_START_ISO"
}

# ============================================================================
# PHASE 0 — Freeze, metadata, read-only snapshot mount
# ============================================================================
phase0_freeze() {
  log PHASE "PHASE 0 — Freeze & metadata"
  local D="$OUT/00_freeze"; mkdir -p "$D"

  runv "Wall clock UTC"          "$D/clock_utc.txt"        date -u
  runv "Wall clock local"        "$D/clock_local.txt"      date
  runv "Uptime"                  "$D/uptime.txt"           uptime
  runv "Kernel boot time"        "$D/boottime.txt"         sysctl kern.boottime
  runv "Hostname"                "$D/hostname.txt"         hostname
  runv "id"                      "$D/id.txt"               id
  runv "logged-in sessions"      "$D/who.txt"              who
  runv "active terminals (w)"    "$D/w.txt"                w
  runv "ifconfig"                "$D/ifconfig.txt"         ifconfig
  runv "network services"        "$D/network_services.txt" /usr/sbin/networksetup -listallnetworkservices

  # Take APFS local snapshot, then mount it read-only as the atime-safe SRC root.
  log INFO "Taking APFS local snapshot..."
  if /usr/bin/tmutil localsnapshot 2>>"$ERR_FILE"; then
    log OK "Local APFS snapshot created"
  else
    log WARN "tmutil localsnapshot failed (Time Machine disabled?)"
  fi
  runv "List local snapshots"    "$D/apfs_snapshots.txt"   /usr/bin/tmutil listlocalsnapshots /

  mount_ro_snapshot
}

# Mount most-recent APFS local snapshot read-only; set SRC on success.
mount_ro_snapshot() {
  local snap
  snap=$(/usr/bin/tmutil listlocalsnapshots / 2>/dev/null | /usr/bin/tail -1 | /usr/bin/sed 's/.*\.//')
  if [[ -z "$snap" ]]; then
    log WARN "No local snapshot — on-disk reads will hit LIVE fs (atime WILL be altered)"
    return 1
  fi
  mkdir -p "$SNAP_MNT"
  if /sbin/mount_apfs -o ro,nobrowse -s "com.apple.TimeMachine.${snap}.local" / "$SNAP_MNT" 2>>"$ERR_FILE"; then
    SRC="$SNAP_MNT"
    log OK "Snapshot mounted read-only at $SNAP_MNT — disk reads are atime-safe"
  else
    log WARN "mount_apfs failed — on-disk reads will hit LIVE fs (atime WILL be altered)"
    return 1
  fi
}

unmount_snapshot() {
  [[ -n "$SRC" ]] || return 0
  /sbin/umount "$SNAP_MNT" 2>>"$ERR_FILE" && log OK "Snapshot unmounted" || log WARN "umount $SNAP_MNT failed"
  rmdir "$SNAP_MNT" 2>/dev/null
}

# ============================================================================
# PHASE 1 — Volatile state (LIVE: must reflect running system)
# ============================================================================
phase1_volatile() {
  log PHASE "PHASE 1 — Volatile state"
  local D="$OUT/01_volatile"; mkdir -p "$D"

  runv "Process tree (wide)"  "$D/ps_full.txt"  ps -Axwwo pid,ppid,uid,user,start,etime,stat,command
  runv "Process tree parent"  "$D/ps_tree.txt"  ps -Axwwo pid,ppid,command
  runv "Process wchan"        "$D/ps_wchan.txt" ps -Axwwo pid,ppid,wchan,command
  run  "pgrep suspects"       "$D/pgrep_suspects.txt" -- \
    'for p in helper osascript curl zsh dscl security zip xattr; do echo "=== $p ==="; pgrep -alf "$p" 2>/dev/null; done'

  runv "lsof network"         "$D/lsof_net.txt" lsof -nP -i
  runv "lsof all files"       "$D/lsof_all.txt" lsof -nP
  run  "lsof known-bad paths" "$D/lsof_tmp.txt" -- \
    "lsof -nP 2>/dev/null | grep -E '/tmp/|/Users/Shared/|/private/tmp/'"

  runv "netstat all"          "$D/netstat_all.txt" netstat -anv
  runv "netstat routes"       "$D/route.txt"       netstat -rn
  runv "ARP table"            "$D/arp.txt"         arp -an
  runv "resolver state"       "$D/resolv.txt"      scutil --dns
  runv "proxy config"         "$D/proxies.txt"     scutil --proxy
  runv "pf ruleset"           "$D/pf_rules.txt"    pfctl -sr
  runv "pf full state"        "$D/pf_all.txt"      pfctl -sa
  runv "Loaded kexts"         "$D/kextstat.txt"    kextstat -l
  runv "System extensions"    "$D/systemextensions.txt" systemextensionsctl list

  log INFO "Enumerating suspect process details..."
  local suspect_pids
  suspect_pids=$(ps -Axwwo pid,command | awk '
    /\/tmp\/|\/private\/tmp\/|\/Users\/Shared\/|\/\.[a-z0-9]/ && $0 !~ /ir_collect/ {print $1}' | sort -u)
  if [[ -n "$suspect_pids" ]]; then
    {
      echo "=== Suspect PIDs (running from non-standard paths) ==="
      echo "$suspect_pids"; echo
      local pid
      for pid in ${(f)suspect_pids}; do
        echo "================================"; echo "=== PID $pid ==="; echo "================================"
        ps -o pid,ppid,uid,user,start,etime,command -p "$pid" 2>/dev/null
        echo "--- lsof ---";          lsof -p "$pid" -nP 2>/dev/null
        echo "--- vmmap summary ---"; vmmap -summary "$pid" 2>/dev/null | head -100
      done
    } > "$D/suspect_processes.txt"
    log WARN "Suspect processes found — see suspect_processes.txt"
  else
    echo "No suspect processes located" > "$D/suspect_processes.txt"
  fi
}

# ============================================================================
# PHASE 2 — On-disk staging & dropped artifacts (reads via $SRC snapshot)
# ============================================================================
phase2_disk() {
  log PHASE "PHASE 2 — On-disk staging & artifacts"
  local D="$OUT/02_disk"; mkdir -p "$D/captured_samples"

  log INFO "Checking known-bad artifact paths..."
  local known_paths=(
    /tmp/helper /tmp/.helper /tmp/update /tmp/installer
    /tmp/osalogging.zip /tmp/out.zip /tmp/out /tmp/archive.zip
    /tmp/list /tmp/system_info.txt
    /private/tmp/helper /private/tmp/osalogging.zip
    /var/tmp/helper /var/tmp/out.zip
    /Users/Shared/helper /Users/Shared/.helper
    "$TARGET_HOME/fg" "$TARGET_HOME/.fg"
    "$TARGET_HOME/Library/Caches/helper"
    "$TARGET_HOME/.helper" "$TARGET_HOME/.config/helper"
    "$TARGET_HOME/Library/LaunchAgents/com.finder.helper.plist"
    /Library/LaunchAgents/com.finder.helper.plist
    /Library/LaunchDaemons/com.finder.helper.plist
    "$TARGET_HOME/Library/LaunchAgents/com.apple.softwareupdate.plist"
  )
  {
    local p sp sz
    for p in "${known_paths[@]}"; do
      sp="$(rp "$p")"
      if [[ -e "$sp" || -L "$sp" ]]; then
        echo "=== FOUND: $p ==="
        stat_meta "$sp"
        /usr/bin/file -b "$sp" 2>/dev/null | sed 's/^/  file: /'
        echo
        sz=$(/usr/bin/stat -f '%z' "$sp" 2>/dev/null); sz=${sz:-0}
        if [[ -f "$sp" ]] && (( sz < 52428800 )); then
          safe_cp "$sp" "$D/captured_samples/${p#/}"
        fi
      fi
    done
  } > "$D/known_paths.txt"

  # Single full-disk traversal: mtime OR btime within 30d (halves the costliest I/O).
  log INFO "Time-bracket search (mtime OR btime <=30d, single pass)..."
  /usr/bin/find "${SRC:-/}" -xdev \
    \( -path "${SRC}/System" -o -path "${SRC}/Library/Apple" \
       -o -path "${SRC}/private/var/folders" -o -path "${SRC}/private/var/db" \
       -o -path "$EVIDENCE_BASE" -o -path "$SNAP_MNT" \
       -o -path "${SRC}/usr" -o -path "${SRC}/bin" -o -path "${SRC}/sbin" \) -prune -o \
    -type f \( -mtime -30 -o -Btime -30 \) -print 2>/dev/null > "$D/files_changed_30d.txt"

  # Mach-O hunt outside legitimate system locations.
  log INFO "Mach-O hunt outside system paths (may take 1-3 min)..."
  /usr/bin/find "${SRC}/tmp" "${SRC}/private/tmp" "${SRC}/var/tmp" \
    "${SRC}/Users" "${SRC}/opt" "${SRC}/usr/local" \
    -xdev -type f ! -path '*/node_modules/*' ! -path '*/Library/Developer/*' \
    ! -path '*/Caches/com.apple.*' 2>/dev/null \
    -exec sh -c '
      out=$(/usr/bin/file -b "$1" 2>/dev/null)
      case "$out" in Mach-O*) echo "$1|$out" ;; esac
    ' _ {} \; > "$D/machos_outside_system.txt"

  log INFO "Codesign verification of Mach-O hits..."
  {
    local f desc sz
    while IFS='|' read -r f desc; do
      [[ -z "$f" ]] && continue
      echo "================================================================"
      echo "FILE: ${f#$SRC}"; echo "TYPE: $desc"
      stat_meta "$f"
      echo "--- codesign -dv ---";   /usr/bin/codesign -dv --verbose=4 "$f" 2>&1 | head -30
      echo "--- spctl assessment ---"; /usr/sbin/spctl -a -vv "$f" 2>&1
      echo "--- otool -L ---";        /usr/bin/otool -L "$f" 2>/dev/null | head -20
      echo
      sz=$(/usr/bin/stat -f '%z' "$f" 2>/dev/null); sz=${sz:-0}
      (( sz < 52428800 )) && safe_cp "$f" "$D/captured_samples/${${f#$SRC}#/}"
    done < "$D/machos_outside_system.txt"
  } > "$D/machos_verified.txt"

  log INFO "Archive hunt in suspect locations..."
  /usr/bin/find "${SRC}/tmp" "${SRC}/private/tmp" "${SRC}/var/tmp" \
    "${SRC}/Users/Shared" "$(rp "$TARGET_HOME")" \
    -xdev -type f \( -name '*.zip' -o -name '*.tar.gz' -o -name 'out' -o -name 'data' \) \
    -mtime -30 ! -path '*/Library/Caches/*' ! -path '*/node_modules/*' 2>/dev/null > "$D/archives_recent.txt"
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
    echo "# Executables/scripts in /tmp or Downloads (<=30d) without com.apple.quarantine"
    local f ft
    /usr/bin/find "${SRC}/tmp" "${SRC}/private/tmp" "$(rp "$TARGET_HOME/Downloads")" \
      -xdev -type f -mtime -30 2>/dev/null | while read -r f; do
        /usr/bin/xattr -lp com.apple.quarantine "$f" >/dev/null 2>&1 && continue
        ft=$(/usr/bin/file -b "$f" 2>/dev/null)
        case "$ft" in
          Mach-O*|*executable*|*script*) echo "MISSING_QUARANTINE: ${f#$SRC}  [$ft]" ;;
        esac
      done
  } > "$D/no_quarantine.txt"

  log INFO "Recent hidden directories under \$HOME..."
  /usr/bin/find "$(rp "$TARGET_HOME")" -maxdepth 3 -type d -name '.[!.]*' -mtime -30 \
    ! -path '*/Library/*' 2>/dev/null > "$D/recent_hidden_dirs.txt"

  # AMOS staging dirs.
  local sd ssd
  for sd in "$TARGET_HOME/fg" "$TARGET_HOME/.fg" "$TARGET_HOME/Library/.fg" \
            "$TARGET_HOME/.config/fg" "$TARGET_HOME/Library/data"; do
    ssd="$(rp "$sd")"
    [[ -d "$ssd" ]] || continue
    log WARN "Suspect staging dir found: $sd"
    {
      echo "=== STAGING DIR: $sd ==="; /bin/ls -laR "$ssd"; echo
      /usr/bin/find "$ssd" -type f -exec /usr/bin/stat -f '%N atime=%Sa mtime=%Sm size=%z' {} \;
    } >> "$D/staging_dirs.txt"
    safe_cp "$ssd" "$D/captured_samples/${sd#/}"
  done
}

# ============================================================================
# PHASE 3 — Persistence (file reads via snapshot; runtime queries live)
# ============================================================================
phase3_persistence() {
  log PHASE "PHASE 3 — Persistence enumeration"
  local D="$OUT/03_persistence"; mkdir -p "$D"

  {
    local d
    for d in "$TARGET_HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons \
             /System/Library/LaunchAgents /System/Library/LaunchDaemons; do
      echo "=================================="; echo "DIR: $d"; echo "=================================="
      /bin/ls -la@ "$(rp "$d")" 2>/dev/null; echo
    done
  } > "$D/launchd_dirs.txt"

  log INFO "Inspecting third-party LaunchAgents/Daemons..."
  {
    local d p prog sprog
    for d in "$TARGET_HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons; do
      [[ -d "$(rp "$d")" ]] || continue
      for p in "$(rp "$d")"/*.plist(N); do
        echo "================================"; echo "PLIST: ${p#$SRC}"; echo "================================"
        stat_meta "$p"
        echo "--- contents ---"
        /usr/libexec/PlistBuddy -c "Print" "$p" 2>/dev/null || /bin/cat "$p"
        prog=$(/usr/libexec/PlistBuddy -c "Print :Program" "$p" 2>/dev/null)
        [[ -z "$prog" ]] && prog=$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:0" "$p" 2>/dev/null)
        if [[ -n "$prog" ]]; then
          sprog="$(rp "$prog")"
          if [[ -f "$sprog" ]]; then
            echo "--- referenced program: $prog ---"; stat_meta "$sprog"
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
    -type f \( -name 'com.apple.*' -o -name 'com.finder.*' \) 2>/dev/null \
    | sed "s|^$SRC||" > "$D/apple_impersonators.txt"

  # Runtime — must be LIVE.
  run  "launchctl list (user)"       "$D/launchctl_user.txt"   -- "sudo -u $TARGET_USER launchctl list"
  runv "launchctl list (root)"       "$D/launchctl_root.txt"   launchctl list
  run  "launchctl gui session"       "$D/launchctl_gui.txt"    -- "launchctl print gui/$(id -u $TARGET_USER) 2>&1 | head -300"
  run  "launchctl system"            "$D/launchctl_system.txt" -- "launchctl print system 2>&1 | head -300"
  run  "osascript loginitems"        "$D/loginitems_osa.txt"   -- \
    "sudo -u $TARGET_USER osascript -e 'tell application \"System Events\" to get name of every login item'"
  run  "sfltool dumpbtm (user)"      "$D/btm_user.txt"         -- "sudo -u $TARGET_USER sfltool dumpbtm"
  runv "sfltool dumpbtm (root)"      "$D/btm_root.txt"         sfltool dumpbtm
  run  "user crontab"                "$D/crontab_user.txt"     -- "sudo -u $TARGET_USER crontab -l"
  runv "root crontab"                "$D/crontab_root.txt"     crontab -l
  run  "at jobs"                     "$D/at_jobs.txt"          -- "ls -la /var/at/jobs 2>/dev/null"
  run  "periodic dirs"               "$D/periodic.txt"         -- "ls -la /etc/periodic*/ /etc/cron* 2>/dev/null"

  log INFO "Capturing shell init files..."
  {
    local rc
    for rc in \
      "$TARGET_HOME/.zshenv" "$TARGET_HOME/.zprofile" "$TARGET_HOME/.zshrc" \
      "$TARGET_HOME/.zlogin" "$TARGET_HOME/.zlogout" \
      "$TARGET_HOME/.bash_profile" "$TARGET_HOME/.bashrc" \
      "$TARGET_HOME/.profile" "$TARGET_HOME/.bash_login" \
      /etc/zshenv /etc/zprofile /etc/zshrc /etc/zlogin /etc/profile /etc/bashrc; do
      if [[ -f "$(rp "$rc")" ]]; then
        echo "================================"; echo "FILE: $rc"; echo "================================"
        stat_meta "$(rp "$rc")"; echo "--- contents ---"; /bin/cat "$(rp "$rc")"; echo
      fi
    done
  } > "$D/shell_rc_files.txt"

  log INFO "Searching shell init for suspect patterns..."
  /usr/bin/grep -nHE 'curl|wget|base64|eval|source.*http|/tmp/' \
    "$(rp "$TARGET_HOME")"/.zsh* "$(rp "$TARGET_HOME")"/.bash* "$(rp "$TARGET_HOME")"/.profile \
    "$(rp /etc)"/zsh* "$(rp /etc)"/bash* "$(rp /etc/profile)" 2>/dev/null \
    | sed "s|^$SRC||" > "$D/shell_rc_suspects.txt"

  log INFO "Capturing SSH state..."
  {
    echo "=== ~/.ssh/ listing ==="; /bin/ls -la "$(rp "$TARGET_HOME/.ssh")/" 2>/dev/null; echo
    local f
    for f in "$TARGET_HOME/.ssh/authorized_keys" "$TARGET_HOME/.ssh/config" "$TARGET_HOME/.ssh/known_hosts"; do
      if [[ -f "$(rp "$f")" ]]; then
        echo "=== $f ==="; stat_meta "$(rp "$f")"; echo "--- contents ---"; /bin/cat "$(rp "$f")"; echo
      fi
    done
  } > "$D/ssh_state.txt"

  run "sudoers"             "$D/sudoers.txt"          -- "cat '$(rp /etc/sudoers)'"
  run "sudoers.d listing"   "$D/sudoers_d_ls.txt"     -- "ls -la '$(rp /etc/sudoers.d)/'"
  run "sudoers.d contents"  "$D/sudoers_d.txt"        -- \
    "for f in '$(rp /etc/sudoers.d)'/*; do [ -f \"\$f\" ] && echo === \"\${f#$SRC}\" === && cat \"\$f\"; done"
  run "sudoers NOPASSWD"    "$D/sudoers_nopasswd.txt" -- \
    "grep -rE 'NOPASSWD|ALL=' '$(rp /etc/sudoers)' '$(rp /etc/sudoers.d)/' 2>/dev/null | sed 's|^$SRC||'"
  run "PAM dir listing"     "$D/pam_dir.txt"          -- "ls -la '$(rp /etc/pam.d)/'"
  run "PAM recent mods"     "$D/pam_recent.txt"       -- "find '$(rp /etc/pam.d)' -mtime -90 | sed 's|^$SRC||'"

  run "user LoginHook"      "$D/loginhook_user.txt"   -- "sudo -u $TARGET_USER defaults read com.apple.loginwindow LoginHook 2>&1"
  run "user LogoutHook"     "$D/logouthook_user.txt"  -- "sudo -u $TARGET_USER defaults read com.apple.loginwindow LogoutHook 2>&1"
  run "global loginwindow"  "$D/loginwindow_global.txt" -- "defaults read /Library/Preferences/com.apple.loginwindow 2>&1"
  run "profiles (user)"     "$D/profiles_user.txt"    -- "sudo -u $TARGET_USER profiles list 2>&1"
  runv "profiles (system)"  "$D/profiles_system.txt"  profiles list
  runv "profiles show -all" "$D/profiles_all.txt"     profiles show -all
  run "authdb login.console" "$D/authdb_login.txt"    -- "security authorizationdb read system.login.console 2>&1"
  run "Dock persistent-apps" "$D/dock.txt"            -- \
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
      if [[ -d "$(rp "$path")" ]]; then
        echo "=== $path ==="; /bin/ls -la "$(rp "$path")" 2>/dev/null; echo
      fi
    done
    for prof in "$(rp "$TARGET_HOME/Library/Application Support/Firefox/Profiles")"/*(N); do
      [[ -d "$prof/extensions" ]] || continue
      echo "=== ${prof#$SRC}/extensions ==="; /bin/ls -la "$prof/extensions" 2>/dev/null; echo
    done
  } > "$D/browser_extensions.txt"
}

# ============================================================================
# PHASE 4 — Logs (LIVE), FSEvents (LIVE), history/TCC reads via snapshot
# ============================================================================
phase4_logs() {
  log PHASE "PHASE 4 — Logs, FSEvents, history, TCC"
  local D="$OUT/04_logs"; mkdir -p "$D"

  log INFO "Collecting unified log archive (--last $LOG_LOOKBACK)... 1-3 min"
  if /usr/bin/log collect --output "$D/unifiedlog.logarchive" --last "$LOG_LOOKBACK" 2>>"$ERR_FILE"; then
    log OK "unified log archive saved"
  else
    log WARN "log collect failed (see run.err)"
  fi

  log INFO "Snapshotting /var/db/diagnostics & uuidtext..."
  /usr/bin/tar -czf "$D/diagnostics_raw.tgz" /var/db/diagnostics /var/db/uuidtext 2>/dev/null \
    && log OK "raw tracev3 snapshot saved" || log WARN "diagnostics tar failed"

  log INFO "Running targeted unified log queries..."
  run "log: helper exec"         "$D/log_helper.txt" -- \
    "log show --style syslog --info --last $LOG_LOOKBACK --predicate '
      (process == \"helper\") OR (eventMessage CONTAINS \"/tmp/helper\") OR (eventMessage CONTAINS \"/tmp/update\")'"
  run "log: shell paste"         "$D/log_shell.txt"  -- \
    "log show --style syslog --info --last $LOG_LOOKBACK --predicate '
      (process == \"zsh\" OR process == \"Terminal\" OR process == \"iTerm2\" OR process == \"wezterm-gui\")
      AND (eventMessage CONTAINS \"curl\" OR eventMessage CONTAINS \"base64\" OR eventMessage CONTAINS \"eval\")'"
  run "log: curl activity"       "$D/log_curl.txt"   -- \
    "log show --style syslog --info --last $LOG_LOOKBACK --predicate 'process == \"curl\"'"
  run "log: osascript"           "$D/log_osascript.txt" -- \
    "log show --style syslog --info --last $LOG_LOOKBACK --predicate 'process == \"osascript\"'"
  run "log: osascript dialogs"   "$D/log_osascript_dialog.txt" -- \
    "log show --style syslog --info --last $LOG_LOOKBACK --predicate '
      process == \"osascript\" AND (eventMessage CONTAINS \"display dialog\" OR eventMessage CONTAINS \"hidden answer\")'"
  run "log: DNS/mDNS C2"         "$D/log_dns_c2.txt" -- \
    "log show --style syslog --info --last $LOG_LOOKBACK --predicate '
      subsystem == \"com.apple.network\" OR subsystem == \"com.apple.mDNSResponder\"' | \
      grep -iE 'faced31|stratos37|homebrewclubs|homebrewfaq|homebrewonline|homebrewupdate|logmel|tradingviewen|sites-phantom|filmoraus|93\\.152\\.230\\.79|195\\.82\\.147\\.38' || true"
  run "log: keychain access"     "$D/log_keychain.txt" -- \
    "log show --style syslog --info --last $LOG_LOOKBACK --predicate 'subsystem == \"com.apple.securityd\" OR process == \"security\"'"
  run "log: Gatekeeper/XProtect" "$D/log_gatekeeper.txt" -- \
    "log show --style syslog --info --last $LOG_LOOKBACK --predicate '
      process == \"syspolicyd\" OR process == \"amfid\" OR subsystem == \"com.apple.syspolicy\" OR subsystem == \"com.apple.xprotect\"'"
  run "log: TCC prompts"         "$D/log_tcc.txt"    -- \
    "log show --style syslog --info --last $LOG_LOOKBACK --predicate 'subsystem == \"com.apple.TCC\" OR process == \"tccd\"'"

  log INFO "Snapshotting TCC databases (via snapshot src)..."
  /usr/bin/sqlite3 "$(rp "$TARGET_HOME/Library/Application Support/com.apple.TCC/TCC.db")" \
    "SELECT client, service, auth_value, datetime(last_modified,'unixepoch') ts FROM access ORDER BY last_modified DESC;" \
    > "$D/tcc_user.txt" 2>>"$ERR_FILE"
  /usr/bin/sqlite3 "$(rp "/Library/Application Support/com.apple.TCC/TCC.db")" \
    "SELECT client, service, auth_value, datetime(last_modified,'unixepoch') ts FROM access ORDER BY last_modified DESC;" \
    > "$D/tcc_system.txt" 2>>"$ERR_FILE"
  safe_cp "$(rp "$TARGET_HOME/Library/Application Support/com.apple.TCC/TCC.db")" "$D/TCC_user.db"
  safe_cp "$(rp "/Library/Application Support/com.apple.TCC/TCC.db")" "$D/TCC_system.db"

  log INFO "Copying FSEvents (LIVE kernel fs log)..."
  /bin/ls -la /.fseventsd/ > "$D/fseventsd_list.txt" 2>>"$ERR_FILE"
  /usr/bin/tar -czf "$D/fseventsd_raw.tgz" /.fseventsd 2>/dev/null \
    && log OK "FSEvents snapshot saved" || log WARN "fseventsd tar failed (SIP?)"

  log INFO "Extracting FSEvents strings (last 30d files)..."
  local strings_cmd
  if (( $+commands[strings] )); then strings_cmd=(/usr/bin/strings); else strings_cmd=(tr -cd '[:print:]\n'); fi
  /usr/bin/find /.fseventsd -type f -mtime -30 2>/dev/null | head -200 | while read -r f; do
    /usr/bin/gunzip -c "$f" 2>/dev/null
  done | "${strings_cmd[@]}" | /usr/bin/sort -u > "$D/fseventsd_strings.txt"
  /usr/bin/grep -iE '/tmp/helper|/fg/|osalogging|wallet|keychain|Cookies|/Users/Shared' \
    "$D/fseventsd_strings.txt" > "$D/fseventsd_iocs.txt" 2>/dev/null

  log INFO "Capturing shell histories (via snapshot src)..."
  {
    local h
    for h in "$TARGET_HOME/.zsh_history" "$TARGET_HOME/.zhistory" \
             "$TARGET_HOME/.bash_history" "$TARGET_HOME/.history" \
             "$TARGET_HOME/.local/share/fish/fish_history"; do
      if [[ -f "$(rp "$h")" ]]; then
        echo "================================"; echo "FILE: $h"; echo "================================"
        stat_meta "$(rp "$h")"; echo "--- contents (last 500 lines) ---"; /usr/bin/tail -500 "$(rp "$h")"; echo
      fi
    done
  } > "$D/shell_histories.txt"
  safe_cp "$(rp "$TARGET_HOME/.zsh_history")"  "$D/raw_zsh_history"
  safe_cp "$(rp "$TARGET_HOME/.bash_history")" "$D/raw_bash_history"

  /usr/bin/grep -nE 'curl.*\|.*zsh|curl.*\|.*bash|base64.*-[dD]|brewe?\.sh|brew\.org|brew\.click' \
    "$(rp "$TARGET_HOME/.zsh_history")" "$(rp "$TARGET_HOME/.bash_history")" 2>/dev/null \
    | sed "s|^$SRC||" > "$D/paste_evidence.txt"

  run "QuickLook thumb cache"  "$D/quicklook.txt" -- \
    "ls -la '$(rp "$TARGET_HOME/Library/Application Support/Quick Look")/' 2>&1"

  # Spotlight queries must run LIVE (mdfind has no snapshot view) — logged as collector-induced.
  log INFO "Spotlight metadata for recent files (LIVE)..."
  /usr/bin/mdfind -onlyin /tmp 'kMDItemFSCreationDate >= $time.this_week' > "$D/mdfind_tmp.txt" 2>/dev/null
  sudo -u "$TARGET_USER" /usr/bin/mdfind -onlyin "$TARGET_HOME" \
    'kMDItemFSCreationDate >= $time.this_week' > "$D/mdfind_home.txt" 2>/dev/null
}

# ============================================================================
# PHASE 5 — Credential blast radius (ALL reads via snapshot — atime preserved)
# ============================================================================
phase5_secrets() {
  log PHASE "PHASE 5 — Credential blast radius"
  local D="$OUT/05_secrets"; mkdir -p "$D"
  log WARN "Enumerates secret LOCATIONS + atimes, NOT contents. No keys/passwords written."

  log INFO "Enumerating Keychain item names (no contents)..."
  run "Keychain list" "$D/keychains_list.txt" -- "sudo -u $TARGET_USER security list-keychains"
  sudo -u "$TARGET_USER" /usr/bin/security dump-keychain 2>/dev/null \
    | /usr/bin/awk '/"svce"|"acct"|0x00000007/ {print}' | /usr/bin/sort -u \
    > "$D/keychain_items_NAMES_ONLY.txt"

  log INFO "Browser credential store metadata (atime is the evidence)..."
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
      echo "=========================================="; echo "BROWSER: $bp"; echo "=========================================="
      for f in 'Login Data' 'Cookies' 'Web Data' 'History' 'Local State' 'Local Extension Settings' 'IndexedDB'; do
        p="$(rp "$bp/$f")"; [[ -e "$p" ]] && { stat_meta "$p"; echo; }
      done
    done
    for prof in "$(rp "$TARGET_HOME/Library/Application Support/Firefox/Profiles")"/*(N); do
      [[ -d "$prof" ]] || continue
      echo "=========================================="; echo "FIREFOX PROFILE: ${prof#$SRC}"; echo "=========================================="
      for f in logins.json key4.db cookies.sqlite places.sqlite; do
        [[ -e "$prof/$f" ]] && { stat_meta "$prof/$f"; echo; }
      done
    done
    echo "=========================================="; echo "SAFARI"; echo "=========================================="
    for f in \
      "$TARGET_HOME/Library/Safari/Cookies.binarycookies" \
      "$TARGET_HOME/Library/Cookies/Cookies.binarycookies" \
      "$TARGET_HOME/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies" \
      "$TARGET_HOME/Library/Safari/History.db" \
      "$TARGET_HOME/Library/Keychains/login.keychain-db"; do
      p="$(rp "$f")"; [[ -e "$p" ]] && { stat_meta "$p"; echo; }
    done
  } > "$D/browser_credstores.txt"

  log INFO "Crypto wallet artifact inspection..."
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
      echo "=========================================="; echo "WALLET PATH: $w"; echo "=========================================="
      /bin/ls -la "$sw" 2>/dev/null
      /usr/bin/find "$sw" -type f \( -name '*wallet*' -o -name '*keys*' -o -name '*seed*' \
        -o -name '*.json' -o -name '*.dat' \) 2>/dev/null | while read -r f; do stat_meta "$f"; echo; done
    done

    typeset -A EXT_WALLETS
    EXT_WALLETS=(
      nkbihfbeogaeaoehlefnkodbefgpgknn  MetaMask
      bfnaelmomeimhlpmgjnjophhpkkoljpa  Phantom
      dmkamcknogkgcdfhhbddcghachkejeap  Keplr
      hnfanknocfeofbddgcijnmhnfnkdnaad  Coinbase
      ejbalbakoplchlghecdalmeeeajnimhm  MetaMask_Edge
      bhghoamapcdpbohphigoooaddinpkbai  Authenticator
      aiifbnbfobpmeekipheeijimdpnlpgpp  TerraStation
      fhbohimaelbohpjbbldcngcnapndodjp  BinanceChain
      ibnejdfjmmkpcnlpebklmnkoeoihofec  TronLink
      aeachknmefphepccionboohckonoeemg  CoinPocket
      jblndlipeogpafnldhgmapagcccfchpi  Kaikas
    )
    local browser base id name p
    for browser in Chrome 'BraveSoftware/Brave-Browser' 'Microsoft Edge' Vivaldi; do
      base="$(rp "$TARGET_HOME/Library/Application Support/$browser/Default/Local Extension Settings")"
      [[ -d "$base" ]] || continue
      for id name in ${(kv)EXT_WALLETS}; do
        p="$base/$id"; [[ -d "$p" ]] || continue
        echo "=========================================="; echo "EXT WALLET: $name ($id) in $browser"; echo "=========================================="
        /bin/ls -la "$p"
        /usr/bin/find "$p" -type f 2>/dev/null | while read -r f; do stat_meta "$f"; echo; done
      done
    done
  } > "$D/wallets.txt"

  log INFO "Developer secrets inspection..."
  {
    local f
    for f in \
      "$TARGET_HOME/.ssh"/id_* \
      "$TARGET_HOME/.ssh/known_hosts" "$TARGET_HOME/.ssh/config" \
      "$TARGET_HOME/.aws/credentials" "$TARGET_HOME/.aws/config" \
      "$TARGET_HOME/.aws/sso/cache"/* "$TARGET_HOME/.azure"/* \
      "$TARGET_HOME/.config/gcloud"/* "$TARGET_HOME/.config/gh/hosts.yml" \
      "$TARGET_HOME/.kube/config" "$TARGET_HOME/.docker/config.json" \
      "$TARGET_HOME/.docker/contexts"/* \
      "$TARGET_HOME/.netrc" "$TARGET_HOME/.npmrc" "$TARGET_HOME/.yarnrc" \
      "$TARGET_HOME/.pypirc" "$TARGET_HOME/.cargo/credentials"* \
      "$TARGET_HOME/.gitconfig" "$TARGET_HOME/.git-credentials" \
      "$TARGET_HOME/.gnupg"/* \
      "$TARGET_HOME/.config/op"/* "$TARGET_HOME/.1password"/* \
      "$TARGET_HOME/Library/Application Support/Slack/storage"/* \
      "$TARGET_HOME/Library/Application Support/discord/Local Storage"/* \
      "$TARGET_HOME/Library/Application Support/Code/User/globalStorage"/* \
      "$TARGET_HOME/Library/Application Support/JetBrains"/*/options/security.xml; do
      local sf="$(rp "$f")"
      [[ -e "$sf" ]] || continue
      stat_meta "$sf"; echo
    done
  } > "$D/dev_secrets.txt"

  log INFO "Apple Notes artifact inspection..."
  {
    local nd="$(rp "$TARGET_HOME/Library/Group Containers/group.com.apple.notes")"
    if [[ -d "$nd" ]]; then
      /bin/ls -la "$nd/"; echo
      local f
      for f in "$nd/NoteStore.sqlite"*; do [[ -e "$f" ]] && { stat_meta "$f"; echo; }; done
    fi
  } > "$D/notes.txt"

  run "iCloud Keychain sync" "$D/icloud_kc.txt" -- \
    "sudo -u $TARGET_USER defaults read MobileMeAccounts 2>&1 | grep -A2 KEYCHAIN_SYNC"

  log INFO "Password manager container inspection..."
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
# PHASE 6 — Additional Mach-O sweep (via snapshot)
# ============================================================================
phase6_samples() {
  log PHASE "PHASE 6 — Additional Mach-O sample collection"
  local D="$OUT/06_samples"; mkdir -p "$D"

  log INFO "Final sweep of suspect binary locations..."
  /usr/bin/find \
    "$(rp "$TARGET_HOME/Library/Application Support")" \
    "$(rp "$TARGET_HOME/.config")" "$(rp "$TARGET_HOME/.local")" \
    "${SRC}/Users/Shared" "${SRC}/opt" "${SRC}/tmp" "${SRC}/private/tmp" "${SRC}/var/tmp" \
    -xdev -type f -size -50M 2>/dev/null | while read -r f; do
      local out sig
      out=$(/usr/bin/file -b "$f" 2>/dev/null)
      case "$out" in
        Mach-O*)
          sig=$(/usr/bin/codesign -dv "$f" 2>&1)
          if echo "$sig" | /usr/bin/grep -qE 'adhoc|revoked|not signed|invalid'; then
            echo "SUSPECT: ${f#$SRC}"; echo "  type: $out"
            echo "$sig" | /usr/bin/sed 's/^/  sig: /'; echo
          fi
          ;;
      esac
  done > "$D/suspect_unsigned_machos.txt"
}

# ============================================================================
# PHASE 7 — System metadata & posture (LIVE)
# ============================================================================
phase7_sysmeta() {
  log PHASE "PHASE 7 — System metadata & security posture"
  local D="$OUT/07_sysmeta"; mkdir -p "$D"

  runv "macOS version"     "$D/sw_vers.txt"        sw_vers
  runv "Kernel version"    "$D/uname.txt"          uname -a
  run  "Hardware info"     "$D/hardware.txt"       -- "system_profiler SPHardwareDataType"
  run  "Software info"     "$D/software.txt"       -- "system_profiler SPSoftwareDataType"
  run  "Installed apps"    "$D/installed_apps.txt" -- "system_profiler SPApplicationsDataType -detailLevel mini"
  run  "XProtect version"  "$D/xprotect_version.txt" -- \
    "defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist CFBundleShortVersionString 2>&1"
  run  "XProtect Remediator" "$D/xprotect_remediator.txt" -- \
    "ls -la /Library/Apple/System/Library/CoreServices/XProtect.app 2>&1; defaults read /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist 2>&1"
  run  "MRT version"       "$D/mrt_version.txt"    -- \
    "defaults read /Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist 2>&1"
  run  "Gatekeeper status" "$D/gatekeeper.txt"     -- "spctl --status"
  run  "SIP status"        "$D/sip_status.txt"     -- "csrutil status"
  run  "AMFI boot args"    "$D/amfi.txt"           -- "nvram boot-args 2>&1"
  run  "MDM profiles"      "$D/mdm.txt"            -- "profiles status -type enrollment 2>&1"
  run  "FileVault status"  "$D/filevault.txt"      -- "fdesetup status 2>&1"
  run  "App firewall"      "$D/firewall.txt"       -- \
    "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>&1; /usr/libexec/ApplicationFirewall/socketfilterfw --listapps 2>&1"
  run  "Disk list"         "$D/diskutil.txt"       -- "diskutil list"
  run  "APFS info"         "$D/apfs.txt"           -- "diskutil apfs list"
  run  "df"                "$D/df.txt"             -- "df -h"
  run  "powermetrics"      "$D/powermetrics.txt"   -- "powermetrics -i 1 -n 1 --samplers all 2>&1 | head -200"
}

# ============================================================================
# PHASE 8 — IOC sweep, manifest, bundle
# ============================================================================
phase8_finalize() {
  log PHASE "PHASE 8 — Finalize: IOC sweep, manifest, bundle"
  local D="$OUT/08_final"; mkdir -p "$D"

  log INFO "Sweeping collected data for known IOCs (fixed-string)..."
  {
    echo "# IOC hit report — Odyssey/AMOS campaign indicators"
    echo "# Generated: $(ts)"; echo
    local ioc
    for ioc in "${IOC_STRINGS[@]}"; do
      echo "================================"; echo "IOC: $ioc"; echo "================================"
      /usr/bin/grep -rInF --binary-files=without-match \
        --exclude-dir=_meta --exclude='ioc_hits.txt' \
        -- "$ioc" "$OUT" 2>/dev/null | head -100
      echo
    done
  } > "$D/ioc_hits.txt"

  local hit_count
  hit_count=$(/usr/bin/grep -cE '^[^#=[:space:]].*:[0-9]+:' "$D/ioc_hits.txt" 2>/dev/null); hit_count=${hit_count:-0}
  if (( hit_count > 0 )); then
    log WARN "IOC hits: $hit_count lines flagged — see 08_final/ioc_hits.txt"
  else
    log INFO "No IOC string hits (NOT proof of clean — logs may be missing/encrypted)"
  fi

  log INFO "Generating compromise depth assessment scaffold..."
  cat > "$D/COMPROMISE_DEPTH.md" <<EOF
# Compromise Depth Assessment — ${CASE_ID}

Generated: $(ts)

## Indicator checklist
- [ ] Stage-1 zsh wrapper executed (\`04_logs/log_shell.txt\`, \`paste_evidence.txt\`)
- [ ] Stage-2 beacon to faced31.com (\`04_logs/log_curl.txt\`, \`log_dns_c2.txt\`)
- [ ] Stage-3 /tmp/helper downloaded (\`02_disk/known_paths.txt\`, \`log_curl.txt\`)
- [ ] Stage-3 /tmp/helper executed (\`04_logs/log_helper.txt\`)
- [ ] osascript password dialog fired (\`04_logs/log_osascript_dialog.txt\`)
- [ ] Keychain access by non-Apple process (\`04_logs/log_keychain.txt\`)
- [ ] curl POST exfil (\`04_logs/log_curl.txt\`, -F file=)
- [ ] Persistence plist installed (\`03_persistence/launchd_plists_inspected.txt\`)
- [ ] Sensitive file atimes updated in window (\`05_secrets/*\`)

## Classification
| Pattern | Match? |
|---|---|
| **Beacon only** | |
| **Stage-3 ran, no password capture** | |
| **Full compromise (Keychain captured)** | |
| **Persistent foothold** | |

## Notes

EOF

  log INFO "Building SHA-256 manifest..."
  ( cd "$OUT" && /usr/bin/find . -type f ! -path "./_meta/MANIFEST.sha256" \
      -exec /usr/bin/shasum -a 256 {} + ) > "$MANIFEST"
  local file_count total_size
  file_count=$(/usr/bin/wc -l < "$MANIFEST"); file_count=${file_count// /}
  total_size=$(/usr/bin/du -sh "$OUT" | awk '{print $1}')
  log OK "Manifest: ${file_count} files, ${total_size}"

  cat > "$OUT/README.md" <<EOF
# IR Evidence Bundle — ${CASE_ID}

**Collected:** $(ts)
**Host:** $(hostname)
**Target user:** ${TARGET_USER}
**Script version:** ${SCRIPT_VERSION}
**Log lookback:** ${LOG_LOOKBACK}
**Read source:** $( [[ -n "$SRC" ]] && echo "read-only APFS snapshot (atime preserved)" || echo "LIVE filesystem (atime altered)" )

## Structure
| Dir | Contents |
|---|---|
| \`_meta/\` | Run log, error log, SHA-256 manifest, this README |
| \`00_freeze/\` | Wall clock, uptime, APFS snapshot reference |
| \`01_volatile/\` | Process tree, lsof, netstat, network state |
| \`02_disk/\` | Known-bad paths, time-bracket search, Mach-O hunt, archives, samples |
| \`03_persistence/\` | LaunchAgents/Daemons, launchctl, BTM, cron, shell init, SSH, sudoers, profiles |
| \`04_logs/\` | Unified log archive + raw tracev3, targeted queries, TCC, FSEvents, history |
| \`05_secrets/\` | Keychain NAMES, browser/wallet/dev-secret metadata (atime evidence) |
| \`06_samples/\` | Additional suspect Mach-O sweep |
| \`07_sysmeta/\` | macOS version, XProtect/Gatekeeper, MDM, FileVault, hardware |
| \`08_final/\` | IOC sweep, compromise depth template |

## Quick triage
1. \`08_final/ioc_hits.txt\` — direct campaign IOC evidence.
2. \`04_logs/log_helper.txt\` + \`log_curl.txt\` — Stage-3 exec + C2.
3. \`04_logs/log_osascript_dialog.txt\` — password dialog.
4. \`04_logs/paste_evidence.txt\` — exact pasted command.
5. \`03_persistence/apple_impersonators.txt\` — persistence.
6. \`05_secrets/browser_credstores.txt\` + \`wallets.txt\` — atime access.
7. Fill in \`08_final/COMPROMISE_DEPTH.md\`.

## Integrity
\`\`\`
cd ${CASE_ID} && shasum -a 256 -c _meta/MANIFEST.sha256
\`\`\`

## Chain of custody
Full command sequence in \`_meta/run.log\`; non-zero exits in \`_meta/run.err\`.
EOF

  unmount_snapshot

  log INFO "Creating compressed bundle..."
  local elapsed=$(( EPOCHSECONDS - SCRIPT_START_EPOCH ))
  log INFO "Total collection time: ${elapsed}s"

  if ! cd "$EVIDENCE_BASE"; then
    log ERR "Cannot cd to $EVIDENCE_BASE — bundle not created"; return 1
  fi
  /usr/bin/tar -czf "${CASE_ID}.tar.gz" "$CASE_ID" 2>>"$ERR_FILE"
  /usr/bin/shasum -a 256 "${CASE_ID}.tar.gz" > "${CASE_ID}.tar.gz.sha256"
  local bundle_size
  bundle_size=$(/usr/bin/du -sh "${CASE_ID}.tar.gz" | awk '{print $1}')
  log OK "Bundle: ${EVIDENCE_BASE}/${CASE_ID}.tar.gz  (${bundle_size})"
  log OK "Hash:   ${EVIDENCE_BASE}/${CASE_ID}.tar.gz.sha256"
  cat "${CASE_ID}.tar.gz.sha256"
}

# ============================================================================
# Main
# ============================================================================
main() {
  printf "\n%s╔══════════════════════════════════════════════════════════════════╗%s\n" "$CW" "$CN"
  printf "%s║       macOS IR Evidence Collector  v%-7s                     ║%s\n" "$CW" "$SCRIPT_VERSION" "$CN"
  printf "%s║       Threat: Odyssey/AMOS Stealer (ClickFix)                    ║%s\n" "$CW" "$CN"
  printf "%s╚══════════════════════════════════════════════════════════════════╝%s\n\n" "$CW" "$CN"

  # Ensure snapshot is always torn down even on early failure.
  trap 'unmount_snapshot' EXIT INT TERM

  preflight
  phase0_freeze
  phase1_volatile
  phase2_disk
  phase3_persistence
  phase4_logs
  phase5_secrets
  phase6_samples
  phase7_sysmeta
  phase8_finalize

  printf "\n%s════════════════════════════════════════════════════════════════════%s\n" "$CG" "$CN"
  printf "%s COLLECTION COMPLETE%s\n" "$CG" "$CN"
  printf "%s════════════════════════════════════════════════════════════════════%s\n" "$CG" "$CN"
  printf " Bundle:   %s%s/%s.tar.gz%s\n" "$CW" "$EVIDENCE_BASE" "$CASE_ID" "$CN"
  printf " Hash:     %s%s/%s.tar.gz.sha256%s\n" "$CW" "$EVIDENCE_BASE" "$CASE_ID" "$CN"
  printf " Manifest: %s%s/_meta/MANIFEST.sha256%s\n" "$CW" "$OUT" "$CN"
  printf " Run log:  %s%s%s\n" "$CW" "$LOG_FILE" "$CN"
  printf "\n%s Next steps:%s\n" "$CY" "$CN"
  printf "  1. Verify hash, transfer bundle to analysis workstation over USB.\n"
  printf "  2. Review %s%s/08_final/ioc_hits.txt%s first.\n" "$CW" "$OUT" "$CN"
  printf "  3. Open unified log archive on analyst Mac:\n"
  printf "     %slog show --archive %s/04_logs/unifiedlog.logarchive --info ...%s\n" "$CW" "$OUT" "$CN"
  printf "  4. Fill in %s%s/08_final/COMPROMISE_DEPTH.md%s.\n\n" "$CW" "$OUT" "$CN"
}

main "$@"