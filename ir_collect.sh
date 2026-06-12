#!/bin/zsh
# ============================================================================
# ir_collect.sh — macOS Incident Response Evidence Collector
# ============================================================================
# Target:      Network-isolated macOS host (Ventura+ / Sonoma / Sequoia)
# Threat:      Odyssey / Poseidon / AMOS macOS infostealer (ClickFix delivery)
# Author:      Khodaparastan
# Version:     1.0  (2026-06-12)
# Invocation:  sudo -E ./ir_collect.sh
#
# This script collects forensic evidence in 8 phases:
#   0  Freeze & metadata
#   1  Volatile process / network / memory state
#   2  On-disk staging & dropped artifacts
#   3  Persistence enumeration
#   4  Unified log, FSEvents, shell history, TCC
#   5  Credential & secret blast-radius enumeration
#   6  Mach-O sample collection
#   7  System metadata & security posture
#   8  Finalize: IOC sweep, manifest, bundle
#
# All output is preserved hashed (SHA-256) and bundled as <CASE_ID>.tar.gz
# ============================================================================

set -u
setopt PIPE_FAIL EXTENDED_GLOB NULL_GLOB

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------
SCRIPT_VERSION="1.0"
SCRIPT_START_EPOCH=$(date -u +%s)
SCRIPT_START_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)

CASE_ID="${CASE_ID:-IR-$(date -u +%Y%m%d-%H%M%S)-$(hostname -s)}"
EVIDENCE_BASE="${EVIDENCE_BASE:-/Volumes/IR}"
LOG_LOOKBACK="${LOG_LOOKBACK:-14d}"
TARGET_USER="${TARGET_USER:-${SUDO_USER:-$USER}}"
TARGET_HOME="$(/usr/bin/dscl . -read /Users/${TARGET_USER} NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
[[ -z "$TARGET_HOME" || ! -d "$TARGET_HOME" ]] && TARGET_HOME="/Users/${TARGET_USER}"

OUT="${EVIDENCE_BASE}/${CASE_ID}"
META="${OUT}/_meta"
LOG_FILE="${META}/run.log"
ERR_FILE="${META}/run.err"
MANIFEST="${META}/MANIFEST.sha256"

# Known IOCs for in-collection sweep
IOC_STRINGS=(
  "faced31.com"
  "stratos37.com"
  "homebrewclubs.org"
  "homebrewfaq.org"
  "homebrewonline.org"
  "homebrewupdate.org"
  "Homebrewlub.com"
  "logmeln.com"
  "logmeeine.com"
  "tradingviewen.com"
  "sites-phantom.com"
  "filmoraus.com"
  "93.152.230.79"
  "195.82.147.38"
  "Kgvte6N4Ab73QPUcm-3iajAe2K8dLrWEzsysY8YZ3xQ"
  "ipbGT_eh94rq6jM2djVvrJLF7eC1_HFhhXRh6rlQVCE"
  "setup-555549446b661f7073483a219ad86bf9c0312e89"
  "ab15698009e532f4735792cd06a793f618769121"
  "498d82aab2ce9fc2ec1e7358d0aa83d8e02a031ac4a177549d07a26262c5193c"
  "xll1reccl6ecroh4"
  "/tmp/helper"
  "osalogging.zip"
  "expand 32-byte k"
  "com.finder.helper"
  "homebrew/update"
  "api/metrics/run"
)

# ----------------------------------------------------------------------------
# Colors & helpers
# ----------------------------------------------------------------------------
if [[ -t 1 ]]; then
  CR='\033[0;31m'; CG='\033[0;32m'; CY='\033[0;33m'
  CB='\033[0;34m'; CC='\033[0;36m'; CW='\033[1;37m'; CN='\033[0m'
else
  CR=''; CG=''; CY=''; CB=''; CC=''; CW=''; CN=''
fi

ts() { date -u +%Y-%m-%dT%H:%M:%S.%3NZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ; }

log() {
  local lvl="$1"; shift
  local msg="[$(ts)] [${lvl}] $*"
  case "$lvl" in
    INFO)  printf "${CB}%s${CN}\n" "$msg" ;;
    OK)    printf "${CG}%s${CN}\n" "$msg" ;;
    WARN)  printf "${CY}%s${CN}\n" "$msg" ;;
    ERR)   printf "${CR}%s${CN}\n" "$msg" ;;
    PHASE) printf "\n${CW}========== %s ==========${CN}\n" "$*" ;;
    *)     printf "%s\n" "$msg" ;;
  esac
  printf "%s\n" "$msg" >> "$LOG_FILE" 2>/dev/null
}

# run <description> <output_path> -- <command...>
# Captures stdout, stderr, exit code; never aborts on failure.
run() {
  local desc="$1"; shift
  local out="$1"; shift
  [[ "$1" == "--" ]] && shift
  local cmd="$*"
  log INFO "→ $desc"
  printf "\n### [%s] %s\n### cmd: %s\n" "$(ts)" "$desc" "$cmd" >> "$LOG_FILE"
  if [[ -n "$out" ]]; then
    mkdir -p "$(dirname "$out")"
    eval "$cmd" > "$out" 2>> "$ERR_FILE"
  else
    eval "$cmd" >> "$LOG_FILE" 2>> "$ERR_FILE"
  fi
  local rc=$?
  printf "### exit=%d\n" "$rc" >> "$LOG_FILE"
  [[ $rc -ne 0 ]] && log WARN "  (exit=$rc) $desc — see run.err"
  return 0
}

# safe_cp <src> <dst>  (preserve metadata, no follow, log result)
safe_cp() {
  local src="$1" dst="$2"
  [[ -e "$src" || -L "$src" ]] || { log WARN "skip (missing): $src"; return 0; }
  mkdir -p "$(dirname "$dst")"
  /bin/cp -pPR "$src" "$dst" 2>>"$ERR_FILE" && log OK "copied: $src" || log WARN "cp failed: $src"
}

# stat_meta <file>   — write timestamps + size + xattrs to log without opening file
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
    log ERR "Must run as root (use: sudo -E $0)"
    exit 1
  fi

  if [[ ! -d "$EVIDENCE_BASE" ]]; then
    log ERR "EVIDENCE_BASE not found: $EVIDENCE_BASE"
    log ERR "Mount an external USB volume and re-run with EVIDENCE_BASE=/Volumes/<name>"
    exit 1
  fi

  # Refuse to write to the local boot volume (avoid touching the host's APFS)
  local base_dev=$(/bin/df "$EVIDENCE_BASE" | awk 'NR==2{print $1}')
  local root_dev=$(/bin/df / | awk 'NR==2{print $1}')
  if [[ "$base_dev" == "$root_dev" ]]; then
    log ERR "EVIDENCE_BASE is on the local boot volume — refusing. Use external media."
    exit 1
  fi

  local avail_gb=$(/bin/df -g "$EVIDENCE_BASE" | awk 'NR==2{print $4}')
  log INFO "Available space on $EVIDENCE_BASE: ${avail_gb}G"
  [[ $avail_gb -lt 10 ]] && log WARN "Less than 10G free; collection may be incomplete"

  mkdir -p "$OUT" "$META" || { log ERR "Cannot create $OUT"; exit 1; }
  touch "$LOG_FILE" "$ERR_FILE" "$MANIFEST"

  log INFO "Case ID:           $CASE_ID"
  log INFO "Output:            $OUT"
  log INFO "Target user:       $TARGET_USER"
  log INFO "Target home:       $TARGET_HOME"
  log INFO "Log lookback:      $LOG_LOOKBACK"
  log INFO "Script version:    $SCRIPT_VERSION"
  log INFO "Start (UTC):       $SCRIPT_START_ISO"
}

# ============================================================================
# PHASE 0 — Freeze & system metadata
# ============================================================================
phase0_freeze() {
  log PHASE "PHASE 0 — Freeze & metadata"
  local D="$OUT/00_freeze"
  mkdir -p "$D"

  run "Wall clock UTC"            "$D/clock_utc.txt"        -- date -u
  run "Wall clock local"          "$D/clock_local.txt"      -- date
  run "Uptime"                    "$D/uptime.txt"           -- uptime
  run "Kernel boot time"          "$D/boottime.txt"         -- sysctl kern.boottime
  run "Hostname"                  "$D/hostname.txt"         -- hostname
  run "Active user (whoami)"      "$D/whoami.txt"           -- whoami
  run "id"                        "$D/id.txt"               -- id
  run "logged-in sessions (who)"  "$D/who.txt"              -- who
  run "active terminals (w)"      "$D/w.txt"                -- w
  run "ifconfig"                  "$D/ifconfig.txt"         -- ifconfig
  run "networksetup interfaces"   "$D/network_services.txt" -- /usr/sbin/networksetup -listallnetworkservices

  # APFS local snapshot for read-only forensic mount later
  log INFO "Taking APFS local snapshot for forensic mount option..."
  /usr/bin/tmutil localsnapshot 2>>"$ERR_FILE" \
    && log OK "Local APFS snapshot created" \
    || log WARN "tmutil localsnapshot failed (Time Machine may be disabled)"
  run "List local snapshots"      "$D/apfs_snapshots.txt"   -- /usr/bin/tmutil listlocalsnapshots /
}

# ============================================================================
# PHASE 1 — Volatile state (process / network)
# ============================================================================
phase1_volatile() {
  log PHASE "PHASE 1 — Volatile state"
  local D="$OUT/01_volatile"
  mkdir -p "$D"

  # Process state
  run "Full process tree (ps wide)"   "$D/ps_full.txt"  -- ps -Axwwo "pid,ppid,uid,user,start,etime,stat,command"
  run "Process tree by parent"        "$D/ps_tree.txt"  -- ps -Axwwo "pid,ppid,command"
  run "Process wchan"                 "$D/ps_wchan.txt" -- ps -Axwwo "pid,ppid,wchan,command"
  run "pgrep suspects"                "$D/pgrep_suspects.txt" -- \
    'for p in helper osascript curl zsh dscl security zip xattr; do echo "=== $p ==="; pgrep -alf "$p" 2>/dev/null; done'

  # File descriptor enumeration
  run "lsof network (all)"            "$D/lsof_net.txt"   -- lsof -nP -i
  run "lsof all files (truncated)"    "$D/lsof_all.txt"   -- lsof -nP
  run "lsof for known-bad paths"      "$D/lsof_tmp.txt"   -- \
    "lsof -nP 2>/dev/null | grep -E '/tmp/|/Users/Shared/|/private/tmp/'"

  # Network state
  run "netstat all"                   "$D/netstat_all.txt"   -- netstat -anv
  run "netstat routes"                "$D/route.txt"         -- netstat -rn
  run "ARP table"                     "$D/arp.txt"           -- arp -an
  run "host resolver state"           "$D/resolv.txt"        -- scutil --dns
  run "active proxy config"           "$D/proxies.txt"       -- scutil --proxy

  # PF firewall state
  run "pf ruleset"                    "$D/pf_rules.txt"      -- pfctl -sr
  run "pf full state"                 "$D/pf_all.txt"        -- pfctl -sa

  # Kernel extensions / system extensions
  run "Loaded kexts"                  "$D/kextstat.txt"      -- kextstat -l
  run "System extensions"             "$D/systemextensions.txt" -- systemextensionsctl list

  # Per-suspect detail: any process with cwd or exec under /tmp, /Users/Shared, hidden dirs
  log INFO "Enumerating suspect process details..."
  local suspect_pids=$(ps -Axwwo "pid,command" | awk '
    /\/tmp\/|\/private\/tmp\/|\/Users\/Shared\/|\/\.[a-z0-9]/ && $0 !~ /ir_collect/ {print $1}
  ' | sort -u)
  if [[ -n "$suspect_pids" ]]; then
    {
      echo "=== Suspect PIDs (running from non-standard paths) ==="
      echo "$suspect_pids"
      echo
      for pid in ${(f)suspect_pids}; do
        echo "================================"
        echo "=== PID $pid ==="
        echo "================================"
        ps -o "pid,ppid,uid,user,start,etime,command" -p "$pid" 2>/dev/null
        echo "--- lsof ---"
        lsof -p "$pid" -nP 2>/dev/null
        echo "--- vmmap summary ---"
        vmmap -summary "$pid" 2>/dev/null | head -100
      done
    } > "$D/suspect_processes.txt"
    log WARN "Suspect processes found — see suspect_processes.txt"
  else
    echo "No suspect processes located" > "$D/suspect_processes.txt"
  fi
}

# ============================================================================
# PHASE 2 — On-disk staging & dropped artifacts
# ============================================================================
phase2_disk() {
  log PHASE "PHASE 2 — On-disk staging & artifacts"
  local D="$OUT/02_disk"
  mkdir -p "$D/captured_samples"

  # Known-bad paths
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
    for p in "${known_paths[@]}"; do
      if [[ -e "$p" || -L "$p" ]]; then
        echo "=== FOUND: $p ==="
        stat_meta "$p"
        /usr/bin/file -b "$p" 2>/dev/null | sed 's/^/  file: /'
        echo
        # Capture any file < 50MB for offline analysis
        local sz=$(/usr/bin/stat -f '%z' "$p" 2>/dev/null || echo 0)
        if [[ -f "$p" && $sz -lt 52428800 ]]; then
          mkdir -p "$D/captured_samples/$(dirname "${p#/}")"
          safe_cp "$p" "$D/captured_samples/${p#/}"
        fi
      fi
    done
  } > "$D/known_paths.txt"

  # Time-bracket search — anything modified in the last 30 days outside system paths
  log INFO "Time-bracket search (modified in last 30d)..."
  /usr/bin/find / -xdev \
    \( -path /System -o -path /Library/Apple -o -path /private/var/folders \
       -o -path /private/var/db -o -path "$EVIDENCE_BASE" \
       -o -path /usr -o -path /bin -o -path /sbin \) -prune -o \
    -type f -mtime -30 -print 2>/dev/null > "$D/files_modified_30d.txt"

  log INFO "Time-bracket search (created in last 30d via APFS btime)..."
  /usr/bin/find / -xdev \
    \( -path /System -o -path /Library/Apple -o -path /private/var/folders \
       -o -path /private/var/db -o -path "$EVIDENCE_BASE" \
       -o -path /usr -o -path /bin -o -path /sbin \) -prune -o \
    -type f -Btime -30 -print 2>/dev/null > "$D/files_btime_30d.txt"

  # Hunt all Mach-O binaries outside legitimate system locations
  log INFO "Mach-O hunt outside system paths (this may take 1-3 min)..."
  /usr/bin/find /tmp /private/tmp /var/tmp /Users /opt /usr/local \
    -xdev -type f ! -path '*/node_modules/*' ! -path '*/Library/Developer/*' \
    ! -path '*/Caches/com.apple.*' 2>/dev/null \
    -exec sh -c '
      out=$(/usr/bin/file -b "$1" 2>/dev/null)
      case "$out" in
        Mach-O*) echo "$1|$out" ;;
      esac
    ' _ {} \; > "$D/machos_outside_system.txt"

  # For each Mach-O hit: codesign + hash + capture
  log INFO "Codesign verification of Mach-O hits..."
  {
    while IFS='|' read -r f desc; do
      [[ -z "$f" ]] && continue
      echo "================================================================"
      echo "FILE:  $f"
      echo "TYPE:  $desc"
      stat_meta "$f"
      echo "--- codesign -dv ---"
      /usr/bin/codesign -dv --verbose=4 "$f" 2>&1 | head -30
      echo "--- spctl assessment ---"
      /usr/sbin/spctl -a -vv "$f" 2>&1
      echo "--- otool -L (linked libs) ---"
      /usr/bin/otool -L "$f" 2>/dev/null | head -20
      echo
      # Capture if < 50MB
      local sz=$(/usr/bin/stat -f '%z' "$f" 2>/dev/null || echo 0)
      if [[ $sz -lt 52428800 ]]; then
        mkdir -p "$D/captured_samples/$(dirname "${f#/}")"
        safe_cp "$f" "$D/captured_samples/${f#/}"
      fi
    done < "$D/machos_outside_system.txt"
  } > "$D/machos_verified.txt"

  # ZIP / archive hunt in suspect locations
  log INFO "Archive hunt in suspect locations..."
  /usr/bin/find /tmp /private/tmp /var/tmp /Users/Shared "$TARGET_HOME" \
    -xdev -type f \( -name '*.zip' -o -name '*.tar.gz' -o -name 'out' -o -name 'data' \) \
    -mtime -30 ! -path '*/Library/Caches/*' ! -path '*/node_modules/*' 2>/dev/null > "$D/archives_recent.txt"
  {
    while read -r a; do
      [[ -f "$a" ]] || continue
      echo "=== $a ==="
      stat_meta "$a"
      echo "--- contents ---"
      /usr/bin/unzip -l "$a" 2>/dev/null | head -80
      echo
    done < "$D/archives_recent.txt"
  } > "$D/archives_inspected.txt"

  # Files in download-typical locations lacking quarantine xattr
  log INFO "Quarantine-xattr anomaly check..."
  {
    echo "# Executables/scripts in /tmp or Downloads modified in last 30d without com.apple.quarantine"
    /usr/bin/find /tmp /private/tmp "$TARGET_HOME/Downloads" -xdev -type f -mtime -30 2>/dev/null | \
    while read -r f; do
      /usr/bin/xattr -lp com.apple.quarantine "$f" >/dev/null 2>&1 && continue
      local ft=$(/usr/bin/file -b "$f" 2>/dev/null)
      case "$ft" in
        Mach-O*|*executable*|*script*)
          echo "MISSING_QUARANTINE: $f  [$ft]"
          ;;
      esac
    done
  } > "$D/no_quarantine.txt"

  # Hidden directories under HOME created recently
  log INFO "Recent hidden directories under \$HOME..."
  /usr/bin/find "$TARGET_HOME" -maxdepth 3 -type d -name '.[!.]*' -mtime -30 \
    ! -path '*/Library/*' 2>/dev/null > "$D/recent_hidden_dirs.txt"

  # AMOS-specific staging directory check
  for sd in "$TARGET_HOME/fg" "$TARGET_HOME/.fg" "$TARGET_HOME/Library/.fg" \
            "$TARGET_HOME/.config/fg" "$TARGET_HOME/Library/data"; do
    [[ -d "$sd" ]] || continue
    log WARN "Suspect staging dir found: $sd"
    {
      echo "=== STAGING DIR: $sd ==="
      /bin/ls -laR "$sd"
      echo
      /usr/bin/find "$sd" -type f -exec /usr/bin/stat -f '%N atime=%Sa mtime=%Sm size=%z' {} \;
    } >> "$D/staging_dirs.txt"
    safe_cp "$sd" "$D/captured_samples/${sd#/}"
  done
}

# ============================================================================
# PHASE 3 — Persistence enumeration
# ============================================================================
phase3_persistence() {
  log PHASE "PHASE 3 — Persistence enumeration"
  local D="$OUT/03_persistence"
  mkdir -p "$D"

  # LaunchAgents / LaunchDaemons
  {
    for d in \
      "$TARGET_HOME/Library/LaunchAgents" \
      /Library/LaunchAgents \
      /Library/LaunchDaemons \
      /System/Library/LaunchAgents \
      /System/Library/LaunchDaemons; do
      echo "=================================="
      echo "DIR: $d"
      echo "=================================="
      /bin/ls -la@ "$d" 2>/dev/null
      echo
    done
  } > "$D/launchd_dirs.txt"

  # Third-party launchd plists (skip Apple's own, but keep .plist matching impersonation patterns)
  log INFO "Inspecting third-party LaunchAgents/Daemons..."
  {
    for d in "$TARGET_HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons; do
      [[ -d "$d" ]] || continue
      for p in "$d"/*.plist(N); do
        local label=$(basename "$p")
        echo "================================"
        echo "PLIST: $p"
        echo "================================"
        stat_meta "$p"
        echo "--- contents ---"
        /usr/libexec/PlistBuddy -c "Print" "$p" 2>/dev/null || /bin/cat "$p"
        # Get the program path and codesign it
        local prog=$(/usr/libexec/PlistBuddy -c "Print :Program" "$p" 2>/dev/null)
        [[ -z "$prog" ]] && prog=$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:0" "$p" 2>/dev/null)
        if [[ -n "$prog" && -f "$prog" ]]; then
          echo "--- referenced program: $prog ---"
          stat_meta "$prog"
          /usr/bin/codesign -dv --verbose=4 "$prog" 2>&1 | head -10
          /usr/sbin/spctl -a -vv "$prog" 2>&1
        fi
        echo
      done
    done
  } > "$D/launchd_plists_inspected.txt"

  # Apple-impersonating plists in user dir (real Apple plists live in /System)
  log INFO "Apple-impersonating plist check..."
  /usr/bin/find "$TARGET_HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons \
    -type f -name 'com.apple.*' -o -name 'com.finder.*' 2>/dev/null > "$D/apple_impersonators.txt"

  # launchctl runtime
  run "launchctl list (user)"        "$D/launchctl_user.txt"   -- "sudo -u $TARGET_USER launchctl list"
  run "launchctl list (root)"        "$D/launchctl_root.txt"   -- launchctl list
  run "launchctl print gui session"  "$D/launchctl_gui.txt"    -- "launchctl print gui/$(id -u $TARGET_USER) 2>&1 | head -300"
  run "launchctl print system"       "$D/launchctl_system.txt" -- "launchctl print system 2>&1 | head -300"

  # Login items + BTM (Background Task Management) — Ventura+
  run "osascript loginitems"         "$D/loginitems_osa.txt"   -- \
    "sudo -u $TARGET_USER osascript -e 'tell application \"System Events\" to get name of every login item'"
  run "sfltool dumpbtm (user)"       "$D/btm_user.txt"         -- "sudo -u $TARGET_USER sfltool dumpbtm"
  run "sfltool dumpbtm (root)"       "$D/btm_root.txt"         -- sfltool dumpbtm

  # cron / at / periodic
  run "user crontab"                 "$D/crontab_user.txt"     -- "sudo -u $TARGET_USER crontab -l"
  run "root crontab"                 "$D/crontab_root.txt"     -- crontab -l
  run "at jobs"                      "$D/at_jobs.txt"          -- "ls -la /var/at/jobs 2>/dev/null"
  run "periodic dirs"                "$D/periodic.txt"         -- "ls -la /etc/periodic*/ /etc/cron* 2>/dev/null"

  # Shell init files
  log INFO "Capturing shell init files..."
  {
    for rc in \
      "$TARGET_HOME/.zshenv" "$TARGET_HOME/.zprofile" "$TARGET_HOME/.zshrc" \
      "$TARGET_HOME/.zlogin" "$TARGET_HOME/.zlogout" \
      "$TARGET_HOME/.bash_profile" "$TARGET_HOME/.bashrc" \
      "$TARGET_HOME/.profile" "$TARGET_HOME/.bash_login" \
      /etc/zshenv /etc/zprofile /etc/zshrc /etc/zlogin \
      /etc/profile /etc/bashrc; do
      if [[ -f "$rc" ]]; then
        echo "================================"
        echo "FILE: $rc"
        echo "================================"
        stat_meta "$rc"
        echo "--- contents ---"
        /bin/cat "$rc"
        echo
      fi
    done
  } > "$D/shell_rc_files.txt"

  # Suspect lines in shell init
  log INFO "Searching shell init for suspect patterns..."
  /usr/bin/grep -nHE 'curl|wget|base64|eval|source.*http|/tmp/' \
    "$TARGET_HOME"/.zsh* "$TARGET_HOME"/.bash* "$TARGET_HOME"/.profile \
    /etc/zsh* /etc/bash* /etc/profile 2>/dev/null > "$D/shell_rc_suspects.txt"

  # SSH state
  log INFO "Capturing SSH state..."
  {
    echo "=== ~/.ssh/ listing ==="
    /bin/ls -la "$TARGET_HOME/.ssh/" 2>/dev/null
    echo
    for f in "$TARGET_HOME/.ssh/authorized_keys" "$TARGET_HOME/.ssh/config" "$TARGET_HOME/.ssh/known_hosts"; do
      if [[ -f "$f" ]]; then
        echo "=== $f ==="
        stat_meta "$f"
        echo "--- contents ---"
        /bin/cat "$f"
        echo
      fi
    done
  } > "$D/ssh_state.txt"

  # sudoers / sudoers.d
  run "sudoers"                      "$D/sudoers.txt"          -- "cat /etc/sudoers"
  run "sudoers.d listing"            "$D/sudoers_d_ls.txt"     -- "ls -la /etc/sudoers.d/"
  run "sudoers.d contents"           "$D/sudoers_d.txt"        -- \
    "for f in /etc/sudoers.d/*; do [ -f \"\$f\" ] && echo === \"\$f\" === && cat \"\$f\"; done"
  run "sudoers NOPASSWD grep"        "$D/sudoers_nopasswd.txt" -- \
    "grep -rE 'NOPASSWD|ALL=' /etc/sudoers /etc/sudoers.d/ 2>/dev/null"

  # PAM
  run "PAM dir listing"              "$D/pam_dir.txt"          -- "ls -la /etc/pam.d/"
  run "PAM recent modifications"     "$D/pam_recent.txt"       -- "find /etc/pam.d -mtime -90"

  # Login/logout hooks (legacy)
  run "user LoginHook"               "$D/loginhook_user.txt"   -- "sudo -u $TARGET_USER defaults read com.apple.loginwindow LoginHook 2>&1"
  run "user LogoutHook"              "$D/logouthook_user.txt"  -- "sudo -u $TARGET_USER defaults read com.apple.loginwindow LogoutHook 2>&1"
  run "global loginwindow"           "$D/loginwindow_global.txt" -- "defaults read /Library/Preferences/com.apple.loginwindow 2>&1"

  # Configuration profiles (MDM-style)
  run "profiles list (user)"         "$D/profiles_user.txt"    -- "sudo -u $TARGET_USER profiles list 2>&1"
  run "profiles list (system)"       "$D/profiles_system.txt"  -- "profiles list 2>&1"
  run "profiles show -all"           "$D/profiles_all.txt"     -- "profiles show -all 2>&1"

  # Authorization DB
  run "authdb system.login.console"  "$D/authdb_login.txt"     -- \
    "security authorizationdb read system.login.console 2>&1"

  # Dock / Finder hooks
  run "Dock persistent-apps"         "$D/dock.txt"             -- \
    "sudo -u $TARGET_USER defaults read com.apple.dock persistent-apps 2>&1 | grep -A2 _CFURLString"

  # Browser extension persistence implants
  log INFO "Enumerating browser extensions..."
  {
    for path in \
      "$TARGET_HOME/Library/Application Support/Google/Chrome/Default/Extensions" \
      "$TARGET_HOME/Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions" \
      "$TARGET_HOME/Library/Application Support/Microsoft Edge/Default/Extensions" \
      "$TARGET_HOME/Library/Application Support/Vivaldi/Default/Extensions" \
      "$TARGET_HOME/Library/Application Support/Arc/User Data/Default/Extensions" \
      "$TARGET_HOME/Library/Safari/Extensions"; do
      if [[ -d "$path" ]]; then
        echo "=== $path ==="
        /bin/ls -la "$path" 2>/dev/null
        echo
      fi
    done
    # Firefox profile-based extensions
    for prof in "$TARGET_HOME/Library/Application Support/Firefox/Profiles"/*; do
      [[ -d "$prof/extensions" ]] || continue
      echo "=== $prof/extensions ==="
      /bin/ls -la "$prof/extensions" 2>/dev/null
      echo
    done
  } > "$D/browser_extensions.txt"
}

# ============================================================================
# PHASE 4 — Unified log, FSEvents, history, TCC
# ============================================================================
phase4_logs() {
  log PHASE "PHASE 4 — Logs, FSEvents, history, TCC"
  local D="$OUT/04_logs"
  mkdir -p "$D"

  # Full unified log archive (most important single artifact)
  log INFO "Collecting unified log archive (--last $LOG_LOOKBACK)... this takes 1-3 min"
  /usr/bin/log collect --output "$D/unifiedlog.logarchive" --last "$LOG_LOOKBACK" 2>>"$ERR_FILE" \
    && log OK "unified log archive saved" \
    || log WARN "log collect failed (see run.err)"

  # Raw tracev3 + uuidtext for offline parsing (mac_apt, UnifiedLogReader)
  log INFO "Snapshotting /var/db/diagnostics & uuidtext..."
  /usr/bin/tar -czf "$D/diagnostics_raw.tgz" \
    /var/db/diagnostics /var/db/uuidtext 2>/dev/null \
    && log OK "raw tracev3 snapshot saved" \
    || log WARN "diagnostics tar failed"

  # Targeted log queries (faster pivots — read by IR analyst before opening archive)
  log INFO "Running targeted unified log queries..."

  run "log: helper / /tmp/helper exec"  "$D/log_helper.txt" -- \
    "log show --style syslog --info --last $LOG_LOOKBACK --predicate '
      (process == \"helper\") OR
      (eventMessage CONTAINS \"/tmp/helper\") OR
      (eventMessage CONTAINS \"/tmp/update\")'"

  run "log: shell paste evidence"       "$D/log_shell.txt"  -- \
    "log show --style syslog --info --last $LOG_LOOKBACK --predicate '
      (process == \"zsh\" OR process == \"Terminal\" OR process == \"iTerm2\" OR process == \"wezterm-gui\")
      AND (eventMessage CONTAINS \"curl\" OR eventMessage CONTAINS \"base64\" OR eventMessage CONTAINS \"eval\")'"

  run "log: curl activity"              "$D/log_curl.txt"   -- \
    "log show --style syslog --info --last $LOG_LOOKBACK --predicate 'process == \"curl\"'"

  run "log: osascript activity"         "$D/log_osascript.txt" -- \
    "log show --style syslog --info --last $LOG_LOOKBACK --predicate 'process == \"osascript\"'"

  run "log: osascript password dialogs" "$D/log_osascript_dialog.txt" -- \
    "log show --style syslog --info --last $LOG_LOOKBACK --predicate '
      process == \"osascript\" AND
      (eventMessage CONTAINS \"display dialog\" OR eventMessage CONTAINS \"hidden answer\")'"

  run "log: DNS / mDNSResponder C2"     "$D/log_dns_c2.txt" -- \
    "log show --style syslog --info --last $LOG_LOOKBACK --predicate '
      subsystem == \"com.apple.network\" OR subsystem == \"com.apple.mDNSResponder\"' | \
      grep -iE 'faced31|stratos37|homebrewclubs|homebrewfaq|homebrewonline|homebrewupdate|logmel|tradingviewen|sites-phantom|filmoraus|93\\.152\\.230\\.79|195\\.82\\.147\\.38' || true"

  run "log: keychain access"            "$D/log_keychain.txt" -- \
    "log show --style syslog --info --last $LOG_LOOKBACK --predicate '
      subsystem == \"com.apple.securityd\" OR process == \"security\"'"

  run "log: Gatekeeper / XProtect"      "$D/log_gatekeeper.txt" -- \
    "log show --style syslog --info --last $LOG_LOOKBACK --predicate '
      process == \"syspolicyd\" OR process == \"amfid\" OR
      subsystem == \"com.apple.syspolicy\" OR subsystem == \"com.apple.xprotect\"'"

  run "log: TCC prompts"                "$D/log_tcc.txt"    -- \
    "log show --style syslog --info --last $LOG_LOOKBACK --predicate '
      subsystem == \"com.apple.TCC\" OR process == \"tccd\"'"

  # TCC databases (current state of granted permissions)
  log INFO "Snapshotting TCC databases..."
  /usr/bin/sqlite3 "$TARGET_HOME/Library/Application Support/com.apple.TCC/TCC.db" \
    "SELECT client, service, auth_value, datetime(last_modified,'unixepoch') as ts FROM access ORDER BY last_modified DESC;" \
    > "$D/tcc_user.txt" 2>>"$ERR_FILE"
  /usr/bin/sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" \
    "SELECT client, service, auth_value, datetime(last_modified,'unixepoch') as ts FROM access ORDER BY last_modified DESC;" \
    > "$D/tcc_system.txt" 2>>"$ERR_FILE"
  safe_cp "$TARGET_HOME/Library/Application Support/com.apple.TCC/TCC.db" "$D/TCC_user.db"
  safe_cp "/Library/Application Support/com.apple.TCC/TCC.db" "$D/TCC_system.db"

  # FSEvents — kernel-level filesystem activity log
  log INFO "Copying FSEvents (kernel-level filesystem log)..."
  /bin/ls -la /.fseventsd/ > "$D/fseventsd_list.txt" 2>>"$ERR_FILE"
  /usr/bin/tar -czf "$D/fseventsd_raw.tgz" /.fseventsd 2>/dev/null \
    && log OK "FSEvents snapshot saved" \
    || log WARN "fseventsd tar failed (SIP may block)"

  # Quick text extraction for IOC strings
  log INFO "Extracting FSEvents strings (last 30d files)..."
  /usr/bin/find /.fseventsd -type f -mtime -30 2>/dev/null | head -200 | while read -r f; do
    /usr/bin/gunzip -c "$f" 2>/dev/null
  done | /usr/bin/strings | /usr/bin/sort -u > "$D/fseventsd_strings.txt"
  /usr/bin/grep -iE '/tmp/helper|/fg/|osalogging|wallet|keychain|Cookies|/Users/Shared' \
    "$D/fseventsd_strings.txt" > "$D/fseventsd_iocs.txt" 2>/dev/null

  # Shell histories — the user's own record of the paste
  log INFO "Capturing shell histories..."
  {
    for h in \
      "$TARGET_HOME/.zsh_history" "$TARGET_HOME/.zhistory" \
      "$TARGET_HOME/.bash_history" "$TARGET_HOME/.history" \
      "$TARGET_HOME/.local/share/fish/fish_history"; do
      if [[ -f "$h" ]]; then
        echo "================================"
        echo "FILE: $h"
        echo "================================"
        stat_meta "$h"
        echo "--- contents (last 500 lines) ---"
        /usr/bin/tail -500 "$h"
        echo
      fi
    done
  } > "$D/shell_histories.txt"
  # Also copy raw histories
  safe_cp "$TARGET_HOME/.zsh_history" "$D/raw_zsh_history"
  safe_cp "$TARGET_HOME/.bash_history" "$D/raw_bash_history"

  # Smoking-gun grep: the actual paste line
  /usr/bin/grep -nE 'curl.*\|.*zsh|curl.*\|.*bash|base64.*-[dD]|brewe?\.sh|brew\.org|brew\.click' \
    "$TARGET_HOME"/.zsh_history "$TARGET_HOME"/.bash_history 2>/dev/null > "$D/paste_evidence.txt"

  # QuickLook thumbnail cache (sometimes reveals viewed files)
  run "QuickLook thumb cache listing" "$D/quicklook.txt" -- \
    "ls -la '$TARGET_HOME/Library/Application Support/Quick Look/' 2>&1"

  # Spotlight metadata (read-only)
  log INFO "Spotlight metadata for recent files..."
  /usr/bin/mdfind -onlyin /tmp 'kMDItemFSCreationDate >= $time.this_week' \
    > "$D/mdfind_tmp.txt" 2>/dev/null
  sudo -u "$TARGET_USER" /usr/bin/mdfind -onlyin "$TARGET_HOME" \
    'kMDItemFSCreationDate >= $time.this_week' > "$D/mdfind_home.txt" 2>/dev/null
}

# ============================================================================
# PHASE 5 — Credential & secret blast radius enumeration
# ============================================================================
phase5_secrets() {
  log PHASE "PHASE 5 — Credential blast radius"
  local D="$OUT/05_secrets"
  mkdir -p "$D"

  log WARN "Phase 5 enumerates secret LOCATIONS and access times, NOT secret contents"
  log WARN "Keychain item names are listed; no keys/passwords are dumped to disk"

  # Keychain inventory (names only, NOT contents)
  log INFO "Enumerating Keychain item names (no contents)..."
  run "Keychain list"                   "$D/keychains_list.txt" -- \
    "sudo -u $TARGET_USER security list-keychains"

  sudo -u "$TARGET_USER" /usr/bin/security dump-keychain 2>/dev/null | \
    /usr/bin/awk '/"svce"|"acct"|0x00000007/ {print}' | \
    /usr/bin/sort -u > "$D/keychain_items_NAMES_ONLY.txt"

  # Browser credential stores — atime/mtime/size only
  log INFO "Browser credential store inspection..."
  {
    echo "# Browser credential store file metadata (atime is critical evidence)"
    echo "# If atime > infection time and user didn't open browser in that window,"
    echo "# the file was read by the malware."
    echo
    for browser_path in \
      "$TARGET_HOME/Library/Application Support/Google/Chrome/Default" \
      "$TARGET_HOME/Library/Application Support/BraveSoftware/Brave-Browser/Default" \
      "$TARGET_HOME/Library/Application Support/Microsoft Edge/Default" \
      "$TARGET_HOME/Library/Application Support/Chromium/Default" \
      "$TARGET_HOME/Library/Application Support/Arc/User Data/Default" \
      "$TARGET_HOME/Library/Application Support/Vivaldi/Default" \
      "$TARGET_HOME/Library/Application Support/com.operasoftware.Opera" \
      "$TARGET_HOME/Library/Application Support/com.operasoftware.OperaGX"; do
      [[ -d "$browser_path" ]] || continue
      echo "=========================================="
      echo "BROWSER: $browser_path"
      echo "=========================================="
      for f in 'Login Data' 'Cookies' 'Web Data' 'History' 'Local State' 'Local Extension Settings' 'IndexedDB'; do
        local p="$browser_path/$f"
        if [[ -e "$p" ]]; then
          stat_meta "$p"
          echo
        fi
      done
    done
    # Firefox
    for prof in "$TARGET_HOME/Library/Application Support/Firefox/Profiles"/*(N); do
      [[ -d "$prof" ]] || continue
      echo "=========================================="
      echo "FIREFOX PROFILE: $prof"
      echo "=========================================="
      for f in logins.json key4.db cookies.sqlite places.sqlite; do
        local p="$prof/$f"
        if [[ -e "$p" ]]; then
          stat_meta "$p"
          echo
        fi
      done
    done
    # Safari
    echo "=========================================="
    echo "SAFARI"
    echo "=========================================="
    for f in \
      "$TARGET_HOME/Library/Safari/Cookies.binarycookies" \
      "$TARGET_HOME/Library/Cookies/Cookies.binarycookies" \
      "$TARGET_HOME/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies" \
      "$TARGET_HOME/Library/Safari/History.db" \
      "$TARGET_HOME/Library/Keychains/login.keychain-db"; do
      [[ -e "$f" ]] && { stat_meta "$f"; echo; }
    done
  } > "$D/browser_credstores.txt"

  # Crypto wallet artifacts
  log INFO "Crypto wallet artifact inspection..."
  {
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
      if [[ -e "$w" ]]; then
        echo "=========================================="
        echo "WALLET PATH: $w"
        echo "=========================================="
        /bin/ls -la "$w" 2>/dev/null
        /usr/bin/find "$w" -type f \( -name '*wallet*' -o -name '*keys*' -o \
          -name '*seed*' -o -name '*.json' -o -name '*.dat' \) 2>/dev/null | \
          while read -r f; do
            stat_meta "$f"
            echo
          done
      fi
    done

    # Browser extension wallets (MetaMask, Phantom, Keplr, etc.)
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
    for browser in Chrome 'BraveSoftware/Brave-Browser' 'Microsoft Edge' Vivaldi; do
      local base="$TARGET_HOME/Library/Application Support/$browser/Default/Local Extension Settings"
      [[ -d "$base" ]] || continue
      for id name in ${(kv)EXT_WALLETS}; do
        local p="$base/$id"
        if [[ -d "$p" ]]; then
          echo "=========================================="
          echo "EXT WALLET: $name ($id) in $browser"
          echo "=========================================="
          /bin/ls -la "$p"
          /usr/bin/find "$p" -type f 2>/dev/null | while read -r f; do
            stat_meta "$f"
            echo
          done
        fi
      done
    done
  } > "$D/wallets.txt"

  # Developer secrets
  log INFO "Developer secrets inspection..."
  {
    for f in \
      "$TARGET_HOME/.ssh"/id_* \
      "$TARGET_HOME/.ssh/known_hosts" "$TARGET_HOME/.ssh/config" \
      "$TARGET_HOME/.aws/credentials" "$TARGET_HOME/.aws/config" \
      "$TARGET_HOME/.aws/sso/cache"/* \
      "$TARGET_HOME/.azure"/* \
      "$TARGET_HOME/.config/gcloud"/* \
      "$TARGET_HOME/.config/gh/hosts.yml" \
      "$TARGET_HOME/.kube/config" \
      "$TARGET_HOME/.docker/config.json" \
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
      [[ -e "$f" ]] || continue
      stat_meta "$f"
      echo
    done
  } > "$D/dev_secrets.txt"

  # Apple Notes — high-value exfil target for password-storing users
  log INFO "Apple Notes artifact inspection..."
  {
    local notes_dir="$TARGET_HOME/Library/Group Containers/group.com.apple.notes"
    if [[ -d "$notes_dir" ]]; then
      /bin/ls -la "$notes_dir/"
      echo
      for f in "$notes_dir/NoteStore.sqlite"*; do
        [[ -e "$f" ]] && { stat_meta "$f"; echo; }
      done
    fi
  } > "$D/notes.txt"

  # iCloud Keychain sync state
  run "iCloud Keychain sync state"  "$D/icloud_kc.txt" -- \
    "sudo -u $TARGET_USER defaults read MobileMeAccounts 2>&1 | grep -A2 KEYCHAIN_SYNC"

  # Password manager local containers
  log INFO "Password manager container inspection..."
  {
    for pm in \
      "$TARGET_HOME/Library/Containers/com.agilebits.onepassword7" \
      "$TARGET_HOME/Library/Containers/com.1password.1password" \
      "$TARGET_HOME/Library/Application Support/Bitwarden" \
      "$TARGET_HOME/Library/Application Support/dashlane" \
      "$TARGET_HOME/Library/Application Support/keeper" \
      "$TARGET_HOME/Library/Application Support/com.lastpass.LastPass"; do
      if [[ -e "$pm" ]]; then
        echo "=== $pm ==="
        /bin/ls -la "$pm" 2>/dev/null
        echo
      fi
    done
  } > "$D/password_managers.txt"
}

# ============================================================================
# PHASE 6 — Mach-O sample collection (additional sweep)
# ============================================================================
phase6_samples() {
  log PHASE "PHASE 6 — Additional Mach-O sample collection"
  local D="$OUT/06_samples"
  mkdir -p "$D"

  # Build a comprehensive list of suspect binaries already captured in Phase 2
  # Plus a few additional locations
  log INFO "Final sweep of suspect binary locations..."
  /usr/bin/find \
    "$TARGET_HOME/Library/Application Support" \
    "$TARGET_HOME/.config" \
    "$TARGET_HOME/.local" \
    /Users/Shared /opt /tmp /private/tmp /var/tmp \
    -xdev -type f -size -50M 2>/dev/null | while read -r f; do
      local out=$(/usr/bin/file -b "$f" 2>/dev/null)
      case "$out" in
        Mach-O*)
          local sig=$(/usr/bin/codesign -dv "$f" 2>&1)
          # Flag if ad-hoc, revoked, or no signature
          if echo "$sig" | /usr/bin/grep -qE 'adhoc|revoked|not signed|invalid'; then
            echo "SUSPECT: $f"
            echo "  type: $out"
            echo "$sig" | /usr/bin/sed 's/^/  sig: /'
            echo
          fi
          ;;
      esac
  done > "$D/suspect_unsigned_machos.txt"
}

# ============================================================================
# PHASE 7 — System metadata & security posture
# ============================================================================
phase7_sysmeta() {
  log PHASE "PHASE 7 — System metadata & security posture"
  local D="$OUT/07_sysmeta"
  mkdir -p "$D"

  run "macOS version"            "$D/sw_vers.txt"          -- sw_vers
  run "Kernel version"           "$D/uname.txt"            -- "uname -a"
  run "Hardware info"            "$D/hardware.txt"         -- "system_profiler SPHardwareDataType"
  run "Software info"            "$D/software.txt"         -- "system_profiler SPSoftwareDataType"
  run "Installed apps"           "$D/installed_apps.txt"   -- "system_profiler SPApplicationsDataType -detailLevel mini"

  # XProtect / MRT data versions — critical for understanding why malware was/wasn't blocked
  run "XProtect version"         "$D/xprotect_version.txt" -- \
    "defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist CFBundleShortVersionString 2>&1"
  run "XProtect Remediator versions" "$D/xprotect_remediator.txt" -- \
    "ls -la /Library/Apple/System/Library/CoreServices/XProtect.app 2>&1; defaults read /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist 2>&1"
  run "MRT version (legacy)"     "$D/mrt_version.txt"      -- \
    "defaults read /Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist 2>&1"
  run "Gatekeeper status"        "$D/gatekeeper.txt"       -- "spctl --status"
  run "SIP status"               "$D/sip_status.txt"       -- "csrutil status"
  run "AMFI boot args"           "$D/amfi.txt"             -- "nvram boot-args 2>&1"

  # MDM enrollment
  run "MDM profiles"             "$D/mdm.txt"              -- "profiles status -type enrollment 2>&1"

  # FileVault status
  run "FileVault status"         "$D/filevault.txt"        -- "fdesetup status 2>&1"

  # Firewall
  run "App firewall state"       "$D/firewall.txt"         -- "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>&1; /usr/libexec/ApplicationFirewall/socketfilterfw --listapps 2>&1"

  # Disk layout
  run "Disk list"                "$D/diskutil.txt"         -- "diskutil list"
  run "APFS info"                "$D/apfs.txt"             -- "diskutil apfs list"
  run "df"                       "$D/df.txt"               -- "df -h"

  # Configuration
  run "powermetrics summary"     "$D/powermetrics.txt"     -- "powermetrics -i 1 -n 1 --samplers all 2>&1 | head -200"
}

# ============================================================================
# PHASE 8 — IOC sweep, manifest, bundle
# ============================================================================
phase8_finalize() {
  log PHASE "PHASE 8 — Finalize: IOC sweep, manifest, bundle"
  local D="$OUT/08_final"
  mkdir -p "$D"

  # IOC sweep across all collected outputs
  log INFO "Sweeping all collected data for known IOCs..."
  {
    echo "# IOC hit report — Odyssey/AMOS campaign indicators"
    echo "# Generated: $(ts)"
    echo
    for ioc in "${IOC_STRINGS[@]}"; do
      echo "================================"
      echo "IOC: $ioc"
      echo "================================"
      /usr/bin/grep -rIn --binary-files=without-match "$ioc" "$OUT" 2>/dev/null \
        | /usr/bin/grep -v "$D/ioc_hits.txt" \
        | head -100
      echo
    done
  } > "$D/ioc_hits.txt"

  local hit_count=$(/usr/bin/grep -cE '^[^=]' "$D/ioc_hits.txt" 2>/dev/null || echo 0)
  if [[ $hit_count -gt 0 ]]; then
    log WARN "IOC hits: $hit_count lines flagged — see 08_final/ioc_hits.txt"
  else
    log INFO "No IOC string hits in collected data (this does NOT mean clean — encrypted/missing logs)"
  fi

  # Compromise depth assessment scaffold
  log INFO "Generating compromise depth assessment scaffold..."
  cat > "$D/COMPROMISE_DEPTH.md" <<EOF
# Compromise Depth Assessment — ${CASE_ID}

Generated: $(ts)

Review the following indicators in the collected evidence to populate this matrix.

## Indicator checklist

- [ ] Stage-1 zsh wrapper executed (check \`04_logs/log_shell.txt\` + \`04_logs/paste_evidence.txt\`)
- [ ] Stage-2 beacon to faced31.com fired (check \`04_logs/log_curl.txt\` + \`04_logs/log_dns_c2.txt\`)
- [ ] Stage-3 /tmp/helper downloaded (check \`02_disk/known_paths.txt\` + \`04_logs/log_curl.txt\`)
- [ ] Stage-3 /tmp/helper executed (check \`04_logs/log_helper.txt\` for posix_spawn or exec events)
- [ ] osascript "display dialog" + "hidden answer" fired (check \`04_logs/log_osascript_dialog.txt\`)
- [ ] security/keychain access by non-Apple process (check \`04_logs/log_keychain.txt\`)
- [ ] curl POST exfiltration outbound (check \`04_logs/log_curl.txt\` for -F file= patterns)
- [ ] Persistence plist installed (check \`03_persistence/launchd_plists_inspected.txt\`)
- [ ] Sensitive file atimes updated in incident window (check \`05_secrets/*\`)

## Classification (fill in)

| Pattern | Match? |
|---|---|
| **Beacon only** | |
| **Stage-3 ran, no password capture** | |
| **Full compromise (Keychain captured)** | |
| **Persistent foothold** | |

## Notes

EOF

  # Build SHA-256 manifest of every collected file
  log INFO "Building SHA-256 manifest..."
  (cd "$OUT" && /usr/bin/find . -type f ! -path "./_meta/MANIFEST.sha256" \
    -exec /usr/bin/shasum -a 256 {} +) > "$MANIFEST"

  local file_count=$(/usr/bin/wc -l < "$MANIFEST")
  local total_size=$(/usr/bin/du -sh "$OUT" | awk '{print $1}')
  log OK "Manifest: $file_count files, $total_size"

  # README in the bundle
  cat > "$OUT/README.md" <<EOF
# IR Evidence Bundle — ${CASE_ID}

**Collected:** $(ts)
**Host:** $(hostname)
**Target user:** ${TARGET_USER}
**Script version:** ${SCRIPT_VERSION}
**Log lookback:** ${LOG_LOOKBACK}

## Structure

| Dir | Contents |
|---|---|
| \`_meta/\` | Run log, error log, SHA-256 manifest, this README |
| \`00_freeze/\` | Wall clock, uptime, APFS snapshot reference |
| \`01_volatile/\` | Process tree, lsof, netstat, network state |
| \`02_disk/\` | Known-bad paths, time-bracket file search, Mach-O hunt, archives, captured samples |
| \`03_persistence/\` | LaunchAgents/Daemons, launchctl, BTM, cron, shell init, SSH, sudoers, profiles |
| \`04_logs/\` | Unified log archive + raw tracev3, targeted queries, TCC, FSEvents, shell history |
| \`05_secrets/\` | Keychain item NAMES (no contents), browser/wallet/dev-secret file metadata |
| \`06_samples/\` | Additional suspect Mach-O sweep |
| \`07_sysmeta/\` | macOS version, XProtect/Gatekeeper status, MDM, FileVault, hardware |
| \`08_final/\` | IOC sweep results, compromise depth assessment template |

## Quick triage

1. Open \`08_final/ioc_hits.txt\` — direct evidence of campaign IOCs in collected data.
2. Open \`04_logs/log_helper.txt\` and \`log_curl.txt\` — proves Stage-3 execution and C2 contact.
3. Open \`04_logs/log_osascript_dialog.txt\` — proves password dialog displayed.
4. Open \`04_logs/paste_evidence.txt\` — exact command line the user pasted.
5. Open \`03_persistence/apple_impersonators.txt\` and \`launchd_plists_inspected.txt\` — persistence check.
6. Open \`05_secrets/browser_credstores.txt\` and \`wallets.txt\` — atime evidence of malware access.
7. Fill in \`08_final/COMPROMISE_DEPTH.md\`.

## Integrity

All files are listed with SHA-256 in \`_meta/MANIFEST.sha256\`.
Verify integrity at any time with:
\`\`\`
cd ${CASE_ID} && shasum -a 256 -c _meta/MANIFEST.sha256
\`\`\`

## Chain of custody

The full sequence of commands executed during collection is logged in
\`_meta/run.log\`. Any non-zero exit codes / errors are in \`_meta/run.err\`.
EOF

  log INFO "Creating compressed bundle..."
  local SCRIPT_END_EPOCH=$(date -u +%s)
  local elapsed=$((SCRIPT_END_EPOCH - SCRIPT_START_EPOCH))
  log INFO "Total collection time: ${elapsed}s"

  cd "$EVIDENCE_BASE" || return
  /usr/bin/tar -czf "${CASE_ID}.tar.gz" "$CASE_ID" 2>>"$ERR_FILE"
  /usr/bin/shasum -a 256 "${CASE_ID}.tar.gz" > "${CASE_ID}.tar.gz.sha256"
  local bundle_size=$(/usr/bin/du -sh "${CASE_ID}.tar.gz" | awk '{print $1}')
  log OK "Bundle: ${EVIDENCE_BASE}/${CASE_ID}.tar.gz  (${bundle_size})"
  log OK "Hash:   ${EVIDENCE_BASE}/${CASE_ID}.tar.gz.sha256"
  cat "${CASE_ID}.tar.gz.sha256"
}

# ============================================================================
# Main
# ============================================================================
main() {
  printf "\n${CW}╔══════════════════════════════════════════════════════════════════╗${CN}\n"
  printf "${CW}║       macOS IR Evidence Collector  v%-7s                     ║${CN}\n" "$SCRIPT_VERSION"
  printf "${CW}║       Threat: Odyssey/AMOS Stealer (ClickFix)                    ║${CN}\n"
  printf "${CW}╚══════════════════════════════════════════════════════════════════╝${CN}\n\n"

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

  printf "\n${CG}════════════════════════════════════════════════════════════════════${CN}\n"
  printf "${CG} COLLECTION COMPLETE${CN}\n"
  printf "${CG}════════════════════════════════════════════════════════════════════${CN}\n"
  printf " Bundle:   ${CW}%s/%s.tar.gz${CN}\n" "$EVIDENCE_BASE" "$CASE_ID"
  printf " Hash:     ${CW}%s/%s.tar.gz.sha256${CN}\n" "$EVIDENCE_BASE" "$CASE_ID"
  printf " Manifest: ${CW}%s/_meta/MANIFEST.sha256${CN}\n" "$OUT"
  printf " Run log:  ${CW}%s${CN}\n" "$LOG_FILE"
  printf "\n${CY} Next steps:${CN}\n"
  printf "  1. Verify hash, transfer bundle to analysis workstation over USB.\n"
  printf "  2. Review ${CW}%s/08_final/ioc_hits.txt${CN} first.\n" "$OUT"
  printf "  3. Open unified log archive on analyst Mac:\n"
  printf "     ${CW}log show --archive %s/04_logs/unifiedlog.logarchive --info ...${CN}\n" "$OUT"
  printf "  4. Fill in ${CW}%s/08_final/COMPROMISE_DEPTH.md${CN}.\n\n" "$OUT"
}

main "$@"
