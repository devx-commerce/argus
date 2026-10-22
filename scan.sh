#!/usr/bin/env bash
# argus - read-only host compromise and malware triage scanner (macOS + Linux)
# Part of the argus skill. Deterministic layer; the model triages the TSV it emits.
#
# SAFETY CONTRACT (do not weaken):
#   - Read-only. Never deletes, kills, quarantines, chmods, or installs anything.
#   - Never executes a potentially-compromised artifact. Versions of suspect
#     packages are read from the filesystem, never by running pip/npm/the CLI.
#     Any python it runs uses -I -S so .pth / sitecustomize payloads cannot load.
#   - Never phones home. All IOC matching is against local state only.
#   - Redacts matched content: reports file:line + which IOC, not the line text.
#   - Degrades gracefully without sudo, jq, lsof, docker, GNU coreutils.
#
# Exit: 0 clean/info-only, 1 if any HIGH, 2 if any CRIT.

set -u

VERSION="1.0.0"
SELF="$(cd "$(dirname "$0")" && pwd)"
OS="$(uname -s)"
NOW="$(date +%s)"

# ---- options -----------------------------------------------------------------
ROOT_OVERRIDE=""          # --root DIR : scan only this tree (fixture/positive-control mode)
OUTDIR=""                 # --out DIR
WANT_CLAMAV=0             # --clamav   : run clamav only if already installed
WANT_TRIVY=0              # --trivy    : run pinned trivy (CRITICAL only); fetches trivy DB over network
QUIET=0                   # --quiet    : summary only to stdout
NOCOLOR=0

# Pinned Trivy. argus never auto-installs it; use install-trivy.sh (checksum-verified).
TRIVY_PIN="${ARGUS_TRIVY_PIN:-0.72.0}"

usage() {
  cat <<EOF
argus $VERSION - read-only host compromise / malware triage (macOS + Linux)

usage: scan.sh [--root DIR] [--out DIR] [--clamav] [--quiet] [--no-color]

  --root DIR    scan only DIR (filesystem layers only; for positive-control tests)
  --clamav      run clamscan ONLY if clamav is already installed (never installs it)
  --trivy       run pinned trivy (v$TRIVY_PIN) for CRITICAL known-CVEs/secrets/misconfig;
                uses trivy only if already installed (install-trivy.sh installs it, pinned).
                Note: trivy fetches its vulnerability DB over the network.
  --out DIR     write report to DIR (default: a fresh temp dir, printed at the end)
  --quiet       print only the summary to the terminal (full report still written)
  --no-color    disable ANSI color

Read-only. Makes no changes. Full detail: see SKILL.md and PATCHES.md.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --root) ROOT_OVERRIDE="${2:-}"; shift 2;;
    --out) OUTDIR="${2:-}"; shift 2;;
    --clamav) WANT_CLAMAV=1; shift;;
    --trivy) WANT_TRIVY=1; shift;;
    --quiet) QUIET=1; shift;;
    --no-color) NOCOLOR=1; shift;;
    --deep) shift;;  # deep mode is driven by the skill/workflow, not this script
    -h|--help) usage; exit 0;;
    *) echo "unknown option: $1" >&2; usage; exit 64;;
  esac
done

# ---- output sink -------------------------------------------------------------
if [ -z "$OUTDIR" ]; then
  OUTDIR="$(mktemp -d "${TMPDIR:-/tmp}/argus.XXXXXX")" || { echo "cannot create temp dir" >&2; exit 1; }
fi
mkdir -p "$OUTDIR" 2>/dev/null
TSV="$OUTDIR/findings.tsv"
REPORT="$OUTDIR/report.txt"
PIDACC="$OUTDIR/.pidacc"      # correlation accumulator: pid \t reason
: > "$TSV"; : > "$REPORT"; : > "$PIDACC"

# color
if [ -t 1 ] && [ "$NOCOLOR" = 0 ]; then
  C_CRIT=$'\033[1;31m'; C_HIGH=$'\033[31m'; C_MED=$'\033[33m'; C_LOW=$'\033[36m'; C_INFO=$'\033[2m'; C_0=$'\033[0m'
else
  C_CRIT=""; C_HIGH=""; C_MED=""; C_LOW=""; C_INFO=""; C_0=""
fi

n_crit=0; n_high=0; n_med=0; n_low=0; n_info=0

emit() { # sev layer category title evidence
  local sev="$1" layer="$2" cat="$3" title="$4" ev="$5"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$NOW" "$sev" "$layer" "$cat" "$title" "$ev" >> "$TSV"
  local col=""; case "$sev" in
    CRIT) col="$C_CRIT"; n_crit=$((n_crit+1));;
    HIGH) col="$C_HIGH"; n_high=$((n_high+1));;
    MED)  col="$C_MED";  n_med=$((n_med+1));;
    LOW)  col="$C_LOW";  n_low=$((n_low+1));;
    *)    col="$C_INFO"; n_info=$((n_info+1));;
  esac
  printf '[%-4s] %-10s %s  %s\n' "$sev" "$layer" "$title" "$ev" >> "$REPORT"
  [ "$QUIET" = 1 ] && return 0
  [ "$sev" = INFO ] && return 0   # keep terminal readable; INFO lives in the file
  printf '%s[%-4s]%s %-10s %s  %s%s%s\n' "$col" "$sev" "$C_0" "$layer" "$title" "$C_INFO" "$ev" "$C_0"
}

have() { command -v "$1" >/dev/null 2>&1; }
lc() { tr '[:upper:]' '[:lower:]'; }

# file mtime (epoch), portable
fmtime() { if [ "$OS" = Darwin ]; then stat -f %m "$1" 2>/dev/null; else stat -c %Y "$1" 2>/dev/null; fi; }

# ---- scan roots & prune set --------------------------------------------------
FIXTURE=0
if [ -n "$ROOT_OVERRIDE" ]; then
  ROOTS=("$ROOT_OVERRIDE"); FIXTURE=1
else
  ROOTS=("$HOME")
fi

# directories pruned from every filesystem walk: this session's own artifacts,
# the skill itself, cloud-sync trees (reading them triggers downloads), caches,
# and VCS metadata. Prevents self-matching our own IOC strings. In fixture mode
# we trust the supplied --root, so only VCS metadata is pruned.
if [ "$FIXTURE" = 1 ]; then
  PRUNE=( "(" -name ".git" ")" -prune -o )
else
  PRUNE=(
    "(" -path "$HOME/.claude/projects" -o \
        -path "$HOME/.claude/file-history" -o \
        -path "$HOME/.claude/paste-cache" -o \
        -path "$HOME/.claude/debug" -o \
        -path "$HOME/.claude/backups" -o \
        -path "$HOME/.claude/todos" -o \
        -path "$SELF" -o \
        -path "$OUTDIR" -o \
        -path "$HOME/Library/Mobile Documents" -o \
        -path "$HOME/Library/CloudStorage" -o \
        -path "$HOME/Library/Caches" -o \
        -path "$HOME/.Trash" -o \
        -path "/private/tmp/claude-*" -o \
        -name ".git" ")" -prune -o
  )
fi

walk() { # walk ROOT [find-tests...] ; always ends with -print0
  local root="$1"; shift
  [ -d "$root" ] || return 0
  find "$root" "${PRUNE[@]}" "$@" -print0 2>/dev/null
}

# grep a value in a file, report only file:line (content redacted)
grep_redacted() { # iocid sev category value file
  local iocid="$1" sev="$2" cat="$3" val="$4" f="$5"
  [ -f "$f" ] || return 0
  local lines
  lines="$(grep -F -i -n -- "$val" "$f" 2>/dev/null | sed 's/:.*//' | tr '\n' ',' | sed 's/,$//')"
  [ -n "$lines" ] && emit "$sev" "ioc" "$cat" "IOC $iocid matched" "$f (lines $lines)"
}

# ------------------------------------------------------------------------------
echo "argus $VERSION  host=$(hostname 2>/dev/null)  os=$OS  roots=${ROOTS[*]}  $(date)" | tee -a "$REPORT"
[ "$FIXTURE" = 1 ] && echo "(fixture mode: filesystem layers only)" | tee -a "$REPORT"
echo | tee -a "$REPORT"

# ===== LAYER 1 : IOC match (Oct 2026 wave) ====================================
layer1_iocs() {
  # pre-pass: locate cook.pth / cook.py so we can correlate sitecustomize.py
  local cookdirs=""
  local hit
  for r in "${ROOTS[@]}"; do
    while IFS= read -r -d '' hit; do
      cookdirs="$cookdirs:$(dirname "$hit")"
      emit CRIT ioc litellm-1107 "LiteLLM payload file present" "$hit"
    done < <(walk "$r" -type f \( -name cook.pth -o -name cook.py \))
  done

  # low-risk files for content IOC matching (bounded; avoids secret leakage)
  local LR=""
  add_lr() { [ -e "$1" ] && LR="$LR
$1"; }
  add_lr /etc/hosts
  for f in "$HOME/.zshrc" "$HOME/.zshenv" "$HOME/.zprofile" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile"; do add_lr "$f"; done
  for d in "$HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons; do
    [ -d "$d" ] && for p in "$d"/*.plist; do add_lr "$p"; done
  done
  for f in /etc/crontab /etc/cron.d/* /etc/rc.local; do add_lr "$f"; done
  [ -d /etc/systemd/system ] && for u in /etc/systemd/system/*.service; do add_lr "$u"; done
  [ -d "$HOME/.config/systemd/user" ] && for u in "$HOME/.config/systemd/user/"*.service; do add_lr "$u"; done
  # lockfiles (also reused by npm detection)
  LOCKFILES=""
  for r in "${ROOTS[@]}"; do
    while IFS= read -r -d '' hit; do LOCKFILES="$LOCKFILES
$hit"; add_lr "$hit"; done \
      < <(walk "$r" -type f \( -name package-lock.json -o -name yarn.lock -o -name pnpm-lock.yaml -o -name npm-shrinkwrap.json \))
  done

  # iterate IOC dataset
  local sev cat typ val note
  while IFS=$'\t' read -r sev cat typ val note; do
    case "$sev" in ''|\#*) continue;; esac
    [ -z "${typ:-}" ] && continue
    case "$typ" in
      fname)
        # cook.pth / cook.py are already emitted by the correlation pre-pass
        case "$val" in cook.pth|cook.py) continue;; esac
        if [ "$val" = sitecustomize.py ]; then
          for r in "${ROOTS[@]}"; do
            while IFS= read -r -d '' hit; do
              case ":$cookdirs:" in *":$(dirname "$hit"):"*)
                emit CRIT ioc "$cat" "sitecustomize.py beside cook.* (LiteLLM backdoor)" "$hit";;
              esac
            done < <(walk "$r" -type f -name sitecustomize.py)
          done
          continue
        fi
        for r in "${ROOTS[@]}"; do
          while IFS= read -r -d '' hit; do emit "$sev" ioc "$cat" "IOC file: $val" "$hit"
          done < <(walk "$r" -type f -name "$val")
        done
        ;;
      pippkg)
        for r in "${ROOTS[@]}"; do
          while IFS= read -r -d '' hit; do emit "$sev" ioc "$cat" "compromised python dist present: $val" "$hit"
          done < <(walk "$r" \( -type d -o -type f \) -name "${val}*")
        done
        ;;
      npmpkg)
        local pkg="${val%@*}" ver="${val##*@}" base
        base="${pkg##*/}"
        # installed copy (read package.json version from filesystem; never run npm)
        for r in "${ROOTS[@]}"; do
          while IFS= read -r -d '' pj; do
            if grep -F -q "\"version\": \"$ver\"" "$pj" 2>/dev/null; then
              emit CRIT ioc "$cat" "compromised npm package INSTALLED: $val" "$pj"
            fi
          done < <(walk "$r" -type f -path "*/node_modules/$pkg/package.json")
        done
        # referenced in a lockfile
        printf '%s\n' "$LOCKFILES" | while IFS= read -r lf; do
          [ -f "$lf" ] || continue
          if grep -F -q "$base-$ver.tgz" "$lf" 2>/dev/null || grep -F -q "$pkg@$ver" "$lf" 2>/dev/null; then
            emit "$sev" ioc "$cat" "compromised npm package in lockfile: $val" "$lf"
          fi
        done
        ;;
      netioc|strioc)
        printf '%s\n' "$LR" | while IFS= read -r f; do
          [ -n "$f" ] && grep_redacted "$cat" "$sev" "$cat" "$val" "$f"
        done
        # stash netiocs for the network layer
        [ "$typ" = netioc ] && printf '%s\n' "$val" >> "$OUTDIR/.netioc"
        ;;
      vsext)
        for base in "$HOME/.vscode/extensions" "$HOME/.vscode-insiders/extensions" "$HOME/.cursor/extensions" "$HOME/.vscode-server/extensions"; do
          [ -d "$base" ] || continue
          for d in "$base/$val"*; do
            [ -e "$d" ] && emit "$sev" ioc "$cat" "known-malicious editor extension" "$(basename "$d") in $base"
          done
        done
        ;;
    esac
  done < "$SELF/iocs.tsv"
}

# ===== LAYER 2 : persistence ==================================================
# deliberately NOT matching bare http(s):// - every plist DOCTYPE line contains an
# apple.com DTD URL and would false-positive. Markers are genuine dropper primitives.
PERSIST_MARKERS='/tmp/|/private/tmp/|/var/tmp/|/Users/Shared/|/dev/shm|curl |wget |base64 |/dev/tcp/|mkfifo|fsockopen|nc -e|ncat |osascript -e|python -c|python3 -c|/bin/sh -c .*(curl|wget)'

scan_plist() { # path
  local p="$1"; [ -f "$p" ] || return 0
  case "$(basename "$p")" in com.apple.*) return 0;; esac
  local m
  m="$(grep -n -E -i "$PERSIST_MARKERS" "$p" 2>/dev/null | sed 's/:.*//' | tr '\n' ',' | sed 's/,$//')"
  [ -n "$m" ] && emit MED persistence launchd "launch item invokes suspicious command" "$p (lines $m)"
}

layer2_persistence() {
  [ "$FIXTURE" = 1 ] && { # in fixture mode only check plists/cron under the root
    for p in $(find "${ROOTS[0]}" -type f -name '*.plist' 2>/dev/null); do scan_plist "$p"; done
    return 0
  }
  if [ "$OS" = Darwin ]; then
    for d in "$HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons; do
      [ -d "$d" ] && for p in "$d"/*.plist; do scan_plist "$p"; done
    done
    # third-party kexts / system extensions
    if have kextstat; then
      kextstat 2>/dev/null | grep -v -i 'com.apple' | awk 'NR>1{print $6}' | while read -r k; do
        [ -n "$k" ] && emit LOW persistence kext "third-party kernel extension loaded" "$k"
      done
    fi
    systemextensionsctl list 2>/dev/null | grep -i -E 'activated|enabled' | grep -v -i 'com.apple' | while read -r l; do
      [ -n "$l" ] && emit LOW persistence sysext "third-party system extension" "$l"
    done
    # login items (may hit TCC)
    if li="$(osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null)"; then
      [ -n "$li" ] && emit INFO persistence loginitem "login items present (review)" "$li"
    else
      emit INFO persistence loginitem "login items not read (TCC/permission)" "skipped"
    fi
  else
    # Linux
    [ -s /etc/ld.so.preload ] && emit HIGH persistence ldpreload "/etc/ld.so.preload is non-empty (library-injection rootkit sign)" "$(cat /etc/ld.so.preload 2>/dev/null | tr '\n' ' ')"
    for u in /etc/systemd/system/*.service "$HOME/.config/systemd/user/"*.service; do
      [ -f "$u" ] || continue
      m="$(grep -n -E -i "$PERSIST_MARKERS" "$u" 2>/dev/null | sed 's/:.*//' | tr '\n' ',' | sed 's/,$//')"
      [ -n "$m" ] && emit MED persistence systemd "systemd unit invokes suspicious command" "$u (lines $m)"
    done
    [ -f /etc/rc.local ] && grep -q -E -i "$PERSIST_MARKERS" /etc/rc.local 2>/dev/null && emit MED persistence rc "/etc/rc.local invokes suspicious command" /etc/rc.local
    # rogue UID 0 accounts
    awk -F: '($3==0 && $1!="root"){print $1}' /etc/passwd 2>/dev/null | while read -r u; do
      [ -n "$u" ] && emit HIGH persistence passwd "non-root account with UID 0" "$u in /etc/passwd"
    done
  fi
  # cron (both)
  if cronout="$(crontab -l 2>/dev/null)"; then
    printf '%s\n' "$cronout" | grep -n -E -i "$PERSIST_MARKERS" 2>/dev/null | sed 's/:.*//' | tr '\n' ',' | sed 's/,$//' | while read -r ls; do
      [ -n "$ls" ] && emit MED persistence cron "user crontab invokes suspicious command" "crontab (lines $ls)"
    done
  fi
  for f in /etc/crontab /etc/cron.d/*; do
    [ -f "$f" ] || continue
    grep -q -E -i "$PERSIST_MARKERS" "$f" 2>/dev/null && emit MED persistence cron "system cron invokes suspicious command" "$f"
  done
  # shell rc one-liner droppers
  for f in "$HOME/.zshrc" "$HOME/.zshenv" "$HOME/.zprofile" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile"; do
    [ -f "$f" ] || continue
    # only true remote-pipe-to-shell droppers; NOT eval "$(...)" (brew/rbenv/nvm/pyenv use it)
    grep -q -E -i 'curl[^|]*\|[[:space:]]*(sh|bash)|wget[^|]*\|[[:space:]]*(sh|bash)' "$f" 2>/dev/null \
      && emit HIGH persistence shellrc "shell rc pipes a remote download straight to a shell" "$f"
  done
  # ssh authorized_keys
  for ak in "$HOME/.ssh/authorized_keys" /root/.ssh/authorized_keys; do
    [ -f "$ak" ] || continue
    local nkeys age
    nkeys="$(grep -c '^ssh-\|^ecdsa-\|^sk-' "$ak" 2>/dev/null)"
    age="$(( (NOW - $(fmtime "$ak" 2>/dev/null || echo "$NOW")) / 86400 ))"
    if [ "${age:-99}" -lt 30 ]; then
      emit LOW persistence ssh "authorized_keys modified in last ${age}d ($nkeys keys)" "$ak"
    else
      emit INFO persistence ssh "authorized_keys present ($nkeys keys)" "$ak"
    fi
  done
}

# ===== LAYER 3 : processes, network, crypto-miner heuristics ==================
# distinctive miner binary names only - no generic words (networkservice, sysupdate,
# stratum, trex) that substring-match legitimate macOS/Electron processes.
MINER_NAMES='xmrig|minerd|cpuminer|cgminer|bminer|nbminer|phoenixminer|teamredminer|ethminer|lolminer|xmr-stak|nanominer|kinsing|kdevtmpfsi|kthreaddk'
POOL_PORTS='3333|4444|5555|7777|8333|9000|14433|14444|45560|45700'
# real temp dirs only - a hidden dir (.pnpm, .nvm, .cargo) is normal on a dev box.
TMP_PATH_RE='^(/tmp/|/private/tmp/|/var/tmp/|/dev/shm/|/Users/Shared/)'

allowlisted() { # path-or-name -> 0 if allowlisted
  local s; s="$(printf '%s' "$1" | lc)"
  local pat
  while IFS= read -r pat; do
    case "$pat" in ''|\#*) continue;; esac
    local p; p="$(printf '%s' "$pat" | lc)"
    case "$s" in $p) return 0;; esac
  done < "$SELF/allowlist.txt"
  return 1
}

psline() { if [ "$OS" = Darwin ]; then ps -axo pid=,pcpu=,comm=,command= 2>/dev/null; else ps -eo pid=,pcpu=,comm=,args= 2>/dev/null; fi; }

layer3_runtime() {
  [ "$FIXTURE" = 1 ] && return 0
  # --- two CPU samples for sustained-load correlation ---
  local s1 s2
  s1="$(psline)"; sleep 3; s2="$(psline)"
  # miner names + suspicious exec paths
  printf '%s\n' "$s2" | while read -r pid cpu comm rest; do
    [ -z "${pid:-}" ] && continue
    local full="$comm $rest" lcfull; lcfull="$(printf '%s' "$full" | lc)"
    if printf '%s' "$lcfull" | grep -q -E "$MINER_NAMES"; then
      if allowlisted "$comm"; then emit INFO process expected "miner-name match but allowlisted" "pid $pid $comm"
      else printf '%s\tminer-name\n' "$pid" >> "$PIDACC"; fi
    fi
    # exec path in temp/hidden
    local exe="$comm"
    case "$rest" in /*) exe="${rest%% *}";; esac
    if printf '%s' "$exe" | grep -q -E "$TMP_PATH_RE"; then
      if allowlisted "$exe"; then :; else printf '%s\ttemp-or-hidden-path\n' "$pid" >> "$PIDACC"; fi
    fi
    # sustained high CPU (present in both samples)
    local hi; hi="$(printf '%s' "${cpu%%.*}")"
    if [ "${hi:-0}" -ge 80 ] 2>/dev/null && printf '%s' "$s1" | grep -q "^[[:space:]]*$pid[[:space:]]"; then
      allowlisted "$comm" || printf '%s\tsustained-high-cpu\n' "$pid" >> "$PIDACC"
    fi
    # linux: unlinked (deleted) executable
    if [ "$OS" != Darwin ] && [ -L "/proc/$pid/exe" ]; then
      ls -l "/proc/$pid/exe" 2>/dev/null | grep -q '(deleted)' && printf '%s\tdeleted-exe\n' "$pid" >> "$PIDACC"
    fi
  done
  # --- network ---
  local netioc_list=""
  [ -f "$OUTDIR/.netioc" ] && netioc_list="$(cat "$OUTDIR/.netioc")"
  if have lsof; then
    # established outbound
    lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null | awk 'NR>1{print $2"\t"$9}' | while IFS=$'\t' read -r pid conn; do
      local rport rip
      rport="${conn##*:}"; rip="${conn#*->}"; rip="${rip%:*}"
      if printf '%s' "$rport" | grep -q -E "^($POOL_PORTS)$"; then
        printf '%s\tmining-pool-port\n' "$pid" >> "$PIDACC"
      fi
      if [ -n "$netioc_list" ]; then
        printf '%s\n' "$netioc_list" | while IFS= read -r ic; do
          case "$rip" in "$ic") emit CRIT network c2 "live connection to known IOC" "pid $pid -> $conn";; esac
        done
      fi
      printf '%s\t%s\n' "$pid" "$conn" >> "$OUTDIR/.conns"
    done
    # listeners (informational)
    lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print $1" (pid "$2") "$9}' | sort -u | while read -r l; do
      emit INFO network listen "listening socket" "$l"
    done
  elif have ss; then
    ss -tnp 2>/dev/null | grep -E "ESTAB" | while read -r l; do emit INFO network listen "socket" "$l"; done
  else
    emit INFO network listen "no lsof/ss available" "skipped"
  fi
  # --- correlate pids ---
  [ -s "$PIDACC" ] || return 0
  sort -u "$PIDACC" | awk -F'\t' '{a[$1]=a[$1]" "$2} END{for(p in a) print p"\t"a[p]}' | while IFS=$'\t' read -r pid reasons; do
    local n; n="$(printf '%s' "$reasons" | wc -w | tr -d ' ')"
    local info; info="$(ps -p "$pid" -o comm= 2>/dev/null)"
    local sev=MED
    case "$reasons" in *miner-name*) sev=HIGH;; esac
    case "$reasons" in *mining-pool-port*) sev=HIGH;; esac
    [ "$n" -ge 2 ] && sev=CRIT
    emit "$sev" process heuristic "suspicious process (${reasons# })" "pid $pid ${info:-?}"
  done
}

# ===== LAYER 4 : package hygiene (light) ======================================
layer4_pkg() {
  # unusual .pth files (persistence vector) excluding well-known benign ones
  for r in "${ROOTS[@]}"; do
    walk "$r" -type f -path "*/site-packages/*.pth" | tr '\0' '\n' | while IFS= read -r p; do
      [ -z "$p" ] && continue
      case "$(basename "$p")" in
        distutils-precedence.pth|__editable__*.pth|setuptools.pth|easy-install.pth|*.dist-info*) continue;;
      esac
      emit INFO pkg pth "python .pth startup hook (review if unfamiliar)" "$p"
    done
  done
  # editor extensions inventory -> file only
  for base in "$HOME/.vscode/extensions" "$HOME/.cursor/extensions"; do
    [ -d "$base" ] && ls -1 "$base" 2>/dev/null | sed 's/^/  ext: /' >> "$REPORT"
  done
}

# ===== LAYER 5 : security posture + optional engines ==========================
vlt() { # version_lt A B  -> 0 (true) if A < B
  [ "$1" = "$2" ] && return 1
  local lo; lo="$(printf '%s\n%s\n' "$1" "$2" | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n 2>/dev/null | head -1)"
  [ "$lo" = "$1" ]
}

layer5_posture() {
  [ "$FIXTURE" = 1 ] && return 0
  if [ "$OS" = Darwin ]; then
    emit INFO posture macos "macOS version" "$(sw_vers -productVersion 2>/dev/null)"
    if s="$(csrutil status 2>/dev/null)"; then
      case "$s" in *disabled*) emit HIGH posture sip "System Integrity Protection is DISABLED" "$s";; *) emit INFO posture sip "SIP enabled" "$s";; esac
    fi
    if g="$(spctl --status 2>/dev/null)"; then
      case "$g" in *disabled*) emit MED posture gatekeeper "Gatekeeper is disabled" "$g";; *) emit INFO posture gatekeeper "Gatekeeper enabled" "$g";; esac
    fi
    # eMudhra / emSign CA in login+system keychains
    if security find-certificate -a -c emSign >/dev/null 2>&1; then
      emit LOW posture emudhra "emSign (eMudhra) CA present in keychain - ensure runtime CA bundles are patched" "keychain"
    fi
  else
    emit INFO posture linux "kernel" "$(uname -r 2>/dev/null)"
    [ -f /etc/ssl/certs/ca-certificates.crt ] && grep -q -i emSign /etc/ssl/certs/ca-certificates.crt 2>/dev/null \
      && emit LOW posture emudhra "emSign (eMudhra) CA in system bundle - ensure ca-certificates updated" "/etc/ssl/certs/ca-certificates.crt"
  fi
  # optional ClamAV (only if already installed)
  if [ "$WANT_CLAMAV" = 1 ]; then
    if have clamscan; then
      emit INFO engine clamav "running clamscan on $HOME (infected-only)" "this may take a while"
      clamscan -r -i --no-summary --max-filesize=50M --max-scansize=200M "$HOME" 2>/dev/null | grep -i FOUND | while read -r l; do
        emit HIGH engine clamav "ClamAV detection" "$l"
      done
    else
      emit INFO engine clamav "clamav requested but not installed (not auto-installing)" "skipped"
    fi
  fi
  # optional Trivy - CRITICAL-only known-CVE / secret / misconfig scan (pinned)
  if [ "$WANT_TRIVY" = 1 ]; then
    if have trivy; then
      local tv; tv="$(trivy --version 2>/dev/null | awk '/Version:/{print $2; exit}')"
      [ -n "$tv" ] && [ "$tv" != "$TRIVY_PIN" ] && emit INFO engine trivy "trivy $tv installed but pin is $TRIVY_PIN (reinstall via install-trivy.sh to match)" "version drift"
      emit INFO engine trivy "running trivy fs (CRITICAL only) - fetching DB over network" "root=${ROOTS[0]}"
      local tout="$OUTDIR/trivy.txt"
      trivy fs --quiet --no-progress --severity CRITICAL --scanners vuln,secret,misconfig "${ROOTS[0]}" > "$tout" 2>/dev/null
      local tc; tc="$(grep -c -E 'CRITICAL' "$tout" 2>/dev/null || echo 0)"
      if [ "${tc:-0}" -gt 0 ]; then
        emit HIGH engine trivy "trivy reported CRITICAL findings (see trivy.txt)" "$tc lines in $tout"
      else
        emit INFO engine trivy "trivy found no CRITICAL findings" "$tout"
      fi
    else
      emit INFO engine trivy "trivy requested but not installed - run install-trivy.sh (pins v$TRIVY_PIN, checksum-verified)" "skipped"
    fi
  fi
}

# ===== LAYER 6 : patch posture ================================================
layer6_patch() {
  [ "$FIXTURE" = 1 ] && return 0
  # node (binary is not the suspect; only npm packages are) - safe to run --version
  if have node; then
    local nv; nv="$(node --version 2>/dev/null | sed 's/^v//')"
    local maj="${nv%%.*}"
    case "$maj" in
      22) vlt "$nv" 22.23.4 && emit MED patch node "Node $nv < 22.23.4 (eMudhra CA + Brotli RCE fix)" "node";;
      24) vlt "$nv" 24.22.1 && emit MED patch node "Node $nv < 24.22.1 (eMudhra CA + Brotli RCE fix)" "node";;
      26) vlt "$nv" 26.12.1 && emit MED patch node "Node $nv < 26.12.1 (eMudhra CA + Brotli RCE fix)" "node";;
      18|20) emit MED patch node "Node $nv is EOL (no fixes for the Oct-2026 issues)" "node";;
    esac
  fi
  if have go; then
    local gv; gv="$(go version 2>/dev/null | awk '{print $3}' | sed 's/^go//')"
    if [ -n "$gv" ]; then
      case "$gv" in 1.27.*) vlt "$gv" 1.27.3 && emit MED patch go "Go $gv < 1.27.3 (eMudhra CVE-2026-111943)" go;;
                    1.26.*) vlt "$gv" 1.26.10 && emit MED patch go "Go $gv < 1.26.10 (eMudhra CVE-2026-111943)" go;; esac
    fi
  fi
  if have tailscale; then
    local tv; tv="$(tailscale version 2>/dev/null | head -1 | awk '{print $1}')"
    [ -n "$tv" ] && vlt "$tv" 1.104.2 && emit MED patch tailscale "Tailscale $tv < 1.104.2 (TS-2026-013 eMudhra)" tailscale
  fi
  if have php; then
    local pv; pv="$(php -r 'echo PHP_VERSION;' 2>/dev/null)"   # no web request; php2shell is not triggered by CLI
    local pmaj="${pv%.*}"
    case "$pmaj" in
      8.5) vlt "$pv" 8.5.12 && emit HIGH patch php "PHP $pv < 8.5.12 (php2shell CVE-2026-109618/9)" php;;
      8.4) vlt "$pv" 8.4.27 && emit HIGH patch php "PHP $pv < 8.4.27 (php2shell)" php;;
      8.3) vlt "$pv" 8.3.36 && emit HIGH patch php "PHP $pv < 8.3.36 (php2shell)" php;;
      8.2) vlt "$pv" 8.2.35 && emit HIGH patch php "PHP $pv < 8.2.35 (php2shell)" php;;
    esac
  fi
  # local WordPress plugin versions (filesystem read only)
  for r in "${ROOTS[@]}"; do
    walk "$r" -type f \( -path "*/updraftplus/readme.txt" -o -path "*/seo-by-rank-math*/readme.txt" -o -path "*/bricksforge/*.php" \) \
      | tr '\0' '\n' | while IFS= read -r f; do
      [ -z "$f" ] && continue
      local ver; ver="$(grep -i -m1 -E 'Stable tag:|Version:' "$f" 2>/dev/null | grep -o -E '[0-9]+\.[0-9]+(\.[0-9]+)*' | head -1)"
      case "$f" in
        *updraftplus*) emit INFO patch wordpress "UpdraftPlus $ver present (TeamUpdraft breach: rotate UpdraftCentral keys, hunt backdoors)" "$f";;
        *rank-math*)   emit INFO patch wordpress "Rank Math $ver present (PRO 3.0.123 was trojanized; safe 3.0.124)" "$f";;
        *bricksforge*) emit INFO patch wordpress "Bricksforge present (CVE-2026-85097 exploited; fix 3.1.8.10/4.0.2)" "$f";;
      esac
    done
  done
}

# ---- run ---------------------------------------------------------------------
layer1_iocs
layer2_persistence
layer3_runtime
layer4_pkg
layer5_posture
layer6_patch

# ---- summary -----------------------------------------------------------------
{
  echo
  echo "==================== SUMMARY ===================="
  echo "CRIT=$n_crit  HIGH=$n_high  MED=$n_med  LOW=$n_low  INFO=$n_info"
  echo "findings TSV : $TSV"
  echo "full report  : $REPORT"
  echo "scan is read-only; nothing was changed. triage the TSV before acting."
} | tee -a "$REPORT"

if [ "$n_crit" -gt 0 ]; then exit 2; elif [ "$n_high" -gt 0 ]; then exit 1; else exit 0; fi
