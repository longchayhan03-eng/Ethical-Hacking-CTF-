#!/usr/bin/env bash
# recon_hunt.sh - polite recon of one CTF box: ports, services, banners, web,
# FTP, SMB, DNS, SNMP, SSH - and a summary of flag-looking strings it finds.
# Only use it on targets you're allowed to test (your CTF/LAB box).
#
# It is deliberately gentle: rate-limited nmap, a capped number of web
# requests per second, timeouts on everything, small built-in wordlists.
#
# Usage:
#   ./recon_hunt.sh -t 3.144.177.121
#   ./recon_hunt.sh -t 3.144.177.121 -d lab.local          # you already know the domain
#   ./recon_hunt.sh -t 3.144.177.121 -T 100                # only top 100 ports (if the question says to limit scanning)
#   ./recon_hunt.sh -t 3.144.177.121 -p 21,22,80,2222      # only these ports
#   ./recon_hunt.sh -t 3.144.177.121 -p 15000-15100        # only a port range the question names
#   ./recon_hunt.sh -t 3.144.177.121 -D                    # deep: big SecLists wordlists
#   ./recon_hunt.sh -t 3.144.177.121 -q                    # quick: top 1000 ports only, no UDP, short lists
#   ./recon_hunt.sh -t 3.144.177.121 -p 80 -A 'student012:pass'   # web again, behind a login pop-up
#
# Works best with: sudo apt install nmap curl smbclient smbmap dnsutils snmp seclists

set -u
BUDGET_MIN=20; AUTH=""; TARGET=""; DOMAINS=(); TOP=""; PORTS=""; FULL=0; DEEP=0; QUICK=0
RATE=200          # nmap packets per second (max)
WEBRATE=15        # web requests per second (max)
REGEX='ehCTF\{[^}]*\}|SIT\{[^}]*\}|FLAG\{[^}]*\}|flag\{[^}]*\}'
EXTRA_PORTS="21,22,23,25,53,80,110,111,135,139,143,161,443,445,993,995,1433,1521,2049,2121,2222,3000,3306,3389,4444,5000,5001,5002,5003,5004,5005,5432,5900,6379,8000,8008,8080,8081,8443,8888,9000,9090,10000,27017,31337"

say()  { printf '\n\033[1;34m[*] %s\033[0m\n' "$*"; }
good() { printf '\033[1;32m[+] %s\033[0m\n' "$*"; }
bad()  { printf '\033[1;31m[!] %s\033[0m\n' "$*"; }
note() { printf '    %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
  sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'
  cat <<'EOF'

Options:
  -t IP      target IP or hostname                              (required)
  -d DOMAIN  domain name if you know it (e.g. lab.local). Repeatable
  -T N       only the top N TCP ports + common CTF ports (default: ALL 65535 ports)
  -p LIST    scan only these ports, e.g. 21,22,80 (overrides -T)
  -F         all 65535 TCP ports (this is now the default; kept for old commands)
  -D         deep: SecLists wordlists for vhosts and directories (slower)
  -q         quick: top 1000 ports only, no UDP, short web wordlists
  -R N       nmap max packets per second (default 200)
  -W N       web max requests per second (default 15)
  -r REGEX   extra flag pattern (32-char LAB flags are always looked for)
  -M MIN     time budget for the whole run in minutes (default 20). Steps shrink or skip to fit
  -A U:P     username:password for an HTTP basic-auth (pop-up) login, to scan behind it
  -h         help
EOF
  exit "${1:-1}"
}

while getopts "t:d:T:p:FDqR:W:r:A:M:h" o; do
  case "$o" in
    t) TARGET="$OPTARG" ;; d) DOMAINS+=("$OPTARG") ;; T) TOP="$OPTARG" ;; p) PORTS="$OPTARG" ;;
    F) FULL=1 ;; D) DEEP=1 ;; q) QUICK=1 ;; R) RATE="$OPTARG" ;; W) WEBRATE="$OPTARG" ;;
    r) REGEX="$REGEX|$OPTARG" ;; A) AUTH="$OPTARG" ;; M) BUDGET_MIN="$OPTARG" ;; h) usage 0 ;; *) usage ;;
  esac
done
[ -z "$TARGET" ] && { bad "Give the target with -t"; usage; }
HERE="$(cd "$(dirname "$0")" && pwd)"
WEBPY="$HERE/recon_web.py"
[ -f "$WEBPY" ] || bad "recon_web.py not found next to this script; web checks will be limited"

OUT="recon_${TARGET//[^A-Za-z0-9.]/_}"; mkdir -p "$OUT"
# everything printed is also saved, so it can run in the background and be read later
exec > >(tee "$OUT/run.log") 2>&1
START=$(date +%s)
DEADLINE=$(( START + BUDGET_MIN * 60 ))
left()  { echo $(( DEADLINE - $(date +%s) )); }          # seconds left in the budget
SKIPPED=()
# nmap throws away ALL results for a host that hits --host-timeout, so these grow with -M
SVC_T="$(( BUDGET_MIN / 5 > 3 ? BUDGET_MIN / 5 : 3 ))m"      # service pass: 3 min at -M 15, 12 min at -M 60
DEEP_T="$(( BUDGET_MIN / 7 > 2 ? BUDGET_MIN / 7 : 2 ))m"     # --version-all pass
UDP_T="$(( BUDGET_MIN * 6 > 90 ? BUDGET_MIN * 6 : 90 ))s"     # UDP: 90 s at -M 15, 6 min at -M 60
note "Time budget: $BUDGET_MIN min (change with -M). Quick services run before the web step; the web step gets what's left."
note "Results go in $OUT/"
SUDO=""; [ "$(id -u)" -ne 0 ] && have sudo && sudo -n true 2>/dev/null && SUDO="sudo"
[ "$(id -u)" -eq 0 ] && SUDO=" "

# ---------------- 1. port discovery ----------------
say "1. Port discovery (gentle: max $RATE packets/s, 2 retries)"
OPEN=""
if have nmap; then
  SCANTYPE="-sT"; [ -n "$SUDO" ] && SCANTYPE="-sS"
  # default = every TCP port; -T N or -q narrow it, -p picks exact ports
  if [ -n "$PORTS" ]; then PSPEC=(-p "$PORTS"); note "scanning the ports you gave: $PORTS"
  elif [ -n "$TOP" ]; then PSPEC=(--top-ports "$TOP"); note "scanning the top $TOP ports + common CTF ports"
  elif (( QUICK )); then PSPEC=(--top-ports 1000); note "quick mode: top 1000 ports only"
  else PSPEC=(-p-); FULL=1; note "scanning ALL 65535 TCP ports (~5-6 min at $RATE packets/s). Use -T 100 if the question says to limit scanning"; fi
  ${SUDO:+$SUDO} nmap $SCANTYPE -Pn -n -T3 --max-rate "$RATE" --max-retries 2 \
       "${PSPEC[@]}" "$TARGET" -oN "$OUT/ports.txt" -oG "$OUT/ports.gnmap" >/dev/null 2>&1
  # top-N can miss CTF ports like 2222/31337, so check those too (unless -p given)
  if [ -n "$TOP" ] || (( QUICK )); then
    ${SUDO:+$SUDO} nmap $SCANTYPE -Pn -n -T3 --max-rate "$RATE" --max-retries 2 -p "$EXTRA_PORTS" "$TARGET" \
         -oG "$OUT/ports_extra.gnmap" >/dev/null 2>&1
  fi
  OPEN=$(cat "$OUT"/ports*.gnmap 2>/dev/null | grep -oE '[0-9]+/open/tcp' | cut -d/ -f1 | sort -un | paste -sd, -)
  [ -z "$SUDO" ] && note "(not root, so using a slower connect scan. Run with sudo for SYN scans)"
else
  bad "nmap not installed (sudo apt install nmap). Falling back to a small connect check."
  LIST="${PORTS:-$EXTRA_PORTS}"
  OPEN=$(python3 - "$TARGET" "$LIST" <<'PY'
import sys, socket, concurrent.futures as cf
host, spec = sys.argv[1], sys.argv[2]; ports = []
for part in spec.split(","):
    if "-" in part: a, b = part.split("-"); ports += range(int(a), int(b) + 1)
    elif part: ports.append(int(part))
def chk(p):
    try:
        s = socket.create_connection((host, p), timeout=1.5); s.close(); return p
    except Exception: return None
with cf.ThreadPoolExecutor(20) as ex:
    print(",".join(str(p) for p in sorted(filter(None, ex.map(chk, ports)))))
PY
)
fi
if [ -z "$OPEN" ]; then bad "No open TCP ports found. Check the IP, your VPN/network, or try -F."; else good "Open TCP ports: $OPEN"; fi
IFS=, read -ra OPEN_ARR <<< "$OPEN"

# ---------------- 2. service fingerprint ----------------
# Fast pass first (normal -sV + default scripts, each script capped at 30s),
# then the slow --version-all only on ports nmap couldn't name.
declare -A SVC
if [ -n "$OPEN" ] && have nmap; then
  say "2. Service fingerprint (fast -sV -sC first, then --version-all only on unknown ports)"
  ST2="-sT"; [ -n "$SUDO" ] && ST2="-sS"
  T0=$(date +%s)
  ${SUDO:+$SUDO} nmap $ST2 -Pn -n -T4 --max-rate "$RATE" -sV --version-intensity 5 -sC \
       --script-timeout 30s --host-timeout "$SVC_T" -p "$OPEN" "$TARGET" -oN "$OUT/services.txt" >/dev/null 2>&1
  note "fast pass done in $(( $(date +%s) - T0 ))s"
  grep -qE '^[0-9]+/tcp' "$OUT/services.txt" 2>/dev/null || { bad "service detection timed out (nmap drops results when that happens); banners below still identify most services"; SKIPPED+=("service detection: sudo nmap -sV -sC -p $OPEN $TARGET"); }
  # ports with no name, a guessed name (ends in ?), "unknown", or "tcpwrapped"
  UNKNOWN=$(grep -E '^[0-9]+/tcp +open' "$OUT/services.txt" | awk '$3 ~ /\?$|^unknown$|^tcpwrapped$/ || NF < 3 {split($1,a,"/"); print a[1]}' | paste -sd, -)
  if [ -n "$UNKNOWN" ] && [ "$(left)" -lt $(( BUDGET_MIN * 36 )) ]; then
    note "nmap couldn't name ports $UNKNOWN; skipping the slow --version-all pass to save time (banners and probes below still cover them)"
    SKIPPED+=("--version-all on $UNKNOWN: sudo nmap -sV --version-all -p $UNKNOWN $TARGET")
  elif [ -n "$UNKNOWN" ]; then
    note "nmap couldn't name ports $UNKNOWN, trying every probe on just those (max $DEEP_T)"
    T0=$(date +%s)
    ${SUDO:+$SUDO} nmap $ST2 -Pn -n -T4 --max-rate "$RATE" -sV --version-all \
         --host-timeout "$DEEP_T" -p "$UNKNOWN" "$TARGET" -oN "$OUT/services_unknown.txt" >/dev/null 2>&1
    note "deep pass done in $(( $(date +%s) - T0 ))s"
    # replace the unknown lines with the deep-pass results
    python3 - "$OUT/services.txt" "$OUT/services_unknown.txt" <<'PY'
import re, sys
main, deep = sys.argv[1], sys.argv[2]
try: better = {l.split("/")[0]: l for l in open(deep) if re.match(r"\d+/tcp +open", l)}
except FileNotFoundError: better = {}
lines = [better.get(l.split("/")[0], l) if re.match(r"\d+/tcp +open", l) else l for l in open(main)]
open(main, "w").writelines(lines)
PY
    grep -E '^SF' "$OUT/services_unknown.txt" >> "$OUT/services.txt" 2>/dev/null
  fi
  grep -E '^[0-9]+/tcp' "$OUT/services.txt" | sed 's/^/    /'
  while read -r line; do
    p="${line%%/*}"; s=$(awk '{print $3}' <<< "$line"); SVC[$p]="$s"
  done < <(grep -E '^[0-9]+/tcp +open' "$OUT/services.txt")
  if grep -q '^SF' "$OUT/services.txt"; then
    good "Unrecognised service fingerprint (SF: block) - raw responses below, flags often hide here"
    grep -E '^SF' "$OUT/services.txt" | sed 's/^SF[-:]//' | tr -d '\n' | sed 's/%r/\n%r/g' | head -20 | sed 's/^/    /'; echo
  fi
  grep -E '^\|' "$OUT/services.txt" | grep -iE 'anonymous|allowed|title|banner|robots|disallow|domain|dns|commonName|workgroup|share' | head -25 | sed 's/^/    script: /'
fi

# ---------------- 3. UDP ----------------
if (( ! QUICK )) && have nmap && [ -n "$SUDO" ]; then
  say "3. UDP (DNS 53, TFTP 69, NTP 123, NetBIOS 137, SNMP 161)"
  $SUDO nmap -sU -Pn -n -T3 --max-rate 50 --max-retries 1 --host-timeout "$UDP_T" -p 53,69,123,137,161 "$TARGET" -oG "$OUT/udp.gnmap" >/dev/null 2>&1
  grep -oE '[0-9]+/(open|open\|filtered)/udp//[a-z-]*' "$OUT/udp.gnmap" | sed 's/^/    /'
  UDP_OPEN=$(grep -oE '[0-9]+/open(\|filtered)?/udp' "$OUT/udp.gnmap" | cut -d/ -f1 | paste -sd, -)
  [ -z "$UDP_OPEN" ] && UDP_OPEN="53,161"   # nothing back (or timed out): still try DNS and SNMP directly
else
  UDP_OPEN="53,161"   # still try DNS and SNMP directly below
  (( QUICK )) && note "3. UDP scan skipped (quick mode); DNS and SNMP are still tried directly" \
              || note "3. UDP scan needs root (run with sudo); DNS and SNMP are still tried directly"
fi

# ---------------- 4. banners ----------------
say "4. Banners from every open port (up to 8 at once)"
grab_banner() {
  local p=$1 b
  b=$( (sleep 2; printf 'HELP\r\n'; sleep 2) | timeout 6 nc -n -w 4 "$TARGET" "$p" 2>/dev/null | head -c 1500 | tr -d '\000')
  [ -z "$b" ] && b=$(printf 'GET / HTTP/1.0\r\n\r\n' | timeout 5 nc -n -w 3 "$TARGET" "$p" 2>/dev/null | head -c 600 | tr -d '\000')
  printf '%s\n' "$b" > "$OUT/banner_$p.txt"
}
# wait only for these jobs by PID (a bare "wait" would also wait for the run.log tee and hang)
PIDS=()
for p in "${OPEN_ARR[@]}"; do
  [ -z "$p" ] && continue
  grab_banner "$p" & PIDS+=($!)
  (( ${#PIDS[@]} >= 8 )) && { wait "${PIDS[@]}"; PIDS=(); }
done
[ ${#PIDS[@]} -gt 0 ] && wait "${PIDS[@]}"
for p in "${OPEN_ARR[@]}"; do
  [ -z "$p" ] && continue
  first=$(tr '\r' ' ' < "$OUT/banner_$p.txt" | grep -v '^\s*$' | head -3 | cut -c1-120 | paste -sd'|' -)
  printf '    %-6s %s\n' "$p" "${first:-(silent)}"
done

is_web() {  # port answers HTTP?
  local p=$1 s="${SVC[$1]:-}"
  [[ "$s" == *http* || "$s" == *ssl* ]] && return 0
  head -c 20 "$OUT/banner_$p.txt" 2>/dev/null | grep -q '^HTTP/' && return 0
  return 1
}

# ---------------- 5. DNS ----------------
port_open() { [[ ",$OPEN," == *",$1,"* ]]; }
DNS_TRIED=0
if port_open 53 || [[ ",$UDP_OPEN," == *",53,"* ]]; then
  say "5. DNS"
  if have dig; then
    # find the domain: reverse lookup, SOA of known domains, nmap output
    for d in $(dig +short -x "$TARGET" @"$TARGET" 2>/dev/null; grep -ohE '[a-z0-9-]+\.(local|lab|htb|thm|ctf|internal|corp|lan)' "$OUT"/*.txt 2>/dev/null | sort -u); do
      d="${d%.}"; base=$(awk -F. '{print $(NF-1)"."$NF}' <<< "$d"); DOMAINS+=("$base")
    done
    mapfile -t DOMAINS < <(printf '%s\n' "${DOMAINS[@]}" | grep -v '^$' | sort -u)
    [ ${#DOMAINS[@]} -eq 0 ] && note "no domain known yet (pass one with -d); the web step may find it, DNS is retried after it"
    [ ${#DOMAINS[@]} -gt 0 ] && DNS_TRIED=1   # only counts as done if there was a domain to ask about
    for d in "${DOMAINS[@]}"; do
      note "zone transfer for $d:"
      timeout 15 dig axfr "$d" @"$TARGET" +time=5 +tries=1 > "$OUT/dns_axfr_$d.txt" 2>&1
      if grep -qE '\sIN\s' "$OUT/dns_axfr_$d.txt"; then
        good "Zone transfer allowed for $d"
        grep -E '\sIN\s' "$OUT/dns_axfr_$d.txt" | sort -u | sed 's/^/    /'
        grep -E '\sIN\s+(A|CNAME)\s' "$OUT/dns_axfr_$d.txt" | awk '{print $1}' | sed 's/\.$//' >> "$OUT/dns_hosts.txt"
      else
        note "  refused. Querying record types instead:"
        for t in SOA NS MX TXT A ANY; do
          r=$(dig +short "$d" "$t" @"$TARGET" +time=3 +tries=1 2>/dev/null)
          [ -n "$r" ] && printf '    %-4s %s\n' "$t" "$(echo "$r" | paste -sd' ' -)" | tee -a "$OUT/dns_records.txt"
        done
        for sub in www dev admin login mail ns1 flag secret test staging; do
          r=$(dig +short "$sub.$d" A @"$TARGET" +time=2 +tries=1 2>/dev/null); t=$(dig +short "$sub.$d" TXT @"$TARGET" +time=2 +tries=1 2>/dev/null)
          [ -n "$r$t" ] && { printf '    %-16s %s %s\n' "$sub.$d" "$r" "$t" | tee -a "$OUT/dns_records.txt"; echo "$sub.$d" >> "$OUT/dns_hosts.txt"; }
        done
      fi
    done
  else bad "dig missing: sudo apt install dnsutils"; fi
fi

# ---------------- 7. FTP ----------------
for p in "${OPEN_ARR[@]}"; do
  [[ "${SVC[$p]:-}" == ftp* || "$p" == 21 || "$p" == 2121 ]] || continue
  say "6. FTP on port $p (anonymous login, small files only)"
  timeout 120 python3 - "$TARGET" "$p" "$OUT/ftp_$p" <<'PY'
import ftplib, os, sys
host, port, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
os.makedirs(out, exist_ok=True)
for user, pw in (("anonymous", "anonymous"), ("anonymous", ""), ("ftp", "ftp")):
    try:
        f = ftplib.FTP(); f.connect(host, port, timeout=8); banner = f.getwelcome()
        f.login(user, pw); break
    except ftplib.error_perm: f = None
    except Exception as e: print("    FTP error:", e); sys.exit()
print("    banner:", banner)
if not f: print("    anonymous login refused (look for credentials elsewhere)"); sys.exit()
print(f"    ANONYMOUS LOGIN ALLOWED ({user}/{pw or 'empty'})")
f.set_pasv(True); count = 0
def walk(path, depth=0):
    global count
    if depth > 4 or count > 60: return
    entries = []
    try:   # MLSD gives clean facts, but some servers answer it with LIST-style lines, so check
        entries = [e for e in f.mlsd(path) if "type" in e[1]]
    except Exception: pass
    if not entries:
        import re
        lines = []
        try: f.retrlines("LIST -a " + path if path else "LIST -a", lines.append)
        except Exception:
            try: f.retrlines("LIST " + path if path else "LIST", lines.append)
            except Exception: pass
        for line in lines:   # -rw-r--r--  1 user group  154 Sep 14 15:58 name
            m = re.match(r"^([dl-])\S{9}\S*\s+\d+\s+\S+\s+\S+\s+(\d+)\s+\w{3}\s+\d+\s+[\d:]+\s+(.+)$", line)
            if m:
                name = m.group(3).split(" -> ")[0]
                entries.append((name, {"type": "dir" if m.group(1) == "d" else "file", "size": m.group(2)}))
    if not entries:
        try:
            for line in f.nlst(path) if path else f.nlst(): entries.append((os.path.basename(line), {"type": "?"}))
        except Exception: pass
    for name, facts in entries:
        if name in (".", ".."): continue
        full = f"{path}/{name}" if path else name
        t = facts.get("type", "?")
        if t == "dir" or (t == "?" and "." not in name):
            print("    dir :", full); walk(full, depth + 1); continue
        size = int(facts.get("size", 0) or 0)
        print(f"    file: {full} ({size} bytes)")
        if size < 1_000_000:
            try:
                local = os.path.join(out, full.replace("/", "_"))
                with open(local, "wb") as fh: f.retrbinary("RETR " + full, fh.write)
                count += 1
                if size < 300:
                    print("      ->", open(local, "rb").read().decode("latin-1").strip()[:200])
            except Exception as e: print("      (couldn't download:", e, ")")
walk("")
f.quit()
PY
done

# ---------------- 8. SMB ----------------
if port_open 445 || port_open 139; then
  say "7. SMB (null session / guest, small files only)"
  if have smbclient; then
    timeout 20 smbclient -N -L "//$TARGET" -g 2>/dev/null | grep '^Disk|' > "$OUT/smb_shares.txt"
    if [ ! -s "$OUT/smb_shares.txt" ]; then
      timeout 20 smbclient -U 'guest%' -L "//$TARGET" -g 2>/dev/null | grep '^Disk|' > "$OUT/smb_shares.txt"
    fi
    if [ -s "$OUT/smb_shares.txt" ]; then
      while IFS='|' read -r _ share comment; do
        [[ "$share" == *'$' ]] && { note "share $share (admin share, skipped)"; continue; }
        if [ "$(left)" -lt 240 ]; then
          note "share $share: not downloaded, keeping time for the web step"
          SKIPPED+=("SMB share $share: smbclient -N //$TARGET/$share -c 'recurse ON; prompt OFF; mget *'"); continue
        fi
        note "share: $share  ${comment}"
        mkdir -p "$OUT/smb_$share"
        ( cd "$OUT/smb_$share" && timeout 60 smbclient -N "//$TARGET/$share" -c 'recurse ON; prompt OFF; ls; mget *' 2>/dev/null ) \
          | grep -vE '^\s*$|blocks of size|^getting|NT_STATUS' | head -30 | sed 's/^/      /'
        find "$OUT/smb_$share" -type f -size -300c -exec sh -c 'printf "      %s -> " "${1##*/}"; head -c 200 "$1" | tr "\n" " "; echo' _ {} \;
      done < "$OUT/smb_shares.txt"
      note "hidden shares (ending in \$) aren't listed; try names you find in notes: smbclient -N //$TARGET/NAME"
    else
      note "no shares with a null session or guest (credentials needed?)"
    fi
    have smbmap && timeout 60 smbmap -H "$TARGET" -r --depth 5 2>/dev/null | grep -vE '^\s*$|SMBMap|github|ShawnDEvans|_|\\$' | head -40 > "$OUT/smbmap.txt"
  else bad "smbclient missing: sudo apt install smbclient"; fi
fi

# ---------------- 9. SNMP ----------------
if [[ ",$UDP_OPEN," == *",161,"* ]] || port_open 161; then
  say "8. SNMP (UDP 161)"
  if have snmpwalk; then
    for c in public private community manager; do
      r=$(timeout 10 snmpwalk -v2c -c "$c" -t 2 -r 1 "$TARGET" system 2>/dev/null)
      if [ -n "$r" ]; then
        good "community string '$c' works"
        echo "$r" | sed 's/^/    /' | head -12
        WALK=90; [ "$(left)" -lt 300 ] && WALK=30
        note "full walk (max ${WALK}s) saved to $OUT/snmp_$c.txt"
        timeout "$WALK" snmpwalk -v2c -c "$c" -t 2 -r 1 "$TARGET" > "$OUT/snmp_$c.txt" 2>/dev/null
        grep -iE 'flag|sit\{|secret|pass|user' "$OUT/snmp_$c.txt" | head -10 | sed 's/^/    interesting: /'
        break
      fi
    done
    [ -z "${r:-}" ] && note "no response to common community strings (try: onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt $TARGET)"
  else
    note "snmpwalk not installed (sudo apt install snmp), using the built-in python walker"
    for c in public private community manager; do
      WALK=60; [ "$(left)" -lt 300 ] && WALK=25
      timeout "$WALK" python3 - "$TARGET" "$c" 161 400 > "$OUT/snmp_$c.txt" 2>/dev/null <<'PY'
import socket, sys
def enc_len(n):
    if n < 128: return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big"); return bytes([0x80 | len(b)]) + b
def tlv(t, v): return bytes([t]) + enc_len(len(v)) + v
def enc_int(n): return tlv(2, n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big", signed=True))
def enc_oid(o):
    out = bytes([40 * o[0] + o[1]])
    for x in o[2:]:
        b = [x & 0x7f]; x >>= 7
        while x: b.insert(0, 0x80 | (x & 0x7f)); x >>= 7
        out += bytes(b)
    return tlv(6, out)
def rd(buf, i):
    t = buf[i]; l = buf[i + 1]; i += 2
    if l & 0x80: n = l & 0x7f; l = int.from_bytes(buf[i:i + n], "big"); i += n
    return t, buf[i:i + l], i + l
def dec_oid(b):
    o = [b[0] // 40, b[0] % 40]; x = 0
    for c in b[1:]:
        x = (x << 7) | (c & 0x7f)
        if not c & 0x80: o.append(x); x = 0
    return tuple(o)
def show(t, v):
    if t == 4:
        try: s = v.decode()
        except UnicodeDecodeError: return "Hex-STRING: " + v.hex(" ")
        return 'STRING: "%s"' % s
    if t in (2, 0x41, 0x42, 0x43, 0x46): return "INTEGER: %d" % int.from_bytes(v, "big")
    if t == 6: return "OID: " + ".".join(map(str, dec_oid(v)))
    if t == 0x40: return "IpAddress: " + ".".join(map(str, v))
    return "type 0x%02x: %s" % (t, v.hex())
host, comm = sys.argv[1], sys.argv[2]
port = int(sys.argv[3]) if len(sys.argv) > 3 else 161
limit = int(sys.argv[4]) if len(sys.argv) > 4 else 500
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
oid = (1, 3, 6, 1, 2, 1); n = 0
while n < limit:
    pdu = tlv(0xa1, enc_int(n + 1) + enc_int(0) + enc_int(0) + tlv(0x30, tlv(0x30, enc_oid(oid) + b"\x05\x00")))
    msg = tlv(0x30, enc_int(1) + tlv(4, comm.encode()) + pdu)
    for _ in range(2):
        try: s.sendto(msg, (host, port)); data = s.recv(65535); break
        except socket.timeout: data = None
    if not data: break
    try:
        _, body, _ = rd(data, 0); i = 0
        _, _, i = rd(body, i); _, _, i = rd(body, i)           # version, community
        _, pdu, _ = rd(body, i); j = 0
        _, _, j = rd(pdu, j); _, err, j = rd(pdu, j); _, _, j = rd(pdu, j)
        _, vbl, _ = rd(pdu, j); _, vb, _ = rd(vbl, 0)
        _, ob, k = rd(vb, 0); t, val, _ = rd(vb, k)
    except Exception: break
    if int.from_bytes(err, "big") or t in (0x80, 0x81, 0x82): break
    new = dec_oid(ob)
    if new <= oid: break
    oid = new; n += 1
    print(".".join(map(str, oid)), "=", show(t, val), flush=True)
PY
      if [ -s "$OUT/snmp_$c.txt" ]; then
        r=1; good "community string '$c' works (full walk saved to $OUT/snmp_$c.txt)"
        head -12 "$OUT/snmp_$c.txt" | sed 's/^/    /'
        grep -iE 'flag|sit\{|secret|pass|user' "$OUT/snmp_$c.txt" | head -10 | sed 's/^/    interesting: /'
        break
      else rm -f "$OUT/snmp_$c.txt"; fi
    done
    [ -z "${r:-}" ] && note "no response to common community strings (try: onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt $TARGET)"
  fi
fi

# ---------------- 10. SSH ----------------
for p in "${OPEN_ARR[@]}"; do
  [[ "${SVC[$p]:-}" == ssh* ]] || head -c 4 "$OUT/banner_$p.txt" 2>/dev/null | grep -q '^SSH-' || continue
  say "9. SSH on port $p (version and pre-login banner, no password attempts)"
  head -1 "$OUT/banner_$p.txt" | sed 's/^/    version: /'
  if have ssh; then
    timeout 12 ssh -p "$p" -o BatchMode=yes -o ConnectTimeout=6 -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=none -o LogLevel=INFO \
        nobody@"$TARGET" 2>&1 | grep -vE 'Permission denied|Connection closed|Permanently added|^$' | head -20 > "$OUT/ssh_banner_$p.txt"
    if [ -s "$OUT/ssh_banner_$p.txt" ]; then good "pre-login banner:"; sed 's/^/    /' "$OUT/ssh_banner_$p.txt"; else note "no pre-login banner"; fi
  fi
done

# ---------------- 11. unusual ports ----------------
COMMON=",21,22,23,25,53,80,110,111,135,139,143,161,443,445,993,995,3306,3389,5432,"
ODD=()
for p in "${OPEN_ARR[@]}"; do
  [ -z "$p" ] && continue
  [[ "$COMMON" == *",$p,"* ]] && continue
  is_web "$p" && continue
  [[ "${SVC[$p]:-}" == ssh* ]] && continue
  head -c 4 "$OUT/banner_$p.txt" 2>/dev/null | grep -q '^SSH-' && continue
  ODD+=("$p")
done
poke_port() {
  local p=$1 probe r
  : > "$OUT/probe_$p.txt"; : > "$OUT/probe_$p.show"
  for probe in '' 'help' '?' 'flag' 'GET / HTTP/1.0'; do
    r=$( (sleep 1; printf '%s\r\n' "$probe"; sleep 2) | timeout 6 nc -n -w 3 "$TARGET" "$p" 2>/dev/null | head -c 500 | tr -d '\000')
    [ -n "$r" ] && { printf '    sent %-16s got: %s\n' "'$probe'" "$(echo "$r" | tr '\r\n' '  ' | cut -c1-150)" >> "$OUT/probe_$p.show"; echo "$r" >> "$OUT/probe_$p.txt"; }
  done
}
if [ ${#ODD[@]} -gt 0 ]; then
  say "10. Unusual ports ${ODD[*]} - poking each with a few inputs (all ports at once)"
  PIDS=()
  for p in "${ODD[@]}"; do
    poke_port "$p" & PIDS+=($!)
    (( ${#PIDS[@]} >= 8 )) && { wait "${PIDS[@]}"; PIDS=(); }
  done
  [ ${#PIDS[@]} -gt 0 ] && wait "${PIDS[@]}"
  for p in "${ODD[@]}"; do
    note "port $p (${SVC[$p]:-unknown}):"
    if [ -s "$OUT/probe_$p.show" ]; then cat "$OUT/probe_$p.show"; else note "  silent to every probe (try nc -nv $TARGET $p by hand)"; fi
    rm -f "$OUT/probe_$p.show"
  done
fi

# ---------------- 11. web (last, gets the time that is left) ----------------
WEB_PORTS=()
for p in "${OPEN_ARR[@]}"; do [ -n "$p" ] && is_web "$p" && WEB_PORTS+=("$p"); done
if [ ${#WEB_PORTS[@]} -gt 0 ]; then
  REMAIN=$(( $(left) - 45 ))      # keep ~45 s for the summary
  say "11. Web (max $WEBRATE requests/s, about $(( REMAIN > 0 ? REMAIN/60 : 0 )) min left in the budget)"
  DARGS=(); for d in "${DOMAINS[@]}"; do DARGS+=(-d "$d"); done
  [ -f "$OUT/dns_hosts.txt" ] && while read -r h; do DARGS+=(-d "$h"); done < <(sort -u "$OUT/dns_hosts.txt")
  WARGS=(--rate "$WEBRATE"); (( QUICK )) && WARGS+=(--quick)
  [ -n "$AUTH" ] && WARGS+=(--auth "$AUTH")
  if (( DEEP )); then
    [ -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt ] && WARGS+=(--vhost-list /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt)
    [ -f /usr/share/seclists/Discovery/Web-Content/common.txt ] && WARGS+=(--dir-list /usr/share/seclists/Discovery/Web-Content/common.txt)
    note "deep mode: SecLists wordlists, this can take several minutes per web port"
  fi
  i=0
  for p in "${WEB_PORTS[@]}"; do
    i=$((i+1)); REMAIN=$(( $(left) - 45 )); PORTS_LEFT=$(( ${#WEB_PORTS[@]} - i + 1 ))
    SLICE=$(( REMAIN / PORTS_LEFT ))
    if [ "$SLICE" -lt 60 ]; then
      bad "out of time for web port $p; run it on its own:  sudo bash recon_hunt.sh -t $TARGET -p $p"
      SKIPPED+=("web port $p: sudo bash recon_hunt.sh -t $TARGET -p $p"); continue
    fi
    scheme=http; [[ "${SVC[$p]:-}" == *ssl* || "${SVC[$p]:-}" == *https* || "$p" == 443 || "$p" == 8443 ]] && scheme=https
    note "--- $scheme://$TARGET:$p/"
    [ -f "$WEBPY" ] && python3 "$WEBPY" -u "$scheme://$TARGET:$p/" -o "$OUT/web_$p" "${DARGS[@]}" "${WARGS[@]}" --max-time "$SLICE" | tee "$OUT/web_$p.log"
  done
  # domain found on the web but DNS not queried yet? do it now
  if (( ! DNS_TRIED )) && have dig && { port_open 53 || [[ ",$UDP_OPEN," == *",53,"* ]]; }; then
    for d in $(grep -ohE 'hostnames seen: .*' "$OUT"/web_*.log 2>/dev/null | sed 's/hostnames seen: //; s/, /\n/g' | awk -F. 'NF>=2{print $(NF-1)"."$NF}' | sort -u); do
      note "DNS for $d (found on the web page):"
      timeout 15 dig axfr "$d" @"$TARGET" +time=5 +tries=1 > "$OUT/dns_axfr_$d.txt" 2>&1
      grep -qE '\sIN\s' "$OUT/dns_axfr_$d.txt" && { good "Zone transfer allowed for $d"; grep -E '\sIN\s' "$OUT/dns_axfr_$d.txt" | sort -u | sed 's/^/    /'; } \
        || note "  zone transfer refused"
    done
  fi
fi

# ---------------- 12. summary ----------------
say "Summary  ($(( $(date +%s) - START ))s)"
python3 - "$OUT" "$REGEX" <<'PY'
import os, re, sys
out, rx = sys.argv[1], re.compile(sys.argv[2])
lab = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9]{32}(?![A-Za-z0-9])")
hits = {}
for root, _, files in os.walk(out):
    for fn in files:
        if fn == "run.log": continue      # our own output, would double-count everything
        p = os.path.join(root, fn)
        try: data = open(p, "rb").read(3_000_000).decode("latin-1")
        except Exception: continue
        for m in rx.findall(data): hits.setdefault(m, set()).add(os.path.relpath(p, out))
        for m in lab.findall(data):
            # LAB flags mix upper, lower and digits; skip hashes and plain words
            if re.search(r"[A-Z]", m) and re.search(r"[a-z]", m) and re.search(r"\d", m):
                hits.setdefault(m, set()).add(os.path.relpath(p, out))
def where(path):
    """Turn a result file name into the service it came from (= which question it answers)."""
    f = path.replace("\\", "/")
    rules = [(r"^ftp_(\d+)", "FTP port {0}  (file transfer / port 21 question)"),
             (r"^smb_([^/]+)", "SMB share '{0}'  (shares / spidering question)"),
             (r"^smbmap", "SMB  (shares / spidering question)"),
             (r"^dns_axfr_(.+)\.txt", "DNS zone transfer of {0}  (dig / records question)"),
             (r"^dns_", "DNS records  (dig / records question)"),
             (r"^snmp_", "SNMP over UDP  (UDP / monitoring question)"),
             (r"^ssh_banner_(\d+)", "SSH pre-login banner, port {0}"),
             (r"^banner_(\d+)", "banner of port {0}"),
             (r"^probe_(\d+)", "reply from odd port {0}  (irregular port question)"),
             (r"^services", "nmap fingerprint (SF block)  (fingerprint / irregular port question)"),
             (r"^web_(\d+)/index_([^/]+)\.html", "web port {0}, home page of vhost {1}"),
             (r"^web_(\d+)/([^_/]+)_(.+)", "web port {0}, site {1}, file {2}"),
             (r"^web_(\d+)", "web port {0}")]
    for rx, label in rules:
        m = re.match(rx, f)
        if m: return label.format(*m.groups())
    return f
if hits:
    print("\033[1;32m[+] Flag-looking strings, and where each was found (match the service to the question):\033[0m")
    for k, v in sorted(hits.items()):
        srcs = sorted({where(x) for x in v if not x.endswith(".log")} or {where(x) for x in v})
        print(f"    {k}")
        for src in srcs[:3]: print(f"        <- {src}")
else:
    print("    no flag-looking strings found")
PY
note "Open ports: ${OPEN:-none}"
if [ -s "$OUT/services.txt" ]; then
  note "Services (answers to 'what software / version / OS' questions):"
  grep -E '^[0-9]+/tcp +open' "$OUT/services.txt" | sed 's/^/      /'
  os=$(grep -ohiE 'Service Info: OS: [^;]*|Ubuntu|Debian|Amazon Linux|CentOS|Red Hat|Fedora|Alpine|Windows[^;,]*' "$OUT/services.txt" "$OUT"/banner_*.txt 2>/dev/null | sort -f | uniq -ci | sort -rn | head -3 | awk '{$1=""; print}' | paste -sd',' -)
  [ -n "$os" ] && note "OS hints from banners:$os"
fi
[ -s "$OUT/udp.gnmap" ] && note "UDP: $(grep -oE '[0-9]+/open[^,]*/udp//[a-z-]*' "$OUT/udp.gnmap" | paste -sd' ' -)"
grep -hE 'VHOST|DIRECTORY LISTING|FORM|VALID USERNAME|LOGIN WORKS|AUTH on|BASIC AUTH WORKS|LFI|SQL ERROR|reflected|COMMAND INJECTION|TEMPLATE INJECTION|IDOR|FILE UPLOAD|exposed git|endpoint from|secret-looking|tamperable|decodes|HTTP auth|comment|hostnames seen' "$OUT"/web_*.log 2>/dev/null | sed 's/^ */    /' | head -40
grep -l 'ANONYMOUS LOGIN ALLOWED' -r "$OUT" >/dev/null 2>&1 && note "FTP: anonymous login allowed"
[ -s "$OUT/smb_shares.txt" ] && note "SMB shares: $(cut -d'|' -f2 "$OUT/smb_shares.txt" | paste -sd' ' -)"
ls "$OUT"/dns_axfr_*.txt >/dev/null 2>&1 && grep -lqE '\sIN\s' "$OUT"/dns_axfr_*.txt 2>/dev/null && note "DNS: zone transfer allowed"
ls "$OUT"/snmp_*.txt >/dev/null 2>&1 && note "SNMP: readable with a default community string"
if [ ${#SKIPPED[@]} -gt 0 ]; then
  bad "Skipped or cut short to stay inside the $BUDGET_MIN-minute budget (run these separately if needed):"
  printf '    %s\n' "${SKIPPED[@]}"
fi
grep -l 'time limit reached' "$OUT"/web_*.log >/dev/null 2>&1 && note "web: time limit reached on $(grep -l 'time limit reached' "$OUT"/web_*.log | sed 's/.*web_//; s/.log//' | paste -sd' ' -) - re-run with -p PORT for a full web pass"
note "Total time: $(( ($(date +%s) - START) / 60 )) min $(( ($(date +%s) - START) % 60 )) s"
note "Everything is saved in $OUT/ (this whole output is in $OUT/run.log)"
