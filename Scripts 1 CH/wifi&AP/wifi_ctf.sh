#!/usr/bin/env bash
# wifi_ctf.sh - one tool for the three Wi-Fi capture question types in the ICT2212 CTF.
# Only use it on captures you're allowed to analyse (your CTF files).
#
#   survey : overview of a capture, tells you which mode fits
#   assoc  : hidden SSID / BSSID / association ID for a client      (e.g. "hidden in plain sight")
#   crack  : crack WPA2 handshake, decrypt, find the flag            (e.g. "four messages one secret")
#   twin   : evil twin - find the fake AP and the sign-in it caught  (e.g. "same name, different AP")
#
# Examples:
#   ./wifi_ctf.sh survey -f capture.pcap
#   ./wifi_ctf.sh assoc  -f survey.pcap   -c 00:21:6a:8e:3c:51
#   ./wifi_ctf.sh crack  -f wireless.pcap -w wordlist.txt -e Campus-Club
#   ./wifi_ctf.sh twin   -f evil-twin.pcap -e Cafe-Guest -p FlatWhite2026CafeGuest
#
# Needs: tshark, and for crack mode aircrack-ng.
#   sudo apt install tshark aircrack-ng

set -u

MODE="${1:-}"; [ $# -gt 0 ] && shift
PCAP=""; CLIENT=""; WORDLIST=""; SSID=""; BSSID=""; PASS=""; VICTIM=""
REGEX='\b[A-Za-z0-9]{32}\b'

say()  { printf '\n\033[1;34m[*] %s\033[0m\n' "$*"; }
good() { printf '\033[1;32m[+] %s\033[0m\n' "$*"; }
bad()  { printf '\033[1;31m[!] %s\033[0m\n' "$*"; }
note() { printf '    %s\n' "$*"; }

usage() {
  sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
  cat <<'EOF'

Options (which ones you need depends on the mode):
  -f FILE    capture file (.pcap or .pcapng)                 all modes
  -c MAC     client/laptop MAC from the question              assoc
  -w FILE    wordlist                                         crack
  -e SSID    network name                                     crack, twin
  -b BSSID   AP MAC (pick one AP when names clash)            crack
  -p PASS    known Wi-Fi password                             crack (skip cracking), twin
  -v MAC     victim MAC, if the question gives it             twin (optional)
  -r REGEX   flag pattern, default bare 32-char strings (-r adds a pattern)   crack
  -h         help
EOF
  exit "${1:-1}"
}

[ -z "$MODE" ] || [ "$MODE" = "-h" ] || [ "$MODE" = "--help" ] && usage 0
case "$MODE" in survey|assoc|crack|twin) ;; *) bad "Unknown mode '$MODE'. Use survey, assoc, crack or twin."; usage ;; esac

while getopts "f:c:w:e:b:p:v:r:h" opt; do
  case "$opt" in
    f) PCAP="$OPTARG" ;;   c) CLIENT="${OPTARG,,}" ;;  w) WORDLIST="$OPTARG" ;;
    e) SSID="$OPTARG" ;;   b) BSSID="${OPTARG,,}" ;;   p) PASS="$OPTARG" ;;
    v) VICTIM="${OPTARG,,}" ;; r) REGEX="$REGEX|$OPTARG" ;;   h) usage 0 ;; *) usage ;;
  esac
done

[ -z "$PCAP" ] && { bad "Give the capture with -f"; usage; }
[ -f "$PCAP" ] || { bad "File not found: $PCAP"; exit 1; }
command -v tshark >/dev/null || { bad "tshark not installed: sudo apt install tshark"; exit 1; }

# ---------- helpers ----------
tsh() { tshark -r "$PCAP" "$@" 2>/dev/null; }

# hex -> text (python3, so it works even without xxd)
hex2text() { python3 -c 'import sys;sys.stdout.write(bytes.fromhex(sys.argv[1]).decode("utf-8","replace"))' "$1" 2>/dev/null; }

# SSIDs sometimes print as hex; turn them back into text
ssid_text() {
  local s="$1"
  if [[ -n "$s" && "$s" =~ ^[0-9a-fA-F]+$ ]] && (( ${#s} % 2 == 0 )); then
    local t; t="$(hex2text "$s" | tr -d '\0')"
    [[ -n "$t" && "$t" =~ ^[[:print:]]+$ ]] && { printf '%s' "$t"; return; }
  fi
  printf '%s' "$s"
}

# numbers from tshark can be 0x0525 or 1317; this handles both
num() { local v="${1%%,*}"; [ -z "$v" ] && { echo ""; return; }; echo $(( v )); }

nocolon() { echo "${1//:/}" | tr 'A-F' 'a-f'; }

# turn an HTTP body (hex or text) into readable, URL-decoded text
decode_body() {
  local b="$1"
  if [[ "$b" =~ ^[0-9a-fA-F]+$ ]] && (( ${#b} % 2 == 0 )); then
    b="$(hex2text "$b")"
  fi
  printf '%s' "$b"
}
urldecode() { python3 -c 'import sys,urllib.parse;print(urllib.parse.unquote_plus(sys.stdin.read().strip()))'; }

# print form fields one per line, decoded, and guess username/password
show_form() {
  python3 - "$1" <<'PY'
import sys, urllib.parse
raw = sys.argv[1].strip()
pairs = urllib.parse.parse_qsl(raw, keep_blank_values=True)
if not pairs:
    print("    (not a form)  " + raw[:300]); sys.exit()
user = pw = None
for k, v in pairs:
    print(f"      {k} = {v}")
    kl = k.lower()
    if user is None and any(x in kl for x in ("user", "login", "email", "name", "uid")): user = v
    if pw is None and "pass" in kl or (pw is None and kl in ("pw", "pwd")): pw = v
if user is not None and pw is not None:
    print(f"    -> username: {user}")
    print(f"    -> password: {pw}")
    print(f"    -> SIT{{{user}_{pw}}}   (check the format the question asks for)")
PY
}

# ---------- survey ----------
do_survey() {
  say "Networks (beacons and probe responses): count, BSSID, channel, encrypted?, SSID"
  tsh -Y 'wlan.fc.type_subtype == 8 || wlan.fc.type_subtype == 5' -T fields \
      -e wlan.bssid -e wlan_radio.channel -e wlan.fixed.capabilities.privacy -e wlan.ssid \
    | awk -F'\t' -v OFS='\t' '{for(i=1;i<=4;i++) if($i=="") $i="-"; print}' \
    | sort | uniq -c | sort -rn | while read -r cnt b ch pr s; do
        # empty columns (no channel info, hidden SSID) are "-" so the columns don't shift
        [ "$ch" = "-" ] && ch=""; [ "$pr" = "-" ] && pr=""; [ "$s" = "-" ] && s=""
        s="$(ssid_text "${s:-}")"
        printf '    %5s  %s  ch %-3s  enc=%-5s  %s\n' "$cnt" "$b" "${ch:-?}" "${pr:-?}" "${s:-<hidden>}"
      done

  say "SSIDs broadcast by more than one BSSID (possible evil twin)"
  local dup
  dup=$(tsh -Y 'wlan.fc.type_subtype == 8' -T fields -e wlan.ssid -e wlan.bssid | sort -u \
        | awk -F'\t' '$1!=""{n[$1]++; l[$1]=l[$1]" "$2} END{for(s in n) if(n[s]>1) print s"\t"l[s]}')
  if [ -n "$dup" ]; then
    while IFS=$'\t' read -r s l; do note "$(ssid_text "$s"):$l"; done <<< "$dup"
  else note "none"; fi

  say "Clients asking to join (association / reassociation requests): count, client, BSSID, SSID"
  tsh -Y 'wlan.fc.type_subtype == 0 || wlan.fc.type_subtype == 2' -T fields -e wlan.sa -e wlan.bssid -e wlan.ssid \
    | sort | uniq -c | while read -r cnt c b s; do printf '    %5s  %s -> %s  %s\n' "$cnt" "$c" "$b" "$(ssid_text "${s:-}")"; done

  say "Handshake (EAPOL) frames per BSSID"
  tsh -Y eapol -T fields -e wlan.bssid | sort | uniq -c | sed 's/^/   /'

  say "Deauthentication frames: count, from, to"
  tsh -Y 'wlan.fc.type_subtype == 12' -T fields -e wlan.sa -e wlan.da | sort | uniq -c | sort -rn | head -15 | sed 's/^/   /'

  say "Unencrypted HTTP POSTs visible without a key: $(tsh -Y 'http.request.method == "POST"' | wc -l)"

  say "Which mode to use"
  note "Question gives a client MAC and asks for SSID/BSSID/association ID  -> assoc -c <MAC>"
  note "WPA2 network, a wordlist, asks you to crack/decrypt                 -> crack -w <list> -e <SSID>"
  note "Same SSID on two BSSIDs, deauths, password given, asks for sign-in  -> twin -e <SSID> -p <PASS>"
}

# ---------- assoc ----------
do_assoc() {
  [ -z "$CLIENT" ] && { bad "assoc needs the client MAC: -c 00:11:22:33:44:55"; exit 1; }
  say "Association / reassociation responses sent to $CLIENT"
  local lines
  lines=$(tsh -Y "(wlan.fc.type_subtype == 1 || wlan.fc.type_subtype == 3) && wlan.da == $CLIENT" \
          -T fields -e frame.number -e wlan.bssid -e wlan.fixed.status_code -e wlan.fixed.aid)
  [ -z "$lines" ] && { bad "No association responses to $CLIENT. Check the MAC (lowercase, colons)."; exit 1; }

  local ok=()
  while IFS=$'\t' read -r fr b st aid; do
    local s; s=$(num "$st")
    if [ "${s:-1}" = "0" ]; then
      local a=$(( $(num "$aid") & 0x3FFF ))
      note "frame $fr  BSSID $b  status SUCCESS  AID $aid -> $a (decimal)"
      ok+=("$fr|$b|$a")
    else
      note "frame $fr  BSSID $b  status $st (FAILED, ignore)"
    fi
  done <<< "$lines"

  [ ${#ok[@]} -eq 0 ] && { bad "No successful association. Read the status codes above."; exit 1; }

  for e in "${ok[@]}"; do
    IFS='|' read -r fr b a <<< "$e"
    say "Successful join: frame $fr to $b"
    local s
    s=$(tsh -Y "(wlan.fc.type_subtype == 0 || wlan.fc.type_subtype == 2 || wlan.fc.type_subtype == 4) && wlan.sa == $CLIENT && wlan.bssid == $b && wlan.ssid" \
        -T fields -e wlan.ssid | grep -v '^$' | head -1)
    [ -z "$s" ] && s=$(tsh -Y "wlan.fc.type_subtype == 5 && wlan.bssid == $b && wlan.ssid" -T fields -e wlan.ssid | grep -v '^$' | head -1)
    [ -z "$s" ] && s=$(tsh -Y "wlan.fc.type_subtype == 8 && wlan.bssid == $b && wlan.ssid" -T fields -e wlan.ssid | grep -v '^$' | head -1)
    s="$(ssid_text "$s")"
    local data; data=$(tsh -Y "wlan.fc.type == 2 && wlan.bssid == $b && (wlan.sa == $CLIENT || wlan.da == $CLIENT)" | wc -l)
    good "SSID   : ${s:-<not found - check probe/association requests by hand>}"
    good "BSSID  : $b   (no colons: $(nocolon "$b"))"
    good "AID    : $a"
    note "data frames between client and this AP afterwards: $data  (more = the network it actually used)"
    note "e.g. SIT{${s}_$(nocolon "$b")_${a}}   (check the format the question asks for)"
  done
}

# ---------- crack ----------
do_crack() {
  for t in aircrack-ng airdecap-ng; do
    command -v "$t" >/dev/null || { bad "$t not installed: sudo apt install aircrack-ng"; exit 1; }
  done
  [ -z "$SSID" ] && [ -z "$BSSID" ] && { bad "crack needs the network: -e SSID or -b BSSID"; exit 1; }

  local OUT="crack_$(basename "${PCAP%.*}")"; mkdir -p "$OUT"
  local WORK="$OUT/capture.pcap"
  tshark -r "$PCAP" -F pcap -w "$WORK" 2>/dev/null || cp "$PCAP" "$WORK"

  local e; e=$(tshark -r "$WORK" -Y eapol 2>/dev/null | wc -l)
  say "Handshake (EAPOL) frames: $e"
  (( e >= 4 )) && good "Full 4-way handshake present" || bad "Fewer than 4 EAPOL frames, cracking/decrypting may fail"

  local TARGET=(); [ -n "$SSID" ] && TARGET+=(-e "$SSID"); [ -n "$BSSID" ] && TARGET+=(-b "$BSSID")
  if [ -z "$PASS" ]; then
    [ -z "$WORDLIST" ] && { bad "Give a wordlist with -w, or the password with -p"; exit 1; }
    [ -f "$WORDLIST" ] || { bad "Wordlist not found: $WORDLIST"; exit 1; }
    tr -d '\r' < "$WORDLIST" > "$OUT/wordlist.txt"
    say "Cracking with aircrack-ng ($(wc -l < "$OUT/wordlist.txt") words)"
    rm -f "$OUT/key.txt"
    aircrack-ng -q -w "$OUT/wordlist.txt" "${TARGET[@]}" -l "$OUT/key.txt" "$WORK"
    [ -s "$OUT/key.txt" ] || { bad "Not in the wordlist. Check the SSID spelling or try -b <BSSID>."; exit 1; }
    PASS="$(cat "$OUT/key.txt")"; good "Passphrase: $PASS"
  fi

  local DS="$SSID"
  if [ -z "$DS" ]; then
    DS=$(tshark -r "$WORK" -Y "wlan.bssid == $BSSID && wlan.ssid" -T fields -e wlan.ssid 2>/dev/null | grep -v '^$' | head -1)
    DS="$(ssid_text "$DS")"
  fi
  say "Decrypting with airdecap-ng"
  local D=(-e "$DS" -p "$PASS"); [ -n "$BSSID" ] && D+=(-b "$BSSID")
  airdecap-ng "${D[@]}" "$WORK" | sed 's/^/    /'
  local DEC="$OUT/capture-dec.pcap"
  [ -s "$DEC" ] || { bad "Nothing decrypted. Wrong SSID/password, or the handshake for that session is missing."; exit 1; }
  good "Decrypted capture: $DEC"

  say "HTTP in the decrypted traffic"
  tshark -r "$DEC" -Y http -T fields -e frame.number -e ip.src -e ip.dst -e http.request.method \
         -e http.request.uri -e http.response.code 2>/dev/null | sed 's/^/    /'
  mkdir -p "$OUT/http_objects"
  tshark -r "$DEC" -q --export-objects "http,$OUT/http_objects" >/dev/null 2>&1

  say "Searching for the flag: $REGEX"
  local F
  F=$( {
    tshark -r "$DEC" -Y http -T fields -e http.file_data 2>/dev/null | while read -r l; do decode_body "$l"; echo; done
    grep -raE "$REGEX" "$OUT/http_objects" 2>/dev/null
    for s in $(tshark -r "$DEC" -T fields -e tcp.stream 2>/dev/null | sort -un); do
      tshark -r "$DEC" -q -z "follow,tcp,ascii,$s" 2>/dev/null
    done
    strings "$DEC"
  } | grep -oE "$REGEX" | sort -u )
  if [ -n "$F" ]; then good "Flag candidate(s):"; echo "$F" | sed 's/^/    /'
  else bad "No match. Open $DEC in Wireshark and Follow > TCP Stream. HTTP files are in $OUT/http_objects/"; fi
}

# ---------- twin ----------
do_twin() {
  [ -z "$SSID" ] && { bad "twin needs the network name: -e SSID"; exit 1; }
  local KEY=()
  [ -n "$PASS" ] && KEY=(-o wlan.enable_decryption:TRUE -o "uat:80211_keys:\"wpa-pwd\",\"${PASS}:${SSID}\"")

  say "APs broadcasting \"$SSID\": beacons, BSSID, channel, encrypted?, first frame"
  local aps
  aps=$(tsh -Y "wlan.fc.type_subtype == 8 && wlan.ssid == \"$SSID\"" -T fields \
        -e wlan.bssid -e wlan_radio.channel -e wlan.fixed.capabilities.privacy -e frame.number \
        | awk -F'\t' '{c[$1]++; if(!($1 in f)){f[$1]=$4; ch[$1]=($2==""?"?":$2); p[$1]=($3==""?"?":$3)}} END{for(b in c) print c[b]"\t"b"\t"ch[b]"\t"p[b]"\t"f[b]}' | sort -t$'\t' -k5 -n)
  [ -z "$aps" ] && { bad "No beacons for \"$SSID\". Check the spelling (case matters)."; exit 1; }
  while IFS=$'\t' read -r c b ch p f; do printf '    %5s  %s  ch %-3s  enc=%-5s  first seen frame %s\n' "$c" "$b" "${ch:-?}" "${p:-?}" "$f"; done <<< "$aps"
  local -a APLIST; mapfile -t APLIST < <(cut -f2 <<< "$aps")

  say "Deauthentication frames: count, claimed sender, target"
  local deauth
  deauth=$(tsh -Y 'wlan.fc.type_subtype == 12' -T fields -e wlan.sa -e wlan.da -e frame.number)
  awk -F'\t' '{print $1"\t"$2}' <<< "$deauth" | sort | uniq -c | sort -rn | head -10 | sed 's/^/   /'
  local DSRC FIRST_DEAUTH
  DSRC=$(awk -F'\t' '$1!=""{print $1}' <<< "$deauth" | sort | uniq -c | sort -rn | awk 'NR==1{print $2}')
  FIRST_DEAUTH=$(awk -F'\t' 'NR==1{print $3}' <<< "$deauth")
  [ -n "$DSRC" ] && note "deauths claim to come from $DSRC  -> that's the REAL AP being spoofed"

  if [ -z "$VICTIM" ]; then
    VICTIM=$(awk -F'\t' '$2!="" && $2!="ff:ff:ff:ff:ff:ff"{print $2}' <<< "$deauth" | sort | uniq -c | sort -rn | awk 'NR==1{print $2}')
    [ -n "$VICTIM" ] && note "most-targeted client (assumed victim): $VICTIM   (override with -v)"
  fi

  local TWIN=""
  if [ -n "$VICTIM" ]; then
    say "Victim $VICTIM: successful associations"
    local joins
    joins=$(tsh -Y "(wlan.fc.type_subtype == 1 || wlan.fc.type_subtype == 3) && wlan.da == $VICTIM" \
            -T fields -e frame.number -e wlan.bssid -e wlan.fixed.status_code)
    while IFS=$'\t' read -r fr b st; do
      [ -z "$fr" ] && continue
      local s; s=$(num "$st")
      local tag=""; [ -n "$FIRST_DEAUTH" ] && (( fr > FIRST_DEAUTH )) && tag="(after deauth)"
      note "frame $fr  $b  status ${st}  $tag"
      if [ "${s:-1}" = "0" ] && [ -n "$tag" ] && [ "$b" != "$DSRC" ]; then TWIN="$b"; fi
    done <<< "$joins"
  fi

  if [ -z "$TWIN" ]; then
    for b in "${APLIST[@]}"; do [ "$b" != "$DSRC" ] && { TWIN="$b"; break; }; done
    [ -n "$TWIN" ] && note "no clear post-deauth join; guessing twin = the AP that isn't being spoofed"
  fi
  [ -z "$TWIN" ] && { bad "Couldn't tell which AP is the twin. Look at the lists above and filter by hand."; exit 1; }
  good "Evil twin BSSID: $TWIN"

  say "HTTP POSTs per BSSID (decoys pile up on the real AP)"
  tsh "${KEY[@]}" -Y 'http.request.method == "POST"' -T fields -e wlan.bssid | sort | uniq -c | sed 's/^/   /'

  say "Sign-ins sent to the twin ($TWIN)"
  local posts
  posts=$(tsh "${KEY[@]}" -Y "http.request.method == \"POST\" && wlan.bssid == $TWIN" \
          -T fields -e frame.number -e wlan.sa -e http.host -e http.request.uri -e http.file_data)
  if [ -z "$posts" ]; then
    bad "No POSTs to the twin."
    note "If the twin is encrypted with a different password, its traffic won't decrypt with -p."
    note "Also check other protocols below."
  else
    while IFS=$'\t' read -r fr src host uri body; do
      note "frame $fr  from $src  http://$host$uri"
      show_form "$(decode_body "$body")"
    done <<< "$posts"
    note "More than one? Use the one from the victim, and check which got a success response."
  fi

  say "Other cleartext logins seen via the twin (FTP/POP/IMAP/basic auth)"
  tsh "${KEY[@]}" -Y "wlan.bssid == $TWIN && (ftp.request.command == \"USER\" || ftp.request.command == \"PASS\" || pop.request || imap.request || http.authbasic)" \
      -T fields -e frame.number -e ftp.request.arg -e http.authbasic -e pop.request.parameter -e imap.request | sed 's/^/    /'
}

case "$MODE" in
  survey) do_survey ;; assoc) do_assoc ;; crack) do_crack ;; twin) do_twin ;;
esac
