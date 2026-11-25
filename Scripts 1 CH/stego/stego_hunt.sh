#!/usr/bin/env bash
# stego_hunt.sh - work through the steganography checks on one file and report
# anything that looks like a flag, a password or encoded text.
# Only use it on files you're allowed to analyse (your CTF files).
#
# Usage:
#   ./stego_hunt.sh -f ilovesit.jpeg
#   ./stego_hunt.sh -f image.jpg -p 'KnownPassphrase'
#   ./stego_hunt.sh -f image.jpg -w /usr/share/wordlists/rockyou.txt
#   ./stego_hunt.sh -f image.png -r 'flag\{[^}]*\}'
#   ./stego_hunt.sh -f image.jpg -q                        # quick: skip brute forcing
#   ./stego_hunt.sh -d 'NXVwM3I1M2N1cjNwNDU1dzByZA=='      # just decode a string
#
# Uses whatever is installed and skips the rest:
#   sudo apt install libimage-exiftool-perl binwalk foremost steghide stegseek zsteg \
#                    outguess zbar-tools pngcheck sox stegsnow fcrackzip p7zip-full

set -u
FILE=""; WORDLIST=""; PASSES=(); REGEX='\b[A-Za-z0-9]{32}\b'; DECODE_ONLY=""; QUICK=0
ZIP_TIME=60   # seconds allowed for cracking a locked zip with a wordlist

say()  { printf '\n\033[1;34m[*] %s\033[0m\n' "$*"; }
good() { printf '\033[1;32m[+] %s\033[0m\n' "$*"; }
bad()  { printf '\033[1;31m[!] %s\033[0m\n' "$*"; }
note() { printf '    %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
  sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
  cat <<'EOF'

Options:
  -f FILE   the image/audio/file to check                   (required unless -d)
  -p PASS   a passphrase to try (steghide, outguess, zips). Repeatable
  -w FILE   wordlist for brute forcing (default: rockyou.txt if unzipped)
  -r REGEX  flag pattern (default: bare 32-char strings \b[A-Za-z0-9]{32}\b; -r adds another pattern)
  -q        quick: skip stegseek, zip wordlist cracking and zsteg -a
  -d TEXT   only decode TEXT (base64, base32, hex, rot13, ...) and exit
  -h        help
EOF
  exit "${1:-1}"
}

while getopts "f:p:w:r:d:qh" o; do
  case "$o" in
    f) FILE="$OPTARG" ;; p) PASSES+=("$OPTARG") ;; w) WORDLIST="$OPTARG" ;;
    r) REGEX="$REGEX|$OPTARG" ;; d) DECODE_ONLY="$OPTARG" ;; q) QUICK=1 ;;
    h) usage 0 ;; *) usage ;;
  esac
done


# ---------- decoder: tries common encodings, up to 3 layers deep ----------
# prints:  chain => result   for anything readable, and FLAG lines for regex hits
decode() {
  python3 -I - "$REGEX" "$@" <<'PY'
import sys, re, base64, binascii, codecs, urllib.parse
regex = re.compile(sys.argv[1]); inputs = sys.argv[2:]

def printable(s):
    return len(s) >= 4 and sum(c.isprintable() or c in "\r\n\t" for c in s) / len(s) > 0.95

def b(x): return x.decode("utf-8")
def try_b64(s):
    t = re.sub(r"\s", "", s)
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", t) or len(t) < 8: return None
    return b(base64.b64decode(t + "=" * (-len(t) % 4)))
def try_b64url(s):
    t = s.strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", t) or not re.search(r"[-_]", t): return None
    return b(base64.urlsafe_b64decode(t + "=" * (-len(t) % 4)))
def try_b32(s):
    t = re.sub(r"\s", "", s).upper()
    if not re.fullmatch(r"[A-Z2-7]+=*", t) or len(t) < 8: return None
    return b(base64.b32decode(t + "=" * (-len(t) % 8)))
def try_hex(s):
    t = re.sub(r"[\s:]|0x|\\x", "", s)
    if not re.fullmatch(r"[0-9a-fA-F]+", t) or len(t) % 2 or len(t) < 8: return None
    return b(bytes.fromhex(t))
def try_bin(s):
    t = s.split()
    if not t or not all(re.fullmatch(r"[01]{7,8}", x) for x in t):
        u = re.sub(r"\s", "", s)
        if not re.fullmatch(r"[01]+", u) or len(u) % 8: return None
        t = [u[i:i+8] for i in range(0, len(u), 8)]
    return "".join(chr(int(x, 2)) for x in t)
def try_oct(s):
    t = s.split()
    if len(t) < 4 or not all(re.fullmatch(r"[0-7]{2,3}", x) for x in t): return None
    return "".join(chr(int(x, 8)) for x in t)
def try_dec(s):
    t = re.split(r"[\s,]+", s.strip())
    if len(t) < 4 or not all(x.isdigit() and 9 <= int(x) < 127 for x in t): return None
    return "".join(chr(int(x)) for x in t)
def try_b85(s):
    t = s.strip()
    if t.startswith("<~") and t.endswith("~>"): return b(base64.a85decode(t, adobe=True))
    if len(t) < 10 or re.fullmatch(r"[A-Za-z0-9+/=]+", t): return None
    try: return b(base64.b85decode(t))
    except Exception: return b(base64.a85decode(t))
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def try_b58(s):
    t = s.strip()
    if len(t) < 8 or any(c not in B58 for c in t): return None
    n = 0
    for c in t: n = n * 58 + B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b(b"\x00" * (len(t) - len(t.lstrip("1"))) + raw)
def try_url(s):
    if "%" not in s: return None
    r = urllib.parse.unquote_plus(s); return r if r != s else None
def rot13(s): return codecs.encode(s, "rot13") if re.search(r"[A-Za-z]", s) else None
def rot47(s):
    if not re.search(r"[!-~]", s): return None
    return "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in s)
def reverse(s): return s[::-1] if len(s) >= 6 else None
MORSE = {".-":"A","-...":"B","-.-.":"C","-..":"D",".":"E","..-.":"F","--.":"G","....":"H","..":"I",".---":"J",
 "-.-":"K",".-..":"L","--":"M","-.":"N","---":"O",".--.":"P","--.-":"Q",".-.":"R","...":"S","-":"T","..-":"U",
 "...-":"V",".--":"W","-..-":"X","-.--":"Y","--..":"Z","-----":"0",".----":"1","..---":"2","...--":"3",
 "....-":"4",".....":"5","-....":"6","--...":"7","---..":"8","----.":"9"}
def try_morse(s):
    if not re.fullmatch(r"[.\- /|]+", s.strip()) or "." not in s: return None
    return " ".join("".join(MORSE.get(ch, "?") for ch in w.split()) for w in re.split(r"\s*[/|]\s*", s.strip()))

DECODERS = [("base64", try_b64), ("base64url", try_b64url), ("base32", try_b32), ("hex", try_hex),
            ("binary", try_bin), ("octal", try_oct), ("decimal", try_dec), ("base85", try_b85),
            ("base58", try_b58), ("url", try_url), ("morse", try_morse)]
WEAK = [("rot13", rot13), ("rot47", rot47), ("reverse", reverse)]  # only shown if they lead somewhere

seen, flags = set(inputs), set()
def check_flag(chain, text):
    for m in regex.findall(text):
        if m not in flags:
            flags.add(m); print(f"FLAG  {chain} => {m}")

shown = set()
def walk(start):
    # breadth-first, so the shortest decoding chain is the one reported
    queue = [(start, "", 0, False)]
    while queue:
        text, chain, depth, weak = queue.pop(0)
        check_flag(chain or "plain", text)
        if depth == 3: continue
        last = chain.split(" > ")[-1] if chain else ""
        for name, fn in DECODERS + WEAK:
            if name == last and name in ("rot13", "rot47", "reverse"): continue  # applying twice undoes it
            # this text already holds a flag: rot/reverse of it would only "find" scrambled copies
            if (name, fn) in WEAK and regex.search(text): continue
            try: r = fn(text)
            except Exception: r = None
            if r: r = r.strip()
            if not r or r == text or not printable(r) or r in seen: continue
            seen.add(r)
            c = f"{chain} > {name}" if chain else name
            is_weak = weak or (name, fn) in WEAK
            # results reached through rot/reverse are usually junk, so only show them if they contain the flag
            if (not is_weak or regex.search(r)) and r not in shown:
                shown.add(r); print(f"DECODED  {c} => {r[:200]}")
            queue.append((r, c, depth + 1, is_weak))
    text = start
    # Caesar shifts: only report if one reveals the flag
    # Caesar shifts keep the length and letters, so skip them if a flag was already found
    # (otherwise a bare 32-char flag would come back 25 times, once per shift)
    if re.search(r"[A-Za-z]", text) and not flags and not regex.search(text):
        for k in range(1, 26):
            r = "".join(chr((ord(ch) - (65 if ch.isupper() else 97) + k) % 26 + (65 if ch.isupper() else 97))
                        if ch.isalpha() else ch for ch in text)
            if regex.search(r): check_flag(f"caesar+{k}", r)

for s in inputs:
    s = s.strip()
    if s: walk(s)
PY
}


if [ -n "$DECODE_ONLY" ]; then
  say "Decoding: $DECODE_ONLY"
  out=$(decode "$DECODE_ONLY")
  [ -n "$out" ] && echo "$out" | sed 's/^/    /' || bad "Nothing decoded to readable text."
  exit 0
fi

[ -z "$FILE" ] && { bad "Give the file with -f (or a string with -d)"; usage; }
[ -f "$FILE" ] || { bad "File not found: $FILE"; exit 1; }

OUT="stego_$(basename "${FILE%.*}")"; rm -rf "$OUT"; mkdir -p "$OUT"
CANDS="$OUT/candidates.txt"; : > "$CANDS"
FOUND="$OUT/flags.txt"; : > "$FOUND"
LOOK=()      # things only your eyes can judge
WORK="$OUT/input_$(basename "$FILE")"; cp "$FILE" "$WORK"
HAVE_PIL=0; python3 -c 'import PIL' 2>/dev/null && HAVE_PIL=1
note "Results go in $OUT/   (your original file isn't touched)"
(( QUICK )) && note "Quick mode: skipping stegseek, zip wordlist cracking and zsteg -a"

record_flags() { grep -aoE "$REGEX" 2>/dev/null | sort -u | tee -a "$FOUND" | sed 's/^/    FLAG: /'; }
mime() { file -b --mime-type "$1"; }
decode_into_found() {   # decode every argument, print results, keep flags
  local d; d=$(decode "$@")
  [ -n "$d" ] && { echo "$d" | sed 's/^/    /'; echo "$d" | sed -n 's/^FLAG .* => //p' >> "$FOUND"; }
}

# ---------- 1. file type and header ----------
say "1. File type and header"
file "$WORK" | sed "s|^$OUT/||; s/^/    /"
EXT=$(mime "$WORK")
note "Mime type: $EXT"
python3 -I - "$WORK" "$OUT" <<'PY'
import sys
path, out = sys.argv[1], sys.argv[2]
d = bytearray(open(path, "rb").read())
known = {b"\x89PNG\r\n\x1a\n": "png", b"\xff\xd8\xff": "jpeg", b"GIF87a": "gif", b"GIF89a": "gif",
         b"BM": "bmp", b"RIFF": "riff (wav)", b"PK\x03\x04": "zip", b"%PDF": "pdf", b"ID3": "mp3"}
if any(d.startswith(m) for m in known):
    print("    header looks valid"); sys.exit()
fix = None
if d[12:16] == b"IHDR":                       # PNG with a broken signature
    d[:8] = b"\x89PNG\r\n\x1a\n"; fix = "png"
elif d[6:10] in (b"JFIF", b"Exif"):           # JPEG with broken first bytes
    d[:4] = b"\xff\xd8\xff" + (b"\xe0" if d[6:10] == b"JFIF" else b"\xe1"); fix = "jpg"
elif d[1:6] in (b"IF87a", b"IF89a") or d[:6].endswith(b"7a") or d[:6].endswith(b"9a"):
    d[:6] = b"GIF89a"; fix = "gif"
if fix:
    p = f"{out}/repaired_header.{fix}"; open(p, "wb").write(d)
    print(f"    BROKEN HEADER: looks like a {fix.upper()} with damaged magic bytes. Repaired copy: {p}")
else:
    print("    header doesn't match a common type (first bytes: " + d[:8].hex(" ") + "). Compare with a known file in a hex editor.")
PY
REP=$(ls "$OUT"/repaired_header.* 2>/dev/null | head -1)
if [ -n "$REP" ]; then WORK="$REP"; EXT=$(mime "$WORK"); good "Carrying on with the repaired file ($EXT)"; LOOK+=("$REP  (repaired header, open it)"); fi
case "$FILE" in *.*) e="${FILE##*.}"; e="${e,,}"
  case "$EXT:$e" in image/jpeg:jp*g|image/png:png|image/gif:gif|image/bmp:bmp|image/x-ms-bmp:bmp|audio/*:*|text/*:*|*:"") ;;
    *) note "Extension .$e doesn't match the real type ($EXT). It may be disguised." ;; esac ;; esac

# ---------- 2. PNG structure (CRC, real height, text chunks) ----------
if [ "$EXT" = "image/png" ]; then
  say "2. PNG structure (chunk CRCs, real width/height, text chunks)"
  have pngcheck && pngcheck -v "$WORK" 2>&1 | tail -3 | sed 's/^/    pngcheck: /'
  python3 -I - "$WORK" "$OUT" >> "$OUT/png_report.txt" <<'PY'
import sys, struct, zlib
path, out = sys.argv[1], sys.argv[2]
d = bytearray(open(path, "rb").read()); i = 8; fixed = False
while i + 8 <= len(d):
    L = struct.unpack(">I", d[i:i+4])[0]; t = bytes(d[i+4:i+8]); body = bytes(d[i+8:i+8+L])
    crc = struct.unpack(">I", d[i+8+L:i+12+L])[0] if i + 12 + L <= len(d) else None
    real = zlib.crc32(t + body) & 0xffffffff
    if t in (b"tEXt", b"zTXt", b"iTXt"):
        txt = zlib.decompress(body.split(b"\x00", 2)[-1][1:]) if t == b"zTXt" else body
        print("TEXT", t.decode(), txt.replace(b"\x00", b" = ").decode("latin-1")[:300])
    if t not in (b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tEXt", b"zTXt", b"iTXt", b"pHYs", b"gAMA", b"cHRM",
                 b"sRGB", b"iCCP", b"bKGD", b"tIME", b"tRNS", b"sBIT", b"hIST", b"sPLT", b"eXIf"):
        print("ODD chunk", t, L, "bytes:", body[:60])
    if crc is not None and crc != real:
        print(f"CRCBAD {t.decode('latin-1')} at {i} (stored {crc:08x}, real {real:08x})")
        if t == b"IHDR":
            w, h = struct.unpack(">II", body[:8])
            for W in [w] + list(range(1, 4097)):
                hit = None
                for H in range(1, 4097):
                    if zlib.crc32(t + struct.pack(">II", W, H) + body[8:]) & 0xffffffff == crc:
                        hit = H; break
                if hit:
                    d[i+8:i+16] = struct.pack(">II", W, hit); fixed = True
                    print(f"SIZEFIX stored {w}x{h}, real {W}x{hit}"); break
    if t == b"IEND": break
    i += 12 + L
if fixed: open(f"{out}/fixed_size.png", "wb").write(d)
PY
  while IFS= read -r l; do
    case "$l" in
      TEXT*)   note "text chunk: ${l#TEXT }"; echo "${l#* * }" >> "$CANDS" ;;
      ODD*)    note "unusual chunk: ${l#ODD chunk }" ;;
      CRCBAD*) bad "CRC mismatch: ${l#CRCBAD }" ;;
      SIZEFIX*) good "Image size was tampered with: ${l#SIZEFIX }. Fixed copy: $OUT/fixed_size.png  <- OPEN IT"; LOOK+=("$OUT/fixed_size.png  (real height restored)") ;;
    esac
  done < "$OUT/png_report.txt"
  [ -s "$OUT/png_report.txt" ] || note "chunks and CRCs look normal"
fi

# ---------- 3. metadata ----------
say "3. Metadata (exiftool)"
if have exiftool; then
  exiftool "$WORK" | grep -viE '^(ExifTool Version|Directory|File (Name|Size|Permissions|Access|Inode|Modification)|MIME Type|File Type)' | sed 's/^/    /'
  exiftool -s3 -Comment -UserComment -ImageDescription -XPComment -XPKeywords -XPSubject -XPTitle -Artist \
           -Copyright -Title -Subject -Keywords -Description -Author -Creator -Software -Make -Model \
           -GPSLatitude -GPSLongitude -Warning "$WORK" 2>/dev/null >> "$CANDS"
  exiftool "$WORK" | record_flags
else
  bad "exiftool missing: sudo apt install libimage-exiftool-perl"
fi
python3 -I - "$WORK" >> "$CANDS" <<'PY'
import sys
d = open(sys.argv[1], "rb").read()
if d[:2] == b"\xff\xd8":                      # JPEG comments, even without exiftool
    i = 2
    while i < len(d) - 4 and d[i] == 0xFF:
        m, L = d[i+1], int.from_bytes(d[i+2:i+4], "big")
        if m == 0xFE: print(d[i+4:i+2+L].decode("latin-1").strip())
        if m == 0xDA: break
        i += 2 + L
PY

# ---------- 4. readable strings ----------
say "4. Readable strings"
strings -n 6 "$WORK" > "$OUT/strings.txt"
note "$(wc -l < "$OUT/strings.txt") strings saved to $OUT/strings.txt"
record_flags < "$OUT/strings.txt"
grep -iE 'flag|pass|key|secret|hidden|sit\{|ctf' "$OUT/strings.txt" | head -15 | sed 's/^/    interesting: /'
grep -oE '[A-Za-z0-9+/=_-]{12,}' "$OUT/strings.txt" | head -200 >> "$CANDS"
grep -E '^[ .\-/]{8,}$|^([01]{8} ?){4,}$|^([0-9]{2,3}[ ,]){4,}' "$OUT/strings.txt" | head -20 >> "$CANDS"

# ---------- 5. data after the end of the image ----------
say "5. Data appended after the file ends"
python3 -I - "$WORK" "$OUT/appended.bin" <<'PY'
import sys
d = open(sys.argv[1], "rb").read(); end = None
if d[:2] == b"\xff\xd8": end = d.rfind(b"\xff\xd9") + 2
elif d[:8] == b"\x89PNG\r\n\x1a\n":
    j = d.find(b"IEND"); end = j + 8 if j >= 0 else None
elif d[:3] == b"GIF": end = d.rfind(b"\x3b") + 1
if end and end < len(d):
    open(sys.argv[2], "wb").write(d[end:])
    print(f"    {len(d)-end} extra bytes after the image, saved to {sys.argv[2]}")
    print("    first bytes:", d[end:end+64])
else:
    print("    none")
for sig, name in [(b"PK\x03\x04","zip"),(b"Rar!\x1a\x07","rar"),(b"7z\xbc\xaf\x27\x1c","7z"),(b"%PDF-","pdf"),
                  (b"\x89PNG\r\n","png"),(b"\xff\xd8\xff\xe0","jpeg"),(b"\x1f\x8b\x08\x00","gzip"),(b"BZh91AY","bzip2")]:
    j = d.find(sig, 4)
    if j > 0: print(f"    {name} signature inside the file at offset {j} (can be a false alarm; binwalk confirms)")
PY
if [ -s "$OUT/appended.bin" ]; then
  file "$OUT/appended.bin" | sed "s|^$OUT/||; s/^/    /"
  strings -n 4 "$OUT/appended.bin" | head -10 | sed 's/^/    text: /'
  strings -n 4 "$OUT/appended.bin" | record_flags
  strings -n 8 "$OUT/appended.bin" >> "$CANDS"
fi

# ---------- 6. embedded files ----------
say "6. Embedded files (binwalk / foremost)"
if have binwalk; then
  binwalk "$WORK" | sed '1,3d; s/^/    /'
  binwalk -e -q -C "$OUT/binwalk" "$WORK" >/dev/null 2>&1 || binwalk -e -q --run-as=root -C "$OUT/binwalk" "$WORK" >/dev/null 2>&1
else bad "binwalk missing: sudo apt install binwalk"; fi
have foremost && foremost -Q -i "$WORK" -o "$OUT/foremost" >/dev/null 2>&1
for d in "$OUT/binwalk" "$OUT/foremost"; do
  [ -d "$d" ] && find "$d" -type f ! -name audit.txt | sed "s|^|    extracted: |"
done

# ---------- 7. GIF frames ----------
if [ "$EXT" = "image/gif" ]; then
  say "7. GIF frames"
  if (( HAVE_PIL )); then
    python3 -I - "$WORK" "$OUT/gif_frames" <<'PY'
import sys, os
from PIL import Image
im = Image.open(sys.argv[1]); os.makedirs(sys.argv[2], exist_ok=True); n = 0; durs = []
try:
    while True:
        im.convert("RGBA").save(f"{sys.argv[2]}/frame_{n:03d}.png"); durs.append(im.info.get("duration", 0)); n += 1; im.seek(n)
except EOFError: pass
print(f"    {n} frames saved to {sys.argv[2]}/")
odd = [i for i, d in enumerate(durs) if durs and d != max(set(durs), key=durs.count)]
if odd: print(f"    frames with an unusual delay (often where the flag flashes): {odd}")
if im.info.get("comment"): print("    GIF comment:", im.info["comment"][:200])
PY
    LOOK+=("$OUT/gif_frames/  (step through the frames)")
  else bad "Pillow missing for GIF frames: sudo apt install python3-pil"; fi
fi

# ---------- 8. decode anything suspicious ----------
say "8. Decoding suspicious strings (base64, base32, hex, binary, rot13, ...)"
sort -u "$CANDS" | grep -v '^$' > "$CANDS.u"; mv "$CANDS.u" "$CANDS"
DEC=$(mapfile -t A < "$CANDS"; [ ${#A[@]} -gt 0 ] && decode "${A[@]}")
if [ -n "$DEC" ]; then
  echo "$DEC" | sed 's/^/    /'
  echo "$DEC" | sed -n 's/^FLAG .* => //p' >> "$FOUND"
else note "nothing decoded to readable text"; fi
mapfile -t DECODED < <(echo "$DEC" | sed -n 's/^DECODED .* => //p')

# passphrases to try everywhere: empty, yours, every candidate, every decoded result
TRY=("" "${PASSES[@]}")
while IFS= read -r l; do TRY+=("$l"); done < "$CANDS"
TRY+=("${DECODED[@]}")
mapfile -t TRY < <(printf '%s\n' "${TRY[@]}" | awk '!seen[$0]++')
note "${#TRY[@]} passphrase guesses collected for the next steps"

WL="$WORDLIST"
[ -z "$WL" ] && [ -f /usr/share/wordlists/rockyou.txt ] && WL=/usr/share/wordlists/rockyou.txt

# ---------- 9. steghide ----------
STEGOUT="$OUT/steghide"; mkdir -p "$STEGOUT"
case "$EXT" in image/jpeg|image/bmp|image/x-ms-bmp|audio/x-wav|audio/wav|audio/vnd.wave|audio/basic|audio/x-au)
  say "9. steghide"
  if have steghide; then
    GOT=""; ok=0
    for pw in "${TRY[@]}"; do
      if steghide extract -sf "$WORK" -p "$pw" -xf "$STEGOUT/extracted.bin" -f -q 2>/dev/null; then GOT="$pw"; ok=1; break; fi
    done
    if (( ok )); then
      good "steghide extracted data with passphrase: '${GOT}'"
      file "$STEGOUT/extracted.bin" | sed "s|^$OUT/||; s/^/    /"
      head -c 600 "$STEGOUT/extracted.bin" | sed 's/^/    | /'; echo
      record_flags < "$STEGOUT/extracted.bin"
      mapfile -t B < <(strings -n 6 "$STEGOUT/extracted.bin" | head -50)
      [ ${#B[@]} -gt 0 ] && decode_into_found "${B[@]}"
    else
      note "no passphrase worked out of ${#TRY[@]} tried"
    fi
  else bad "steghide missing: sudo apt install steghide"; fi ;;
esac

# ---------- 10. outguess ----------
if [ "$EXT" = "image/jpeg" ]; then
  say "10. outguess"
  if have outguess; then
    hit=0
    for pw in "${TRY[@]}"; do
      if [ -z "$pw" ]; then outguess -r "$WORK" "$OUT/outguess.out" >/dev/null 2>&1
      else outguess -k "$pw" -r "$WORK" "$OUT/outguess.out" >/dev/null 2>&1; fi
      [ -s "$OUT/outguess.out" ] || continue
      # outguess always writes something; keep it only if it's readable or a real file type
      t=$(file -b "$OUT/outguess.out")
      if grep -aqE "$REGEX" "$OUT/outguess.out" || { [[ "$t" != data* ]] && [[ "$t" != *"non-ISO"* ]]; }; then
        good "outguess found data with key '${pw}': $t"
        head -c 400 "$OUT/outguess.out" | sed 's/^/    | /'; echo
        record_flags < "$OUT/outguess.out"; hit=1; break
      fi
    done
    (( hit )) || { note "nothing readable"; rm -f "$OUT/outguess.out"; }
  else note "outguess not installed (sudo apt install outguess), skipped"; fi
fi

# ---------- 11. stegseek brute force ----------
if [ ! -s "$STEGOUT/extracted.bin" ] && have stegseek && (( ! QUICK )); then
  case "$EXT" in image/jpeg|image/bmp|image/x-ms-bmp|audio/x-wav|audio/wav|audio/vnd.wave|audio/basic|audio/x-au)
    say "11. stegseek brute force"
    if [ -n "$WL" ] && [ -f "$WL" ]; then
      stegseek "$WORK" "$WL" "$STEGOUT/stegseek.out" 2>&1 | grep -E 'Found|passphrase|error|Could' | sed 's/^/    /'
      [ -s "$STEGOUT/stegseek.out" ] && { head -c 600 "$STEGOUT/stegseek.out" | sed 's/^/    | /'; echo; record_flags < "$STEGOUT/stegseek.out"; }
    else
      note "no wordlist. Unzip rockyou once: sudo gunzip /usr/share/wordlists/rockyou.txt.gz"
    fi ;;
  esac
fi

# ---------- 12. hidden bits in pixels (zsteg + built-in check) ----------
case "$EXT" in image/png|image/bmp|image/x-ms-bmp)
  say "12. Hidden bits in pixels (LSB)"
  if have zsteg; then
    if (( QUICK )); then zsteg "$WORK" 2>/dev/null > "$OUT/zsteg.txt"; else zsteg -a "$WORK" 2>/dev/null > "$OUT/zsteg.txt"; fi
    grep -E 'text:|file:' "$OUT/zsteg.txt" | grep -vE 'file: (data|Matlab|DOS|PGP|OpenPGP|Apple|Atari|GLS_BINARY)' | head -25 | sed 's/^/    zsteg: /'
    record_flags < "$OUT/zsteg.txt"
  else note "zsteg not installed (sudo apt install zsteg), using the built-in check only"; fi
  if (( HAVE_PIL )); then
    python3 -I - "$WORK" "$REGEX" <<'PY'
import sys, re
from PIL import Image
im = Image.open(sys.argv[1]); rx = re.compile(sys.argv[2].encode())
im = im.convert("RGBA") if "A" in im.getbands() else im.convert("RGB")
px = list(im.getdata())[:60000]; bands = im.getbands()
def read(chans, bit, msb=True):
    bits = [(p[c] >> bit) & 1 for p in px for c in chans]
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        v = 0
        for b in (bits[i:i+8] if msb else bits[i:i+8][::-1]): v = (v << 1) | b
        out.append(v)
    return bytes(out)
tries = [("".join(bands[c] for c in ch), ch) for ch in ([0,1,2], [0], [1], [2]) + (([3],) if len(bands) == 4 else ())]
for name, ch in tries:
    for bit in (0, 1):
        for msb in (True, False):
            data = read(ch, bit, msb)
            m = rx.search(data)
            head = data[:60]
            printable = sum(32 <= c < 127 for c in head) / max(1, len(head))
            if m or printable > 0.9:
                tag = f"b{bit+1},{name.lower()},{'msb' if msb else 'lsb'}-first"
                if m: print(f"    FLAG via {tag}: {m.group().decode('latin-1')}")
                else: print(f"    readable text via {tag}: {head.decode('latin-1')!r}")
PY
  fi | tee "$OUT/lsb_builtin.txt" | sed 's/^    FLAG via/    FLAG (pixel bits)/'
  grep -oE "$REGEX" "$OUT/lsb_builtin.txt" >> "$FOUND" 2>/dev/null ;;
esac

# ---------- 13. colour planes and QR codes ----------
case "$EXT" in image/*)
  say "13. Colour/bit planes and QR codes"
  if (( HAVE_PIL )); then
    python3 -I - "$WORK" "$OUT/planes" <<'PY'
import sys, os
from PIL import Image
im = Image.open(sys.argv[1]); os.makedirs(sys.argv[2], exist_ok=True)
try: im.seek(0)
except Exception: pass
im = im.convert("RGBA") if "A" in im.getbands() else im.convert("RGB")
n = 0
for ci, c in enumerate(im.getbands()):
    ch = im.getchannel(ci)
    for bit in (0, 1, 2, 7):
        ch.point(lambda v, b=bit: 255 if (v >> b) & 1 else 0).convert("1").save(f"{sys.argv[2]}/{c}_bit{bit}.png"); n += 1
    ch.save(f"{sys.argv[2]}/{c}_channel.png"); n += 1
print(f"    {n} plane images saved to {sys.argv[2]}/ (look for text or a QR code in the bit0 ones)")
PY
    LOOK+=("$OUT/planes/  (flip through the bit planes, especially *_bit0.png)")
  else bad "Pillow missing for bit planes: sudo apt install python3-pil"; fi
  if have zbarimg; then
    for img in "$WORK" "$OUT"/fixed_size.png "$OUT"/planes/*.png "$OUT"/gif_frames/*.png; do
      [ -f "$img" ] || continue
      z=$(zbarimg -q --raw "$img" 2>/dev/null)
      [ -n "$z" ] && { good "QR/barcode in $(basename "$img"): $z"; echo "$z" | record_flags; decode_into_found "$z"; }
    done
  else note "zbarimg not installed (sudo apt install zbar-tools), QR check skipped"; fi ;;
esac

# ---------- 14. audio ----------
case "$EXT" in audio/*|video/*)
  say "14. Audio"
  if have sox; then
    sox "$WORK" -n spectrogram -o "$OUT/spectrogram.png" 2>/dev/null && { note "spectrogram saved: $OUT/spectrogram.png (text can be drawn into the sound)"; LOOK+=("$OUT/spectrogram.png  (look for text)"); }
    have zbarimg && [ -f "$OUT/spectrogram.png" ] && zbarimg -q --raw "$OUT/spectrogram.png" 2>/dev/null | sed 's/^/    QR in spectrogram: /'
  else note "sox not installed (sudo apt install sox). Open the file in Audacity, View > Spectrogram"; fi
  note "also try: steghide (already done for WAV), and listen for Morse or DTMF tones" ;;
esac

# ---------- 15. text files ----------
case "$EXT" in text/*)
  say "15. Text file tricks (whitespace, zero-width characters)"
  python3 -I - "$WORK" "$REGEX" > "$OUT/text_tricks.txt" <<'PY'
import sys, re
t = open(sys.argv[1], encoding="utf-8", errors="replace").read(); rx = re.compile(sys.argv[2])
zw = [c for c in t if c in "​‌‍⁠﻿"]
if zw:
    print(f"    {len(zw)} zero-width characters found")
    kinds = sorted(set(zw))
    if len(kinds) >= 2:
        for zero, one in [(kinds[0], kinds[1]), (kinds[1], kinds[0])]:
            bits = "".join("0" if c == zero else "1" for c in zw if c in (zero, one))
            s = "".join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits) - 7, 8))
            if s.isprintable(): print(f"    decoded ({ord(zero):04x}=0, {ord(one):04x}=1): {s[:200]}")
trail = [l for l in t.splitlines() if l != l.rstrip(" \t")]
if trail: print(f"    {len(trail)} lines with trailing spaces/tabs (whitespace stego: try stegsnow)")
PY
  cat "$OUT/text_tricks.txt"; record_flags < "$OUT/text_tricks.txt" >/dev/null
  if have stegsnow; then
    for pw in "${TRY[@]}"; do
      if [ -z "$pw" ]; then r=$(stegsnow -C "$WORK" 2>/dev/null); else r=$(stegsnow -C -p "$pw" "$WORK" 2>/dev/null); fi
      if [ -n "$r" ] && [[ "$r" =~ ^[[:print:][:space:]]+$ ]]; then good "stegsnow (pass '${pw}'): $r"; echo "$r" | record_flags; break; fi
    done
  else note "stegsnow not installed (sudo apt install stegsnow)"; fi ;;
esac

# ---------- 16. archives found along the way ----------
say "16. Archives found inside (zip / 7z / rar)"
narch=0
while IFS= read -r a; do
  t=$(file -b "$a"); narch=$((narch+1))
  dest="$OUT/unpacked_$narch"; mkdir -p "$dest"
  note "$(echo "$a" | sed "s|^$OUT/||"): $t"
  opened=0
  if [[ "$t" == Zip* ]] && have unzip; then
    for pw in "${TRY[@]}"; do
      if unzip -o -P "$pw" -d "$dest" "$a" >/dev/null 2>&1 && [ -n "$(ls -A "$dest")" ]; then
        good "unzipped with password '${pw}'"; opened=1; break; fi
    done
    if (( ! opened && ! QUICK )) && [ -n "$WL" ] && [ -f "$WL" ] && have fcrackzip; then
      note "cracking the zip password with $(basename "$WL") (max ${ZIP_TIME}s)"
      pw=$(timeout "$ZIP_TIME" fcrackzip -u -D -p "$WL" "$a" 2>/dev/null | sed -n 's/.*pw == //p' | head -1)
      [ -n "$pw" ] && unzip -o -P "$pw" -d "$dest" "$a" >/dev/null 2>&1 && { good "zip password cracked: '$pw'"; opened=1; }
    fi
  fi
  if (( ! opened )) && have 7z; then
    for pw in "${TRY[@]}"; do
      if 7z x -y -p"$pw" -o"$dest" "$a" >/dev/null 2>&1 && [ -n "$(ls -A "$dest")" ]; then good "opened with 7z (password '${pw}')"; opened=1; break; fi
    done
  fi
  if (( opened )); then
    find "$dest" -type f | sed "s|^|    unpacked: |"
    find "$dest" -type f -size -2M -exec cat {} + 2>/dev/null | record_flags
  else
    bad "couldn't open it. Locked? Try: zip2john file.zip > h && john h --wordlist=rockyou.txt"
  fi
done < <(find "$OUT" -type f ! -path "*/planes/*" ! -path "*/gif_frames/*" ! -path "*/unpacked_*" -size -50M \
          -exec sh -c 'file -b "$1" | grep -qiE "^(Zip|7-zip|RAR)" && echo "$1"' _ {} \; 2>/dev/null)
(( narch == 0 )) && note "none"

# ---------- 17. final sweep ----------
say "17. Final sweep of everything extracted"
mapfile -t EX < <(find "$OUT" -type f -size -2M ! -name 'flags.txt' ! -name 'candidates.txt' ! -name 'strings.txt' \
                   ! -path "*/planes/*" ! -path "*/gif_frames/*" ! -name 'input_*' ! -name '*.png' 2>/dev/null \
                   -exec sh -c 'file -b "$1" | grep -qiE "text|ascii|utf-8|json|xml|csv" && echo "$1"' _ {} \;)
if [ ${#EX[@]} -gt 0 ]; then
  mapfile -t S < <(cat "${EX[@]}" 2>/dev/null | grep -oE '[[:print:]]{6,}' | sort -u | head -200)
  [ ${#S[@]} -gt 0 ] && decode_into_found "${S[@]}" >/dev/null
fi
grep -raoE "$REGEX" "$OUT" --exclude=flags.txt --exclude-dir=planes 2>/dev/null | sed 's/^[^:]*://' >> "$FOUND"
sort -u "$FOUND" -o "$FOUND"

say "Summary"
if [ -s "$FOUND" ]; then
  good "Flag candidate(s):"; sed 's/^/    /' "$FOUND"
else
  bad "No flag matched $REGEX."
  note "Read the DECODED lines above, open extracted files by hand, and see stego.pdf for the manual checklist."
fi
if [ ${#LOOK[@]} -gt 0 ]; then
  say "Check these with your own eyes (the script can't read text in pictures)"
  printf '    %s\n' "${LOOK[@]}"
fi
