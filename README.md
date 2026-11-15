# Diceware

👤 **Author:** [@rrieye](https://github.com/rrieye)

> *platypwnies CTF 2026 — crypto*
>
> A "password manager" that generates diceware passphrases over a single-server
> PIR protocol. Three flags, each a different way the home-made construction falls
> apart: an untrusted server, key reuse, and a secret that leaks through an error
> oracle.

- **Warmup** — `PP{ (: )}`
- **User** — `PP{ (: )}`
- **Admin** — `PP{ (: )}`

---

## The setup

Two services:

- **Wordlist server** (`:8080`) — a Rust `actix-files` server that serves the EFF
  short wordlist (`eff_short_wordlist_1.txt`, 1296 words) and answers PIR lookups.
- **Password manager** (`:8081`) — a Flask app. It never looks a word up itself;
  it sends an encrypted PIR query to the wordlist server and trusts whatever comes
  back.

A passphrase is six words. To fetch one word the app runs a **single-server PIR**
based on the **Paillier** cryptosystem (the `inspire` library): the client encrypts
a one-hot selection vector, the server homomorphically combines it with the
database, and the client decrypts the result. The database is addressed as a
`6 × 6 × 6 × 6` hypercube (four dice, `6^4 = 1296`), so a query carries four
encrypted one-hot vectors and the response is eight Paillier ciphertexts that the
client folds back down to one word.

There are two PIR clients baked in, `CLIENT_USERS` and `CLIENT_ADMIN`, each with its
own Paillier keypair. The important server bits:

```python
def generate_password(client, wordlist):
    # six words, each from a *fresh* set of random dice rolls
    return " ".join(look_up_word(client, [secrets.choice(DICE) for _ in range(4)], wordlist).decode()
                    for _ in range(6))

# at boot:
app.config["SECRET_KEY"] = generate_password(CLIENT_ADMIN, DEFAULT_WORDLIST)  # admin passphrase
# FlagUser's password    = generate_password(CLIENT_USERS, DEFAULT_WORDLIST)
```

Endpoints that matter:

| route | what it does |
|---|---|
| `/reset_password` | `generate_password(CLIENT_USERS, wordlist)` — **`wordlist` is attacker-controlled** (SSRF). Blocks `username == "FlagUser"`. |
| `/_app_key` | `generate_password(CLIENT_ADMIN, wordlist)` then `raise NotImplementedError` — result discarded |
| `/flag` | returns the admin flag iff `session["is_admin"] == True` (nothing ever sets it) |

### The leak everything hinges on

The wordlist server writes each lookup's query and response to a `tmp/` directory,
and it's configured with `show_files_listing()` **and** `use_hidden_files()`. So
`http://host:8080/tmp/` is a directory listing of every PIR query/response that has
gone through it — including the **12 lookups from boot** (`CLIENT_ADMIN` ×6 then
`CLIENT_USERS` ×6) that produced the admin `SECRET_KEY` and FlagUser's password.

Those files only live briefly: setup runs during `gunicorn --preload` (~60s, one
lookup ≈ 5s) and the platform wipes `tmp/` once the instance is handed over. The
whole game is to be polling before `:8081` comes up. `grab.py` does exactly that —
start it the instant a fresh instance's address appears and it captures all 12.

```
$ python grab.py 10.83.16.27
[*] watching http://10.83.16.27:8080/tmp/  (web-up marks the end of the setup window)
[  0.33s] got EJBPMPBb.query  queries=1
[  0.52s] got ivNijsAb.query  queries=2
...
[  2.41s] got ecjBh1Ig.query  queries=12
[  4.0s] --- :8081 is up (setup finished) ---
```

Group the 12 `.query` files by their embedded public key `n` and you get **two
keys × six queries** — the admin set and the users set.

---

## Flag 1 — warmup: *you are the server now*

`reset_password(username, wordlist=URL)` lets us name the wordlist server. The
password manager never verifies the PIR response, so if we point it at a server we
control we decide what every word decodes to.

A Paillier ciphertext only needs the **public** key to construct, and the PIR
response is just a tree of ciphertexts that the client folds down by alternating
*decrypt* and *decompose/compose*. So `build_response(n, word)` (in `pir.py`) hands
back eight leaves that decode to any `word` we like under *any* client key — we read
`n` straight out of the query.

Point `reset_password` for `Warmup User` at our server, answer every lookup with
`zzzz`, and their new password becomes `zzzz zzzz zzzz zzzz zzzz zzzz`. Log in, read
the flag.

```
python warmup.py <WEB_IP> <MY_VPN_IP>
```

---

## Flag 2 — user: *key reuse allows response reuse*

FlagUser's password came from `generate_password(CLIENT_USERS, …)` at boot. We can't
reset FlagUser directly (the username is blocked), but we captured the six
`CLIENT_USERS` responses from that run in `tmp/`.

Because `reset_password` uses the **same** `CLIENT_USERS` key, we can **replay** a
captured response: register a throwaway account, reset it while our wordlist server
echoes back one captured response, and the app decrypts it with the users key and
sets our password to the original word — which we read off our own account page.
Do that for all six responses and we have FlagUser's six words as an unordered set.

The order is the only thing missing; brute the `6! = 720` permutations against
`/login` as FlagUser until one lands, then read the user flag.

```
python grab.py <HOST>          # at boot, capture tmp/
python user.py <WEB_IP> <MY_VPN_IP>
```

```
[*] finding the users key (the one that replays to a real word)...
    key#0 -> None
    key#1 -> 'tilt'
[*] FlagUser's words (unordered): ['stung', 'blurt', 'worry', 'crowd', 'guru', 'tilt']
[*] bruteforcing word order via FlagUser login...
[+] password: tilt blurt stung worry guru crowd
[+] flag: ['PP{k3y_r3u53_41l0wS_r3sp0ns3_r3u5e::…}']
```

---

## Flag 3 — admin: recover the `SECRET_KEY`

`/flag` needs `session["is_admin"] == True` and nothing ever sets it, so we must
**forge** the Flask session cookie — which needs `SECRET_KEY`, the six-word admin
passphrase (`1296^6 ≈ 2^62`, not brute-forceable).

The admin passphrase was chosen once at boot from six random dice rolls. Those rolls
exist **only** inside `CLIENT_ADMIN`'s six setup queries (the ones we grabbed).
`/_app_key` re-runs `generate_password(CLIENT_ADMIN, …)` but with *fresh* rolls and
throws the answer away, so it can't reproduce the secret — but it gives us two
things:

1. It uses the **admin private key** to decode whatever response we feed it (via an
   attacker-controlled wordlist URL).
2. `generate_password` does `.decode()` on each word, so a decoded value that isn't
   valid UTF-8 raises `UnicodeDecodeError` *before* the `NotImplementedError`. By
   counting how many callbacks our wordlist server gets before the request dies, we
   learn **whether the decoded word was valid UTF-8** — a 1-bit oracle.

The last piece is that `Database::process` is **deterministic and public**: no fresh
randomness, just homomorphic exponentiations and compositions. So for a captured
admin query (which fixes one secret index `idx_j`) we can recompute
`process(query, DB')` over **any database we choose**, using only the public key.
The result decodes (inside `/_app_key`, with the admin key) to `DB'[idx_j]`.

Put it together — binary search each secret index:

- For bit `b`, build `DB'` with an invalid-UTF-8 byte at every index whose bit `b`
  is 1, and a valid ASCII word everywhere else.
- `process(query_j, DB')` → feed to `/_app_key` → oracle says *valid* iff bit `b`
  of `idx_j` is 0.
- 11 bits pin `idx_j ∈ [0, 1296)`; then `word_j = wordlist[idx_j]`.

That's `6 words × 11 bits = 66` PIR evaluations (`process` is the slow part;
`pir.py` uses `gmpy2` and `admin.py` runs them across all cores). Identifying which
captured key is the admin one is a single all-valid-DB response — the admin key
gives six callbacks, the users key fails to decrypt our response and gives one.

Order is recovered **offline**: registering any user yields a cookie signed with the
real `SECRET_KEY`, so we just test the `720` permutations against that HMAC
signature (`flasksign.verify_key`). Then forge `{"is_admin": true}` and `GET /flag`.

```
python grab.py <HOST>          # at boot, capture tmp/
python admin.py <WEB_IP> <MY_VPN_IP>
```

```
[*] 12 captured queries; gmpy2=True
    key#0 2048 bits, 6 words
    key#1 2048 bits, 6 words
[*] identifying the admin key (one all-valid response per key)...
[+] admin key: 2048 bits, 6 words
[*] computing 66 PIR responses on 8 cores (slow part)...
[*] done in 71s; running oracle...
[+] word0: index 851 -> 'otter'
[+] word1: index 97  -> 'bagged'
...
[+] SECRET_KEY = 'otter bagged … … … …'
[+] flag: ['PP{…admin…::…}']
```

---

## Why the construction fails

- **The PIR response is unauthenticated.** With only the public key an attacker can
  forge a response that decodes to anything (warmup) — a confidentiality primitive
  (PIR) was used where an integrity primitive (a MAC) was needed.
- **The same key is reused across trust boundaries.** `CLIENT_USERS` signs FlagUser's
  secret *and* serves attacker-triggered resets, so captured ciphertexts replay
  (user). The fix is a fresh key per purpose and never decoding attacker-supplied
  responses on a secret key.
- **A deterministic PIR + an error side-channel = a decryption oracle.** `/_app_key`
  turns the admin key into a UTF-8 validity oracle, and deterministic `process`
  lets us aim it at arbitrary databases to read the secret index out bit by bit
  (admin).
- **And the whole thing is only reachable because `tmp/` is a public directory
  listing** that keeps the boot-time PIR traffic around.

---

## Files

| file | role |
|---|---|
| `pir.py` | Paillier + postcard/num-bigint serialization + `inspire` PIR (`process`, `build_response`, `build_query`, query parsing) |
| `flasksign.py` | Flask/itsdangerous session cookie signer + key check |
| `grab.py` | boot-time `tmp/` scraper — run it the instant a fresh instance appears |
| `warmup.py` | flag 1 — untrusted PIR server |
| `user.py` | flag 2 — replay captured `CLIENT_USERS` responses, brute word order |
| `admin.py` | flag 3 — `process` + `/_app_key` UTF-8 oracle → `SECRET_KEY` → forged cookie |

`pir.py` has a self-test (`python pir.py`). `admin.py`/`user.py` expect a
`grab_dump/` populated by `grab.py` from the **current** instance's boot.
