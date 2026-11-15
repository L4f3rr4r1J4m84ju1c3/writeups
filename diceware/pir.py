"""
Paillier + the `inspire` single-server PIR, reimplemented in Python.

The challenge serialises everything with postcard, and num-bigint 0.5.1 encodes a
BigUint as a Vec<u32> of little-endian limbs where every u32 is a LEB128 varint.
That's all we need to parse queries, rebuild responses, and run the server-side
`Database::process` ourselves.

gmpy2 is used if present; otherwise pure Python.
"""
import random

try:
    from gmpy2 import mpz, powmod as _powmod
    HAVE_GMP = True
    def _pow(b, e, m): return _powmod(b, e, m)
except Exception:
    HAVE_GMP = False
    mpz = int
    def _pow(b, e, m): return pow(b, e, m)


# --- postcard varints --------------------------------------------------------
def put_uvarint(v):
    v = int(v)
    out = bytearray()
    while True:
        b = v & 0x7f
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)

def get_uvarint(b, i):
    shift = val = 0
    while True:
        c = b[i]; i += 1
        val |= (c & 0x7f) << shift
        if not c & 0x80:
            return val, i
        shift += 7


# --- BigUint <-> bytes -------------------------------------------------------
def biguint_to_bytes(x):
    x = int(x)
    if x == 0:
        return put_uvarint(0)
    limbs = []
    while x:
        limbs.append(x & 0xffffffff)
        x >>= 32
    out = bytearray(put_uvarint(len(limbs)))
    for d in limbs:
        out += put_uvarint(d)
    return bytes(out)

def biguint_from_bytes(b, i):
    cnt, i = get_uvarint(b, i)
    x = 0
    for k in range(cnt):
        d, i = get_uvarint(b, i)
        x |= d << (32 * k)
    return x, i


# --- Paillier (g = n+1) ------------------------------------------------------
def enc(n, m, r=None):
    n2 = n * n
    if r is None:
        r = random.randrange(1, n - 1)
    return ((1 + (m % n) * n) * pow(r, n, n2)) % n2


# --- Query { pk: BigUint, selectors: Vec<Vec<Ciphertext>> } ------------------
def parse_query_n(body):
    n, _ = biguint_from_bytes(body, 0)
    return n

def parse_query(body):
    n, i = biguint_from_bytes(body, 0)
    outer, i = get_uvarint(body, i)
    selectors = []
    for _ in range(outer):
        inner, i = get_uvarint(body, i)
        vec = []
        for _ in range(inner):
            ct, i = biguint_from_bytes(body, i)
            vec.append(ct)
        selectors.append(vec)
    return n, selectors, i

def build_query(n, coords, shape):
    # one-hot encrypted selector per coordinate
    out = bytearray(biguint_to_bytes(n))
    sels = [[enc(n, 1 if j == c else 0) for j in range(size)] for c, size in zip(coords, shape)]
    out += put_uvarint(len(sels))
    for s in sels:
        out += put_uvarint(len(s))
        for ct in s:
            out += biguint_to_bytes(ct)
    return bytes(out)


# --- Response ----------------------------------------------------------------
def serialize_response(cts):
    out = bytearray(put_uvarint(0))        # Response::Ok = enum variant 0
    out += put_uvarint(len(cts))
    for ct in cts:
        out += biguint_to_bytes(ct)
    return bytes(out)

def build_response(n, word, depth=4):
    """A malicious server response that decodes to `word` under *any* client key."""
    W = int.from_bytes(word, "little")
    cur = [enc(n, W)]
    for _ in range(depth - 1):             # expand 1 -> 2 -> 4 -> 8 leaves
        nxt = []
        for ct in cur:
            lo, hi = ct % n, ct // n
            nxt += [enc(n, lo), enc(n, hi)]
        cur = nxt
    return serialize_response(cur)


# --- Database::process (deterministic, public, no fresh randomness) ----------
def process(n, selectors, entries):
    n = mpz(n); n2 = n * n
    one_hots = [[mpz(ct) for ct in sel] for sel in selectors]
    pts = [[mpz(e)] for e in entries]
    cts = []
    for stage in range(len(one_hots) - 1, -1, -1):
        one_hot = one_hots[stage]
        r = len(one_hot)
        cts = []
        for start in range(0, len(pts), r):
            rows = pts[start:start + r]
            cols = []
            col = 0
            while True:
                acc = None
                for ct, row in zip(one_hot, rows):
                    if col < len(row):
                        t = _pow(ct, row[col], n2)
                        acc = t if acc is None else (acc * t) % n2
                if acc is None:
                    break
                cols.append(acc)
                col += 1
            cts.append(cols)
        if stage > 0:
            pts = [[v for ct in row for v in (ct % n, ct // n)] for row in cts]
    return cts[0]


def word_to_pt(word):
    return int.from_bytes(word, "little")


if __name__ == "__main__":
    # sanity check: process() against a known DB with a small Paillier key
    def prime(bits):
        def isp(x, k=16):
            if x < 2:
                return False
            for q in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
                if x % q == 0:
                    return x == q
            d = x - 1; r = 0
            while d % 2 == 0:
                d //= 2; r += 1
            for _ in range(k):
                a = random.randrange(2, x - 1)
                y = pow(a, d, x)
                if y in (1, x - 1):
                    continue
                for _ in range(r - 1):
                    y = y * y % x
                    if y == x - 1:
                        break
                else:
                    return False
            return True
        while True:
            c = random.getrandbits(bits) | (1 << (bits - 1)) | 1
            if isp(c):
                return c

    p, q = prime(512), prime(512)
    n = p * q; n2 = n * n; phi = (p - 1) * (q - 1); pinv = pow(phi, -1, n)
    shape = [6, 6, 6, 6]
    words = [f"w{i:04d}".encode() for i in range(1296)]
    entries = [word_to_pt(w) for w in words]

    def decode(cts):
        dec = lambda c: (((pow(c, phi, n2) - 1) // n) * pinv) % n
        pts = [dec(c) for c in cts]
        for _ in range(len(shape) - 1):
            pts = [dec(pts[k] + pts[k + 1] * n) for k in range(0, len(pts), 2)]
        v = pts[0]
        return v.to_bytes((v.bit_length() + 7) // 8, "little")

    ok = True
    for coords in ([0, 0, 0, 0], [1, 2, 3, 4], [5, 5, 5, 5], [3, 1, 4, 2]):
        _, sels, _ = parse_query(build_query(n, coords, shape))
        flat = 216 * coords[0] + 36 * coords[1] + 6 * coords[2] + coords[3]
        rec = decode(process(n, sels, entries))
        print(coords, "->", rec, "exp", words[flat], "OK" if rec == words[flat] else "FAIL")
        ok &= rec == words[flat]
    print("ALL OK" if ok else "FAILED")
