"""Forge a Flask session cookie given the app's SECRET_KEY.

Flask signs the session with itsdangerous' URLSafeTimedSerializer, salt
'cookie-session', HMAC-SHA1 and key_derivation='hmac'. Payloads this small
aren't zlib-compressed, so we don't bother.
"""
import base64, hashlib, hmac, json, time


def _b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=")

def _unb64(s):
    s = s.encode() if isinstance(s, str) else s
    return base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))


def sign_session(secret_key, data, salt=b"cookie-session"):
    if isinstance(secret_key, str):
        secret_key = secret_key.encode()
    payload = _b64(json.dumps(data, separators=(",", ":")).encode())
    ts = int(time.time())
    stamp = _b64(ts.to_bytes((ts.bit_length() + 7) // 8, "big"))
    value = payload + b"." + stamp
    key = hmac.new(secret_key, salt, hashlib.sha1).digest()
    sig = hmac.new(key, value, hashlib.sha1).digest()
    return (value + b"." + _b64(sig)).decode()


def verify_key(secret_key, cookie, salt=b"cookie-session"):
    """True if `secret_key` is the one that signed `cookie` (used to brute word order)."""
    if isinstance(secret_key, str):
        secret_key = secret_key.encode()
    value, _, sig = cookie.rpartition(".")
    key = hmac.new(secret_key, salt, hashlib.sha1).digest()
    want = hmac.new(key, value.encode(), hashlib.sha1).digest()
    return hmac.compare_digest(_b64(want).decode(), sig)


if __name__ == "__main__":
    print(sign_session("test", {"user_name": "me"}))
