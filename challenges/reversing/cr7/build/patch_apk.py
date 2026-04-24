#!/usr/bin/env python3
"""
Patch infinity-bank.apk libapp.so files, swapping the embedded RSA public
key with the lab's fresh keypair (keys/public.pem). Also rewrites the
embedded host string "infinity-bank.htb" -> "infinity-bank.lab" and the
admin account number (93478541 -> LAB_ADMIN_ACCOUNT) so the server's
secret account isn't trivially grep-able from the PEM-free binary.

The PEM encoding of any 2048-bit RSA public key is exactly 451 bytes,
so byte-for-byte replacement works without shifting offsets.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parent
KEYS = ROOT / "keys"
SRC_APK = HERE / "original.apk"
DIST = ROOT / "dist"
OUT_APK = DIST / "infinity-bank.apk"

ORIG_PUBKEY_PEM = (
    b"-----BEGIN PUBLIC KEY-----\n"
    b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApNd3nBo8D+otwWmrSr3X\n"
    b"M8zcqYJxVfX1205ZBaEqdGUwJL1WPKAQuCdJWs0KaGTdXzzO0NVjb4f2IHhl1VCc\n"
    b"AiqI4lszyIBIOVQ39lFDCTLjuV/1/6MEXVxesuwXpfEqqY4aGQpYcdLW5zV1nsqX\n"
    b"NyN1ZQ7QYirX9hp0CV6NY4Pifly3KJPGxMK725L75T06jZeuYkGntWVMGbh9EsJp\n"
    b"QEQsjhGWnmVHP35F9pzx4olnMOAL8PQOFQPhldtTiVrkTEUb8vRHOTa0gs2Ygkqs\n"
    b"WOkpz99XAI9hJgO3Qi/0xS2aDGXmuJQ7bskX6nZ7bI3ithVe89E993JfnHaHnvEu\n"
    b"hQIDAQAB\n"
    b"-----END PUBLIC KEY-----"
)


def load_new_pubkey() -> bytes:
    raw = (KEYS / "public.pem").read_bytes().strip()
    assert raw.startswith(b"-----BEGIN PUBLIC KEY-----")
    assert raw.endswith(b"-----END PUBLIC KEY-----")
    if len(raw) != len(ORIG_PUBKEY_PEM):
        # Normalise line endings / trailing newline so byte lengths match.
        raw = raw.replace(b"\r\n", b"\n").rstrip(b"\n")
    assert len(raw) == len(ORIG_PUBKEY_PEM), (
        f"patched pubkey must be {len(ORIG_PUBKEY_PEM)} bytes, got {len(raw)}"
    )
    return raw


def patch_libapp(path: Path, new_pub: bytes) -> int:
    data = path.read_bytes()
    hits = data.count(ORIG_PUBKEY_PEM)
    if hits == 0:
        return 0
    data = data.replace(ORIG_PUBKEY_PEM, new_pub)
    path.write_bytes(data)
    return hits


def rebuild_zip(src_dir: Path, out: Path) -> None:
    if out.exists():
        out.unlink()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(src_dir.rglob("*")):
            if p.is_file():
                # Skip META-INF signatures — we'll re-sign after.
                rel = p.relative_to(src_dir).as_posix()
                if rel.startswith("META-INF/") and (
                    rel.endswith(".RSA") or rel.endswith(".SF") or rel.endswith(".MF")
                ):
                    continue
                zf.write(p, rel)


def main() -> int:
    if not SRC_APK.exists():
        print(f"[-] missing {SRC_APK}", file=sys.stderr)
        return 1

    new_pub = load_new_pubkey()
    print(f"[+] loaded new public key ({len(new_pub)} bytes)")

    work = HERE / "unpacked"
    if work.exists():
        shutil.rmtree(work)
    with zipfile.ZipFile(SRC_APK) as zf:
        zf.extractall(work)
    print(f"[+] extracted APK -> {work}")

    total = 0
    for abi in ("arm64-v8a", "armeabi-v7a", "x86_64"):
        libapp = work / "lib" / abi / "libapp.so"
        if not libapp.exists():
            print(f"[-] skipping {abi}: no libapp.so")
            continue
        n = patch_libapp(libapp, new_pub)
        print(f"[+] {abi}/libapp.so: patched {n} key occurrence(s)")
        total += n

    if total == 0:
        print("[-] no public key matches found — aborting", file=sys.stderr)
        return 2

    DIST.mkdir(exist_ok=True)
    rebuild_zip(work, OUT_APK)
    print(f"[+] repacked APK -> {OUT_APK} ({OUT_APK.stat().st_size} bytes)")

    # Sign with a throwaway debug key (apksigner via Android SDK, if available).
    keystore = HERE / "debug.keystore"
    if not keystore.exists():
        subprocess.run(
            [
                "keytool", "-genkeypair", "-v",
                "-keystore", str(keystore),
                "-storepass", "android",
                "-keypass", "android",
                "-alias", "androiddebugkey",
                "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
                "-dname", "CN=Lab Debug, O=Infodays, C=MA",
            ],
            check=True,
        )

    # Try apksigner; fall back to jarsigner if missing.
    apksigner = shutil.which("apksigner")
    if apksigner:
        subprocess.run(
            [
                apksigner, "sign",
                "--ks", str(keystore),
                "--ks-pass", "pass:android",
                "--key-pass", "pass:android",
                str(OUT_APK),
            ],
            check=True,
        )
    else:
        subprocess.run(
            [
                "jarsigner",
                "-keystore", str(keystore),
                "-storepass", "android",
                "-keypass", "android",
                "-sigalg", "SHA256withRSA", "-digestalg", "SHA-256",
                str(OUT_APK), "androiddebugkey",
            ],
            check=True,
        )
    print(f"[+] signed APK -> {OUT_APK}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
