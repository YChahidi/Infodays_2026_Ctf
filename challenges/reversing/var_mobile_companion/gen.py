#!/usr/bin/env python3
"""
var_mobile_companion — build-time generator.

Produces all five flags and the derived data that gets baked into
the APK: raw asset bytes, Java source files with hardcoded
constants, and the final flag.txt for the author.

Five flags (ez -> insane):

  1  strings_dump            plain text in assets/welcome.txt
  2  static_constants        hardcoded String fragments in DebugHelper
  3  xor_decode              XOR-encoded byte[] in XorVault
  4  aes_composed_key        AES/CBC with key = SHA256(pkg || ver || salt)
  5  custom_vm               VM bytecode interpreter in VMInterpreter
                             (opcodes + reg file drive flag reconstruction)

Usage:
    python3 gen.py                  # random hex suffix
    python3 gen.py --hex a7f2c409   # deterministic
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import secrets
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "src"
JAVA_PKG = SRC / "java" / "com" / "infodays" / "referee"
ASSETS = SRC / "assets"
RES_VALUES = SRC / "res" / "values"
RES_RAW = SRC / "res" / "raw"

PKG = "com.infodays.referee.companion"
VER_NAME = "1.0.0"
VER_CODE = 10000
AES_SALT = "infodays2026_var_referee_salt"


# ---------------------------------------------------------------- util

def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding

    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


def java_byte_array(name: str, data: bytes) -> str:
    """Render a byte[] initializer with signed-byte casts."""
    parts = []
    for b in data:
        v = b if b < 128 else b - 256
        parts.append(f"(byte){v}")
    return f"    static final byte[] {name} = new byte[] {{ {', '.join(parts)} }};"


def java_int_array(name: str, data: list[int]) -> str:
    return f"    static final int[] {name} = new int[] {{ {', '.join(str(x) for x in data)} }};"


# ------------------------------------------------------------- VM spec

# Tiny register-machine VM interpreted by VMInterpreter.java.
# Registers: R[0..7]. Opcodes operate on a single reg file and an
# output byte buffer. The interpreter's `run()` method pushes one
# byte per STORE and returns new String(bytes, "UTF-8").
#
# Encoding: each instruction is two ints — (op, arg). The program
# ends when op == OP_HALT.

OP_LOAD_IMM = 1   # R[arg >> 8] = arg & 0xFF
OP_XOR_IMM  = 2   # R[arg >> 8] ^= arg & 0xFF
OP_ADD_IMM  = 3   # R[arg >> 8] = (R[arg>>8] + (arg & 0xFF)) & 0xFF
OP_SUB_IMM  = 4   # R[arg >> 8] = (R[arg>>8] - (arg & 0xFF)) & 0xFF
OP_ROTL     = 5   # R[arg >> 8] = ((R[arg>>8] << (arg & 7)) | (R[arg>>8] >> (8 - (arg & 7)))) & 0xFF
OP_STORE    = 6   # out.write(R[arg])
OP_HALT     = 0


def compile_vm_program(plaintext: bytes, seed: int) -> list[int]:
    """For each byte in plaintext: load a scrambled value into R0,
    XOR with a key byte, ROTL by a small amount, SUB an offset, STORE.
    Then HALT.

    Each byte takes: LOAD_IMM, XOR_IMM, ROTL, SUB_IMM, STORE = 5 instructions.
    """
    prog: list[int] = []
    rng_state = seed & 0xFFFFFFFF

    def next_byte() -> int:
        nonlocal rng_state
        rng_state = (rng_state * 1103515245 + 12345) & 0xFFFFFFFF
        return (rng_state >> 16) & 0xFF

    for ch in plaintext:
        k = next_byte()
        rot = (next_byte() % 7) + 1  # 1..7
        off = next_byte()

        # We want: ((scrambled ^ k) ROTL rot - off) & 0xFF == ch
        # Forward: pick scrambled so that after ops we get ch.
        # Reverse: scrambled = (((ch + off) & 0xFF) ROTR rot) ^ k
        added = (ch + off) & 0xFF
        rotated = ((added >> rot) | (added << (8 - rot))) & 0xFF
        scrambled = rotated ^ k

        # R0 = scrambled
        prog += [OP_LOAD_IMM, (0 << 8) | scrambled]
        # R0 ^= k
        prog += [OP_XOR_IMM, (0 << 8) | k]
        # R0 = ROTL(R0, rot)
        prog += [OP_ROTL, (0 << 8) | rot]
        # R0 -= off
        prog += [OP_SUB_IMM, (0 << 8) | off]
        # STORE R0
        prog += [OP_STORE, 0]

    prog += [OP_HALT, 0]
    return prog


# --------------------------------------------------- file emitters

def write_debug_helper(flag2: str) -> None:
    # Split into 4 fragments, store as String constants, concat in method.
    parts = [flag2[i:i + 12] for i in range(0, len(flag2), 12)]
    while len(parts) < 4:
        parts.append("")
    a, b, c, d = parts[0], parts[1], parts[2], parts[3] if len(parts) >= 4 else ""
    if len(parts) > 4:
        d = "".join(parts[3:])

    src = f'''package com.infodays.referee;

public final class DebugHelper {{
    // Debug builds only — remove before shipping!
    public static final String FRAG_A = "{a}";
    public static final String FRAG_B = "{b}";
    public static final String FRAG_C = "{c}";
    public static final String FRAG_D = "{d}";

    public static String whisperDebugFlag() {{
        StringBuilder sb = new StringBuilder();
        sb.append(FRAG_A);
        sb.append(FRAG_B);
        sb.append(FRAG_C);
        sb.append(FRAG_D);
        return sb.toString();
    }}
}}
'''
    (JAVA_PKG / "DebugHelper.java").write_text(src)


def write_xor_vault(flag3: str) -> None:
    key = b"RefereeKit/2026!"  # 16 bytes
    enc = xor_bytes(flag3.encode(), key)

    src = f'''package com.infodays.referee;

public final class XorVault {{
    // Stored XOR-encoded with a short repeating key. At runtime
    // decodeReport() walks the buffer and returns a UTF-8 string.
{java_byte_array("ENC", enc)}
{java_byte_array("KEY", key)}

    public static String decodeReport() {{
        byte[] out = new byte[ENC.length];
        for (int i = 0; i < ENC.length; i++) {{
            out[i] = (byte) (ENC[i] ^ KEY[i % KEY.length]);
        }}
        return new String(out);
    }}
}}
'''
    (JAVA_PKG / "XorVault.java").write_text(src)


def write_aes_vault(flag4: str) -> None:
    # Key = SHA256(pkg || "|" || ver_name || "|" || salt) truncated to 16 bytes.
    key_material = f"{PKG}|{VER_NAME}|{AES_SALT}".encode()
    key = hashlib.sha256(key_material).digest()[:16]
    # IV = SHA256("iv:" || salt) first 16 bytes
    iv = hashlib.sha256(("iv:" + AES_SALT).encode()).digest()[:16]
    ct = aes_cbc_encrypt(flag4.encode(), key, iv)
    ct_b64 = base64.b64encode(ct).decode()

    src = f'''package com.infodays.referee;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

public final class AesVault {{
    // Encrypted flag payload (Base64).
    public static final String CIPHERTEXT_B64 = "{ct_b64}";

    // Hardcoded app identity — mirrors what the real AndroidManifest
    // advertises. Players can read all three from res/values/strings.xml.
    public static final String PKG = "{PKG}";
    public static final String VER = "{VER_NAME}";
    public static final String SALT = "{AES_SALT}";

    public static String unlockVault() throws Exception {{
        String keyMaterial = PKG + "|" + VER + "|" + SALT;
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] keyDigest = md.digest(keyMaterial.getBytes("UTF-8"));
        byte[] key = Arrays.copyOf(keyDigest, 16);

        MessageDigest md2 = MessageDigest.getInstance("SHA-256");
        byte[] ivDigest = md2.digest(("iv:" + SALT).getBytes("UTF-8"));
        byte[] iv = Arrays.copyOf(ivDigest, 16);

        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] pt = c.doFinal(Base64.getDecoder().decode(CIPHERTEXT_B64));
        return new String(pt, "UTF-8");
    }}
}}
'''
    (JAVA_PKG / "AesVault.java").write_text(src)


def write_vm_interpreter(flag5: str, seed: int) -> None:
    prog = compile_vm_program(flag5.encode(), seed)

    src = f'''package com.infodays.referee;

import java.io.ByteArrayOutputStream;

public final class VMInterpreter {{
    // Custom stack-less register-file VM. The `run()` method walks
    // PROG two ints at a time (opcode + argument) and accumulates
    // bytes into an output buffer via OP_STORE. The whole thing is
    // pure Java — no native code, no reflection.

    public static final int OP_HALT     = 0;
    public static final int OP_LOAD_IMM = 1;
    public static final int OP_XOR_IMM  = 2;
    public static final int OP_ADD_IMM  = 3;
    public static final int OP_SUB_IMM  = 4;
    public static final int OP_ROTL     = 5;
    public static final int OP_STORE    = 6;

{java_int_array("PROG", prog)}

    public static String run() {{
        int[] R = new int[8];
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int pc = 0;
        while (pc < PROG.length) {{
            int op = PROG[pc];
            int arg = PROG[pc + 1];
            pc += 2;
            int reg = (arg >> 8) & 0xFF;
            int imm = arg & 0xFF;
            if (op == OP_HALT) break;
            else if (op == OP_LOAD_IMM) R[reg] = imm;
            else if (op == OP_XOR_IMM)  R[reg] = R[reg] ^ imm;
            else if (op == OP_ADD_IMM)  R[reg] = (R[reg] + imm) & 0xFF;
            else if (op == OP_SUB_IMM)  R[reg] = (R[reg] - imm) & 0xFF;
            else if (op == OP_ROTL) {{
                int v = R[reg] & 0xFF;
                int s = imm & 7;
                R[reg] = ((v << s) | (v >>> (8 - s))) & 0xFF;
            }}
            else if (op == OP_STORE) out.write(R[arg & 0xFF]);
        }}
        try {{ return out.toString("UTF-8"); }} catch (Exception e) {{ return ""; }}
    }}
}}
'''
    (JAVA_PKG / "VMInterpreter.java").write_text(src)


def write_main_activity() -> None:
    # Simple non-Android main class so everything compiles with plain javac.
    src = '''package com.infodays.referee;

public final class MainActivity {
    public static void main(String[] args) throws Exception {
        System.out.println("VAR Referee Companion 1.0.0");
        System.out.println("[1] welcome: " + WelcomeLoader.load());
        System.out.println("[2] debug:   " + DebugHelper.whisperDebugFlag());
        System.out.println("[3] xor:     " + XorVault.decodeReport());
        System.out.println("[4] aes:     " + AesVault.unlockVault());
        System.out.println("[5] vm:      " + VMInterpreter.run());
    }
}
'''
    (JAVA_PKG / "MainActivity.java").write_text(src)


def write_welcome_loader() -> None:
    src = '''package com.infodays.referee;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

public final class WelcomeLoader {
    public static String load() throws Exception {
        InputStream in = WelcomeLoader.class.getResourceAsStream("/assets/welcome.txt");
        if (in == null) return "";
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        return new String(out.toByteArray(), "UTF-8").trim();
    }
}
'''
    (JAVA_PKG / "WelcomeLoader.java").write_text(src)


def write_welcome_asset(flag1: str) -> None:
    ASSETS.mkdir(parents=True, exist_ok=True)
    (ASSETS / "welcome.txt").write_text(
        "Welcome to the VAR Referee Companion.\n"
        "Tournament: Infodays 2026 CTF\n"
        "Build: 1.0.0 (debug)\n"
        f"Build token: {flag1}\n"
    )


def write_strings_xml() -> None:
    RES_VALUES.mkdir(parents=True, exist_ok=True)
    xml = f'''<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">VAR Referee Companion</string>
    <string name="pkg">{PKG}</string>
    <string name="ver_name">{VER_NAME}</string>
    <string name="aes_salt">{AES_SALT}</string>
</resources>
'''
    (RES_VALUES / "strings.xml").write_text(xml)


def write_android_manifest() -> None:
    SRC.mkdir(parents=True, exist_ok=True)
    xml = f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{PKG}"
    android:versionCode="{VER_CODE}"
    android:versionName="{VER_NAME}">

    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33" />

    <application
        android:label="@string/app_name"
        android:allowBackup="false">
        <activity android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
'''
    (SRC / "AndroidManifest.xml").write_text(xml)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hex", default=None)
    args = ap.parse_args()
    rand_hex = args.hex or secrets.token_hex(4)
    seed = int.from_bytes(hashlib.sha256(rand_hex.encode()).digest()[:4], "big")

    flag1 = f"INFODAYS{{SaamNoLimits_apk_strings_dump_{rand_hex}}}"
    flag2 = f"INFODAYS{{SaamNoLimits_apk_static_constants_{rand_hex}}}"
    flag3 = f"INFODAYS{{SaamNoLimits_apk_xor_decode_{rand_hex}}}"
    flag4 = f"INFODAYS{{SaamNoLimits_apk_aes_composed_key_{rand_hex}}}"
    flag5 = f"INFODAYS{{SaamNoLimits_apk_custom_vm_insane_{rand_hex}}}"

    JAVA_PKG.mkdir(parents=True, exist_ok=True)
    ASSETS.mkdir(parents=True, exist_ok=True)
    RES_VALUES.mkdir(parents=True, exist_ok=True)
    RES_RAW.mkdir(parents=True, exist_ok=True)

    write_welcome_asset(flag1)
    write_debug_helper(flag2)
    write_xor_vault(flag3)
    write_aes_vault(flag4)
    write_vm_interpreter(flag5, seed)
    write_welcome_loader()
    write_main_activity()
    write_strings_xml()
    write_android_manifest()

    (HERE / "flag.txt").write_text(
        f"[1 easy]        {flag1}\n"
        f"[2 medium]      {flag2}\n"
        f"[3 hard]        {flag3}\n"
        f"[4 very hard]   {flag4}\n"
        f"[5 insane]      {flag5}\n"
    )

    print(f"[gen] hex={rand_hex} seed=0x{seed:08x}")
    for i, f in enumerate([flag1, flag2, flag3, flag4, flag5], 1):
        print(f"[gen] flag {i} -> {f}")
    print(f"[gen] wrote sources under {SRC} and flag.txt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
