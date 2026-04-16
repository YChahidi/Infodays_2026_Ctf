# var_mobile_companion — Author Writeup

**Category:** Mobile / Reverse Engineering
**Artifact:** `dist/companion.apk` — a single signed Android APK
**Difficulty:** Five flags, Easy → Insane

All five flags are recoverable by **pure static analysis** of the
DEX + resources + assets. No device, no emulator, no frida, no
network. A player with `jadx-gui` and a Python REPL has
everything they need.

## Stage 0 — unpack

```bash
unzip -l companion.apk
# AndroidManifest.xml
# resources.arsc
# classes.dex
# assets/welcome.txt
# META-INF/*
```

Load into jadx:

```bash
jadx-gui companion.apk
```

You'll see five classes under `com.infodays.referee`:

- `MainActivity` — the (non-Android) entrypoint wiring all five vaults
- `WelcomeLoader` — reads `assets/welcome.txt`
- `DebugHelper` — four `String` constants plus a concatenator
- `XorVault` — two `byte[]` arrays plus a decode loop
- `AesVault` — Base64 ciphertext plus a SHA-256-keyed AES decryptor
- `VMInterpreter` — 128-element `int[]` plus a tiny register-machine

## Flag 1 — Easy (`strings_dump`)

The cheapest kind of flag. `assets/welcome.txt` is stored raw
inside the APK zip and not touched by encoding/obfuscation:

```bash
unzip -p companion.apk assets/welcome.txt
# Welcome to the VAR Referee Companion.
# Tournament: Infodays 2026 CTF
# Build: 1.0.0 (debug)
# Build token: INFODAYS{SaamNoLimits_apk_strings_dump_<hex>}
```

Or just `strings companion.apk | grep INFODAYS` — the flag is
picked up verbatim.

## Flag 2 — Medium (`static_constants`)

`DebugHelper.java` (decompiled) looks like:

```java
public final class DebugHelper {
    public static final String FRAG_A = "INFODAYS{Sa";
    public static final String FRAG_B = "amNoLimits_";
    public static final String FRAG_C = "apk_static_";
    public static final String FRAG_D = "constants_<hex>}";
    public static String whisperDebugFlag() {
        return FRAG_A + FRAG_B + FRAG_C + FRAG_D;
    }
}
```

Four fragments in declaration order. Concatenate by hand or read
`whisperDebugFlag()` and you have the flag. jadx's decompiler
shows the whole class at a glance.

## Flag 3 — Hard (`xor_decode`)

`XorVault.java`:

```java
public final class XorVault {
    static final byte[] ENC = new byte[] { (byte)0x1b, (byte)0x2c, ... };
    static final byte[] KEY = new byte[] { (byte)0x52, (byte)0x65, (byte)0x66, ... };
    public static String decodeReport() {
        byte[] out = new byte[ENC.length];
        for (int i = 0; i < ENC.length; i++)
            out[i] = (byte) (ENC[i] ^ KEY[i % KEY.length]);
        return new String(out);
    }
}
```

The `KEY` array spells `RefereeKit/2026!` in ASCII (hint in the
class name, confirmed by XOR'ing any byte pair). The full flag is:

```python
enc = bytes(ENC)
key = b"RefereeKit/2026!"
print(bytes(b ^ key[i % len(key)] for i, b in enumerate(enc)).decode())
```

## Flag 4 — Very Hard (`aes_composed_key`)

`AesVault.java`:

```java
public static final String CIPHERTEXT_B64 = "Zm9vYmFyYmF6...";  // ~64 chars
public static final String PKG  = "com.infodays.referee.companion";
public static final String VER  = "1.0.0";
public static final String SALT = "infodays2026_var_referee_salt";

public static String unlockVault() throws Exception {
    String keyMaterial = PKG + "|" + VER + "|" + SALT;
    byte[] keyDigest = MessageDigest.getInstance("SHA-256")
        .digest(keyMaterial.getBytes("UTF-8"));
    byte[] key = Arrays.copyOf(keyDigest, 16);

    byte[] ivDigest = MessageDigest.getInstance("SHA-256")
        .digest(("iv:" + SALT).getBytes("UTF-8"));
    byte[] iv = Arrays.copyOf(ivDigest, 16);

    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
    c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
    return new String(c.doFinal(Base64.getDecoder().decode(CIPHERTEXT_B64)), "UTF-8");
}
```

Everything the player needs is in the class itself. Reproduce in
Python:

```python
import base64, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

pkg, ver, salt = "com.infodays.referee.companion", "1.0.0", "infodays2026_var_referee_salt"
key = hashlib.sha256(f"{pkg}|{ver}|{salt}".encode()).digest()[:16]
iv  = hashlib.sha256(f"iv:{salt}".encode()).digest()[:16]
ct  = base64.b64decode("Zm9vYmFyYmF6...")
print(unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16).decode())
```

The "very hard" rating is because there are **three** separate
String constants plus a derived key schedule plus a derived IV.
A player who hand-copies the wrong constant, forgets the
`"|"`-delimiter, or mis-reads the digest truncation gets nothing
back. Careful transcription wins.

## Flag 5 — Insane (`custom_vm`)

`VMInterpreter.java` is a tiny register-machine:

```java
public static final int[] PROG = new int[] {
    1, 0x00ab, 2, 0x0057, 5, 0x0003, 4, 0x0022, 6, 0x0000,  // byte 1
    1, 0x00cd, 2, 0x0091, 5, 0x0005, 4, 0x0011, 6, 0x0000,  // byte 2
    // ... one 5-instruction group per flag byte ...
    0, 0
};

public static String run() {
    int[] R = new int[8];
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    int pc = 0;
    while (pc < PROG.length) {
        int op  = PROG[pc];
        int arg = PROG[pc + 1];
        pc += 2;
        int reg = (arg >> 8) & 0xFF;
        int imm = arg & 0xFF;
        if      (op == 0) break;                // HALT
        else if (op == 1) R[reg] = imm;         // LOAD_IMM
        else if (op == 2) R[reg] ^= imm;        // XOR_IMM
        else if (op == 3) R[reg] = (R[reg] + imm) & 0xFF;  // ADD
        else if (op == 4) R[reg] = (R[reg] - imm) & 0xFF;  // SUB
        else if (op == 5) {                     // ROTL
            int v = R[reg] & 0xFF, s = imm & 7;
            R[reg] = ((v << s) | (v >>> (8 - s))) & 0xFF;
        }
        else if (op == 6) out.write(R[arg & 0xFF]);         // STORE
    }
    return out.toString("UTF-8");
}
```

Players have three paths:

1. **Re-implement in Python.** Copy `PROG[]`, translate the
   opcode switch, run it. ~20 lines. This is what the author
   solver does — see `solver/solve.py:flag_five`.
2. **Run the class in a JVM.** The bytecode is pure Java, so a
   player can `javac` a tiny main that calls
   `VMInterpreter.run()` and print the result. No Android needed.
3. **Hand-trace the 25 instructions per byte.** Not recommended,
   but feasible for the patient.

Each flag byte is produced by the following 5-instruction
sequence:

```
LOAD_IMM  R0, scrambled
XOR_IMM   R0, k
ROTL      R0, rot
SUB_IMM   R0, off
STORE     R0
```

`scrambled`, `k`, `rot`, and `off` are per-byte and pseudo-random
(the build-time generator seeds a tiny LCG from the flag hex).
There is no structural shortcut — you really do have to run the
interpreter. That's what earns this rung the "insane" label:
even after the code is fully understood, the flag is recovered
by **execution**, not by inspection.

## Author solver

`solver/solve.py` runs all five stages end-to-end using only
the Python standard library (+ `cryptography` for AES). It:

1. Unzips the APK and reads `assets/welcome.txt` for flag 1.
2. Parses the DEX string pool with a hand-rolled reader and
   scans for `static_constants_` fragments for flag 2.
3. Walks the DEX looking for `fill-array-data-payload` chunks
   with 1-byte element width, XORs each against the guessed
   key, and accepts the first result that starts with
   `INFODAYS{` for flag 3.
4. Recognises the PKG / VER / SALT / B64 strings by format and
   reruns the SHA-256 → AES/CBC chain for flag 4.
5. Walks the DEX looking for `fill-array-data-payload` chunks
   with 4-byte element width, interprets each as a VM program,
   and keeps the one that emits a valid `INFODAYS{...}`.

No external tools (no apktool, no jadx, no androguard). Run:

```bash
python3 solver/solve.py dist/companion.apk
```

End-to-end timing is under one second.

## Teaching points

- **`strings` still wins a lot of the time.** Attackers don't
  decompile if the flag falls out of `strings`. Use proper
  obfuscation even for "debug" tokens.
- **String constants are trivially readable.** Java string
  pools in DEX preserve the exact source literals — splitting
  a flag into chunks buys you nothing unless you also destroy
  the concat pattern (e.g. runtime generation).
- **Repeating-key XOR is not encryption.** Any ASCII plaintext
  with a short key is one `printable ASCII` heuristic away from
  falling over.
- **Key derivation from static inputs does not add security.**
  If every input is in the same class, the reverse engineer
  has every input too. Real KDFs derive from user input, device
  identifiers, or server-issued secrets.
- **Custom VMs slow attackers but do not stop them.** A tiny
  stack-less register machine is 20 lines of Python to
  re-implement. If your threat model is "buy me six hours",
  great. If it's "buy me a week", this is not the tool.

## Build pipeline notes (author-only)

The APK is built without Android Studio, Gradle, or the Google
SDK. See `build.sh`:

1. `gen.py` emits the Java source files with the current flags
   and derived constants (XOR'd bytes, AES ciphertext, VM
   program) baked in.
2. `javac` compiles to `.class` files.
3. `d8` (from Google's r8.jar) converts `.class` → `classes.dex`.
4. `aapt2 compile` + `aapt2 link` build the binary
   `AndroidManifest.xml` + `resources.arsc` from the text
   manifest and `src/res`.
5. `zip` adds `classes.dex` and `assets/` into the linked
   base APK.
6. `jarsigner` V1-signs it with a self-generated debug keystore.

Result: an 8 KB APK with real binary AXML, a real DEX, and a
valid jarsigner signature. Ships as-is to players.
