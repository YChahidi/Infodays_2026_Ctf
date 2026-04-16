# var_mobile_companion

**Category:** Mobile / Reverse Engineering (Android)
**Difficulty:** Five flags — Easy, Medium, Hard, Very Hard, Insane
**Artifact:** a single signed `.apk` file (`dist/companion.apk`)

## Player brief

> The Infodays 2026 referee crew are beta-testing a phone app —
> **VAR Referee Companion** — that caches match briefings,
> decrypts per-match reports, and runs a tiny "stats VM" for
> live calls on the sideline.
>
> You recovered a debug build of the APK from a trash WiFi AP at
> the stadium. The app shipped with five separate build tokens
> baked into different parts of the code. Find all five.
>
> Players don't need a device or emulator — everything is static
> analysis. Decompile with `jadx-gui`, poke around with
> `apktool d`, or just `strings` the file for flag 1.
>
> **Flag format:** `INFODAYS{SaamNoLimits_<phrase>_<hex>}`

## Difficulty ladder

| # | Flag           | Difficulty | Vector |
|---|----------------|------------|--------|
| 1 | `strings_dump`          | **Easy**      | Plain-text flag in `assets/welcome.txt` |
| 2 | `static_constants`      | **Medium**    | Hardcoded String fragments in `DebugHelper` concatenated at runtime |
| 3 | `xor_decode`            | **Hard**      | XOR-encoded `byte[]` with a repeating-key `byte[]` in `XorVault` |
| 4 | `aes_composed_key`      | **Very Hard** | AES/CBC with `key = SHA-256(pkg \|\| ver \|\| salt)` — three inputs scattered across the app |
| 5 | `custom_vm_insane`      | **Insane**    | Custom register-machine interpreter in `VMInterpreter` runs ~25 opcodes to reconstruct the flag byte by byte |

No native code, no anti-debug, no runtime tricks — the whole
chain is static analysis from the DEX. The "insane" rung is
insane because the flag is produced by an interpreter whose
program is a hand-tuned sequence of (LOAD, XOR, ROTL, SUB, STORE)
operations targeting a private register file. Players either
hand-trace it, re-implement the VM, or run the class in a real
JVM.

## Recommended tooling

- **[jadx](https://github.com/skylot/jadx)** — decompile DEX to Java; will see all class source
- **apktool** — `apktool d companion.apk` for binary XML + smali
- **strings** — one-liner for flag 1
- **openssl / Python cryptography** — flag 4 AES helper
- **A text editor and a calm mind** — flag 5

## Deployment

```bash
# 1. Rotate all five flags + regenerate Java sources + rebuild APK
./build.sh

# 2. Ship dist/companion.apk to players. That's the entire challenge.
ls -la dist/companion.apk
```

The challenge is a **pure file**, no docker container, no
network service — you just hand players one `.apk`.

## Files

| Path | Purpose |
|------|---------|
| `gen.py` | Generates flags, Java sources, and `flag.txt` |
| `build.sh` | Full build pipeline (javac → d8 → aapt2 → sign) |
| `src/java/com/infodays/referee/*.java` | Generated Java sources (5 flag-bearing classes) |
| `src/res/values/strings.xml` | App resources referenced by flag 4's key derivation |
| `src/assets/welcome.txt` | Flag 1's cleartext |
| `src/AndroidManifest.xml` | App manifest |
| `dist/companion.apk` | Signed APK handed to players |
| `solver/solve.py` | Full author solver — reads DEX + assets, recovers all 5 flags |
| `flag.txt` | Author-side copy of current flags |
| `README.md` / `WRITEUP.md` | Docs |

## Build-host toolchain (author-only)

The build pipeline needs three external tools installed under
`~/tools/`:

| Tool | Source | Purpose |
|------|--------|---------|
| `r8.jar` (contains d8) | [Google Maven](https://dl.google.com/android/maven2/com/android/tools/r8/8.2.47/r8-8.2.47.jar) | `.class` → `classes.dex` |
| `aapt2` + libs | Debian `aapt` + android-lib\* packages | compile + link resources into binary AXML + `resources.arsc` |
| `framework-res.apk` | Debian `android-framework-res` package | `-I` framework for aapt2 link |

Plus JDK 11+ (`javac`, `jarsigner`, `keytool`) from the base OS.

## Current flags

Regenerate with `./build.sh` before publishing. Author-side copy
is in `flag.txt`.
