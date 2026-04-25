# Ghost Protocol — Pwn Challenge

**Category:** Pwn  
**Technique:** ROP chain + libc leak (ret2libc)  
**Difficulty:** Expert  
**Protections:** NX=ON, PIE=OFF, Canary=OFF, ASLR=ON (container default)

---

## File Structure

```
pwn-ghost-protocol/
├── challenge/
│   ├── ghost.c          ← source (do NOT distribute)
│   ├── Dockerfile
│   ├── entrypoint.sh
│   └── manifest.yaml
└── solve/
    ├── solve.py         ← full exploit (author eyes only)
    └── build_and_test.sh
```

**Distribute to players:** compiled `ghost` binary + `nc` address only.  
**Never distribute:** `ghost.c`, `solve.py`, `libc.so.6`.

---

## Anti-AI / Anti-Automation Layers

| Layer | What it does |
|---|---|
| `win()` decoy | Looks like the obvious overflow target. Requires a runtime random key — impossible to satisfy. AI and auto-tools will waste time here. |
| `decoy_shell()` symbol | Exports a visible `system("/bin/sh")` symbol. Unreachable. Grep-based tools will flag it as the win condition incorrectly. |
| Fake command loop | `process_command()` looks like a normal dispatcher. The vuln is `read(0, cmd, 256)` into a 64-byte buffer — subtle and easy to miss on a quick pass. |
| Password gate | Players must know/find `ghostop` before they reach the real vuln. Slows any automated fuzzing pipeline. |
| `gets()` on username | Classic red herring — looks like the vuln but only overwrites rbp with no useful gadget path (win() key check kills it). |

---

## Intended Exploit Path

```
1. Reverse / read the binary
   └─ Notice gets() on username → overflow → win() … but win() needs a random key

2. Log in with password "ghostop"
   └─ Password is hardcoded in the binary (strings / ltrace reveals it)

3. In process_command(), spot read(0, cmd, 256) into char cmd[64]
   └─ Clean 192-byte overflow, no canary

4. Build Stage 1 ROP chain:
   pop rdi ; ret  → puts@got
   puts@plt
   main           ← loop back
   └─ Leaks runtime address of puts → compute libc base

5. Build Stage 2 ROP chain:
   ret            ← stack alignment
   pop rdi ; ret  → /bin/sh string in libc
   system()
   └─ Shell spawned → cat /flag.txt
```

---

## Build & Run Locally

```bash
cd solve
chmod +x build_and_test.sh
./build_and_test.sh

# Once running:
nc 127.0.0.1 1337

# Run the solve:
python3 solve.py LOCAL
```

---

## Deploy to CTF Infrastructure

```bash
# Push image
bash scripts/push-challenge.sh ghost-protocol challenges/real/challenges/pwn/ghost-protocol

# Deploy
export CTFD_URL=https://ctfd.infodays.net
export CTFD_ADMIN_TOKEN=<token>
export CTF_MASTER_SECRET=<secret>
bash scripts/deploy-challenge.sh challenges/manifests/pwn-ghost-protocol.yaml
```

---

## Verify protections after build

Expected checksec output:
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found     ✓ (needed for clean overflow)
NX:       NX enabled          ✓ (no shellcode)
PIE:      No PIE              ✓ (stable gadget addresses)
```

If PIE shows as enabled, the Dockerfile gcc flags were not applied — rebuild.

---

## Notes

- The container uses **Ubuntu 22.04** → **libc-2.35**. The `puts` offset in this libc is stable. Players need to identify the libc version (give the binary, let them run `libc-database` or match via `puts` offset).
- You can optionally include the binary's `libc.so.6` as a handout file — standard practice for harder ret2libc challenges. Your call.
- `socat -T120` kills idle connections after 2 minutes.
