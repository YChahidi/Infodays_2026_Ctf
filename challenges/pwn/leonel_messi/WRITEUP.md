# leonel_messi — Author Writeup (staff only)

> Do not ship this file inside the player bundle.

## 1. Summary

Stack buffer overflow in the `0x0A RECORD` handler, classic ret2win
against a non-PIE binary that ships — but never calls — a `read_flag`
helper. The helper pipes `/home/ctf/flag.txt` to fd 4 (the accepted
client socket in the forked child), so the flag arrives on the same
socket after we redirect RIP.

Binary hardening:

| Mitigation | State |
|------------|-------|
| RELRO | partial |
| Stack canary | off |
| NX | on |
| PIE | off |
| FORTIFY | off |

## 2. The bug

`op_record` (opcode `0x0A`):

```c
uint16_t size = ((uint16_t)body[1] << 8) | body[2];
if (blen < (int)(3 + size)) { /* err */; return; }

char local[128];
memcpy(local, body + 3, size);     // ← no upper bound on `size`
```

`size` is a u16 chosen by the peer, capped only by the outer frame
(body buffer is 1024 bytes in `session()`, so `size ≤ 1021`). That is
still ~900 bytes past `local[128]`, enough to blow through saved rbx,
saved rbp, and saved rip.

## 3. The win function

The author-injected `read_flag`:

```c
static void read_flag(void) {
    int ff = open("/home/ctf/flag.txt", O_RDONLY);
    char fbuf[256];
    ssize_t n = read(ff, fbuf, sizeof(fbuf));
    write(4, fbuf, n);            // fd 4 = accepted client socket
    _exit(0);
}
```

`main()` keeps an `if (argc == 9999) read_flag();` dead branch so the
linker never garbage-collects the symbol.

## 4. Exploit

1. Solve the 16-bit PoW.
2. Send a RECORD frame whose inner `size` is large (e.g. 160) and whose
   payload is `A*144 || p64(ret_gadget) || p64(read_flag)`.
3. `op_record` returns into our chain. The `ret` gadget re-aligns rsp
   (SysV AMD64 ABI requires 16-byte alignment at `call` sites; after
   our `ret` pops RIP, rsp is off by 8).
4. `read_flag` runs, writes the flag bytes to fd 4 (our socket), and
   `_exit(0)` kills the child.
5. The exploit reads the flag off the socket.

### Stack layout (Ubuntu 22.04, gcc 11 `-O1 -no-pie -fno-stack-protector`)

```
 local[128]     @ rsp+0x00
 saved rbx      @ rsp+0x80   (op_record keeps `fd` across calls)
 saved rbp      @ rsp+0x88
 saved rip      @ rsp+0x90   (offset 144)
```

The solver uses `offset_to_rip = 144` to land RIP precisely on `ret`.

## 5. Why the hardening holds against AI shortcuts

| Layer | Blocks |
|-------|--------|
| Scrubbed source comments | No "BOF", no "ret2win", no "use read_flag" hints under version control. |
| Custom LM10 framing | "Write a solver for a pwn challenge" prompts produce menu parsers that fail against the binary protocol. |
| 16-bit PoW | Brute-force automation pays ~40 ms per attempt; interactive fuzzers see real friction. |

## 6. Verified solve

The solver in `solver/solve.py` walks the full chain end-to-end and
has been tested against the Dockerized build. See the main README for
the exact commands.
