/*
 *  LEONEL MESSI — GOAT Edition  (InfoDays 2026 CTF · Pwn · Insane)
 *  Author: saamnolimits
 *
 *  Leo's "Ballon d'Or Vault" — a forking TCP service that stores Messi's
 *  most iconic goals in a heap-backed ledger, gated by a 22-bit SHA-256
 *  proof-of-work and wrapped in a seccomp sandbox that blocks execve.
 *
 *  ───────────────────────────────────────────────────────────────────
 *  LM10 wire protocol (every message is a single framed record)
 *      magic : "LM10"            (4 bytes, fixed)
 *      len   : uint16_t big-end  (body length)
 *      body  : len bytes         (first byte is the opcode)
 *
 *  Opcodes:
 *      0x0A RECORD    0x0A || u16 BE size || content[size]
 *                     response = 0x00 || u8 idx
 *      0x1E RECALL    0x1E || u8 idx
 *                     response = 0x00 || u16 BE len || content[len]
 *      0x4B REFORGE   0x4B || u8 idx || u16 BE off || u16 BE newlen || bytes[newlen]
 *                     response = 0x00
 *      0x37 RETIRE    0x37 || u8 idx
 *                     response = 0x00
 *      0x63 CEREMONY  0x63                                (disconnect)
 *
 *  ───────────────────────────────────────────────────────────────────
 *  Proof-of-work gate (first thing on every new connection)
 *      Server:  "LM10" || u16(18) || 0xEE || nonce[16] || 0x16   (22 bits)
 *      Client:  "LM10" || u16( 8) || 0xEF || suffix[7]
 *      Pass when sha256(nonce || suffix) has >= 22 leading zero bits.
 *
 *  ───────────────────────────────────────────────────────────────────
 *  Compile flags (see Dockerfile): Full RELRO, PIE, stack canary,
 *  FORTIFY=2, NX on, seccomp.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <seccomp.h>

/* ── SHA-256 (inlined to avoid linking OpenSSL) ───────────────────── */

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))

static void sha256(const uint8_t *msg, size_t len, uint8_t out[32]) {
    uint32_t h[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    size_t pad_len = ((len + 1 + 8 + 63) / 64) * 64;
    uint8_t *buf = calloc(1, pad_len);
    memcpy(buf, msg, len);
    buf[len] = 0x80;
    uint64_t bitlen = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++)
        buf[pad_len - 1 - i] = (uint8_t)(bitlen >> (i * 8));

    for (size_t off = 0; off < pad_len; off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)buf[off+4*i]   << 24) |
                   ((uint32_t)buf[off+4*i+1] << 16) |
                   ((uint32_t)buf[off+4*i+2] << 8)  |
                   ((uint32_t)buf[off+4*i+3]);
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = ROTR(w[i-15],7) ^ ROTR(w[i-15],18) ^ (w[i-15]>>3);
            uint32_t s1 = ROTR(w[i-2],17) ^ ROTR(w[i-2],19)  ^ (w[i-2]>>10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = ROTR(e,6) ^ ROTR(e,11) ^ ROTR(e,25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0 = ROTR(a,2) ^ ROTR(a,13) ^ ROTR(a,22);
            uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + mj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    for (int i = 0; i < 8; i++) {
        out[4*i]   = (uint8_t)(h[i] >> 24);
        out[4*i+1] = (uint8_t)(h[i] >> 16);
        out[4*i+2] = (uint8_t)(h[i] >> 8);
        out[4*i+3] = (uint8_t)(h[i]);
    }
    free(buf);
}

/* ── Wire I/O helpers ─────────────────────────────────────────────── */

static const char MAGIC[4] = {'L','M','1','0'};

static ssize_t read_full(int fd, void *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (char*)buf + got, n - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return (ssize_t)got;
}

static int write_full(int fd, const void *buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, (const char*)buf + sent, n - sent);
        if (w <= 0) return -1;
        sent += (size_t)w;
    }
    return 0;
}

static int recv_frame(int fd, uint8_t *body, size_t cap) {
    uint8_t hdr[6];
    if (read_full(fd, hdr, 6) != 6) return -1;
    if (memcmp(hdr, MAGIC, 4) != 0) return -1;
    uint16_t len = ((uint16_t)hdr[4] << 8) | hdr[5];
    if (len == 0) return 0;
    if ((size_t)len > cap) return -1;
    if (read_full(fd, body, len) != (ssize_t)len) return -1;
    return (int)len;
}

static int send_frame(int fd, const uint8_t *body, uint16_t len) {
    uint8_t hdr[6];
    memcpy(hdr, MAGIC, 4);
    hdr[4] = (uint8_t)(len >> 8);
    hdr[5] = (uint8_t)(len);
    if (write_full(fd, hdr, 6) < 0) return -1;
    if (len > 0 && write_full(fd, body, len) < 0) return -1;
    return 0;
}

/* ── PoW gate ─────────────────────────────────────────────────────── */

#define POW_BITS 22

static int pow_gate(int fd) {
    uint8_t nonce[16];
    int urand = open("/dev/urandom", O_RDONLY);
    if (urand < 0) return -1;
    if (read_full(urand, nonce, 16) != 16) { close(urand); return -1; }
    close(urand);

    uint8_t body[32];
    body[0] = 0xEE;
    memcpy(body + 1, nonce, 16);
    body[17] = POW_BITS;
    if (send_frame(fd, body, 18) < 0) return -1;

    uint8_t reply[64];
    int rlen = recv_frame(fd, reply, sizeof(reply));
    if (rlen != 8 || reply[0] != 0xEF) return -1;

    uint8_t probe[23];
    memcpy(probe, nonce, 16);
    memcpy(probe + 16, reply + 1, 7);
    uint8_t digest[32];
    sha256(probe, 23, digest);

    int full_bytes = POW_BITS / 8;
    int rem = POW_BITS % 8;
    for (int i = 0; i < full_bytes; i++)
        if (digest[i] != 0) return -1;
    if (rem && (digest[full_bytes] & (0xFF << (8 - rem))) != 0) return -1;
    return 0;
}

/* ── Sandbox (seccomp) ────────────────────────────────────────────── */

static int install_seccomp(void) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
    if (!ctx) return -1;
    int allow[] = {
        SCMP_SYS(read),        SCMP_SYS(write),      SCMP_SYS(openat),
        SCMP_SYS(close),       SCMP_SYS(fstat),      SCMP_SYS(lseek),
        SCMP_SYS(mmap),        SCMP_SYS(munmap),     SCMP_SYS(mprotect),
        SCMP_SYS(brk),         SCMP_SYS(rt_sigreturn),
        SCMP_SYS(exit),        SCMP_SYS(exit_group),
        SCMP_SYS(newfstatat),  SCMP_SYS(pread64),
    };
    for (size_t i = 0; i < sizeof(allow)/sizeof(allow[0]); i++) {
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, allow[i], 0) < 0) {
            seccomp_release(ctx); return -1;
        }
    }
    int rc = seccomp_load(ctx);
    seccomp_release(ctx);
    return rc;
}

/* ── State ────────────────────────────────────────────────────────── */

#define MAX_ENTRIES 16

typedef struct {
    uint8_t *ptr;
    uint16_t len;
} entry_t;

/* Per-session entries live in BSS — one session per forked child. */
static entry_t ents[MAX_ENTRIES];

/* ── Opcode handlers ──────────────────────────────────────────────── */

/*  RECORD   body = 0x0A || u16 BE size || content[size]
 *  malloc(size), copy `size` bytes in from the frame body.               */
__attribute__((noinline))
static void op_record(int fd, const uint8_t *body, int blen) {
    uint8_t resp[4];
    if (blen < 3) { resp[0] = 0xFF; send_frame(fd, resp, 1); return; }
    uint16_t size = ((uint16_t)body[1] << 8) | body[2];
    if (size == 0 || size > 0x800) { resp[0] = 0xFF; send_frame(fd, resp, 1); return; }
    if (blen < (int)(3 + size)) { resp[0] = 0xFF; send_frame(fd, resp, 1); return; }

    int idx = -1;
    for (int i = 0; i < MAX_ENTRIES; i++) if (ents[i].ptr == NULL) { idx = i; break; }
    if (idx < 0) { resp[0] = 0xFF; send_frame(fd, resp, 1); return; }

    uint8_t *p = (uint8_t *)malloc(size);
    if (!p) { resp[0] = 0xFF; send_frame(fd, resp, 1); return; }
    memcpy(p, body + 3, size);
    ents[idx].ptr = p;
    ents[idx].len = size;

    resp[0] = 0x00;
    resp[1] = (uint8_t)idx;
    send_frame(fd, resp, 2);
}

/*  RECALL   body = 0x1E || u8 idx
 *  Echo back ents[idx].len bytes starting at ents[idx].ptr.              */
__attribute__((noinline))
static void op_recall(int fd, const uint8_t *body, int blen) {
    uint8_t resp[4 + 0x800];
    if (blen < 2) { resp[0] = 0xFF; send_frame(fd, resp, 1); return; }
    uint8_t idx = body[1];
    if (idx >= MAX_ENTRIES || ents[idx].ptr == NULL) {
        resp[0] = 0xFF; send_frame(fd, resp, 1); return;
    }
    uint16_t len = ents[idx].len;
    resp[0] = 0x00;
    resp[1] = (uint8_t)(len >> 8);
    resp[2] = (uint8_t)(len);
    memcpy(resp + 3, ents[idx].ptr, len);
    send_frame(fd, resp, (uint16_t)(3 + len));
}

/*  REFORGE  body = 0x4B || u8 idx || u16 BE off || u16 BE newlen || bytes
 *  memcpy(ents[idx].ptr + off, bytes, newlen)   — no bounds check.       */
__attribute__((noinline))
static void op_reforge(int fd, const uint8_t *body, int blen) {
    uint8_t resp[2];
    if (blen < 6) { resp[0] = 0xFF; send_frame(fd, resp, 1); return; }
    uint8_t idx = body[1];
    uint16_t off    = ((uint16_t)body[2] << 8) | body[3];
    uint16_t newlen = ((uint16_t)body[4] << 8) | body[5];
    if (idx >= MAX_ENTRIES || ents[idx].ptr == NULL) {
        resp[0] = 0xFF; send_frame(fd, resp, 1); return;
    }
    if (blen < (int)(6 + newlen)) { resp[0] = 0xFF; send_frame(fd, resp, 1); return; }
    memcpy(ents[idx].ptr + off, body + 6, newlen);
    resp[0] = 0x00;
    send_frame(fd, resp, 1);
}

/*  RETIRE   body = 0x37 || u8 idx
 *  free(ents[idx].ptr)   — pointer & length are NOT cleared.             */
__attribute__((noinline))
static void op_retire(int fd, const uint8_t *body, int blen) {
    uint8_t resp[2];
    if (blen < 2) { resp[0] = 0xFF; send_frame(fd, resp, 1); return; }
    uint8_t idx = body[1];
    if (idx >= MAX_ENTRIES || ents[idx].ptr == NULL) {
        resp[0] = 0xFF; send_frame(fd, resp, 1); return;
    }
    free(ents[idx].ptr);
    resp[0] = 0x00;
    send_frame(fd, resp, 1);
}

/* ── Session loop ─────────────────────────────────────────────────── */

__attribute__((noinline))
static void session(int fd) {
    if (pow_gate(fd) < 0) { close(fd); return; }
    if (install_seccomp() < 0) { close(fd); return; }

    for (int i = 0; i < MAX_ENTRIES; i++) { ents[i].ptr = NULL; ents[i].len = 0; }

    uint8_t body[4096];
    while (1) {
        int blen = recv_frame(fd, body, sizeof(body));
        if (blen <= 0) break;
        uint8_t op = body[0];
        if      (op == 0x0A) op_record(fd, body, blen);
        else if (op == 0x1E) op_recall (fd, body, blen);
        else if (op == 0x4B) op_reforge(fd, body, blen);
        else if (op == 0x37) op_retire (fd, body, blen);
        else if (op == 0x63) break;
        else { uint8_t r = 0xFF; send_frame(fd, &r, 1); }
    }
    close(fd);
}

/* ── Forking TCP server ───────────────────────────────────────────── */

static int server_sd;

static void exit_server(int sig) {
    (void)sig;
    if (server_sd > 0) close(server_sd);
    _exit(0);
}

int main(int argc, char **argv) {
    int reuse = 1;
    struct sockaddr_in addr;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        return 1;
    }
    int port = atoi(argv[1]);

    signal(SIGINT, exit_server);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);

    server_sd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sd < 0) { perror("socket"); return 1; }

    setsockopt(server_sd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(server_sd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(server_sd); return 1;
    }
    if (listen(server_sd, 16) < 0) {
        perror("listen"); close(server_sd); return 1;
    }

    for (;;) {
        struct sockaddr cli;
        socklen_t       cli_len = sizeof(cli);
        int fd = accept(server_sd, &cli, &cli_len);
        if (fd < 0) { if (errno == EINTR) continue; perror("accept"); continue; }

        pid_t pid = fork();
        if (pid < 0) { perror("fork"); close(fd); continue; }
        if (pid == 0) {
            close(server_sd);
            session(fd);
            _exit(0);
        }
        close(fd);
    }
    return 0;
}
