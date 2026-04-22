/*
 *  SHANKS v2 — InfoDays 2026 CTF  (Insane, Anti-AI retrofit)
 *  Author: saamnolimits
 *
 *  Forking socket server.  Every inbound connection:
 *    1. Completes a custom-framed PoW handshake (magic PW01).
 *    2. Sends a captain prompt in a custom frame (magic CAP1).
 *    3. Reads the framed captain response and overflows the buffer
 *       in check_username() as before.
 *
 *  Anti-AI design principles applied:
 *    #3 Custom/fictional format — the wire protocol is invented
 *       for this challenge.  No training data exists on PW01/CAP1
 *       framing, so an LLM asked "write a client" will either make
 *       it up or get it wrong.
 *    #7 Anti-automation — every connection must satisfy a 16-bit
 *       SHA-256 PoW before the overflow primitive is exposed.  The
 *       canary/RBP/retaddr brute force needs ~2000 connections, so
 *       the PoW is a real friction for naive automation while still
 *       tractable for a purpose-built solver.
 *
 *  Bug (retained from v1):
 *    - check_username() declares a 1032-byte buffer but the framed
 *      read honours an attacker-supplied length up to 0x440 = 1056,
 *      giving a 24-byte overflow that reaches the canary, saved rbp,
 *      and return address.  Input is then XOR'd with 0x0d before
 *      memcmp, matching "shanks".
 *
 *  Intended solve (unchanged mechanics, new wire):
 *    1. Solve the PW01 PoW on each connection.
 *    2. Bruteforce canary via fork-survival oracle.
 *    3. Bruteforce saved rbp + saved return address -> ELF base.
 *    4. Stack-pivot via helper's leave;ret into the buffer, drop a
 *       ROP chain that writes libc address (write@GOT) via write()
 *       back over the socket -> libc base.
 *    5. Second payload: ROP chain with dup2(fd,0/1/2) + system("/bin/sh").
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ── POW difficulty (leading zero bits) ──────────────────────────── */
#define POW_DIFFICULTY 16
#define POW_CHALLENGE_LEN 8
#define POW_NONCE_LEN 8

/* ── Inline SHA-256 (public-domain style, FIPS 180-4) ────────────── */
typedef struct {
    uint32_t h[8];
    uint64_t bits;
    uint8_t  buf[64];
    size_t   buflen;
} sha256_t;

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
};

static inline uint32_t ror32(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }

static void sha256_init(sha256_t *s) {
    static const uint32_t H0[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19,
    };
    memcpy(s->h, H0, sizeof(H0));
    s->bits = 0;
    s->buflen = 0;
}

static void sha256_compress(sha256_t *s, const uint8_t blk[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)blk[i*4]<<24) | ((uint32_t)blk[i*4+1]<<16)
             | ((uint32_t)blk[i*4+2]<<8) | (uint32_t)blk[i*4+3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ror32(w[i-15], 7) ^ ror32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = ror32(w[i-2], 17) ^ ror32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=s->h[0],b=s->h[1],c=s->h[2],d=s->h[3],e=s->h[4],f=s->h[5],g=s->h[6],h=s->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ror32(e,6) ^ ror32(e,11) ^ ror32(e,25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = ror32(a,2) ^ ror32(a,13) ^ ror32(a,22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    s->h[0]+=a; s->h[1]+=b; s->h[2]+=c; s->h[3]+=d;
    s->h[4]+=e; s->h[5]+=f; s->h[6]+=g; s->h[7]+=h;
}

static void sha256_update(sha256_t *s, const void *data, size_t len) {
    const uint8_t *p = data;
    s->bits += (uint64_t)len * 8;
    if (s->buflen) {
        size_t take = 64 - s->buflen;
        if (take > len) take = len;
        memcpy(s->buf + s->buflen, p, take);
        s->buflen += take;
        p += take; len -= take;
        if (s->buflen == 64) { sha256_compress(s, s->buf); s->buflen = 0; }
    }
    while (len >= 64) { sha256_compress(s, p); p += 64; len -= 64; }
    if (len) { memcpy(s->buf, p, len); s->buflen = len; }
}

static void sha256_final(sha256_t *s, uint8_t out[32]) {
    uint64_t bits = s->bits;
    uint8_t pad = 0x80;
    sha256_update(s, &pad, 1);
    uint8_t zero = 0;
    while (s->buflen != 56) sha256_update(s, &zero, 1);
    uint8_t lenbe[8];
    for (int i = 0; i < 8; i++) lenbe[i] = (uint8_t)(bits >> (56 - i*8));
    sha256_update(s, lenbe, 8);
    for (int i = 0; i < 8; i++) {
        out[i*4+0] = (uint8_t)(s->h[i] >> 24);
        out[i*4+1] = (uint8_t)(s->h[i] >> 16);
        out[i*4+2] = (uint8_t)(s->h[i] >>  8);
        out[i*4+3] = (uint8_t)(s->h[i]      );
    }
}

static int leading_zero_bits(const uint8_t *d, size_t n) {
    int z = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t b = d[i];
        if (b == 0) { z += 8; continue; }
        for (int j = 7; j >= 0; j--) { if (b & (1u << j)) return z; z++; }
    }
    return z;
}

/* ── Robust I/O helpers ──────────────────────────────────────────── */

static ssize_t read_all(int fd, void *buf, size_t n) {
    uint8_t *p = buf;
    size_t  left = n;
    while (left) {
        ssize_t r = read(fd, p, left);
        if (r <= 0) {
            if (r < 0 && errno == EINTR) continue;
            return r == 0 ? (ssize_t)(n - left) : r;
        }
        p += r; left -= r;
    }
    return (ssize_t)n;
}

static ssize_t write_all(int fd, const void *buf, size_t n) {
    const uint8_t *p = buf;
    size_t left = n;
    while (left) {
        ssize_t r = write(fd, p, left);
        if (r <= 0) {
            if (r < 0 && errno == EINTR) continue;
            return r;
        }
        p += r; left -= r;
    }
    return (ssize_t)n;
}

static int get_random(void *buf, size_t n) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t r = read_all(fd, buf, n);
    close(fd);
    return (r == (ssize_t)n) ? 0 : -1;
}

/* ── Custom wire protocol ────────────────────────────────────────────
 *  Frame:   4-byte magic | 2-byte length (big-endian) | length bytes payload
 *  Magics:  "PW01"   proof-of-work challenge (server->client)
 *                    and response (client->server)
 *           "CAP1"   captain prompt / response
 * ──────────────────────────────────────────────────────────────────── */

static int send_frame(int fd, const char magic[4], const void *payload, uint16_t len) {
    uint8_t hdr[6];
    memcpy(hdr, magic, 4);
    hdr[4] = (uint8_t)(len >> 8);
    hdr[5] = (uint8_t)(len & 0xff);
    if (write_all(fd, hdr, 6) != 6) return -1;
    if (len && write_all(fd, payload, len) != (ssize_t)len) return -1;
    return 0;
}

/* Read the frame header, verify magic, return the advertised length.
   Payload read is the caller's responsibility (to keep the overflow
   primitive in check_username() straight — and to let us use the
   attacker-supplied length as the read() count). */
static int recv_frame_header(int fd, const char magic[4], uint16_t *out_len) {
    uint8_t hdr[6];
    if (read_all(fd, hdr, 6) != 6) return -1;
    if (memcmp(hdr, magic, 4) != 0) return -1;
    *out_len = ((uint16_t)hdr[4] << 8) | hdr[5];
    return 0;
}

static int do_pow(int fd) {
    uint8_t challenge[POW_CHALLENGE_LEN];
    uint8_t difficulty = POW_DIFFICULTY;
    if (get_random(challenge, POW_CHALLENGE_LEN) < 0) return 0;

    /* Send PW01 payload: 8-byte challenge || 1-byte difficulty. */
    uint8_t pld[POW_CHALLENGE_LEN + 1];
    memcpy(pld, challenge, POW_CHALLENGE_LEN);
    pld[POW_CHALLENGE_LEN] = difficulty;
    if (send_frame(fd, "PW01", pld, sizeof(pld)) < 0) return 0;

    /* Receive PW01 response: 8-byte nonce. */
    uint16_t nlen = 0;
    if (recv_frame_header(fd, "PW01", &nlen) < 0) return 0;
    if (nlen != POW_NONCE_LEN) return 0;
    uint8_t nonce[POW_NONCE_LEN];
    if (read_all(fd, nonce, POW_NONCE_LEN) != POW_NONCE_LEN) return 0;

    /* Verify sha256(challenge || nonce) has >= difficulty leading zero bits. */
    sha256_t s; sha256_init(&s);
    sha256_update(&s, challenge, POW_CHALLENGE_LEN);
    sha256_update(&s, nonce, POW_NONCE_LEN);
    uint8_t digest[32];
    sha256_final(&s, digest);
    return leading_zero_bits(digest, 32) >= difficulty;
}

static int server_sd;

static void exit_server(int sig) {
    (void)sig;
    if (server_sd > 0) close(server_sd);
    _exit(0);
}

/*
 * helper() hands the attacker four deterministic ROP gadgets and a
 * `leave; ret` pivot.  Unchanged from v1.
 *   pop rdi ; ret            (5f c3)
 *   pop rsi ; pop r15 ; ret  (5e 41 5f c3)
 *   pop rdx ; ret            (5a c3)
 *   leave ; ret              (c9 c3)
 */
__attribute__((used, noinline))
void helper(void) {
    asm volatile (
        "jmp 1f                      \n"
        ".byte 0x5f, 0xc3            \n"    /* pop rdi ; ret           */
        ".byte 0x5e, 0x41, 0x5f, 0xc3\n"    /* pop rsi ; pop r15 ; ret */
        ".byte 0x5a, 0xc3            \n"    /* pop rdx ; ret           */
        ".byte 0xc9, 0xc3            \n"    /* leave ; ret             */
        "1: nop                      \n"
    );
}

/*
 * check_username — the vulnerable routine.
 *   - 1032-byte buffer.
 *   - Reads the attacker-supplied frame length (up to 0x440 = 1056),
 *     then read()s exactly that many bytes straight into buf.  A
 *     length > 1032 is the overflow primitive.
 *   - each byte is XOR'd with 0xd in place.
 *   - memcmp against the XOR'd captain name ("shanks" ^ 0x0d = "~elcf~").
 */
__attribute__((noinline))
static int check_username(int fd) {
    unsigned char buf[1032];
    ssize_t n;
    int i;

    /* Emit the whole frame in one syscall so partial-recv clients see it
       as a single blob (nicer for players hand-writing a parser). */
    send_frame(fd, "CAP1", "Captain: ", 9);

    /* Read the client's CAP1 frame header so we know how many bytes
       to draw into buf.  The advertised length becomes the read()
       count — an attacker can set it up to 0x440, giving a 24-byte
       overflow past buf into canary/rbp/retaddr territory. */
    uint8_t fhdr[6];
    if (read_all(fd, fhdr, 6) != 6) return 0;
    if (memcmp(fhdr, "CAP1", 4) != 0) return 0;
    uint16_t flen = ((uint16_t)fhdr[4] << 8) | fhdr[5];
    if (flen == 0 || flen > 0x440) return 0;

    n = read(fd, buf, flen);
    if (n <= 0) return 0;

    for (i = 0; i < (int)n; i++) buf[i] ^= 0x0d;

    return memcmp(buf, "\x7e" "elcf\x7e", 6) == 0;
}

int main(int argc, char **argv) {
    int reuse = 1;
    int port;
    struct sockaddr_in addr;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        return 1;
    }
    port = atoi(argv[1]);

    signal(SIGINT, exit_server);
    signal(SIGPIPE, SIG_IGN);

    server_sd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sd < 0) { perror("socket"); return 1; }

    setsockopt(server_sd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(server_sd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(server_sd); return 1;
    }
    if (listen(server_sd, 5) < 0) {
        perror("listen"); close(server_sd); return 1;
    }

    signal(SIGCHLD, SIG_IGN);

    for (;;) {
        struct sockaddr cli;
        socklen_t       cli_len = sizeof(cli);
        int             fd;
        pid_t           pid;

        fd = accept(server_sd, &cli, &cli_len);
        if (fd < 0) { perror("accept"); continue; }

        pid = fork();
        if (pid < 0) { perror("fork"); close(fd); continue; }

        if (pid == 0) {
            volatile int child_fd = fd;
            close(server_sd);
            if (!do_pow(child_fd)) {
                const char msg[] = "pow";
                send_frame(child_fd, "PWNO", msg, sizeof(msg) - 1);
                close(child_fd);
                _exit(0);
            }
            if (check_username(child_fd)) {
                const char ok[] = "Captain found!\n";
                send_frame(child_fd, "CAP1", ok, sizeof(ok) - 1);
            }
            close(child_fd);
            _exit(0);
        }

        close(fd);
    }
    return 0;
}
