/*
 *  SHANKS — InfoDays 2026 CTF  (Insane)
 *
 *  Pirate crew roster manager.  The captain keeps a ledger of crew
 *  members in fixed-size heap chunks.  Several bugs lurk:
 *
 *    1. Double-free: "dismiss" zeroes the slot only AFTER the menu
 *       re-prints, so a fast second dismiss on the same slot before
 *       any allocation happens triggers a double-free → tcache dup.
 *
 *    2. Heap overflow in "promote": writing the new title reads up
 *       to 0x100 bytes into a 0x58-byte inline buffer, smashing the
 *       next chunk's metadata + fd pointer.
 *
 *    3. Use-After-Free in "inspect": slot pointer is not NULLed
 *       immediately; reading a dismissed crew member leaks heap/libc.
 *
 *  Intended chain (glibc 2.35, Ubuntu 22.04):
 *    • Leak heap via UAF inspect
 *    • Tcache-dup or overflow to hijack fd → __free_hook / return-addr
 *    • Overwrite with win() gadget address (or one-gadget)
 *    • Trigger free → shell / flag
 *
 *  But since full RELRO + PIE + canaries are on, the easiest path is:
 *    1. UAF-inspect to leak libc (unsorted-bin fd from a larger chunk)
 *    2. Overflow "promote" to poison tcache fd → _IO_list_all or
 *       environ (stack leak) → ROP
 *    3. Or: overflow to smash a function pointer stored in the struct
 *       and redirect to the hidden shanks_verdict() that reads the flag
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_CREW    8
#define NAME_SZ     0x40
#define TITLE_SZ    0x58
#define BIO_SZ      0x200

typedef struct Crew Crew;
typedef void (*action_fn)(Crew *);

struct Crew {
    char      name[NAME_SZ];       /* 0x00 */
    char      title[TITLE_SZ];     /* 0x40 */
    action_fn on_inspect;          /* 0x98 */
    long      bounty;              /* 0xa0 */
    char     *bio;                 /* 0xa8  — separate heap alloc */
};

static Crew *roster[MAX_CREW];
static int   dismissed[MAX_CREW];  /* lazy clear — the bug */

/* ── normal callbacks ─────────────────────────────────────────── */

static void inspect_normal(Crew *c) {
    printf("  Name   : %s\n", c->name);
    printf("  Title  : %s\n", c->title);
    printf("  Bounty : %ld beri\n", c->bounty);
    if (c->bio)
        printf("  Bio    : %s\n", c->bio);
}

/* ── hidden win function ──────────────────────────────────────── */

__attribute__((used))
static void shanks_verdict(Crew *c) {
    (void)c;
    char buf[128] = {0};
    FILE *f = fopen("flag.txt", "r");
    if (!f) { puts("  [The Red Hair Pirates have left.]"); exit(1); }
    if (!fgets(buf, sizeof(buf) - 1, f)) { fclose(f); exit(1); }
    fclose(f);
    puts("");
    puts("  ╔══════════════════════════════════════════════════╗");
    puts("  ║   SHANKS: \"I bet my arm on the new era.\"         ║");
    puts("  ╚══════════════════════════════════════════════════╝");
    printf("  %s\n", buf);
    exit(0);
}

/* ── I/O helpers ──────────────────────────────────────────────── */

static int read_int(void) {
    int v, c;
    if (scanf("%d", &v) != 1) exit(0);
    while ((c = getchar()) != '\n' && c != EOF) {}
    return v;
}

static void read_line(char *dst, size_t cap) {
    if (!fgets(dst, (int)cap, stdin)) exit(0);
    dst[strcspn(dst, "\n")] = 0;
}

/* ── menu operations ──────────────────────────────────────────── */

static void op_recruit(void) {
    printf("  slot [0-%d]: ", MAX_CREW - 1);
    int i = read_int();
    if (i < 0 || i >= MAX_CREW || roster[i]) {
        puts("  [!] slot taken or invalid"); return;
    }

    roster[i] = calloc(1, sizeof(Crew));
    if (!roster[i]) exit(1);
    roster[i]->on_inspect = inspect_normal;
    roster[i]->bounty     = (i + 1) * 100000000L;
    dismissed[i] = 0;

    printf("  name: ");
    read_line(roster[i]->name, NAME_SZ);

    printf("  title: ");
    read_line(roster[i]->title, TITLE_SZ);

    printf("  add bio? (y/n): ");
    char yn[4];
    read_line(yn, sizeof(yn));
    if (yn[0] == 'y' || yn[0] == 'Y') {
        roster[i]->bio = malloc(BIO_SZ);
        if (!roster[i]->bio) exit(1);
        printf("  bio: ");
        read_line(roster[i]->bio, BIO_SZ);
    }

    puts("  [+] crew member recruited");
}

/* BUG: promote writes up to 0x100 into title[0x58] → heap overflow */
static void op_promote(void) {
    printf("  slot: ");
    int i = read_int();
    if (i < 0 || i >= MAX_CREW || !roster[i]) {
        puts("  [!] invalid"); return;
    }
    printf("  new title (max 256): ");
    /* Intentional overflow: title is only 0x58 bytes but we read 0x100 */
    ssize_t got = read(0, roster[i]->title, 0x100);
    if (got <= 0) exit(0);
    printf("  [+] promoted — %zd bytes written\n", got);
}

/* BUG: inspect after dismiss → UAF read (leaks heap / libc) */
static void op_inspect(void) {
    printf("  slot: ");
    int i = read_int();
    if (i < 0 || i >= MAX_CREW || !roster[i]) {
        puts("  [!] invalid"); return;
    }
    roster[i]->on_inspect(roster[i]);
}

/* BUG: double-dismiss possible because slot NULLed lazily */
static void op_dismiss(void) {
    printf("  slot: ");
    int i = read_int();
    if (i < 0 || i >= MAX_CREW || !roster[i]) {
        puts("  [!] invalid"); return;
    }
    if (roster[i]->bio) {
        free(roster[i]->bio);
        roster[i]->bio = NULL;
    }
    free(roster[i]);
    /* BUG: slot pointer cleared only after next menu print, not here.
       A second dismiss before any alloc → double free. */
    dismissed[i] = 1;
}

static void lazy_clear(void) {
    for (int i = 0; i < MAX_CREW; i++) {
        if (dismissed[i]) {
            roster[i] = NULL;
            dismissed[i] = 0;
        }
    }
}

/* ── web splash (served by wrapper, not this binary) ──────────── */

static void banner(void) {
    puts("");
    puts("  ╔══════════════════════════════════════════════════╗");
    puts("  ║     SHANKS — Red Hair Pirates Crew Roster        ║");
    puts("  ║                 InfoDays 2026                     ║");
    puts("  ╠══════════════════════════════════════════════════╣");
    puts("  ║  1) Recruit crew member                          ║");
    puts("  ║  2) Promote (update title)                       ║");
    puts("  ║  3) Inspect crew member                          ║");
    puts("  ║  4) Dismiss crew member                          ║");
    puts("  ║  5) Set sail                                     ║");
    puts("  ╚══════════════════════════════════════════════════╝");
    printf("  choice> ");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);
    alarm(180);

    puts("");
    puts("  Welcome aboard the Red Force.");
    puts("  Only the captain decides who stays.");

    for (;;) {
        lazy_clear();
        banner();
        switch (read_int()) {
            case 1: op_recruit();  break;
            case 2: op_promote();  break;
            case 3: op_inspect();  break;
            case 4: op_dismiss();  break;
            case 5: puts("  The Red Force sets sail. Farewell."); return 0;
            default: puts("  [!] unknown order");
        }
    }
}
