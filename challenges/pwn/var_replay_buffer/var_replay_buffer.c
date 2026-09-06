#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NSLOTS          8
#define REPLAY_DATA_SZ  240

typedef struct Replay Replay;
typedef void (*play_fn)(Replay *);

struct Replay {
    char    data[REPLAY_DATA_SZ];
    play_fn playback;
    long    ref_id;
};

static Replay *reel[NSLOTS];

static void live_feed(Replay *r) {
    printf("  [LIVE #%ld] %.64s\n", r->ref_id, r->data);
}

static void highlight_reel(Replay *r) {
    printf("  [HIGHLIGHT #%ld]\n  ", r->ref_id);
    puts(r->data);
}

__attribute__((used))
static void ref_verdict(Replay *r) {
    (void)r;
    char buf[128] = {0};
    FILE *f = fopen("flag.txt", "r");
    if (!f) { puts("  [VAR OFFLINE]"); exit(1); }
    if (!fgets(buf, sizeof(buf) - 1, f)) { fclose(f); exit(1); }
    fclose(f);
    puts("");
    puts("  ╔══════════════════════════════════════════╗");
    puts("  ║        REFEREE'S FINAL VERDICT           ║");
    puts("  ╚══════════════════════════════════════════╝");
    printf("  %s\n", buf);
    exit(0);
}

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

static void banner(void) {
    puts("");
    puts("  ╔══════════════════════════════════════════╗");
    puts("  ║   VAR REPLAY BUFFER — InfoDays 2026      ║");
    puts("  ╠══════════════════════════════════════════╣");
    puts("  ║  1) Create replay                        ║");
    puts("  ║  2) Edit replay tag                      ║");
    puts("  ║  3) Compress feed   (press-room only)    ║");
    puts("  ║  4) Play replay                          ║");
    puts("  ║  5) Retire replay                        ║");
    puts("  ║  6) Leave the booth                      ║");
    puts("  ╚══════════════════════════════════════════╝");
    printf("  choice> ");
}

static void op_create(void) {
    printf("  slot: ");
    int i = read_int();
    if (i < 0 || i >= NSLOTS || reel[i]) { puts("  [!] invalid slot"); return; }
    printf("  feed type (1=live, 2=highlight): ");
    int k = read_int();
    if (k != 1 && k != 2) { puts("  [!] unknown feed"); return; }

    reel[i] = calloc(1, sizeof(Replay));
    if (!reel[i]) exit(1);
    reel[i]->playback = (k == 1) ? live_feed : highlight_reel;
    reel[i]->ref_id   = i * 7 + 42;

    printf("  tag: ");
    char tag[64];
    read_line(tag, sizeof(tag));
    strncpy(reel[i]->data, tag, 63);
    puts("  [+] replay created");
}

static void op_edit(void) {
    printf("  slot: ");
    int i = read_int();
    if (i < 0 || i >= NSLOTS || !reel[i]) { puts("  [!] invalid slot"); return; }
    printf("  new tag: ");
    char tag[64];
    read_line(tag, sizeof(tag));
    memset(reel[i]->data, 0, 64);
    strncpy(reel[i]->data, tag, 63);
    puts("  [+] tag updated");
}

static void op_compress(void) {
    printf("  slot: ");
    int i = read_int();
    if (i < 0 || i >= NSLOTS || !reel[i]) { puts("  [!] invalid slot"); return; }

    printf("  raw-feed bytes: ");
    int n = read_int();
    if (n <= 0 || n > 0x200) { puts("  [!] impossible length"); return; }

    printf("  paste feed now:\n");
    ssize_t got = read(0, reel[i]->data, (size_t)n);
    if (got <= 0) exit(0);
    printf("  [+] compressed %zd bytes\n", got);
}

static void op_play(void) {
    printf("  slot: ");
    int i = read_int();
    if (i < 0 || i >= NSLOTS || !reel[i]) { puts("  [!] invalid slot"); return; }
    reel[i]->playback(reel[i]);
}

static void op_retire(void) {
    printf("  slot: ");
    int i = read_int();
    if (i < 0 || i >= NSLOTS || !reel[i]) { puts("  [!] invalid slot"); return; }
    free(reel[i]);
    reel[i] = NULL;
    puts("  [+] replay retired");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);
    alarm(180);

    puts("");
    puts("  Welcome to the VAR Replay Buffer.");
    puts("  Only verified officials may compress raw feeds.");

    for (;;) {
        banner();
        switch (read_int()) {
            case 1: op_create();   break;
            case 2: op_edit();     break;
            case 3: op_compress(); break;
            case 4: op_play();     break;
            case 5: op_retire();   break;
            case 6: puts("  goodbye."); return 0;
            default: puts("  [!] unknown choice");
        }
    }
}
