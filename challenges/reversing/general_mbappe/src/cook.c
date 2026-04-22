/*
 *  GENERAL MBAPPE — InfoDays 2026 CTF  (Reversing, Hard)
 *  Author: saamnolimits
 *
 *  Kitchen-ISA interpreter with a SIDE-CHANNEL spice input.  The
 *  cook takes two arguments:
 *
 *      ./cook recipe.asm spice.bin
 *
 *  spice.bin is a 32-byte blob that becomes the permutation lookup
 *  table at mem[0xA0..0xBF].  The recipe references it via indirect
 *  memory loads — reading the recipe alone will not tell you what
 *  shuffle le general is applying.  The spice bytes are NOT in the
 *  recipe source, NOT in this binary, and NOT in any text artefact
 *  shipped in the player's zip.  Find the spice.
 *
 *  Registers (uint8_t):
 *    VEGETABLE, FRUIT, MEAT, DAIRY  — general scratch
 *    CARBO                           — memory pointer (mem[CARBO])
 *    INDEX                           — auxiliary counter
 *    TMP, LADLE                      — extra scratch
 *
 *  Memory layout after setup:
 *    mem[0x00..0x1F]  player's 32-byte guess
 *    mem[0x20..0x3F]  scratch (used by recipe)
 *    mem[0x40..0x5F]  key-load region (red herring, retained)
 *    mem[0x80..0x9F]  verbatim copy of the guess (for success echo)
 *    mem[0xA0..0xBF]  SPICE — the 32-byte permutation table
 *
 *  ISA (one instruction per line, ';' starts a comment):
 *    AES256     <imm>              ; putchar(imm)
 *    BOIL       <reg>, <imm>       ; reg = imm
 *    MOVR       <dst>, <src>       ; dst = src
 *    QUICKMAFFS <reg>, <op>, <imm> ; op in {ADD,SUB,XOR}
 *    GOODBYE    <reg>              ; reg = mem[CARBO]; CARBO += 1
 *    WINDOW     <reg>              ; mem[CARBO] = reg; CARBO += 1
 *    LADDER     <reg>, <imm>, <lbl>; if reg != imm goto lbl
 *    HALT       <code>             ; exit(code)
 *    FLAMBE                         ; no-op — flavour text
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <ctype.h>
#include <unistd.h>

#define MEM_SZ    256
#define MAX_LINES 4096
#define MAX_LABELS 128
#define MAX_LINE  256

enum { R_VEGETABLE=0, R_FRUIT, R_MEAT, R_DAIRY, R_CARBO, R_INDEX, R_TMP, R_LADLE, R_COUNT };

static const char *REG_NAMES[] = {
    "VEGETABLE", "FRUIT", "MEAT", "DAIRY", "CARBO", "INDEX", "TMP", "LADLE"
};

static uint8_t mem[MEM_SZ];
static uint8_t regs[R_COUNT];

static char   *lines[MAX_LINES];
static int     nlines;

static struct { char name[64]; int line; } labels[MAX_LABELS];
static int     nlabels;

static int reg_id(const char *s) {
    for (int i = 0; i < R_COUNT; i++) if (!strcasecmp(s, REG_NAMES[i])) return i;
    return -1;
}

static long parse_imm(const char *s) {
    return (long)strtol(s, NULL, 0);
}

static int label_line(const char *name) {
    for (int i = 0; i < nlabels; i++) if (!strcmp(labels[i].name, name)) return labels[i].line;
    return -1;
}

static char *trim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) *--e = 0;
    return s;
}

static void strip_comment(char *s) {
    char *c = strchr(s, ';');
    if (c) *c = 0;
}

static void load_recipe(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { perror("recipe"); exit(2); }
    char buf[MAX_LINE];
    while (fgets(buf, sizeof(buf), f)) {
        if (nlines >= MAX_LINES) { fprintf(stderr, "recipe too long\n"); exit(2); }
        strip_comment(buf);
        char *t = trim(buf);
        lines[nlines++] = strdup(t);
    }
    fclose(f);

    for (int i = 0; i < nlines; i++) {
        char *L = lines[i];
        size_t n = strlen(L);
        if (n >= 2 && L[n-1] == ':') {
            if (nlabels >= MAX_LABELS) { fprintf(stderr, "too many labels\n"); exit(2); }
            size_t take = (n - 1 < sizeof(labels[nlabels].name) - 1)
                          ? n - 1 : sizeof(labels[nlabels].name) - 1;
            memcpy(labels[nlabels].name, L, take);
            labels[nlabels].name[take] = 0;
            labels[nlabels].line = i;
            nlabels++;
        }
    }
}

static int tokenise(char *line, char *tok[8]) {
    int n = 0;
    char *p = line;
    while (*p && n < 8) {
        while (*p && (isspace((unsigned char)*p) || *p == ',')) p++;
        if (!*p) break;
        tok[n++] = p;
        while (*p && !isspace((unsigned char)*p) && *p != ',') p++;
        if (*p) { *p = 0; p++; }
    }
    return n;
}

static void apply_math(int r, const char *op, long v) {
    if      (!strcasecmp(op, "ADD")) regs[r] = (uint8_t)(regs[r] + v);
    else if (!strcasecmp(op, "SUB")) regs[r] = (uint8_t)(regs[r] - v);
    else if (!strcasecmp(op, "XOR")) regs[r] = (uint8_t)(regs[r] ^ v);
    else { fprintf(stderr, "unknown math op: %s\n", op); exit(2); }
}

static int execute(void) {
    int ip = 0;
    while (ip < nlines) {
        char work[MAX_LINE];
        strncpy(work, lines[ip], sizeof(work)-1);
        work[sizeof(work)-1] = 0;
        char *tok[8];
        int n = tokenise(work, tok);
        if (n == 0) { ip++; continue; }
        if (n == 1 && tok[0][strlen(tok[0])-1] == ':') { ip++; continue; }

        const char *mn = tok[0];
        if (!strcasecmp(mn, "AES256") && n == 2) {
            putchar((int)parse_imm(tok[1]));
            fflush(stdout);
        } else if (!strcasecmp(mn, "BOIL") && n == 3) {
            int r = reg_id(tok[1]);
            if (r < 0) { fprintf(stderr, "bad reg: %s\n", tok[1]); return 2; }
            regs[r] = (uint8_t)parse_imm(tok[2]);
        } else if (!strcasecmp(mn, "MOVR") && n == 3) {
            int d = reg_id(tok[1]);
            int s = reg_id(tok[2]);
            if (d < 0 || s < 0) { fprintf(stderr, "bad reg\n"); return 2; }
            regs[d] = regs[s];
        } else if (!strcasecmp(mn, "QUICKMAFFS") && n == 4) {
            int r = reg_id(tok[1]);
            if (r < 0) { fprintf(stderr, "bad reg: %s\n", tok[1]); return 2; }
            apply_math(r, tok[2], parse_imm(tok[3]));
        } else if (!strcasecmp(mn, "GOODBYE") && n == 2) {
            int r = reg_id(tok[1]);
            if (r < 0) { fprintf(stderr, "bad reg: %s\n", tok[1]); return 2; }
            regs[r] = mem[regs[R_CARBO]];
            regs[R_CARBO]++;
        } else if (!strcasecmp(mn, "WINDOW") && n == 2) {
            int r = reg_id(tok[1]);
            if (r < 0) { fprintf(stderr, "bad reg: %s\n", tok[1]); return 2; }
            mem[regs[R_CARBO]] = regs[r];
            regs[R_CARBO]++;
        } else if (!strcasecmp(mn, "LADDER") && n == 4) {
            int r = reg_id(tok[1]);
            if (r < 0) { fprintf(stderr, "bad reg: %s\n", tok[1]); return 2; }
            long imm = parse_imm(tok[2]);
            if (regs[r] != (uint8_t)imm) {
                int t = label_line(tok[3]);
                if (t < 0) { fprintf(stderr, "unknown label: %s\n", tok[3]); return 2; }
                ip = t;
                continue;
            }
        } else if (!strcasecmp(mn, "FLAMBE") && n == 1) {
            /* no-op flavour instruction */
        } else if (!strcasecmp(mn, "HALT") && n == 2) {
            return (int)parse_imm(tok[1]);
        } else {
            fprintf(stderr, "parse error at line %d: '%s'\n", ip+1, lines[ip]);
            return 2;
        }
        ip++;
    }
    return 0;
}

static int load_spice(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror("spice"); return -1; }
    size_t got = fread(&mem[0xA0], 1, 32, f);
    fclose(f);
    if (got != 32) {
        fprintf(stderr, "spice must be exactly 32 bytes (got %zu)\n", got);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc < 3) {
        fprintf(stderr, "usage: %s recipe.asm spice.bin\n", argv[0]);
        fprintf(stderr, "  le general ne cuisine pas sans epices.\n");
        return 2;
    }
    const char *rpath = argv[1];
    const char *spath = argv[2];

    if (load_spice(spath) < 0) return 2;
    load_recipe(rpath);

    char in[128] = {0};
    printf("Enter the kitchen pass: ");
    fflush(stdout);
    if (!fgets(in, sizeof(in), stdin)) return 1;
    size_t L = strlen(in);
    while (L && (in[L-1] == '\n' || in[L-1] == '\r')) in[--L] = 0;

    for (int i = 0; i < 32; i++) {
        uint8_t b = (i < (int)L) ? (uint8_t)in[i] : 0;
        mem[0x00 + i] = b;
        mem[0x80 + i] = b;
    }

    int rc = execute();
    if (rc == 0) {
        printf("Le general sourit.  Access granted, capitaine.\n");
        printf("infodays{SaamNoLimits_");
        fwrite(&mem[0x80], 1, 32, stdout);
        printf("}\n");
        return 0;
    } else {
        printf("Le general fronce les sourcils.  Recette ratee.\n");
        return 1;
    }
}
