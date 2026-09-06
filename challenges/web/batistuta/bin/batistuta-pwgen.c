/*
 * batistuta-pwgen — mint a 20-char temporary password.
 * Seeds libc rand() with gettimeofday(tv_sec*1000 + tv_usec/1000).
 * Internal tool used by the squad's vault reset flow.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

static const char *CHARSET =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

static void generate_password(unsigned int seed) {
    char pw[21];
    srand(seed);
    for (int i = 0; i < 20; i++) {
        pw[i] = CHARSET[rand() % 62];
    }
    pw[20] = '\0';
    puts(pw);
}

int main(int argc, char **argv) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    generate_password((unsigned int)(tv.tv_sec * 1000 + tv.tv_usec / 1000));
    return 0;
}
