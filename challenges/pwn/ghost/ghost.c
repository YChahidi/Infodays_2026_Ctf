/*
 * ghost.c -- INFODAYS CTF Finals
 * Challenge: Ghost Protocol
 *
 * Build (inside Docker):
 *   gcc -o ghost ghost.c -fno-pie -no-pie -fno-stack-protector -m64 -O0
 *
 * Protections:
 *   NX:      ON  (no shellcode)
 *   PIE:     OFF (fixed binary base -- stable ROP gadgets)
 *   ASLR:    ON  (libc base is random)
 *   Canary:  OFF (clean overflow)
 *
 * Intended path:
 *   1. Spot decoy overflow in handle_login() -> win() is a trap (random key).
 *   2. Find real overflow in process_command() via read(0, cmd, 256) into cmd[64].
 *   3. Leak libc: ROP chain calls puts(puts@got) -> compute libc base.
 *   4. ret2libc: system("/bin/sh") with libc gadgets.
 *   5. Shell -> cat /flag.txt
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * protocol_teardown -- "comms cleanup routine"
 * Actually plants pop rdi ; ret into the binary as a ROP gadget.
 * Without this, the binary has <6 gadgets and Stage 1 is impossible.
 * Players will find it during gadget hunting -- that is fine and intended.
 */
void __attribute__((used)) __attribute__((noinline)) protocol_teardown(void) {
    __asm__ __volatile__ (
        "pop %rdi\n\t"
        "ret\n\t"
    );
}

/* Decoy: looks like the goal. system() is exported to lure grep/auto-tools. */
void __attribute__((used)) decoy_shell(void) {
    puts("[*] Initializing secure shell...");
    system("/bin/sh");   /* unreachable in any normal flow */
}

/* Fake win -- checks a runtime random key you cannot know. Dead end. */
void __attribute__((used)) win(void) {
    char key[8];
    puts("[!] Backdoor triggered.");
    printf("Enter override key: ");
    fflush(stdout);
    fgets(key, sizeof(key), stdin);
    extern char _ghost_key[8];
    if (memcmp(key, _ghost_key, 8) == 0) {
        puts("[+] Access granted.");
        char buf[64];
        FILE *f = fopen("/flag.txt", "r");
        if (f) { fgets(buf, 64, f); puts(buf); fclose(f); }
    } else {
        puts("[-] Wrong key. Connection closed.");
        exit(1);
    }
}

/* Runtime random key -- seeded at start, never reachable via win(). */
char _ghost_key[8];

void init_key(void) {
    FILE *f = fopen("/dev/urandom", "r");
    if (f) { fread(_ghost_key, 1, 8, f); fclose(f); }
}

/*
 * handle_login -- DECOY overflow.
 * gets(username) overflows into password then rbp then rip -> win().
 * win() requires the random key -> impossible. AI will fixate here.
 */
void handle_login(void) {
    char username[64];
    char password[32];

    printf("Username: ");
    fflush(stdout);
    gets(username);   /* decoy overflow -- leads to win() which needs random key */

    printf("Password: ");
    fflush(stdout);
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0;

    /* Hardcoded password -- intentional, lets player reach the real vuln. */
    if (strcmp(password, "ghostop") == 0) {
        puts("[+] Authentication successful.");
    } else {
        puts("[-] Access denied.");
        exit(0);
    }
}

/*
 * process_command -- REAL overflow.
 * cmd[64] but read() accepts 256 bytes -> clean RIP overwrite, no canary.
 */
void process_command(void) {
    char cmd[64];
    size_t n;

    printf("\nghostshell> ");
    fflush(stdout);

    n = read(0, cmd, 256);   /* <-- real vulnerability */
    if (n <= 0) return;

    if (cmd[n-1] == '\n') cmd[n-1] = 0;

    if      (strncmp(cmd, "status", 6) == 0) puts("[*] System nominal. All nodes operational.");
    else if (strncmp(cmd, "agents", 6) == 0) puts("[*] Active agents: SHADOW, VIPER, GHOST");
    else if (strncmp(cmd, "help",   4) == 0) puts("Commands: status | agents | transmit | exit");
    else if (strncmp(cmd, "exit",   4) == 0) { puts("[*] Disconnecting."); exit(0); }
    else { printf("[?] Unknown command: %s\n", cmd); fflush(stdout); }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    init_key();

    puts("===========================================");
    puts("   GHOST PROTOCOL -- Secure Command Link  ");
    puts("===========================================");
    puts("[*] Encrypted channel established.");
    puts("[*] Identity verification required.\n");

    handle_login();
    process_command();

    return 0;
}
