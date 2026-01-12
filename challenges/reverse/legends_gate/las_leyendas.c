#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ptrace.h>

void secure_gate() {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
        exit(1);
    }
}

int main() {
    secure_gate();
    char input[50];
    unsigned char secret[] = {0x6e, 0x16, 0x17, 0x7d, 0x6e, 0x11, 0x5b, 0x11, 0x4c, 0x46, 0x16, 0x17, 0x03};
    int len = 13;

    printf("--- ENSA Agadir: Legendary Access ---\n");
    printf("Code: ");
    
    if (fgets(input, sizeof(input), stdin)) {
        input[strcspn(input, "\n")] = 0;

        int valid = 1;
        if (strlen(input) != len) valid = 0;

        for (int i = 0; i < len && valid; i++) {
            if ((input[i] ^ 0x22) != secret[i]) {
                valid = 0;
            }
        }

        if (valid) {
            printf("[+] Legend Verified! Flag: INFODAYS{RE_15_NOT_GU3551NG_2026}\n");
        } else {
            printf("[!] Unauthorized.\n");
        }
    }
    return 0;
}
