#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void play_match() {
    char comment[256];
    char *flag = NULL;
    char *flag_ptr = NULL;
    FILE *f = fopen("flag.txt", "r");
    
    if (f == NULL) {
        printf("Flag file missing!\n");
        exit(1);
    }
    
    // Flag on HEAP (not stack!)
    flag = malloc(128);
    fgets(flag, 128, f);
    fclose(f);
    
    // Store flag pointer on stack
    flag_ptr = flag;
    
    printf("\n");
    printf("╔════════════════════════════════════════╗\n");
    printf("║     VAR Review System - 2030 Edition   ║\n");
    printf("╠════════════════════════════════════════╣\n");
    printf("║  Enter your controversial comment      ║\n");
    printf("║  about the referee's decision:         ║\n");
    printf("╚════════════════════════════════════════╝\n");
    printf("\n>> ");
    
    fgets(comment, sizeof(comment), stdin);
    comment[strcspn(comment, "\n")] = 0;
    
    printf("\n");
    printf("┌────────────────────────────────────────┐\n");
    printf("│ Referee's Response:                    │\n");
    printf("├────────────────────────────────────────┤\n");
    printf("│ ");
    
    // FORMAT STRING VULNERABILITY
    printf(comment);
    
    printf("\n└────────────────────────────────────────┘\n");
    
    free(flag);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    play_match();
    return 0;
}
