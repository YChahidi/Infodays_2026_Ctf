#include <stdio.h>
#include <stdlib.h>

void play_match() {
    char flag[64];
    char comment[128];
    FILE *f = fopen("flag.txt", "r");

    if (f == NULL) {
        printf("Flag file is missing! Contact Admin.\n");
        exit(1);
    }

    // Read flag onto the STACK
    fgets(flag, sizeof(flag), f);
    fclose(f);

    printf("Welcome to the VAR Review System.\n");
    printf("Enter your comment on the last play: ");
    
    // Read user input
    fgets(comment, sizeof(comment), stdin);

    printf("\nReferee's Log: ");
    // VULNERABILITY: User input is passed directly as the format string
    printf(comment); 
    
    printf("\nReview complete.\n");
}

int main() {
    // Disable buffering so the player sees output immediately over the network
    setvbuf(stdout, NULL, _IONBF, 0);
    play_match();
    return 0;
}
