#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned long hashcode = 0x21DD09EC;

unsigned long check_password(const char *p) {
    int *ip = (int *)p;
    int i;
    int res = 0;
    for (i = 0; i < 5; i++) {
        res += ip[i];
    }
    return res;
}

int main(int argc, char *argv[]) {
    // Allocate 20 bytes (5 * 4-byte integers)
    unsigned char input[20];

    // Fill with 0x06C5CEC8 (little-endian)
    int x = 0x21D8C5A8;
    int val = 0x00011111;
    for (int i = 0; i < 4; i++) {
        memcpy(&input[i * 4], &val, 4);
    }
    memcpy(&input[4 * 4], &x, 4);

    // No strlen check because this is binary, not a string
    if (check_password((char *)input) == hashcode) {
        printf("passcode is correct.\n");
    }
    else {
        printf("wrong passcode.\n");
    }

    return 0;
}
