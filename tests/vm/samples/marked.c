/* Harmless program that contains the string matched by rules/pathguard_test.yar. */
#include <stdio.h>

static const char marker[] = "PATHGUARD-TEST-MARKER-7f3a9c";

int main(void) {
    printf("this should have been blocked: %s\n", marker);
    return 0;
}
