/* Harmless program whose SHA-256 the tests put on the blocklist. */
#include <stdio.h>

int main(void) {
    puts("this should have been blocked: pathguard blocklist sample 51c2");
    return 0;
}
