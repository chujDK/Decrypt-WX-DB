#include "decrypt.h"
#include "keyleak.h"
#include <cstdio>

int main(int argc, char* argv[]) {
    if (argc != 3) {
        return -1;
    }
    cipher_ctx* ctx;
    ctx = GetWXCipherContext();
    if (ctx == nullptr) {
        printf("[-] Failed to get cipher context\n");
        return -1;
    }

    DecryptWXDB(argv[1], argv[2], ctx);

    return 0;
}