#include "decrypt.h"
#include "keyleak.h"
#include <corecrt_wstdio.h>
#include <cstdio>
#include <Windows.h>


int main(int argc, char* argv[]) {
    if (argc != 3) {
        return -1;
    }
    cipher_ctx* ctx;
    fprintf(stdout, "[+] ready to decrypt %s\n", argv[1]);
    while (1) {
        ctx = GetWXCipherContext();
        if (ctx == nullptr) {
            fprintf(stderr, "[-] Failed to get cipher context, retry...\n");
        }
        if(DecryptWXDB(argv[1], argv[2], ctx)) {
            fprintf(stdout, "[+] decrypt successed\n");
            return 0;
        }
        Sleep(100);
    }

    return 0;
}