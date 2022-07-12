#ifndef __DECRYPT_H__
#define __DECRYPT_H__
#include "wxstruct.h"
int DecryptWXDB(const char *szFile, const char *szOutput, struct cipher_ctx *ctx);
#endif