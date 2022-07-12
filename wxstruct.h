#ifndef __WXSTRUCT_H__
#define __WXSTRUCT_H__
struct cipher_ctx{
  int derive_key;
  int pass_sz;
  unsigned char *key;
  unsigned char *hmac_key;
  unsigned char *pass;
  char *keyspec;
};
#endif