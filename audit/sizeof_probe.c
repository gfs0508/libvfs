#include "vfs_core.h"
#include <sodium.h>
#include <stdio.h>
int main(void){
  /* reproduce the packed struct exactly as in vfs_core.c to check sizeof */
  typedef struct {
    char magic[4]; uint8_t vm, vn;
    uint64_t ops, mem, payload_sz;
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    unsigned char hash[crypto_hash_sha256_BYTES];
  } __attribute__((packed)) H;
  printf("packed header sizeof = %zu bytes\n", sizeof(H));
  printf("SALTBYTES=%d NPUBBYTES=%d SHA256=%d\n",
         crypto_pwhash_SALTBYTES,
         crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
         crypto_hash_sha256_BYTES);
  return 0;
}
