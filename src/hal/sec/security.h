#include <stdio.h>
#include <stdlib.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#ifdef __cplusplus
extern "C"{
#endif

int encrypt(unsigned char *plaintext, int plaintext_len,
	unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len,
	unsigned char *key, unsigned char *iv, unsigned char *plaintext);
void deriveSecret (uint8_t stpubx[],uint8_t stpuby[], uint8_t lcpriv[],
	uint8_t lcpubx[],  uint8_t lcpuby[], uint8_t secret[]);
int generateKeys(uint8_t *keys);
void encrypt_ino(uint8_t *key, uint8_t *cdata, size_t size);
void decrypt_ino(uint8_t *key, uint8_t *cdata, size_t size);

#ifdef __cplusplus
} // extern "C"
#endif

