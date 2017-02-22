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
#include <unistd.h>
#include <fcntl.h>

#include "nanoecc/ecc.h"

#define secp128r1 16
#define secp192r1 24
#define secp256r1 32
#define secp384r1 48
#define ECC_CURVE secp256r1


#if (ECC_CURVE != secp192r1 && ECC_CURVE != secp256r1 \
    && ECC_CURVE != secp384r1)
    #error "Must define ECC_CURVE to one of the available curves"
#endif

#define NUM_ECC_DIGITS ECC_CURVE

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;
  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new())) printf("\nErro EVP_CIPHER_CTX_new\n");
  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    printf("\nError EVP_EncryptInit\n");
  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    printf("\nError EVP_EncryptUpdate\n");
  ciphertext_len = len;
  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) 
    printf("\nError EVP_EncryptFinal_ex\n");
  ciphertext_len += len;
  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, 
  unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new())) 
    printf("\nError EVP_CIPHER_CTX_new\n");
  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    printf("\nError EVP_DecryptInit_ex\n");
  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    printf("\nError EVP_DecryptUpdate\n");
    plaintext_len = len;
    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) 
    printf("\nError EVP_DecriptFinal\n");
  plaintext_len += len;
  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}

//Calculates the length of a decoded string
size_t calcDecodeLength(const char* b64input) { 
	size_t len = strlen(b64input), 
    padding = 0;
  //last two chars are =
	if (b64input[len-1] == '=' && b64input[len-2] == '=') 
		padding = 2;
	else if (b64input[len-1] == '=') //last char is =
		padding = 1;
	return (len*3)/4 - padding;
}

void derive_secret(uint8_t stpubx[],uint8_t stpuby[],
  uint8_t lcpriv[],uint8_t lcpubx[],  uint8_t lcpuby[], uint8_t secret[])
{
    //bignums for storing key values
    // private local key
    BIGNUM *prv = BN_bin2bn(lcpriv, NUM_ECC_DIGITS, NULL);
    
    // public local key
    BIGNUM *locx = BN_bin2bn(lcpubx, NUM_ECC_DIGITS, NULL);
    BIGNUM *locy = BN_bin2bn(lcpuby, NUM_ECC_DIGITS, NULL);
    
    // public imported key
    BIGNUM *pubx = BN_bin2bn(stpubx, NUM_ECC_DIGITS, NULL);
    BIGNUM *puby = BN_bin2bn(stpuby, NUM_ECC_DIGITS, NULL);
    
    //EC_KEY stores a public key (and optionally a private as well)
    // myecc is the local key pair, peerecc is the public imported key
    EC_KEY            *myecc  = NULL, *peerecc = NULL;
    EVP_PKEY          *pkey   = NULL, *peerkey = NULL;
    
    //Initializing EC POINT on public imported key
    EC_GROUP *curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    
    //ECC point on public imported key
    EC_POINT *ptimport = EC_POINT_new(curve);
    
    //ECC point on public local key
    EC_POINT *ptlocal = EC_POINT_new(curve);
    BN_CTX *bnctx = BN_CTX_new();
    
    EC_POINT_set_affine_coordinates_GFp(curve, ptimport, pubx, puby, bnctx);
    EC_POINT_set_affine_coordinates_GFp(curve, ptlocal, locx, locy, bnctx);
    
    /* ---------------------------------------------------------- *
    *                Creating keys from curve                      *
    * ---------------------------------------------------------- */
    if (NULL == (myecc = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1))){
        printf("Error creating local key");
    }
    if (NULL == (peerecc = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1))){
        printf("Error creating imported public key");
    }

    /* ------------------------------------------------------------ *
   * Certificate sign using OPENSSL_EC_NAMED_CURVE flag             *
   * ---------------------------------------------------------------*/
    EC_KEY_set_asn1_flag(myecc, OPENSSL_EC_NAMED_CURVE);
    EC_KEY_set_asn1_flag(peerecc, OPENSSL_EC_NAMED_CURVE);
    //Setting public keys (local and imported) on EC_KEY
    if (1 != EC_KEY_set_public_key(myecc, ptlocal)) 
      printf("Error setting public local key");
    if (1 != EC_KEY_set_public_key(peerecc, ptimport)) 
      printf("Error setting imported public key");
    //Setting private local key on EC_KEY
    if (1 != EC_KEY_set_private_key(myecc, prv)) 
      printf("Error setting private key");
    //Creating EVP_KEY struct to derive shared secret
    peerkey=EVP_PKEY_new();
    if (!EVP_PKEY_assign_EC_KEY(peerkey,peerecc))
      printf("Error sign peerkey");
    pkey=EVP_PKEY_new();
    if (!EVP_PKEY_assign_EC_KEY(pkey,myecc))
      printf("Error sign pkey");
    //shared secret context
    EVP_PKEY_CTX *ctx;
    //shared secret
    unsigned char *skey;
    //shared secret buffersize
    size_t skeylen;
    /* Generating context for shared secret derivation */
    if (NULL == (ctx = EVP_PKEY_CTX_new(pkey, NULL))) 
      printf("Error generating shared secret ctx");
    /* Initializing context */
    if (1 != EVP_PKEY_derive_init(ctx)) 
      printf("Error initalizing derivaton");
    /* Setting imported public key onto derivation */
    if (1 != EVP_PKEY_derive_set_peer(ctx, peerkey)) 
      printf("Error setting peer key");
    /* Dynamically allocating buffer size */
    if (EVP_PKEY_derive(ctx, NULL, &skeylen) <= 0) 
      printf("Error allocating buffer size");
    skey = OPENSSL_malloc(skeylen);
    /* Derive sahred secret */
    if (1 != (EVP_PKEY_derive(ctx, skey, &skeylen))) 
      printf("Error deriving secret");
    //Printing Shared Secret
    memcpy(secret, skey, skeylen);
  
  /* ---------------------------------------------------------- *
   *                Freeing structs                             *
   * ---------------------------------------------------------- */
    EVP_cleanup();
    ERR_free_strings();
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peerkey);
    EVP_PKEY_free(pkey);
    //EC_KEY_free(myecc); Causing double free error:Unknown reason
    //EC_KEY_free(peerecc); Causing segmentation fault:Unknown reason
    EC_POINT_free(ptlocal);
    EC_POINT_free(ptimport);
    BN_CTX_free(bnctx);
}

extern void EccPoint_mult(EccPoint *p_result, EccPoint *p_point, uint8_t *p_scalar);

void vli_print(uint8_t *p_vli)
{
    unsigned i;
    for (i=0; i<NUM_ECC_DIGITS-1; ++i){
      printf("0x%02X, ", (unsigned)p_vli[i]);
    }
    printf("0x%02X", (unsigned)p_vli[i]);
}

void getRandomBytes(int randfd, void *p_dest, unsigned p_size)
{  
    if(read(randfd, p_dest, p_size) != (int)p_size){
      printf("Failed to get random bytes.\n");
    }
}

int generate_keys(uint8_t *keys)
{
    int randfd;
    unsigned l_num = 1;
    randfd = open("/dev/urandom", O_RDONLY);
    if (randfd == -1)
    {
      printf("No access to urandom\n");
      return 0;
    }
    uint8_t l_private[NUM_ECC_DIGITS];
    EccPoint l_public;
    int success=0, count=0;
    //if make_keys fails, try renew random values and retry
    while (!success){
      count++;
      getRandomBytes(randfd,(char*)l_private, NUM_ECC_DIGITS*sizeof(uint8_t));
      success = ecc_make_key(&l_public, l_private, l_private);
      if (count >10){
        printf("Error: Cannot generate ecc key! Something went wrong.\n");
      }
    }
    memcpy(keys, l_private, NUM_ECC_DIGITS);
    memcpy(keys+NUM_ECC_DIGITS, l_public.x, NUM_ECC_DIGITS);
    memcpy(keys+(NUM_ECC_DIGITS*2), l_public.y, NUM_ECC_DIGITS);
    return 1;
}

void gen_keys_ino(uint8_t *private, uint8_t *public)
{
    EccPoint point;
    memcpy(public, point.x, NUM_ECC_DIGITS);
    memcpy(public+NUM_ECC_DIGITS, point.y, NUM_ECC_DIGITS);
    if (ecc_make_key(&point, private, private)==0){
      printf("Error: Cannot generate keys. Please try another random seed.\n");
    }
}
