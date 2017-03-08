/*
 * Copyright (c) 2017, CESAR.
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the BSD license. See the LICENSE file for details.
 *
 */
#ifdef __cplusplus
extern "C" {
#endif

#define	EVP_CIPHER_CTX_NEW	1 /* Error creating context */
#define EVP_ENC_INIT		2 /* Error initializing encrypt function*/
#define EVP_ENC_UPDATE		3 /* Error updating encrypt function*/
#define EVP_ENC_FINAL		4 /* Error finilizing encrypt function*/
#define EVP_DEC_INIT		5 /* Error initializing decrypt function*/
#define EVP_DEC_UPDATE		6 /* Error updating decrypt function*/
#define EVP_DEC_FINAL		7 /* Error finilizing decrypt function*/
#define ECC_KEY_NEW		8 /* Error creating new local key */
#define ECC_KEY_SET_PUB_KEY	9 /* Error setting public key */
#define ECC_KEY_SET_PVT_KEY	9 /* Error setting private key */


#ifdef __cplusplus
}
#endif
