#ifndef BENCHMARK_ENCLAVE_T_H__
#define BENCHMARK_ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/random.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


int wc_sha256_init(Sha256* sha256);
int wc_sha256_update(Sha256* sha256, byte* buf, int bufSz);
int wc_sha256_final(Sha256* sha256, byte* digest);
int wc_aesgcm_setKey(Aes* aes, const byte* key, word32 len);
int wc_aesgcm_encrypt(Aes* aes, byte* out, const byte* in, word32 sz, const byte* iv, word32 ivSz, byte* authTag, word32 authTagSz, const byte* authIn, word32 authInSz);
int wc_aesgcm_decrypt(Aes* aes, byte* out, const byte* in, word32 sz, const byte* iv, word32 ivSz, const byte* authTag, word32 authTagSz, const byte* authIn, word32 authInSz);
int wc_rsa_encrypt(const byte* m, word32 mSz, byte* out, word32 outSz, RsaKey* key);
int wc_rsa_decrypt(const byte* in, word32 inSz, byte* out, word32 mSz, RsaKey* key);
int wc_rsa_init(RsaKey* rsa);
int wc_rsa_free(RsaKey* rsa);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
