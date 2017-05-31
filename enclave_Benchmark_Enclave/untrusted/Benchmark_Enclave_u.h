#ifndef BENCHMARK_ENCLAVE_U_H__
#define BENCHMARK_ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfcrypt/test/test.h"
#include "wolfcrypt/benchmark/benchmark.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_current_time, (double* time));

sgx_status_t wc_sha256_init(sgx_enclave_id_t eid, int* retval, Sha256* sha256);
sgx_status_t wc_sha256_update(sgx_enclave_id_t eid, int* retval, Sha256* sha256, byte* buf, int bufSz);
sgx_status_t wc_sha256_final(sgx_enclave_id_t eid, int* retval, Sha256* sha256, byte* digest);
sgx_status_t wc_aesgcm_setKey(sgx_enclave_id_t eid, int* retval, Aes* aes, const byte* key, word32 len);
sgx_status_t wc_aesgcm_encrypt(sgx_enclave_id_t eid, int* retval, Aes* aes, byte* out, const byte* in, word32 sz, const byte* iv, word32 ivSz, byte* authTag, word32 authTagSz, const byte* authIn, word32 authInSz);
sgx_status_t wc_aesgcm_decrypt(sgx_enclave_id_t eid, int* retval, Aes* aes, byte* out, const byte* in, word32 sz, const byte* iv, word32 ivSz, const byte* authTag, word32 authTagSz, const byte* authIn, word32 authInSz);
sgx_status_t wc_rsa_encrypt(sgx_enclave_id_t eid, int* retval, const byte* m, word32 mSz, byte* out, word32 outSz, RsaKey* key);
sgx_status_t wc_rsa_decrypt(sgx_enclave_id_t eid, int* retval, const byte* in, word32 inSz, byte* out, word32 mSz, RsaKey* key);
sgx_status_t wc_rsa_init(sgx_enclave_id_t eid, int* retval, RsaKey* rsa);
sgx_status_t wc_rsa_free(sgx_enclave_id_t eid, int* retval, RsaKey* rsa);
sgx_status_t wc_test(sgx_enclave_id_t eid, int* retval, void* args);
sgx_status_t wc_benchmark_test(sgx_enclave_id_t eid, int* retval, void* args);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
