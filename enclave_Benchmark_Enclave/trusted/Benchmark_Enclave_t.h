#ifndef BENCHMARK_ENCLAVE_T_H__
#define BENCHMARK_ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "wolfssl/ssl.h"
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
int wc_test(void* args);
int wc_benchmark_test(void* args);
int enc_wolfSSL_Init();
void enc_wolfSSL_Debugging_ON();
WOLFSSL_METHOD* enc_wolfTLSv1_2_client_method();
WOLFSSL_CTX* enc_wolfSSL_CTX_new(WOLFSSL_METHOD* method);
int enc_wolfSSL_CTX_use_PrivateKey_buffer(WOLFSSL_CTX* ctx, const unsigned char* buf, long int sz, int type);
int enc_wolfSSL_CTX_load_verify_buffer(WOLFSSL_CTX* ctx, const unsigned char* buf, long int sz, int type);
int enc_wolfSSL_CTX_use_certificate_chain_buffer_format(WOLFSSL_CTX* ctx, const unsigned char* buf, long int sz, int type);
WOLFSSL* enc_wolfSSL_new(WOLFSSL_CTX* ctx);
int enc_wolfSSL_set_fd(WOLFSSL* ssl, int fd);
int enc_wolfSSL_connect(WOLFSSL* ssl);
int enc_wolfSSL_write(WOLFSSL* ssl, const void* in, int sz);
int enc_wolfSSL_get_error(WOLFSSL* ssl, int ret);
int enc_wolfSSL_read(WOLFSSL* ssl, void* out, int sz);
void enc_wolfSSL_free(WOLFSSL* ssl);
void enc_wolfSSL_CTX_free(WOLFSSL_CTX* ctx);
int enc_wolfSSL_Cleanup();

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_current_time(double* time);
sgx_status_t SGX_CDECL ocall_low_res_time(int* time);
sgx_status_t SGX_CDECL ocall_recv(size_t* retval, int sockfd, void* buf, size_t len, int flags);
sgx_status_t SGX_CDECL ocall_send(size_t* retval, int sockfd, const void* buf, size_t len, int flags);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
