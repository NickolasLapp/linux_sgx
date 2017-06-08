#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "Benchmark_Enclave_t.h"

#include "wolfssl/certs_test.h"
#include "sgx_trts.h"

static volatile byte RNG_unset = 1;
static WC_RNG rng;

int wc_sha256_init(Sha256* sha256) {
	return wc_InitSha256(sha256);
}

int wc_sha256_update(Sha256* sha256, byte* buf, int bufSz)
{
	return wc_Sha256Update(sha256, buf, bufSz);
}

int wc_sha256_final(Sha256* sha256, byte* digest)
{
	return wc_Sha256Final(sha256, digest);
}


int wc_aesgcm_setKey(Aes* aes, const byte* key, word32 sz)
{
	return wc_AesGcmSetKey(aes, key, sz);
}

int wc_aesgcm_encrypt(Aes* aes, byte* c, const byte*p, word32 pSz, const byte* iv, word32 ivSz, byte* tag, word32 tagSz, const byte* ad, word32 adSz)
{
	return wc_AesGcmEncrypt(aes, c, p, pSz, iv, ivSz, tag, tagSz, ad, adSz);
}

int wc_aesgcm_decrypt(Aes* aes, byte* p, const byte* c, word32 cSz, const byte* iv, word32 ivSz, const byte* tag, word32 tagSz, const byte* ad, word32 adSz)
{
	return wc_AesGcmDecrypt(aes, p, c, cSz, iv, 12, tag, 16, ad, 13);
}


/* return size of encrypted data */
int wc_rsa_encrypt(const byte* m, word32 mSz, byte* out, word32 outSz, RsaKey* rsaKey)
{
	return wc_RsaPublicEncrypt(m, mSz, out, outSz, rsaKey, &rng);
}

int wc_rsa_decrypt(const byte* in, word32 inSz, byte* m, word32 mSz, RsaKey* rsaKey)
{
	return wc_RsaPrivateDecrypt(in, inSz, m, mSz, rsaKey);
}


int wc_rsa_free(RsaKey* rsaKey)
{
	return wc_FreeRsaKey(rsaKey);
}

int wc_test(void* args)
{
	return wolfcrypt_test(args);
}

int wc_benchmark_test(void* args)
{
    return benchmark_test(args);
}


/* RSA key is set from wolfSSL certs_test.h */
int wc_rsa_init(RsaKey* rsaKey)
{
	int    ret;
	word32 bytes;
	word32 idx = 0;
	const byte* tmp;

#ifdef USE_CERT_BUFFERS_1024
	tmp = rsa_key_der_1024;
	bytes = sizeof_rsa_key_der_1024;
#elif defined(USE_CERT_BUFFERS_2048)
	tmp = rsa_key_der_2048;
	bytes = sizeof_rsa_key_der_2048;
#else
#error "need a cert buffer size"
#endif /* USE_CERT_BUFFERS */

	ret = wc_InitRsaKey(rsaKey, 0);
	if (ret < 0) {
		return -1;
	}
	ret = wc_RsaPrivateKeyDecode(tmp, &idx, rsaKey, bytes);
	if (ret != 0) {
		return -1;
	}

	if (RNG_unset) { /* not atomic, for demo only. RNG could be moved to user APP and passed by reference */
		RNG_unset = 0;
		ret = wc_InitRng(&rng);
		if (ret < 0) {
			return -1;
		}
	}

	#ifdef WC_RSA_BLINDING
	wc_RsaSetRNG(rsaKey, rng);
	#endif

	return 0;
}

void enc_wolfSSL_Debugging_ON(void)
{
    wolfSSL_Debugging_ON();
}

int enc_wolfSSL_Init(void)
{
    return wolfSSL_Init();
}

WOLFSSL_METHOD* enc_wolfTLSv1_2_client_method(void)
{
    return wolfTLSv1_2_client_method();
}

WOLFSSL_CTX* enc_wolfSSL_CTX_new(WOLFSSL_METHOD* method)
{
    if(sgx_is_within_enclave(method, wolfSSL_METHOD_GetObjectSize()) != 1)
        abort();
    return wolfSSL_CTX_new(method);
}

int enc_wolfSSL_CTX_use_certificate_chain_buffer_format(WOLFSSL_CTX* ctx,
        const unsigned char* buf, long sz, int type)
{
    if(sgx_is_within_enclave(ctx, wolfSSL_CTX_GetObjectSize()) != 1)
        abort();
    return wolfSSL_CTX_use_certificate_chain_buffer_format(ctx, buf, sz, type);
}

int enc_wolfSSL_CTX_use_PrivateKey_buffer(WOLFSSL_CTX* ctx, const unsigned char* buf,
                                            long sz, int type)
{
    if(sgx_is_within_enclave(ctx, wolfSSL_CTX_GetObjectSize()) != 1)
        abort();
    return wolfSSL_CTX_use_PrivateKey_buffer(ctx, buf, sz, type);
}

int enc_wolfSSL_CTX_load_verify_buffer(WOLFSSL_CTX* ctx, const unsigned char* in,
                                       long sz, int format)
{
    if(sgx_is_within_enclave(ctx, wolfSSL_CTX_GetObjectSize()) != 1)
        abort();
    return wolfSSL_CTX_load_verify_buffer(ctx, in, sz, format);
}

WOLFSSL* enc_wolfSSL_new( WOLFSSL_CTX* ctx)
{
    if(sgx_is_within_enclave(ctx, wolfSSL_CTX_GetObjectSize()) != 1)
        abort();
    return wolfSSL_new(ctx);
}

int enc_wolfSSL_set_fd(WOLFSSL* ssl, int fd)
{
    if(sgx_is_within_enclave(ssl, wolfSSL_GetObjectSize()) != 1)
        abort();
    return wolfSSL_set_fd(ssl, fd);
}

int enc_wolfSSL_connect(WOLFSSL* ssl)
{
    if(sgx_is_within_enclave(ssl, wolfSSL_GetObjectSize()) != 1)
        abort();
    return wolfSSL_connect(ssl);
}

int enc_wolfSSL_write(WOLFSSL* ssl, const void* in, int sz)
{
    if(sgx_is_within_enclave(ssl, wolfSSL_GetObjectSize()) != 1)
        abort();
    return wolfSSL_write(ssl, in, sz);
}

int enc_wolfSSL_get_error(WOLFSSL* ssl, int ret)
{
    if(sgx_is_within_enclave(ssl, wolfSSL_GetObjectSize()) != 1)
        abort();
    return wolfSSL_get_error(ssl, ret);
}

int enc_wolfSSL_read(WOLFSSL* ssl, void* data, int sz)
{
    if(sgx_is_within_enclave(ssl, wolfSSL_GetObjectSize()) != 1)
        abort();
    return wolfSSL_read(ssl, data, sz);
}

void enc_wolfSSL_free(WOLFSSL* ssl)
{
    if(sgx_is_within_enclave(ssl, wolfSSL_GetObjectSize()) != 1)
        abort();
    wolfSSL_free(ssl);
}

void enc_wolfSSL_CTX_free(WOLFSSL_CTX* ctx)
{
    if(sgx_is_within_enclave(ctx, wolfSSL_CTX_GetObjectSize()) != 1)
        abort();
    wolfSSL_CTX_free(ctx);
}

int enc_wolfSSL_Cleanup(void)
{
    wolfSSL_Cleanup();
}

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

void sprintf(char* buf, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
}

double current_time(void)
{
    double curr;
    ocall_current_time(&curr);
    return curr;
}

int LowResTimer(void) /* low_res timer */
{
    int time;
    ocall_low_res_time(&time);
    return time;
}

size_t recv(int sockfd, void *buf, size_t len, int flags)
{
    size_t ret, sgxStatus;
    sgxStatus = ocall_recv(&ret, sockfd, buf, len, flags);
    return ret;
}

size_t send(int sockfd, const void *buf, size_t len, int flags)
{
    size_t ret, sgxStatus;
    sgxStatus = ocall_send(&ret, sockfd, buf, len, flags);
    return ret;
}
