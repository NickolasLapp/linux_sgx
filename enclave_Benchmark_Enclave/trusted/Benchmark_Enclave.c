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
	return wc_Sha256Final(sha256, digest); }


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

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

double current_time(void)
{
    double curr;
    ocall_current_time(&curr);
    return curr;
}
