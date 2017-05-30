#include "Benchmark_Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_wc_sha256_init_t {
	int ms_retval;
	Sha256* ms_sha256;
} ms_wc_sha256_init_t;

typedef struct ms_wc_sha256_update_t {
	int ms_retval;
	Sha256* ms_sha256;
	byte* ms_buf;
	int ms_bufSz;
} ms_wc_sha256_update_t;

typedef struct ms_wc_sha256_final_t {
	int ms_retval;
	Sha256* ms_sha256;
	byte* ms_digest;
} ms_wc_sha256_final_t;

typedef struct ms_wc_aesgcm_setKey_t {
	int ms_retval;
	Aes* ms_aes;
	byte* ms_key;
	word32 ms_len;
} ms_wc_aesgcm_setKey_t;

typedef struct ms_wc_aesgcm_encrypt_t {
	int ms_retval;
	Aes* ms_aes;
	byte* ms_out;
	byte* ms_in;
	word32 ms_sz;
	byte* ms_iv;
	word32 ms_ivSz;
	byte* ms_authTag;
	word32 ms_authTagSz;
	byte* ms_authIn;
	word32 ms_authInSz;
} ms_wc_aesgcm_encrypt_t;

typedef struct ms_wc_aesgcm_decrypt_t {
	int ms_retval;
	Aes* ms_aes;
	byte* ms_out;
	byte* ms_in;
	word32 ms_sz;
	byte* ms_iv;
	word32 ms_ivSz;
	byte* ms_authTag;
	word32 ms_authTagSz;
	byte* ms_authIn;
	word32 ms_authInSz;
} ms_wc_aesgcm_decrypt_t;

typedef struct ms_wc_rsa_encrypt_t {
	int ms_retval;
	byte* ms_m;
	word32 ms_mSz;
	byte* ms_out;
	word32 ms_outSz;
	RsaKey* ms_key;
} ms_wc_rsa_encrypt_t;

typedef struct ms_wc_rsa_decrypt_t {
	int ms_retval;
	byte* ms_in;
	word32 ms_inSz;
	byte* ms_out;
	word32 ms_mSz;
	RsaKey* ms_key;
} ms_wc_rsa_decrypt_t;

typedef struct ms_wc_rsa_init_t {
	int ms_retval;
	RsaKey* ms_rsa;
} ms_wc_rsa_init_t;

typedef struct ms_wc_rsa_free_t {
	int ms_retval;
	RsaKey* ms_rsa;
} ms_wc_rsa_free_t;

static sgx_status_t SGX_CDECL sgx_wc_sha256_init(void* pms)
{
	ms_wc_sha256_init_t* ms = SGX_CAST(ms_wc_sha256_init_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	Sha256* _tmp_sha256 = ms->ms_sha256;

	CHECK_REF_POINTER(pms, sizeof(ms_wc_sha256_init_t));

	ms->ms_retval = wc_sha256_init(_tmp_sha256);


	return status;
}

static sgx_status_t SGX_CDECL sgx_wc_sha256_update(void* pms)
{
	ms_wc_sha256_update_t* ms = SGX_CAST(ms_wc_sha256_update_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	Sha256* _tmp_sha256 = ms->ms_sha256;
	byte* _tmp_buf = ms->ms_buf;

	CHECK_REF_POINTER(pms, sizeof(ms_wc_sha256_update_t));

	ms->ms_retval = wc_sha256_update(_tmp_sha256, _tmp_buf, ms->ms_bufSz);


	return status;
}

static sgx_status_t SGX_CDECL sgx_wc_sha256_final(void* pms)
{
	ms_wc_sha256_final_t* ms = SGX_CAST(ms_wc_sha256_final_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	Sha256* _tmp_sha256 = ms->ms_sha256;
	byte* _tmp_digest = ms->ms_digest;

	CHECK_REF_POINTER(pms, sizeof(ms_wc_sha256_final_t));

	ms->ms_retval = wc_sha256_final(_tmp_sha256, _tmp_digest);


	return status;
}

static sgx_status_t SGX_CDECL sgx_wc_aesgcm_setKey(void* pms)
{
	ms_wc_aesgcm_setKey_t* ms = SGX_CAST(ms_wc_aesgcm_setKey_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	Aes* _tmp_aes = ms->ms_aes;
	byte* _tmp_key = ms->ms_key;

	CHECK_REF_POINTER(pms, sizeof(ms_wc_aesgcm_setKey_t));

	ms->ms_retval = wc_aesgcm_setKey(_tmp_aes, (const byte*)_tmp_key, ms->ms_len);


	return status;
}

static sgx_status_t SGX_CDECL sgx_wc_aesgcm_encrypt(void* pms)
{
	ms_wc_aesgcm_encrypt_t* ms = SGX_CAST(ms_wc_aesgcm_encrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	Aes* _tmp_aes = ms->ms_aes;
	byte* _tmp_out = ms->ms_out;
	byte* _tmp_in = ms->ms_in;
	byte* _tmp_iv = ms->ms_iv;
	byte* _tmp_authTag = ms->ms_authTag;
	byte* _tmp_authIn = ms->ms_authIn;

	CHECK_REF_POINTER(pms, sizeof(ms_wc_aesgcm_encrypt_t));

	ms->ms_retval = wc_aesgcm_encrypt(_tmp_aes, _tmp_out, (const byte*)_tmp_in, ms->ms_sz, (const byte*)_tmp_iv, ms->ms_ivSz, _tmp_authTag, ms->ms_authTagSz, (const byte*)_tmp_authIn, ms->ms_authInSz);


	return status;
}

static sgx_status_t SGX_CDECL sgx_wc_aesgcm_decrypt(void* pms)
{
	ms_wc_aesgcm_decrypt_t* ms = SGX_CAST(ms_wc_aesgcm_decrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	Aes* _tmp_aes = ms->ms_aes;
	byte* _tmp_out = ms->ms_out;
	byte* _tmp_in = ms->ms_in;
	byte* _tmp_iv = ms->ms_iv;
	byte* _tmp_authTag = ms->ms_authTag;
	byte* _tmp_authIn = ms->ms_authIn;

	CHECK_REF_POINTER(pms, sizeof(ms_wc_aesgcm_decrypt_t));

	ms->ms_retval = wc_aesgcm_decrypt(_tmp_aes, _tmp_out, (const byte*)_tmp_in, ms->ms_sz, (const byte*)_tmp_iv, ms->ms_ivSz, (const byte*)_tmp_authTag, ms->ms_authTagSz, (const byte*)_tmp_authIn, ms->ms_authInSz);


	return status;
}

static sgx_status_t SGX_CDECL sgx_wc_rsa_encrypt(void* pms)
{
	ms_wc_rsa_encrypt_t* ms = SGX_CAST(ms_wc_rsa_encrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	byte* _tmp_m = ms->ms_m;
	byte* _tmp_out = ms->ms_out;
	RsaKey* _tmp_key = ms->ms_key;

	CHECK_REF_POINTER(pms, sizeof(ms_wc_rsa_encrypt_t));

	ms->ms_retval = wc_rsa_encrypt((const byte*)_tmp_m, ms->ms_mSz, _tmp_out, ms->ms_outSz, _tmp_key);


	return status;
}

static sgx_status_t SGX_CDECL sgx_wc_rsa_decrypt(void* pms)
{
	ms_wc_rsa_decrypt_t* ms = SGX_CAST(ms_wc_rsa_decrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	byte* _tmp_in = ms->ms_in;
	byte* _tmp_out = ms->ms_out;
	RsaKey* _tmp_key = ms->ms_key;

	CHECK_REF_POINTER(pms, sizeof(ms_wc_rsa_decrypt_t));

	ms->ms_retval = wc_rsa_decrypt((const byte*)_tmp_in, ms->ms_inSz, _tmp_out, ms->ms_mSz, _tmp_key);


	return status;
}

static sgx_status_t SGX_CDECL sgx_wc_rsa_init(void* pms)
{
	ms_wc_rsa_init_t* ms = SGX_CAST(ms_wc_rsa_init_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	RsaKey* _tmp_rsa = ms->ms_rsa;

	CHECK_REF_POINTER(pms, sizeof(ms_wc_rsa_init_t));

	ms->ms_retval = wc_rsa_init(_tmp_rsa);


	return status;
}

static sgx_status_t SGX_CDECL sgx_wc_rsa_free(void* pms)
{
	ms_wc_rsa_free_t* ms = SGX_CAST(ms_wc_rsa_free_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	RsaKey* _tmp_rsa = ms->ms_rsa;

	CHECK_REF_POINTER(pms, sizeof(ms_wc_rsa_free_t));

	ms->ms_retval = wc_rsa_free(_tmp_rsa);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[10];
} g_ecall_table = {
	10,
	{
		{(void*)(uintptr_t)sgx_wc_sha256_init, 0},
		{(void*)(uintptr_t)sgx_wc_sha256_update, 0},
		{(void*)(uintptr_t)sgx_wc_sha256_final, 0},
		{(void*)(uintptr_t)sgx_wc_aesgcm_setKey, 0},
		{(void*)(uintptr_t)sgx_wc_aesgcm_encrypt, 0},
		{(void*)(uintptr_t)sgx_wc_aesgcm_decrypt, 0},
		{(void*)(uintptr_t)sgx_wc_rsa_encrypt, 0},
		{(void*)(uintptr_t)sgx_wc_rsa_decrypt, 0},
		{(void*)(uintptr_t)sgx_wc_rsa_init, 0},
		{(void*)(uintptr_t)sgx_wc_rsa_free, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


