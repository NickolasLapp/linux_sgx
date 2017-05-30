#include "Benchmark_Enclave_u.h"
#include <errno.h>

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

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Benchmark_Enclave = {
	0,
	{ NULL },
};
sgx_status_t wc_sha256_init(sgx_enclave_id_t eid, int* retval, Sha256* sha256)
{
	sgx_status_t status;
	ms_wc_sha256_init_t ms;
	ms.ms_sha256 = sha256;
	status = sgx_ecall(eid, 0, &ocall_table_Benchmark_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t wc_sha256_update(sgx_enclave_id_t eid, int* retval, Sha256* sha256, byte* buf, int bufSz)
{
	sgx_status_t status;
	ms_wc_sha256_update_t ms;
	ms.ms_sha256 = sha256;
	ms.ms_buf = buf;
	ms.ms_bufSz = bufSz;
	status = sgx_ecall(eid, 1, &ocall_table_Benchmark_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t wc_sha256_final(sgx_enclave_id_t eid, int* retval, Sha256* sha256, byte* digest)
{
	sgx_status_t status;
	ms_wc_sha256_final_t ms;
	ms.ms_sha256 = sha256;
	ms.ms_digest = digest;
	status = sgx_ecall(eid, 2, &ocall_table_Benchmark_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t wc_aesgcm_setKey(sgx_enclave_id_t eid, int* retval, Aes* aes, const byte* key, word32 len)
{
	sgx_status_t status;
	ms_wc_aesgcm_setKey_t ms;
	ms.ms_aes = aes;
	ms.ms_key = (byte*)key;
	ms.ms_len = len;
	status = sgx_ecall(eid, 3, &ocall_table_Benchmark_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t wc_aesgcm_encrypt(sgx_enclave_id_t eid, int* retval, Aes* aes, byte* out, const byte* in, word32 sz, const byte* iv, word32 ivSz, byte* authTag, word32 authTagSz, const byte* authIn, word32 authInSz)
{
	sgx_status_t status;
	ms_wc_aesgcm_encrypt_t ms;
	ms.ms_aes = aes;
	ms.ms_out = out;
	ms.ms_in = (byte*)in;
	ms.ms_sz = sz;
	ms.ms_iv = (byte*)iv;
	ms.ms_ivSz = ivSz;
	ms.ms_authTag = authTag;
	ms.ms_authTagSz = authTagSz;
	ms.ms_authIn = (byte*)authIn;
	ms.ms_authInSz = authInSz;
	status = sgx_ecall(eid, 4, &ocall_table_Benchmark_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t wc_aesgcm_decrypt(sgx_enclave_id_t eid, int* retval, Aes* aes, byte* out, const byte* in, word32 sz, const byte* iv, word32 ivSz, const byte* authTag, word32 authTagSz, const byte* authIn, word32 authInSz)
{
	sgx_status_t status;
	ms_wc_aesgcm_decrypt_t ms;
	ms.ms_aes = aes;
	ms.ms_out = out;
	ms.ms_in = (byte*)in;
	ms.ms_sz = sz;
	ms.ms_iv = (byte*)iv;
	ms.ms_ivSz = ivSz;
	ms.ms_authTag = (byte*)authTag;
	ms.ms_authTagSz = authTagSz;
	ms.ms_authIn = (byte*)authIn;
	ms.ms_authInSz = authInSz;
	status = sgx_ecall(eid, 5, &ocall_table_Benchmark_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t wc_rsa_encrypt(sgx_enclave_id_t eid, int* retval, const byte* m, word32 mSz, byte* out, word32 outSz, RsaKey* key)
{
	sgx_status_t status;
	ms_wc_rsa_encrypt_t ms;
	ms.ms_m = (byte*)m;
	ms.ms_mSz = mSz;
	ms.ms_out = out;
	ms.ms_outSz = outSz;
	ms.ms_key = key;
	status = sgx_ecall(eid, 6, &ocall_table_Benchmark_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t wc_rsa_decrypt(sgx_enclave_id_t eid, int* retval, const byte* in, word32 inSz, byte* out, word32 mSz, RsaKey* key)
{
	sgx_status_t status;
	ms_wc_rsa_decrypt_t ms;
	ms.ms_in = (byte*)in;
	ms.ms_inSz = inSz;
	ms.ms_out = out;
	ms.ms_mSz = mSz;
	ms.ms_key = key;
	status = sgx_ecall(eid, 7, &ocall_table_Benchmark_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t wc_rsa_init(sgx_enclave_id_t eid, int* retval, RsaKey* rsa)
{
	sgx_status_t status;
	ms_wc_rsa_init_t ms;
	ms.ms_rsa = rsa;
	status = sgx_ecall(eid, 8, &ocall_table_Benchmark_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t wc_rsa_free(sgx_enclave_id_t eid, int* retval, RsaKey* rsa)
{
	sgx_status_t status;
	ms_wc_rsa_free_t ms;
	ms.ms_rsa = rsa;
	status = sgx_ecall(eid, 9, &ocall_table_Benchmark_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

