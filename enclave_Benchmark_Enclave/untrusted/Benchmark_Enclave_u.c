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

typedef struct ms_wc_test_t {
	int ms_retval;
	void* ms_args;
} ms_wc_test_t;

typedef struct ms_wc_benchmark_test_t {
	int ms_retval;
	void* ms_args;
} ms_wc_benchmark_test_t;

typedef struct ms_enc_wolfSSL_Init_t {
	int ms_retval;
} ms_enc_wolfSSL_Init_t;


typedef struct ms_enc_wolfTLSv1_2_client_method_t {
	WOLFSSL_METHOD* ms_retval;
} ms_enc_wolfTLSv1_2_client_method_t;

typedef struct ms_enc_wolfSSL_CTX_new_t {
	WOLFSSL_CTX* ms_retval;
	WOLFSSL_METHOD* ms_method;
} ms_enc_wolfSSL_CTX_new_t;

typedef struct ms_enc_wolfSSL_CTX_use_PrivateKey_buffer_t {
	int ms_retval;
	WOLFSSL_CTX* ms_ctx;
	unsigned char* ms_buf;
	long int ms_sz;
	int ms_type;
} ms_enc_wolfSSL_CTX_use_PrivateKey_buffer_t;

typedef struct ms_enc_wolfSSL_CTX_load_verify_buffer_t {
	int ms_retval;
	WOLFSSL_CTX* ms_ctx;
	unsigned char* ms_buf;
	long int ms_sz;
	int ms_type;
} ms_enc_wolfSSL_CTX_load_verify_buffer_t;

typedef struct ms_enc_wolfSSL_CTX_use_certificate_chain_buffer_format_t {
	int ms_retval;
	WOLFSSL_CTX* ms_ctx;
	unsigned char* ms_buf;
	long int ms_sz;
	int ms_type;
} ms_enc_wolfSSL_CTX_use_certificate_chain_buffer_format_t;

typedef struct ms_enc_wolfSSL_new_t {
	WOLFSSL* ms_retval;
	WOLFSSL_CTX* ms_ctx;
} ms_enc_wolfSSL_new_t;

typedef struct ms_enc_wolfSSL_set_fd_t {
	int ms_retval;
	WOLFSSL* ms_ssl;
	int ms_fd;
} ms_enc_wolfSSL_set_fd_t;

typedef struct ms_enc_wolfSSL_connect_t {
	int ms_retval;
	WOLFSSL* ms_ssl;
} ms_enc_wolfSSL_connect_t;

typedef struct ms_enc_wolfSSL_write_t {
	int ms_retval;
	WOLFSSL* ms_ssl;
	void* ms_in;
	int ms_sz;
} ms_enc_wolfSSL_write_t;

typedef struct ms_enc_wolfSSL_get_error_t {
	int ms_retval;
	WOLFSSL* ms_ssl;
	int ms_ret;
} ms_enc_wolfSSL_get_error_t;

typedef struct ms_enc_wolfSSL_read_t {
	int ms_retval;
	WOLFSSL* ms_ssl;
	void* ms_out;
	int ms_sz;
} ms_enc_wolfSSL_read_t;

typedef struct ms_enc_wolfSSL_free_t {
	WOLFSSL* ms_ssl;
} ms_enc_wolfSSL_free_t;

typedef struct ms_enc_wolfSSL_CTX_free_t {
	WOLFSSL_CTX* ms_ctx;
} ms_enc_wolfSSL_CTX_free_t;

typedef struct ms_enc_wolfSSL_Cleanup_t {
	int ms_retval;
} ms_enc_wolfSSL_Cleanup_t;

typedef struct ms_ocall_print_string_t {
	char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_current_time_t {
	double* ms_time;
} ms_ocall_current_time_t;

typedef struct ms_ocall_low_res_time_t {
	int* ms_time;
} ms_ocall_low_res_time_t;

typedef struct ms_ocall_recv_t {
	size_t ms_retval;
	int ocall_errno;
	int ms_sockfd;
	void* ms_buf;
	size_t ms_len;
	int ms_flags;
} ms_ocall_recv_t;

typedef struct ms_ocall_send_t {
	size_t ms_retval;
	int ocall_errno;
	int ms_sockfd;
	void* ms_buf;
	size_t ms_len;
	int ms_flags;
} ms_ocall_send_t;

static sgx_status_t SGX_CDECL Benchmark_Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Benchmark_Enclave_ocall_current_time(void* pms)
{
	ms_ocall_current_time_t* ms = SGX_CAST(ms_ocall_current_time_t*, pms);
	ocall_current_time(ms->ms_time);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Benchmark_Enclave_ocall_low_res_time(void* pms)
{
	ms_ocall_low_res_time_t* ms = SGX_CAST(ms_ocall_low_res_time_t*, pms);
	ocall_low_res_time(ms->ms_time);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Benchmark_Enclave_ocall_recv(void* pms)
{
	ms_ocall_recv_t* ms = SGX_CAST(ms_ocall_recv_t*, pms);
	ms->ms_retval = ocall_recv(ms->ms_sockfd, ms->ms_buf, ms->ms_len, ms->ms_flags);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Benchmark_Enclave_ocall_send(void* pms)
{
	ms_ocall_send_t* ms = SGX_CAST(ms_ocall_send_t*, pms);
	ms->ms_retval = ocall_send(ms->ms_sockfd, (const void*)ms->ms_buf, ms->ms_len, ms->ms_flags);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[5];
} ocall_table_Benchmark_Enclave = {
	5,
	{
		(void*)Benchmark_Enclave_ocall_print_string,
		(void*)Benchmark_Enclave_ocall_current_time,
		(void*)Benchmark_Enclave_ocall_low_res_time,
		(void*)Benchmark_Enclave_ocall_recv,
		(void*)Benchmark_Enclave_ocall_send,
	}
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

sgx_status_t wc_test(sgx_enclave_id_t eid, int* retval, void* args)
{
	sgx_status_t status;
	ms_wc_test_t ms;
	ms.ms_args = args;
	status = sgx_ecall(eid, 10, &ocall_table_Benchmark_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t wc_benchmark_test(sgx_enclave_id_t eid, int* retval, void* args)
{
	sgx_status_t status;
	ms_wc_benchmark_test_t ms;
	ms.ms_args = args;
	status = sgx_ecall(eid, 11, &ocall_table_Benchmark_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_Init(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_enc_wolfSSL_Init_t ms;
	status = sgx_ecall(eid, 12, &ocall_table_Benchmark_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_Debugging_ON(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 13, &ocall_table_Benchmark_Enclave, NULL);
	return status;
}

sgx_status_t enc_wolfTLSv1_2_client_method(sgx_enclave_id_t eid, WOLFSSL_METHOD** retval)
{
	sgx_status_t status;
	ms_enc_wolfTLSv1_2_client_method_t ms;
	status = sgx_ecall(eid, 14, &ocall_table_Benchmark_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_new(sgx_enclave_id_t eid, WOLFSSL_CTX** retval, WOLFSSL_METHOD* method)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_new_t ms;
	ms.ms_method = method;
	status = sgx_ecall(eid, 15, &ocall_table_Benchmark_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_use_PrivateKey_buffer(sgx_enclave_id_t eid, int* retval, WOLFSSL_CTX* ctx, const unsigned char* buf, long int sz, int type)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_use_PrivateKey_buffer_t ms;
	ms.ms_ctx = ctx;
	ms.ms_buf = (unsigned char*)buf;
	ms.ms_sz = sz;
	ms.ms_type = type;
	status = sgx_ecall(eid, 16, &ocall_table_Benchmark_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_load_verify_buffer(sgx_enclave_id_t eid, int* retval, WOLFSSL_CTX* ctx, const unsigned char* buf, long int sz, int type)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_load_verify_buffer_t ms;
	ms.ms_ctx = ctx;
	ms.ms_buf = (unsigned char*)buf;
	ms.ms_sz = sz;
	ms.ms_type = type;
	status = sgx_ecall(eid, 17, &ocall_table_Benchmark_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_use_certificate_chain_buffer_format(sgx_enclave_id_t eid, int* retval, WOLFSSL_CTX* ctx, const unsigned char* buf, long int sz, int type)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_use_certificate_chain_buffer_format_t ms;
	ms.ms_ctx = ctx;
	ms.ms_buf = (unsigned char*)buf;
	ms.ms_sz = sz;
	ms.ms_type = type;
	status = sgx_ecall(eid, 18, &ocall_table_Benchmark_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_new(sgx_enclave_id_t eid, WOLFSSL** retval, WOLFSSL_CTX* ctx)
{
	sgx_status_t status;
	ms_enc_wolfSSL_new_t ms;
	ms.ms_ctx = ctx;
	status = sgx_ecall(eid, 19, &ocall_table_Benchmark_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_set_fd(sgx_enclave_id_t eid, int* retval, WOLFSSL* ssl, int fd)
{
	sgx_status_t status;
	ms_enc_wolfSSL_set_fd_t ms;
	ms.ms_ssl = ssl;
	ms.ms_fd = fd;
	status = sgx_ecall(eid, 20, &ocall_table_Benchmark_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_connect(sgx_enclave_id_t eid, int* retval, WOLFSSL* ssl)
{
	sgx_status_t status;
	ms_enc_wolfSSL_connect_t ms;
	ms.ms_ssl = ssl;
	status = sgx_ecall(eid, 21, &ocall_table_Benchmark_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_write(sgx_enclave_id_t eid, int* retval, WOLFSSL* ssl, const void* in, int sz)
{
	sgx_status_t status;
	ms_enc_wolfSSL_write_t ms;
	ms.ms_ssl = ssl;
	ms.ms_in = (void*)in;
	ms.ms_sz = sz;
	status = sgx_ecall(eid, 22, &ocall_table_Benchmark_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_get_error(sgx_enclave_id_t eid, int* retval, WOLFSSL* ssl, int ret)
{
	sgx_status_t status;
	ms_enc_wolfSSL_get_error_t ms;
	ms.ms_ssl = ssl;
	ms.ms_ret = ret;
	status = sgx_ecall(eid, 23, &ocall_table_Benchmark_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_read(sgx_enclave_id_t eid, int* retval, WOLFSSL* ssl, void* out, int sz)
{
	sgx_status_t status;
	ms_enc_wolfSSL_read_t ms;
	ms.ms_ssl = ssl;
	ms.ms_out = out;
	ms.ms_sz = sz;
	status = sgx_ecall(eid, 24, &ocall_table_Benchmark_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_free(sgx_enclave_id_t eid, WOLFSSL* ssl)
{
	sgx_status_t status;
	ms_enc_wolfSSL_free_t ms;
	ms.ms_ssl = ssl;
	status = sgx_ecall(eid, 25, &ocall_table_Benchmark_Enclave, &ms);
	return status;
}

sgx_status_t enc_wolfSSL_CTX_free(sgx_enclave_id_t eid, WOLFSSL_CTX* ctx)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_free_t ms;
	ms.ms_ctx = ctx;
	status = sgx_ecall(eid, 26, &ocall_table_Benchmark_Enclave, &ms);
	return status;
}

sgx_status_t enc_wolfSSL_Cleanup(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_enc_wolfSSL_Cleanup_t ms;
	status = sgx_ecall(eid, 27, &ocall_table_Benchmark_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

