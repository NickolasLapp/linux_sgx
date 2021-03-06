######## Intel(R) SGX SDK Settings ########
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= SIM
SGX_ARCH ?= x64

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2
endif

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif

Crypto_Library_Name := sgx_tcrypto

Wolfcrypt_C_Extra_Flags := -DWOLFSSL_SGX
Wolfcrypt_C_Files :=static_trusted/wolfssl/wolfcrypt/src/aes.c\
					static_trusted/wolfssl/wolfcrypt/src/arc4.c\
					static_trusted/wolfssl/wolfcrypt/src/asn.c\
					static_trusted/wolfssl/wolfcrypt/src/blake2b.c\
					static_trusted/wolfssl/wolfcrypt/src/camellia.c\
					static_trusted/wolfssl/wolfcrypt/src/coding.c\
					static_trusted/wolfssl/wolfcrypt/src/chacha.c\
					static_trusted/wolfssl/wolfcrypt/src/chacha20_poly1305.c\
					static_trusted/wolfssl/src/crl.c\
					static_trusted/wolfssl/wolfcrypt/src/des3.c\
					static_trusted/wolfssl/wolfcrypt/src/dh.c\
					static_trusted/wolfssl/wolfcrypt/src/tfm.c\
					static_trusted/wolfssl/wolfcrypt/src/ecc.c\
					static_trusted/wolfssl/wolfcrypt/src/error.c\
					static_trusted/wolfssl/wolfcrypt/src/hash.c\
					static_trusted/wolfssl/wolfcrypt/src/hc128.c\
					static_trusted/wolfssl/wolfcrypt/src/hmac.c\
					static_trusted/wolfssl/wolfcrypt/src/integer.c\
					static_trusted/wolfssl/src/internal.c\
					static_trusted/wolfssl/src/io.c\
					static_trusted/wolfssl/src/keys.c\
					static_trusted/wolfssl/wolfcrypt/src/logging.c\
					static_trusted/wolfssl/wolfcrypt/src/md4.c\
					static_trusted/wolfssl/wolfcrypt/src/md5.c\
					static_trusted/wolfssl/wolfcrypt/src/memory.c\
					static_trusted/wolfssl/src/ocsp.c\
					static_trusted/wolfssl/wolfcrypt/src/pkcs7.c\
					static_trusted/wolfssl/wolfcrypt/src/pkcs12.c\
					static_trusted/wolfssl/wolfcrypt/src/poly1305.c\
					static_trusted/wolfssl/wolfcrypt/src/wc_port.c\
					static_trusted/wolfssl/wolfcrypt/src/wolfmath.c\
					static_trusted/wolfssl/wolfcrypt/src/pwdbased.c\
					static_trusted/wolfssl/wolfcrypt/src/rabbit.c\
					static_trusted/wolfssl/wolfcrypt/src/random.c\
					static_trusted/wolfssl/wolfcrypt/src/ripemd.c\
					static_trusted/wolfssl/wolfcrypt/src/rsa.c\
					static_trusted/wolfssl/wolfcrypt/src/dsa.c\
					static_trusted/wolfssl/wolfcrypt/src/sha.c\
					static_trusted/wolfssl/wolfcrypt/src/sha256.c\
					static_trusted/wolfssl/wolfcrypt/src/sha512.c\
					static_trusted/wolfssl/wolfcrypt/src/signature.c\
					static_trusted/wolfssl/src/ssl.c\
					static_trusted/wolfssl/src/tls.c\
					static_trusted/wolfssl/wolfcrypt/src/wc_encrypt.c\
					static_trusted/wolfssl/wolfcrypt/src/wolfevent.c\
					static_trusted/wolfssl/wolfcrypt/test/test.c\
					static_trusted/wolfssl/wolfcrypt/benchmark/benchmark.c

Wolfcrypt_Include_Paths := -I./static_trusted/wolfssl/ \
						   -I./static_trusted/wolfssl/wolfcrypt/test/ \
						   -I./static_trusted/wolfssl/wolfcrypt/benchmark/ \
						   -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport


Flags_Just_For_C := -Wno-implicit-function-declaration -std=c11
Common_C_Cpp_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Wolfcrypt_Include_Paths) -fno-builtin-printf -I.
Wolfcrypt_C_Flags := $(Flags_Just_For_C) $(Common_C_Cpp_Flags) $(Wolfcrypt_C_Extra_Flags)

Wolfcrypt_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=trusted/wolfcrypt.lds

Wolfcrypt_C_Objects := $(Wolfcrypt_C_Files:.c=.o)

ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif


.PHONY: all run

all: libwolfcrypt.sgx.static.lib.a

######## wolfcrypt Objects ########

static_trusted/wolfcrypt_t.h:
	@cd ./static_trusted
	@echo "GEN  =>  $@"

static_trusted/wolfcrypt_t.o: ./trusted/wolfcrypt_t.c
	@$(CC) $(Wolfcrypt_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

static_trusted/%.o: static_trusted/%.c
	@echo $(Wolfcrypt_C_Flags) -c $< -o $@
	@$(CC) $(Wolfcrypt_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

libwolfcrypt.sgx.static.lib.a: static_trusted/wolfcrypt_t.h $(Wolfcrypt_C_Objects)
	ar rcs libwolfcrypt.sgx.static.lib.a $(Wolfcrypt_Cpp_Objects) $(Wolfcrypt_C_Objects)
	@echo "LINK =>  $@"

clean:
	@rm -f wolfcrypt.* static_trusted/wolfcrypt_t.*  $(Wolfcrypt_C_Objects)
