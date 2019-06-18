#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "user_types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

typedef struct struct_foo_t {
	uint32_t struct_foo_0;
	uint64_t struct_foo_1;
} struct_foo_t;

typedef enum enum_foo_t {
	ENUM_FOO_0 = 0,
	ENUM_FOO_1 = 1,
} enum_foo_t;

typedef union union_foo_t {
	uint32_t union_foo_0;
	uint32_t union_foo_1;
	uint64_t union_foo_3;
} union_foo_t;

void SGX_UBRIDGE(SGX_NOCONVENTION, PushSampledKeysOut, (unsigned char* private_key, uint32_t key_size, unsigned char* ZT_public_key_gx, unsigned char* ZT_public_key_gy));
void SGX_UBRIDGE(SGX_NOCONVENTION, VerifySignatureOutside, (uint32_t key_size, unsigned char* signature_x, unsigned char* signature_y, unsigned char* private_key, unsigned char* public_key_x, unsigned char* public_key_y, unsigned char* signature_r, unsigned char* signature_s));
void SGX_UBRIDGE(SGX_NOCONVENTION, VerifySignature, (unsigned char* signature_x, unsigned char* signature_y, uint32_t sig_size_x, uint32_t sig_size_y));
void SGX_UBRIDGE(SGX_NOCONVENTION, PublishKey, (unsigned char* bin_x, uint32_t size_bin_x, unsigned char* bin_y, uint32_t size_bin_y, unsigned char* signature_r, unsigned char* signature_s, uint32_t sig_r_size, uint32_t sig_s_size));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
void SGX_UBRIDGE(SGX_NOCONVENTION, build_fetchChildHash, (uint32_t left, uint32_t right, unsigned char* lchild, unsigned char* rchild, uint32_t hash_size, uint32_t recursion_level));
uint8_t SGX_UBRIDGE(SGX_NOCONVENTION, uploadObject, (unsigned char* serialized_bucket, uint32_t bucket_size, uint32_t label, unsigned char* hash, uint32_t hash_size, uint32_t size_for_level, uint32_t recursion_level));
uint8_t SGX_UBRIDGE(SGX_NOCONVENTION, downloadObject, (unsigned char* serialized_bucket, uint32_t bucket_size, uint32_t label, unsigned char* hash, uint32_t hash_size, uint32_t level, uint32_t D_lev));
uint8_t SGX_UBRIDGE(SGX_NOCONVENTION, downloadPath, (unsigned char* serialized_path, uint32_t path_size, uint32_t label, unsigned char* path_hash, uint32_t path_hash_size, uint32_t level, uint32_t D_lev));
uint8_t SGX_UBRIDGE(SGX_NOCONVENTION, uploadPath, (unsigned char* serialized_path, uint32_t path_size, uint32_t label, unsigned char* path_hash, uint32_t path_hash_size, uint32_t level, uint32_t D_level));
void SGX_UBRIDGE(SGX_NOCONVENTION, time_report, (uint8_t point));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pointer_user_check, (int* val));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pointer_in, (int* val));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pointer_out, (int* val));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pointer_in_out, (int* val));
SGX_DLLIMPORT void* SGX_UBRIDGE(SGX_CDECL, memccpy, (void* dest, const void* src, int val, size_t len));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_function_allow, ());
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));

sgx_status_t InitializeKeys(sgx_enclave_id_t eid);
sgx_status_t createNewORAMInstance(sgx_enclave_id_t eid, uint32_t* retval, uint32_t maxBlocks, uint32_t dataSize, uint32_t stashSize, uint32_t oblivious_flag, uint32_t recursion_data_size, int8_t recursion_levels, uint64_t onchip_posmap_mem_limit, uint32_t oram_type, uint8_t pZ);
sgx_status_t accessInterface(sgx_enclave_id_t eid, uint32_t instance_id, uint8_t oram_type, unsigned char* encrypted_request, unsigned char* encrypted_response, unsigned char* tag_in, unsigned char* tag_out, uint32_t request_size, uint32_t response_size, uint32_t tag_size);
sgx_status_t accessBulkReadInterface(sgx_enclave_id_t eid, uint32_t instance_id, uint8_t oram_type, uint32_t no_of_requests, unsigned char* encrypted_request, unsigned char* encrypted_response, unsigned char* tag_in, unsigned char* tag_out, uint32_t request_size, uint32_t response_size, uint32_t tag_size, unsigned char* encrypted_keys, uint32_t encrypted_keys_size);
sgx_status_t ecall_type_char(sgx_enclave_id_t eid, char val);
sgx_status_t ecall_type_int(sgx_enclave_id_t eid, int val);
sgx_status_t ecall_type_float(sgx_enclave_id_t eid, float val);
sgx_status_t ecall_type_double(sgx_enclave_id_t eid, double val);
sgx_status_t ecall_type_size_t(sgx_enclave_id_t eid, size_t val);
sgx_status_t ecall_type_wchar_t(sgx_enclave_id_t eid, wchar_t val);
sgx_status_t ecall_type_struct(sgx_enclave_id_t eid, struct struct_foo_t val);
sgx_status_t ecall_type_enum_union(sgx_enclave_id_t eid, enum enum_foo_t val1, union union_foo_t* val2);
sgx_status_t ecall_pointer_user_check(sgx_enclave_id_t eid, size_t* retval, void* val, size_t sz);
sgx_status_t ecall_pointer_in(sgx_enclave_id_t eid, int* val);
sgx_status_t ecall_pointer_out(sgx_enclave_id_t eid, int* val);
sgx_status_t ecall_pointer_in_out(sgx_enclave_id_t eid, int* val);
sgx_status_t ecall_pointer_string(sgx_enclave_id_t eid, char* str);
sgx_status_t ecall_pointer_string_const(sgx_enclave_id_t eid, const char* str);
sgx_status_t ecall_pointer_size(sgx_enclave_id_t eid, void* ptr, size_t len);
sgx_status_t ecall_pointer_count(sgx_enclave_id_t eid, int* arr, int cnt);
sgx_status_t ecall_pointer_isptr_readonly(sgx_enclave_id_t eid, buffer_t buf, size_t len);
sgx_status_t ocall_pointer_attr(sgx_enclave_id_t eid);
sgx_status_t ecall_array_user_check(sgx_enclave_id_t eid, int arr[4]);
sgx_status_t ecall_array_in(sgx_enclave_id_t eid, int arr[4]);
sgx_status_t ecall_array_out(sgx_enclave_id_t eid, int arr[4]);
sgx_status_t ecall_array_in_out(sgx_enclave_id_t eid, int arr[4]);
sgx_status_t ecall_array_isary(sgx_enclave_id_t eid, array_t arr);
sgx_status_t ecall_function_calling_convs(sgx_enclave_id_t eid);
sgx_status_t ecall_function_public(sgx_enclave_id_t eid);
sgx_status_t ecall_function_private(sgx_enclave_id_t eid, int* retval);
sgx_status_t ecall_malloc_free(sgx_enclave_id_t eid);
sgx_status_t ecall_sgx_cpuid(sgx_enclave_id_t eid, int cpuinfo[4], int leaf);
sgx_status_t ecall_exception(sgx_enclave_id_t eid);
sgx_status_t ecall_map(sgx_enclave_id_t eid);
sgx_status_t ecall_increase_counter(sgx_enclave_id_t eid, size_t* retval);
sgx_status_t ecall_producer(sgx_enclave_id_t eid);
sgx_status_t ecall_consumer(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
