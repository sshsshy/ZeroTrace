#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_createNewORAMInstance_t {
	uint32_t ms_retval;
	uint32_t ms_maxBlocks;
	uint32_t ms_dataSize;
	uint32_t ms_stashSize;
	uint32_t ms_oblivious_flag;
	uint32_t ms_recursion_data_size;
	int8_t ms_recursion_levels;
	uint64_t ms_onchip_posmap_mem_limit;
	uint32_t ms_oram_type;
	uint8_t ms_pZ;
} ms_createNewORAMInstance_t;

typedef struct ms_createNewLSORAMInstance_t {
	uint32_t ms_retval;
	uint32_t ms_key_size;
	uint32_t ms_value_size;
	uint32_t ms_num_blocks;
	uint8_t ms_mem_mode;
	uint8_t ms_oblivious_type;
	uint8_t ms_dummy_populate;
} ms_createNewLSORAMInstance_t;

typedef struct ms_accessInterface_t {
	uint32_t ms_instance_id;
	uint8_t ms_oram_type;
	unsigned char* ms_encrypted_request;
	unsigned char* ms_encrypted_response;
	unsigned char* ms_tag_in;
	unsigned char* ms_tag_out;
	uint32_t ms_request_size;
	uint32_t ms_response_size;
	uint32_t ms_tag_size;
} ms_accessInterface_t;

typedef struct ms_accessBulkReadInterface_t {
	uint32_t ms_instance_id;
	uint8_t ms_oram_type;
	uint32_t ms_no_of_requests;
	unsigned char* ms_encrypted_request;
	unsigned char* ms_encrypted_response;
	unsigned char* ms_tag_in;
	unsigned char* ms_tag_out;
	uint32_t ms_request_size;
	uint32_t ms_response_size;
	uint32_t ms_tag_size;
} ms_accessBulkReadInterface_t;

typedef struct ms_InitializeKeys_t {
	int8_t ms_retval;
	unsigned char* ms_bin_x;
	unsigned char* ms_bin_y;
	unsigned char* ms_bin_r;
	unsigned char* ms_bin_s;
	uint32_t ms_size_bin;
} ms_InitializeKeys_t;

typedef struct ms_LSORAMInsert_t {
	int8_t ms_retval;
	uint32_t ms_instance_id;
	unsigned char* ms_encrypted_request;
	uint32_t ms_request_size;
	unsigned char* ms_tag_in;
	uint32_t ms_tag_size;
	unsigned char* ms_client_pubkey;
	uint32_t ms_pubkey_size;
	uint32_t ms_pubkey_size_x;
	uint32_t ms_pubkey_size_y;
} ms_LSORAMInsert_t;

typedef struct ms_LSORAMFetch_t {
	int8_t ms_retval;
	uint32_t ms_instance_id;
	unsigned char* ms_encrypted_request;
	uint32_t ms_request_size;
	unsigned char* ms_encrypted_response;
	uint32_t ms_response_size;
	unsigned char* ms_tag_in;
	unsigned char* ms_tag_out;
	uint32_t ms_tag_size;
	unsigned char* ms_client_pubkey;
	uint32_t ms_pubkey_size;
	uint32_t ms_pubkey_size_x;
	uint32_t ms_pubkey_size_y;
} ms_LSORAMFetch_t;

typedef struct ms_LSORAMEvict_t {
	int8_t ms_retval;
	uint32_t ms_instance_id;
	unsigned char* ms_key;
	uint32_t ms_key_size;
} ms_LSORAMEvict_t;

typedef struct ms_deleteLSORAMInstance_t {
	uint8_t ms_retval;
	uint32_t ms_instance_id;
} ms_deleteLSORAMInstance_t;

typedef struct ms_ecall_type_char_t {
	char ms_val;
} ms_ecall_type_char_t;

typedef struct ms_ecall_type_int_t {
	int ms_val;
} ms_ecall_type_int_t;

typedef struct ms_ecall_type_float_t {
	float ms_val;
} ms_ecall_type_float_t;

typedef struct ms_ecall_type_double_t {
	double ms_val;
} ms_ecall_type_double_t;

typedef struct ms_ecall_type_size_t_t {
	size_t ms_val;
} ms_ecall_type_size_t_t;

typedef struct ms_ecall_type_wchar_t_t {
	wchar_t ms_val;
} ms_ecall_type_wchar_t_t;

typedef struct ms_ecall_type_struct_t {
	struct struct_foo_t ms_val;
} ms_ecall_type_struct_t;

typedef struct ms_ecall_type_enum_union_t {
	enum enum_foo_t ms_val1;
	union union_foo_t* ms_val2;
} ms_ecall_type_enum_union_t;

typedef struct ms_ecall_pointer_user_check_t {
	size_t ms_retval;
	void* ms_val;
	size_t ms_sz;
} ms_ecall_pointer_user_check_t;

typedef struct ms_ecall_pointer_in_t {
	int* ms_val;
} ms_ecall_pointer_in_t;

typedef struct ms_ecall_pointer_out_t {
	int* ms_val;
} ms_ecall_pointer_out_t;

typedef struct ms_ecall_pointer_in_out_t {
	int* ms_val;
} ms_ecall_pointer_in_out_t;

typedef struct ms_ecall_pointer_string_t {
	char* ms_str;
	size_t ms_str_len;
} ms_ecall_pointer_string_t;

typedef struct ms_ecall_pointer_string_const_t {
	char* ms_str;
	size_t ms_str_len;
} ms_ecall_pointer_string_const_t;

typedef struct ms_ecall_pointer_size_t {
	void* ms_ptr;
	size_t ms_len;
} ms_ecall_pointer_size_t;

typedef struct ms_ecall_pointer_count_t {
	int* ms_arr;
	int ms_cnt;
} ms_ecall_pointer_count_t;

typedef struct ms_ecall_pointer_isptr_readonly_t {
	buffer_t ms_buf;
	size_t ms_len;
} ms_ecall_pointer_isptr_readonly_t;

typedef struct ms_ecall_array_user_check_t {
	int* ms_arr;
} ms_ecall_array_user_check_t;

typedef struct ms_ecall_array_in_t {
	int* ms_arr;
} ms_ecall_array_in_t;

typedef struct ms_ecall_array_out_t {
	int* ms_arr;
} ms_ecall_array_out_t;

typedef struct ms_ecall_array_in_out_t {
	int* ms_arr;
} ms_ecall_array_in_out_t;

typedef struct ms_ecall_array_isary_t {
	array_t*  ms_arr;
} ms_ecall_array_isary_t;

typedef struct ms_ecall_function_private_t {
	int ms_retval;
} ms_ecall_function_private_t;

typedef struct ms_ecall_sgx_cpuid_t {
	int* ms_cpuinfo;
	int ms_leaf;
} ms_ecall_sgx_cpuid_t;

typedef struct ms_ecall_increase_counter_t {
	size_t ms_retval;
} ms_ecall_increase_counter_t;

typedef struct ms_ocall_print_string_t {
	char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_getOutsidePtr_OCALL_t {
	unsigned char* ms_retval;
} ms_getOutsidePtr_OCALL_t;

typedef struct ms_createLSORAM_OCALL_t {
	void* ms_retval;
	uint32_t ms_id;
	uint32_t ms_key_size;
	uint32_t ms_value_size;
	uint32_t ms_num_blocks_p;
	uint8_t ms_oblv_mode;
} ms_createLSORAM_OCALL_t;

typedef struct ms_build_fetchChildHash_t {
	uint32_t ms_left;
	uint32_t ms_right;
	unsigned char* ms_lchild;
	unsigned char* ms_rchild;
	uint32_t ms_hash_size;
	uint32_t ms_recursion_level;
} ms_build_fetchChildHash_t;

typedef struct ms_uploadBucket_OCALL_t {
	uint8_t ms_retval;
	unsigned char* ms_serialized_bucket;
	uint32_t ms_bucket_size;
	uint32_t ms_label;
	unsigned char* ms_hash;
	uint32_t ms_hash_size;
	uint32_t ms_size_for_level;
	uint8_t ms_recursion_level;
} ms_uploadBucket_OCALL_t;

typedef struct ms_downloadBucket_OCALL_t {
	uint8_t ms_retval;
	unsigned char* ms_serialized_bucket;
	uint32_t ms_bucket_size;
	uint32_t ms_label;
	unsigned char* ms_hash;
	uint32_t ms_hash_size;
	uint32_t ms_size_for_level;
	uint8_t ms_level;
} ms_downloadBucket_OCALL_t;

typedef struct ms_downloadPath_OCALL_t {
	uint8_t ms_retval;
	unsigned char* ms_serialized_path;
	uint32_t ms_path_size;
	uint32_t ms_label;
	unsigned char* ms_path_hash;
	uint32_t ms_path_hash_size;
	uint8_t ms_level;
	uint32_t ms_D_lev;
} ms_downloadPath_OCALL_t;

typedef struct ms_uploadPath_OCALL_t {
	uint8_t ms_retval;
	unsigned char* ms_serialized_path;
	uint32_t ms_path_size;
	uint32_t ms_label;
	unsigned char* ms_path_hash;
	uint32_t ms_path_hash_size;
	uint8_t ms_level;
	uint32_t ms_D_level;
} ms_uploadPath_OCALL_t;

typedef struct ms_time_report_t {
	uint8_t ms_point;
} ms_time_report_t;

typedef struct ms_ocall_pointer_user_check_t {
	int* ms_val;
} ms_ocall_pointer_user_check_t;

typedef struct ms_ocall_pointer_in_t {
	int* ms_val;
} ms_ocall_pointer_in_t;

typedef struct ms_ocall_pointer_out_t {
	int* ms_val;
} ms_ocall_pointer_out_t;

typedef struct ms_ocall_pointer_in_out_t {
	int* ms_val;
} ms_ocall_pointer_in_out_t;

typedef struct ms_memccpy_t {
	void* ms_retval;
	void* ms_dest;
	void* ms_src;
	int ms_val;
	size_t ms_len;
} ms_memccpy_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_getOutsidePtr_OCALL(void* pms)
{
	ms_getOutsidePtr_OCALL_t* ms = SGX_CAST(ms_getOutsidePtr_OCALL_t*, pms);
	ms->ms_retval = getOutsidePtr_OCALL();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_createLSORAM_OCALL(void* pms)
{
	ms_createLSORAM_OCALL_t* ms = SGX_CAST(ms_createLSORAM_OCALL_t*, pms);
	ms->ms_retval = createLSORAM_OCALL(ms->ms_id, ms->ms_key_size, ms->ms_value_size, ms->ms_num_blocks_p, ms->ms_oblv_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_build_fetchChildHash(void* pms)
{
	ms_build_fetchChildHash_t* ms = SGX_CAST(ms_build_fetchChildHash_t*, pms);
	build_fetchChildHash(ms->ms_left, ms->ms_right, ms->ms_lchild, ms->ms_rchild, ms->ms_hash_size, ms->ms_recursion_level);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_uploadBucket_OCALL(void* pms)
{
	ms_uploadBucket_OCALL_t* ms = SGX_CAST(ms_uploadBucket_OCALL_t*, pms);
	ms->ms_retval = uploadBucket_OCALL(ms->ms_serialized_bucket, ms->ms_bucket_size, ms->ms_label, ms->ms_hash, ms->ms_hash_size, ms->ms_size_for_level, ms->ms_recursion_level);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_downloadBucket_OCALL(void* pms)
{
	ms_downloadBucket_OCALL_t* ms = SGX_CAST(ms_downloadBucket_OCALL_t*, pms);
	ms->ms_retval = downloadBucket_OCALL(ms->ms_serialized_bucket, ms->ms_bucket_size, ms->ms_label, ms->ms_hash, ms->ms_hash_size, ms->ms_size_for_level, ms->ms_level);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_downloadPath_OCALL(void* pms)
{
	ms_downloadPath_OCALL_t* ms = SGX_CAST(ms_downloadPath_OCALL_t*, pms);
	ms->ms_retval = downloadPath_OCALL(ms->ms_serialized_path, ms->ms_path_size, ms->ms_label, ms->ms_path_hash, ms->ms_path_hash_size, ms->ms_level, ms->ms_D_lev);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_uploadPath_OCALL(void* pms)
{
	ms_uploadPath_OCALL_t* ms = SGX_CAST(ms_uploadPath_OCALL_t*, pms);
	ms->ms_retval = uploadPath_OCALL(ms->ms_serialized_path, ms->ms_path_size, ms->ms_label, ms->ms_path_hash, ms->ms_path_hash_size, ms->ms_level, ms->ms_D_level);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_time_report(void* pms)
{
	ms_time_report_t* ms = SGX_CAST(ms_time_report_t*, pms);
	time_report(ms->ms_point);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pointer_user_check(void* pms)
{
	ms_ocall_pointer_user_check_t* ms = SGX_CAST(ms_ocall_pointer_user_check_t*, pms);
	ocall_pointer_user_check(ms->ms_val);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pointer_in(void* pms)
{
	ms_ocall_pointer_in_t* ms = SGX_CAST(ms_ocall_pointer_in_t*, pms);
	ocall_pointer_in(ms->ms_val);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pointer_out(void* pms)
{
	ms_ocall_pointer_out_t* ms = SGX_CAST(ms_ocall_pointer_out_t*, pms);
	ocall_pointer_out(ms->ms_val);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pointer_in_out(void* pms)
{
	ms_ocall_pointer_in_out_t* ms = SGX_CAST(ms_ocall_pointer_in_out_t*, pms);
	ocall_pointer_in_out(ms->ms_val);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_memccpy(void* pms)
{
	ms_memccpy_t* ms = SGX_CAST(ms_memccpy_t*, pms);
	ms->ms_retval = memccpy(ms->ms_dest, (const void*)ms->ms_src, ms->ms_val, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_function_allow(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_function_allow();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[20];
} ocall_table_Enclave = {
	20,
	{
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_getOutsidePtr_OCALL,
		(void*)Enclave_createLSORAM_OCALL,
		(void*)Enclave_build_fetchChildHash,
		(void*)Enclave_uploadBucket_OCALL,
		(void*)Enclave_downloadBucket_OCALL,
		(void*)Enclave_downloadPath_OCALL,
		(void*)Enclave_uploadPath_OCALL,
		(void*)Enclave_time_report,
		(void*)Enclave_ocall_pointer_user_check,
		(void*)Enclave_ocall_pointer_in,
		(void*)Enclave_ocall_pointer_out,
		(void*)Enclave_ocall_pointer_in_out,
		(void*)Enclave_memccpy,
		(void*)Enclave_ocall_function_allow,
		(void*)Enclave_sgx_oc_cpuidex,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t createNewORAMInstance(sgx_enclave_id_t eid, uint32_t* retval, uint32_t maxBlocks, uint32_t dataSize, uint32_t stashSize, uint32_t oblivious_flag, uint32_t recursion_data_size, int8_t recursion_levels, uint64_t onchip_posmap_mem_limit, uint32_t oram_type, uint8_t pZ)
{
	sgx_status_t status;
	ms_createNewORAMInstance_t ms;
	ms.ms_maxBlocks = maxBlocks;
	ms.ms_dataSize = dataSize;
	ms.ms_stashSize = stashSize;
	ms.ms_oblivious_flag = oblivious_flag;
	ms.ms_recursion_data_size = recursion_data_size;
	ms.ms_recursion_levels = recursion_levels;
	ms.ms_onchip_posmap_mem_limit = onchip_posmap_mem_limit;
	ms.ms_oram_type = oram_type;
	ms.ms_pZ = pZ;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t createNewLSORAMInstance(sgx_enclave_id_t eid, uint32_t* retval, uint32_t key_size, uint32_t value_size, uint32_t num_blocks, uint8_t mem_mode, uint8_t oblivious_type, uint8_t dummy_populate)
{
	sgx_status_t status;
	ms_createNewLSORAMInstance_t ms;
	ms.ms_key_size = key_size;
	ms.ms_value_size = value_size;
	ms.ms_num_blocks = num_blocks;
	ms.ms_mem_mode = mem_mode;
	ms.ms_oblivious_type = oblivious_type;
	ms.ms_dummy_populate = dummy_populate;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t accessInterface(sgx_enclave_id_t eid, uint32_t instance_id, uint8_t oram_type, unsigned char* encrypted_request, unsigned char* encrypted_response, unsigned char* tag_in, unsigned char* tag_out, uint32_t request_size, uint32_t response_size, uint32_t tag_size)
{
	sgx_status_t status;
	ms_accessInterface_t ms;
	ms.ms_instance_id = instance_id;
	ms.ms_oram_type = oram_type;
	ms.ms_encrypted_request = encrypted_request;
	ms.ms_encrypted_response = encrypted_response;
	ms.ms_tag_in = tag_in;
	ms.ms_tag_out = tag_out;
	ms.ms_request_size = request_size;
	ms.ms_response_size = response_size;
	ms.ms_tag_size = tag_size;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t accessBulkReadInterface(sgx_enclave_id_t eid, uint32_t instance_id, uint8_t oram_type, uint32_t no_of_requests, unsigned char* encrypted_request, unsigned char* encrypted_response, unsigned char* tag_in, unsigned char* tag_out, uint32_t request_size, uint32_t response_size, uint32_t tag_size)
{
	sgx_status_t status;
	ms_accessBulkReadInterface_t ms;
	ms.ms_instance_id = instance_id;
	ms.ms_oram_type = oram_type;
	ms.ms_no_of_requests = no_of_requests;
	ms.ms_encrypted_request = encrypted_request;
	ms.ms_encrypted_response = encrypted_response;
	ms.ms_tag_in = tag_in;
	ms.ms_tag_out = tag_out;
	ms.ms_request_size = request_size;
	ms.ms_response_size = response_size;
	ms.ms_tag_size = tag_size;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t InitializeKeys(sgx_enclave_id_t eid, int8_t* retval, unsigned char* bin_x, unsigned char* bin_y, unsigned char* bin_r, unsigned char* bin_s, uint32_t size_bin)
{
	sgx_status_t status;
	ms_InitializeKeys_t ms;
	ms.ms_bin_x = bin_x;
	ms.ms_bin_y = bin_y;
	ms.ms_bin_r = bin_r;
	ms.ms_bin_s = bin_s;
	ms.ms_size_bin = size_bin;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t LSORAMInsert(sgx_enclave_id_t eid, int8_t* retval, uint32_t instance_id, unsigned char* encrypted_request, uint32_t request_size, unsigned char* tag_in, uint32_t tag_size, unsigned char* client_pubkey, uint32_t pubkey_size, uint32_t pubkey_size_x, uint32_t pubkey_size_y)
{
	sgx_status_t status;
	ms_LSORAMInsert_t ms;
	ms.ms_instance_id = instance_id;
	ms.ms_encrypted_request = encrypted_request;
	ms.ms_request_size = request_size;
	ms.ms_tag_in = tag_in;
	ms.ms_tag_size = tag_size;
	ms.ms_client_pubkey = client_pubkey;
	ms.ms_pubkey_size = pubkey_size;
	ms.ms_pubkey_size_x = pubkey_size_x;
	ms.ms_pubkey_size_y = pubkey_size_y;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t LSORAMFetch(sgx_enclave_id_t eid, int8_t* retval, uint32_t instance_id, unsigned char* encrypted_request, uint32_t request_size, unsigned char* encrypted_response, uint32_t response_size, unsigned char* tag_in, unsigned char* tag_out, uint32_t tag_size, unsigned char* client_pubkey, uint32_t pubkey_size, uint32_t pubkey_size_x, uint32_t pubkey_size_y)
{
	sgx_status_t status;
	ms_LSORAMFetch_t ms;
	ms.ms_instance_id = instance_id;
	ms.ms_encrypted_request = encrypted_request;
	ms.ms_request_size = request_size;
	ms.ms_encrypted_response = encrypted_response;
	ms.ms_response_size = response_size;
	ms.ms_tag_in = tag_in;
	ms.ms_tag_out = tag_out;
	ms.ms_tag_size = tag_size;
	ms.ms_client_pubkey = client_pubkey;
	ms.ms_pubkey_size = pubkey_size;
	ms.ms_pubkey_size_x = pubkey_size_x;
	ms.ms_pubkey_size_y = pubkey_size_y;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t LSORAMEvict(sgx_enclave_id_t eid, int8_t* retval, uint32_t instance_id, unsigned char* key, uint32_t key_size)
{
	sgx_status_t status;
	ms_LSORAMEvict_t ms;
	ms.ms_instance_id = instance_id;
	ms.ms_key = key;
	ms.ms_key_size = key_size;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t deleteLSORAMInstance(sgx_enclave_id_t eid, uint8_t* retval, uint32_t instance_id)
{
	sgx_status_t status;
	ms_deleteLSORAMInstance_t ms;
	ms.ms_instance_id = instance_id;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_type_char(sgx_enclave_id_t eid, char val)
{
	sgx_status_t status;
	ms_ecall_type_char_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 9, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_type_int(sgx_enclave_id_t eid, int val)
{
	sgx_status_t status;
	ms_ecall_type_int_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 10, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_type_float(sgx_enclave_id_t eid, float val)
{
	sgx_status_t status;
	ms_ecall_type_float_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 11, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_type_double(sgx_enclave_id_t eid, double val)
{
	sgx_status_t status;
	ms_ecall_type_double_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 12, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_type_size_t(sgx_enclave_id_t eid, size_t val)
{
	sgx_status_t status;
	ms_ecall_type_size_t_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 13, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_type_wchar_t(sgx_enclave_id_t eid, wchar_t val)
{
	sgx_status_t status;
	ms_ecall_type_wchar_t_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 14, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_type_struct(sgx_enclave_id_t eid, struct struct_foo_t val)
{
	sgx_status_t status;
	ms_ecall_type_struct_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 15, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_type_enum_union(sgx_enclave_id_t eid, enum enum_foo_t val1, union union_foo_t* val2)
{
	sgx_status_t status;
	ms_ecall_type_enum_union_t ms;
	ms.ms_val1 = val1;
	ms.ms_val2 = val2;
	status = sgx_ecall(eid, 16, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_user_check(sgx_enclave_id_t eid, size_t* retval, void* val, size_t sz)
{
	sgx_status_t status;
	ms_ecall_pointer_user_check_t ms;
	ms.ms_val = val;
	ms.ms_sz = sz;
	status = sgx_ecall(eid, 17, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_pointer_in(sgx_enclave_id_t eid, int* val)
{
	sgx_status_t status;
	ms_ecall_pointer_in_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 18, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_out(sgx_enclave_id_t eid, int* val)
{
	sgx_status_t status;
	ms_ecall_pointer_out_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 19, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_in_out(sgx_enclave_id_t eid, int* val)
{
	sgx_status_t status;
	ms_ecall_pointer_in_out_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 20, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_string(sgx_enclave_id_t eid, char* str)
{
	sgx_status_t status;
	ms_ecall_pointer_string_t ms;
	ms.ms_str = (char*)str;
	ms.ms_str_len = str ? strlen(str) + 1 : 0;
	status = sgx_ecall(eid, 21, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_string_const(sgx_enclave_id_t eid, const char* str)
{
	sgx_status_t status;
	ms_ecall_pointer_string_const_t ms;
	ms.ms_str = (char*)str;
	ms.ms_str_len = str ? strlen(str) + 1 : 0;
	status = sgx_ecall(eid, 22, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_size(sgx_enclave_id_t eid, void* ptr, size_t len)
{
	sgx_status_t status;
	ms_ecall_pointer_size_t ms;
	ms.ms_ptr = ptr;
	ms.ms_len = len;
	status = sgx_ecall(eid, 23, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_count(sgx_enclave_id_t eid, int* arr, int cnt)
{
	sgx_status_t status;
	ms_ecall_pointer_count_t ms;
	ms.ms_arr = arr;
	ms.ms_cnt = cnt;
	status = sgx_ecall(eid, 24, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_isptr_readonly(sgx_enclave_id_t eid, buffer_t buf, size_t len)
{
	sgx_status_t status;
	ms_ecall_pointer_isptr_readonly_t ms;
	ms.ms_buf = (buffer_t)buf;
	ms.ms_len = len;
	status = sgx_ecall(eid, 25, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ocall_pointer_attr(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 26, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_array_user_check(sgx_enclave_id_t eid, int arr[4])
{
	sgx_status_t status;
	ms_ecall_array_user_check_t ms;
	ms.ms_arr = (int*)arr;
	status = sgx_ecall(eid, 27, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_array_in(sgx_enclave_id_t eid, int arr[4])
{
	sgx_status_t status;
	ms_ecall_array_in_t ms;
	ms.ms_arr = (int*)arr;
	status = sgx_ecall(eid, 28, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_array_out(sgx_enclave_id_t eid, int arr[4])
{
	sgx_status_t status;
	ms_ecall_array_out_t ms;
	ms.ms_arr = (int*)arr;
	status = sgx_ecall(eid, 29, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_array_in_out(sgx_enclave_id_t eid, int arr[4])
{
	sgx_status_t status;
	ms_ecall_array_in_out_t ms;
	ms.ms_arr = (int*)arr;
	status = sgx_ecall(eid, 30, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_array_isary(sgx_enclave_id_t eid, array_t arr)
{
	sgx_status_t status;
	ms_ecall_array_isary_t ms;
	ms.ms_arr = (array_t *)&arr[0];
	status = sgx_ecall(eid, 31, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_function_calling_convs(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 32, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_function_public(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 33, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_function_private(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_function_private_t ms;
	status = sgx_ecall(eid, 34, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_malloc_free(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 35, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_sgx_cpuid(sgx_enclave_id_t eid, int cpuinfo[4], int leaf)
{
	sgx_status_t status;
	ms_ecall_sgx_cpuid_t ms;
	ms.ms_cpuinfo = (int*)cpuinfo;
	ms.ms_leaf = leaf;
	status = sgx_ecall(eid, 36, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_exception(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 37, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_map(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 38, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_increase_counter(sgx_enclave_id_t eid, size_t* retval)
{
	sgx_status_t status;
	ms_ecall_increase_counter_t ms;
	status = sgx_ecall(eid, 39, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_producer(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 40, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_consumer(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 41, &ocall_table_Enclave, NULL);
	return status;
}

