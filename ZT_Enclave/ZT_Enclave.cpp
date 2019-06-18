/*
*    ZeroTrace: Oblivious Memory Primitives from Intel SGX 
*    Copyright (C) 2018  Sajin (sshsshy)
*
*    This program is free software: you can redistribute it and/or modify
*    it under the terms of the GNU General Public License as published by
*    the Free Software Foundation, version 3 of the License.
*
*    This program is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*    GNU General Public License for more details.
*
*    You should have received a copy of the GNU General Public License
*    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <string.h>
#include <vector>
#include "Globals_Enclave.hpp"
#include "ORAMTree.hpp"
#include "PathORAM_Enclave.hpp"
#include "CircuitORAM_Enclave.hpp"
#include "tsgxsslio.h"

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

std::vector<PathORAM *> poram_instances;
std::vector<CircuitORAM *> coram_instances;

uint32_t poram_instance_id=0;
uint32_t coram_instance_id=0;

bool extractSealedKeys(){
	/*
	uint32_t sealed_keys_size = ;
	unsigned char *sealed_keys = malloc(sealed_keys_size);
		
	// OCALL to outside to extract sealed key
	bool return_value=false;
	retrieveSealedKeys(&return_value, sealed_keys, sealed_keys_size);

	if(return_value==false){
		return false;
	}
	else{
		//Parse the sealed blob, extract keys
		return true
	}
	*/
	
	return false;
}

void serializeECCKeys(sgx_ec256_private_t *ZT_private_key, sgx_ec256_public_t *ZT_public_key, unsigned char *serialized_keys) {
	//Memcpy bytewise all three pieces of the keys into serialized_keys
	unsigned char *serialized_keys_ptr = serialized_keys;	
	memcpy(serialized_keys_ptr, ZT_private_key->r, SGX_ECP256_KEY_SIZE);
	serialized_keys_ptr+=SGX_ECP256_KEY_SIZE;
	memcpy(serialized_keys_ptr, ZT_public_key->gx, SGX_ECP256_KEY_SIZE);
	serialized_keys_ptr+=SGX_ECP256_KEY_SIZE;
	memcpy(serialized_keys_ptr, ZT_public_key->gy, SGX_ECP256_KEY_SIZE);
}

void enclave_sha256(char * string, uint32_t str_len){
	sgx_status_t ret = SGX_SUCCESS;
	sgx_sha256_hash_t p_hash;
	sgx_sha256_msg((const uint8_t*) string, str_len, &p_hash);
	printf("SHA256 Output Enclave: \n");
	for(int i = 0; i < SGX_SHA256_HASH_SIZE ; i++)
	{
		printf("%02x ", p_hash[i]);
	}
	printf("\n");
}

void SerializeBNPair(BIGNUM *x, BIGNUM *y, unsigned char **bin_x, unsigned char **bin_y){
	uint32_t size_bin_x = BN_num_bytes(x);
	uint32_t size_bin_y = BN_num_bytes(y);
	*bin_x = (unsigned char*) malloc(size_bin_x);
	*bin_y = (unsigned char*) malloc(size_bin_y);
	BN_bn2bin(x, *bin_x);
	BN_bn2bin(y, *bin_y);  
}

bool generateAndSealKeys(){
	EC_KEY *ec_signing = NULL;
	ECDSA_SIG *sig_sgxssl = NULL, *sig_pubkey = NULL;
	const EC_POINT* pub_point = NULL;
	const BIGNUM *sig_r, *sig_s;
	unsigned char *bin_x, *bin_y, *bin_r, *bin_s;
	BIGNUM *x, *y;
	x = BN_new();
	y = BN_new();
	BN_CTX *bn_ctx = BN_CTX_new();
		printf("HERE 1\n");
	EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	
	int ret;
	ec_signing = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (ec_signing == NULL) {
		printf("Enclave: EC_KEY_new_by_curve_name failure: %ld\n", ERR_get_error());
		return false;
	}
	sgx_EC_key_pair = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (ec_signing == NULL) {
		printf("Enclave: EC_KEY_new_by_curve_name failure: %ld\n", ERR_get_error());
		return false;
	}

	//Setp hardcoded Enclave Signing Key
	BIGNUM *r;
	r = BN_new();
	r = BN_bin2bn(hardcoded_signing_key, SGX_ECP256_KEY_SIZE, NULL);
	
	ret = EC_KEY_set_private_key(ec_signing, r);
	if(ret==0)
		printf("Error with EC_KEY_set_private_key()\n");

	//Generate an EC Key pair
	if (!EC_KEY_generate_key(sgx_EC_key_pair))
		printf("Enclave: Sampling keys failed\n");

	//Get x,y from ephemeral_key
	pub_point = EC_KEY_get0_public_key(sgx_EC_key_pair);
	if(pub_point == NULL)
		printf("Enclave: EC_KEY_get0_public_key Failed \n");
	ret = EC_POINT_get_affine_coordinates_GFp(ec_group, pub_point, x, y, bn_ctx);
	if(ret==0)
		printf("Enclave: EC_POINT_get_affine_coordinates_GFp Failed \n");

	//TODO: Seal Keys
	//Serialize public_key x,y to binary
	uint32_t size_bin_x = BN_num_bytes(x), size_bin_y = BN_num_bytes(y);
	SerializeBNPair(x, y, &bin_x, &bin_y);
	
	//Sign the ephemeral key pair before publishing
	//Sign (bin_x||bin_y)
	uint32_t serialized_pub_key_size = size_bin_x + size_bin_y;
	unsigned char *serialized_pub_key = (unsigned char*) malloc(serialized_pub_key_size);
	memcpy(serialized_pub_key, bin_x, size_bin_x);
	memcpy(serialized_pub_key + size_bin_x, bin_y, size_bin_y);
	BIGNUM *kinv = NULL, *rp = NULL;
	ECDSA_sign_setup(ec_signing, NULL, &kinv, &rp);
	sig_pubkey = ECDSA_do_sign_ex((const unsigned char*) serialized_pub_key, serialized_pub_key_size, kinv, rp, ec_signing);
	if(sig_pubkey == NULL)
		printf("Enclave: ECDSA_do_sign_ex ERROR\n");

	//Serialize signature
	ECDSA_SIG_get0(sig_pubkey, &sig_r, &sig_s);
	uint32_t size_bin_r = BN_num_bytes(sig_r), size_bin_s = BN_num_bytes(sig_s);
	SerializeBNPair((BIGNUM*) sig_r, (BIGNUM*) sig_s, &bin_r, &bin_s);
	
	//Publish ephemeral key pair and the signature
	PublishKey(bin_x, size_bin_x, bin_y, size_bin_y, bin_r, bin_s, size_bin_r, size_bin_s);
		
	free(serialized_pub_key);
	free(bin_x);
	free(bin_y);
	free(bin_r);
	free(bin_s);	
	return true;
}

/*
bool generateAndSealKeys(){
	sgx_status_t ecc_return=SGX_SUCCESS;
	sgx_ecc_state_handle_t ecc_handle;
	sgx_ec256_public_t verification_key;

	//Parameters for sgx_seal_data
	sgx_sealed_data_t p_sealed_data;
	sgx_attributes_t attribute_mask;
	sgx_misc_select_t misc_mask;
	attribute_mask.flags = 0xFF0000000000000B;
	attribute_mask.xfrm = 0;
	misc_mask = 0xF0000000;

	ecc_return = sgx_ecc256_open_context(&ecc_handle);
	if(ecc_return!=SGX_SUCCESS)
		printf("OPEN ECC Context FAIL!!\n");
	
	ecc_return = sgx_ecc256_create_key_pair(&ZT_private_key, &ZT_public_key, ecc_handle);
	if(ecc_return!=SGX_SUCCESS)
		printf("Sampling ECC Keys FAIL!!\n");
	else
		printf("Sampling ECC Keys SUCCESS!!\n");

	PushSampledKeysOut((unsigned char *) ZT_private_key.r, SGX_ECP256_KEY_SIZE, (unsigned char*) ZT_public_key.gx, (unsigned char*) ZT_public_key.gy);	

	
	uint32_t seal_data_size = SGX_ECP256_KEY_SIZE*3;
	unsigned char *serialized_keys = (unsigned char*) malloc(seal_data_size);
	uint32_t sealed_data_size = sgx_calc_sealed_data_size(0, seal_data_size);
	printf("sealed_data_size = %d\n", sealed_data_size);
	serializeECCKeys(&ZT_private_key, &ZT_public_key, serialized_keys);
	

	char text[3]="HI";
	enclave_sha256(text, 2);
	sgx_ec256_signature_t ec_signature;

	memcpy((uint8_t*) private_signing_key.r, (uint8_t*) hardcoded_signing_key, SGX_ECP256_KEY_SIZE);
	memcpy((uint8_t*) verification_key.gx, (uint8_t*) hardcoded_verification_key_x, SGX_ECP256_KEY_SIZE);
	memcpy((uint8_t*) verification_key.gy, (uint8_t*) hardcoded_verification_key_y, SGX_ECP256_KEY_SIZE);

	//For signing with SGX sampled ECDSA key
	//ecc_return = sgx_ecdsa_sign((const uint8_t *) text, 2, (sgx_ec256_private_t*) &ZT_private_key, &ec_signature, ecc_handle);
	
	//Sign with OpenSSL generated hardcoded key	
	ecc_return = sgx_ecdsa_sign((const uint8_t *) text, 2, (sgx_ec256_private_t*) &private_signing_key, &ec_signature, ecc_handle);

	if(ecc_return!= SGX_SUCCESS)
		printf("ERROR WITH sgx_ecdsa_sign\n");

	//p_sealed_data.aes_data.payload=aes_gcm_buffer;
	//KEYPOLICY_MRENCLAVE = 0x0001
	//KEYPOLICY_MRSIGNER = 0x0002
	//ecc_return = sgx_seal_data_ex(0x0001, attribute_mask, misc_mask, 0, NULL, seal_data_size, (uint8_t*) serialized_keys, sealed_data_size, &p_sealed_data);
	//ecc_return = sgx_seal_data(0, NULL, seal_data_size, (uint8_t*) serialized_keys, sealed_data_size, &p_sealed_data);
	//if(ecc_return!=SGX_SUCCESS)
	//	printf("sgx_seal_data FAIL!!\n");
	//OCALL to seal keys and store public key in plaintext (for client to retrieve)

	//VerifySignatureOutside((uint32_t *)ec_signature.x, SGX_NISTP_ECP256_KEY_SIZE, (uint32_t*) ec_signature.y, SGX_NISTP_ECP256_KEY_SIZE);

	unsigned char *signature_r = (unsigned char*) malloc(SGX_ECP256_KEY_SIZE);
	unsigned char *signature_s = (unsigned char*) malloc(SGX_ECP256_KEY_SIZE);
	sgx_ec256_signature_t openssl_signature;
	unsigned char *ptr_x = (unsigned char*) ec_signature.x;
	unsigned char *ptr_y = (unsigned char*) ec_signature.y;

	printf("SGX Signature bytes:\n");
	printf("Sig_r : ");
	for(int r = 0; r < SGX_ECP256_KEY_SIZE; r++){
		printf("%02x ", *(ptr_x+r));
	}	
	printf("\n");

	printf("Sig_s : ");
	for(int r = 0; r < SGX_ECP256_KEY_SIZE; r++){
		printf("%02x ", *(ptr_y+r));
	}	
	printf("\n");

	VerifySignatureOutside( SGX_ECP256_KEY_SIZE, (unsigned char *)ec_signature.x, (unsigned char*) ec_signature.y, (unsigned char *) private_signing_key.r, (unsigned char*) verification_key.gx, (unsigned char*) verification_key.gy, signature_r, signature_s);
	
	memcpy((unsigned char *) openssl_signature.x, signature_r, SGX_ECP256_KEY_SIZE);
	memcpy((unsigned char *) openssl_signature.y, signature_s, SGX_ECP256_KEY_SIZE);
		
	uint8_t result;
	int result1;

	//Check valid public key point:
	sgx_ecc256_check_point(&verification_key, ecc_handle, &result1);
	if(result1==0)
		printf("PK is an invalid point! \n");
	else printf("PK is valid point! \n");
	

	//Verify with SGX sampled ECDSA keys
	//ecc_return = sgx_ecdsa_verify((const uint8_t *) text, 2, &ZT_public_key, &ec_signature,
        //                               &result, ecc_handle);

	//Verify with OpenSSL generated hardcoded keys
	ecc_return = sgx_ecdsa_verify((const uint8_t *) text, 2, &verification_key, &ec_signature,
                                        &result, ecc_handle);

	if(ecc_return != SGX_SUCCESS)
		printf("sgx_ecdsa_verify did not return SGX_SUCCESS\n");
		
	printf("result = %d\n", result);
	if(result==SGX_EC_VALID)
		printf("SGX Verifying signature(with hardcoded-keys) with hardcoded keys: Valid Signature \n");
	else if (result== SGX_EC_INVALID_SIGNATURE)
		printf("SGX Verifying signature(with hardcoded-keys) with hardcoded keys: Invalid Signature \n");

	//Verify the OpenSSL signature using hardcoded keys
	ecc_return = sgx_ecdsa_verify((const uint8_t *) text, 2, &verification_key, &openssl_signature,
                                        &result, ecc_handle);

	if(ecc_return != SGX_SUCCESS)
		printf("sgx_ecdsa_verify did not return SGX_SUCCESS\n");
		
	printf("result = %d\n", result);
	if(result==SGX_EC_VALID)
		printf("SGX verifying Signature generated by OpenSSL with hardcoded-keys: Valid Signature \n");
	else if (result== SGX_EC_INVALID_SIGNATURE)
		printf("SGX verifying Signature generated by OpenSSL with hardcoded-keys: Invalid Signature \n");

	//unsigned char *serialized_keys_ptr = serialized_keys+SGX_ECP256_KEY_SIZE;
	//Sign the public key with the Hardcoded ECDSA keys before publishing
	//ECDSA_sign(serialized_keys_ptr, SGX_ECP256_KEY_SIZE*2);
	//ecc_return = sgx_ecdsa_sign(serialized_keys_ptr, SGX_ECP256_KEY_SIZE*2, private_signing_key, &sign, ecc_handle);
	
	if(ecc_return!=SGX_SUCCESS)
		printf("Signing Failed!!\n");
	else
		printf("Signing SUCCESS!!\n");
	
	//Publish Signed Public Key
	//publishPublicKey(serialized_keys_ptr, SGX_ECP256_KEY_SIZE*2);

	//free(serialized_keys);	
	sgx_ecc256_close_context(ecc_handle);
}
*/

void InitializeKeys(){
	if(!PK_in_memory){
		//Attempt to extract a previously sealed key-pair
		if(!extractSealedKeys()){
			generateAndSealKeys();
		}
	}	
}

uint32_t createNewORAMInstance(uint32_t max_blocks, uint32_t data_size, uint32_t stash_size, uint32_t oblivious_flag, uint32_t recursion_data_size, int8_t recursion_levels, uint64_t onchip_posmap_mem_limit, uint32_t oram_type, uint8_t pZ){

	if(oram_type==0){
		PathORAM *new_poram_instance = (PathORAM*) malloc(sizeof(PathORAM));
		poram_instances.push_back(new_poram_instance);
		
		#ifdef DEBUG_ZT_ENCLAVE
			printf("In createNewORAMInstance, before Create, recursion_levels = %d\n", recursion_levels);	
		#endif
		
		//TODO : INVOKING THE VIRTUAL FUNCTION SEG-FAULTS:		
		//new_poram_instance->Create(pZ, max_blocks, data_size, stash_size, oblivious_flag, recursion_data_size, recursion_levels, onchip_posmap_mem_limit);
		new_poram_instance->Initialize(pZ, max_blocks, data_size, stash_size, oblivious_flag, recursion_data_size, recursion_levels, onchip_posmap_mem_limit);
		#ifdef DEBUG_ZT_ENCLAVE
			printf("In createNewORAMInstance, after Create\n");	
		#endif			
		return poram_instance_id++;
	}
	else if(oram_type==1){
		CircuitORAM *new_coram_instance = (CircuitORAM*) malloc(sizeof(CircuitORAM));
		coram_instances.push_back(new_coram_instance);

		printf("Just before Create\n");
		//new_coram_instance->Create();
		//new_coram_instance->Create(pZ, max_blocks, data_size, stash_size, oblivious_flag, recursion_data_size, recursion_levels, onchip_posmap_mem_limit);
		new_coram_instance->Initialize(pZ, max_blocks, data_size, stash_size, oblivious_flag, recursion_data_size, recursion_levels, onchip_posmap_mem_limit);	
		return coram_instance_id++;
	}
}


void accessInterface(uint32_t instance_id, uint8_t oram_type, unsigned char *encrypted_request, unsigned char *encrypted_response, unsigned char *tag_in, unsigned char* tag_out, uint32_t encrypted_request_size, uint32_t response_size, uint32_t tag_size){
	//TODO : Would be nice to remove this dynamic allocation.
	PathORAM *poram_current_instance;
	CircuitORAM *coram_current_instance;

	unsigned char *data_in, *data_out, *request, *request_ptr;
	uint32_t id, opType;
	request = (unsigned char *) malloc (encrypted_request_size);
	data_out = (unsigned char *) malloc (response_size);	

	sgx_status_t status = SGX_SUCCESS;
	status = sgx_rijndael128GCM_decrypt((const sgx_aes_gcm_128bit_key_t *) SHARED_AES_KEY, (const uint8_t *) encrypted_request,
                                    encrypted_request_size, (uint8_t *) request, (const uint8_t *) HARDCODED_IV, IV_LENGTH,
                                    NULL, 0, (const sgx_aes_gcm_128bit_tag_t*) tag_in);
	/*	
	if(status == SGX_SUCCESS)
		printf("Decrypt returned Success flag\n");
	else{
		if(status == SGX_ERROR_INVALID_PARAMETER)
			printf("Decrypt returned SGX_ERROR_INVALID_PARAMETER Failure flag\n");		
		else
			printf("Decrypt returned another Failure flag\n");
	}
	*/

	//Extract Request Id and OpType
	opType = request[0];
	request_ptr = request+1;
	memcpy(&id, request_ptr, ID_SIZE_IN_BYTES); 
	//printf("Request Type = %c, Request_id = %d", opType, id);
	data_in = request_ptr+ID_SIZE_IN_BYTES;

	//TODO: Fix Instances issue.
	//current_instance_2->Access();
	//current_instance_2->Access(id, opType, data_in, data_out);
	if(oram_type==0){
		poram_current_instance = poram_instances[instance_id];
		poram_current_instance->Access_temp(id, opType, data_in, data_out);
	}
	else {
		coram_current_instance = coram_instances[instance_id];
		coram_current_instance->Access_temp(id, opType, data_in, data_out);
	}
	//Encrypt Response
	status = sgx_rijndael128GCM_encrypt((const sgx_aes_gcm_128bit_key_t *) SHARED_AES_KEY, data_out, response_size,
                                        (uint8_t *) encrypted_response, (const uint8_t *) HARDCODED_IV, IV_LENGTH, NULL, 0,
                                        (sgx_aes_gcm_128bit_tag_t *) tag_out);
	/*
	if(status == SGX_SUCCESS)
		printf("Encrypt returned Success flag\n");
	else{
		if(status == SGX_ERROR_INVALID_PARAMETER)
			printf("Encrypt returned SGX_ERROR_INVALID_PARAMETER Failure flag\n");		
		else
			printf("Encrypt returned another Failure flag\n");
	}	
	*/

	free(request);
	free(data_out);

}

void accessBulkReadInterface(uint32_t instance_id, uint8_t oram_type, uint32_t no_of_requests, unsigned char *encrypted_request, unsigned char *encrypted_response, unsigned char *tag_in, unsigned char* tag_out, uint32_t encrypted_request_size, uint32_t response_size, uint32_t tag_size, unsigned char *serialized_client_public_key, uint32_t client_public_key_size){
	//TODO : Would be nice to remove this dynamic allocation.
	PathORAM *poram_current_instance;
	CircuitORAM *coram_current_instance;
	sgx_status_t status = SGX_SUCCESS;
	unsigned char *data_in, *request, *request_ptr, *response, *response_ptr;
	uint32_t id;
	char opType = 'r';
	uint32_t tdata_size;
	if(oram_type==0){
		poram_current_instance = poram_instances[instance_id];
		tdata_size = poram_current_instance->data_size;
	}	
	else{
		coram_current_instance = coram_instances[instance_id];
		tdata_size = coram_current_instance->data_size;
	}
	request = (unsigned char *) malloc (encrypted_request_size);
	response = (unsigned char *) malloc (response_size);	
	data_in = (unsigned char *) malloc(tdata_size);
	
	#ifdef HYBRID_ENCRYPTION
		//Rebuild client_public_key to EC_KEY
		EC_GROUP *curve = NULL;
		EC_KEY *client_public_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
		BIGNUM *x, *y;
		x = BN_new();
		y = BN_new();
		BN_CTX *bn_ctx = BN_CTX_new();
		if(NULL == (curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)))
			printf("Enclave: Setting EC_GROUP failed \n");
	
		EC_POINT *pub_point = EC_POINT_new(curve);
		unsigned char bin_x[SGX_ECP256_KEY_SIZE];
		unsigned char bin_y[SGX_ECP256_KEY_SIZE];
		memcpy(bin_x, serialized_client_public_key, SGX_ECP256_KEY_SIZE);
		memcpy(bin_y, serialized_client_public_key + SGX_ECP256_KEY_SIZE, SGX_ECP256_KEY_SIZE);

		/*
		printf("Serialized Client's Public Key in enclave :\n");
		for(int t = 0; t < SGX_ECP256_KEY_SIZE; t++)
			printf("%02X", bin_x[t]);
		printf("\n");
		printf("Serialized Client's Public Key in enclave :\n");
		for(int t = 0; t < SGX_ECP256_KEY_SIZE; t++)
			printf("%02X", bin_y[t]);
		printf("\n");
		*/

		const EC_POINT *point = EC_KEY_get0_public_key(sgx_EC_key_pair);
		BIGNUM *x1, *y1;
		x1 = BN_new();
		y1 = BN_new();
		EC_POINT_get_affine_coordinates_GFp(curve, point, x1, y1, bn_ctx);
		unsigned char *bin_point = (unsigned char*) malloc(32*2);
		BN_bn2bin(x1,bin_point);
		BN_bn2bin(y1,bin_point+32);
		x = BN_bin2bn(bin_x, SGX_ECP256_KEY_SIZE, NULL);
		y = BN_bin2bn(bin_y, SGX_ECP256_KEY_SIZE, NULL);
		if(EC_POINT_set_affine_coordinates_GFp(curve, pub_point, x, y, bn_ctx)==0)
			printf("Enclave: EC_POINT_set_affine_coordinates FAILED \n");

		if(EC_KEY_set_public_key(client_public_key, pub_point)==0)
			printf("Enclave: EC_KEY_set_public_key FAILED \n");

		//ECDH_compute_secret with this public key and enclave private key
		uint32_t field_size = EC_GROUP_get_degree(curve);
		uint32_t secret_len = (field_size+7)/8;
		unsigned char *secret = (unsigned char*) malloc(secret_len);
		//Returns a 32 byte secret	
		secret_len = ECDH_compute_key(secret, secret_len, EC_KEY_get0_public_key(client_public_key),
						sgx_EC_key_pair, NULL);

		EC_POINT *mul_point = EC_POINT_new(curve);
		const EC_POINT* p[1];
		const BIGNUM* m[1];
		p[0] = pub_point;
		m[0] = EC_KEY_get0_private_key(sgx_EC_key_pair);
		int ret = EC_POINTs_mul(curve, mul_point, NULL, 1, p, m, bn_ctx);

		BIGNUM *t1, *t2;
		t1 = BN_new();
		t2 = BN_new();
		ret = EC_POINT_get_affine_coordinates_GFp(curve, mul_point, t1, t2, bn_ctx);
		unsigned char* bin_t1 = (unsigned char*) malloc(32);
		BN_bn2bin(t1, bin_t1);	
	
		//Extract AES key and IV
		unsigned char aes_key[KEY_LENGTH];
		unsigned char iv[IV_LENGTH];
		memcpy(aes_key, secret, KEY_LENGTH);
		memcpy(iv, secret+KEY_LENGTH, IV_LENGTH);

		status = sgx_rijndael128GCM_decrypt((const sgx_aes_gcm_128bit_key_t *) aes_key, (const uint8_t *) encrypted_request, 
						encrypted_request_size, (uint8_t *) request, (const uint8_t *) iv, IV_LENGTH, 
						NULL, 0, (const sgx_aes_gcm_128bit_tag_t*) tag_in);
		free(secret);
		BN_CTX_free(bn_ctx);
	#else
		status = sgx_rijndael128GCM_decrypt((const sgx_aes_gcm_128bit_key_t *) SHARED_AES_KEY, (const uint8_t *) encrypted_request,
                                    encrypted_request_size, (uint8_t *) request, (const uint8_t *) HARDCODED_IV, IV_LENGTH,
                                    NULL, 0, (const sgx_aes_gcm_128bit_tag_t*) tag_in);
	
	#endif
	
	if(status!=SGX_SUCCESS) {
		if(status == SGX_ERROR_INVALID_PARAMETER)
			printf("Decrypt returned SGX_ERROR_INVALID_PARAMETER Failure flag\n");		
		else
			printf("Decrypt returned another Failure flag\n");
	}

	request_ptr = request;
	response_ptr = response;

	for(int l=0; l<no_of_requests; l++){			
		//Extract Request Ids
		memcpy(&id, request_ptr, ID_SIZE_IN_BYTES);
		request_ptr+=ID_SIZE_IN_BYTES; 

		//TODO: Fix Instances issue.
		if(oram_type==0)
			poram_current_instance->Access_temp(id, opType, data_in, response_ptr);
		else
			coram_current_instance->Access_temp(id, opType, data_in, response_ptr);
		response_ptr+=(tdata_size);
	}

	//Encrypt Response

	#ifdef HYBRID_ENCRYPTION
		status = sgx_rijndael128GCM_encrypt((const sgx_aes_gcm_128bit_key_t *) aes_key, response, response_size,
                                        (uint8_t *) encrypted_response, (const uint8_t *) iv, IV_LENGTH, NULL, 0,
                                        (sgx_aes_gcm_128bit_tag_t *) tag_out);
	#else
		status = sgx_rijndael128GCM_encrypt((const sgx_aes_gcm_128bit_key_t *) SHARED_AES_KEY, response, response_size,
                                        (uint8_t *) encrypted_response, (const uint8_t *) HARDCODED_IV, IV_LENGTH, NULL, 0,
                                        (sgx_aes_gcm_128bit_tag_t *) tag_out);
	#endif
	/*
	if(status == SGX_SUCCESS)
		printf("Encrypt returned Success flag\n");
	else{
		if(status == SGX_ERROR_INVALID_PARAMETER)
			printf("Encrypt returned SGX_ERROR_INVALID_PARAMETER Failure flag\n");		
		else
			printf("Encrypt returned another Failure flag\n");
	}
	*/

	free(request);
	free(response);
	free(data_in);

}
//Clean up all instances of ORAM on terminate.
