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

std::vector<PathORAM *> poram_instances;
std::vector<CircuitORAM *> coram_instances;

uint32_t poram_instance_id=0;
uint32_t coram_instance_id=0;

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


void accessBulkReadInterface(uint32_t instance_id, uint8_t oram_type, uint32_t no_of_requests, unsigned char *encrypted_request, unsigned char *encrypted_response, unsigned char *tag_in, unsigned char* tag_out, uint32_t encrypted_request_size, uint32_t response_size, uint32_t tag_size){
	//TODO : Would be nice to remove this dynamic allocation.
	PathORAM *poram_current_instance;
	CircuitORAM *coram_current_instance;
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
	status = sgx_rijndael128GCM_encrypt((const sgx_aes_gcm_128bit_key_t *) SHARED_AES_KEY, response, response_size,
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
	free(response);
	free(data_in);

}
//Clean up all instances of ORAM on terminate.
