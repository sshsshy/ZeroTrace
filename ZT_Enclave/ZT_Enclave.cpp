#include "ZT_Enclave.hpp"

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
  for(int i = 0; i < SGX_SHA256_HASH_SIZE ; i++) {
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

bool generateAndSealKeys(unsigned char *bin_x_p, unsigned char *bin_y_p, unsigned char *bin_r_p, unsigned char *bin_s_p){
  EC_KEY *ec_signing = NULL;
  ECDSA_SIG *sig_sgxssl = NULL, *sig_pubkey = NULL;
  const EC_POINT* pub_point = NULL;
  const BIGNUM *sig_r, *sig_s;
  unsigned char *bin_x, *bin_y, *bin_r, *bin_s;
  BIGNUM *x, *y; 
  int ret;

  // Setup hardcoded Enclave Signing Key
  BIGNUM *r;
  r = BN_new();
  r = BN_bin2bn(hardcoded_signing_key, SGX_ECP256_KEY_SIZE, NULL);

  ec_signing = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (ec_signing == NULL) {
    printf("Enclave: EC_KEY_new_by_curve_name failure: %ld\n", ERR_get_error());
    return false;
  }

  ret = EC_KEY_set_private_key(ec_signing, r);
  if(ret==0)
    printf("Error with EC_KEY_set_private_key()\n");

  // Sample new (ephemeral) asymmetric key pair
  x = BN_new();
  y = BN_new();
  BN_CTX *bn_ctx = BN_CTX_new();
  printf("HERE 1\n");
  EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  
  sgx_EC_key_pair = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (sgx_EC_key_pair == NULL) {
    printf("Enclave: EC_KEY_new_by_curve_name failure: %ld\n", ERR_get_error());
    return false;
  } 

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
  // End of sampling keys

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
  printf("Sizes of : bin_x: %d, bin_y: %d, bin_r: %d, bin_s: %d\n", size_bin_x, size_bin_y, size_bin_r, size_bin_s);
  //PublishKey(bin_x, size_bin_x, bin_y, size_bin_y, bin_r, bin_s, size_bin_r, size_bin_s);
	  
  memcpy(bin_x_p, bin_x, size_bin_x);
  memcpy(bin_y_p, bin_y, size_bin_y);
  memcpy(bin_r_p, bin_r, size_bin_r);
  memcpy(bin_s_p, bin_s, size_bin_s);
  free(serialized_pub_key); 
  free(bin_x);
  free(bin_y);
  free(bin_r);
  free(bin_s);	
  return true;
}

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


int8_t InitializeKeys(unsigned char *bin_x,  unsigned char* bin_y, 
       unsigned char* bin_r, unsigned char* bin_s, uint32_t size_bin){
  if(!PK_in_memory){
    //Attempt to extract a previously sealed key-pair
    if(!extractSealedKeys()){
      //TODO: Stripped sizes here, since we'd generate these values inside the gen function
      // and will know sizes inside. Ensure this holds, take off this TD if so.
      generateAndSealKeys(bin_x, bin_y, bin_r, bin_s);
    }
  }	
  return 1;
}


uint32_t createNewORAMInstance(uint32_t max_blocks, uint32_t data_size, uint32_t stash_size, uint32_t oblivious_flag, uint32_t recursion_data_size, int8_t recursion_levels, uint64_t onchip_posmap_mem_limit, uint32_t oram_type, uint8_t pZ){

  if(oram_type==0){
    PathORAM *new_poram_instance = new PathORAM();
    poram_instances.push_back(new_poram_instance);
    
    #ifdef DEBUG_ZT_ENCLAVE
	    printf("In createNewORAMInstance, before Create, recursion_levels = %d\n", recursion_levels);	
    #endif
    
    new_poram_instance->Create(pZ, max_blocks, data_size, stash_size, oblivious_flag, recursion_data_size, recursion_levels, onchip_posmap_mem_limit);
    #ifdef DEBUG_ZT_ENCLAVE
	    printf("In createNewORAMInstance, after Create\n");	
    #endif			
    return poram_instance_id++;
  }
  else if(oram_type==1){
    CircuitORAM *new_coram_instance = new CircuitORAM();
    coram_instances.push_back(new_coram_instance);

    printf("Just before Create\n");
    new_coram_instance->Create(pZ, max_blocks, data_size, stash_size, oblivious_flag, recursion_data_size, recursion_levels, onchip_posmap_mem_limit);
    return coram_instance_id++;
  }
}

uint32_t createNewLSORAMInstance(uint32_t key_size, uint32_t value_size, uint32_t num_blocks,
          uint8_t mode, uint8_t oblivious_type, uint8_t populate_flag) {
  LinearScan_ORAM *new_lsoram_instance = new LinearScan_ORAM(lsoram_instance_id, key_size, value_size, num_blocks,
                  mode, oblivious_type, populate_flag);
  lsoram_instances.push_back(new_lsoram_instance);   
  return lsoram_instance_id++; 
}

int8_t LSORAMInsert(uint32_t instance_id, unsigned char *key, uint32_t key_size, unsigned char*value, uint32_t value_size){
  LinearScan_ORAM *current_instance = lsoram_instances[instance_id];
  return(current_instance->insert(key, key_size, value, value_size));
}

int8_t LSORAMFetch(uint32_t instance_id, unsigned char *key, uint32_t key_size, unsigned char*value, uint32_t value_size){
  LinearScan_ORAM *current_instance = lsoram_instances[instance_id];
  return(current_instance->fetch(key, key_size, value, value_size));
}

int8_t LSORAMEvict(uint32_t instance_id, unsigned char* key, uint32_t key_size){
  LinearScan_ORAM *current_instance = lsoram_instances[instance_id];
  return(current_instance->evict(key, key_size));
}

uint8_t deleteLSORAMInstance(uint32_t instance_id){
  LinearScan_ORAM *instance = lsoram_instances[instance_id];
  delete(instance);
  return 1;
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
    printf("In PathORAM instance \n");
    poram_current_instance = poram_instances[instance_id];
    //poram_current_instance->Access_temp(id, opType, data_in, data_out);
    printf("Before Access call\n");	
    poram_current_instance->Access(id, opType, data_in, data_out);
  }
  else {
    coram_current_instance = coram_instances[instance_id];
    //coram_current_instance->Access_temp(id, opType, data_in, data_out);
    coram_current_instance->Access(id, opType, data_in, data_out);
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
	    poram_current_instance->Access(id, opType, data_in, response_ptr);
    else
	    coram_current_instance->Access(id, opType, data_in, response_ptr);
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
