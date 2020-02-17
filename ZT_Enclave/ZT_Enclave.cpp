#include "ZT_Enclave.hpp"

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
      generateAndSealKeys(bin_x, bin_y, bin_r, bin_s);
    }
  }	
  return 1;
}

uint32_t getNewORAMInstanceID(uint8_t oram_type){
  if(oram_type==0)
    return poram_instance_id++;
  else if(oram_type==1)
    return coram_instance_id++;
}

uint8_t createNewORAMInstance(uint32_t instance_id, uint32_t max_blocks, uint32_t data_size, uint32_t stash_size, uint32_t oblivious_flag, uint32_t recursion_data_size, int8_t recursion_levels, uint8_t oram_type, uint8_t pZ){

  if(oram_type==0){
    PathORAM *new_poram_instance = new PathORAM();
    poram_instances.push_back(new_poram_instance);
    
    #ifdef DEBUG_ZT_ENCLAVE
	    printf("In createNewORAMInstance, before Create, recursion_levels = %d\n", recursion_levels);	
    #endif
    
    new_poram_instance->Create(instance_id, oram_type, pZ, max_blocks, data_size, stash_size, oblivious_flag, recursion_data_size, recursion_levels);
    #ifdef DEBUG_ZT_ENCLAVE
	    printf("In createNewORAMInstance, after Create\n");	
    #endif			
    return 0;
  }
  else if(oram_type==1){
    CircuitORAM *new_coram_instance = new CircuitORAM();
    coram_instances.push_back(new_coram_instance);

    #ifdef DEBUG_ZT_ENCLAVE
    printf("Just before Create\n");
    #endif

    new_coram_instance->Create(instance_id, oram_type, pZ, max_blocks, data_size, stash_size, oblivious_flag, recursion_data_size, recursion_levels);
    return 0;
  }
}

uint32_t createNewLSORAMInstance(uint32_t key_size, uint32_t value_size, uint32_t num_blocks,
          uint8_t mode, uint8_t oblivious_type, uint8_t populate_flag) {
  LinearScan_ORAM *new_lsoram_instance = new LinearScan_ORAM(lsoram_instance_id, 
            key_size, value_size, num_blocks, mode, oblivious_type, populate_flag);

  lsoram_instances.push_back(new_lsoram_instance); 
  return lsoram_instance_id++; 
}

int8_t LSORAMAccess(uint32_t instance_id, unsigned char *key, uint32_t key_size, unsigned char*value, uint32_t value_size){
  LinearScan_ORAM *current_instance = lsoram_instances[instance_id];
  //return(current_instance->access(key, key_size, value, value_size));
}

int8_t processLSORAMInsert(uint32_t instance_id, unsigned char *key, uint32_t key_size, unsigned char*value, uint32_t value_size){
  LinearScan_ORAM *current_instance = lsoram_instances[instance_id];
  return(current_instance->insert(key, key_size, value, value_size));
}

int8_t processLSORAMFetch(uint32_t instance_id, unsigned char *key, uint32_t key_size, unsigned char*value, uint32_t value_size){
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
  data_in = request_ptr+ID_SIZE_IN_BYTES;

  if(oram_type==0){
    poram_current_instance = poram_instances[instance_id];
    poram_current_instance->Access(id, opType, data_in, data_out);
  }
  else {
    coram_current_instance = coram_instances[instance_id];
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



// LinearScan ORAM Handler Functions:

/*
  Input: request, request_size
  Output: Instantiate and populate req_key and req_value
*/
uint32_t parseInsertRequest(unsigned char *request, uint32_t request_size, unsigned char **req_key,
         unsigned char** req_value, uint32_t *req_key_size, uint32_t *req_value_size) {
  unsigned char* req_ptr = request;

  memcpy(req_key_size, req_ptr, sizeof(uint32_t));;
  req_ptr+=sizeof(uint32_t);

  *req_key = (unsigned char*) malloc (*req_key_size);
  memcpy(*req_key, req_ptr, *req_key_size);
  req_ptr+=(*req_key_size);

  memcpy(req_value_size, req_ptr, sizeof(uint32_t));
  req_ptr+= sizeof(uint32_t);

  *req_value = (unsigned char*) malloc (*req_value_size);
  memcpy(*req_value, req_ptr, *req_value_size); 
}


uint32_t parseFetchRequest(unsigned char *request, uint32_t request_size, 
         unsigned char **req_key) {

  // Populate req_key with request_size bytes of request
  // If request_size is < req_key_size, it gets padded and handled by LSORAM
  unsigned char* req_ptr = request;

  *req_key = (unsigned char*) malloc (request_size);
  memcpy(*req_key, req_ptr, request_size); 
}


/*
Input: encrypted_request, tag_in, request_size, tag_size, client_pubkey, pubkey_size
Output: aes_key, iv
*/
uint32_t DecryptRequest(unsigned char* encrypted_request, unsigned char **request, 
         uint32_t request_size, unsigned char* tag_in, uint32_t tag_size, 
         unsigned char *client_pubkey, uint32_t pubkey_size_x, uint32_t pubkey_size_y, 
         unsigned char *aes_key, unsigned char *iv){

  // Decrypt Request -> PT Request
  //   Rebuild client_public_key to EC_KEY
  EC_GROUP *curve = NULL;
  EC_KEY *client_public_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  BIGNUM *x, *y;
  x = BN_new();
  y = BN_new();
  BN_CTX *bn_ctx = BN_CTX_new();
  if(NULL == (curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)))
    printf("Enclave: Setting EC_GROUP failed \n");
	
  EC_POINT *pub_point = EC_POINT_new(curve);
  //unsigned char bin_x[SGX_ECP256_KEY_SIZE];
  //unsigned char bin_y[SGX_ECP256_KEY_SIZE];
  unsigned char *bin_x = (unsigned char*) malloc (pubkey_size_x);
  unsigned char *bin_y = (unsigned char*) malloc (pubkey_size_y);
  memcpy(bin_x, client_pubkey, pubkey_size_x);
  memcpy(bin_y, client_pubkey + pubkey_size_x, pubkey_size_y);

  /* 
  printf("Serialized Client's Public Key in enclave :\n");
  for(int t = 0; t < SGX_ECP256_KEY_SIZE; t++)
  printf("%02X", bin_x[t]);
  printf("\n");
  printf("Serialized Client's Public Key in enclave :\n");
  for(int t = 0; t < SGX_ECP256_KEY_SIZE; t++)
    printf("%02X", bin_y[t]);
  printf("\n"); 
  printf("Encrypted Request Bytes in enclave :\n");
  for(int t = 0; t<request_size; t++)
    printf("%02X", encrypted_request[t]);
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
  x = BN_bin2bn(bin_x, pubkey_size_x, NULL);
  y = BN_bin2bn(bin_y, pubkey_size_y, NULL);
  if(EC_POINT_set_affine_coordinates_GFp(curve, pub_point, x, y, bn_ctx)==0)
    printf("Enclave: EC_POINT_set_affine_coordinates FAILED \n");

  if(EC_KEY_set_public_key(client_public_key, pub_point)==0)
    printf("Enclave: EC_KEY_set_public_key FAILED \n");

  //    ECDH_compute_secret with this public key and enclave private key
  uint32_t field_size = EC_GROUP_get_degree(curve);
  uint32_t secret_len = (field_size+7)/8;
  unsigned char *secret = (unsigned char*) malloc(secret_len);
  //    Returns a 32 byte secret	
  secret_len = ECDH_compute_key(secret, secret_len, EC_KEY_get0_public_key(client_public_key),
               sgx_EC_key_pair, NULL);
	
  //    Extract AES key and IV
  //*aes_key =(unsigned char*) malloc(KEY_LENGTH);
  //*iv = (unsigned char*) malloc(IV_LENGTH);
  memcpy(aes_key, secret, KEY_LENGTH);
  memcpy(iv, secret+KEY_LENGTH, IV_LENGTH);

  /*
  unsigned char *ptr = aes_key;
  printf("ecdh_aes_key bytes: \n"); 
  for(int t = 0; t < KEY_LENGTH; t++)
    printf("%02X", ptr[t]);
  printf("\n"); 

  ptr = iv;
  printf("iv bytes: \n"); 
  for(int t = 0; t < IV_LENGTH; t++)
    printf("%02X", ptr[t]);
  printf("\n");

  printf("tag_in bytes:\n"); 
  for(int t =0; t <TAG_SIZE; t++)
    printf("%02X", tag_in[t]);
  printf("\n");  
  */

  *request = (unsigned char *) malloc (request_size);
  sgx_status_t status = SGX_SUCCESS;

  status = sgx_rijndael128GCM_decrypt((const sgx_aes_gcm_128bit_key_t *) aes_key,
           (const uint8_t *) encrypted_request, 
           request_size, (uint8_t *) *request, (const uint8_t *) iv, IV_LENGTH, 
           NULL, 0, (const sgx_aes_gcm_128bit_tag_t*) tag_in);

  /*
  unsigned char *req_ptr = *request;
  printf("Decrypted request bytes (%d) : \n", request_size); 
  for(int t = 0; t<request_size; t++){
    printf("%02X", req_ptr[t]);
  } 
  printf("\n");  
  */

  free(secret);
  free(bin_x);
  free(bin_y);
  BN_CTX_free(bn_ctx); 
}



uint32_t EncryptResponse(unsigned char *response, uint32_t response_size,
         unsigned char *aes_key, unsigned char *iv, unsigned char 
         *encrypted_response, unsigned char *tag_out){

  sgx_status_t status;
  status = sgx_rijndael128GCM_encrypt((const sgx_aes_gcm_128bit_key_t *) aes_key, response, response_size,
           (uint8_t *) encrypted_response, (const uint8_t *) iv, IV_LENGTH, NULL, 0,
           (sgx_aes_gcm_128bit_tag_t *) tag_out);

}

int8_t LSORAMFetch(uint32_t instance_id, unsigned char *encrypted_request, uint32_t request_size,
         unsigned char *encrypted_response, uint32_t response_size, unsigned char *tag_in, 
         unsigned char *tag_out, uint32_t tag_size, unsigned char *client_pubkey,
         uint32_t pubkey_size, uint32_t pubkey_size_x, uint32_t pubkey_size_y){

  unsigned char aes_key[KEY_LENGTH];
  unsigned char iv[IV_LENGTH];

  unsigned char *response = (unsigned char*) malloc(response_size);
  unsigned char *req_key, *request;

  //DecryptRequest
  DecryptRequest(encrypted_request, &request, request_size, tag_in, tag_size, client_pubkey, 
                 pubkey_size_x, pubkey_size_y, aes_key, iv);
  
  parseFetchRequest(request, request_size, &req_key);

  //LSORAMFetch()
  processLSORAMFetch(instance_id, req_key, request_size, response, response_size);
 
  //EncryptResponse
  EncryptResponse(response, response_size, aes_key, iv, encrypted_response, tag_out);
  free(response);
}

int8_t LSORAMInsert(uint32_t instance_id, unsigned char *encrypted_request, uint32_t request_size,
         unsigned char *tag_in, uint32_t tag_size, unsigned char *client_pubkey,
         uint32_t pubkey_size, uint32_t pubkey_size_x, uint32_t pubkey_size_y){

  unsigned char aes_key[KEY_LENGTH];
  unsigned char iv[KEY_LENGTH];
 
  LinearScan_ORAM *lsoram_instance = lsoram_instances[instance_id];
  unsigned char *req_key, *req_value, *request;
  uint32_t req_key_size, req_value_size;

  //DecryptRequest
  DecryptRequest(encrypted_request, &request, request_size, tag_in, tag_size, client_pubkey, 
                 pubkey_size_x, pubkey_size_y, aes_key, iv);

  parseInsertRequest(request, request_size, &req_key, &req_value, &req_key_size, &req_value_size);

  //LSORAMInsert()
  processLSORAMInsert(instance_id, req_key, req_key_size, req_value, req_value_size);

}

int8_t LSORAMInsert_pt(uint32_t instance_id, unsigned char *key, uint32_t key_size, 
       unsigned char *value, uint32_t value_size){

  processLSORAMInsert(instance_id, key, key_size, value, value_size);
}

int8_t HSORAMFetch(uint32_t lsoram_iid, uint32_t oram_iid, uint8_t oram_type,
       unsigned char *encrypted_request, uint32_t request_size,
       unsigned char *encrypted_response, uint32_t response_size, unsigned char *tag_in, 
       unsigned char *tag_out, uint32_t tag_size, unsigned char *client_pubkey,
       uint32_t pubkey_size, uint32_t pubkey_size_x, uint32_t pubkey_size_y){
  
  unsigned char aes_key[KEY_LENGTH];
  unsigned char iv[IV_LENGTH];

  unsigned char *response = (unsigned char*) malloc(response_size);
  unsigned char *data_in = (unsigned char*) malloc(response_size);
  unsigned char *req_key, *request;
  //Hacky here because Oblivious functions currentyly work at 8 byte granularity
  //So we convert from 8 byte back to 4 byte index into ORAM scheme.
  uint64_t oram_index_t;
  uint32_t oram_index;

  //DecryptRequest
  DecryptRequest(encrypted_request, &request, request_size, tag_in, tag_size, client_pubkey, 
                 pubkey_size_x, pubkey_size_y, aes_key, iv);
  
  parseFetchRequest(request, request_size, &req_key);

  //LSORAMFetch()
  processLSORAMFetch(lsoram_iid, req_key, request_size, (unsigned char*) &oram_index_t, sizeof(uint64_t));

  oram_index = (uint32_t) oram_index_t;
  PathORAM *poram_current_instance;
  CircuitORAM *coram_current_instance;
  if(oram_type==0){
    poram_current_instance = poram_instances[oram_iid];
    poram_current_instance->Access(oram_index, 'r', data_in, response);
  }
  else {
    coram_current_instance = coram_instances[oram_iid];
    coram_current_instance->Access(oram_index, 'r', data_in, response);
  }
 
  //EncryptResponse
  EncryptResponse(response, response_size, aes_key, iv, encrypted_response, tag_out);
  free(response);
  free(data_in);
}

//TODO: HSORAMInsert and HSORAMFetch handling and testing 
// ZT_ORAMServer performs an HSORAMInsert identical to LSORAM insert. 
// Here in HSORAM we split the Insert into an LSORAM <key, index> insert
//      and an ORAM access <index, value>
int8_t HSORAMInsert(uint32_t lsoram_iid, uint32_t oram_iid, uint8_t oram_type,
         uint64_t oram_index_p,
         unsigned char *encrypted_request, uint32_t request_size,
         unsigned char *tag_in, uint32_t tag_size, unsigned char *client_pubkey,
         uint32_t pubkey_size, uint32_t pubkey_size_x, uint32_t pubkey_size_y){

  // oram_index is a uint32_t variable for indexing into the ORAM scheme 
  unsigned char aes_key[KEY_LENGTH];
  unsigned char iv[KEY_LENGTH];
 
  LinearScan_ORAM *lsoram_instance = lsoram_instances[lsoram_iid];
  unsigned char *req_key, *req_value, *request, *data_out;
  uint32_t req_key_size, req_value_size;
  uint64_t oram_index_t = oram_index_p;
  uint32_t oram_index = (uint32_t) oram_index_t;

  //DecryptRequest
  DecryptRequest(encrypted_request, &request, request_size, tag_in, tag_size, client_pubkey, 
                 pubkey_size_x, pubkey_size_y, aes_key, iv);

  parseInsertRequest(request, request_size, &req_key, &req_value, &req_key_size, &req_value_size);

  //LSORAMInsert()
  processLSORAMInsert(lsoram_iid, req_key, req_key_size, (unsigned char*) &oram_index_t, sizeof(uint64_t));

  // Perform an LSORAM insert of <key, oram_index>
  // Perform an ORAM insert of <oram_index, value>
  // oram_index keeps increasing with insert.
  // TODO: How to handle it exceeding max_blocks? 
  PathORAM *poram_current_instance;
  CircuitORAM *coram_current_instance;
  data_out = (unsigned char*) malloc(req_value_size);
  if(oram_type==0){
    poram_current_instance = poram_instances[oram_iid];
    poram_current_instance->Access(oram_index, 'w', req_value, data_out);
  }
  else {
    coram_current_instance = coram_instances[oram_iid];
    coram_current_instance->Access(oram_index, 'w', req_value, data_out);
  }
  free(data_out);
}

/*
uint32_t LSORAMAccess_Handler(uint32_t instance_id, unsigned char *encrypted_request,
         unsigned char *encrypted_response, unsigned char *tag_in, unsigned char* 
         tag_out, uint32_t request_size, uint32_t response_size, uint32_t tag_size,
         unsigned char *client_pubkey, uint32_t pubkey_size){
   
  // Decrypt Request -> PT Request
  //   Rebuild client_public_key to EC_KEY
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
  memcpy(bin_x, client_pubkey, SGX_ECP256_KEY_SIZE);
  memcpy(bin_y, client_pubkey + SGX_ECP256_KEY_SIZE, SGX_ECP256_KEY_SIZE);

  
  printf("Serialized Client's Public Key in enclave :\n");
  for(int t = 0; t < SGX_ECP256_KEY_SIZE; t++)
  printf("%02X", bin_x[t]);
  printf("\n");
  printf("Serialized Client's Public Key in enclave :\n");
  for(int t = 0; t < SGX_ECP256_KEY_SIZE; t++)
    printf("%02X", bin_y[t]);
  printf("\n");
  

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

  //    ECDH_compute_secret with this public key and enclave private key
  uint32_t field_size = EC_GROUP_get_degree(curve);
  uint32_t secret_len = (field_size+7)/8;
  unsigned char *secret = (unsigned char*) malloc(secret_len);
  //    Returns a 32 byte secret	
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
	
  //    Extract AES key and IV
  unsigned char aes_key[KEY_LENGTH];
  unsigned char iv[IV_LENGTH];
  memcpy(aes_key, secret, KEY_LENGTH);
  memcpy(iv, secret+KEY_LENGTH, IV_LENGTH);

  unsigned char* request = (unsigned char *) malloc (request_size);
  unsigned char* response = (unsigned char *) malloc (response_size);	
  sgx_status_t status = SGX_SUCCESS;
 
  status = sgx_rijndael128GCM_decrypt((const sgx_aes_gcm_128bit_key_t *) aes_key, (const uint8_t *) encrypted_request, 
           request_size, (uint8_t *) request, (const uint8_t *) iv, IV_LENGTH, 
           NULL, 0, (const sgx_aes_gcm_128bit_tag_t*) tag_in);

  free(secret);
  BN_CTX_free(bn_ctx);

  // Split PT Request -> Key, Value
  unsigned char* req_ptr = request;
  LinearScan_ORAM *lsoram_instace = lsoram_instances[instance_id];
  unsigned char *req_key, *req_value;
  uint32_t req_key_size, req_value_size;

  memcpy(&req_key_size, req_ptr, sizeof(uint32_t));;
  req_ptr+=sizeof(uint32_t);

  req_key = (unsigned char*) malloc (req_key_size);
  memcpy(req_key, req_ptr, req_key_size);
  req_ptr+=req_key_size;

  memcpy(&req_value_size, req_ptr, sizeof(uint32_t));
  req_ptr+= sizeof(uint32_t);

  req_value = (unsigned char*) malloc (req_value_size);
  memcpy(req_value, req_ptr, req_value_size);
  

  // LSORAM_Access(Key,Value)

  status = sgx_rijndael128GCM_encrypt((const sgx_aes_gcm_128bit_key_t *) aes_key, response, response_size,
           (uint8_t *) encrypted_response, (const uint8_t *) iv, IV_LENGTH, NULL, 0,
           (sgx_aes_gcm_128bit_tag_t *) tag_out);


  free(request);
  free(req_value);
  free(req_key);
  // return 
}
*/
