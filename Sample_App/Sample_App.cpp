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

#include "Sample_App.hpp"

uint32_t no_of_elements;
uint32_t no_of_accesses;
uint32_t *element;
uint32_t min_expected_no_of_parameters = 10;
bool resume_experiment;
bool inmem_flag;
uint32_t data_size;
uint32_t max_blocks;
int requestlength;
uint32_t stash_size;
uint32_t oblivious = 0;
uint32_t recursion_data_size = 0;
uint32_t oram_type = 0;
int32_t recursion_levels_e;
uint32_t oram_id = 0;
unsigned char *encrypted_request, *tag_in, *encrypted_response, *tag_out;
uint32_t request_size, response_size;
unsigned char *data_in;
unsigned char *data_out;
uint32_t bulk_batch_size=0;

clock_t generate_request_start, generate_request_stop, extract_response_start, extract_response_stop, process_request_start, process_request_stop, generate_request_time, extract_response_time,  process_request_time;
uint8_t Z;
FILE *iquery_file; 
 
double time_taken(timespec *start, timespec *end){
  long seconds, nseconds;
  seconds = end->tv_sec - start->tv_sec;
  nseconds = end->tv_nsec - start->tv_nsec;
  double mstime = ( double(seconds * 1000) + double(nseconds/MILLION) );
  return mstime;
}

int AES_GCM_128_encrypt (unsigned char *plaintext, int plaintext_len, unsigned char *aad,
  int aad_len, unsigned char *key, unsigned char *iv, int iv_len,
  unsigned char *ciphertext, unsigned char *tag)
{
  EVP_CIPHER_CTX *ctx;

  int len;
  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) {
    printf("Failed context intialization for OpenSSL EVP\n");
  }

  /* Initialise the encryption operation. */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)){
    printf("Failed AES_GCM_128 intialization for OpenSSL EVP\n");	
  }

  /* Set IV length if default 12 bytes (96 bits) is not appropriate */
  if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)){
    printf("Failed IV config\n");
  }

  /* Initialise key and IV */
  if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
    printf("Failed intialization for key and IV for AES_GCM\n");	
  }

  /* Provide any AAD data. This can be called zero or more times as
   * required
   */
  //if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
  //	printf("Failed AAD\n");

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  //printf("Error code = %d\n\n", EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len));
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
    printf("Failed AES_GCM encrypt\n");
  }
  ciphertext_len = len;

  /* Finalise the encryption. Normally ciphertext bytes may be written at
   * this stage, but this does not occur in GCM mode
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)){
    printf("Failed Finalizing ciphertext\n");	
  }
  ciphertext_len += len;

  /* Get the tag */
  if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag))
    printf("Failed tag for AES_GCM_encrypt\n");

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int AES_GCM_128_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
  int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
  int iv_len, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  int ret;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) 
    printf("Failed context intialization for OpenSSL EVP\n");

  /* Initialise the decryption operation. */
  if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
    printf("Failed AES_GCM_128 intialization for OpenSSL EVP\n");	

  /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
  if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
    printf("Failed IV config\n");

  /* Initialise key and IV */
  if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
    printf("Failed intialization for key and IV for AES_GCM_128\n");	
  /* Provide any AAD data. This can be called zero or more times as
   * required
   */
  //if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
  //	printf("Failed AAD\n");

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    printf("Failed AES_GCM decrypt\n");
  plaintext_len = len;

  /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
  if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag))
    printf("Failed tag for AES_GCM_decrypt\n");

  /* Finalise the decryption. A positive return value indicates success,
   * anything else is a failure - the plaintext is not trustworthy.
   */
  ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  if(ret > 0)
  {
    /* Success */
    plaintext_len += len;
    return plaintext_len;
  }
  else
  {
    /* Verify failed */
    return -1;
  }
}

void serializeRequest(uint32_t request_id, char op_type, unsigned char *data, uint32_t data_size, unsigned char* serialized_request){
  unsigned char *request_ptr = serialized_request;
  *request_ptr=op_type;
  request_ptr+=1;
  memcpy(request_ptr, (unsigned char*) &request_id,  ID_SIZE_IN_BYTES);
  request_ptr+=  ID_SIZE_IN_BYTES;	
  memcpy(request_ptr, data, data_size);
}


int encryptRequest(int request_id, char op_type, unsigned char *data, uint32_t data_size, unsigned char *encrypted_request, unsigned char *tag, uint32_t request_size){
  int encrypted_request_size;	
  //Sample IV;
  unsigned char *iv = (unsigned char *) malloc (IV_LENGTH);
  //1 from op_type
  unsigned char *serialized_request = (unsigned char*) malloc (1+ID_SIZE_IN_BYTES+data_size);
  serializeRequest(request_id, op_type, data, data_size, serialized_request);

  encrypted_request_size = AES_GCM_128_encrypt(serialized_request, request_size, NULL, 0, (unsigned char*) SHARED_AES_KEY, (unsigned char*) HARDCODED_IV, IV_LENGTH, encrypted_request, tag);
  //printf("encrypted_request_size returned for AES_GCM_128_encrypt = %d\n", encrypted_request_size);

  free(serialized_request);
  free(iv);
  return encrypted_request_size;
}


int encryptBulkReadRequest(int *rs, uint32_t req_counter, uint32_t bulk_batch_size, unsigned char *encrypted_request, unsigned char *tag, uint32_t request_size, unsigned char *iv, unsigned char** serialized_client_public_key ){
  int ret;
  #ifdef HYBRID_ENCRYPTION
    EC_KEY *ephemeral_key = NULL;
    BIGNUM *x, *y;
    x = BN_new();
    y = BN_new();
    BN_CTX *bn_ctx = BN_CTX_new();
    const EC_GROUP *curve = NULL;

    if(NULL == (curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)))
      printf("Setting EC_GROUP failed \n");

    ephemeral_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if(ephemeral_key==NULL)
      printf("Client: EC_KEY_new_by_curve_name Fail\n");

    ret = EC_KEY_generate_key(ephemeral_key);
    if(ret!=1)
      printf("Client: EC_KEY_generate_key Fail\n");

    const EC_POINT *pub_point;
    pub_point = EC_KEY_get0_public_key((const EC_KEY *) ephemeral_key);
    if(pub_point == NULL)
      printf("Client: EC_KEY_get0_public_key Fail\n");
	
    ret = EC_POINT_get_affine_coordinates_GFp(curve, pub_point, x, y, bn_ctx);
    if(ret==0)
      printf("Client: EC_POINT_get_affine_coordinates_GFp Failed \n");
	
    //TODO : Fill serialized_client_public_key with the sampled keys pub key.
    unsigned char *bin_x, *bin_y;
    uint32_t size_bin_x = BN_num_bytes(x);
    uint32_t size_bin_y = BN_num_bytes(y);
    bin_x = (unsigned char*) malloc(size_bin_x);
    bin_y = (unsigned char*) malloc(size_bin_y);
    BN_bn2bin(x, bin_x);
    BN_bn2bin(y, bin_y);
    *serialized_client_public_key = (unsigned char*) malloc(size_bin_x + size_bin_y);
    memcpy(*serialized_client_public_key, bin_x, size_bin_x);
    memcpy(*(serialized_client_public_key) + size_bin_x, bin_y, size_bin_y);

    //TEST snippet for key comparison at client and enclave
    const EC_POINT *point = EC_KEY_get0_public_key(ENCLAVE_PUBLIC_KEY);
    BIGNUM *x1, *y1;
    x1 = BN_new();
    y1 = BN_new();
    ret = EC_POINT_get_affine_coordinates_GFp(curve, point, x1, y1, bn_ctx);
    unsigned char *bin_point = (unsigned char*) malloc(32*2);
    BN_bn2bin(x1,bin_point);
    BN_bn2bin(y1,bin_point+32);	

    /*
    printf("Serialized Client's Public Key at Client :\n");
    for(int t = 0; t < size_bin_x+size_bin_y; t++)
	    printf("%02X", (*serialized_client_public_key)[t]);
    printf("\n");

    printf("Serialized Enclave's Public Key at Client :\n");
    for(int t = 0; t < size_bin_x+size_bin_y; t++)
	    printf("%02X", bin_point[t]);
    printf("\n");
    */

    uint32_t field_size = EC_GROUP_get_degree(EC_KEY_get0_group(ENCLAVE_PUBLIC_KEY));
    uint32_t secret_len = (field_size+7)/8;
    unsigned char *secret = (unsigned char*) malloc(secret_len);
    //Returns a 32 byte secret	
    secret_len = ECDH_compute_key(secret, secret_len, EC_KEY_get0_public_key(ENCLAVE_PUBLIC_KEY),
					    ephemeral_key, NULL);

    /*	
    printf("Secret computed by Client :\n");
    for(int t = 0; t < secret_len; t++)
	    printf("%02X", secret[t]);
    printf("\n");
    */


    //Sample IV;
    //TODO : Replace IV with sampling? Check with IG
    //TODO : KDF over the shared_secret!
    memcpy(ecdh_shared_aes_key, secret, KEY_LENGTH);
    memcpy(ecdh_shared_iv, secret + KEY_LENGTH, IV_LENGTH);
    BN_CTX_free(bn_ctx);
  #endif

  int encrypted_request_size = ID_SIZE_IN_BYTES * bulk_batch_size;	
  //Sample IV;
  unsigned char *serialized_request = (unsigned char*) malloc (encrypted_request_size);
  unsigned char *serialized_request_ptr = serialized_request;
  for(int i =0;i<bulk_batch_size;i++){
    memcpy(serialized_request_ptr, &(rs[req_counter+i]), ID_SIZE_IN_BYTES);
    serialized_request_ptr+=ID_SIZE_IN_BYTES;
  }

  #ifdef HYBRID_ENCRYPTION
    encrypted_request_size = AES_GCM_128_encrypt(serialized_request, request_size, NULL, 0, (unsigned char*) ecdh_shared_aes_key, (unsigned char*) ecdh_shared_iv, IV_LENGTH, encrypted_request, tag);
  #else
    encrypted_request_size = AES_GCM_128_encrypt(serialized_request, request_size, NULL, 0, (unsigned char*) SHARED_AES_KEY, (unsigned char*) HARDCODED_IV, IV_LENGTH, encrypted_request, tag);
  #endif	

  free(serialized_request);
  return encrypted_request_size;
}

int encryptBulkReadRequest(int *rs, uint32_t req_counter, uint32_t bulk_batch_size, unsigned char *encrypted_request, unsigned char *tag, uint32_t request_size ){
  int encrypted_request_size;	
  //Sample IV;
  unsigned char *iv = (unsigned char *) malloc (IV_LENGTH);
  unsigned char *serialized_request = (unsigned char*) malloc (encrypted_request_size);
  unsigned char *serialized_request_ptr = serialized_request;
  for(int i =0;i<bulk_batch_size;i++){
    memcpy(serialized_request_ptr, &(rs[req_counter+i]), ID_SIZE_IN_BYTES);
    serialized_request_ptr+=ID_SIZE_IN_BYTES;
  }

  encrypted_request_size = AES_GCM_128_encrypt(serialized_request, request_size, NULL, 0, (unsigned char*) SHARED_AES_KEY, (unsigned char*) HARDCODED_IV, IV_LENGTH, encrypted_request, tag);
  //printf("encrypted_request_size returned for AES_GCM_128_encrypt = %d\n", encrypted_request_size);

  free(serialized_request);
  free(iv);
  return encrypted_request_size;

}

void decryptBulkReadRequest(uint32_t bulk_batch_size, unsigned char *encrypted_request, unsigned char *tag, uint32_t request_size){
  unsigned char *decrypted_request = (unsigned char*) malloc (request_size);
  int decrypted_request_size = AES_GCM_128_decrypt(encrypted_request, request_size, NULL, 0, tag, (unsigned char *) SHARED_AES_KEY,(unsigned char*) HARDCODED_IV, IV_LENGTH, decrypted_request);	
  uint32_t request_id;
  uint32_t *req_id = (uint32_t*) decrypted_request;
  for(int i =0;i<bulk_batch_size;i++){	
    printf("Decrypted request id = %d\n", *req_id);
    req_id++;
  }		
  free(decrypted_request);
}


uint32_t computeCiphertextSize(uint32_t data_size){
  //Rounded up to nearest block size:
  uint32_t encrypted_request_size;
  encrypted_request_size = ((1+ID_SIZE_IN_BYTES+data_size) / AES_GCM_BLOCK_SIZE_IN_BYTES);
  if((ID_SIZE_IN_BYTES+data_size)%AES_GCM_BLOCK_SIZE_IN_BYTES!=0)
    encrypted_request_size+=1;
  encrypted_request_size*=16;
  printf("Request_size = %d\n", encrypted_request_size);
  return encrypted_request_size;
}

uint32_t computeBulkRequestsCiphertextSize(uint32_t bulk_batch_size) {
  uint32_t encrypted_request_size;
  encrypted_request_size = ((ID_SIZE_IN_BYTES*bulk_batch_size) / AES_GCM_BLOCK_SIZE_IN_BYTES);
  if((ID_SIZE_IN_BYTES*bulk_batch_size)%AES_GCM_BLOCK_SIZE_IN_BYTES!=0)
    encrypted_request_size+=1;
  encrypted_request_size*=AES_GCM_BLOCK_SIZE_IN_BYTES;
  printf("Request_size = %d\n", encrypted_request_size);
  return encrypted_request_size;
}

void decryptRequest(unsigned char *encrypted_request, unsigned char *tag, uint32_t request_size){
  printf("Encrypted payload = %s", encrypted_request);
  unsigned char *decrypted_request = (unsigned char*) malloc (request_size);
  int decrypted_request_size = AES_GCM_128_decrypt(encrypted_request, request_size, NULL, 0, tag, (unsigned char *) SHARED_AES_KEY,(unsigned char*) HARDCODED_IV, IV_LENGTH, decrypted_request);	
  uint32_t request_id;
  memcpy(&request_id, decrypted_request+1, 4);
  printf("Decrypted request id = %d\n", request_id);
  printf("Decrypted payload = %s", (decrypted_request + 4));
  free(decrypted_request);

}

int extractResponse(unsigned char *encrypted_response, unsigned char *tag, int response_size, unsigned char *data_out) {
  AES_GCM_128_decrypt(encrypted_response, response_size, NULL, 0, tag, (unsigned char*) SHARED_AES_KEY, (unsigned char*) HARDCODED_IV, IV_LENGTH, data_out);
  return response_size;
}

int extractBulkResponse(unsigned char *encrypted_response, unsigned char *tag, int response_size, unsigned char *data_out) {
  AES_GCM_128_decrypt(encrypted_response, response_size, NULL, 0, tag, (unsigned char*) SHARED_AES_KEY, (unsigned char*) HARDCODED_IV, IV_LENGTH, data_out);
  return response_size;
}

void getParams(int argc, char* argv[])
{
  if(argc<min_expected_no_of_parameters) {
    printf("Command line parameters error, expected :\n");
    printf(" <N> <No_of_requests> <Stash_size> <Data_block_size> <\"resume\"/\"new\"> <\"memory\"/\"hdd\"> <0/1 = Non-oblivious/Oblivious> <Recursion_block_size> <\"auto\"/\"path\"/\"circuit\"> <Z>\n\n");
  }

  std::string str = argv[1];
  max_blocks = std::stoi(str);
  str = argv[2];
  requestlength = std::stoi(str);
  str = argv[3];
  stash_size = std::stoi(str);
  str = argv[4];
  data_size = std::stoi(str);	
        str = argv[5];
  if(str=="resume")
    resume_experiment = true;
  str = argv[6];
  if(str=="memory")
    inmem_flag = true;
  str = argv[7];
  if(str=="1")
    oblivious = 1;
  str = argv[8];	
  recursion_data_size = std::stoi(str);

  str = argv[9];
  if(str=="path")
    oram_type = 0;
  if(str=="circuit")
    oram_type = 1;
  str=argv[10];
  Z = std::stoi(str);
  str=argv[11];
  bulk_batch_size = std::stoi(str);

  std::string qfile_name = "ZT_"+std::to_string(max_blocks)+"_"+std::to_string(data_size);
  iquery_file = fopen(qfile_name.c_str(),"w");
  
}


struct node{
  uint32_t id;
  uint32_t data;
  struct node *left, *right;
};

int initializeZeroTrace() {
  // Variables for Enclave Public Key retrieval 
  uint32_t max_buff_size = PRIME256V1_KEY_SIZE;
  unsigned char bin_x[PRIME256V1_KEY_SIZE], bin_y[PRIME256V1_KEY_SIZE], signature_r[PRIME256V1_KEY_SIZE], signature_s[PRIME256V1_KEY_SIZE];
  
  ZT_Initialize(bin_x, bin_y, signature_r, signature_s, max_buff_size);
  
  EC_GROUP *curve;
  EC_KEY *enclave_verification_key = NULL;
  ECDSA_SIG *sig_enclave = ECDSA_SIG_new();	
  BIGNUM *x, *y, *xh, *yh, *sig_r, *sig_s;
  BN_CTX *bn_ctx = BN_CTX_new();
  int ret;

  if(NULL == (curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)))
	  printf("Setting EC_GROUP failed \n");

  EC_POINT *pub_point = EC_POINT_new(curve);
  //Verify the Enclave Public Key
  enclave_verification_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  xh = BN_bin2bn(hardcoded_verification_key_x, PRIME256V1_KEY_SIZE, NULL);
  yh = BN_bin2bn(hardcoded_verification_key_y, PRIME256V1_KEY_SIZE, NULL);
  EC_KEY_set_public_key_affine_coordinates(enclave_verification_key, xh, yh);
  unsigned char *serialized_public_key = (unsigned char*) malloc (PRIME256V1_KEY_SIZE*2);
  memcpy(serialized_public_key, bin_x, PRIME256V1_KEY_SIZE);
  memcpy(serialized_public_key + PRIME256V1_KEY_SIZE, bin_y, PRIME256V1_KEY_SIZE);
	  
  sig_enclave->r = BN_bin2bn(signature_r, PRIME256V1_KEY_SIZE, NULL);
  sig_enclave->s = BN_bin2bn(signature_s, PRIME256V1_KEY_SIZE, NULL);	
  
  ret = ECDSA_do_verify((const unsigned char*) serialized_public_key, PRIME256V1_KEY_SIZE*2, sig_enclave, enclave_verification_key);
  if(ret==1){
	  printf("GetEnclavePublishedKey : Verification Successful! \n");
  }
  else{
	  printf("GetEnclavePublishedKey : Verification FAILED! \n");
  }
  
  //Load the Enclave Public Key
  ENCLAVE_PUBLIC_KEY = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  
  x = BN_bin2bn(bin_x, PRIME256V1_KEY_SIZE, NULL);
  y = BN_bin2bn(bin_y, PRIME256V1_KEY_SIZE, NULL);
  if(EC_POINT_set_affine_coordinates_GFp(curve, pub_point, x, y, bn_ctx)==0)
	  printf("EC_POINT_set_affine_coordinates FAILED \n");

  if(EC_KEY_set_public_key(ENCLAVE_PUBLIC_KEY, pub_point)==0)
	  printf("EC_KEY_set_public_key FAILED \n");

  BN_CTX_free(bn_ctx);
  free(serialized_public_key);

}

int main(int argc, char *argv[]) {
  getParams(argc, argv);

  initializeZeroTrace();
  
  uint32_t zt_id = ZT_New(max_blocks, data_size, stash_size, oblivious, recursion_data_size, oram_type, Z);
  //Store returned zt_id, to make use of different ORAM instances!
  printf("Obtained zt_id = %d\n", zt_id);    

  //Variable declarations
  RandomRequestSource reqsource;
  clock_t start,end,tclock;  
  int *rs = reqsource.GenerateRandomSequence(requestlength,max_blocks-1);
  uint32_t i = 0;

  uint32_t encrypted_request_size;
  request_size = ID_SIZE_IN_BYTES + data_size;
  tag_in = (unsigned char*) malloc (TAG_SIZE);
  tag_out = (unsigned char*) malloc (TAG_SIZE);
  data_in = (unsigned char*) malloc (data_size);

  start = clock();

  #ifdef PRINT_REQ_DETAILS	
    printf("Starting Actual Access requests\n");
  #endif	

  if(bulk_batch_size==0) {

    response_size = data_size;
    //+1 for simplicity printing a null-terminated string
    data_out = (unsigned char*) malloc (data_size + 1);

    encrypted_request_size = computeCiphertextSize(data_size);
    encrypted_request = (unsigned char *) malloc (encrypted_request_size);				
    encrypted_response = (unsigned char *) malloc (response_size);		

    for(i=0;i<requestlength;i++) {
      #ifdef PRINT_REQ_DETAILS		
        printf("---------------------------------------------------\n\nRequest no : %d\n",i);
        printf("Access ID: %d\n",rs[i]);
      #endif

      //TODO: Patch this along with instances patch		
      uint32_t instance_id = 0;	
      
      //Prepare Request:
      //request = rs[i]
      generate_request_start = clock();
      encryptRequest(0, 'r', data_in, data_size, encrypted_request, tag_in, encrypted_request_size);
      generate_request_stop = clock();		

      //Process Request:
      process_request_start = clock();		
      ZT_Access(instance_id, oram_type, encrypted_request, encrypted_response, tag_in, tag_out, encrypted_request_size, response_size, TAG_SIZE);
      process_request_stop = clock();				

      //Extract Response:
      extract_response_start = clock();
      extractResponse(encrypted_response, tag_out, response_size, data_out);
      extract_response_stop = clock();

      data_out[data_size]='\0';
      printf("Obtained data : %s\n", data_out);

      #ifdef RESULTS_DEBUG
          printf("datasize = %d, Fetched Data :", data_size);
          for(uint32_t j=0; j < data_size;j++){
        printf("%c", data_out[j]);
          }
          printf("\n");
      #endif

      #ifdef ANALYSIS

        //TIME in CLOCKS
        generate_request_time = generate_request_stop - generate_request_start;
        process_request_time = process_request_stop - process_request_start;			
        extract_response_time = extract_response_stop - extract_response_start;
        fprintf(iquery_file,"%f\t%f\t%f\n", double(generate_request_time)/double(CLOCKS_PER_MS), double(process_request_time)/double(CLOCKS_PER_MS), double(extract_response_time)/double(CLOCKS_PER_MS));
      
        #ifdef NO_CACHING_APP
          system("sudo sync");
          system("sudo echo 3 > /proc/sys/vm/drop_caches");
        #endif
      #endif
    }
  }
  
  else{
    response_size = data_size * bulk_batch_size;
    data_out = (unsigned char*) malloc (response_size);
  
    uint32_t req_counter = 0;		
    encrypted_request_size = computeBulkRequestsCiphertextSize(bulk_batch_size);
    encrypted_request = (unsigned char *) malloc (encrypted_request_size);				
    encrypted_response = (unsigned char *) malloc (response_size);			
       
    for(i=0;i<requestlength/bulk_batch_size;i++) {
      #ifdef PRINT_REQ_DETAILS		
        printf("---------------------------------------------------\n\nRequest no : %d\n",i);
        printf("Access ID: %d\n",rs[i]);
      #endif

      //TODO: Patch this along with instances patch		
      uint32_t instance_id = 0;
              
      generate_request_start = clock();
      encryptBulkReadRequest(rs, req_counter, bulk_batch_size, encrypted_request, tag_in, encrypted_request_size);
      generate_request_stop = clock();		

      //decryptBulkReadRequest(bulk_batch_size, encrypted_request, tag_in, encrypted_request_size);

      //Process Request:
      process_request_start = clock();		
      ZT_Bulk_Read(instance_id, oram_type, bulk_batch_size, encrypted_request, encrypted_response, tag_in, tag_out, encrypted_request_size, response_size, TAG_SIZE);
      process_request_stop = clock();				

      //Extract Response:
      extract_response_start = clock();
      //extractResponse(encrypted_response, tag_out, response_size, data_out);
      extractBulkResponse(encrypted_response, tag_out, response_size, data_out);			
      extract_response_stop = clock();

      //printf("Obtained data : %s\n", data_out);

      #ifdef RESULTS_DEBUG
          printf("datasize = %d, Fetched Data :", data_size);
          for(uint32_t j=0; j < data_size;j++){
        printf("%c", data_out[j]);
          }
          printf("\n");
      #endif

      #ifdef ANALYSIS

        //TIME in CLOCKS
        generate_request_time = generate_request_stop - generate_request_start;
        process_request_time = process_request_stop - process_request_start;			
        extract_response_time = extract_response_stop - extract_response_start;
        fprintf(iquery_file,"%f\t%f\t%f\n", double(generate_request_time)/double(CLOCKS_PER_MS), double(process_request_time)/double(CLOCKS_PER_MS), double(extract_response_time)/double(CLOCKS_PER_MS));
      
        #ifdef NO_CACHING_APP
          system("sudo sync");
          system("sudo echo 3 > /proc/sys/vm/drop_caches");
        #endif
      #endif
      req_counter+=bulk_batch_size;
    }
  }
  //strcpy((char *)data_in, "Hello World");
  printf("Requests Fin\n");	

  #ifdef ANALYSIS
    fclose(iquery_file);
  #endif

  end = clock();
  tclock = end - start;

  //Time in CLOCKS :
  printf("%ld\n",tclock);
  if(bulk_batch_size==0)
    printf("Per query time = %f ms\n",(1000 * ( (double)tclock/ ( (double)requestlength) ) / (double) CLOCKS_PER_SEC));	
  else
    printf("Per query time = %f ms\n",(1000 * ( (double)tclock/ ( (double)requestlength) ) / (double) CLOCKS_PER_SEC));
  //printf("%ld\n",CLOCKS_PER_SEC);
  
  free(encrypted_request);
  free(encrypted_response);
  free(tag_in);
  free(tag_out);
  free(data_in);
  free(data_out);

  //printf("Enter a character before exit ...\n");
  //getchar();
  return 0;
}


