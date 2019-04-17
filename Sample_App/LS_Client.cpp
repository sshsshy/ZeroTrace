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
#include "utils.hpp"

int32_t min_expected_no_of_parameters = 7;
uint32_t num_blocks;
int requestlength;
uint32_t data_size;
uint32_t key_size;
uint32_t value_size;
uint8_t store_mode;
uint8_t oblivious_mode;

unsigned char *encrypted_request, *tag_in, *encrypted_response, *tag_out;
uint32_t request_size, response_size;
unsigned char *data_in;
unsigned char *data_out;

clock_t generate_request_start, generate_request_stop, extract_response_start, extract_response_stop, process_request_start, process_request_stop, generate_request_time, extract_response_time,  process_request_time;

void getParams(int argc, char* argv[])
{
  if(argc<min_expected_no_of_parameters) {
    printf("Command line parameters error, expected :\n");
    printf(" <N> <No_of_requests> <key_size> <value_size> <0/1 = Store In-PRM/Outside-PRM> <0/1 = Access-Oblivious/Full-Oblivious> \n");
  }

  std::string str = argv[1];
  num_blocks = std::stoi(str);
  str = argv[2];
  requestlength = std::stoi(str);
  str = argv[3];
  key_size = std::stoi(str);
  str = argv[4];
  value_size = std::stoi(str);	
  str = argv[5];
  store_mode = std::stoi(str);
  str = argv[6];
  oblivious_mode = std::stoi(str);
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
  
  uint32_t zt_id = ZT_New_LSORAM(num_blocks, key_size, value_size, store_mode, oblivious_mode, 1);
  printf("Obtained zt_id = %d\n", zt_id);

  unsigned char *key = (unsigned char *) malloc(key_size);
  unsigned char *value = (unsigned char *) malloc(value_size);
  unsigned char *value_returned = (unsigned char *) malloc(value_size);
 
  for(int i =0; i<key_size-1;i++){
    key[i] = 'A';
  } 
  for(int i =0; i<value_size-1;i++){
    value[i] = 'E';
  }
  key[key_size-1]='\0';
  value[value_size-1]='\0';
   
  printf("Before insert1\n"); 
  ZT_LSORAM_insert(zt_id, key, key_size, value, value_size);
  key[0]='B';
  printf("Before insert2\n"); 
  ZT_LSORAM_insert(zt_id, key, key_size, value, value_size);
  key[0]='C';
  printf("Before insert3\n"); 
  ZT_LSORAM_insert(zt_id, key, key_size, value, value_size);
  key[0]='B'; 
  ZT_LSORAM_fetch(zt_id, key, key_size, value_returned, value_size);
 
  uint32_t old_id = zt_id; 
  
  zt_id = ZT_New_LSORAM(num_blocks, key_size, value_size, store_mode, oblivious_mode, 1);
  key[0]='A'; 
  ZT_LSORAM_insert(zt_id, key, key_size, value, value_size);
  key[0]='B';
  printf("Before insert2\n"); 
  ZT_LSORAM_insert(zt_id, key, key_size, value, value_size);
  key[0]='C';
  printf("Before insert3\n"); 
  ZT_LSORAM_insert(zt_id, key, key_size, value, value_size);
  key[0]='A'; 
  ZT_LSORAM_fetch(zt_id, key, key_size, value_returned, value_size);

  ZT_LSORAM_evict(old_id, key, key_size);
  ZT_LSORAM_evict(zt_id, key, key_size);

  key[0]='C';
  ZT_LSORAM_fetch(zt_id, key, key_size, value_returned, value_size);

 
  ZT_LSORAM_delete(old_id);
  ZT_LSORAM_delete(zt_id);
 
  /* 
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

  response_size = data_size;
  data_out = (unsigned char*) malloc (data_size);

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

  
  printf("Requests Fin\n");	

  end = clock();
  tclock = end - start;

  //Time in CLOCKS :
  printf("%ld\n",tclock);
  printf("Per query time = %f ms\n",(1000 * ( (double)tclock/ ( (double)requestlength) ) / (double) CLOCKS_PER_SEC));	

  free(encrypted_request);
  free(encrypted_response);
  free(tag_in);
  free(tag_out);
  free(data_in);
  free(data_out);
  */
  return 0;
}


