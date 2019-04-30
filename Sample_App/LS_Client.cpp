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
#include <iostream>
#include <map>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string>
#include "utils.hpp"

int32_t min_expected_no_of_parameters = 7;
uint32_t num_blocks;
int requestlength;
uint32_t data_size;
uint32_t key_size;
uint32_t value_size;
uint8_t store_mode;
uint8_t oblivious_mode;


clock_t generate_request_start, generate_request_stop, extract_response_start,
        extract_response_stop, process_request_start, process_request_stop, 
        generate_request_time, extract_response_time, process_request_time;

clock_t inserts_start, inserts_stop, inserts_time, insert_time;
clock_t fetches_start, fetches_stop, fetches_time, fetch_time;

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
  enclave_public_key = serialized_public_key;

}

int generateKeyValuePair(unsigned char *key, unsigned char *value, uint32_t key_size, uint32_t value_size){
  int rfd = open("/dev/urandom", O_RDONLY);
  if (rfd < 0 || read(rfd, key, key_size) < key_size) {
    // Can't even read random data?
    perror("reading random string");
    exit(1);
  }  
  if (rfd < 0 || read(rfd, value, value_size) < value_size) {
    // Can't even read random data?
    perror("reading random string");
    exit(1);
  }
  close(rfd); 
  return 1;
}

void displayKeyValuePair(unsigned char *key, unsigned char *value, uint32_t key_size, uint32_t value_size){
  printf("<");
  for(int t=0; t<key_size; t++) {
    char pc = 'A' + (key[t] % 26);
    printf("%c", pc); 
  }
  printf(", ");  
   for(int t=0; t<value_size; t++) {
    char pc = 'A' + (value[t] % 26);
    printf("%c", pc); 
  }
  printf(">\n");
}

void displayKey(unsigned char *key, uint32_t key_size){
  printf("<");
  for(int t=0; t<key_size; t++) {
    char pc = 'A' + (key[t] % 26);
    printf("%c", pc); 
  }
  printf(">\n");
}

int client_LSORAM_Insert(uint32_t instance_id, unsigned char *key, uint32_t key_size, unsigned char* value, uint32_t value_size){
  unsigned char *serialized_request, *encrypted_request, *tag_in;
  unsigned char *client_pubkey, *ecdh_aes_key, *iv;
  uint32_t pubkey_size_x, pubkey_size_y;
 
  uint32_t request_size = serializeLSORAMRequest(key, key_size, value, value_size, &serialized_request);
  
  encryptLSORAMRequest(ENCLAVE_PUBLIC_KEY, serialized_request, request_size, 
         &encrypted_request, &client_pubkey, &pubkey_size_x, &pubkey_size_y, 
         &ecdh_aes_key, &iv, &tag_in);

  /* 
  printf("Clientpubkey going into ZT_LSORAM_insert:\n");
  printf("X: :\n");
  for(int t = 0; t < 32; t++)
  printf("%02X", client_pubkey[t]);
  printf("\n");
  printf("Y :\n");
  for(int t = 0; t < 32; t++)
    printf("%02X", client_pubkey[32+t]);
  printf("\n");
  */

  ZT_LSORAM_insert(instance_id, encrypted_request, request_size,
                   tag_in, TAG_SIZE, client_pubkey, pubkey_size_x, pubkey_size_y);

  free(serialized_request);   
}

//TODO: Finish and Test client_LSORAM_Fetch
int client_LSORAM_Fetch(uint32_t instance_id, unsigned char *key, uint32_t key_size, unsigned char* encrypted_value, uint32_t value_size){
  //value needs to be populated by ZT_LSORAM_fetch
  unsigned char *serialized_request, *encrypted_request, *tag_in;
  unsigned char *client_pubkey, *ecdh_aes_key, *iv, *response;
  uint32_t pubkey_size_x, pubkey_size_y;

  // Response buffer and tag, populated by the enclave
  unsigned char tag_out[TAG_SIZE];
 
  generate_request_start = clock();

  uint32_t request_size = serializeLSORAMRequest(key, key_size, encrypted_value, 0, &serialized_request);
  
  encryptLSORAMRequest(ENCLAVE_PUBLIC_KEY, serialized_request, request_size, 
         &encrypted_request, &client_pubkey, &pubkey_size_x, &pubkey_size_y, &ecdh_aes_key, &iv, &tag_in);
  
  generate_request_stop = clock();
  generate_request_time = generate_request_stop - generate_request_start;
  printf("Request Generate time = %f ms\n",double(generate_request_time)/double(CLOCKS_PER_MS));

  /* 
  printf("Clientpubkey going into ZT_LSORAM_fetch:\n");
  printf("X: :\n");
  for(int t = 0; t < 32; t++)
  printf("%02X", client_pubkey[t]);
  printf("\n");
  printf("Y :\n");
  for(int t = 0; t < 32; t++)
    printf("%02X", client_pubkey[32+t]);
  printf("\n");
  */

  // TODO: Perform ZT_LSORAM_fetch
  
  process_request_start = clock();

  ZT_LSORAM_fetch(instance_id, encrypted_request, request_size,
                  encrypted_value, value_size, tag_in, tag_out, TAG_SIZE,
                  client_pubkey, pubkey_size_x, pubkey_size_y);
  
  process_request_stop = clock();
  process_request_time = process_request_stop - process_request_start;
  printf("Process Request Time = %f ms\n",double(process_request_time)/double(CLOCKS_PER_MS));

  //TODO: Decrypt Response

  extract_response_start = clock();

  decryptLSORAMResponse(encrypted_value, value_size, tag_out, ecdh_aes_key,
                        iv, &response);

  extract_response_stop = clock(); 
  printf("Extract Response Time = %f ms\n\n",double(extract_response_time)/double(CLOCKS_PER_MS));
 
  #ifdef DEBUG_LSORAM
    printf("Obtained Key Value Pair:\n");
    displayKeyValuePair(key, response, key_size, value_size);
  #endif
  free(serialized_request);   
}

int main(int argc, char *argv[]) {
  getParams(argc, argv);

  initializeZeroTrace();
  
  uint32_t zt_id = ZT_New_LSORAM(num_blocks, key_size, value_size, store_mode, oblivious_mode, 1);
  printf("Obtained zt_id = %d\n", zt_id);

  /* 
  for(int i =0; i<key_size-1;i++){
    key[i] = 'A';
  } 
  for(int i =0; i<value_size-1;i++){
    value[i] = 'E';
  }
  key[key_size-1]='\0';
  value[value_size-1]='\0';
  */
 
  //TODO: 
  // 1) Automate Generate Insert/Access/Evict requests
  // 2) Asymetric encrypt queries
  // 3) ZT_LSORAM_access(zt_id, encrypted_request, request_size, encrypted_response, response_size);
  
  std::map<std::string, std::string> kv_table;
  
 
  // TODO: Maintain a map of key/value pairs inserted
  
  inserts_start = clock();
  for (int i = 0; i <num_blocks; i++) { 
    unsigned char *key = (unsigned char *) malloc(key_size);
    unsigned char *value = (unsigned char *) malloc(value_size);

    generateKeyValuePair(key, value, key_size, value_size);
    #ifdef DEBUG_LSORAM
      printf("In LS_Client, Key-Value pair to be inserted: \n");
      displayKeyValuePair(key, value, key_size, value_size);
    #endif
    client_LSORAM_Insert(zt_id, key, key_size, value, value_size);

    std::string key_str, value_str;
    key_str.assign((const char*) key, key_size);
    value_str.assign((const char*) value, value_size);
    kv_table.insert(std::pair<std::string, std::string>(key_str, value_str));
  }  
  inserts_stop = clock();
  inserts_time = inserts_stop - inserts_start;
  
  printf("Table size = %d\n", kv_table.size());
 
  
  // TODO: Send requests for inserted keys, check that value returned matches the one in map
  std::map<std::string, std::string>::iterator it = kv_table.begin();
  unsigned char *encrypted_value_returned = (unsigned char *) malloc(value_size);
  
  fetches_start = clock(); 
  for (int i = 0; i <requestlength; i++) { 
    //TODO: Iterate over keys
    unsigned char *key = (unsigned char*) it->first.c_str();

    #ifdef DEBUG_LSORAM
      printf("In LS_Client, Key to be fetched: \n");
      displayKey(key, key_size);
    #endif

    client_LSORAM_Fetch(zt_id, key, key_size, encrypted_value_returned, value_size);

    it++;
    if(it==kv_table.end())
      it=kv_table.begin(); 
    
  } 
  fetches_stop = clock();
  fetches_time = fetches_stop-fetches_start;
  

  printf("Total insert time = %f\n", double(inserts_time)/double(CLOCKS_PER_MS)); 
  printf("Per Record insert time = %f\n",(double(inserts_time)/double(CLOCKS_PER_MS))/double(num_blocks)); 
  printf("Total fetch time = %f\n", double(fetches_time)/double(CLOCKS_PER_MS)); 
  printf("Per Record fetch time = %f\n",(double(fetches_time)/double(CLOCKS_PER_MS))/double(requestlength)); 
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


