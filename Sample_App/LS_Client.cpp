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

#include "LS_Client.hpp"
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


void getParams(int argc, char* argv[])
{
  if(argc<min_expected_no_of_parameters) {
    printf("Command line parameters error, expected :\n");
    printf(" <N> <No_of_requests> <key_size> <value_size> <0/1 = Store In-PRM/Outside-PRM> <0/1 = Access-Oblivious/Full-Oblivious> <Logfile>\n");
  }

  std::string str = argv[1];
  NUM_BLOCKS = std::stoi(str);
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
  str = argv[7];
  logfile = str;

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
  
  int8_t ret;
  ret = ZT_Initialize(bin_x, bin_y, signature_r, signature_s, max_buff_size);
  
  EC_GROUP *curve;
  EC_KEY *enclave_verification_key = NULL;
  ECDSA_SIG *sig_enclave = ECDSA_SIG_new();	
  BIGNUM *x, *y, *xh, *yh;
  BN_CTX *bn_ctx = BN_CTX_new();

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

  #ifdef VERBOSE
    if(ret==1){
	    printf("GetEnclavePublishedKey : Verification Successful! \n");
    }
    else{
	    printf("GetEnclavePublishedKey : Verification FAILED! \n");
    }
  #endif  

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

  for(uint32_t i =0; i<key_size; i++){
      key[i] = 'A' + (key[i]%26);
  }

  for(uint32_t i =0; i<value_size; i++){
      value[i] = 'A' + (value[i] % 26);
  }
  
  close(rfd); 
  return 1;
}

void displayKeyValuePair(unsigned char *key, unsigned char *value, uint32_t key_size, uint32_t value_size){
  printf("<");
  for(int t=0; t<key_size; t++) {
    //char pc = 'A' + (key[t] % 26);
    printf("%c", key[t]); 
  }
  printf(", ");  
   for(int t=0; t<value_size; t++) {
    //char pc = 'A' + (value[t] % 26);
    printf("%c", value[t]); 
  }
  printf(">\n");
}

void displayKey(unsigned char *key, uint32_t key_size){
  printf("<");
  for(int t=0; t<key_size; t++) {
    //char pc = 'A' + (key[t] % 26);
    printf("%c", key[t]); 
  }
  printf(">\n");
}

int client_LSORAM_Insert(uint32_t lsoram_iid, uint32_t oram_iid, unsigned char *key, uint32_t key_size, unsigned char* value, uint32_t value_size){
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

  #ifdef HSORAM_MODE
    ZT_HSORAM_insert(lsoram_iid, oram_iid, HSORAM_ORAM_TYPE, oram_index++, encrypted_request,
       request_size, tag_in, TAG_SIZE, client_pubkey, pubkey_size_x, pubkey_size_y);
  #else
    ZT_LSORAM_insert(lsoram_iid, encrypted_request, request_size,
                   tag_in, TAG_SIZE, client_pubkey, pubkey_size_x, pubkey_size_y);
  #endif


  free(serialized_request);   
}

//TODO: Finish and Test client_LSORAM_Fetch
int client_LSORAM_Fetch(uint32_t lsoram_iid, uint32_t oram_iid, unsigned char *key, uint32_t key_size, unsigned char* value, uint32_t value_size, uint32_t req_ctr, double *gentime, double *processtime, double *extracttime){
  //value needs to be populated by ZT_LSORAM_fetch
  unsigned char *serialized_request, *encrypted_request, *tag_in;
  unsigned char *client_pubkey, *ecdh_aes_key, *iv, *response;
  uint32_t pubkey_size_x, pubkey_size_y;

  // Response buffer and tag, populated by the enclave
  unsigned char tag_out[TAG_SIZE];
 
  generate_request_start = clock();

  //uint32_t request_size = serializeLSORAMRequest(key, key_size, encrypted_value, 0, &serialized_request);
 
  //Request is just key encrypted for fetch 
  encryptLSORAMRequest(ENCLAVE_PUBLIC_KEY, key, key_size, 
         &encrypted_request, &client_pubkey, &pubkey_size_x, &pubkey_size_y, &ecdh_aes_key, &iv, &tag_in);
  
  generate_request_stop = clock();
  generate_request_time = generate_request_stop - generate_request_start;
  //printf("Request Generate time = %f ms\n",double(generate_request_time)/double(CLOCKS_PER_MS));
  gentime[req_ctr] = double(generate_request_time)/double(CLOCKS_PER_MS);

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

  
  process_request_start = clock();

  #ifdef HSORAM_MODE
    ZT_HSORAM_fetch(lsoram_iid, oram_iid, HSORAM_ORAM_TYPE, encrypted_request, key_size,
       value, value_size, tag_in, tag_out, TAG_SIZE,
       client_pubkey, pubkey_size_x, pubkey_size_y);  
  #else
    ZT_LSORAM_fetch(lsoram_iid, encrypted_request, key_size,
                  value, value_size, tag_in, tag_out, TAG_SIZE,
                  client_pubkey, pubkey_size_x, pubkey_size_y);
  #endif



  process_request_stop = clock();
  process_request_time = process_request_stop - process_request_start;
  //printf("Process Request Time = %f ms\n", double(process_request_time)/double(CLOCKS_PER_MS));
  processtime[req_ctr] = double(process_request_time)/double(CLOCKS_PER_MS);
  

  extract_response_start = clock();

  decryptLSORAMResponse(value, value_size, tag_out, ecdh_aes_key,
                        iv, &response);

  extract_response_stop = clock(); 
  extract_response_time = extract_response_stop - extract_response_start; 
  //printf("Extract Response Time = %f ms\n\n",double(extract_response_time)/double(CLOCKS_PER_MS));
  extracttime[req_ctr] = double(extract_response_time)/double(CLOCKS_PER_MS);
 
  #ifdef DEBUG_LSORAM
    printf("Obtained Key Value Pair:\n");
    displayKeyValuePair(key, response, key_size, value_size);
  #endif
  
  memcpy(value, response, value_size);
  free(response);
}

int main(int argc, char *argv[]) {
  getParams(argc, argv);

  initializeZeroTrace();

  double ftime[requestlength];
  double processtime[requestlength];
  double gentime[requestlength];
  double extracttime[requestlength];

  uint32_t zt_lsoram_id;
  uint32_t zt_oram_id = 0; 

  #ifdef HSORAM_MODE
    zt_lsoram_id = ZT_New_LSORAM(NUM_BLOCKS, key_size, HSORAM_INDEX_SIZE, store_mode, oblivious_mode, 1);
    zt_oram_id = ZT_New(HSORAM_MAX_BLOCKS, value_size, HSORAM_STASH_SIZE, HSORAM_OBLIVIOUS_TYPE_ORAM, HSORAM_RECURSION_DATA_SIZE, HSORAM_ORAM_TYPE, HSORAM_Z);
  #else
    zt_lsoram_id = ZT_New_LSORAM(NUM_BLOCKS, key_size, value_size, store_mode, oblivious_mode, 1);
  #endif
  //printf("Obtained zt_lsoram_id = %d\n", zt_lsoram_id); 
 
  std::map<std::string, std::string> kv_table;
  
  inserts_time = 0; 
  for (int i = 0; i <NUM_BLOCKS; i++) { 
    unsigned char *key = (unsigned char *) malloc(key_size);
    unsigned char *value = (unsigned char *) malloc(value_size);

    generateKeyValuePair(key, value, key_size, value_size);
    #ifdef DEBUG_LSORAM
      printf("In LS_Client, Key-Value pair to be inserted: \n");
      displayKeyValuePair(key, value, key_size, value_size);
    #endif

    inserts_start = clock();
   
    if(store_mode==1){
      ZT_LSORAM_oprm_insert_pt(zt_lsoram_id, key, key_size, value, value_size);
    }
    else{
      ZT_LSORAM_iprm_insert_pt(zt_lsoram_id, key, key_size, value, value_size);
      //client_LSORAM_Insert(zt_lsoram_id, zt_oram_id, key, key_size, value, value_size);
    }
    inserts_stop = clock();
    
    std::string key_str, value_str;
    key_str.assign((const char*) key, key_size);
    value_str.assign((const char*) value, value_size);
    kv_table.insert(std::pair<std::string, std::string>(key_str, value_str));
    inserts_time = inserts_stop - inserts_start;
  }  
  
  std::map<std::string, std::string>::iterator it = kv_table.begin();
  std::map<std::string, std::string>::iterator lookup;
  unsigned char *encrypted_value_returned = (unsigned char *) malloc(value_size);
  
  fetches_time = 0;

  for (int i = 0; i <requestlength; i++) { 
    unsigned char *key = (unsigned char*) it->first.c_str();

    #ifdef DEBUG_LSORAM
      printf("In LS_Client, Key to be fetched: \n");
      displayKey(key, key_size);
    #endif

    fetches_start = clock(); 
    client_LSORAM_Fetch(zt_lsoram_id, zt_oram_id, key, key_size, encrypted_value_returned, value_size, i, gentime, processtime, extracttime);
    fetches_stop = clock();
    ftime[i]=double(fetches_stop-fetches_start)/double(CLOCKS_PER_MS);

    //If in Correctness Test Mode, check that the returned value is correct.
    #ifdef TEST_CORRECTNESS
      std::string val_returned;
      val_returned.assign((const char*) encrypted_value_returned, (size_t) value_size);
      int32_t cmp_val = val_returned.compare(it->second);     
 
      if(cmp_val==0)
        printf("Req No %d: Lookup Correctness Test PASS.\n", i+1);
      else 
        printf("Req No %d: Lookup Correctness Test FAIL.\n", i+1);
    #endif

    it++;
    if(it==kv_table.end())
      it=kv_table.begin(); 
   
    fetches_time+=(fetches_stop-fetches_start);
  } 
 

  double fetch_time=(double(fetches_time)/double(CLOCKS_PER_MS))/double(requestlength);
  double insert_time=(double(inserts_time)/double(CLOCKS_PER_MS))/double(NUM_BLOCKS);

  #ifdef SHOW_TIMING_RESULTS
    printf("Total insert time = %f\n", double(inserts_time)/double(CLOCKS_PER_MS)); 
    printf("Per Record insert time = %f\n",insert_time); 
    printf("Total fetch time = %f\n", double(fetches_time)/double(CLOCKS_PER_MS)); 
    printf("Per Record fetch time = %f\n",fetch_time); 
  #endif

  FILE *fptr = fopen(logfile.c_str(), "a");
  double gentime_avg, processtime_avg, extracttime_avg;
  double gentime_std, processtime_std, extracttime_std;

  gentime_avg = compute_avg((double *) gentime, requestlength);
  processtime_avg = compute_avg((double *) processtime, requestlength);
  extracttime_avg = compute_avg((double *) extracttime, requestlength);
  
  gentime_std = compute_stddev((double *) gentime, requestlength);
  processtime_std = compute_stddev((double *) processtime, requestlength);
  extracttime_std = compute_stddev((double *) extracttime, requestlength);

  double stddev=compute_stddev((double*) ftime, requestlength);
  

  uint64_t request_size = key_size + TAG_SIZE;
  uint64_t response_size = value_size + TAG_SIZE;
  //fprintf(fptr, "%d,%f,%f\n", num_blocks, fetch_time, stddev);
  fprintf(fptr, "%d, %f, %f, %f, %f, %f, %f, %ld, %ld\n", NUM_BLOCKS, gentime_avg, gentime_std, processtime_avg,
         processtime_std, extracttime_avg, extracttime_std, request_size, response_size);
  fclose(fptr);

  return 0;
}


