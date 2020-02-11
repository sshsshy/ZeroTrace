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

#include "Test_Correctness.hpp"


unsigned char *encrypted_request, *tag_in, *encrypted_response, *tag_out;
//encrypted response size is same as response_size.
uint32_t request_size, response_size, encrypted_request_size;

unsigned char *data_in;
unsigned char *data_out;

clock_t generate_request_start, generate_request_stop, extract_response_start, extract_response_stop, process_request_start, process_request_stop, generate_request_time, extract_response_time,  process_request_time;
 
//TODO: Might not need this struct! Take it off.
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

int run_experiment(exp_params params){
  uint32_t max_blocks = params.max_blocks;
  uint32_t data_size = params.data_size;
  uint32_t request_length = params.request_length; 
  uint32_t stash_size = params.stash_size;
  uint32_t oblivious_flag = params.oblivious_flag;
  uint32_t recursion_data_size = params.recursion_data_size;
  uint32_t oram_type = params.oram_type;
  uint8_t Z = params.Z;

  printf("PARAMS in run_experiment: max_blocks =%d, data_size =%d\n", max_blocks, data_size);

  printf("Before ZT_New call\n"); 
  uint32_t zt_id = ZT_New(max_blocks, data_size, stash_size, oblivious_flag, recursion_data_size, oram_type, Z);
  printf("Done with ZT_New call, zt_id = %d\n", zt_id);


  //Variable declarations
  RandomRequestSource reqsource;
  clock_t start,end,tclock;  
  uint32_t *rs = reqsource.GenerateRandomSequence(request_length, max_blocks);
  uint32_t *insert_seq =  reqsource.GenerateRandomPermutation(max_blocks); 


  uint32_t i = 0;

  printf("Generated Insertion Permutation = \n");
  for(i = 0; i<max_blocks; i++)
    printf("%d, ", insert_seq[i]);
  printf("\n");

  request_size = ID_SIZE_IN_BYTES + data_size;
  tag_in = (unsigned char*) malloc (TAG_SIZE);
  tag_out = (unsigned char*) malloc (TAG_SIZE);
  data_in = (unsigned char*) malloc (data_size);
 

  response_size = data_size;
  //+1 for simplicity printing a null-terminated string
  data_out = (unsigned char*) malloc (data_size + 1);

  encrypted_request_size = computeCiphertextSize(data_size);
  encrypted_request = (unsigned char *) malloc (encrypted_request_size);				
  encrypted_response = (unsigned char *) malloc (response_size);		

  #ifdef PRINT_REQ_DETAILS
    printf("Starting ORAM writes to store unique data into each index before performing read requests.\n");
  #endif

  // Write data blocks for indices i: 0 to MAX_BLOCKS-1, as encryption of index padded with 0s to fill DATA_SIZE
  for(i=0;i<max_blocks;i++) { 
    //Prepare Datablock for index i:
      //Encrypt i, pad with 0s to fill DATA_SIZE
    prepareDataBlock(data_in, insert_seq[i], data_size);
      
    //Populate data_in with prepared datablock ^
    encryptRequest(insert_seq[i], 'w', data_in, data_size, encrypted_request, tag_in, encrypted_request_size);

    //Perform the ORAM write
    printf("Before ZT_Access call\n");
    ZT_Access(zt_id, oram_type, encrypted_request, encrypted_response, tag_in, tag_out, encrypted_request_size, response_size, TAG_SIZE);
    printf("After ZT_Access call\n");
  }


  #ifdef PRINT_REQ_DETAILS	
    printf("Starting Actual Access requests\n");
  #endif	


  start = clock();
  for(i=0;i<request_length;i++) {
    #ifdef PRINT_REQ_DETAILS		
      printf("---------------------------------------------------\n\nRequest no : %d\n",i);
      printf("Access ID: %d\n",rs[i]);
    #endif
 
    //Prepare Request:
    //request = rs[i]
    generate_request_start = clock();
    encryptRequest(rs[i], 'r', data_in, data_size, encrypted_request, tag_in, encrypted_request_size);
    generate_request_stop = clock();		

    //Process Request:
    process_request_start = clock();		
    ZT_Access(zt_id, oram_type, encrypted_request, encrypted_response, tag_in, tag_out, encrypted_request_size, response_size, TAG_SIZE);
    process_request_stop = clock();				

    //Extract Response:
    extract_response_start = clock();
    extractResponse(encrypted_response, tag_out, response_size, data_out);
    extract_response_stop = clock();
 
    if(checkFetchedDataBlock(data_out, rs[i], data_size)){
      printf("checkFetchedDataBlock - FAIL\n");
      return 1;
    }  
    else
      printf("checkFetchedDataBlock - SUCCESS\n");
    

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
      //fprintf(iquery_file,"%f\t%f\t%f\n", double(generate_request_time)/double(CLOCKS_PER_MS), double(process_request_time)/double(CLOCKS_PER_MS), double(extract_response_time)/double(CLOCKS_PER_MS));
    
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
  printf("Per query time = %f ms\n",(1000 * ( (double)tclock/ ( (double)request_length) ) / (double) CLOCKS_PER_SEC));	
  //printf("%ld\n",CLOCKS_PER_SEC);
  
  free(encrypted_request);
  free(encrypted_response);
  free(tag_in);
  free(tag_out);
  free(data_in);
  free(data_out);
  return 0;
}


int main(int argc, char *argv[]) {

  initializeZeroTrace();

  // DATA_SIZE, MAX_BLOCKS, REQ_LENGTH, STASH_SIZE, OBLIVIOUS_FLAG, RECURSION_DATA_SIZE, ORAM_TYPE, Z
  exp_params EXP1 = {32, 10000, 100, 200, 1, 64, 0, 4};
  exp_params EXP2 = {256, 10000, 100, 150, 1, 64, 0, 4};
  exp_params EXP3 = {1024,100000, 100, 150, 1, 64, 0, 4}; 

  exp_params EXP4 = {32, 10000, 100, 10, 1, 64, 1, 4};
  exp_params EXP5 = {256, 10000, 100, 10, 1, 64, 1, 4};
  exp_params EXP6 = {1024,100000, 100, 10, 1, 64, 1, 4}; 

  if(run_experiment(EXP1))
    printf("EXP1: Failed! \n");
  else
    printf("EXP1: SUCCESS! \n");

  /*
  if(run_experiment(EXP2))
    printf("EXP2: Failed! \n");
  else
    printf("EXP2: SUCCESS! \n");

  if(run_experiment(EXP3))
    printf("EXP3: Failed! \n");
  else
    printf("EXP3: SUCCESS! \n");
  */
 
  if(run_experiment(EXP4))
    printf("EXP4: Failed! \n");
  else
    printf("EXP4: SUCCESS! \n");

  /*
  if(run_experiment(EXP5))
    printf("EXP5: Failed! \n");
  else
    printf("EXP5: SUCCESS! \n");

  if(run_experiment(EXP3))
    printf("EXP6: Failed! \n");
  else
    printf("EXP6: SUCCESS! \n");
  */

  return 0;
}



