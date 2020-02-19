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

#ifdef DETAILED_MICROBENCHMARKER
  det_mb ***MB = NULL; 
  uint8_t mb_recursion_levels;
  uint32_t mb_request_length; 

  uint8_t  NUM_EXPECTED_PARAMS=9;   
  std::string LOG_FOLDER;
  std::string LOG_FILE;
 
#endif

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

  #ifdef DETAILED_MICROBENCHMARKER
    if(MB) {
      // free them up and reallocate for presumably new parameters 
      for(uint32_t i = 0; i< mb_request_length; i++) {
        for(uint32_t j=0; j< mb_recursion_levels; j++) {
          free(MB[i][j]);
        }
        free(MB[i]);       
      }
      free(MB);
    }
    mb_request_length = request_length;
    setMicrobenchmarkerParams(oram_type, request_length); 
  #endif

  printf("Before ZT_New call\n"); 
  uint32_t zt_id = ZT_New(max_blocks, data_size, stash_size, oblivious_flag, recursion_data_size, oram_type, Z);
  printf("Done with ZT_New call, zt_id = %d\n", zt_id);


  //Variable declarations
  RandomRequestSource reqsource;
  clock_t start,end,tclock;  
  uint32_t *rs = reqsource.GenerateRandomSequence(request_length, max_blocks);
  uint32_t *insert_seq =  reqsource.GenerateRandomPermutation(max_blocks); 

  uint32_t i = 0;

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
    ZT_Access(zt_id, oram_type, encrypted_request, encrypted_response, tag_in, tag_out, encrypted_request_size, response_size, TAG_SIZE);
  }


  #ifdef PRINT_REQ_DETAILS	
    printf("Starting Actual Access requests\n");
  #endif	


  #ifdef DETAILED_MICROBENCHMARKER
    mb_recursion_levels = getRecursionLevels();

    MB = (det_mb***) malloc (mb_request_length * sizeof(det_mb**));
    for(uint32_t i = 0; i<mb_request_length; i++) {
      MB[i] = (det_mb**) malloc (mb_recursion_levels * sizeof(det_mb*));
      for(uint32_t j = 0; j<mb_recursion_levels; j++) {
        MB[i][j] = (det_mb*) malloc(sizeof(det_mb));
      }
    }

    initiateMicrobenchmarker(MB);
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
 
    #ifdef CHECK_CORRECTNESS		
      if(checkFetchedDataBlock(data_out, rs[i], data_size)){
        printf("checkFetchedDataBlock - FAIL\n");
        return 1;
      }  
    #endif 

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
 
  #ifdef DETAILED_MICROBENCHMARKER
    det_mb det_mb_avg;
    det_mb det_mb_std;
    uint8_t recursion_levels =mb_recursion_levels; 

    if(mb_recursion_levels==1){

      double download_time_avg, download_time_std, posmap_time_avg, posmap_time_std,
             fetch_block_time_avg, fetch_block_time_std, eviction_time_avg, eviction_time_std,
             upload_time_avg, upload_time_std, total_time_avg, total_time_std;

      double posmap_time[mb_request_length], download_time_level[mb_request_length], 
             fetch_block_time_level[mb_request_length], eviction_time_level[mb_request_length],
             upload_time_level[mb_request_length], total_time[mb_request_length];  

      for(uint32_t i=0; i<mb_request_length; i++) {
        posmap_time[i] = MB[i][0]->posmap_time;
      }
      posmap_time_avg = compute_avg((double*) posmap_time, mb_request_length);
      posmap_time_std = compute_stddev((double*) posmap_time, mb_request_length);
      //printf("Posmap_time AVG = %lf, Posmap_time STDDEV = %lf\n", posmap_time_avg, posmap_time_std);
      
      for(uint32_t i=0; i<mb_request_length; i++) {
         download_time_level[i] = MB[i][0]->download_path_time;
      }
      download_time_avg=compute_avg((double*)download_time_level, mb_request_length);  
      download_time_std=compute_stddev((double*)download_time_level, mb_request_length); 
      //printf("Download_time_avg = %lf, Download_time_std = %lf\n", 
      //         download_time_avg, download_time_std);

      for(uint32_t i=0; i<mb_request_length; i++) {
         fetch_block_time_level[i] = MB[i][0]->fetch_block_time;
      }
      fetch_block_time_avg=compute_avg((double*)fetch_block_time_level, mb_request_length);  
      fetch_block_time_std=compute_stddev((double*)fetch_block_time_level, mb_request_length); 
      //printf("Fetch_block_time_avg = %lf, Fetch_block_time_std = %lf\n", 
      //       fetch_block_time_avg, fetch_block_time_std);
    
 
      for(uint32_t i=0; i<mb_request_length; i++) {
         eviction_time_level[i] = MB[i][0]->eviction_time;
      }
      eviction_time_avg=compute_avg((double*)eviction_time_level, mb_request_length);  
      eviction_time_std=compute_stddev((double*)eviction_time_level, mb_request_length); 
      //printf("Eviction_logic_time_avg = %lf, Eviction_logic_time_std = %lf\n", 
      //       eviction_time_avg, eviction_time_std);


      for(uint32_t i=0; i<mb_request_length; i++) {
         upload_time_level[i] = MB[i][0]->upload_path_time;
      }
      upload_time_avg=compute_avg((double*)upload_time_level, mb_request_length);  
      upload_time_std=compute_stddev((double*)upload_time_level, mb_request_length); 
      //printf("Upload_time_avg = %lf, Upload_time_std = %lf\n", upload_time_avg, upload_time_std);


      for(uint32_t i=0; i<mb_request_length; i++) {
        total_time[i] = MB[i][0]->total_time;
      }
      total_time_avg = compute_avg((double*) total_time, mb_request_length);
      total_time_std = compute_stddev((double*) total_time, mb_request_length);

      //Populate LOG_FILE, LOG_FILE_avg and, LOG_FILE_std
      printf("Log_file = %s\n", LOG_FILE.c_str());
      std::string LOG_FILE_AVG = LOG_FILE+"_AVG";
      std::string LOG_FILE_STD = LOG_FILE+"_STD";
      FILE *log_file = fopen(LOG_FILE.c_str(),"w");
      if(log_file==NULL)
        printf("fopen failed\n");

      printf("Before logfile loop\n"); 
      for(uint32_t i=0; i<mb_request_length; i++){
        double p = posmap_time[i];
        double d = download_time_level[i];
        double f = fetch_block_time_level[i];
        double e = eviction_time_level[i];
        double u = upload_time_level[i];
        double t = total_time[i];
        fprintf(log_file, "%f, %f, %f, %f, %f, %f\n", p, d, f, e, u, t);
      } 
      printf("Done with logfile loop\n"); 
      fclose(log_file);

      FILE *log_file_avg = fopen(LOG_FILE_AVG.c_str(), "w");
      fprintf(log_file_avg, "%f, %f, %f, %f, %f, %f\n", posmap_time_avg, download_time_avg,
              fetch_block_time_avg, eviction_time_avg, upload_time_avg, total_time_avg);
      fclose(log_file_avg);

      FILE *log_file_std = fopen(LOG_FILE_STD.c_str(), "w");
      fprintf(log_file_std, "%f, %f, %f, %f, %f, %f\n", posmap_time_std, download_time_std,
              fetch_block_time_std, eviction_time_std, upload_time_std, total_time_std);
      fclose(log_file_std);
    }
    else{
      //Position Map time is only in level 0, so no need to iterate over recursion_levels;
      //TODO: Posmap time for recursion( Put into the highest recursion level?)
 
      //Download Path time for all levels of recursion
      double download_time_avg[mb_recursion_levels];
      double download_time_std[mb_recursion_levels];
      double download_time_level[mb_request_length];
      for(uint32_t j=0; j<recursion_levels; j++) {
        for(uint32_t i=0; i<mb_request_length; i++) {
           download_time_level[i] = MB[i][j]->download_path_time;
        }
        download_time_avg[j]=compute_avg((double*)download_time_level, mb_request_length);  
        download_time_std[j]=compute_stddev((double*)download_time_level, mb_request_length); 
        printf("Download_time_avg[%d] = %lf, Download_time_std[%d] = %lf\n", j, download_time_avg[j], j, download_time_std[j]);
      }

      //Fetch Block time for all levels of recursion
      double fetch_block_time_avg[mb_recursion_levels];
      double fetch_block_time_std[mb_recursion_levels];
      double fetch_block_time_level[mb_request_length];
      for(uint32_t j=0; j<recursion_levels; j++) {
        for(uint32_t i=0; i<mb_request_length; i++) {
           fetch_block_time_level[i] = MB[i][j]->fetch_block_time;
        }
        fetch_block_time_avg[j]=compute_avg((double*)fetch_block_time_level, mb_request_length);  
        fetch_block_time_std[j]=compute_stddev((double*)fetch_block_time_level, mb_request_length); 
        printf("Fetch_block_time_avg[%d] = %lf, Fetch_block_time_std[%d] = %lf\n", j, fetch_block_time_avg[j], j, fetch_block_time_std[j]);
      }

      //Eviction time for all levels of recursion
      double eviction_time_avg[mb_recursion_levels];
      double eviction_time_std[mb_recursion_levels];
      double eviction_time_level[mb_request_length];
      for(uint32_t j=0; j<recursion_levels; j++) {
        for(uint32_t i=0; i<mb_request_length; i++) {
           eviction_time_level[i] = MB[i][j]->eviction_time;
        }
        eviction_time_avg[j]=compute_avg((double*)eviction_time_level, mb_request_length);  
        eviction_time_std[j]=compute_stddev((double*)eviction_time_level, mb_request_length); 
        printf("Eviction_logic_time_avg[%d] = %lf, Eviction_logic_time_std[%d] = %lf\n", j, eviction_time_avg[j], j, eviction_time_std[j]);
      }


      //Upload Path time for all levels of recursion
      double upload_time_avg[mb_recursion_levels];
      double upload_time_std[mb_recursion_levels];
      double upload_time_level[mb_request_length];
      for(uint32_t j=0; j<recursion_levels; j++) {
        for(uint32_t i=0; i<mb_request_length; i++) {
           upload_time_level[i] = MB[i][j]->upload_path_time;
        }
        upload_time_avg[j]=compute_avg((double*)upload_time_level, mb_request_length);  
        upload_time_std[j]=compute_stddev((double*)upload_time_level, mb_request_length); 
        //printf("Upload_time_avg[%d] = %lf, Upload_time_std[%d] = %lf\n", j, upload_time_avg[j], j, upload_time_std[j]);
      }

    }






        // Compute stats on all the accesses and populate 
        // det_mb_avg and det_mb_std.
        // The client will invoke a DET_MB_get_results call to 
        // fetch the pointers to these structures and then display the results as required
      
  #endif

 
  end = clock();
  tclock = end - start;

  printf("Requests Fin\n");	

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

#ifdef DETAILED_MICROBENCHMARKER
  void getParams(int argc, char* argv[])
  {
    if(argc!=NUM_EXPECTED_PARAMS) {
      printf("Command line parameters error, received: %d, expected :%d\n",
             argc, NUM_EXPECTED_PARAMS);
      printf(" <N> <No_of_requests> <Stash_size> <Data_block_size> <Recursion_block_size> <\"path(0)\"/\"circuit(1)\"> <Z> <LogFolder (Must Exist)>\n\n");
      exit(0);
    }

    std::string str = argv[1];
    MAX_BLOCKS = std::stoi(str);
    str = argv[2];
    REQUEST_LENGTH = std::stoi(str);
    str = argv[3];
    STASH_SIZE = std::stoi(str);
    str = argv[4];
    DATA_SIZE = std::stoi(str);	
    str = argv[5];	
    RECURSION_DATA_SIZE = std::stoi(str);
    str = argv[6];
    if(str=="path"||std::stoi(str)==0)
      ORAM_TYPE = 0;
    if(str=="circuit"||std::stoi(str)==1)
      ORAM_TYPE = 1;
    str=argv[7];
    Z = std::stoi(str);
    str = argv[8];
    LOG_FOLDER = str;
    std::string ot;
    if(ORAM_TYPE==0)
      ot = "PO";
    else
      ot = "CO";
    LOG_FILE = LOG_FOLDER+'/'+
               ot +"_"+ std::to_string(MAX_BLOCKS) +"_"+ std::to_string(DATA_SIZE) +"_"+ std::to_string(STASH_SIZE) +"_"+
               std::to_string(Z) +"_"+ std::to_string(REQUEST_LENGTH);
    printf("LOG_FILE = %s", LOG_FILE.c_str()); 
    //std::string qfile_name = "ZT_"+std::to_string(MAX_BLOCKS)+"_"+std::to_string(DATA_SIZE);
    //iquery_file = fopen(qfile_name.c_str(),"w");
  }
#endif

int main(int argc, char *argv[]) {

  initializeZeroTrace();
  printf("Done with initializeZeroTrace\n");

  // DATA_SIZE, MAX_BLOCKS, REQ_LENGTH, STASH_SIZE, OBLIVIOUS_FLAG, RECURSION_DATA_SIZE, ORAM_TYPE, Z

  #ifdef DETAILED_MICROBENCHMARKER
    getParams(argc, argv);
    exp_params EXP;
    EXP.max_blocks = MAX_BLOCKS; 
    EXP.data_size = DATA_SIZE;
    EXP.request_length = REQUEST_LENGTH;
    EXP.stash_size = STASH_SIZE;
    EXP.recursion_data_size = RECURSION_DATA_SIZE;
    //Currently hard-coded Oblivious mode.
    EXP.oblivious_flag = 1;
    EXP.oram_type = ORAM_TYPE;
    EXP.Z = Z;
  
    if(run_experiment(EXP))
      printf("EXP Failed! \n");
    else
      printf("EXP SUCCESS! \n");
 
  #else
    exp_params EXP1 = {128, 10000, 100, 70, 1, 64, 0, 4};
    exp_params EXP2 = {128, 10000, 100, 60, 1, 64, 0, 3};
    exp_params EXP3 = {128, 10000, 100, 50, 1, 64, 0, 3}; 

    exp_params EXP4 = {128, 1024, 100, 15, 1, 64, 1, 2};
    exp_params EXP5 = {128, 1024, 100, 15, 1, 64, 1, 3};
    exp_params EXP6 = {128, 16384, 100, 15, 1, 64, 1, 3}; 

    if(run_experiment(EXP1))
      printf("EXP1: Failed! \n");
    else
      printf("EXP1: SUCCESS! \n");

    if(run_experiment(EXP2))
      printf("EXP2: Failed! \n");
    else
      printf("EXP2: SUCCESS! \n");

    if(run_experiment(EXP3))
      printf("EXP3: Failed! \n");
    else
      printf("EXP3: SUCCESS! \n");
   
    if(run_experiment(EXP4))
      printf("EXP4: Failed! \n");
    else
      printf("EXP4: SUCCESS! \n");

    if(run_experiment(EXP5))
      printf("EXP5: Failed! \n");
    else
      printf("EXP5: SUCCESS! \n");

    if(run_experiment(EXP6))
      printf("EXP6: Failed! \n");
    else
      printf("EXP6: SUCCESS! \n");
  
  #endif
 
  return 0;
}



