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

/*
Untrusted Application Code for ZeroTrace
Usage : 
printf("./app <N> <No_of_requests> <Stash_size> <Data_block_size> <"resume"/"new"> <"memory"/"hdd"> <"0"/"1" = Non-oblivious/Oblivious> <Recursion_block_size>");
Note : parameters surrounded by quotes should entered in as is without the quotes.

//META-NOTES :
//_e trailed variables are computed/obtained from enclave
//_p trailed variables are obtained from commandline parameters
*/

#include "App.h"

#define MAX_PATH FILENAME_MAX
#define CIRCUIT_ORAM
#define NUMBER_OF_WARMUP_REQUESTS 0
#define ANALYSIS 1
#define MILLION 1E6
#define HASH_LENGTH 32


#ifdef DETAILED_MICROBENCHMARKER
  typedef struct detailed_microbenchmark_params{
    uint8_t oram_type;  
    uint8_t recursion_levels;
    uint32_t num_requests;
    bool on;
  }det_mb_params;

  det_mb_params DET_MB_PARAMS;
  det_mb ***MB = NULL; 
  uint32_t req_counter=0;
#endif

//#define NO_CACHING_APP 1
//#define EXITLESS_MODE 1
//#define POSMAP_EXPERIMENT 1


// Global Variables Declarations
uint64_t PATH_SIZE_LIMIT = 1 * 1024 * 1024;
uint32_t aes_key_size = 16;
uint32_t hash_size = 32;	
#define ADDITIONAL_METADATA_SIZE 24
uint32_t oram_id = 0;

//Timing variables
uint32_t recursion_levels_e = 0;

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
bool resume_experiment = false;
bool inmem_flag = true;

// Storage Backends:
//TODO: Switch to LS for each LSORAM, Path, Circuit
LocalStorage ls;
std::map<uint32_t, LocalStorage*> ls_PORAM;
std::map<uint32_t, LocalStorage*> ls_CORAM;
std::map<uint32_t, std::vector<tuple*>*> ls_LSORAM;

double compute_stddev(double *elements, uint32_t num_elements) {
  double mean = 0, var = 0, stddev;
  for(uint32_t i=0; i<num_elements; i++) {
    mean+=elements[i];   
  }
  mean=(mean/num_elements);
  for(uint32_t i=0; i<num_elements; i++) {
    double diff = mean - elements[i];
    var+=(diff*diff);
  }
  var=var/num_elements;
  stddev = sqrt(var);
  return stddev;
}

double compute_avg(double *elements, uint32_t num_elements) {
  double mean = 0, var = 0, stddev;
  for(uint32_t i=0; i<num_elements; i++) {
    mean+=elements[i];   
  }
  mean=(mean/num_elements);
  return mean;
}

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

struct oram_request{
  uint32_t *id;
  uint32_t *level;
  uint32_t *d_lev;
  bool *recursion;
  bool *block;
};

struct oram_response{
  unsigned char *path;
  unsigned char *path_hash;
  unsigned char *new_path;
  unsigned char *new_path_hash;
};

struct thread_data{
  struct oram_request *req;
  struct oram_response *resp;
};

struct thread_data td;
struct oram_request req_struct;
struct oram_response resp_struct;	
unsigned char *data_in;
unsigned char *data_out;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret) {
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                fprintf(stderr, "ZT_LSORAM:Info: %s\n", sgx_errlist[idx].sug);
            fprintf(stderr, "ZT_LSORAM:Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        fprintf(stderr, "ZT_LSORAM:Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void) {
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        fprintf(stderr, "ZT_LSORAM:Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            fprintf(stderr, "ZT_LSORAM:Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        fprintf(stderr, "Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str) {
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}

void *HandleRequest(void *arg) {
  //printf("In Handle Request thread\n");

  struct thread_data *data;
  data = (struct thread_data *) arg;
  unsigned char *ptr = data->resp->path;
  unsigned char *ptr_hash = data->resp->path_hash;
  uint32_t* id = data->req->id;
  uint32_t *level= data->req->level;
  uint32_t *d_lev = data->req->d_lev;
  bool *recursion = data->req->recursion;
  

  uint64_t path_hash_size = 2 * (*d_lev) * HASH_LENGTH; // 2 from siblings 		

  uint64_t i = 0;

  while(1) {
    //*id==-1 || *level == -1 || 
    while( *(data->req->block) ) {}
    //printf("APP : Recieved Request\n");

    ls.downloadPath(*id, data->resp->path, data->resp->path_hash, path_hash_size, *level , *d_lev);	
    //printf("APP : Downloaded Path\n");	
    *(data->req->block) = true;
        
    while(*(data->req->block)) {}
    ls.uploadPath(*id, data->resp->new_path, data->resp->new_path_hash, *level, *d_lev);
    //printf("APP : Uploaded Path\n");
    *(data->req->block) = true;

    //pthread_exit(NULL);
  }
    
}

uint64_t timediff(struct timeval *start, struct timeval *end) {
  long seconds,useconds;
  uint64_t mtime;
  seconds  = end->tv_sec  - start->tv_sec;
  useconds = end->tv_usec - start->tv_usec;
  mtime = ((seconds) * 1000 + useconds/1000.0) + 0.5;
  return mtime;
}

double timetaken(timespec *start, timespec *end) {
  long seconds, nseconds;
  seconds = end->tv_sec - start->tv_sec;
  nseconds = end->tv_nsec - start->tv_nsec;
  double mstime = ( double(seconds * 1000) + double(nseconds/MILLION) );
  return mstime;
}


uint32_t ZT_New_LSORAM( uint32_t num_blocks, uint32_t key_size, uint32_t value_size, uint8_t mode, uint8_t oblivious_type, uint8_t populate_flag) {
  sgx_status_t sgx_return;
  uint32_t instance_id;
  sgx_return = createNewLSORAMInstance(global_eid, &instance_id, key_size, value_size, num_blocks, mode, oblivious_type, populate_flag);

  return instance_id;
}
  
int8_t ZT_LSORAM_insert(uint32_t instance_id, unsigned char *encrypted_request, uint32_t request_size, 
       unsigned char* tag_in, uint32_t tag_size, unsigned char *client_pubkey, uint32_t pubkey_size_x,
       uint32_t pubkey_size_y) { 
  sgx_status_t sgx_return; 
  int8_t ret;
  sgx_return = LSORAMInsert(global_eid, &ret, instance_id, encrypted_request,
               request_size, tag_in, tag_size, client_pubkey, pubkey_size_x+pubkey_size_y, pubkey_size_x, pubkey_size_y);
  return ret;
}

int8_t ZT_LSORAM_oprm_insert_pt(uint32_t instance_id, unsigned char *key_l, 
       uint32_t key_size, unsigned char *value_l, uint32_t value_size) {

  std::vector<tuple *> *LSORAM_store;
  auto search = ls_LSORAM.find(instance_id); 
  if(search != ls_LSORAM.end()) {
    LSORAM_store = search->second;
  }
  else{
    return -1;
  }

  int8_t ret;
  tuple *t = (tuple *) malloc(sizeof(tuple));
  t->key = (unsigned char*) malloc (key_size);
  t->value = (unsigned char*) malloc (value_size);
  memcpy(t->key, key_l, key_size);
  memcpy(t->value, value_l, value_size);
  LSORAM_store->push_back(t);
    
  return ret;
}

int8_t ZT_LSORAM_iprm_insert_pt(uint32_t instance_id, unsigned char *key_l, 
       uint32_t key_size, unsigned char *value_l, uint32_t value_size) {

  int8_t ret;
  sgx_status_t sgx_return;
  sgx_return = LSORAMInsert_pt(global_eid, &ret, instance_id, key_l, 
               key_size, value_l, value_size);  
 
  return ret;
}


int8_t ZT_LSORAM_fetch(uint32_t instance_id, unsigned char *encrypted_request, uint32_t request_size, unsigned char *encrypted_response, 
                       uint32_t response_size, unsigned char* tag_in, unsigned char* tag_out, uint32_t tag_size, 
		       unsigned char *client_pubkey, uint32_t pubkey_size_x, uint32_t pubkey_size_y) { 
  sgx_status_t sgx_return; 
  int8_t ret;
  sgx_return = LSORAMFetch(global_eid, &ret, instance_id, encrypted_request, request_size, encrypted_response, response_size, 
               tag_in, tag_out, tag_size, client_pubkey, pubkey_size_x + pubkey_size_y, pubkey_size_x, pubkey_size_y);
  return ret;
}

int8_t ZT_HSORAM_insert(uint32_t lsoram_iid, uint32_t oram_iid, uint8_t oram_type, uint64_t oram_index,
       unsigned char *encrypted_request, uint32_t request_size, 
       unsigned char* tag_in, uint32_t tag_size, unsigned char *client_pubkey, uint32_t pubkey_size_x,
       uint32_t pubkey_size_y) { 
  sgx_status_t sgx_return; 
  int8_t ret;
  sgx_return = HSORAMInsert(global_eid, &ret, lsoram_iid, oram_iid, oram_type, 
               oram_index, encrypted_request, request_size, tag_in, tag_size, 
               client_pubkey, pubkey_size_x+pubkey_size_y, pubkey_size_x,
               pubkey_size_y);
  return ret;
}

int8_t ZT_HSORAM_fetch(uint32_t lsoram_iid, uint32_t oram_iid, uint8_t oram_type, 
       unsigned char *encrypted_request, uint32_t request_size, 
       unsigned char *encrypted_response, uint32_t response_size, 
       unsigned char* tag_in, unsigned char* tag_out, uint32_t tag_size, 
       unsigned char *client_pubkey, uint32_t pubkey_size_x, uint32_t pubkey_size_y) { 
  sgx_status_t sgx_return; 
  int8_t ret;
  sgx_return = HSORAMFetch(global_eid, &ret, lsoram_iid, oram_iid, oram_type,
               encrypted_request, request_size, encrypted_response, response_size, 
               tag_in, tag_out, tag_size, client_pubkey, 
               pubkey_size_x + pubkey_size_y, pubkey_size_x, pubkey_size_y);
  return ret;
}

int8_t ZT_LSORAM_evict(uint32_t id, unsigned char *key, uint32_t key_size) {
  sgx_status_t sgx_return; 
  int8_t ret;
  sgx_return = LSORAMEvict(global_eid, &ret, id, key, key_size);
  return ret;
}

void ZT_LSORAM_delete(uint32_t id) {
  sgx_status_t sgx_return;
  uint8_t ret;
  sgx_return = deleteLSORAMInstance(global_eid, &ret, id);
}

unsigned char *getOutsidePtr_OCALL() {
  unsigned char *ptr = (unsigned char*) malloc (10);
  memcpy(ptr, "ABCD\n", 6);
  return ptr;
}

void* createLSORAM_OCALL(uint32_t id, uint32_t key_size, uint32_t value_size, uint32_t num_blocks_p, uint8_t oblv_mode) {
  std::vector<tuple*> *LSORAM_store = new std::vector<tuple*>();
  ls_LSORAM.insert(std::make_pair(id, LSORAM_store));

  if(oblv_mode == FULL_OBLV) {
    //Instantiate num_blocks_p blocks;
    for(uint8_t i =0; i<num_blocks_p; i++) {
      tuple *t1 = (tuple *) malloc(sizeof(tuple));
      t1->key = (unsigned char*) malloc (key_size);
      t1->value = (unsigned char*) malloc (value_size);
      LSORAM_store->push_back(t1);
   } 
  } 
  else {
    //In ACCESS_OBLV, no need to instantiate blocks
  } 
  return ((void*) LSORAM_store);
}

void* insertLSORAM_OCALL() {
}


void myprintf(char *buffer, uint32_t buffer_size) {
  char buff_temp[buffer_size];
  sprintf(buff_temp, buffer, buffer_size);
  printf("%s", buff_temp);
}

uint8_t uploadPath_OCALL(uint32_t instance_id, uint8_t oram_type, unsigned char* path_array, uint32_t path_size, uint32_t leaf_label, unsigned char* path_hash, uint32_t path_hash_size, uint8_t level, uint32_t D_level) {
  LocalStorage *ls;
  if(oram_type==0) {
    auto search = ls_PORAM.find(instance_id); 
    if(search != ls_PORAM.end()) {
      ls = search->second;
    }
    ls->uploadPath(leaf_label, path_array, path_hash, level, D_level);
  }
  else if(oram_type==1) {
    auto search = ls_CORAM.find(instance_id); 
    if(search != ls_CORAM.end()) {
      ls = search->second;
    }
    ls->uploadPath(leaf_label, path_array, path_hash, level, D_level);
  }
  return 1;
}

uint8_t uploadBucket_OCALL(uint32_t instance_id, uint8_t oram_type, unsigned char* serialized_bucket, uint32_t bucket_size, uint32_t label, unsigned char* hash, uint32_t hashsize, uint32_t size_for_level, uint8_t recursion_level) {
  LocalStorage *ls;
  if(oram_type==0) {
    auto search = ls_PORAM.find(instance_id); 
    if(search != ls_PORAM.end()) {
      ls = search->second;
      ls->uploadBucket(label, serialized_bucket, size_for_level, hash, hashsize, recursion_level);
    }else{
      //printf("Did NOT find corresponding backend in ls_PORAM\n");
    }

  }
  else if(oram_type==1) {
    auto search = ls_CORAM.find(instance_id); 
    if(search != ls_CORAM.end()) {
      ls = search->second;
    }
    ls->uploadBucket(label, serialized_bucket, size_for_level, hash, hashsize, recursion_level);
   }
  return 1;
}

uint8_t downloadPath_OCALL(uint32_t instance_id, uint8_t oram_type, unsigned char* path_array, uint32_t path_size, uint32_t leaf_label, unsigned char *path_hash, uint32_t path_hash_size, uint8_t level, uint32_t D_level) {	
  LocalStorage *ls;
  if(oram_type==0) {
    auto search = ls_PORAM.find(instance_id); 
    if(search != ls_PORAM.end()) {
      ls = search->second;
    }
    ls->downloadPath(leaf_label, path_array, path_hash, path_hash_size, level, D_level);
   }
  else if(oram_type==1) {
    auto search = ls_CORAM.find(instance_id); 
    if(search != ls_CORAM.end()) {
      ls = search->second;
    }
    ls->downloadPath(leaf_label, path_array, path_hash, path_hash_size, level, D_level);
   }

  return 1;
}

uint8_t downloadBucket_OCALL(uint32_t instance_id, uint8_t oram_type, unsigned char* serialized_bucket, uint32_t bucket_size, uint32_t label, unsigned char* hash, uint32_t hashsize, uint32_t size_for_level, uint8_t recursion_level) {
  LocalStorage *ls;
  if(oram_type==0) {
    auto search = ls_PORAM.find(instance_id); 
    if(search != ls_PORAM.end()) {
      ls = search->second;
    }
    ls->downloadBucket(label, serialized_bucket, size_for_level, hash, hashsize, recursion_level);
   }
  else if(oram_type==1) {
    auto search = ls_CORAM.find(instance_id); 
    if(search != ls_CORAM.end()) {
      ls = search->second;
    }
    ls->downloadBucket(label, serialized_bucket, size_for_level, hash, hashsize, recursion_level);
   }
  return 1;
}

void build_fetchChildHash(uint32_t instance_id, uint8_t oram_type, uint32_t left, uint32_t right, unsigned char* lchild, unsigned char* rchild, uint32_t hash_size, uint32_t recursion_level) {
  LocalStorage *ls;
  if(oram_type==0) {
    auto search = ls_PORAM.find(instance_id); 
    if(search != ls_PORAM.end()) {
      ls = search->second;
    }
    ls->fetchHash(left, lchild, hash_size, recursion_level);
    ls->fetchHash(right, rchild, hash_size, recursion_level);
   }
  else if(oram_type==1) {
    auto search = ls_CORAM.find(instance_id); 
    if(search != ls_CORAM.end()) {
      ls = search->second;
    }
    ls->fetchHash(left,lchild,hash_size, recursion_level);
    ls->fetchHash(right,rchild,hash_size, recursion_level);
   }
}

uint8_t computeRecursionLevels(uint32_t max_blocks, uint32_t recursion_data_size, uint64_t onchip_posmap_memory_limit) {
  uint8_t recursion_levels = 1;
  uint8_t x;
    
  if(recursion_data_size!=0) {		
    recursion_levels = 1;
    x = recursion_data_size / sizeof(uint32_t);
    uint64_t size_pmap0 = max_blocks * sizeof(uint32_t);
    uint64_t cur_pmap0_blocks = max_blocks;

    while(size_pmap0 > onchip_posmap_memory_limit) {
      cur_pmap0_blocks = (uint64_t) ceil((double)cur_pmap0_blocks/(double)x);
      recursion_levels++;
      size_pmap0 = cur_pmap0_blocks * sizeof(uint32_t);
    }

    #ifdef RECURSION_LEVELS_DEBUG
     printf("IN App: max_blocks = %d\n", max_blocks);
     printf("Recursion Levels : %d\n",recursion_levels);
    #endif
  }
  return recursion_levels;
}

#ifdef DETAILED_MICROBENCHMARKER

  void setMicrobenchmarkerParams(uint8_t oram_type, uint32_t num_requests) {
     DET_MB_PARAMS.oram_type = oram_type;
     DET_MB_PARAMS.num_requests = num_requests;
     DET_MB_PARAMS.on = false;
  }

  void initializeMicrobenchmarker() {
   DET_MB_PARAMS.on = false;
   uint8_t recursion_levels = DET_MB_PARAMS.recursion_levels;
   uint32_t num_reqs = DET_MB_PARAMS.num_requests; 

   
  }

  void initiateMicrobenchmarker(det_mb ***TC_MB) {
    DET_MB_PARAMS.on = true;
    MB=TC_MB;
  }

  uint8_t getRecursionLevels() {
    return(DET_MB_PARAMS.recursion_levels);
  }

#endif

void time_report(int report_type, uint8_t level) {
  //Compute based on report_type and update MB.

  clockid_t clk_id = CLOCK_PROCESS_CPUTIME_ID;
  static struct timespec start, end;
  
  #ifdef DETAILED_MICROBENCHMARKER
    if(DET_MB_PARAMS.on == true) {

      if(DET_MB_PARAMS.oram_type==0) {
        //PathORAM part
        if(report_type==PO_POSMAP_START) {
          clock_gettime(clk_id, &start); 
        }
   
        if(report_type==PO_POSMAP_END) {
          clock_gettime(clk_id, &end); 
          double posmap_time = timetaken(&start, &end);
          det_mb *ptr = MB[req_counter][0];
          ptr->posmap_time = posmap_time;
        } 

        if(report_type==PO_DOWNLOAD_PATH_START) {
          clock_gettime(clk_id, &start); 
        } 

        if(report_type==PO_DOWNLOAD_PATH_END) {
          clock_gettime(clk_id, &end); 
          double dp_time = timetaken(&start, &end);
          det_mb *ptr = MB[req_counter][level];
          ptr->download_path_time = dp_time;
        }

        if(report_type==PO_FETCH_BLOCK_START) {
          clock_gettime(clk_id, &start); 
        } 

        if(report_type==PO_FETCH_BLOCK_END) {
          clock_gettime(clk_id, &end); 
          double fb_time = timetaken(&start, &end);
          det_mb *ptr = MB[req_counter][level];
          ptr->fetch_block_time = fb_time;
        }

        if(report_type==PO_EVICTION_START) {
          clock_gettime(clk_id, &start); 
        } 

        if(report_type==PO_EVICTION_END) {
          clock_gettime(clk_id, &end); 
          double el_time = timetaken(&start, &end);
          det_mb *ptr = MB[req_counter][level];
          ptr->eviction_time = el_time;
        }

        if(report_type==PO_UPLOAD_PATH_START) {
          clock_gettime(clk_id, &start); 
        } 

        if(report_type==PO_UPLOAD_PATH_END) {
          clock_gettime(clk_id, &end); 
          double up_time = timetaken(&start, &end);
          det_mb *ptr = MB[req_counter][level];
          ptr->upload_path_time = up_time;
        }
   
      }
      else if(DET_MB_PARAMS.oram_type==1) {
        //CircuitORAM part

        if(report_type==CO_POSMAP_START) {
          clock_gettime(clk_id, &start); 
        }
   
        if(report_type==CO_POSMAP_END) {
          clock_gettime(clk_id, &end); 
          double posmap_time = timetaken(&start, &end);
          det_mb *ptr = MB[req_counter][0];
          ptr->posmap_time = posmap_time;
        } 

        if(report_type==CO_DOWNLOAD_PATH_START) {
          clock_gettime(clk_id, &start); 
        } 

        if(report_type==CO_DOWNLOAD_PATH_END) {
          clock_gettime(clk_id, &end); 
          double dp_time = timetaken(&start, &end);
          //printf("Download Time = %f, %d", dp_time, level);
          det_mb *ptr = MB[req_counter][level];
          ptr->download_path_time = dp_time;
        }

        if(report_type==CO_FETCH_BLOCK_START) {
          clock_gettime(clk_id, &start); 
        } 

        if(report_type==CO_FETCH_BLOCK_END) {
          clock_gettime(clk_id, &end); 
          double fb_time = timetaken(&start, &end);
          det_mb *ptr = MB[req_counter][level];
          ptr->fetch_block_time = fb_time;
        }

        if(report_type==CO_UPLOAD_PATH_START) {
          clock_gettime(clk_id, &start); 
        } 

        if(report_type==CO_UPLOAD_PATH_END) {
          clock_gettime(clk_id, &end); 
          double up_time = timetaken(&start, &end);
          //printf("Upload Time = %f\n", up_time);
          det_mb *ptr = MB[req_counter][level];
          ptr->upload_path_time = up_time;
        }

        if(report_type==CO_EVICTION_START) {
          clock_gettime(clk_id, &start); 
        } 

        if(report_type==CO_EVICTION_END) {
          clock_gettime(clk_id, &end); 
          double el_time = timetaken(&start, &end);
          det_mb *ptr = MB[req_counter][level];
          ptr->eviction_time = el_time;
        }

      }
    }
  #endif
}


int8_t ZT_Initialize(unsigned char *bin_x, unsigned char* bin_y, 
       unsigned char *bin_r, unsigned char* bin_s, uint32_t buff_size) {
  
  int8_t ret;

  // Initialize the enclave 
  if(initialize_enclave() < 0) {
    printf("Enter a character before exit ...\n");
    getchar();
    return -1; 
  }

  // Utilize edger8r attributes
  edger8r_array_attributes();
  edger8r_pointer_attributes();
  edger8r_type_attributes();
  edger8r_function_attributes();

  // Utilize trusted libraries 
  ecall_libc_functions();
  ecall_libcxx_functions();
  ecall_thread_functions();

  // Extract Public Key and send it over 
  InitializeKeys(global_eid, &ret, bin_x, bin_y, bin_r, bin_s, buff_size);
  return ret;
}

void ZT_Close() {
        sgx_destroy_enclave(global_eid);
}

uint32_t ZT_New( uint32_t max_blocks, uint32_t data_size, uint32_t stash_size, uint32_t oblivious_flag, uint32_t recursion_data_size, uint32_t oram_type, uint8_t pZ) {
  sgx_status_t sgx_return = SGX_SUCCESS;
  int8_t rt;
  uint8_t urt;
  uint32_t instance_id;
  int8_t recursion_levels;
  LocalStorage *ls_oram = new LocalStorage();    

  // RecursionLevels is really number of levels of ORAM
  // So if no recursion, recursion_levels = 1 
  recursion_levels = computeRecursionLevels(max_blocks, recursion_data_size, MEM_POSMAP_LIMIT);
  printf("APP.cpp : ComputedRecursionLevels = %d", recursion_levels);
    
  uint32_t D = (uint32_t) ceil(log((double)max_blocks/pZ)/log((double)2));
  printf("App.cpp: Parmas for LS : \n \(%d, %d, %d, %d, %d, %d, %d, %d)\n",
         max_blocks,D,pZ,stash_size,data_size + ADDITIONAL_METADATA_SIZE,inmem_flag, recursion_data_size + ADDITIONAL_METADATA_SIZE, recursion_levels);
  
  // LocalStorage Module, just works with recursion_levels 0 to recursion_levels 
  // And functions without treating recursive and non-recursive backends differently
  // Hence recursion_levels passed = recursion_levels,

  ls_oram->setParams(max_blocks,D,pZ,stash_size,data_size + ADDITIONAL_METADATA_SIZE,inmem_flag, recursion_data_size + ADDITIONAL_METADATA_SIZE, recursion_levels);

  #ifdef DETAILED_MICROBENCHMARKER  
   printf("DET_MB_PARAMS.recursion_levels = %d\n", recursion_levels);
   DET_MB_PARAMS.recursion_levels = recursion_levels; 
   // Spawn required variables for microbenchmarker
   initializeMicrobenchmarker();
   // Client flags the DET_MB_PARAMS, by setting a bool ON to start
   // the detailed microbenchmarking 
  #endif
 
  #ifdef EXITLESS_MODE
    int rc;
    pthread_t thread_hreq;
    req_struct.id = (uint32_t*) malloc (4);
    req_struct.level = (uint32_t*) malloc(4);
    req_struct.d_lev = (uint32_t*) malloc(4);
    req_struct.recursion = (bool *) malloc(1);
    req_struct.block = (bool *) malloc(1);

    resp_struct.path = (unsigned char*) malloc(PATH_SIZE_LIMIT);
    resp_struct.path_hash = (unsigned char*) malloc (PATH_SIZE_LIMIT);
    resp_struct.new_path = (unsigned char*) malloc (PATH_SIZE_LIMIT);
    resp_struct.new_path_hash = (unsigned char*) malloc (PATH_SIZE_LIMIT);
    td.req = &req_struct;
    td.resp = &resp_struct;

    *(req_struct.block) = true;
    *(req_struct.id) = 7;

    rc = pthread_create(&thread_hreq, NULL, HandleRequest, (void *)&td);
    if (rc) {
        std::cout << "Error:unable to create thread," << rc << std::endl;
        exit(-1);
    }
  #else

    sgx_return = getNewORAMInstanceID(global_eid, &instance_id, oram_type);
    printf("INSTANCE_ID returned = %d\n", instance_id);  

    if(oram_type==0){
      ls_PORAM.insert(std::make_pair(instance_id, ls_oram));
      printf("Inserted instance_id = %d into ls_PORAM\n", instance_id);
    }
    else if(oram_type==1) {
      ls_CORAM.insert(std::make_pair(instance_id, ls_oram));
      printf("Inserted instance_id = %d into ls_CORAM\n", instance_id);
    }

    uint8_t ret;
    sgx_return = createNewORAMInstance(global_eid, &ret, instance_id, max_blocks, data_size, stash_size, oblivious_flag, recursion_data_size, recursion_levels, oram_type, pZ);
    

  #endif

  #ifdef DEBUG_PRINT
      printf("initialize_oram Successful\n");
  #endif
  return (instance_id);
}


void ZT_Access(uint32_t instance_id, uint8_t oram_type, unsigned char *encrypted_request, unsigned char *encrypted_response, unsigned char *tag_in, unsigned char* tag_out, uint32_t request_size, uint32_t response_size, uint32_t tag_size) {

  #ifdef DETAILED_MICROBENCHMARKER
    static struct timespec start, end;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
  #endif

    accessInterface(global_eid, instance_id, oram_type, encrypted_request, encrypted_response, tag_in, tag_out, request_size, response_size, tag_size);
  
  #ifdef DETAILED_MICROBENCHMARKER
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);
    double total_time = timetaken(&start, &end);

    if(DET_MB_PARAMS.on == true) {
      MB[req_counter][0]->total_time=total_time;
      req_counter++; 
        if(DET_MB_PARAMS.num_requests==req_counter) { 
          req_counter=0;
          DET_MB_PARAMS.on = false;
        }
    }
  #endif
 
}

void ZT_Bulk_Read(uint32_t instance_id, uint8_t oram_type, uint32_t no_of_requests, unsigned char *encrypted_request, unsigned char *encrypted_response, unsigned char *tag_in, unsigned char* tag_out, uint32_t request_size, uint32_t response_size, uint32_t tag_size) {
    accessBulkReadInterface(global_eid, instance_id, oram_type, no_of_requests, encrypted_request, encrypted_response, tag_in, tag_out, request_size, response_size, tag_size);
}

/*
  uint32_t posmap_size = 4 * max_blocks;
  uint32_t stash_size =  (stashSize+1) * (dataSize_p+8);

*/

/*
if(resume_experiment) {
    
    //Determine if experiment is recursive , and setup parameters accordingly
    if(recursion_data_size!=0) {	
      uint32_t *posmap = (uint32_t*) malloc (MEM_POSMAP_LIMIT*16*4);
      unsigned char *merkle =(unsigned char*) malloc(hash_size + aes_key_size);
      ls.restoreMerkle(merkle,hash_size + aes_key_size);				
      ls.restorePosmap(posmap, MEM_POSMAP_LIMIT*16);
      //Print and test Posmap HERE
      
      //TODO : Fix restoreMerkle and restorePosmap in Enclave :
      //sgx_return = restoreEnclavePosmap(posmap,);			
      for(uint8_t k = 1; k <=recursion_levels_e;k++) {
        uint32_t stash_size;
        unsigned char* stash = (unsigned char*) malloc (stash_size);
        //ls.restoreStash();	
        //TODO: Fix restore Stash in Enclave				
        //sgx_return = frestoreEnclaveStashLevel();
        free(stash);						
      }
      
      free(posmap);	
      free(merkle);
      
    }
    else {
    uint32_t current_stashSize = 0;
    uint32_t *posmap = (uint32_t*) malloc (posmap_size);
    uint32_t *stash = (uint32_t*) malloc(4 * 2 * stashSize);
    unsigned char *merkle =(unsigned char*) malloc(hash_size);
    ls.restoreState(posmap, max_blocks, stash, &current_stashSize, merkle, hash_size+aes_key_size);		
    //sgx_return = restore_enclave_state(global_eid, &rt32, max_blocks, dataSize_p, posmap, posmap_size, stash, current_stashSize * 8, merkle, hash_size+aes_key_size);
    //printf("Restore done\n");
    free(posmap);
    free(stash);
    free(merkle);
    }
  }
*/
