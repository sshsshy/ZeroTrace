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

#include "LinearScan_ORAM.hpp"

LinearScan_ORAM::LinearScan_ORAM(uint32_t instance_id, uint32_t key_size_p, 
               uint32_t value_size_p, uint32_t num_blocks_p, uint8_t mode_p, 
               uint8_t oblv_mode, uint8_t dummy_populate=true) {

  sgx_status_t ret = SGX_SUCCESS;
  // TODO: For convenience round up key_size and value_size to next int div by 8
  // (For assembly functions to not cause any irregularities)
  key_size = ceil(float(key_size_p)/8) * 8;
  value_size = ceil(float(value_size_p)/8) * 8;
  num_blocks = num_blocks_p;

  //Define Enumerates for these 2
  mem_mode = mode_p;
  oblivious_mode = oblv_mode;

  switch(mem_mode){
    case INSIDE_PRM: {
      LSORAM_store = new std::vector<tuple *>();
      if(oblv_mode == FULL_OBLV){
        // Instantiate num_blocks_p
        // populateDummyElements();
      } 
      
      // Do nothing is ACCESS_OBLV 

      break;
    }

    case OUTSIDE_PRM:{
      //Invoke untrusted function to create a vector and return pointer to vector
      ret = createLSORAM_OCALL((void **) &LSORAM_store, instance_id, key_size, value_size, num_blocks, oblivious_mode);
      if(oblv_mode == FULL_OBLV){
        //Instantiate num_blocks_p ( would be done by createLSORAM_OCALL)
        //populateDummyElements
      }     
      break;
    }
  }

  if(dummy_populate) {
    populateDummyElements();
  } 
}


//Fill all value blurbs with ['AB..Z']*
void LinearScan_ORAM::populateDummyElements() {
  
}

//Test key doesn't already exist, sizes of key and value < key_size, value_size
// if current size = num_blocks, realloc and update num_blocks (by doubling current size?)
int8_t LinearScan_ORAM::insert(unsigned char* key, uint32_t key_size_p, unsigned char* value, uint32_t value_size_p) {

  // local copies/ptrs to key and value
  // used to pad key/value if below LSORAM key_size or value_siz
  unsigned char *key_l = key, *value_l = value;

  if(key_size_p>key_size||value_size_p>value_size){
    printf("Key or value size > declared size of LSORAM\n");
    return -1;
  } else if(key_size_p < key_size) {
    // reintance new buffer for key with key_size, 
    // copy obtained key and pad with 0x00s
    key_l = (unsigned char*) malloc (key_size);
    memcpy(key_l, key, key_size_p);
    for(uint8_t i = key_size_p; i<key_size; i++) {
      key_l[i]=0x00;
    }
  } else if(value_size_p < value_size) {
    // reintance new buffer for key with key_size, 
    // copy obtained key and pad with 0x00s
    value_l = (unsigned char*) malloc (value_size);
    memcpy(value_l, value, value_size_p);
    for(uint8_t i = value_size_p; i<value_size; i++) {
      value_l[i]=0x00;
    }
  }
   

  if(oblivious_mode==ACCESS_OBLV){
    //TODO: Prevent double inserts
    tuple *t = (tuple *) malloc(sizeof(tuple));
    t->key = (unsigned char*) malloc (key_size);
    t->value = (unsigned char*) malloc (value_size);
    memcpy(t->key, key_l, key_size);
    memcpy(t->value, value_l, value_size);
    LSORAM_store->push_back(t);
    printf("<%s,%s>", t->key, t->value);
  }
  else{
    //insertLSORAM_OCALL();      
    //Linear scan across all tuples and insert at first free one.
  }

  return 1;
}

//Test key exists
// The value buffer is passed from outside the enclave, and the LS-ORAM
// populates and sends it back.
int8_t LinearScan_ORAM::fetch(unsigned char* key, uint32_t key_size_p, unsigned char *value, uint32_t value_size_p){ 

  unsigned char *key_l;
  if(key_size_p>key_size||value_size_p>value_size){
    printf("Key or value size > declared size of LSORAM\n");
    return -1;
  } else if(key_size_p < key_size) {
    // reintance new buffer for key with key_size, 
    // copy obtained key and pad with 0x00s
    key_l = (unsigned char*) malloc (key_size);
    memcpy(key_l, key, key_size_p);
    for(uint8_t i = key_size_p; i<key_size; i++) {
      key_l[i]=0x00;
    }
  } 

  uint32_t flag=0;
  uint8_t ctr = 0;

  printf("Before vector iterator loop \n"); 
  for(std::vector<tuple*>::iterator it = LSORAM_store->begin(); it!=LSORAM_store->end(); ++it) { 
    ocomp_set_flag(key_l, (*it)->key, key_size, &flag);
    printf("After index %d, key was: %s, flag = %d\n" , ctr, (*it)->key,flag);

    omove_buffer(value, (*it)->value, value_size, flag);      
    //printf("<%s,%s>\n", (*it)->key, (*it)->value);
    //Perform oblivious pass over iterator->key and key, and then iterator->value and value
  }

  return 1;
}

// Removes element by adding index to empty_slots
// Test key does exist, 
int8_t LinearScan_ORAM::evict(unsigned char* key, uint32_t key_size_p){
  unsigned char *key_l;
  if(key_size_p>key_size){
    printf("Key or value size > declared size of LSORAM\n");
    return -1;
  } else if(key_size_p < key_size) {
    // reintance new buffer for key with key_size, 
    // copy obtained key and pad with 0x00s
    key_l = (unsigned char*) malloc (key_size);
    memcpy(key_l, key, key_size_p);
    for(uint8_t i = key_size_p; i<key_size; i++) {
      key_l[i]=0x00;
    }
  } 

  int32_t cmp_result;
  for(std::vector<tuple*>::iterator it = LSORAM_store->begin(); it!=LSORAM_store->end(); ++it) { 
    cmp_result = memcmp(key_l, (*it)->key, key_size);
    if(cmp_result==0){
      free((*it)->key);
      free((*it)->value);
      LSORAM_store->erase(it);
      return 1;
    }
    //printf("<%s,%s>\n", (*it)->key, (*it)->value);
    //Perform oblivious pass over iterator->key and key, and then iterator->value and value
  }

  return -1;
}


LinearScan_ORAM::~LinearScan_ORAM() {
  std::vector<tuple*>::iterator trail_ptr = LSORAM_store->begin();
  for(std::vector<tuple*>::iterator it = LSORAM_store->begin(); it!=LSORAM_store->end(); ++it) { 
    free((*it)->key);
    free((*it)->value);
    free((*it));
    trail_ptr++;
  }
  LSORAM_store->clear();
}
