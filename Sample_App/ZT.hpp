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


#ifdef DETAILED_MICROBENCHMARKER
  void initiateMicrobenchmarker(det_mb ***MB);
  uint8_t getRecursionLevels();
  void setMicrobenchmarkerParams(uint8_t oram_type, uint32_t request_length);
#endif

int8_t ZT_Initialize(unsigned char *bin_x, unsigned char *bin_y, unsigned char *bin_r, unsigned char *bin_s, uint32_t buff_size);
void ZT_Close();
uint32_t ZT_New( uint32_t max_blocks, uint32_t data_size, uint32_t stash_size, uint32_t oblivious_flag, uint32_t recursion_data_size, uint32_t oram_type, uint8_t pZ);
uint32_t ZT_New_LSORAM( uint32_t num_blocks, uint32_t key_size, uint32_t value_size, uint8_t mode, uint8_t oblivious_type, uint8_t populate_flag);
 

void ZT_Access(uint32_t instance_id, uint8_t oram_type, unsigned char *encrypted_request, unsigned char *encrypted_response, unsigned char *tag_in, unsigned char* tag_out, uint32_t request_size, uint32_t response_size, uint32_t tag_size);
void ZT_Bulk_Read(uint32_t instance_id, uint8_t oram_type, uint32_t bulk_batch_size, unsigned char *encrypted_request, unsigned char *encrypted_response, unsigned char *tag_in, unsigned char* tag_out, uint32_t request_size, uint32_t response_size, uint32_t tag_size);

//LSORAM Access-oblivious API 

int8_t ZT_LSORAM_insert(uint32_t instance_id, unsigned char *encrypted_request, uint32_t request_size, 
       unsigned char* tag_in, uint32_t tag_size, unsigned char *client_pubkey, uint32_t pubkey_size_x,
       uint32_t pubkey_size_y);

int8_t ZT_LSORAM_fetch(uint32_t instance_id, unsigned char *encrypted_request,
       uint32_t request_size, unsigned char *encrypted_response, 
       uint32_t response_size, unsigned char* tag_in, unsigned char* tag_out, 
       uint32_t tag_size, unsigned char *client_pubkey, uint32_t pubkey_size_x,
       uint32_t pubkey_size_y); 


int8_t ZT_HSORAM_insert(uint32_t lsoram_iid, uint32_t oram_iid, uint8_t oram_type, 
       uint64_t oram_index, unsigned char *encrypted_request, uint32_t request_size, 
       unsigned char* tag_in, uint32_t tag_size, unsigned char *client_pubkey, 
       uint32_t pubkey_size_x, uint32_t pubkey_size_y);

int8_t ZT_LSORAM_oprm_insert_pt(uint32_t instance_id, unsigned char *key_l, 
       uint32_t key_size, unsigned char *value_l, uint32_t value_size);

int8_t ZT_LSORAM_iprm_insert_pt(uint32_t instance_id, unsigned char *key_l, 
       uint32_t key_size, unsigned char *value_l, uint32_t value_size);

int8_t ZT_HSORAM_fetch(uint32_t lsoram_iid, uint32_t oram_iid, uint8_t oram_type,
       unsigned char *encrypted_request, uint32_t request_size, 
       unsigned char *encrypted_response, uint32_t response_size, 
       unsigned char* tag_in, unsigned char* tag_out, uint32_t tag_size, 
       unsigned char *client_pubkey, uint32_t pubkey_size_x,
       uint32_t pubkey_size_y); 

int8_t ZT_LSORAM_evict(uint32_t id, unsigned char *key, uint32_t key_size);
void ZT_LSORAM_delete(uint32_t id);

//LSORAM Full-olivious API
//void ZT_LSORAM_Access();

