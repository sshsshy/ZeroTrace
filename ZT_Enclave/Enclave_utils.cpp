
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

#include "Enclave_utils.hpp"

void oarray_search(uint32_t *array, uint32_t loc, uint32_t *leaf, uint32_t newLabel,uint32_t N_level) {
  for(uint32_t i=0;i<N_level;i++) {
    omove(i,&(array[i]),loc,leaf,newLabel);
  }
  return;
}

void displayKey(unsigned char *key, uint32_t key_size){
  printf("<");
  for(int t=0; t<key_size; t++) {
    char pc = 'A' + (key[t] % 26);
    printf("%c", pc); 
  }
  printf(">\n");
}

void serializeECCKeys(sgx_ec256_private_t *ZT_private_key, sgx_ec256_public_t *ZT_public_key, unsigned char *serialized_keys) {
  //Memcpy bytewise all three pieces of the keys into serialized_keys
  unsigned char *serialized_keys_ptr = serialized_keys;	
  memcpy(serialized_keys_ptr, ZT_private_key->r, SGX_ECP256_KEY_SIZE);
  serialized_keys_ptr+=SGX_ECP256_KEY_SIZE;
  memcpy(serialized_keys_ptr, ZT_public_key->gx, SGX_ECP256_KEY_SIZE);
  serialized_keys_ptr+=SGX_ECP256_KEY_SIZE;
  memcpy(serialized_keys_ptr, ZT_public_key->gy, SGX_ECP256_KEY_SIZE);
}

void enclave_sha256(char * string, uint32_t str_len){
  sgx_status_t ret = SGX_SUCCESS;
  sgx_sha256_hash_t p_hash;
  sgx_sha256_msg((const uint8_t*) string, str_len, &p_hash);
  printf("SHA256 Output Enclave: \n");
  for(int i = 0; i < SGX_SHA256_HASH_SIZE ; i++) {
    printf("%02x ", p_hash[i]);
  }
  printf("\n");
}

void SerializeBNPair(BIGNUM *x, BIGNUM *y, unsigned char **bin_x, unsigned char **bin_y){
  uint32_t size_bin_x = BN_num_bytes(x);
  uint32_t size_bin_y = BN_num_bytes(y);
  *bin_x = (unsigned char*) malloc(size_bin_x);
  *bin_y = (unsigned char*) malloc(size_bin_y);
  BN_bn2bin(x, *bin_x);
  BN_bn2bin(y, *bin_y);  
}

