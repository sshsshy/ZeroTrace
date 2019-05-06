
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

#ifndef __ZT_ENCLAVE_UTILS__
  #include "Globals_Enclave.hpp"
  #include "oasm_lib.h" 

  void oarray_search(uint32_t *array, uint32_t loc, uint32_t *leaf, uint32_t newLabel,uint32_t N_level);

  void displayKey(unsigned char *key, uint32_t key_size);

  void serializeECCKeys(sgx_ec256_private_t *ZT_private_key, sgx_ec256_public_t *ZT_public_key, unsigned char *serialized_keys);

  void enclave_sha256(char * string, uint32_t str_len);

  void SerializeBNPair(BIGNUM *x, BIGNUM *y, unsigned char **bin_x, unsigned char **bin_y);
  
  #define __ZT_ENCLAVE_UTILS__

#endif
