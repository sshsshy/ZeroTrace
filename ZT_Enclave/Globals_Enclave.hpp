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

#ifndef __ZT_GLOBALS_ENCLAVE__
  #define __ZT_GLOBALS_ENCLAVE__
  #include "../Globals.hpp"
  #include "../CONFIG.h"
  #include "../CONFIG_FLAGS.h"
  #include <string.h>
  #include "ORAM_Interface.hpp"
  #include <stdarg.h>
  #include <stdio.h>      /* vsnprintf */
  #include "Enclave_t.h"  /* print_string */
  #include <stdlib.h>
  #include <stdio.h>
  #include <stdint.h>
  #include <math.h>
  #include <sgx_tcrypto.h>
  #include "sgx_trts.h"
  #include <openssl/ec.h>
  #include <assert.h>

  static bool PK_in_memory = false;
  static sgx_ec256_private_t ZT_private_key;
        static sgx_ec256_public_t ZT_public_key;
  static EC_KEY* sgx_EC_key_pair;

  static sgx_ec256_private_t private_signing_key;


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

  struct nodev2{
    unsigned char *serialized_block;
    struct nodev2 *next;
  };

  //TODO : Do we need this ?
  struct request_parameters{
      char opType;
      uint32_t id;
      uint32_t position_in_id;
      uint32_t level;
  };

  //Hard-coded Enclave Signing key
  //This key would ideally be sampled and signed in the Remote attestation phase with a client
  //Currently we use a static hard coded ECDSA key for it.

  static unsigned char hardcoded_signing_key[SGX_ECP256_KEY_SIZE] = 
  //ORIGINAL
  {0xaf, 0x6b, 0xe1, 0x99, 0x99, 0x63, 0xd8, 0xae,
   0x7b, 0x66, 0x27, 0x86, 0xe5, 0xb5, 0x45, 0x4b, 
   0xb7, 0x3b, 0xf1, 0xbb, 0x22, 0x58, 0xca, 0xf2, 
   0xda, 0x55, 0x1d, 0x79, 0xd6, 0x34, 0x4c, 0x09};


  void printf(const char *fmt, ...);

  void displaySerializedBlock( unsigned char *serialized_result_block, uint32_t level, uint32_t recursion_levels, uint32_t x);

  void aes_dec_serialized(unsigned char* encrypted_block, uint32_t data_size, unsigned char *decrypted_block, unsigned char* aes_key);
  void aes_enc_serialized(unsigned char* decrypted_block, uint32_t data_size, unsigned char *encrypted_block, unsigned char* aes_key);
#endif
