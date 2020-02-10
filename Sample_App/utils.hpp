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

#ifndef __ZT_utils__

  #include "../Globals.hpp"
  #include "../CONFIG.h"
  #include "../CONFIG_FLAGS.h"
  #include <stdint.h>
  #include <stdio.h>
  #include <stdlib.h>
  #include <iostream>
  #include <string.h>
  #include <random>
  #include <math.h>
  #include "ZT.hpp"
  #include <openssl/ec.h>
  #include <openssl/ecdh.h>
  #include <openssl/ecdsa.h>
  #include <openssl/conf.h>
  #include <openssl/evp.h>
  #include <openssl/err.h>
  #include <openssl/obj_mac.h>

  class RandomRequestSource
  {
  public:
    RandomRequestSource(){};
    // Generates a random sequence of <length> elements, where each element in 
    // [0, <max_capacity-1>]
    uint32_t* GenerateRandomSequence(uint32_t length, uint32_t max_capacity);

    // Generates RandomPermutation of length elements, such that all <length> 
    // elements are unique and from [0, <length>-1]
    uint32_t* GenerateRandomPermutation(uint32_t length);
  };

  //Time Functions
    double time_taken(timespec *start, timespec *end);

  //Buffer size compute Functions:
    uint32_t computeCiphertextSize(uint32_t data_size);
    uint32_t computeBulkRequestsCiphertextSize(uint32_t bulk_batch_size);

  //Buffer-handling/Serialize Functions
    void serializeRequest(uint32_t request_id, char op_type, unsigned char *data,
         uint32_t data_size, unsigned char* serialized_request);
    int32_t serializeLSORAMRequest(unsigned char *key, uint32_t key_size, 
             unsigned char *value, uint32_t value_size, unsigned char **serialized_request);
    void prepareDataBlock(unsigned char *datablock, uint32_t index, uint32_t data_size);
    int checkFetchedDataBlock(unsigned char *datablock, uint32_t index, uint32_t data_size);

  //Crypto Functions
    int AES_GCM_128_encrypt (unsigned char *plaintext, int plaintext_len, unsigned char *aad,
        int aad_len, unsigned char *key, unsigned char *iv, int iv_len,
        unsigned char *ciphertext, unsigned char *tag);
    int AES_GCM_128_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
        int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
        int iv_len, unsigned char *plaintext);
    int encryptRequest(int request_id, char op_type, unsigned char *data, uint32_t data_size, 
        unsigned char *encrypted_request, unsigned char *tag, uint32_t request_size);
    int encryptBulkReadRequest(uint32_t *rs, uint32_t req_counter, uint32_t bulk_batch_size, 
        unsigned char *encrypted_request, unsigned char *tag, uint32_t request_size, 
        unsigned char *iv, unsigned char** serialized_client_public_key );
    int encryptBulkReadRequest(uint32_t *rs, uint32_t req_counter, uint32_t bulk_batch_size, 
        unsigned char *encrypted_request, unsigned char *tag, uint32_t request_size);
    void decryptBulkReadRequest(uint32_t bulk_batch_size, unsigned char *encrypted_request, 
         unsigned char *tag, uint32_t request_size);
    void decryptRequest(unsigned char *encrypted_request, unsigned char *tag, uint32_t request_size);
    int extractResponse(unsigned char *encrypted_response, unsigned char *tag, int response_size, 
        unsigned char *data_out);
    int extractBulkResponse(unsigned char *encrypted_response, unsigned char *tag, 
        int response_size, unsigned char *data_out);

    //LSORAM:
    int encryptLSORAMRequest(EC_KEY* target_public_key, unsigned char *serialized_request,
       uint32_t request_size, unsigned char **encrypted_request, unsigned char **client_pubkey,
       uint32_t *pubkey_size_x, uint32_t *pubkey_size_y,  unsigned char **aes_key, 
       unsigned char **iv, unsigned char **tag);
    int decryptLSORAMResponse(unsigned char *encrypted_response, uint32_t response_size, 
      unsigned char *tag, unsigned char *aes_key, unsigned char *iv, unsigned char **response);

    //Timing and other functions
    double compute_avg(double *elements, uint32_t num_elements);
    double compute_stddev(double *elements, uint32_t num_elements);

  #define __ZT_utils__
#endif
