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

#include "../Globals.hpp"
#include "../CONFIG.h"
#include "../CONFIG_FLAGS.h"
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string.h>
#include <cstdint>
#include <random>
#include "ZT.hpp"
#include "utils.hpp"
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>

EC_KEY *ENCLAVE_PUBLIC_KEY = NULL;
unsigned char *enclave_public_key;

#define NUM_TESTS_PER_ORAM_TYPE 3

//Parameters to fix for each Experiment in Test module
uint32_t DATA_SIZE;
uint32_t MAX_BLOCKS;
uint32_t REQUEST_LENGTH;
uint32_t STASH_SIZE;
uint32_t OBLIVIOUS_FLAG = 0;
uint32_t RECURSION_DATA_SIZE = 0;
uint32_t ORAM_TYPE = 0;
uint8_t Z;

typedef struct experiment_parameters{
  uint32_t data_size;
  uint32_t max_blocks;
  uint32_t request_length;
  uint32_t stash_size;
  uint32_t oblivious_flag;
  uint32_t recursion_data_size;
  uint8_t oram_type;
  uint8_t Z;
}exp_params;
