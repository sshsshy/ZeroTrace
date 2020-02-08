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
#include "utils.hpp"
#include "ZT.hpp"
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>


EC_KEY *ENCLAVE_PUBLIC_KEY = NULL;
unsigned char *enclave_public_key;

//TODO: Cleanse list of global variables

uint32_t NUM_EXPECTED_PARAMS = 8;
bool RESUME_EXPERIMENT;
uint32_t DATA_SIZE;
uint32_t MAX_BLOCKS;
int REQUEST_LENGTH;
uint32_t STASH_SIZE;
uint32_t OBLIVIOUS_FLAG = 0;
uint32_t RECURSION_DATA_SIZE = 0;
uint32_t ORAM_TYPE = 0;

unsigned char *encrypted_request, *tag_in, *encrypted_response, *tag_out;
uint32_t request_size, response_size;
unsigned char *data_in;
unsigned char *data_out;
uint32_t bulk_batch_size=0;
std::string log_file;

uint8_t Z;
FILE *iquery_file; 

uint32_t oram_index =0;

int32_t min_expected_no_of_parameters = 8;
uint32_t NUM_BLOCKS;
int requestlength;
uint32_t data_size;
uint32_t key_size;
uint32_t value_size;
uint8_t store_mode;
uint8_t oblivious_mode;
std::string logfile;


clock_t generate_request_start, generate_request_stop, extract_response_start,
        extract_response_stop, process_request_start, process_request_stop, 
        generate_request_time, extract_response_time, process_request_time;

clock_t inserts_start, inserts_stop, inserts_time, insert_time;
clock_t fetches_start, fetches_stop, fetches_time, fetch_time;

