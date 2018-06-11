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
	#include "Block.hpp"
	#include "oasm_lib.h"
	#include "../Globals.hpp"
	#include <assert.h>

	// define FLAGS :
	#define ENCRYPTION_ON 1
	#define PATH_GRANULAR_IO 1
	#define TIME_PERFORMANCE 1
	#define DEBUG_ZT_ENCLAVE 1
	#define SET_PARAMETERS_DEBUG 1
	//#define BUILDTREE_DEBUG 1
	//#define PATHORAM_ACCESS_REBUILD_DEBUG 1
	//#define PATHORAM_STASH_OVERFLOW_DEBUG 1
	//#define ACCESS_DEBUG 1
	//#define SHOW_STASH_COUNT_DEBUG 1 

	//#define AES_NI 1
	//#define RAND_DATA 1
	//#define SET_PARAMETERS_DEBUG 1
	//#define BUILDTREE_VERIFICATION_DEBUG 1
	//#define SHOW_STASH_CONTENTS 1

	//#define ACCESS_DEBUG 1
	//#define ACCESS_CORAM_DEBUG 1
	//#define ACCESS_CORAM_META_DEBUG 1
	//#define ACCESS_CORAM_DEBUG3 1
	//#define ACCCES_DEBUG_EXITLESS 1
	//#define ACCESS_DEBUG_REBUILD 1 
	//#define EXITLESS_MODE 1
	//#define PASSIVE_ADVERSARY 1
	//#define DEBUG_EFO 1
	//#define DEBUG_INTEGRITY 1
	//#define RESULTS_DEBUG 1
	//#define PAO_DEBUG 1

	// Global Declarations
	#define ADDITIONAL_METADATA_SIZE 24
	#define HASH_LENGTH 32
	#define NONCE_LENGTH 16
	#define KEY_LENGTH 16


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

	struct node{
		Block *block;
		bool occupied;
		struct node *next;
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

	void printf(const char *fmt, ...);

	void displaySerializedBlock( unsigned char *serialized_result_block, uint32_t level, uint32_t recursion_levels, uint32_t x);

	//Inline Functions
	inline uint32_t iBitsPrefix(uint32_t n, uint32_t w, uint32_t i){
		return (~((1<<(w-i)) - 1)) & n;
	}

	inline uint32_t ShiftBy(uint32_t n, uint32_t w) {
		return(n>>w);
	}

	inline uint32_t noOfBitsIn(uint32_t local_deepest){
		uint32_t count = 0;
		while(local_deepest!=0){
			local_deepest = local_deepest >>1;
			count++;
		}	
		return count;
	}

	inline bool isBlockDummy(unsigned char *serialized_block, uint64_t gN){
		bool dummy_flag = *((uint32_t*)(serialized_block+16))==gN;
		return dummy_flag; 
	}

	inline uint32_t getId(unsigned char *serialized_block){
		uint32_t id = *((uint32_t*)(serialized_block+16));
		return id;
	}

	inline uint32_t* getIdPtr(unsigned char *serialized_block){
		uint32_t *id = ((uint32_t*)(serialized_block+16));
		return id;
	}

	inline void setId(unsigned char *serialized_block, uint32_t new_id){
		*((uint32_t*)(serialized_block+16)) = new_id;
	}

	inline uint32_t getTreeLabel(unsigned char *serialized_block){
		uint32_t treeLabel = *((uint32_t*)(serialized_block+20));
		return treeLabel;
	}

	inline uint32_t* getTreeLabelPtr(unsigned char *serialized_block){
		uint32_t *labelptr = ((uint32_t*)(serialized_block+20));
		return labelptr;
	}

	inline void setTreeLabel(unsigned char *serialized_block, uint32_t new_treelabel){
		*((uint32_t*)(serialized_block+20)) = new_treelabel;
	}

	inline unsigned char* getDataPtr(unsigned char* decrypted_path_ptr){
		return (unsigned char*) (decrypted_path_ptr+24);
	}


	void aes_dec_serialized(unsigned char* encrypted_block, uint32_t data_size, unsigned char *decrypted_block, unsigned char* aes_key);
	void aes_enc_serialized(unsigned char* decrypted_block, uint32_t data_size, unsigned char *encrypted_block, unsigned char* aes_key);
#endif
