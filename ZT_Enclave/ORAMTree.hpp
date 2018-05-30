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

#ifndef __ZT_ORAMTREE__
	#include <string.h>
	#include "Globals_Enclave.hpp"
	#include "Bucket.hpp"
	#include "Stash.hpp"

	class ORAMTree {
		public:
			//Basic Tree Params
			uint32_t N;
			uint32_t D;

			//Basic Params
			uint8_t Z;
			uint32_t max_blocks;
			uint32_t data_size;
			uint32_t stash_size;
			bool oblivious_flag;
			int8_t recursion_levels;
			uint32_t recursion_data_size;
			//Oram_type might not be a param anymore in the OOP version
			uint32_t oram_type;

			//Buffers
			unsigned char* encrypted_path;
			unsigned char* decrypted_path;
			unsigned char* fetched_path_array;
			unsigned char* path_hash;
			unsigned char* new_path_hash;
			unsigned char* serialized_result_block;
			
			//Computed Params
			uint32_t x;
			uint64_t gN;
			uint32_t treeSize;
			sgx_sha256_hash_t merkle_root_hash;

			//PositionMap
			uint32_t* posmap;

			//Stash components
			Stash stash;
			Stash *recursive_stash;

			// Parameters for recursive ORAMs (these are per arrays for corresponding parameters for each level of recursion)
			uint64_t *max_blocks_level;
			uint64_t *real_max_blocks_level;
			uint64_t *N_level;
			uint32_t *D_level;
			sgx_sha256_hash_t* merkle_root_hash_level;

			//Key components		
			unsigned char *aes_key;

			//Might not need these variables:
			uint64_t mem_posmap_limit; //1KB onboard posmap received from App.cpp

			//Debug Functions
			void print_stash_count(uint32_t level, uint32_t nlevel);
			void print_pmap0();
			void showPath(unsigned char *decrypted_path, uint32_t num_of_blocks_on_path, uint32_t data_size);
			void showPath_reverse(unsigned char *decrypted_path, uint32_t num_of_blocks_on_path, uint32_t data_size);

			//Initialize/Build Functions
			//void BuildTree(uint32_t max_blocks);
			void BuildTreeRecursive(int32_t level, uint32_t *prev_pmap);
			void BuildTree(uint32_t max_blocks);
			void Initialize();
			void SetParams(uint8_t pZ, uint32_t pmax_blocks, uint32_t pdata_size, uint32_t pstash_size, uint32_t poblivious_flag, uint32_t precursion_data_size, int8_t precursion_levels, uint64_t onchip_posmap_mem_limit);
			void SampleKey();

			//Constructor & Destructor
			ORAMTree();
			~ORAMTree();			
	
			//Path Function
			void verifyPath(unsigned char *path_array, unsigned char *path_hash, uint32_t leaf, uint32_t D, uint32_t block_size, uint32_t level);
			void decryptPath(unsigned char* path_array, unsigned char *decrypted_path_array, uint32_t num_of_blocks_on_path, uint32_t data_size);
			void encryptPath(unsigned char* path_array, unsigned char *encrypted_path_array, uint32_t num_of_blocks_on_path, uint32_t data_size);

			//Access Functions
			unsigned char* ReadBucketsFromPath(uint32_t leaf, unsigned char *path_hash, uint32_t level);
			void CreateNewPathHash(unsigned char *path_ptr, unsigned char *old_path_hash, unsigned char *new_path_hash, uint32_t leaf, uint32_t block_size, uint32_t D_level, uint32_t level);  
			void addToNewPathHash(unsigned char *path_iter, unsigned char* old_path_hash, unsigned char* new_path_hash_trail, unsigned char* new_path_hash, uint32_t level_in_path, uint32_t 							leaf_temp_prev, uint32_t block_size ,uint32_t D_level, uint32_t level);
			void PushBlocksFromPathIntoStash(unsigned char* decrypted_path_ptr, uint32_t level, uint32_t data_size, uint32_t block_size, uint32_t D_level, uint32_t id, uint32_t position_in_id, 				uint32_t *nextLeaf, uint32_t newleaf, uint32_t sampledLeaf, int32_t newleaf_nextlevel);
			uint32_t access_oram_level(char opType, uint32_t leaf, uint32_t id, uint32_t position_in_id, uint32_t level, uint32_t newleaf,uint32_t newleaf_nextleaf, unsigned char *data_in,  								unsigned char *data_out);		
			//uint32_t access(uint32_t id, uint32_t position_in_id, char opType, uint32_t level, unsigned char *data_in, unsigned char *data_out);

			//Misc                
			//uint32_t savePosmap(unsigned char *posmap_serialized, uint32_t posmap_size); 
			void OAssignNewLabelToBlock(uint32_t id, uint32_t position_in_id, uint32_t level, uint32_t newleaf, uint32_t newleaf_nextlevel, uint32_t * nextLeaf);
			uint32_t FillResultBlock(uint32_t id, unsigned char *result_data, uint32_t block_size);
	};

	#define __ZT_ORAMTREE__
#endif
