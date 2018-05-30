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

#ifndef __ZT_PATHORAM__
	#include <stdint.h>
	#include <string.h>

	#include "Globals_Enclave.hpp"
	#include "Block.hpp"
	#include "Bucket.hpp"
	#include "ORAMTree.hpp"
	#include "ORAM_Interface.hpp"

	class PathORAM: public ORAMTree, public ORAM_Interface 
	{
		public:
		PathORAM(uint32_t s_max_blocks, uint32_t s_data_size, uint32_t s_stash_size, uint32_t oblivious, uint32_t s_recursion_data_size, int8_t recursion_levels, uint64_t onchip_posmap_mem_limit);
		uint32_t PathORAM_Access(char opType, uint32_t id, uint32_t position_in_id, uint32_t leaf, uint32_t newleaf, uint32_t newleaf_nextlevel, unsigned char* decrypted_path, unsigned char* path_hash, uint32_t level, uint32_t D_level, uint32_t nlevel, unsigned char* data_in, unsigned char *data_out);
		void PathORAM_RebuildPath(unsigned char* decrypted_path_ptr, uint32_t data_size, uint32_t block_size, uint32_t leaf, uint32_t level, uint32_t D_level, uint32_t nlevel);
		void Initialize(uint8_t pZ, uint32_t pmax_blocks, uint32_t pdata_size, uint32_t pstash_size, uint32_t poblivious_flag, uint32_t precursion_data_size, int8_t precursion_levels, uint64_t onchip_posmap_mem_limit);
		void Access_temp(uint32_t id, char opType, unsigned char* data_in, unsigned char* data_out);	
		uint32_t access(uint32_t id, uint32_t position_in_id, char opType, uint8_t level, unsigned char* data_in, unsigned char* data_out, uint32_t *prev_sampled_leaf);			
		uint32_t access_oram_level(char opType, uint32_t leaf, uint32_t id, uint32_t position_in_id, uint32_t level, uint32_t newleaf,uint32_t newleaf_nextleaf, unsigned char *data_in,  unsigned char *data_out);

		//TODO: Defining body for virtual functions FAIL. (Current workaround for Access =  Access_temp + PathORAM_Access, for Create = Initialize)
		//void Access(uint32_t id, char opType, unsigned char* data_in, unsigned char* data_out);
		//virtual void Create(uint32_t max_blocks, uint32_t data_size, uint32_t stash_size, uint32_t oblivious_flag, uint32_t recursion_data_size, int8_t recursion_levels, uint64_t onchip_posmap_mem_limit);

	
	};

	#define __ZT_PATHORAM__
#endif
