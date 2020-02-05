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


#ifndef __ZT_STASH___
  #define __ZT_STASH___
  #include "Globals_Enclave.hpp"
	#include "oasm_lib.h"

	class Stash{
		private:
			struct nodev2 *start;
			//For non-oblivious stash:		
			uint32_t current_size;
			uint32_t stash_data_size;
			//Static upper bound on stash size
			uint32_t STASH_SIZE;
			//To test if block is dummy, it needs the gN value 
			uint64_t gN;

		public:
			Stash();
			Stash(uint32_t STASH_SIZE, uint32_t data_size, uint32_t gN);
	
			struct nodev2* getStart();
			void setStart(struct nodev2* new_start);
			void setParams(uint32_t param_stash_data_size, uint32_t param_STASH_SIZE, uint32_t param_gN);
			void PerformAccessOperation(char opType, uint32_t id, uint32_t newleaf, unsigned char *data_in, unsigned char *data_out);
			void ObliviousFillResultData(uint32_t id, unsigned char *result_data);
			uint32_t stashOccupancy();
			void setup(uint32_t stash_size, uint32_t data_size, uint32_t gN);
			void setup_nonoblivious(uint32_t data_size, uint32_t gN);
			void insert_new_block();
			void remove(nodev2 *ptr, nodev2 *prev_ptr);
			void pass_insert(unsigned char *serialized_block, bool is_dummy);
			void insert(unsigned char *serialized_block);
      uint32_t displayStashContents(uint64_t nlevel, bool recursive_block);
 	};

#endif
