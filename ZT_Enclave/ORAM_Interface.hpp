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

#ifndef __ZT_ORAM_INTERFACE__

	#include <stdint.h>	

	class ORAM_Interface
	{
	    public:
		//virtual void Create()=0;
	    	virtual void Create(uint32_t instance_id, uint8_t oram_type, uint8_t pZ, uint32_t max_blocks, uint32_t data_size, uint32_t stash_size, uint32_t oblivious_flag, uint32_t recursion_data_size, uint8_t recursion_levels) = 0;
	    	virtual void Access(uint32_t id, char opType, unsigned char* data_in, unsigned char* data_out) = 0;
		//virtual ~ORAM_Interface() {}
	};

	#define __ZT_ORAM_INTERFACE__
#endif
