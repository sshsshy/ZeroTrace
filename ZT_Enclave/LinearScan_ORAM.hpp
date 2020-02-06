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

#ifndef __ZT_LINEARSCAN_ORAM__
  #include <stdint.h>
  #include <string.h>

  #include "../Globals.hpp"
  #include "Globals_Enclave.hpp"
  #include "../CONFIG.h"
  #include "../CONFIG_FLAGS.h"
  #include "oasm_lib.h"
  #include <stdlib.h>
  #include <vector> 

  /*
    If in PRM mode, we don't need to encrypt blocks ?
    Modes:
      0: Store in PRM
      1: Store outside PRM
  */

  class LinearScan_ORAM  {
    private:
      //These key and value sizes are the upper bound.
      //Pad keys and values with 0x00 ?
      std::vector<tuple *> *LSORAM_store;
      uint32_t key_size;
      uint32_t value_size;
      uint32_t num_blocks;
      uint8_t mem_mode;
      uint8_t oblivious_mode;

      uint32_t current_size;
      uint32_t *empty_slots;
      
    public:
      LinearScan_ORAM(uint32_t instance_id, uint32_t key_size, uint32_t value_size, uint32_t num_blocks, uint8_t mode, uint8_t oblivious_mode, uint8_t populate);
      ~LinearScan_ORAM();
     
      uint32_t getKeySize();
      uint32_t getValueSize(); 
     
      void populateDummyElements();

      //Test key doesn't already exist, sizes of key and value < key_size, value_size
      // if current size = num_blocks, realloc and update num_blocks (by doubling current size?)
      int8_t insert(unsigned char* key, uint32_t key_size,  unsigned char *value, uint32_t value_size);
  
      // Fetch: is only for read operation, specifically Access-Only oblivious reads
      // Test key exists
      // The value buffer is passed from outside the enclave, and the LS-ORAM
      // populates and sends it back.
      int8_t fetch(unsigned char* key, uint32_t key_size, unsigned char *value, uint32_t value_size);


      // Access : is the Full-Oblivious counterpart, which does either r/w operation based on op
      // The value buffer is passed from outside the enclave, and the LS-ORAM
      // populates/stores-value-from-it and sends it back.
      int8_t access(uint8_t op, unsigned char* key, uint32_t key_size, unsigned char *value, uint32_t value_size);

     
      // Removes element by adding index to empty_slots
      // Test key does exist, 
      int8_t evict(unsigned char* key, uint32_t key_size);

  };
 #define __ZT_LINEARSCAN_ORAM__
#endif
