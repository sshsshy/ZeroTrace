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

#ifndef __ZT_BUCKET__
  #include "Globals_Enclave.hpp"
  #include "Block.hpp"

  class Bucket {
    public:
      Block *blocks;
      uint8_t Z;
      
      Bucket(unsigned char* serialized_bucket, uint32_t data_size, uint8_t Z);
      Bucket(uint8_t Z);
      Bucket();
      ~Bucket();		

      void initialize(uint32_t data_size, uint32_t gN);
      void reset_blocks(uint32_t data_size, uint32_t gN);
      void sampleRandomness();
      void aes_encryptBlocks(uint32_t data_size, unsigned char *aes_key);
      void aes_decryptBlocks(uint32_t data_size, unsigned char *aes_key);

      unsigned char* serialize(uint32_t data_size);

      void serializeToBuffer(unsigned char* serializeBuffer, uint32_t data_size);

      void displayBlocks();
      void fill();
      void fill(Block *b, uint32_t pos, uint32_t g_data_size);
      void fill(unsigned char *serialized_block, uint32_t pos, uint32_t g_data_size);
      void fill(uint32_t data_size);
  };


  #define __ZT_BUCKET__
#endif
