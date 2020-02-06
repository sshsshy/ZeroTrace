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

/*
LocalStorage.hpp
*/

#include "../Globals.hpp"
#include "../CONFIG.h"
#include "../CONFIG_FLAGS.h"
#include "Enclave_u.h"
#include <string>
#include <iostream>
#include <fstream>
#include <math.h>
#include <unistd.h>
#include <fcntl.h>

#pragma once

class LocalStorage
{

public:
  uint32_t Z;
  //TODO: Probably should switch D out for D_level version?
  uint32_t D;
  uint8_t recursion_levels;
  bool inmem;
  uint64_t gN;

  unsigned char** inmem_tree_l;
  unsigned char** inmem_hash_l;

  uint64_t* blocks_in_level;
  uint64_t* buckets_in_level;
  uint64_t* real_max_blocks_level;
  uint32_t* D_level;

  uint32_t bucket_size;

  uint32_t data_block_size;
  uint32_t recursion_block_size;

  // Variables for Hybrid Storage mechanism
  uint32_t levels_on_disk = 0;
  uint32_t objectkeylimit;

  LocalStorage();
  LocalStorage(LocalStorage &ls);

  void setParams(uint32_t max_blocks, uint32_t D, uint32_t Z, uint32_t stash_size, uint32_t data_size, bool inmem, uint32_t recursion_block_size, uint8_t recursion_levels);

  void fetchHash(uint32_t bucket_id, unsigned char* hash_buffer, uint32_t hash_size, uint8_t level);

  // downloadBucket() is never used, as we typically operate with Paths
  // uploadBucket() on the other hand is used, for initializing the ORAM tree, a bucket at a time.
  // (So that we can initialize without having to maintain the entire ORAM tree in PRM space.)
  uint8_t uploadBucket(uint32_t bucket_id, unsigned char *serialized_bucket, uint32_t bucket_size, unsigned char* hash, uint32_t hash_size, uint8_t level);
  uint8_t downloadBucket(uint32_t bucket_id, unsigned char* bucket, uint32_t bucket_size , unsigned char *hash, uint32_t hash_size, uint8_t level);

  uint8_t uploadPath(uint32_t leaf_label, unsigned char *path, unsigned char *path_hash, uint8_t level, uint32_t D);
  unsigned char* downloadPath(uint32_t leaf_label, unsigned char *path, unsigned char *path_hash, uint32_t path_hash_size, uint8_t level, uint32_t D);

  void saveState(unsigned char *posmap, uint32_t posmap_size, unsigned char *stash, uint32_t stashSize, unsigned char* merkle_root, uint32_t hash_and_key_size);
  void savePosmapMerkleRoot(unsigned char* posmap_serialized, uint32_t posmap_size, unsigned char* merkle_root_and_aes_key, uint32_t hash_and_key_size);
  void saveStashLevel(unsigned char *stash, uint32_t stash_size, uint8_t level);	
  int8_t restoreState(uint32_t *posmap, uint32_t posmap_size, uint32_t *stash, uint32_t *stashSize, unsigned char* merkle_root, uint32_t hash_and_key_size);
  void restorePosmap(uint32_t* posmap, uint32_t size);
  void restoreMerkle(unsigned char* merkle, uint32_t size);

  void showPath_reverse(unsigned char *decrypted_path, uint8_t Z, uint32_t d, uint32_t data_size);

  void deleteObject();
  void copyObject();
};
