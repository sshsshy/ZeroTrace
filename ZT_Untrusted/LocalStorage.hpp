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

#pragma once

class LocalStorage
{
public:
	LocalStorage();
	LocalStorage(LocalStorage &ls);

	void connect();
	void fetchHash(uint32_t objectKey, unsigned char* hash_buffer, uint32_t hashsize, uint32_t recursion_level);
	uint8_t uploadObject(unsigned char *serialized_bucket, uint32_t objectKey, unsigned char* hash, uint32_t hashsize, uint32_t size_for_level, uint32_t recursion_level);
	unsigned char* downloadObject(unsigned char* data, uint32_t objectKey, unsigned char *hash, uint32_t hashsize,uint32_t level, uint32_t D_lev);
	uint8_t uploadPath(unsigned char *serialized_path, uint32_t leafLabel, unsigned char *path_hash,uint32_t level, uint32_t D_level);
	unsigned char* downloadPath(unsigned char* data, uint32_t leafLabel, unsigned char *path_hash, uint32_t path_hash_size, uint32_t level, uint32_t D);
	void setParams(uint32_t maxBlocks, uint32_t D, uint32_t Z, uint32_t stashSize, uint32_t dataSize, bool inmem, uint32_t recursion_block_size, int8_t recursion_levels);
	void saveState(unsigned char *posmap, uint32_t posmap_size, unsigned char *stash, uint32_t stashSize, unsigned char* merkle_root, uint32_t hash_and_key_size);
	void savePosmapMerkleRoot(unsigned char* posmap_serialized, uint32_t posmap_size, unsigned char* merkle_root_and_aes_key, uint32_t hash_and_key_size);
	void saveStashLevel(unsigned char *stash, uint32_t stash_size, uint32_t level);	
	int8_t restoreState(uint32_t *posmap, uint32_t posmap_size, uint32_t *stash, uint32_t *stashSize, unsigned char* merkle_root, uint32_t hash_and_key_size);
	void restorePosmap(uint32_t* posmap, uint32_t size);
	void restoreMerkle(unsigned char* merkle, uint32_t size);

	void deleteObject();
	void copyObject();
};
