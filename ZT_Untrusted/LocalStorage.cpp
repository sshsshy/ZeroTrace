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
LocalStorage.cpp
*/

#include "Enclave_u.h"
#include "LocalStorage.hpp"
#include <string>
#include <iostream>
#include <fstream>
#include <math.h>
#include <unistd.h>
#include <fcntl.h>

#define HASH_LENGTH 32
#define FILESTREAM_MODE 1
#define DEBUG_LS 1
// #define DEBUG_INTEGRITY 1
// Utilization Parameter is the number of blocks of a bucket that is filled at start state. ( 4 = MAX_OCCUPANCY )
#define UTILIZATION_PARAMETER 4
#define ADDITIONAL_METADATA_SIZE 24
//#define NO_CACHING 1
//#define CACHE_UPPER 1
//#define PASSIVE_ADVERSARY 1
//#define PRINT_BUCKETS 1

//uint64_t MEM_POSMAP_LIMIT_LS = 1 * 1024;
uint64_t MEM_POSMAP_LIMIT_LS =  1 * 1024;
//uint32_t MEM_POSMAP_LIMIT_LS = 32 * (4);
uint64_t RAM_LIMIT = (uint64_t)(60 * 1024) * (uint64_t)(1024 * 1024);

uint32_t dataSize;
uint32_t Z;
uint32_t D;

//Take this value as input parameter !
std::string directoryFP = "/mnt/Storage/";
std::string directoryFP_i = directoryFP;
std::string file_name;
std::string file_name_i;
std::string temp;
std::string state_folder = "state";
bool inmem;
unsigned char* inmem_tree;
unsigned char* inmem_hash;
unsigned char** inmem_tree_l;
unsigned char** inmem_hash_l;
uint64_t datatree_size;
uint64_t hashtree_size;
uint32_t bucket_size;
uint32_t recursionBlockSize;
int32_t recursion_levels=0;
uint32_t levels_on_disk = 0;
uint32_t objectkeylimit;
uint64_t *maxBlocks_of_pmap_level;

/*
Debug Module (Auxiliary Snippet) : For Block level debugging on Storage side

uint32_t extDataSize = 1024 - 18;
uint32_t gN = 128;
uint32_t noncelen = 10;

class Block {
	public:
		unsigned char *data;
		uint32_t id;
		uint32_t treeLabel;
		uint8_t *r;

	Block(){
		data = NULL;
		r = NULL;
		treeLabel = 0;
		id = gN;
	}

	Block(Block &b)
	{
		data = (unsigned char*) malloc (extDataSize);
		r = (uint8_t*) malloc(noncelen);
		memcpy(r,b.r,noncelen);
		memcpy(data,b.data,extDataSize);

		treeLabel = b.treeLabel;
		id = b.id;
	}

	Block(uint32_t set_id, uint8_t *set_data, uint32_t set_label){
		//data = ; Generate datablock of appropriate datasize for new block.
		//treeLabel = 0;
		id = set_id;
		data = set_data;
		treeLabel = set_label;
	}

	Block(unsigned char* serialized_block){
		unsigned char* ptr = serialized_block;
		r = (uint8_t*) malloc(noncelen);

		memcpy(r,ptr,noncelen);
		ptr+= noncelen;

		memcpy((void *)&id, ptr, 4);
		ptr+=4;
		memcpy((void *)&treeLabel, ptr, 4);
		ptr+=4;

		data = (unsigned char*) malloc (extDataSize);
		memcpy(data,ptr,extDataSize);
		ptr+= extDataSize;
	}

	void fill (unsigned char* serialized_block)
	{
		unsigned char* ptr = serialized_block;
		r = (uint8_t*) malloc(noncelen);

		memcpy(r,ptr,noncelen);
		ptr+= noncelen;

		memcpy((void *)&id, ptr, 4);
		ptr+=4;
		memcpy((void *)&treeLabel, ptr, 4);
		ptr+=4;

		data = (unsigned char*) malloc (extDataSize);
		memcpy(data,ptr,extDataSize);
		ptr+= extDataSize;
	}

	~Block()
	{
		if(r)
			free(r);
		if(data)
			free(data);
	}

	unsigned char* serialize() {
		unsigned char* serialized_block = (unsigned char*) malloc(dataSize);
		unsigned char *ptr = serialized_block;
		memcpy(ptr,(void *) r,noncelen);
		ptr+=noncelen;
		memcpy(ptr,(void *) &id,sizeof(id));
		ptr+=sizeof(id);
		memcpy(ptr,(void *) &treeLabel,sizeof(treeLabel));
		ptr+=sizeof(treeLabel);
		memcpy(ptr,data,extDataSize);
		ptr+=extDataSize;
		return serialized_block;
	}

	void serializeToBuffer(unsigned char* serialized_block) {
		unsigned char *ptr = serialized_block;
		memcpy(ptr,(void *) r,noncelen);
		ptr+=noncelen;
		memcpy(ptr,(void *) &id,sizeof(id));
		ptr+=sizeof(id);
		memcpy(ptr,(void *) &treeLabel,sizeof(treeLabel));
		ptr+=sizeof(treeLabel);
		memcpy(ptr,data,extDataSize);
		ptr+=extDataSize;
	}

};
*/

LocalStorage::LocalStorage(){
}

int8_t LocalStorage::restoreState(uint32_t *posmap, uint32_t posmap_size, uint32_t* stash, uint32_t *stash_size, unsigned char* merkle_root, uint32_t hash_and_key_size)
{
	//Check if posmap/stash exists
	if(1){
		std::string fpp = directoryFP + temp + "posmap";
		std::string fps = directoryFP + temp + "stash";
		std::string fpr = directoryFP + temp + "merkleroot";
		printf("%s\n",fps.c_str());		
		std::string line,sp1,sp2;
		size_t pos;

		try {
		std::ifstream file(fpp.c_str());
		uint32_t *posmap_iter = (uint32_t*) posmap;
		uint32_t i = 0;
		for(i=0;i<posmap_size;i++) {
			getline(file,line);
			uint32_t item = atoi(line.c_str());
			*posmap_iter = item;
			posmap_iter++;
			}
		//file.write((unsigned char*) posmap, dataSize * Z);
		file.close();

		file.open(fps.c_str());
		uint32_t *stash_iter = (uint32_t*) stash;

		*stash_size = 0;
		while(getline(file,line)) {
			pos = line.find("\t");
			sp1 = line.substr(0,pos);
			sp2 = line.substr(pos+1,std::string::npos);
			*stash_iter=atoi(sp1.c_str());
			stash_iter++;
			*stash_iter=atoi(sp2.c_str());
			stash_iter++;
			(*stash_size)++;
		}
		file.close();

		file.open(fpr.c_str());
		file.read((char *)merkle_root,hash_and_key_size);
		file.close();

	}
	catch (std::ifstream::failure e) {
			std::cerr <<"Exception opening file";
	}
		return 1;
	}
	else
		return -1;
	// Else return -1
}

void LocalStorage::restoreMerkle(unsigned char* merkle, uint32_t size) {
	std::string fpr = directoryFP + "merkleroot";
	try {
		std::ifstream file;
		file.open(fpr.c_str());
		file.read((char *)merkle,size);
		file.close();		
	}
	catch (std::ifstream::failure e) {
			std::cerr <<"Exception opening file";
	}
}

void LocalStorage::restorePosmap(uint32_t* posmap, uint32_t size)
{
	std::string fpp = directoryFP + "posmap";
	try {
		std::ifstream file;
		file.open(fpp.c_str());
		
		uint32_t *posmap_iter = (uint32_t*) posmap;
		uint32_t i = 0;
		char *label = (char*) malloc(5);
		for(i=0;i<size/4;i++) {
			//std::string tempstr = std::to_string(*posmap_iter) + "\n";
			file.getline(label,5);
			std::string tempstr = std::string(label,4);
			*posmap_iter = std::stoi(tempstr,NULL);
			posmap_iter++;
		}		
	}
	catch (std::ifstream::failure e) {
			std::cerr <<"Exception opening file";
	}
}

void LocalStorage::savePosmapMerkleRoot(unsigned char* posmap, uint32_t posmap_size, unsigned char* merkle_root_and_aes_key, uint32_t hash_and_key_size)
{
	std::string fpp = directoryFP + "posmap";
	std::string fpr = directoryFP + "merkleroot";
	try {
		std::ofstream file;
		file.open(fpr.c_str());
		file.write((char *)merkle_root_and_aes_key,hash_and_key_size);
		file.close();
		
		uint32_t *posmap_iter = (uint32_t*) posmap;
		uint32_t i = 0;
		file.open(fpp.c_str());
		for(i=0;i<posmap_size/4;i++) {
			std::string tempstr = std::to_string(*posmap_iter) + "\n";
			file.write(tempstr.c_str(),tempstr.length());
			posmap_iter++;
		}
		file.close();
		
	}
	catch (std::ifstream::failure e) {
			std::cerr <<"Exception opening file";
	}
}

void LocalStorage::saveStashLevel(unsigned char* stash, uint32_t stash_size, uint32_t level) 
{
	std::string fps = directoryFP + temp + "stash" + std::to_string(level);
		try {
		std::ofstream file(fps.c_str());
		file.write((const char*)stash,stash_size);
		/*
		uint32_t *stash_iter = (uint32_t*) stash;
		for(uint32_t i=0;i<stash_size;i++) {
			std::string temp = std::to_string(*(stash_iter++)) + "\t";
			temp+= std::to_string(*(stash_iter++)) + "\n";
			file.write(temp.c_str(),temp.length());
		}*/
		file.close();

		
	}
	catch (std::ifstream::failure e) {
			std::cerr <<"Exception opening file";
	}
}

void LocalStorage::saveState(unsigned char *posmap, uint32_t posmap_size, unsigned char *stash, uint32_t stash_size, unsigned char* merkle_root_and_aes_key,uint32_t hash_and_key_size)
{
	
	std::string fpp = directoryFP + temp + "posmap";
	std::string fps = directoryFP + temp + "stash";
	std::string fpr = directoryFP + temp + "merkleroot";

	try {
		std::ofstream file(fpp.c_str());
		uint32_t *posmap_iter = (uint32_t*) posmap;
		uint32_t i = 0;
		for(i=0;i<posmap_size;i++) {
			std::string temp = std::to_string(*posmap_iter) + "\n";
			file.write(temp.c_str(),temp.length());
			posmap_iter++;
		}
		//file.write((unsigned char*) posmap, dataSize * Z);
		file.close();

		file.open(fps.c_str());
		uint32_t *stash_iter = (uint32_t*) stash;
		for(i=0;i<stash_size;i++) {
			std::string temp = std::to_string(*(stash_iter++)) + "\t";
			temp+= std::to_string(*(stash_iter++)) + "\n";
			file.write(temp.c_str(),temp.length());
		}
		file.close();

		file.open(fpr.c_str());
		file.write((char *)merkle_root_and_aes_key,hash_and_key_size);
		file.close();
	}
	catch (std::ifstream::failure e) {
			std::cerr <<"Exception opening file";
	}
}
void LocalStorage::setParams(uint32_t maxBlocks,uint32_t set_D, uint32_t set_Z, uint32_t stashSize, uint32_t dataSize_p, bool inmem_p, uint32_t recursion_block_size, int8_t recursion_levels_p)
{
	//Test and set directory name
	dataSize = dataSize_p;
	D = set_D;
	Z = set_Z;
	inmem = inmem_p;	

	temp = std::to_string(maxBlocks) + "_" + std::to_string(dataSize) + "_" + std::to_string(stashSize);
	recursionBlockSize = recursion_block_size;
	recursion_levels = recursion_levels_p;

	bucket_size = dataSize_p * Z;
	datatree_size = (pow(2,D+1)-1) * (bucket_size);
	hashtree_size = ((pow(2,D+1)-1) * (HASH_LENGTH));

	#ifdef DEBUG_LS
		printf("\nIN LS : recursion_levels = %d, dataSize = %d, recursionBlockSize = %d\n\n",recursion_levels, dataSize, recursionBlockSize);
		printf("DataTree_size = %ld or %f GB, HashTree_size = %ld or %f GB\n",datatree_size,float(datatree_size)/(float(1024*1024*1024)),hashtree_size,float(hashtree_size)/(float(1024*1024*1024)));
	#endif

	if(inmem==false) {
		#ifndef RESUME_EXPERIMENT
			std::string system_inst = "mkdir "+ directoryFP+ temp + "\n";
			system(system_inst.c_str());
			//std::string system_inst2 = "mkdir " + directoryFP + temp +"_i\n";
			//system(system_inst2.c_str());
			file_name = directoryFP+temp+"/"+temp;
			file_name_i = directoryFP+temp+"/"+temp+"_i";
			//printf("MAXBLOCKS: %d\n",maxBlocks);

			if(recursion_levels==0) {
				std::ofstream file(file_name,std::ios::binary);
				std::ofstream file_i(file_name_i,std::ios::binary);
				file.seekp(datatree_size);
				file.write("",1);
				file.close();
				file_i.seekp(hashtree_size);
				file_i.write("",1);
				file_i.close();
			}
			else {
				//Compute Sizes of Recursive ORAM trees
				uint32_t x = (recursion_block_size - ADDITIONAL_METADATA_SIZE) / UTILIZATION_PARAMETER;
				maxBlocks_of_pmap_level = (uint64_t*) malloc((recursion_levels +1) * sizeof(uint64_t*));
				uint32_t pmap0_blocks = maxBlocks ;
				while(pmap0_blocks > MEM_POSMAP_LIMIT_LS/ UTILIZATION_PARAMETER){
					pmap0_blocks = (uint32_t) ceil((double)pmap0_blocks/(double)x);
				}
				uint32_t lev = 2;
				maxBlocks_of_pmap_level[0] = pmap0_blocks;
				maxBlocks_of_pmap_level[1] = pmap0_blocks;
				while(lev <= recursion_levels){
					maxBlocks_of_pmap_level[lev] = maxBlocks_of_pmap_level[lev-1]*16;
					printf("LS:Level : %d, Blocks : %ld\n", lev, maxBlocks_of_pmap_level[lev]);					
					lev++;
			}			
				
			#ifdef CACHE_UPPER
				//Partition the last disk layer across DRAM and Storage Disk
				uint64_t total_size= 0;
				inmem_tree_l = (unsigned char**) malloc ((recursion_levels+1)*sizeof(unsigned char*));
				inmem_hash_l = (unsigned char**) malloc ((recursion_levels+1)*sizeof(unsigned char*));

				for(uint32_t i = 1;i<= recursion_levels;i++) {
					std::string file_name_this = file_name + "p" + std::to_string(i);
					std::string file_name_this_i = file_name + "p" + std::to_string(i) + "_i";
												
					uint32_t pD_temp = ceil((double)maxBlocks_of_pmap_level[i]/(double) UTILIZATION_PARAMETER);
					uint32_t pD = (uint32_t) ceil(log((double)pD_temp)/log((double)2));
					uint32_t pN = (int) pow((double)2, (double) pD);
					uint32_t ptreeSize = 2*pN-1;	
					uint64_t file_size, remainder, mem_tree_size, next_layer_size, final_file_size = 0; 
					uint64_t hashtree_size_this = (uint64_t)(ptreeSize) * (uint64_t)HASH_LENGTH;

					inmem_hash_l[i] = (unsigned char*) malloc(hashtree_size_this);
					printf("HASHTREE_SIZE for level %d = %f MB\n",i,float(hashtree_size_this)/float(1024*1024));					
					total_size+=hashtree_size_this;

					if(i==recursion_levels)	
						file_size = (uint64_t) ptreeSize* (uint64_t) (Z*dataSize_p); 
					else
						file_size = (uint64_t) ptreeSize* (uint64_t) (Z*recursion_block_size);

					if(i==recursion_levels){						
						//Determine amount that has to be moved to Disk storage
						//Do Math here to detemine number of levels that can be cached.
						remainder = RAM_LIMIT - total_size;
						levels_on_disk = 1;	
						objectkeylimit = ptreeSize - pN;
						mem_tree_size = ( (uint64_t)(pN) * (uint64_t)(Z*dataSize_p));
						final_file_size += ((uint64_t)pN * (uint64_t)(Z*dataSize_p));
			
						printf("mem_tree_size = %f MB\n",(float) mem_tree_size/(float)(1024*1024));
						//Note : Last layer of tree is ALWAYS moved to DISK
						//If tree doesn't fit in memory more of the lower levels are moved to Disk
						while(mem_tree_size > remainder) {				
							next_layer_size = ((uint64_t)(pow(2,pD-(levels_on_disk))) * (uint64_t)Z*dataSize_p); 
							mem_tree_size -= next_layer_size;
							final_file_size += next_layer_size;				
							objectkeylimit -= (pow(2,pD-(levels_on_disk)));
							levels_on_disk++;
							printf("mem_tree_size = %f MB\n",(float) mem_tree_size/(float)(1024*1024));
						}						
						printf("Level on Disk = %d\n", levels_on_disk);					

						//Setup DataTree half Inmem and half in disk
						//Setup Integrity tree Inmem
						inmem_tree_l[i] = (unsigned char*) malloc(mem_tree_size);
						if(!inmem_tree_l[i]) {
							printf("FAILED MALLOC of %f MB\n", float(mem_tree_size)/(float(1024*1024)));
							exit(0);
						}
						std::ofstream file(file_name_this,std::ios::binary);
						file.seekp(final_file_size);
						file.write("X",1);
						file.close();
					}
					else{	
						inmem_tree_l[i] = (unsigned char*) malloc(file_size);
						total_size+=file_size;
					}			
				}		
			
				#else
					for(uint32_t i = 1;i<= recursion_levels;i++) {
						std::string file_name_this = file_name + "p" + std::to_string(i);
						std::string file_name_this_i = file_name + "p" + std::to_string(i) + "_i";
						std::ofstream file(file_name_this,std::ios::binary);
						std::ofstream file_i(file_name_this_i,std::ios::binary);
						uint32_t pD_temp = ceil((double)maxBlocks_of_pmap_level[i]/(double) UTILIZATION_PARAMETER);
						uint32_t pD = (uint32_t) ceil(log((double)pD_temp)/log((double)2));
						uint32_t pN = (int) pow((double)2, (double) pD);
						uint32_t ptreeSize = 2*pN-1;
	
						uint64_t file_size; 
						if(i==recursion_levels)	
							file_size = (uint64_t) ptreeSize* (uint64_t) (Z*dataSize_p); 
						else
							file_size = (uint64_t) ptreeSize* (uint64_t) (Z*recursion_block_size);
						file.seekp(file_size);
						printf("Level = %d, MaxBlocks = %ld, File_size = %ld or %f GB\n", i, maxBlocks_of_pmap_level[i], file_size, float(file_size)/float(1024*1024*1024));				
						file.write("X",1);
						file.close();
					
						uint64_t hashtree_size_this = (uint64_t)(pow(2,pD+1)-1 ) * (uint64_t)HASH_LENGTH;
						file_i.seekp(hashtree_size_this);
						file_i.write("X",1);
						file_i.close();				
					}				
				#endif			
			}	
		#endif
	}
	else {
		if(recursion_levels==-1) {
			#ifdef DEBUG_LS			
				printf("DataTree_size = %ld, HashTree_size = %ld\n",datatree_size,hashtree_size);			
			#endif			
			inmem_tree = (unsigned char *) malloc(datatree_size);
			inmem_hash = (unsigned char *) malloc(hashtree_size);
		}	
		else {	
			#ifdef RESUME_EXPERIMENT
				//Resuming mechanism for in-memory database
			#else	
			
				uint32_t x = (recursion_block_size - 24) / 4;
				#ifdef DEBUG_LS
					printf("X = %d\n",x);
				#endif
				uint64_t pmap0_blocks = maxBlocks; 				
				uint64_t cur_pmap0_blocks = maxBlocks;
				uint64_t *maxBlocks_of_pmap_level = (uint64_t*) malloc((recursion_levels +1) * sizeof(uint64_t*));
			
				uint32_t level = recursion_levels;
				maxBlocks_of_pmap_level[recursion_levels] = pmap0_blocks;
			
		
				while(level > 1) {
					maxBlocks_of_pmap_level[level-1] = ceil((double)maxBlocks_of_pmap_level[level]/(double)x);
					level--;
				}
				maxBlocks_of_pmap_level[0] = maxBlocks_of_pmap_level[1];
				#ifdef DEBUG_LS
					printf("LS:Level : %d, Blocks : %ld\n", 0, maxBlocks_of_pmap_level[0]);	
				#endif	
				level = 2;
			
				while(level <= recursion_levels) {
					maxBlocks_of_pmap_level[level] = maxBlocks_of_pmap_level[level-1] * x;
					#ifdef DEBUG_LS
						printf("LS:Level : %d, Blocks : %ld\n", level, maxBlocks_of_pmap_level[level]);
					#endif				
					level++;
				}
	
				inmem_tree_l = (unsigned char**) malloc ((recursion_levels+1)*sizeof(unsigned char*));
				inmem_hash_l = (unsigned char**) malloc ((recursion_levels+1)*sizeof(unsigned char*));
				for(uint32_t i = 1;i<= recursion_levels;i++) {
					uint64_t level_size; 
					if(i==recursion_levels)	
						level_size = 2 * ceil((double)maxBlocks_of_pmap_level[i])*(Z*(dataSize_p+ADDITIONAL_METADATA_SIZE)); 
					else
						level_size = 2 * ceil((double) maxBlocks_of_pmap_level[i]) * (Z*(recursion_block_size+ADDITIONAL_METADATA_SIZE));
					uint32_t pD_temp = ceil((double)maxBlocks_of_pmap_level[i]/(double) UTILIZATION_PARAMETER);
					uint32_t pD = (uint32_t) ceil(log((double)pD_temp)/log((double)2));
					uint64_t hashtree_size_this = 2 * maxBlocks_of_pmap_level[i] * HASH_LENGTH;				
				
					//Setup Memory locations for hashtree and recursion block	
					inmem_tree_l[i] = (unsigned char*) malloc(level_size);
					inmem_hash_l[i] = (unsigned char*) malloc(hashtree_size_this);
				}			
			#endif
		}
	
	}
	directoryFP_i.append(temp + "_i/");
	directoryFP.append(temp+"/");
}

LocalStorage::LocalStorage(LocalStorage&ls)
{
}

void LocalStorage::connect()
{
	
}

void LocalStorage::fetchHash(uint32_t objectKey, unsigned char* hash, uint32_t hashsize, uint32_t recursion_level) {
	
	std::string file_name_this, file_name_this_i;
	if(recursion_level!=-1)	{
		file_name_this = file_name + "p" + std::to_string(recursion_level); 
		file_name_this_i = file_name_this + "_i";	
	}
	else {
		file_name_this = file_name;	
		file_name_this_i = file_name_i;
	}	
	
	if(inmem==false) {	
		#ifdef CACHE_UPPER
			memcpy(hash,inmem_hash_l[recursion_level] +((uint64_t)(objectKey-1)*(uint64_t)HASH_LENGTH), HASH_LENGTH);
		#else
			//std::string fp_i = directoryFP_i + std::to_string(objectKey);	
			try {
				std::ifstream file(file_name_this_i.c_str(),std::ios::binary);
				file.seekg((objectKey-1)*hashsize);
				file.read((char*) hash, hashsize);
				file.close();
			}
			catch (std::ifstream::failure e) {
				std::cerr << "Exception opening file";
			}
		#endif
	}
	else {
		if(recursion_level!=-1) {
			memcpy(hash,inmem_hash_l[recursion_level]+((objectKey-1)*HASH_LENGTH), HASH_LENGTH);		
		}
		else {
			memcpy(hash,inmem_hash+((objectKey-1)*HASH_LENGTH), HASH_LENGTH);
		}
	}
}

uint8_t LocalStorage::uploadObject(unsigned char *data, uint32_t objectKey,unsigned char *hash, uint32_t hashsize, uint32_t size_for_level, uint32_t recursion_level)
{
	uint64_t pos;
	std::string file_name_this, file_name_this_i;
	if(!inmem) {
		if(recursion_level!=-1)	{
			file_name_this = file_name + "p" + std::to_string(recursion_level); 
			file_name_this_i = file_name_this + "_i";	
		}
		else {
			file_name_this = file_name;	
			file_name_this_i = file_name_i;
		}
	}

	if(inmem == false) {
		try {
			#ifdef DEBUG_LS			
				printf("Level : %d, %s, Pos : %d\n",recursion_level, file_name_this.c_str(),(objectKey-1)*Z*size_for_level);
			#endif

			/*
			//Debug Module :
			uint32_t *printer = (uint32_t*)data;
			printf("BEFORE WRITE : ");
			for(uint8_t e = 0;e < Z ;e++) {
				printer+=4;
				printf("(%d,%d) , ", *printer, *(printer+1));
				printer = (uint32_t*) (data + (e+1)*size_for_level);
			}
			printf("\n");
			*/
			
			pos = (uint64_t)(objectKey-1)*(uint64_t)(Z*size_for_level);
			int filedesc;
	
			#ifdef FILEOPEN_MODE
				filedesc = open(file_name_this.c_str(), O_RDWR|O_DIRECT|O_DSYNC);
				pwrite(filedesc,data,(size_for_level*Z),pos);
				//posix_fadvise(filedesc,pos,(size_for_level*Z),POSIX_FADV_DONTNEED);
				posix_fadvise(filedesc,0,datatree_size,POSIX_FADV_DONTNEED);
				syncfs(filedesc);
				close(filedesc);
				
				filedesc = open(file_name_this_i.c_str(), O_RDWR|O_DIRECT|O_DSYNC);
				pwrite(filedesc,hash,hashsize,(objectKey-1)*hashsize);
				posix_fadvise(filedesc,(objectKey-1)*hashsize,hashsize,POSIX_FADV_DONTNEED);
				syncfs(filedesc);
				close(filedesc);
					
			#elif FILESTREAM_MODE
				#ifdef CACHE_UPPER
					//printf("%d,%d\n",objectKey,objectkeylimit);
					if(recursion_level == recursion_levels){
						if(objectKey <= objectkeylimit) {
							memcpy(inmem_tree_l[recursion_level]+pos,data,(Z*size_for_level));
							memcpy(inmem_hash_l[recursion_level]+((uint64_t)HASH_LENGTH*(uint64_t)(objectKey-1)),hash, hashsize);
						}	
						else{	
							uint32_t adjusted_objectkey = objectKey - objectkeylimit - 1;
							memcpy(inmem_hash_l[recursion_level]+((uint64_t) HASH_LENGTH * (uint64_t) (objectKey-1)),hash, hashsize);
							pos = (uint64_t)(objectKey - 1 - objectkeylimit) * (uint64_t)(Z*size_for_level);
							//std::cout<<"Pos = "<<pos<<"\n";							
							std::ofstream file(file_name_this.c_str(),std::ios::binary|std::ios::in);
							file.seekp(pos);
							file.write((char*) data, (size_for_level*Z));
							file.close();
						}
					}
					else {
						memcpy(inmem_tree_l[recursion_level]+((Z*size_for_level)*(objectKey-1)),data,(Z*size_for_level));
						memcpy(inmem_hash_l[recursion_level]+(HASH_LENGTH*(objectKey-1)),hash, hashsize);
					}
				#else
					std::ofstream file(file_name_this.c_str(),std::ios::binary|std::ios::in);
					file.seekp(pos);
					file.write((char*) data, (size_for_level*Z));
					file.close();
		
					/*
					//Debug Module :
					unsigned char* data2 = (unsigned char*) malloc(Z*size_for_level);
					std::ifstream file2(file_name_this.c_str(),std::ios::binary);
					file2.seekg((objectKey-1)*(Z*size_for_level));
					file2.read((char*) data2, (Z*size_for_level));
					file2.close();			
					printer = (uint32_t*) data2;
					printf("AFTER WRITE : ");
					for(uint8_t e = 0;e < Z ;e++) {
						printer+=4;
						printf("(%d,%d) , ", *printer, *(printer+1));
						printer = (uint32_t*) (data2 + (e+1)*size_for_level);
					}
					printf("\n");
					*/

					file.open(file_name_this_i.c_str(),std::ios::binary|std::ios::in);
					file.seekp((objectKey-1)*hashsize,std::ios_base::beg);
					file.write((char*) hash, hashsize);
					file.close();
				#endif
			#endif
		}
		catch (std::ifstream::failure e) {
			std::cerr << "Exception opening file";
		}
	}
	else {

		if(recursion_level == -1) {
			memcpy(inmem_tree+((Z*size_for_level)*(objectKey-1)),data,(size_for_level*Z));
			memcpy(inmem_hash+(HASH_LENGTH*(objectKey-1)),hash,HASH_LENGTH);
		}
		else {
			uint64_t pos = ((uint64_t)(Z*size_for_level))*((uint64_t)(objectKey-1));
			memcpy(inmem_tree_l[recursion_level]+(pos),data,(size_for_level*Z));
			memcpy(inmem_hash_l[recursion_level]+(HASH_LENGTH*(objectKey-1)),hash,HASH_LENGTH);
		}	
	}
	return 0;
}

uint8_t LocalStorage::uploadPath(unsigned char *path, uint32_t leafLabel,unsigned char *path_hash, uint32_t level, uint32_t D_level)
{
	std::string file_name_this, file_name_this_i;
	uint32_t size_for_level = dataSize;
	uint64_t pos;
	if(!inmem){
		if(level!=-1)	{
			file_name_this = file_name + "p" + std::to_string(level); 
			file_name_this_i = file_name_this + "_i";	
			if(level==recursion_levels)
				size_for_level = dataSize;
			else
				size_for_level = recursionBlockSize;
		}
		else {
			file_name_this = file_name;	
			file_name_this_i = file_name_i;
		}	
	}
	else{
		if(level==recursion_levels)
			size_for_level = dataSize;
		else
			size_for_level = recursionBlockSize;
	}

	uint32_t temp = leafLabel;
	unsigned char* path_iter = path;
	unsigned char* path_hash_iter = path_hash;

	if(inmem == false) {
		#ifdef FILESTREAM_MODE
			FILE *file1, *file2;
			#ifndef CACHE_UPPER
				file1 = fopen(file_name_this.c_str(),"r+b");
				file2 = fopen(file_name_this_i.c_str(), "r+b");
			#endif
		#endif
				
		for(uint8_t i = 0;i<D_level+1;i++) {
			#ifdef DEBUG_PATH_LS
				if(level!=recursion_levels) {
					uint32_t *print_iter = (uint32_t*) (path_iter);
					for(uint8_t q = 0 ;q < Z ;q++) {
						print_iter+=4;
						printf("(%d,%d) : ",*print_iter,*(print_iter+1));
						print_iter+=2;
						for(uint8_t p = 0;p<16;p++) {
							printf(" %d, ", *print_iter);
							print_iter+=1;
						}
					
						printf("\n");				
					}
				}
			#endif

			try {
				#ifdef FILEOPEN_MODE
					system("echo 3 > /proc/sys/vm/drop_caches");
					int filedesc;
					//printf("DP : FILE_DESC_MODE\n");
					//printf("USING SYSCALL OPEN");
					filedesc = open(file_name_this.c_str(), O_RDWR|O_DIRECT|O_DSYNC);
					pos = (temp-1)*(size_for_level*Z);
					pwrite(filedesc,path_iter,(size_for_level*Z),pos);
					path_iter+=(size_for_level*Z);
					posix_fadvise(filedesc,pos,(size_for_level*Z),POSIX_FADV_DONTNEED);
					syncfs(filedesc);
					close(filedesc);

					//printf("DP : FILE_DESC_BASE DONE\n");					
				
					filedesc = open(file_name_this_i.c_str(), O_RDWR|O_DIRECT|O_DSYNC);
					pwrite(filedesc,path_hash_iter,HASH_LENGTH,(temp-1)*HASH_LENGTH);
					path_hash_iter+=(HASH_LENGTH);
					syncfs(filedesc);
					close(filedesc);					

				#elif FILESTREAM_MODE
					#ifdef CACHE_UPPER
						if(level==recursion_levels){
							if(temp > objectkeylimit){
								FILE *file1t;
								file1t = fopen(file_name_this.c_str(),"r+b");
								uint32_t adjusted_temp = temp - objectkeylimit -1;
								//File Access
								pos = (uint64_t)(adjusted_temp)*(uint64_t)(size_for_level*Z);
								fseek(file1t, pos, SEEK_SET);
								fwrite(path_iter, 1, (size_for_level*Z), file1t);
								path_iter += (Z*size_for_level);
								fclose(file1t);								
								
							}	
							else{
								memcpy(inmem_tree_l[level]+((uint64_t)(Z*size_for_level)*(uint64_t)(temp-1)),path_iter,(Z*size_for_level));
								path_iter += (Z*size_for_level);
							}

							//Common integrity tree part
							memcpy(inmem_hash_l[level]+(uint64_t)(HASH_LENGTH*(temp-1)),path_hash_iter,HASH_LENGTH);
							path_hash_iter +=(HASH_LENGTH);
							
						}	
						else{
							uint64_t postemp = (Z*size_for_level)*(temp-1);
							//printf("LS-FS-CU: temp = %d, pos = %ld\n",temp,postemp);
							memcpy(inmem_tree_l[level]+((Z*size_for_level)*(temp-1)),path_iter,(Z*size_for_level));
							memcpy( inmem_hash_l[level]+(HASH_LENGTH*(temp-1)),path_hash_iter,HASH_LENGTH);
							path_iter += (Z*size_for_level);
							path_hash_iter+=HASH_LENGTH;	
						}
					#else
						//Confirm that mode doesn't wipe existing file
						pos = (uint64_t)(temp-1)*(uint64_t)(size_for_level*Z);
						//printf("Seeked pos : %ld\n",pos);
						fseek(file1, pos, SEEK_SET);
						fwrite(path_iter,1,(size_for_level*Z), file1);
						path_iter+=(size_for_level*Z);
									
						pos = (temp-1)*HASH_LENGTH;					
						fseek(file2, pos, SEEK_SET);
						fwrite(path_hash_iter,1, HASH_LENGTH, file2);
						path_hash_iter+=HASH_LENGTH;
					#endif
				#else
					std::ofstream file(file_name_this.c_str(),std::ios::binary|std::ios::in);
					pos = (temp-1)*(size_for_level*Z);				
					file.seekp(pos);
					file.write((char*) path_iter, (size_for_level*Z));
					path_iter+=(size_for_level*Z);
					file.close();
			
					file.open(file_name_this_i.c_str(),std::ios::binary|std::ios::in);
					file.seekp((temp-1)*HASH_LENGTH);
					file.write((char*) path_hash_iter, HASH_LENGTH);
					path_hash_iter+=HASH_LENGTH;
					file.close();
				#endif
				
			}
			catch (std::ifstream::failure e) {
					std::cerr <<"Exception opening file";
			}
			//if(temp > 0) {temp = ((temp+1)>>1)-1;}
			temp = temp>>1;
		}
		#ifdef FILESTREAM_MODE	
			#ifndef CACHE_UPPER
				fclose(file1);							
				fclose(file2);
			#endif
		#endif
		/*
		#ifdef FILE_DESC_MODE
			int fd1 = fileno(file1);
			int fd2 = fileno(file2);
			fdatasync(fd1);
			fdatasync(fd2);
    			posix_fadvise(fd1, 0,0,POSIX_FADV_DONTNEED);
			posix_fadvise(fd2, 0,0,POSIX_FADV_DONTNEED);
			fclose(file1);
			fclose(file2);
		#endif	
		*/

	}
	else {
		if(level == -1) {
			for(uint8_t i = 0;i<D_level+1;i++) {
				memcpy(inmem_tree+(bucket_size*(temp-1)),path_iter,bucket_size);
				memcpy(inmem_hash+(HASH_LENGTH*(temp-1)),path_hash_iter,HASH_LENGTH);
				path_iter += bucket_size;
				path_hash_iter+=HASH_LENGTH;	
				temp = temp>>1;		
			}	
		}
		else {
			//printf("size_for_level = %d\n",size_for_level);	
			for(uint8_t i = 0;i<D_level+1;i++) {
				memcpy(inmem_tree_l[level]+((Z*size_for_level)*(temp-1)),path_iter,(Z*size_for_level));
				#ifndef PASSIVE_ADVERSARY				
					memcpy(inmem_hash_l[level]+(HASH_LENGTH*(temp-1)),path_hash_iter,HASH_LENGTH);
                    /*
                    printf("LS_UploadPath : Level = %d, Bucket no = %d, Hash = ",level, temp);
                    for(uint8_t l = 0;l<HASH_LENGTH;l++)
                      printf("%c",(*(path_hash_iter + l) %26)+'A');
                    printf("\n");
                    */
					path_hash_iter+=HASH_LENGTH;
				#endif
				
				/*
				//DEBUG module				
				uint32_t* iter_ptr = (uint32_t*) path_iter;
				for(uint8_t q = 0; q<Z; q++){
					printf("in LS (uploadPath) : (%d,%d)\n",iter_ptr[4],iter_ptr[5]);
				
					iter_ptr += 6;
					for(uint8_t j = 0 ; j<16;j++){
						printf("%d,", *iter_ptr);
						iter_ptr+=1;
					}
					printf("\n");
					
					iter_ptr+=22;
				}
				*/	
                
                
				path_iter+=(Z*size_for_level);	
				temp = temp>>1;		

			}
			//printf("UploadPath success\n");
			
		}	
	}
	
	/*
	#ifdef FILESTREAM_MODE
		#ifdef NO_CACHING
			if(level == recursion_levels && inmem==false) {
				system("sudo sync");
			}
		#endif
	#endif
	*/
	return 0;
}


unsigned char* LocalStorage::downloadObject(unsigned char* data,uint32_t objectKey,unsigned char *hash, uint32_t hashsize, uint32_t size_for_level, uint32_t recursion_level)
{
	//std::string fp = directoryFP + std::to_string(objectKey);
	//unsigned char* data = (unsigned char*) malloc(dataSize * Z);
	
	std::string file_name_this, file_name_this_i;

	if(!inmem) {
		if(recursion_level!=-1)	{
			file_name_this = file_name + "p" + std::to_string(recursion_level); 
			file_name_this_i = file_name_this + "_i";
		}
		else {
			file_name_this = file_name;	
			file_name_this_i = file_name_i;
		}	
	}

	try {
		//printf("Name: %s, Pos : %d\n", file_name_this.c_str(),(objectKey-1)*Z*size_for_level);
		std::ifstream file(file_name_this.c_str(),std::ios::binary);
		file.seekg((objectKey-1)*(Z*size_for_level));
		file.read((char*) data, (Z*size_for_level));
		file.close();
			
		/*
		//Debug Module :
		uint32_t *printer = (uint32_t*)data;
		printf("AFTER READ : ");		
		for(uint8_t e = 0;e < Z ;e++) {
			printer+=4;
			printf("(%d,%d) , ", *printer, *(printer+1));
			printer = (uint32_t*) (data + (e+1)*size_for_level);
		}
		printf("\n");
		*/
		
		file.open(file_name_this_i.c_str(),std::ios::binary);
		file.seekg((objectKey-1)*hashsize);
		file.read((char*) hash, hashsize);
		file.close();
	}
	catch (std::ifstream::failure e) {
		std::cerr <<"Exception opening file";
	}

	return data;

}
/*
LocalStorage::downloadPath() - returns requested path in *path

Requested path is returned leaf to root.
For each node on path, returned path_hash contains <L-hash, R-Hash> pairs with the exception of a single hash for root node

*/

unsigned char* LocalStorage::downloadPath(unsigned char* path, uint32_t leafLabel, unsigned char *path_hash, uint32_t path_hash_size,uint32_t level, uint32_t D_lev)
{
	uint64_t pos;
	std::string file_name_this, file_name_this_i;
	uint32_t size_for_level = dataSize;

	if(!inmem) {
		if(level!=-1)	{
			file_name_this = file_name + "p" + std::to_string(level); 
			file_name_this_i = file_name_this + "_i";	
			if(level==recursion_levels)
				size_for_level = dataSize;
			else
				size_for_level = recursionBlockSize;
		}
		else {
			file_name_this = file_name;	
			file_name_this_i = file_name_i;
		}	
	}
	else{
		if(level==-1) {
			size_for_level = dataSize;
		}
		else{
			if(level==recursion_levels)
				size_for_level = dataSize;
			else
				size_for_level = recursionBlockSize;
		}
	}

	uint32_t temp = leafLabel;
	unsigned char* path_iter = path;
	unsigned char* path_hash_iter = path_hash;	

	if(inmem == false) {
		//printf("Fetched Path in LS : \n");
		#ifdef PRINT_BUCKETS
			printf("IN LS : Buckets Accessed : \n");
		#endif
		for(uint8_t i =0;i<D_lev+1;i++) {
	
			try {

				uint32_t temp_sib;
				#ifdef SYSOPEN_MODE
					system("echo 1 > /proc/sys/vm/drop_caches");
					system("echo 2 > /proc/sys/vm/drop_caches");
					system("echo 3 > /proc/sys/vm/drop_caches");
					int filedesc;
					//printf("DP : FILE_DESC_MODE\n");
					//printf("USING SYSCALL OPEN");
					filedesc = open(file_name_this.c_str(), O_RDONLY|O_DIRECT);
					pos = (temp-1)*(size_for_level*Z);
					pread(filedesc,path_iter,(size_for_level*Z),pos);
				
					//Print contents to TEST
					uint32_t *labelptr = (uint32_t*) (path_iter+16);
					printf("(%d,%d) \n",*labelptr,*(labelptr+4));
	
					path_iter+=(size_for_level*Z);
					//posix_fadvise(filedesc,pos,(size_for_level*Z),POSIX_FADV_DONTNEED);
					posix_fadvise(filedesc,0,datatree_size,POSIX_FADV_DONTNEED);
					syncfs(filedesc);
					close(filedesc);

					//printf("DP : FILE_DESC_BASE DONE\n");					
					
					if(temp==1) {
						filedesc = open(file_name_this_i.c_str(), O_RDONLY|O_DIRECT);
						pread(filedesc,path_hash_iter,HASH_LENGTH,(temp-1)*HASH_LENGTH);
						path_hash_iter+=(HASH_LENGTH);
						close(filedesc);					
					}
					else {
						if(temp%2 ==0)
							temp_sib = temp+1;
						else	{
							temp_sib = temp;
							temp = temp - 1;			
						}

						filedesc = open(file_name_this_i.c_str(), O_RDONLY|O_DIRECT);
						pread(filedesc,path_hash_iter,HASH_LENGTH,(temp-1)*HASH_LENGTH);
						path_hash_iter+=(HASH_LENGTH);
					
						pread(filedesc,path_hash_iter,HASH_LENGTH,(temp_sib-1)*HASH_LENGTH);
						path_hash_iter+=(HASH_LENGTH);
						posix_fadvise(filedesc,(temp-1)*HASH_LENGTH,HASH_LENGTH*2,POSIX_FADV_DONTNEED);
						close(filedesc);

					}

				#elif FILE_DESC_MODE
						FILE *file;
						file = fopen(file_name_this.c_str(),"rb");
						pos = (temp-1)*(size_for_level*Z);
						fseek(file, pos, SEEK_SET);
						fread(path_iter, 1, (size_for_level*Z), file);
			
						//Print contents to TEST
						uint32_t *labelptr = (uint32_t*) (path_iter+16);
						printf("%d - (%d,%d) \n",temp,*labelptr,*(labelptr+1));

						path_iter+=(size_for_level*Z);
						fflush(file);
						fclose(file);

						//printf("DP : FILE_DESC_BASE DONE\n");					
					
						if(temp==1) {
							file = fopen(file_name_this_i.c_str(),"rb");
							fseek(file, (temp-1)*HASH_LENGTH, SEEK_SET);
							fread(path_hash_iter, 1, HASH_LENGTH, file);
							path_hash_iter+=(HASH_LENGTH);
							fclose(file);					
						}
						else {
							if(temp%2 ==0)
								temp_sib = temp+1;
							else	{
								temp_sib = temp;
								temp = temp - 1;			
							}

							file = fopen(file_name_this_i.c_str(),"rb");
							fseek(file,(temp-1)*HASH_LENGTH, SEEK_SET);					
							fread(path_hash_iter, 1, HASH_LENGTH,file);
							path_hash_iter +=(HASH_LENGTH);
							//fclose(file);

							//file = fopen(file_name_this_i.c_str(),"rb");
							//fseek(file,(temp_sib-1)*HASH_LENGTH,SEEK_SET);
							fread(path_hash_iter, 1, HASH_LENGTH, file);
							path_hash_iter +=(HASH_LENGTH);
							fflush(file);
							fclose(file);
						}

				#else

										
					#ifdef CACHE_UPPER
						if(level==recursion_levels){
							if(temp > objectkeylimit){			
								uint32_t adjusted_temp = temp - objectkeylimit - 1;
								FILE *file;
								file = fopen(file_name_this.c_str(),"rb");
								pos = (uint64_t)(adjusted_temp)*(uint64_t)(size_for_level*Z);
								fseek(file, pos, SEEK_SET);
								fread(path_iter, 1, (size_for_level*Z), file);
								path_iter+=(Z*size_for_level);
								fclose(file);								
								
							}	
							else{
								pos = (uint64_t)(temp-1)*(uint64_t)(size_for_level*Z);
								memcpy(path_iter,(inmem_tree_l[level])+pos,(Z*size_for_level));
								path_iter+=(Z*size_for_level);								
							}

							#ifdef PRINT_BUCKETS
								std::cout<<temp<<","<<pos<<"\n";
								//printf("%d,%ld\n",temp,pos);
							#endif
							//Common integrity tree part
							if(temp==1){
								memcpy(path_hash_iter, inmem_hash_l[level]+(HASH_LENGTH*(temp-1)),HASH_LENGTH);
								path_hash_iter +=(HASH_LENGTH);
							}
							else{
								if(temp%2 ==0)
									temp_sib = temp+1;
								else	{
									temp_sib = temp;
									temp = temp - 1;			
								}
								memcpy(path_hash_iter, inmem_hash_l[level]+(HASH_LENGTH*(temp-1)),HASH_LENGTH);
								path_hash_iter +=(HASH_LENGTH);
								memcpy(path_hash_iter, inmem_hash_l[level]+(HASH_LENGTH*(temp_sib-1)),HASH_LENGTH);
								path_hash_iter +=(HASH_LENGTH);
							}
						}	
						else{
							uint64_t post = (Z*size_for_level)*(temp-1);
							#ifdef PRINT_BUCKETS
								std::cout<<temp<<","<<post<<"\n";
								//printf("%d,%ld",temp,post);
							#endif
							memcpy(path_iter,inmem_tree_l[level]+((Z*size_for_level)*(temp-1)),(Z*size_for_level));
							memcpy(path_hash_iter, inmem_hash_l[level]+(HASH_LENGTH*(temp-1)),HASH_LENGTH);
							path_iter += (Z*size_for_level);
							path_hash_iter+=HASH_LENGTH;	
						}
					#else
						pos = (uint64_t)(temp-1)*(uint64_t)(Z*size_for_level);
						#ifdef PRINT_BUCKETS
							//printf("(%d,%ld)\n",temp,pos);
							std::cout<<"("<<temp<<","<<pos<<")\n";
						#endif
						//printf("Level : %d, %s, Pos : %ld, bucket_label = %d\n",level, file_name_this.c_str(),pos, temp-1);
						//std::string fp = directoryFP + std::to_string(temp);
						std::ifstream file(file_name_this.c_str(),std::ios::binary);
						file.seekg(pos);
						file.read((char*) path_iter, (Z*size_for_level));
						path_iter +=(Z*size_for_level);
						file.close();
				
						/*
						//Print Path for Debugging :
						if(level!=recursion_levels) {
							uint32_t *print_iter = (uint32_t*) (path_iter - (Z*size_for_level));
							for(uint8_t q = 0 ;q < Z ;q++) {
								print_iter+=4;
								printf("(%d,%d) : ",*print_iter,*(print_iter+1));
								print_iter+=2;
								for(uint8_t p = 0;p<16;p++) {
									printf(" %d, ", *print_iter);
									print_iter+=1;
								}
						
								printf("\n");				
							}
						}		
				
						unsigned char *path_debug = path_iter-(Z*size_for_level);
						uint32_t *printer = (uint32_t*) path_debug;
						printer+=4;
						for(uint8_t e = 0 ;e < Z;e++) {
							printf("(%d,%d) , ", *printer,*(printer+1));				
						}
						printf("\n");	
						*/	
	
						if(temp==1) {
							//std::string fp_i1 = directoryFP_i + std::to_string(temp);
							//printf("%s\n",fp_i1.c_str());
							file.open(file_name_this_i.c_str(),std::ios::binary);
							file.seekg((temp-1)*HASH_LENGTH);
							file.read((char*) path_hash_iter, HASH_LENGTH);
							path_hash_iter +=(HASH_LENGTH);
							file.close();					
						}
						else {
							if(temp%2 ==0)
								temp_sib = temp+1;
							else	{
								temp_sib = temp;
								temp = temp - 1;			
							}

							//std::string fp_i1 = directoryFP_i + std::to_string(temp);
							//printf("%s\n",fp_i1.c_str());
							file.open(file_name_this_i.c_str(),std::ios::binary);
							file.seekg((temp-1)*HASH_LENGTH);					
							file.read((char*) path_hash_iter, HASH_LENGTH);
							path_hash_iter +=(HASH_LENGTH);
							//file.close();

							//std::string fp_i2 = directoryFP_i + std::to_string(temp_sib);
							//printf("%s\n",fp_i2.c_str());
							//file.open(file_name_this_i.c_str(),std::ios::binary);
							//file.seekg((temp_sib-1)*HASH_LENGTH);
							file.read((char*) path_hash_iter, HASH_LENGTH);
							path_hash_iter +=(HASH_LENGTH);
							file.close();
						}
					#endif
				#endif
			}
			catch (std::ifstream::failure e) {
					std::cerr <<"Exception opening file";
			}
	
			//if(temp > 0) {temp = ((temp+1)>>1)-1;}
			temp = temp>>1;
		}
		#ifdef PRINT_BUCKETS
			printf("\n");
		#endif
	}
	else {
		if(level == -1) {
			for(uint8_t i = 0;i<D+1;i++) {
				memcpy(path_iter,inmem_tree+((Z*size_for_level)*(temp-1)),(Z*size_for_level));
				#ifndef PASSIVE_ADVERSARY
					memcpy(path_hash_iter, inmem_hash+(HASH_LENGTH*(temp-1)),HASH_LENGTH);
					path_hash_iter+=HASH_LENGTH;				
				#endif
				path_iter += (Z*size_for_level);
				temp = temp>>1;		
			}
		}
		else {	
			for(uint8_t i = 0;i<D_lev+1;i++) {
               		//printf("i = %d, temp = %d\n",i,temp);
				memcpy(path_iter,inmem_tree_l[level]+((Z*size_for_level)*(temp-1)),(Z*size_for_level));
				
				#ifndef PASSIVE_ADVERSARY
					if(i!=D_lev) {
						if(temp%2==0){
							memcpy(path_hash_iter, inmem_hash_l[level]+(HASH_LENGTH*(temp-1)),HASH_LENGTH);
							path_hash_iter+=HASH_LENGTH;
							memcpy(path_hash_iter, inmem_hash_l[level]+(HASH_LENGTH*(temp)),HASH_LENGTH);
							path_hash_iter+=HASH_LENGTH;
							    
							    #ifdef DEBUG_INTEGRITY
								printf("LS : Level = %d, Bucket no = %d, Hash = ",level, temp);
								for(uint8_t l = 0;l<HASH_LENGTH;l++)
								  printf("%c",(*(inmem_hash_l[level]+(HASH_LENGTH*(temp-1)) + l) %26)+'A');
								printf("\nLS : Level = %d, Bucket no = %d, Hash = ",level, temp + 1);
								for(uint8_t l = 0;l<HASH_LENGTH;l++)
								  printf("%c",(*(inmem_hash_l[level]+(HASH_LENGTH*(temp)) + l) %26)+'A');
								printf("\n");
							    #endif
						}
						else{	
							memcpy(path_hash_iter, inmem_hash_l[level]+(HASH_LENGTH*(temp-2)),HASH_LENGTH);
							path_hash_iter+=HASH_LENGTH;
							memcpy(path_hash_iter, inmem_hash_l[level]+(HASH_LENGTH*(temp-1)),HASH_LENGTH);
							path_hash_iter+=HASH_LENGTH;
							    
							    #ifdef DEBUG_INTEGRITY
								printf("LS : Level = %d, Bucket no = %d, Hash = ",level, temp-1);
								for(uint8_t l = 0;l<HASH_LENGTH;l++)
								  printf("%c",(*(inmem_hash_l[level]+(HASH_LENGTH*(temp-2)) + l) %26)+'A');
								printf("\nLS : Level = %d, Bucket no = %d, Hash = ", level, temp);
								for(uint8_t l = 0;l<HASH_LENGTH;l++)
								  printf("%c",(*(inmem_hash_l[level]+(HASH_LENGTH*(temp-1)) + l) %26)+'A');
								printf("\n");
							    #endif
						}					
					}
					else{
						memcpy(path_hash_iter, inmem_hash_l[level]+(HASH_LENGTH*(temp-1)),HASH_LENGTH);
						path_hash_iter+=(HASH_LENGTH);
                        #ifdef DEBUG_INTEGRITY
                            printf("LS : Level = %d, Bucket no = %d, Hash = ",level, temp);
                            for(uint8_t l = 0;l<HASH_LENGTH;l++)
                                printf("%c",(*(inmem_hash_l[level]+(HASH_LENGTH*(temp-1)) + l) %26)+'A');
                            printf("\n");
                        #endif
                                
					}
				#endif				
				
				
				//DEBUG module				
				/*
				uint32_t* iter_ptr = (uint32_t*) path_iter;

				for(uint8_t q = 0; q<Z; q++){
					uint32_t *block = iter_ptr + q*(size_for_level/4) ;
					printf("IN LS , temp = %d : (%d,%d)\n",temp, *(block+4), *(block+5));
											
					//for(uint8_t j = 0 ; j<16;j++){
					//	printf("%d,", *(iter_ptr+6+j));
					//}
					printf("\n");
				}	
				*/

				path_iter += (Z*size_for_level);
				temp = temp>>1;		
			}
		}		
	}
	return path;
}

void LocalStorage::deleteObject()
{

}
void LocalStorage::copyObject()
{

}

