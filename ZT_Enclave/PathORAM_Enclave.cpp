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

#include "PathORAM_Enclave.hpp"

void oarray_search(uint32_t *array, uint32_t loc, uint32_t *leaf, uint32_t newLabel,uint32_t N_level) {
    for(uint32_t i=0;i<N_level;i++) {
        omove(i,&(array[i]),loc,leaf,newLabel);
    }
    return;
}

PathORAM::PathORAM(uint32_t s_max_blocks, uint32_t s_data_size, uint32_t s_stash_size, uint32_t oblivious, uint32_t s_recursion_data_size, int8_t recursion_levels, uint64_t onchip_posmap_mem_limit){
        max_blocks = s_max_blocks;
        data_size = s_data_size;
        stash_size = s_stash_size;
        oblivious_flag = (oblivious==1);
        recursion_data_size = s_recursion_data_size;
        mem_posmap_limit = onchip_posmap_mem_limit;  
};

void PathORAM::Initialize(uint8_t pZ, uint32_t pmax_blocks, uint32_t pdata_size, uint32_t pstash_size, uint32_t poblivious_flag, uint32_t precursion_data_size, int8_t precursion_levels, uint64_t onchip_posmap_mem_limit){
	printf("In PathORAM::Initialize, Started Initialize\n");
	ORAMTree::SampleKey();	
	ORAMTree::SetParams(pZ, pmax_blocks, pdata_size, pstash_size, poblivious_flag, precursion_data_size, precursion_levels, onchip_posmap_mem_limit);
	ORAMTree::Initialize();
	printf("Finished Initialize\n");
}

/*
void PathORAM::Create(uint32_t max_blocks, uint32_t data_size, uint32_t stash_size, uint32_t oblivious_flag, uint32_t recursion_data_size, int8_t recursion_levels, uint64_t onchip_posmap_mem_limit){
	BuildTreeRecursive((recursion_levels==-1)?0:recursion_levels, NULL);
}
*/

uint32_t PathORAM::access_oram_level(char opType, uint32_t leaf, uint32_t id, uint32_t position_in_id, uint32_t level, uint32_t newleaf,uint32_t newleaf_nextleaf, unsigned char *data_in,  unsigned char *data_out)
{
	uint32_t return_value=-1;
	#ifdef EXITLESS_MODE			
		path_hash = resp_struct->path_hash;
	#endif

	decrypted_path = ReadBucketsFromPath(leaf + N_level[level], path_hash, level);

	return_value = PathORAM_Access(opType, id, position_in_id,leaf, newleaf, newleaf_nextleaf,decrypted_path, 
					path_hash,level,D_level[level],N_level[level], data_in, data_out); 
    return return_value;		
}



uint32_t PathORAM::access(uint32_t id, uint32_t position_in_id, char opType, uint8_t level, unsigned char* data_in, unsigned char* data_out, uint32_t* prev_sampled_leaf){
	uint32_t leaf = 0;
	uint32_t nextLeaf;
	uint32_t id_adj;				
	uint32_t newleaf;
	uint32_t newleaf_nextlevel = -1;
	unsigned char random_value[ID_SIZE_IN_BYTES];

	if(recursion_levels ==  -1) {
		sgx_status_t rt = SGX_SUCCESS;
		rt = sgx_read_rand((unsigned char*) random_value,ID_SIZE_IN_BYTES);
		uint32_t newleaf = *((uint32_t *)random_value) % N;

		if(oblivious_flag) {
			oarray_search(posmap,id,&leaf,newleaf,max_blocks);		
		}
		else{
			leaf = posmap[id];
			posmap[id] = newleaf;			
		}	
		time_report(1);	
	
		decrypted_path = ReadBucketsFromPath(leaf+N, path_hash,-1);			
		PathORAM_Access(opType, id, -1, leaf, newleaf, -1, decrypted_path, path_hash, -1, D, N, data_in, data_out);
	}

	else if(level==0) {
		sgx_read_rand((unsigned char*) random_value, ID_SIZE_IN_BYTES);
		//To slot into one of the buckets of next level
		newleaf = *((uint32_t *)random_value) % (N_level[level+1]);
		*prev_sampled_leaf = newleaf;

		if(oblivious_flag) {
			oarray_search(posmap, id, &leaf, newleaf, real_max_blocks_level[level]);				
		}			
		else {
			leaf = posmap[id];
			posmap[id] = newleaf;
		}

		#ifdef ACCESS_DEBUG
			printf("access : Level = %d: \n Requested_id = %d, Corresponding leaf from posmap = %d, Newleaf assigned = %d,\n\n",level,id,leaf,newleaf);
		#endif				
		return leaf;
	}
	else if(level == 1){
		id_adj = id/x;
		leaf = access(id, -1, opType, level-1, data_in, data_out, prev_sampled_leaf);
		

		//sampling leafs for a level ahead		
		sgx_read_rand((unsigned char*) random_value, ID_SIZE_IN_BYTES);
		newleaf_nextlevel = *((uint32_t *)random_value) % N_level[level+1];					

		#ifdef ACCESS_DEBUG
			printf("access : Level = %d: \n leaf = %d, block_id = %d, position_in_id = %d, newleaf_nextlevel = %d\n",level,leaf,id,position_in_id,newleaf_nextlevel);
		#endif

		nextLeaf = access_oram_level(opType, leaf, id, position_in_id, level, *prev_sampled_leaf, newleaf_nextlevel, data_in, data_out);
		*prev_sampled_leaf = newleaf_nextlevel;

		#ifdef ACCESS_DEBUG
			printf("access, Level = %d (After ORAM access): nextLeaf from level = %d \n\n",level,nextLeaf);
		#endif
		return nextLeaf;
	}
	else if(level == recursion_levels){
		//DataAccess for leaf.
		id_adj = id/x;
		position_in_id = id%x;
		leaf = access(id_adj, position_in_id, opType, level-1, data_in, data_out, prev_sampled_leaf);	
		#ifdef ACCESS_DEBUG					
			printf("access, Level = %d:  before access_oram_level : Block_id = %d, Newleaf = %d, Leaf from level = %d, Flag = %d\n",level,id,*prev_sampled_leaf,leaf,oblivious_flag);
		#endif
		//ORAM ACCESS of recursion_levels is to fetch entire Data block, no position_in_id, hence -1)
		time_report(1);
		access_oram_level(opType, leaf, id, -1, level, *prev_sampled_leaf, -1, data_in, data_out);
		return 0;	
	}
	else{
		id_adj = id/x;
		uint32_t nl_position_in_id = id%x;
		leaf = access(id_adj, nl_position_in_id, opType, level-1, data_in, data_out, prev_sampled_leaf);	
		//sampling leafs for a level ahead
		//random_value = (unsigned char*) malloc(size);					
		sgx_read_rand((unsigned char*) random_value, ID_SIZE_IN_BYTES);
		newleaf_nextlevel = *((uint32_t *)random_value) % N_level[level+1];
		newleaf = *prev_sampled_leaf;					
		*prev_sampled_leaf = newleaf_nextlevel;
		//free(random_value);
		#ifdef ACCESS_DEBUG
			printf("access, Level = %d :\n leaf = %d, block_id = %d, position_in_id = %d, newLeaf = %d, newleaf_nextlevel = %d\n",level,leaf,id,position_in_id,newleaf,newleaf_nextlevel);
		#endif										
		nextLeaf = access_oram_level(opType, leaf, id, position_in_id, level, newleaf, newleaf_nextlevel, data_in, data_out);
		#ifdef ACCESS_DEBUG
			printf("access, Level = %d : \n nextLeaf from level = %d\n",level,nextLeaf);
		#endif
	return nextLeaf;

	}

return nextLeaf;
}	

void PathORAM::Access_temp(uint32_t id, char opType, unsigned char* data_in, unsigned char* data_out){
	uint32_t prev_sampled_leaf=-1;
	access(id, -1, opType, recursion_levels, data_in, data_out, &prev_sampled_leaf);
}


/*
uint32_t ORAMTree::access(uint32_t id, uint32_t position_in_id, char opType, uint32_t level, unsigned char *data_in, unsigned char *data_out){ 
    uint32_t leaf = 0;
    size_t size = 4;
    uint32_t nextLeaf;
    uint32_t id_adj;				
    uint32_t newleaf;
    uint32_t newleaf_nextlevel = -1;

    if(level ==  -1) {
        sgx_status_t rt = SGX_SUCCESS;
        rt = sgx_read_rand((unsigned char*) random_value,ID_SIZE_IN_BYTES);
        uint32_t newleaf = *((uint32_t *)random_value) % N;

        if(oblivious_flag) {
            oarray_search(posmap,id,&leaf,newleaf,max_blocks);		
        }
        else{
            leaf = posmap[id];
            posmap[id] = newleaf;			
        }	
        time_report(1);

        decrypted_path = ReadBucketsFromPath(leaf+N, path_hash,-1);			

        switch(oram_controller){
            case PATHORAM : PathORAM_Access(opType, id, -1, leaf, newleaf, -1, decrypted_path, path_hash, -1, D, N, data_in, data_out); break;
            case CIRCUITORAM : CircuitORAM_Access(opType, id, -1, leaf, newleaf, -1, decrypted_path, path_hash, -1, D, N, data_in, data_out); break;
        }

    }

    else if(level==0) {
        sgx_read_rand((unsigned char*) random_value,size);

        //To slot into one of the buckets of next level
        newleaf = *((uint32_t *)random_value) % (N_level[level+1]);
        l0_newleaf = newleaf;

        if(oblivious_flag) {
            oarray_search(posmap, id, &leaf, newleaf, real_max_blocks_level[level]);				
        }			
        else {
            leaf = posmap[id];
            posmap[id] = newleaf;
        }

        #ifdef ACCESS_DEBUG
            printf("access : Level = %d: \n Requested_id = %d, Corresponding leaf from posmap = %d, Newleaf assigned = %d,\n\n",level,id,leaf,newleaf);
        #endif				
        return leaf;
    }
    else if(level == 1){
        id_adj = id/x;
        leaf = access(id, -1, opType, level-1, data_in, data_out);

        //sampling leafs for a level ahead		
        sgx_read_rand((unsigned char*) random_value,size);
        newleaf_nextlevel = *((uint32_t *)random_value) % N_level[level+1];					
        prev_sampled_leaf = newleaf_nextlevel;

        #ifdef ACCESS_DEBUG
            printf("access : Level = %d: \n leaf = %d, block_id = %d, position_in_id = %d, newleaf_nextlevel = %d\n",level,leaf,id,position_in_id,newleaf_nextlevel);
        #endif

        nextLeaf = access_oram_level(opType, leaf, id, position_in_id, level, l0_newleaf, newleaf_nextlevel, data_in, data_out);

        #ifdef ACCESS_DEBUG
            printf("access, Level = %d (After ORAM access): nextLeaf from level = %d \n\n",level,nextLeaf);
        #endif
        return nextLeaf;

    }
    else if(level == recursion_levels){
        //DataAccess for leaf.
        id_adj = id/x;
        position_in_id = id%x;
        leaf = access(id_adj, position_in_id, opType, level-1, data_in, data_out);	
        #ifdef ACCESS_DEBUG					
            printf("access, Level = %d:  before access_oram_level : Block_id = %d, Newleaf = %d, Leaf from level = %d, Flag = %d\n",level,id,prev_sampled_leaf,leaf,oblivious_flag);
        #endif
        //ORAM ACCESS of recursion_levels is to fetch entire Data block, no position_in_id, hence -1)
        time_report(1);
        access_oram_level(opType, leaf, id, -1, level, prev_sampled_leaf, -1, data_in, data_out);
        return 0;	
    }
    else{
        id_adj = id/x;
        uint32_t nl_position_in_id = id%x;
        leaf = access(id_adj, nl_position_in_id, opType, level-1, data_in, data_out);	
        //sampling leafs for a level ahead
        //random_value = (unsigned char*) malloc(size);					
        sgx_read_rand((unsigned char*) random_value,size);
        newleaf_nextlevel = *((uint32_t *)random_value) % N_level[level+1];
        newleaf = prev_sampled_leaf;					
        prev_sampled_leaf = newleaf_nextlevel;
        //free(random_value);
        #ifdef ACCESS_DEBUG
            printf("access, Level = %d :\n leaf = %d, block_id = %d, position_in_id = %d, newLeaf = %d, newleaf_nextlevel = %d\n",level,leaf,id,position_in_id,newleaf,newleaf_nextlevel);
        #endif										
        nextLeaf = access_oram_level(opType, leaf, id, position_in_id, level, newleaf, newleaf_nextlevel, data_in, data_out);
        #ifdef ACCESS_DEBUG
            printf("access, Level = %d : \n nextLeaf from level = %d\n",level,nextLeaf);
        #endif
        return nextLeaf;

    }

return nextLeaf;
}
*/



uint32_t PathORAM::PathORAM_Access(char opType, uint32_t id, uint32_t position_in_id, uint32_t leaf, uint32_t newleaf, uint32_t newleaf_nextlevel, unsigned char* decrypted_path, unsigned char* path_hash, uint32_t 
level, uint32_t D_level, uint32_t nlevel, unsigned char* data_in, unsigned char *data_out) {
	uint32_t i, nextLeaf = 0;
	uint32_t sampledLeaf;
	bool flag = false;
	bool ad_flag = false;
	unsigned char *decrypted_path_ptr = decrypted_path;
	uint8_t rt;
	unsigned char random_value[ID_SIZE_IN_BYTES];
	sgx_read_rand((unsigned char*) random_value, sizeof(uint32_t));
	if(level!=-1){
		sampledLeaf= *((uint32_t *)random_value) % (N_level[level+1]);
	}			
	else{
		sampledLeaf= *((uint32_t *)random_value) % (nlevel);
	}

	uint32_t tblock_size, tdata_size;
	if(recursion_levels!=-1) {
		if(level==recursion_levels) {
			tblock_size = data_size + ADDITIONAL_METADATA_SIZE;
			tdata_size = data_size;	
		} 
		else {
			tblock_size = recursion_data_size + ADDITIONAL_METADATA_SIZE;				
			tdata_size = recursion_data_size;			
		}
	} 
	else {
		tblock_size = data_size + ADDITIONAL_METADATA_SIZE;
		tdata_size = data_size;			
	}
		
	#ifdef PATH_GRANULAR_IO
		uint32_t leaf_temp_prev = (leaf+nlevel)<<1;
		uint32_t path_size = Z*tblock_size*(D_level+1);
		uint32_t new_path_hash_size = ((D_level+1)*HASH_LENGTH);

		#ifdef EXITLESS_MODE
			serialized_path = resp_struct->new_path;
			new_path_hash = resp_struct->new_path_hash;
		#endif
		unsigned char *new_path_hash_trail = new_path_hash;
		unsigned char *new_path_hash_iter = new_path_hash;
		unsigned char *old_path_hash_iter = path_hash;
	#endif	

	//All real blocks from Path get inserted into stash
	//The real blocks also get their ids replaced with dummy identifier.
	PushBlocksFromPathIntoStash(decrypted_path_ptr, level, tdata_size, tblock_size, D_level, id, position_in_id, &nextLeaf, newleaf, sampledLeaf, newleaf_nextlevel);
            
	if(oblivious_flag) {                
		//TODO Scan Stash and Return Block here !
		if(level == recursion_levels){
			recursive_stash[recursion_levels].PerformAccessOperation(opType, id, newleaf, data_in, data_out);
			//Optional TODO : Add layer of encryption to result, such that only real client (outside server stack) can decrypt.                
		}
		else{
			OAssignNewLabelToBlock(id, position_in_id, level, newleaf, newleaf_nextlevel, &nextLeaf);
		}
	}
    
	#ifdef SHOW_STASH_COUNT_DEBUG
		uint32_t stash_oc;
		if(recursion_levels!=0){
			stash_oc = recursive_stash[level].stashOccupancy();
			printf("Level : %d, Before rebuild stash_oc:%d\n",level,stash_oc);
		}			
		else{
			stash_oc = stash.stashOccupancy();
			printf("Before rebuild stash_oc:%d\n",stash_oc);
			//recursive_stash[level].displayStashContents();
		}
	#endif

	if(recursion_levels!=0) {
		if(level == recursion_levels)
		time_report(2);
	}
	else 
		time_report(2);

			//time_report(4);

			//Reset decrypted_path_ptr for Rebuild
			decrypted_path_ptr = decrypted_path;
			PathORAM_RebuildPath(decrypted_path_ptr, tdata_size, tblock_size, leaf, level, D_level, nlevel);
			
			#ifdef ACCESS_DEBUG
				printf("Final Path after PathORAM_RebuildPath: \n");
				showPath_reverse(decrypted_path, Z*(D_level+1), tdata_size);
			#endif


			#ifdef SHOW_STASH_COUNT_DEBUG
				if(recursion_levels!=-1) {
					stash_oc = recursive_stash[level].stashOccupancy();
					printf("Level : %d , After rebuild stash_oc:%d\n",level,stash_oc);		
				}else {
					stash_oc = stash.stashOccupancy();
					printf("After rebuild stash_oc:%d\n",stash_oc);							
				}
			#endif

			#ifdef SHOW_STASH_CONTENTS
				if(level==recursion_levels)
					recursive_stash[level].displayStashContents(nlevel);
			#endif

			//Encrypt and Upload Path :
			#ifdef PATH_GRANULAR_IO
				#ifdef EXITLESS_MODE
					*(req_struct->block) = false;			
				#else
					#ifdef ENCRYPTION_ON
						encryptPath(decrypted_path, encrypted_path, (Z*(D_level+1)), tdata_size);						
					#endif	

					#ifndef PASSIVE_ADVERSARY
						unsigned char *path_ptr;
						new_path_hash_iter = new_path_hash;
						new_path_hash_trail = new_path_hash;
						old_path_hash_iter = path_hash;		
						unsigned char *new_path_hash_ptr = new_path_hash;
						leaf_temp_prev = (leaf+nlevel)<<1;
						#ifdef ENCRYPTION_ON
							path_ptr = encrypted_path;
						#else
							path_ptr = decrypted_path;
						#endif
            
            
                        uint32_t leaf_adj = leaf + nlevel;
                        CreateNewPathHash(path_ptr, path_hash, new_path_hash, leaf_adj, data_size+ADDITIONAL_METADATA_SIZE, D_level, level);            
                    
                        /*
						for(i=0;i < ( Z * (D_level+1) ); i++) {
							if(i%Z==0) {
								uint32_t p = i/Z;
								addToNewPathHash(path_ptr, old_path_hash_iter, new_path_hash_trail, new_path_hash_iter,(D_level+1)-p, leaf_temp_prev, block_size, D_level, level);
								leaf_temp_prev>>1;
								path_ptr+=(Z*block_size);
							}
						
						}
                        */
            
					#endif
		
					uploadPath(&rt, encrypted_path, path_size, leaf + nlevel, new_path_hash, new_path_hash_size, level, D_level);
				#endif
				
				
			#endif

			//printf("nextLeaf = %d",nextLeaf);
			return nextLeaf;
		}

void PathORAM::PathORAM_RebuildPath(unsigned char* decrypted_path_ptr, uint32_t data_size, uint32_t block_size, uint32_t leaf, uint32_t level, uint32_t D_level, uint32_t nlevel){
	uint32_t prefix;
	uint32_t i,k;
	unsigned char *decrypted_path_bucket_iterator = decrypted_path_ptr;
	unsigned char *decrypted_path_temp_iterator;

	for(i=0;i<D_level+1;i++){
		prefix = ShiftBy(leaf+nlevel,i);
		
		bool flag = false;
		nodev2 *listptr = NULL;
		if(recursion_levels!=-1)
			listptr = recursive_stash[level].getStart();		
		else
			listptr = stash.getStart();
			
		if(oblivious_flag) {
			uint32_t posk = 0;			
			for(k=0; k < stash_size; k++)
			{				
				decrypted_path_temp_iterator = decrypted_path_bucket_iterator;			
				uint32_t jprefix = ShiftBy(getTreeLabel(listptr->serialized_block)+nlevel,i);
				uint32_t sblock_written = false;
			
				bool flag = (posk<Z)&&(prefix==jprefix)&&(!sblock_written)&&(!isBlockDummy(listptr->serialized_block, gN));
				for(uint8_t l=0;l<Z;l++){
					flag = (l==posk)&&(posk<Z) && (prefix==jprefix) && (!sblock_written) && (!isBlockDummy(listptr->serialized_block,gN));
				
					#ifdef PATHORAM_ACCESS_REBUILD_DEBUG
						if(flag){
							printf("Block %d,%d TO Bucket %d\n",getId(listptr->serialized_block),getTreeLabel(listptr->serialized_block),prefix);
						}
					#endif

					omove_serialized_block(decrypted_path_temp_iterator, listptr->serialized_block, data_size, flag);
					oset_value(&sblock_written, 1, flag);
					oset_value(getIdPtr(listptr->serialized_block), gN, flag);
					oincrement_value(&posk, flag);
					decrypted_path_temp_iterator+= block_size;
				}						
				listptr=listptr->next;
			}				
		}			
		else {	
			decrypted_path_temp_iterator = decrypted_path_bucket_iterator;			
			uint32_t posk = 0;
			nodev2 *listptr_prev = NULL, *listptr_prev2 = NULL;
			uint32_t cntr = 0;		

			while(listptr && posk<Z) { 						
				uint32_t jprefix = ShiftBy(getTreeLabel(listptr->serialized_block)+nlevel,i);	
				bool flag = (prefix==jprefix);
				if(flag) {
					memcpy(decrypted_path_temp_iterator, listptr->serialized_block, block_size);	
					if(recursion_levels!=0)
						recursive_stash[level].remove(listptr,listptr_prev);
					else{
						nodev2 *rem_ptr = listptr;
						if(listptr->next!=NULL)
							listptr = listptr->next;
						else
							listptr = NULL; 
						stash.remove(rem_ptr,listptr_prev);						
					}							
					posk++;
					decrypted_path_temp_iterator+= block_size;					
				}					
				if(!flag) {
					listptr_prev2 = listptr_prev;
					listptr_prev = listptr;	
					listptr = listptr->next;
				}				
			}

		}	
	
		/*
		#ifdef ACCESS_DEBUG
			decrypted_path_temp_iterator = decrypted_path_bucket_iterator;
			printf("rearrange : Block contents after oblock_move :\n");
			for(uint8_t e =0;e<Z;e++) {
				printf("(%d,%d) , ",getId(decrypted_path_temp_iterator),getTreeLabel(decrypted_path_temp_iterator));
				decrypted_path_temp_iterator+=block_size;
			}
			printf("\n");
		#endif
		*/

		decrypted_path_bucket_iterator+=(Z*block_size);									
	}
}



