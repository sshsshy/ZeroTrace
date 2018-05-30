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

#include "ORAMTree.hpp"

ORAMTree::ORAMTree(){
	//client_key = (unsigned char*) malloc (KEY_LENGTH);
	//sgx_read_rand(client_key, KEY_LENGTH);
	printf("\n\nORAMTREE CONSTRUCTOR WAS CALLED\n\n");
	aes_key = (unsigned char*) malloc (KEY_LENGTH);
	sgx_read_rand(aes_key, KEY_LENGTH);
}

void ORAMTree::SampleKey(){
	//client_key = (unsigned char*) malloc (KEY_LENGTH);
	//sgx_read_rand(client_key, KEY_LENGTH);
	printf("\n\nORAMTREE SAMPLEKEY WAS CALLED\n\n");
	aes_key = (unsigned char*) malloc (KEY_LENGTH);
	sgx_read_rand(aes_key, KEY_LENGTH);

	//TODO: Remove Key-Sampling highjack
	for(int i=0; i<KEY_LENGTH;i++)
		aes_key[i]='A';	
}


ORAMTree::~ORAMTree(){
	free(aes_key);
}

void ORAMTree::print_pmap0(){
    uint32_t p = 0;
    printf("Pmap0 = \n");
    while(p<real_max_blocks_level[0]){
        printf("(%d,%d)\n",p,posmap[p]);
        p++;
    }
    printf("\n");
}

void ORAMTree::verifyPath(unsigned char *path_array, unsigned char *path_hash, uint32_t leaf, uint32_t D, uint32_t block_size, uint32_t level) {
	unsigned char *path_array_iter = path_array;
	unsigned char *path_hash_iter = path_hash;
	sgx_sha256_hash_t parent_hash;
	sgx_sha256_hash_t child;
	sgx_sha256_hash_t lchild;
	sgx_sha256_hash_t rchild;
	sgx_sha256_hash_t lchild_retrieved;
	sgx_sha256_hash_t rchild_retrieved;
	sgx_sha256_hash_t parent_hash_retrieved;
	uint32_t temp = leaf;
	uint32_t cmp1, cmp2, cmp, i;	
	//uint32_t D = (uint32_t) ceil(log((double)max_blocks)/log((double)2));
	
	for(i=D+1;i>0;i--) {
		if(i==(D+1)) {
			//No child hashes to compute			
			sgx_sha256_msg(path_array_iter, (block_size*Z), (sgx_sha256_hash_t*)child);
			path_array_iter+=(block_size*Z);		
			memcpy((uint8_t*)lchild_retrieved, path_hash_iter, HASH_LENGTH);
			path_hash_iter+=HASH_LENGTH;
			memcpy((uint8_t*)rchild_retrieved, path_hash_iter, HASH_LENGTH);
			path_hash_iter+=HASH_LENGTH;

			if(temp%2==0) {
				cmp1 = memcmp((uint8_t*)child,(uint8_t*)lchild_retrieved,HASH_LENGTH);			
			}
			else {
				cmp1 = memcmp((uint8_t*)child,(uint8_t*)rchild_retrieved,HASH_LENGTH);
			}
			
			#ifdef DEBUG_INTEGRITY
				if(cmp1==0){
					printf("Verification Successful at leaf\n");			
				}	
				else {				
					printf("\n Computed child hash value : ");				
					for(uint8_t l = 0;l<HASH_LENGTH;l++)
						printf("%c",(child[l]%26)+'A');
					printf("\n Lchild_retrieved :");
					for(uint8_t l = 0;l<HASH_LENGTH;l++)
						printf("%c",(lchild_retrieved[l]%26)+'A');
					printf("\n Rchild_retrieved :");
					for(uint8_t l = 0;l<HASH_LENGTH;l++)
						printf("%c",(rchild_retrieved[l]%26)+'A');
					printf("\nFAIL_1:%d",cmp1);
                    printf("\n");
				}
			#endif
		}	
		else if(i==1){
			//No sibling child	
			sgx_sha_state_handle_t p_sha_handle;
			sgx_sha256_init(&p_sha_handle);
			sgx_sha256_update(path_array_iter, (block_size*Z), p_sha_handle);
			path_array_iter+=(block_size*Z);
			sgx_sha256_update((uint8_t*)lchild_retrieved, SGX_SHA256_HASH_SIZE, p_sha_handle);
			sgx_sha256_update((uint8_t*)rchild_retrieved, SGX_SHA256_HASH_SIZE, p_sha_handle);
			sgx_sha256_get_hash(p_sha_handle, (sgx_sha256_hash_t*)parent_hash);
			sgx_sha256_close(p_sha_handle);

			//Fetch retreived root hash :
			memcpy((uint8_t*)parent_hash_retrieved, path_hash_iter, HASH_LENGTH);
			path_hash_iter+=HASH_LENGTH;
			// Test if retrieved merkle_root_hash of tree matches internally stored merkle_root_hash 
			// If retrieved matches internal, then computed merkle_root_hash should match as well for free.
			
			if(level==-1){			
				cmp = memcmp((uint8_t*)parent_hash_retrieved, (uint8_t*)merkle_root_hash,HASH_LENGTH);
			}
			else {
				cmp = memcmp((uint8_t*)parent_hash_retrieved, (uint8_t*)merkle_root_hash_level[level],HASH_LENGTH); 	
			}		
			#ifdef DEBUG_INTEGRITY
				if(cmp!=0){
						printf("\nROOT_COMPUTED:");				
						for(uint8_t l = 0;l<HASH_LENGTH;l++)
							printf("%c",(parent_hash[l]%26)+'A');
						printf("\nROOT_RETRIEVED:");
						for(uint8_t l = 0;l<HASH_LENGTH;l++)
							printf("%c",(parent_hash_retrieved[l]%26)+'A');
						printf("\nROOT_MERKLE_LOCAL:");
						for(uint8_t l = 0;l<HASH_LENGTH;l++){
							if(level==-1)							
								printf("%c",(merkle_root_hash[l]%26)+'A');
							elseF
								printf("%c",(merkle_root_hash_level[level][l]%26)+'A');						
						}
						printf("\nFAIL_ROOT:%d\n",cmp);
				}
				else
				{
					printf("\nVERI-SUCCESS!\n");	
					printf("\nROOT_COMPUTED:");				
					for(uint8_t l = 0;l<HASH_LENGTH;l++)
						printf("%c",(parent_hash[l]%26)+'A');
					printf("\nROOT_RETRIEVED:");
					for(uint8_t l = 0;l<HASH_LENGTH;l++)
						printf("%c",(parent_hash_retrieved[l]%26)+'A');
					printf("\nROOT_MERKLE_LOCAL:");
					for(uint8_t l = 0;l<HASH_LENGTH;l++)
						printf("%c",(merkle_root_hash_level[level][l]%26)+'A');
                    printf("\n");
				}		
			#endif
		}
		else {			
			sgx_sha_state_handle_t p_sha_handle;
			sgx_sha256_init(&p_sha_handle);
			sgx_sha256_update(path_array_iter, (block_size*Z), p_sha_handle);
			path_array_iter+=(block_size*Z);
			sgx_sha256_update((uint8_t*)lchild_retrieved, SGX_SHA256_HASH_SIZE, p_sha_handle);
			sgx_sha256_update((uint8_t*)rchild_retrieved, SGX_SHA256_HASH_SIZE, p_sha_handle);
			sgx_sha256_get_hash(p_sha_handle, (sgx_sha256_hash_t*) parent_hash);
			sgx_sha256_close(p_sha_handle);			

			//Children hashes for next round	
			memcpy((uint8_t*)lchild_retrieved, path_hash_iter, HASH_LENGTH);
			path_hash_iter+=HASH_LENGTH;
			memcpy((uint8_t*)rchild_retrieved, path_hash_iter, HASH_LENGTH);
			path_hash_iter+=HASH_LENGTH;
			
			#ifdef DEBUG_INTEGRITY
				printf("\nlchild_of_next_round=");
				for(uint8_t l = 0;l<HASH_LENGTH;l++){				
						printf("%c",(lchild_retrieved[l]%26)+'A');
							
				}			
				printf("\nrchild_of_next_round=");	
				for(uint8_t l = 0;l<HASH_LENGTH;l++){
						printf("%c",(rchild_retrieved[l]%26)+'A');								
				}			
				printf("\ncomputed_parent:");	
				for(uint8_t l = 0;l<HASH_LENGTH;l++)
					printf("%c",(parent_hash[l]%26)+'A');
				printf("\n");		
			#endif		
	
			if(temp%2==0)
				cmp = memcmp((uint8_t*)lchild_retrieved, (uint8_t*)parent_hash, HASH_LENGTH);
			else
				cmp = memcmp((uint8_t*)rchild_retrieved, (uint8_t*)parent_hash, HASH_LENGTH);	
		}
		temp = temp>>1;
	}
}

void ORAMTree::decryptPath(unsigned char* path_array, unsigned char *decrypted_path_array, uint32_t num_of_blocks_on_path, uint32_t data_size) {
	unsigned char *path_iter = path_array;
	unsigned char *decrypted_path_iter = decrypted_path_array;

	for(uint32_t i =0;i<num_of_blocks_on_path;i++) {
		#ifdef ENCRYPTION_ON
			#ifdef AES_NI
				//block.cwf_aes_ebc_dec(extblock_size-24);			
			#else
				aes_dec_serialized(path_iter, data_size, decrypted_path_iter, aes_key);
			#endif
		#endif

		path_iter +=(data_size+ADDITIONAL_METADATA_SIZE);
		decrypted_path_iter +=(data_size+ADDITIONAL_METADATA_SIZE);
	}
}

void ORAMTree::encryptPath(unsigned char* path_array, unsigned char *encrypted_path_array, uint32_t num_of_blocks_on_path, uint32_t data_size) {
	unsigned char *path_iter = path_array;
	unsigned char *encrypted_path_iter = encrypted_path_array;

	for(uint32_t i =0;i<num_of_blocks_on_path;i++) {
		#ifdef ENCRYPTION_ON
			#ifdef AEI
				//block.cwf_aes_ebc_dec(extblock_size-24);			
			#else
				aes_enc_serialized(path_iter, data_size, encrypted_path_iter, aes_key);
			#endif
		#endif
		path_iter +=(data_size + ADDITIONAL_METADATA_SIZE);
		encrypted_path_iter +=(data_size + ADDITIONAL_METADATA_SIZE);
	}
}


void ORAMTree::BuildTreeRecursive(int32_t level, uint32_t *prev_pmap){	
	if(level == 0) {
		uint32_t max_blocks_local;
		if(recursion_levels!=-1)
			max_blocks_local = real_max_blocks_level[level];
		else
			max_blocks_local = max_blocks;

		uint32_t *posmap_l = (uint32_t *) malloc( max_blocks_local * sizeof(uint32_t) );

		#ifdef BUILDTREE_DEBUG
			printf("BUILDTREE_DEBUG : Level 0 :\n");				
		#endif			

		if(recursion_levels!=-1) {
			memcpy(posmap_l, prev_pmap, real_max_blocks_level[level] * sizeof(uint32_t));
			D_level[level] = 0;
			N_level[level] = max_blocks_level[level];		
		}		
		posmap = posmap_l;

		#ifdef DEBUG_INTEGRITY
			if(recursion_levels!=-1) {
				printf("The Merkle Roots are :\n");
				for(uint32_t i=1; i<=recursion_levels; i++){
					printf("Level %d : ",i);
					for(uint32_t l=0; l<HASH_LENGTH; l++){
						printf("%c",(merkle_root_hash_level[i][l]%26)+'A');												
					}
					printf("\n");					
				}
			}
		#endif
	}
	else {
		uint32_t tdata_size;
		uint32_t block_size;

		uint32_t util_divisor = Z;
		uint32_t pD_temp = ceil((double)max_blocks_level[level]/(double)util_divisor);
		uint32_t pD = (uint32_t) ceil(log((double)pD_temp)/log((double)2));
		uint32_t pN = (int) pow((double)2, (double) pD);
		uint32_t ptreeSize = 2*pN-1;	
		D_level[level] = pD;
		N_level[level] = pN;

		#ifdef BUILDTREE_DEBUG				
			printf("\n\nBuildTreeRecursive,\nLevel : %d, Params - D = %d, N = %d, treeSize = %d, x = %d\n",level,pD,pN,ptreeSize,x);
		#endif

		if(level==recursion_levels) {
			tdata_size = data_size;	
			block_size = (data_size+ADDITIONAL_METADATA_SIZE);		
		}
		else {	
			tdata_size = recursion_data_size;
			block_size = recursion_data_size + ADDITIONAL_METADATA_SIZE;
		}						

		uint32_t *posmap_l = (uint32_t *) malloc(max_blocks_level[level] * sizeof(uint32_t));
		if(posmap_l==NULL) {
			printf("Failed to allocate\n");
		}

		uint32_t hashsize = HASH_LENGTH;
		unsigned char* hash_lchild = (unsigned char*) malloc(HASH_LENGTH);	
		unsigned char* hash_rchild = (unsigned char*) malloc(HASH_LENGTH);
		uint32_t blocks_per_bucket_in_ll = real_max_blocks_level[level]/pN;

		#ifdef BUILDTREE_DEBUG
			printf("Posmap Size = %f MB\n",float(max_blocks_level[level]*sizeof(uint32_t))/(float(1024*1024)));
			for(uint8_t jk = 0;jk <=recursion_levels; jk++) {
				printf("real_max_blocks_level[%d] = %d \n",jk,real_max_blocks_level[jk]);
			}
			printf("\n");	
			printf("pN = %d, level = %d, real_max_blocks_level[level] = %d, blocks_per_bucket_in_ll = %d\n",pN, level, real_max_blocks_level[level], blocks_per_bucket_in_ll);
		#endif

		uint32_t c = real_max_blocks_level[level] - (blocks_per_bucket_in_ll * pN);
		uint32_t cnt = 0;

		Bucket temp(Z);
		temp.initialize(tdata_size, gN);
		temp.displayBlocks();

		//Build Last Level of Tree
		uint32_t label = 0;
		for(uint32_t i = pN; i <= ptreeSize; i++) {

			temp.reset_values(gN);

			uint32_t blocks_in_this_bucket = blocks_per_bucket_in_ll;
			if(cnt < c) {
				blocks_in_this_bucket+=1;
				cnt+=1;
			}

			#ifdef BUILDTREE_DEBUG
				printf("Bucket : %d\n", i);
			#endif

			for(uint8_t q=0;q<blocks_in_this_bucket;q++) {	
				temp.blocks[q].id = label;
				temp.blocks[q].treeLabel = i - pN;

				if(level!=recursion_levels) { 	
					#ifdef BUILDTREE_DEBUG										
						printf("Block %d: ",temp.blocks[q].id);
						for(uint8_t p=0;p<x;p++) {
							printf("%d,",(prev_pmap[(label*x)+p]));
						}
						printf("\n");
					#endif
					temp.blocks[q].fill_recursion_data(&(prev_pmap[(label)*x]), recursion_data_size);
				}
				else{
					#ifdef BUILDTREE_DEBUG
						printf("(%d,%d)",temp.blocks[q].id, temp.blocks[q].treeLabel);
					#endif
				}

				posmap_l[temp.blocks[q].id] = temp.blocks[q].treeLabel;
				label++;	
			}

			#ifdef BUILDTREE_DEBUG
				printf("\n");
			#endif

			#ifdef ENCRYPTION_ON
				temp.aes_encryptBlocks(tdata_size, aes_key);
			#endif			
	
			unsigned char *serialized_bucket = temp.serialize(tdata_size);
			uint8_t ret;

			//Hash / Integrity Tree
			sgx_sha256_msg(serialized_bucket, block_size * Z, (sgx_sha256_hash_t*) &(merkle_root_hash_level[level]));

			//Upload Bucket
			uploadObject(&ret, serialized_bucket, Z*block_size ,i, (unsigned char*) &(merkle_root_hash_level[level]), HASH_LENGTH, block_size, level);

			#ifdef BUILDTREE_VERIFICATION_DEBUG
			printf("Level = %d, Bucket no = %d, Hash = ",level, i);
			for(uint8_t l = 0;l<HASH_LENGTH;l++)
			  printf("%c",(merkle_root_hash_level[level][l]%26)+'A');
			printf("\n");
			#endif

			free(serialized_bucket);
		}

		//Build Upper Levels of Tree
		for(uint32_t i = pN - 1; i>=1; i--){
			temp.reset_values(gN);		

			#ifdef ENCRYPTION_ON
				temp.aes_encryptBlocks(tdata_size, aes_key);
			#endif

			unsigned char *serialized_bucket = temp.serialize(tdata_size);
			uint8_t ret;

			//Hash 	
			build_fetchChildHash(i*2, i*2 +1, hash_lchild, hash_rchild, HASH_LENGTH, level);		
			sgx_sha_state_handle_t p_sha_handle;
			sgx_sha256_init(&p_sha_handle);
			sgx_sha256_update(serialized_bucket, block_size * Z, p_sha_handle);					
			sgx_sha256_update(hash_lchild, SGX_SHA256_HASH_SIZE, p_sha_handle);
			sgx_sha256_update(hash_rchild, SGX_SHA256_HASH_SIZE, p_sha_handle);
			sgx_sha256_get_hash(p_sha_handle, (sgx_sha256_hash_t*) merkle_root_hash_level[level]);
			sgx_sha256_close(p_sha_handle);	

			//Upload Bucket 
			uploadObject(&ret, serialized_bucket, Z*block_size ,i, (unsigned char*) &(merkle_root_hash_level[level]), HASH_LENGTH, block_size, level);

			#ifdef BUILDTREE_VERIFICATION_DEBUG
			printf("Level = %d, Bucket no = %d, Hash = ",level, i);
			for(uint8_t l = 0;l<HASH_LENGTH;l++)
			  printf("%c",(merkle_root_hash_level[level][l]%26)+'A');
			printf("\n");
			#endif

			free(serialized_bucket);	
	        }

		free(hash_lchild);
		free(hash_rchild);
		BuildTreeRecursive(level-1, posmap_l);
		if(level!=0)
			free(posmap_l);			
	}
	return;
}

        /*	
        //Testing Module :
        unsigned char *bucket_array = (unsigned char*) malloc(Z*block_size);
        unsigned char *hash = (unsigned char*) malloc(HASH_LENGTH);
        uint8_t rt;
        downloadObject(&rt, bucket_array, Z*block_size, i, hash, HASH_LENGTH,level,D_level[level]);
        Bucket temp2(bucket_array,data_size);
        //Bucket temp3(serialized_bucket, data_size);
        //printf("(%d,%d) \t",temp2.blocks[0].id,temp2.blocks[0].treeLabel);
        temp2.aes_decryptBlocks(data_size);
        temp.aes_decryptBlocks(data_size);
        printf("%d :",i);					
        printf("(%d,%d) - ",temp.blocks[0].id,temp.blocks[0].treeLabel);
        //printf("(%d,%d) - ",temp3.blocks[0].id,temp3.blocks[0].treeLabel);
        //uint32_t *buck_ptr = (uint32_t*)(bucket_array + 16);					
        //printf(" - (%d,%d) - ",*buck_ptr,*(buck_ptr+1));				
        printf("(%d,%d) \n",temp2.blocks[0].id,temp2.blocks[0].treeLabel);
        free(bucket_array);
        */


void ORAMTree::Initialize() {

    if(recursion_levels<0) {
        posmap = (uint32_t*) malloc(max_blocks*sizeof(uint32_t));
	printf("In ORAMTree::Initialize(), Before BuildTreeRecursive\n");
        BuildTree(max_blocks);
	printf("In ORAMTree::Initialize(), After BuildTreeRecursive\n");
    }
    else {
        N_level = (uint64_t*) malloc ((recursion_levels +1) * sizeof(uint64_t));
        D_level = (uint32_t*) malloc ((recursion_levels +1) * sizeof(uint64_t));
        recursive_stash = (Stash *) malloc(sizeof(Stash) * (recursion_levels+1));
        //Fix stash_size for each level
        // 2.19498 log2(N) + 1.56669 * lambda - 10.98615
        printf("RECURSION_LEVELS = %d\n", recursion_levels);
        for(uint32_t i =1;i <=recursion_levels;i++){
		printf("recursion_level i=%d, gN = %d\n",i, gN);
		
		if(i!=recursion_levels){
			if(oblivious_flag)
				recursive_stash[i].setup(stash_size,recursion_data_size, gN);
			else
				recursive_stash[i].setup_nonoblivious(recursion_data_size, gN);
		}
		else{
			if(oblivious_flag)
			        recursive_stash[i].setup(stash_size, data_size, gN);
			else
				recursive_stash[i].setup_nonoblivious(data_size, gN);

		}        
	}
	printf("In ORAMTree::Initialize(), Before BuildTreeRecursive\n");
        BuildTreeRecursive(recursion_levels, NULL);
	printf("In ORAMTree::Initialize(), After BuildTreeRecursive\n");			
    }

	uint32_t d_largest;
	if(recursion_levels==-1)
		d_largest = D;
	else
		d_largest = D_level[recursion_levels];

	//Allocate encrypted_path and decrypted_path to be the largest path sizes the ORAM would ever need
	//So that we dont have to have costly malloc and free within access()
	//Since ZT is currently single threaded, these are shared across all ORAM instances
	//Will have to redesign these to be comoponents of the ORAM_Instance class in a multi-threaded setting.
	//PerformMemoryAllocations()

	uint64_t largest_path_size = Z*(data_size+ADDITIONAL_METADATA_SIZE)*(d_largest+1);
	printf("Z=%d, data_size=%d, d_largest=%d, Largest_path_size = %ld\n", Z, data_size, d_largest, largest_path_size);
	encrypted_path = (unsigned char*) malloc (largest_path_size);
	decrypted_path = (unsigned char*) malloc (largest_path_size);
	fetched_path_array = (unsigned char*) malloc (largest_path_size);
	path_hash = (unsigned char*) malloc (HASH_LENGTH*2*(d_largest+1));
	new_path_hash = (unsigned char*) malloc (HASH_LENGTH*2*(d_largest+1));
	serialized_result_block = (unsigned char*) malloc (data_size+ADDITIONAL_METADATA_SIZE);
}

/*
uint32_t ORAMTree::savePosmap(unsigned char *posmap_serialized, uint32_t posmap_size) {
    uint32_t real_pmap_size;			
    if(recursive_posmap){
        real_pmap_size = max_blocks_level[0]*16;
        //printf("savePosmap : NO_OF_ENTRIES : %d\n",real_pmap_size);
    }		
    else{
        real_pmap_size = max_blocks;
    }
    memcpy(posmap_serialized, posmap, real_pmap_size*4);
    return (real_pmap_size*4);
}
*/
/*
uint32_t saveState(unsigned char *posmap_serialized, uint32_t posmap_size, unsigned char* stash_serialized, uint32_t stash_size) {
        //ASIDE : Test if SGX will fail if posmap_serialized returned a pointer to the posmap in PRM
        memcpy(posmap_serialized, posmap, posmap_size);
        uint32_t stash_size_returned = stash.saveStash(stash_serialized, -1);
        return stash_size_returned;
}
uint32_t restoreState(uint32_t* posmap_stored, uint32_t posmap_size, uint32_t *stash_serialized, uint32_t stash_size)
{
    posmap = (uint32_t*) malloc(posmap_size);
    memcpy(posmap, posmap_stored, posmap_size);
    stash.restoreStash(stash_serialized, stash_size/8);

    node *iter = stash.start;
    while(iter) {
        if(iter->occupied==true&&iter->block->id!=gN){
            printf("%d\n",iter->block->id);
        }				
        iter= iter->next;
    }

    return 1;
}
*/

//For non-recursive level = -1
unsigned char* ORAMTree::ReadBucketsFromPath(uint32_t leaf, unsigned char *path_hash, uint32_t level) {
	uint32_t temp = leaf;
	uint8_t rt;
	uint32_t tdata_size;
	uint32_t path_size, path_hash_size;
	uint32_t D_temp; 

	if(level == -1){
		tdata_size = data_size;
		path_size = Z * (tdata_size+ADDITIONAL_METADATA_SIZE) * (D+1);
		path_hash_size = HASH_LENGTH * 2 * (D+1);
		D_temp = D;		
	}
	else {
		if(level==recursion_levels) {
			tdata_size = data_size;
		}
		else {
			tdata_size = recursion_data_size;
		}
		path_size = Z * (tdata_size+ADDITIONAL_METADATA_SIZE)* (D_level[level]+1);
		path_hash_size = HASH_LENGTH * 2 * (D_level[level]+1);
		D_temp = D_level[level];
	}		

	#ifdef EXITLESS_MODE
		//while( !(*(req_struct->block)) ) {}
		*(req_struct->id) = leaf;
		*(req_struct->level) = level;
		*(req_struct->d_lev) = D_level[level];
		*(req_struct->recursion) = true;
		*(req_struct->block) = false;			

		while( !(*(req_struct->block)) ) {} // Wait til spinlock is set to true by RequestHandler thread

		fetched_path_array = resp_struct->path;
		// NOTE DO NOT FREE THESE IN EXITLESS MODE
		//Set path_array from resp_struct					
	#else
		downloadPath(&rt, fetched_path_array, path_size, leaf, path_hash, path_hash_size, level, D_temp);
	#endif

	#ifndef PASSIVE_ADVERSARY
		verifyPath(fetched_path_array,path_hash,leaf,D_temp,tdata_size + ADDITIONAL_METADATA_SIZE, level);
	#endif

	#ifdef ACCESS_DEBUG
		printf("Verified path \n");
	#endif

	#ifdef ENCRYPTION_ON
		decryptPath(fetched_path_array,decrypted_path,(Z*(D_temp+1)),tdata_size);
	#else
		decrypted_path = fetched_path_array;			
	#endif

	#ifdef ACCESS_DEBUG
		printf("Decrypted path \n");
	#endif

	#ifdef ENCRYPTION_ON
		return decrypted_path;
	#else
		return fetched_path_array;
	#endif
}

void ORAMTree::CreateNewPathHash(unsigned char *path_ptr, unsigned char *old_path_hash, unsigned char *new_path_hash, uint32_t leaf, uint32_t block_size, uint32_t D_level, uint32_t level){
    uint32_t leaf_temp = leaf;
    uint32_t leaf_temp_prev = leaf;
    unsigned char *new_path_hash_trail = new_path_hash;

        for(uint8_t i = 0;i < D_level+1;i++){

            if(i==0){
                sgx_sha256_msg(path_ptr, (block_size*Z), (sgx_sha256_hash_t*) new_path_hash);
                path_ptr+=(block_size*Z);
                new_path_hash_trail = new_path_hash;
                new_path_hash+=HASH_LENGTH;
            }
            else{
                sgx_sha_state_handle_t sha_handle;
                sgx_sha256_init(&sha_handle);
                sgx_sha256_update(path_ptr, (block_size*Z), sha_handle);
                path_ptr+=(block_size*Z);
                if(leaf_temp_prev%2==0) {
                    sgx_sha256_update(new_path_hash_trail, HASH_LENGTH, sha_handle);
                    old_path_hash+=HASH_LENGTH;
                    sgx_sha256_update(old_path_hash, HASH_LENGTH, sha_handle);
                    old_path_hash+=HASH_LENGTH;
                }
                else{
                    sgx_sha256_update(old_path_hash, HASH_LENGTH, sha_handle);
                    old_path_hash+=(2*HASH_LENGTH);
                    sgx_sha256_update(new_path_hash_trail, HASH_LENGTH, sha_handle);

                }
                sgx_sha256_get_hash(sha_handle, (sgx_sha256_hash_t*) new_path_hash);
                new_path_hash_trail+=HASH_LENGTH;
                if(i==D_level){
                        memcpy(merkle_root_hash_level[level], new_path_hash, HASH_LENGTH);
                }
                new_path_hash+=HASH_LENGTH;
                sgx_sha256_close(sha_handle);
            }

            leaf_temp_prev = leaf_temp;
            leaf_temp = leaf_temp >> 1;
        }

}

void ORAMTree::addToNewPathHash(unsigned char *path_iter, unsigned char* old_path_hash, unsigned char* new_path_hash_trail, unsigned char* new_path_hash, uint32_t level_in_path, uint32_t leaf_temp_prev, uint32_t block_size ,uint32_t D_level, uint32_t level) {
    if(level_in_path==D_level+1) {
        sgx_sha256_msg(path_iter, (block_size*Z), (sgx_sha256_hash_t*) new_path_hash);
        new_path_hash_trail = new_path_hash;
        (new_path_hash)+=HASH_LENGTH;
    }

    else if(level_in_path == 1) {
        sgx_sha_state_handle_t sha_handle;
        sgx_sha256_init(&sha_handle);
        sgx_sha256_update(path_iter, (block_size*Z), sha_handle);
        if(leaf_temp_prev%2 == 0)	{
            sgx_sha256_update(new_path_hash_trail, HASH_LENGTH, sha_handle);
            //Skip left child from old path :	reat				
            (old_path_hash)+=HASH_LENGTH;					
            sgx_sha256_update(old_path_hash, HASH_LENGTH, sha_handle);
            (old_path_hash)+=HASH_LENGTH;				
        }
        else {
            sgx_sha256_update(old_path_hash, HASH_LENGTH, sha_handle);
            (old_path_hash)+=HASH_LENGTH;
            //Skip right child from old path:
            (old_path_hash)+=HASH_LENGTH;
            sgx_sha256_update(new_path_hash_trail, HASH_LENGTH, sha_handle);
        }			

        sgx_sha256_get_hash(sha_handle, (sgx_sha256_hash_t*) new_path_hash);
        new_path_hash_trail = new_path_hash;				
        (new_path_hash)+=HASH_LENGTH;
        #ifdef DEBUG_INTEGRITY
            printf("\nROOT_MERKLE_LOCAL previous:");
            for(uint8_t l = 0;l<HASH_LENGTH;l++){
                if(level==-1)
                    printf("%c",(merkle_root_hash[l]%26)+'A');
                else
                    printf("%c",(merkle_root_hash_level[level][l]%26)+'A');

            }
            if(level==-1)
                memcpy(merkle_root_hash,new_path_hash_trail,HASH_LENGTH);
            else
                memcpy(merkle_root_hash_level[level],new_path_hash_trail,HASH_LENGTH);
            printf("\nROOT_MERKLE_LOCAL afterUpdate:");
            for(uint8_t l = 0;l<HASH_LENGTH;l++){
                if(level==-1)
                    printf("%c",(merkle_root_hash[l]%26)+'A');
                else
                    printf("%c",(merkle_root_hash_level[level][l]%26)+'A');
            }
            printf("\n");
        #endif				
        sgx_sha256_close(sha_handle);				
    }
    else {
        sgx_sha_state_handle_t sha_handle;
        sgx_sha256_init(&sha_handle);
        sgx_sha256_update(path_iter, (block_size*Z), sha_handle);
        if(leaf_temp_prev%2 == 0)	{
            sgx_sha256_update(new_path_hash_trail, HASH_LENGTH, sha_handle);
            //Skip left child from old path :					
            (old_path_hash)+=HASH_LENGTH;					
            sgx_sha256_update(old_path_hash, HASH_LENGTH, sha_handle);
            (old_path_hash)+=HASH_LENGTH;				
        }
        else {
            sgx_sha256_update((old_path_hash), HASH_LENGTH, sha_handle);
            (old_path_hash)+=HASH_LENGTH;
            //Skip right child from old path:
            (old_path_hash)+=HASH_LENGTH;
            sgx_sha256_update(new_path_hash_trail, HASH_LENGTH, sha_handle);
        }			
        sgx_sha256_get_hash(sha_handle, (sgx_sha256_hash_t*) new_path_hash);
        new_path_hash_trail = new_path_hash;				
        new_path_hash+=HASH_LENGTH;
        sgx_sha256_close(sha_handle);
    }					

}

void ORAMTree::PushBlocksFromPathIntoStash(unsigned char* decrypted_path_ptr, uint32_t level, uint32_t data_size, uint32_t block_size, uint32_t D_level, uint32_t id, uint32_t position_in_id, uint32_t *nextLeaf, uint32_t newleaf, uint32_t sampledLeaf, int32_t newleaf_nextlevel) {
    uint32_t i;
    #ifdef ACCESS_DEBUG
        printf("Fetched Path in PushBlocksFromPathIntoStash : \n");
        showPath_reverse(decrypted_path, Z*(D_level+1), data_size);
    #endif

    // FetchBlock Module :
    for(i=0;i< (Z*(D_level+1)); i++) {
        bool dummy_flag = getId(decrypted_path_ptr)==gN;
            if(oblivious_flag) {
                if(recursion_levels!=-1){
                    recursive_stash[level].pass_insert(decrypted_path_ptr,isBlockDummy(decrypted_path_ptr, gN));
                }
                else {							
                    stash.pass_insert(decrypted_path_ptr,isBlockDummy(decrypted_path_ptr,gN));
                }
                setId(decrypted_path_ptr,gN);
            }
            else{
                if(!(isBlockDummy(decrypted_path_ptr,gN)))
                {
                    if(getId(decrypted_path_ptr) == id){
                        setTreeLabel(decrypted_path_ptr, newleaf);

                        //NOTE: if write operator, Write new data to block here.
                        if(level!=recursion_levels) {
                            uint32_t* temp_block_ptr = (uint32_t*) getDataPtr(decrypted_path_ptr);
                            *nextLeaf = temp_block_ptr[position_in_id];
                            if(*nextLeaf > gN || *nextLeaf < 0) {
                                //Pull a random leaf as a temp fix.
                                *nextLeaf = sampledLeaf;
                                //printf("NEXTLEAF : %d, replaced with: %d\n",nextLeaf,newleaf_nextlevel);
                            }
                            temp_block_ptr[position_in_id] = newleaf_nextlevel;
                        }
                    }	
                    if(recursion_levels>0) 
                        recursive_stash[level].insert(decrypted_path_ptr);
                    else
                        stash.insert(decrypted_path_ptr);
                }	
            }
        decrypted_path_ptr+=block_size;
    }	
}

//Scan over the stash and fix recustion leaf label
void ORAMTree::OAssignNewLabelToBlock(uint32_t id, uint32_t position_in_id, uint32_t level, uint32_t newleaf, uint32_t newleaf_nextlevel, uint32_t * nextLeaf){
    uint32_t k;
    nodev2 *listptr_t;
    if(recursion_levels>0)
        listptr_t = recursive_stash[level].getStart();		
    else
        listptr_t = stash.getStart();

    for(k=0; k < stash_size; k++)
    {
        bool flag1,flag2 = false;
        flag1 = ( (getId(listptr_t->serialized_block) == id) && (!isBlockDummy(listptr_t->serialized_block,gN)) );
        oassign_newlabel(getTreeLabelPtr(listptr_t->serialized_block),newleaf, flag1);

        #ifdef ACCESS_DEBUG
            if(level != recursion_levels && recursion_levels!=-1){
                //printf("Block %d contents : ", getId(listptr_t->serialized_block));
                if(getId(listptr_t->serialized_block) == id)
                    printf(" New Treelabel = %d\n", getTreeLabel(listptr_t->serialized_block));
                //for(uint8_t p = 0;p< recursion_block_size/4;p++) {
                //	printf("%d,",listptr_t->block->data[p*4]);
                //}
                //printf("\n");
            }
        #endif

        if(level!=recursion_levels && recursion_levels!=-1) {
            for(uint8_t p = 0;p < x;p++) {
                flag2 = (flag1 && (position_in_id == p));
                ofix_recursion( &(listptr_t->serialized_block[24+p*4]), flag2, newleaf_nextlevel, nextLeaf);
                /*
                #ifdef ACCESS_DEBUG						
                    if(getId(listptr_t->serialized_block) == id) {
                        for(uint8_t p = 0;p< recursion_block_size/4;p++) {
                            printf("%d,",listptr_t->serialized_block[24+p*4]);
                        }
                        printf(", nextleaf = %d, flagr = %d\n", *nextLeaf, flagr);
                    }

                #endif
                */
            }
        }
        listptr_t=listptr_t->next;
    }		
}

uint32_t ORAMTree::FillResultBlock(uint32_t id, unsigned char *result_data, uint32_t block_size){
    recursive_stash[recursion_levels].ObliviousFillResultData(id, result_data);
}

//PathORAM_Access(opType, id_adj, id,leaf, newleaf, newleaf_nextleaf,arr_blocks,  path_hash,level,D_level[level],N_level[level]);

/*
uint32_t ORAMTree::access_oram_level(char opType, uint32_t leaf, uint32_t id, uint32_t position_in_id, uint32_t level, uint32_t newleaf,uint32_t newleaf_nextleaf, unsigned char *data_in,  unsigned char *data_out)
{
    uint32_t return_value=-1;
    #ifdef EXITLESS_MODE			
        path_hash = resp_struct->path_hash;
    #endif

    decrypted_path = ReadBucketsFromPath(leaf + N_level[level], path_hash, level);
	
    switch(oram_controller){
        case PATHORAM : return_value = PathORAM_Access(opType, id, position_in_id,leaf, newleaf, newleaf_nextleaf,decrypted_path, 
                                path_hash,level,D_level[level],N_level[level], data_in, data_out); 
                break;
        case CIRCUITORAM: return_value = CircuitORAM_Access(opType, id, position_in_id, leaf, newleaf, newleaf_nextleaf,decrypted_path, 
                                    path_hash,level,D_level[level],N_level[level], data_in, data_out); 
                break;			
    }

    return return_value;		
}
*/
// if target[i] != _|_, then one block should be moved from path[i] to path[target[i]]


//Debug Function to display the count and     stash occupants
void ORAMTree::print_stash_count(uint32_t level, uint32_t nlevel){
    uint32_t stash_oc;
    if(recursion_levels>0){
        stash_oc = recursive_stash[level].stashOccupancy();
        printf("Level : %d, stash_occupancy :%d\n",level,stash_oc);
        recursive_stash[level].displayStashContents(nlevel);
    }			
    else{
        stash_oc = stash.stashOccupancy();
        printf("stash_occupancy :%d\n",stash_oc);
        //recursive_stash[level].displayStashContents();
    }
}

void ORAMTree::showPath(unsigned char *decrypted_path, uint32_t num_of_blocks_on_path, uint32_t data_size) {	
	unsigned char *decrypted_path_iter = decrypted_path;
	uint32_t block_size = data_size + ADDITIONAL_METADATA_SIZE;

	if(data_size == recursion_data_size) {
		for(uint32_t i = 0;i<num_of_blocks_on_path;i++) {
			printf("(%d,%d) :", getId(decrypted_path_iter), getTreeLabel(decrypted_path_iter));
			uint32_t no = (data_size)/sizeof(uint32_t);
			uint32_t* data_iter = (uint32_t*) (decrypted_path_iter + ADDITIONAL_METADATA_SIZE);
					
			for(uint8_t q = 0;q<no;q++)
				printf("%d,",data_iter[q]);	
		
			printf("\n");
			decrypted_path_iter+=block_size;
		}
	} else {
		for(uint32_t i = 0;i<num_of_blocks_on_path;i++) {
			printf("(%d,%d) :",getId(decrypted_path_iter),getTreeLabel(decrypted_path_iter));
			printf("\n");
			decrypted_path_iter+=(block_size);
		}
	}
}

//Debug Function to show a tree path in reverse
void ORAMTree::showPath_reverse(unsigned char *decrypted_path, uint32_t num_of_blocks_on_path, uint32_t data_size) {	
	uint32_t block_size = data_size + ADDITIONAL_METADATA_SIZE;
	unsigned char *decrypted_path_iter = decrypted_path + (num_of_blocks_on_path-1) * block_size;

	if(data_size == recursion_data_size ) {
		for(uint32_t i = 0;i<num_of_blocks_on_path;i++) {
			printf("(%d,%d) :",getId(decrypted_path_iter),getTreeLabel(decrypted_path_iter));
			uint32_t no = (data_size)/sizeof(uint32_t);
			uint32_t* data_iter = (uint32_t*) (decrypted_path_iter + ADDITIONAL_METADATA_SIZE);
					
			for(uint8_t q = 0;q<no;q++)
				printf("%d,",data_iter[q]);	
		
			printf("\n");
			decrypted_path_iter-= block_size;
		}
	} else {
		for(uint32_t i = 0;i<num_of_blocks_on_path;i++) {
			printf("(%d,%d) :",getId(decrypted_path_iter),getTreeLabel(decrypted_path_iter));
			printf("\n");
			decrypted_path_iter-=(block_size);
		}
	}
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
void ORAMTree::SetParams(uint8_t pZ, uint32_t s_max_blocks, uint32_t s_data_size, uint32_t s_stash_size, uint32_t oblivious, uint32_t s_recursion_data_size, int8_t precursion_levels, uint64_t onchip_posmap_mem_limit){
        max_blocks = s_max_blocks;
        data_size = s_data_size;
        stash_size = s_stash_size;
        oblivious_flag = (oblivious==1);
        recursion_data_size = s_recursion_data_size;
        mem_posmap_limit = onchip_posmap_mem_limit;
	recursion_levels = precursion_levels;
	printf("precursion_levels = %d", precursion_levels);
	x = recursion_data_size/sizeof(uint32_t);
	Z = pZ;
        
        if(recursion_levels!=-1) {
            uint64_t size_pmap0 = max_blocks * sizeof(uint32_t);
            uint64_t cur_pmap0_blocks = max_blocks;
            while(size_pmap0 > mem_posmap_limit) {
                cur_pmap0_blocks = (uint64_t) ceil((double)cur_pmap0_blocks/(double)x);
                size_pmap0 = cur_pmap0_blocks * sizeof(uint32_t);
            }

            max_blocks_level = (uint64_t*) malloc((recursion_levels + 1) * sizeof(uint64_t));
            real_max_blocks_level = (uint64_t*) malloc((recursion_levels + 1) * sizeof(uint64_t));
            real_max_blocks_level[recursion_levels] = max_blocks;
            uint32_t lev = recursion_levels-1;
            while(lev > 0) {
                real_max_blocks_level[lev] = ceil((double)real_max_blocks_level[lev+1]/(double) x);
                lev--;
            }	
            real_max_blocks_level[0] = real_max_blocks_level[1];

            #ifdef SET_PARAMETERS_DEBUG
                for(uint8_t j = 0;j <=recursion_levels; j++) {
                    printf("real_max_blocks_level[%d] = %d \n",j,real_max_blocks_level[j]);
                }
                printf("\n");	
            #endif
            
            max_blocks_level[0] = cur_pmap0_blocks;
            max_blocks_level[1] = cur_pmap0_blocks;

            for(uint32_t i = 2;i <= recursion_levels;i++) {			
                max_blocks_level[i] = max_blocks_level[i-1] * x;
            }

            #ifdef SET_PARAMETERS_DEBUG
                for(uint32_t i = 0;i <= recursion_levels;i++) {			
                        printf("ENCLAVE:Level : %d, Blocks : %d\n", i, max_blocks_level[i]);
                }
                printf("\n");
            #endif

            gN = max_blocks_level[recursion_levels];
            merkle_root_hash_level = (sgx_sha256_hash_t*) malloc((recursion_levels +1) * sizeof(sgx_sha256_hash_t));
        }
        else{
            gN = max_blocks;
        } 

}

//Deprecated Functions:


void ORAMTree::BuildTree(uint32_t max_blocks) {	
	uint32_t util_divisor = Z;
	uint32_t pD_temp = ceil((double)max_blocks/(double)util_divisor);
	uint32_t pD = (uint32_t) ceil(log((double)pD_temp)/log((double)2));
	uint32_t pN = (int) pow((double)2, (double) pD);
	uint32_t ptreeSize = 2*pN-1;

	D = pD;
	N = pN;
	treeSize = ptreeSize;
	gN = max_blocks;
	if(oblivious_flag) {
		stash.setup(stash_size, data_size, gN);
	}
	else {
		stash.setup_nonoblivious(data_size, gN);			
	}			

    // TO DO FROM HERE ON : recursive posmap has to use Blocks of different block_size
    // Thus buckets of different types of blocks as well .
	uint32_t hashsize = HASH_LENGTH;

	unsigned char* hash_lchild = (unsigned char*) malloc(HASH_LENGTH);	
	unsigned char* hash_rchild = (unsigned char*) malloc(HASH_LENGTH);
	printf("Params - D = %d, N = %d, treeSize = %d\n",pD,pN,ptreeSize);

	uint32_t blocks_per_bucket_in_ll = max_blocks/pN;
	#ifdef BUILDTREE_DEBUG
	printf("blocks_per_bucket_in_ll = %d\n",blocks_per_bucket_in_ll);
	#endif
	uint32_t c = max_blocks - (blocks_per_bucket_in_ll * pN);
	uint32_t cnt = 0;

	//Build Last level
	uint32_t label = 0;
	for(uint32_t i = pN ; i <= treeSize; i++) {
		#ifdef BUILD_DEBUG
		    printf("Build , Object %d",i);
		#endif
		Bucket temp(Z);
		temp.fill(data_size);
		temp.reset_values(gN);

		uint32_t blocks_in_this_bucket = blocks_per_bucket_in_ll;
		if(cnt < c) {
		    blocks_in_this_bucket+=1;
		    cnt+=1;
	}

        for(uint8_t q=0;q<blocks_in_this_bucket;q++) {	
		temp.blocks[q].id = label;
		temp.blocks[q].treeLabel = i - pN;
		#ifdef BUILDTREE_DEBUG
			printf("%d,",temp.blocks[q].id);
		#endif
		posmap[temp.blocks[q].id] = temp.blocks[q].treeLabel;
		label++;				
        }
        #ifdef BUILDTREE_DEBUG
		printf("\n");
        #endif
        #ifdef ENCRYPTION_ON
		temp.aes_encryptBlocks(data_size, aes_key);
        #endif

        unsigned char *serialized_bucket = temp.serialize(data_size);
        uint8_t ret;

        //Hash / Integrity Tree
        sgx_sha256_msg(serialized_bucket, (data_size+ADDITIONAL_METADATA_SIZE) * Z, (sgx_sha256_hash_t*) &merkle_root_hash);

        //Upload Bucket
        uploadObject(&ret, serialized_bucket, Z*(data_size+ADDITIONAL_METADATA_SIZE) ,i, (unsigned char*) merkle_root_hash, HASH_LENGTH, (data_size+ADDITIONAL_METADATA_SIZE), -1);

        free(serialized_bucket);	
    }

    //Build Upper Levels of Tree
    for(uint32_t i = pN - 1; i>=1; i--){
        //printf("i = %d",i);
	Bucket temp(Z);
	temp.initialize(data_size, gN);
	temp.displayBlocks();		

        #ifdef ENCRYPTION_ON
            temp.aes_encryptBlocks(data_size, aes_key);
        #endif

        unsigned char *serialized_bucket = temp.serialize(data_size);
        uint8_t ret;

        //Hash 	
        build_fetchChildHash(i*2, i*2 +1, hash_lchild, hash_rchild, HASH_LENGTH, -1);		
        sgx_sha_state_handle_t p_sha_handle;
        sgx_sha256_init(&p_sha_handle);
        sgx_sha256_update(serialized_bucket, (data_size+ADDITIONAL_METADATA_SIZE) * Z, p_sha_handle);					
        sgx_sha256_update(hash_lchild, SGX_SHA256_HASH_SIZE, p_sha_handle);
        sgx_sha256_update(hash_rchild, SGX_SHA256_HASH_SIZE, p_sha_handle);
        sgx_sha256_get_hash(p_sha_handle, (sgx_sha256_hash_t*) merkle_root_hash);
        sgx_sha256_close(p_sha_handle);	

        //Upload Bucket 
        uploadObject(&ret, serialized_bucket, Z*(data_size+ADDITIONAL_METADATA_SIZE) ,i, (unsigned char*) merkle_root_hash, HASH_LENGTH, (data_size+ADDITIONAL_METADATA_SIZE), -1);

        free(serialized_bucket);

    }
	/*
        //Testing Module :
        unsigned char *bucket_array = (unsigned char*) malloc(Z*data_size);
        unsigned char *hash = (unsigned char*) malloc(HASH_LENGTH);
        uint8_t rt;
        downloadObject(&rt, bucket_array, Z*data_size, i, hash, HASH_LENGTH, data_size, -1);

        Bucket temp2(bucket_array,g_block_size);
        //printf("(%d,%d) \t",temp2.blocks[0].id,temp2.blocks[0].treeLabel);
        //temp2.aes_decryptBlocks();
        //temp.aes_decryptBlocks();
        printf("%d :",i);					
        printf("(%d,%d) - ",temp.blocks[0].id,temp.blocks[0].treeLabel);				
        printf("(%d,%d) \n",temp2.blocks[0].id,temp2.blocks[0].treeLabel);
        free(bucket_array);
        free(hash);
        */
						
    free(hash_lchild);
    free(hash_rchild);
}
