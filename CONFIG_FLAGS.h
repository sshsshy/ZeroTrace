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

#ifndef __ZT_CONFIG_FLAGS__

  #define CHECK_CORRECTNESS
  #define ENCRYPTION_ON 1
  #define SHOW_TIMING_RESULTS 1
  // VERBOSE Adds additional information of intermediate steps status
  //#define VERBOSE 1
  //#define EXITLESS_MODE 1 
  //#define PASSIVE_ADVERSARY 1
   
  // Storage Flags 
    //#define DEBUG_LS 1
    //#define LS_DEBUG_INTEGRITY 1

  // Client Flags
    //#define PRINT_REQ_DETAILS 1

  // Untrusted-(Shim-)layer specific Flags


  //Enclave-specific Flags
    //#define DEBUG_ZT_ENCLAVE 1
    //#define SET_PARAMETERS_DEBUG 1
    //#define BUILDTREE_DEBUG 1
    //#define ACCESS_DEBUG 1
    //#define DEBUG_INTEGRITY 1 
 
    //#define BUILDTREE_VERIFICATION_DEBUG 1
    //#define SHOW_STASH_COUNT_DEBUG 1 
    //#define SHOW_STASH_CONTENTS 1
    //#define DEBUG_EFO 1
    //#define RESULTS_DEBUG 1
    //#define PAO_DEBUG 1

    //#define PATHORAM_ACCESS_REBUILD_DEBUG 1
    #define STASH_OVERFLOW_DEBUG 1 
    //#define ACCESS_CORAM_DEBUG 1
    //#define ACCESS_CORAM_META_DEBUG 1
    //#define ACCESS_CORAM_DEBUG3 1
    //#define ACCCES_DEBUG_EXITLESS 1
    //#define ACCESS_DEBUG_REBUILD 1 

    //#define DEBUG_PRINT 1
  //#define RECURSION_LEVELS_DEBUG 1

    // Linear Scan ORAM
      //#define DEBUG_LSORAM 1
      //#define TEST_CORRECTNESS 1

    // If you want to use a hybrid of Linear Scan and Path/Circuit ORAM
    // Set HSORAM_MODE to 1 and fill out corresponding ORAM parameters in the
    // HSORAM flags below it
      //#define HSORAM_MODE 1

	//HSORAM_FLAGS:
	  #define HSORAM_MAX_BLOCKS 1000
	  #define HSORAM_OBLIVIOUS_TYPE_ORAM 1
	  #define HSORAM_RECURSION_DATA_SIZE 64
	  // PathORAM = 0, Stash size = 100
	  // CircuitORAM = 1, Stash size = 10
	  #define HSORAM_ORAM_TYPE 0
	  #define HSORAM_STASH_SIZE 100
	  #define HSORAM_Z 4
	  #define HSORAM_INDEX_SIZE 4


  //Variable #defines
  //define FLAGS :
   #define TIME_PERFORMANCE 1
  //#define AES_NI 1
  //#define RAND_DATA 1


  enum PATHORAM_TIMER {PO_POSMAP_START, PO_POSMAP_END, PO_DOWNLOAD_PATH_START, PO_DOWNLOAD_PATH_END,
   PO_FETCH_BLOCK_START, PO_FETCH_BLOCK_END, PO_EVICTION_START, PO_EVICTION_END, 
   PO_UPLOAD_PATH_START, PO_UPLOAD_PATH_END};
 
  enum CIRCUITORAM_TIMER {CO_POSMAP_START, CO_POSMAP_END, CO_FETCH_BLOCK_START, CO_FETCH_BLOCK_END,
   CO_DOWNLOAD_PATH_START, CO_DOWNLOAD_PATH_END, CO_UPLOAD_PATH_START, CO_UPLOAD_PATH_END, 
   CO_EVICTION_START, CO_EVICTION_END}; 

  #define __ZT_CONFIG_FLAGS__ 
#endif 
