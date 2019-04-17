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

#ifndef __GLOBALS__
  //Global Flags
  #define ENCRYPTION_ON 1
  //#define EXITLESS_MODE 1 
  //#define PASSIVE_ADVERSARY 1
    

  //Client-specific Flags
  #define ANALYSIS 1


  // Untrusted-(Shim-)layer specifc Flags



  //Enclave-specific Flags


  //DEBUG Flags:
    //Client/Sample: 
   
    //Enclave
    #define DEBUG_ZT_ENCLAVE 1
    #define SET_PARAMETERS_DEBUG 1
    #define BUILDTREE_DEBUG 1
    #define ACCESS_DEBUG 1
    #define DEBUG_INTEGRITY 1 
 
    //#define SET_PARAMETERS_DEBUG 1
    #define BUILDTREE_VERIFICATION_DEBUG 1
    //#define SHOW_STASH_COUNT_DEBUG 1 
    //#define SHOW_STASH_CONTENTS 1
    //#define DEBUG_EFO 1
    //#define RESULTS_DEBUG 1
    //#define PAO_DEBUG 1

    //#define PATHORAM_ACCESS_REBUILD_DEBUG 1
    //#define PATHORAM_STASH_OVERFLOW_DEBUG 1 
    //#define ACCESS_CORAM_DEBUG 1
    //#define ACCESS_CORAM_META_DEBUG 1
    //#define ACCESS_CORAM_DEBUG3 1
    //#define ACCCES_DEBUG_EXITLESS 1
    //#define ACCESS_DEBUG_REBUILD 1 

  //Variable #defines
  //define FLAGS :
   #define TIME_PERFORMANCE 1
  //#define AES_NI 1
  //#define RAND_DATA 1

  // Global Declarations

  #define ADDITIONAL_METADATA_SIZE 24
  #define HASH_LENGTH 32
  #define NONCE_LENGTH 16
  #define KEY_LENGTH 16
  #define MILLION 1E6
  #define IV_LENGTH 12
  #define ID_SIZE_IN_BYTES 4
  #define KEY_LENGTH 16
  #define TAG_SIZE 16
  #define CLOCKS_PER_MS (CLOCKS_PER_SEC/1000)
  #define AES_GCM_BLOCK_SIZE_IN_BYTES 16
  #define PRIME256V1_KEY_SIZE 32



  //Other Global variables

  const char SHARED_AES_KEY[KEY_LENGTH] = {"AAAAAAAAAAAAAAA"};
  const char HARDCODED_IV[IV_LENGTH] = {"AAAAAAAAAAA"};

  //Hard-coded Enclave Signing key
  //This key would ideally be sampled and signed in the Remote attestation phase with a client
  //Currently we use a static hard coded ECDSA key for it.
   
  static unsigned char hardcoded_verification_key_x[PRIME256V1_KEY_SIZE] = 
	  {0x45, 0xb2, 0x00, 0x83, 0x53, 0x11, 0x4b, 0xbb,
	   0x78, 0xeb, 0x67, 0x17, 0xf2, 0xc9, 0x51, 0xe4,
	   0xcc, 0x1d, 0x93, 0x89, 0x0c, 0x70, 0xe1, 0x93,
	   0xcc, 0xd2, 0x83, 0x01, 0x68, 0x61, 0xe6, 0xec};

  static unsigned char hardcoded_verification_key_y[PRIME256V1_KEY_SIZE] =
	  {0xde, 0x24, 0xec, 0x0b, 0xf9, 0x0c, 0x03, 0x27,
	   0xb8, 0x1b, 0x89, 0x40, 0x80, 0x28, 0x54, 0xd8,
	   0xfb, 0xa5, 0xc8, 0x07, 0x57, 0x4c, 0x38, 0xab,
	   0xc3, 0x3e, 0xfb, 0x68, 0x42, 0xd1, 0xa5, 0xcf};

  enum LSORAM_STORAGE_MODES{ INSIDE_PRM, OUTSIDE_PRM};
  enum LSORAM_OBLV_MODES{ACCESS_OBLV, FULL_OBLV};
  enum LSORAM_ERRORCODES{KEY_SIZE_OUT_OF_BOUND, VALUE_SIZE_OUT_OF_BOUND};

  typedef struct{
    unsigned char *key;
    unsigned char *value;
  }tuple;

  #define __GLOBALS__
#endif

