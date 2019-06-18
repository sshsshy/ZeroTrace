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


#define ANALYSIS 1
#define CLOCKS_PER_MS (CLOCKS_PER_SEC/1000)
#define AES_GCM_BLOCK_SIZE_IN_BYTES 16
#define IV_LENGTH 12
#define ID_SIZE_IN_BYTES 4
#define KEY_LENGTH 16
#define TAG_SIZE 16

#define HYBRID_ENCRYPTION 1
const char SHARED_AES_KEY[KEY_LENGTH] = {"AAAAAAAAAAAAAAA"};
const char HARDCODED_IV[IV_LENGTH] = {"AAAAAAAAAAA"};
const char PUBLISH_FILE_NAME[] = "ENCLAVE_PUBLIC_KEY";
static unsigned char ecdh_shared_aes_key[KEY_LENGTH];
static unsigned char ecdh_shared_iv[IV_LENGTH];
