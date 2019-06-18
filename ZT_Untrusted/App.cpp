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
Untrusted Application Code for ZeroTrace
Usage : 
printf("./app <N> <No_of_requests> <Stash_size> <Data_block_size> <"resume"/"new"> <"memory"/"hdd"> <"0"/"1" = Non-oblivious/Oblivious> <Recursion_block_size>");
Note : parameters surrounded by quotes should entered in as is without the quotes.

//META-NOTES :
//_e trailed variables are computed/obtained from enclave
//_p trailed variables are obtained from commandline parameters
*/


#include "App.h"

#define MAX_PATH FILENAME_MAX
#define CIRCUIT_ORAM
#define NUMBER_OF_WARMUP_REQUESTS 0
#define ANALYSIS 1
#define MILLION 1E6
#define HASH_LENGTH 32
#define DEBUG_PRINT 1
#define PRINT_REQ_DETAILS 1
#define RESULTS_DEBUG 1
#define PUBLIC_KEY_FILE "enclave_public_key"

#define RECURSION_LEVELS_DEBUG 1
//#define NO_CACHING_APP 1
//#define EXITLESS_MODE 1
//#define POSMAP_EXPERIMENT 1

// Global Variables Declarations
uint64_t ORAM_INSTANCE_MEM_POSMAP_LIMIT = 1024;
uint32_t MEM_POSMAP_LIMIT = 10 * 1024;
uint64_t PATH_SIZE_LIMIT = 1 * 1024 * 1024;
uint32_t aes_key_size = 16;
uint32_t hash_size = 32;	
#define ADDITIONAL_METADATA_SIZE 24
uint32_t oram_id = 0;

//Timing variables
long mtime, seconds, useconds;
struct timespec time_rec, time_start, time_end, time_pos, time_fetch, upload_start_time , upload_end_time, download_start_time, download_end_time;
struct timespec time3,time4,time5,time2;
double upload_time, download_time;
double t, t1, t2, t3, ut,dt,tf,te;
clock_t ct, ct1, ct2, ct3, cut, cdt;
clock_t ct_pos, ct_fetch, ct_start, ct_end;
LocalStorage ls;
uint32_t recursion_levels_e = 0;

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
bool resume_experiment = false;
bool inmem_flag =false;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

struct oram_request{
	uint32_t *id;
	uint32_t *level;
	uint32_t *d_lev;
	bool *recursion;
	bool *block;
};

struct oram_response{
	unsigned char *path;
	unsigned char *path_hash;
	unsigned char *new_path;
	unsigned char *new_path_hash;
};

struct thread_data{
	struct oram_request *req;
	struct oram_response *resp;
};

struct thread_data td;
struct oram_request req_struct;
struct oram_response resp_struct;	
unsigned char *data_in;
unsigned char *data_out;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

uint8_t public_verification_key_x[32] = {
	   	0x45, 0xb2, 0x00, 0x83, 0x53, 0x11, 0x4b, 0xbb, 0x78, 0xeb, 0x67, 0x17, 0xf2, 0xc9,
		0x51, 0xe4, 0xcc, 0x1d, 0x93, 0x89, 0x0c, 0x70, 0xe1, 0x93, 0xcc, 0xd2, 0x83, 0x01, 
		0x68, 0x61, 0xe6, 0xec};
uint8_t public_verification_key_y[32] = { 
		0xde, 0x24, 0xec, 0x0b, 0xf9, 0x0c, 0x03, 0x27, 0xb8, 0x1b, 0x89, 0x40, 0x80, 0x28,
		0x54, 0xd8, 0xfb, 0xa5, 0xc8, 0x07, 0x57, 0x4c, 0x38, 0xab, 0xc3, 0x3e, 0xfb, 0x68, 
		0x42, 0xd1, 0xa5, 0xcf};

//Assumes word_size_in_bytes will always be even
void switchEndianness(unsigned char* buffer, uint32_t word_size_in_bytes, uint32_t no_of_words_in_buffer){
	
	//Try 4 first, since the uint32_t* buffer used by SGX signatures.
	//unsigned char *ptr = buffer;
	unsigned char *ptr = buffer;
	unsigned char *ptr_temp = ptr;
	unsigned char temp;
	for(int i = 0; i < no_of_words_in_buffer; i++) {
		__builtin_bswap32(*ptr);
		/*
		for(int j = 0; j < word_size_in_bytes/2; j++) {
			temp = *ptr_temp;
			*ptr_temp = *(ptr+word_size_in_bytes-1-j);
			*(ptr_temp+word_size_in_bytes-1-j) = temp;			
			ptr_temp+=1;
		}
		ptr=ptr+word_size_in_bytes;
		ptr_temp = ptr;
		*/
		ptr+=word_size_in_bytes;
	}
}


void switchEndiannessEntire(unsigned char* buffer, uint32_t no_of_bytes_in_buffer){
	//Try 4 first, since the uint32_t* buffer used by SGX signatures.
	//unsigned char *ptr = buffer;
	unsigned char *ptr = buffer;
	unsigned char *ptr_end = ptr + no_of_bytes_in_buffer - 1;
	unsigned char temp;
	for(int i = 0; i < no_of_bytes_in_buffer/2; i++) {
		temp = *ptr;
		*ptr=*(ptr_end);
		*(ptr_end) = temp;
		ptr+=1;
		ptr_end-=1;
	}
}

void PushSampledKeysOut(unsigned char * ZT_private_key_r, uint32_t key_size, unsigned char* ZT_public_key_gx, unsigned char* ZT_public_key_gy){
	printf("In PushSampledKeysOut\n");
	EC_KEY *ec_key = NULL;
	EC_KEY *ec_key_priv = NULL;
	BIGNUM *x = NULL, *y = NULL, *r = NULL;
	EC_GROUP *curve = NULL;
	EC_POINT *pub = NULL;
	BN_CTX *bn_ctx = NULL;
	bn_ctx = BN_CTX_new(); 	
	
	if(NULL == (curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)))
		printf("Setting EC_GROUP failed \n");
	
	ec_key_priv = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if(ec_key_priv==NULL)
		printf("Setting EC_KEY_new_by_curve_name FAILED\n");

	pub = EC_POINT_new(curve);

	//switchEndianness(ZT_private_key_r, 8, key_size/8);
	switchEndiannessEntire(ZT_private_key_r, key_size);
	r = BN_bin2bn((const unsigned char*) ZT_private_key_r, key_size, NULL);
	
	if(EC_KEY_set_private_key(ec_key_priv, (const BIGNUM *) r)==0)
		printf("Error with EC_KEY_set_private_key\n");
				
	if(EC_POINT_mul(curve, pub, r, NULL, NULL, bn_ctx)==0)
		printf("Error in EC_POINT_mul\n");
	
	if(pub==NULL)
		printf("EC_POINT_mul leaves pub as NULL, error\n");	

	int ret;
	ret = EC_POINT_is_on_curve(curve, pub, bn_ctx);
	if(ret==0)	
		printf("Pub point is not on curve!\n");	
	else if(ret == -1)
		printf("ERROR with EC_POINT_is_on_curve\n");
	else if(ret==1)
		printf("Pub point is on the curve!!\n");
	
	x = BN_new();
	y = BN_new();
 	if(EC_POINT_get_affine_coordinates_GFp(curve, pub, x, y, bn_ctx)==0)
		printf("EC_POINT_get_affine_coordinates_GFp failed\n");
	
	if(x==NULL)
		printf("EC_POINT_get_affine_coordinates leaves x , y  as NULL, error\n");
	
	//Compare ZT_public_key_gx with EC_KEY->r (BIGNUM)
	
	unsigned char *buff_x = (unsigned char*) malloc(key_size);	
	unsigned char *buff_y = (unsigned char*) malloc(key_size);
	
	
	printf("Bytes required = %d, %d \n", BN_num_bytes(x), BN_num_bytes(y));
	ret = BN_bn2bin((const BIGNUM*)x, buff_x);
	ret = BN_bn2bin((const BIGNUM*)y, buff_y);

		
	switchEndiannessEntire(buff_x, key_size);
	switchEndiannessEntire(buff_y, key_size);
	
	printf("OpenSSL Public_key_x bytes: \n");
	for(int i=0; i<32; i++)
		printf("%02X ", *(buff_x+i));
	printf("\n");


	printf("SGX Public_key_x bytes: \n");
	for(int i=0; i<32; i++)
		printf("%02X ", *((unsigned char *)ZT_public_key_gx+i));
	printf("\n");

	printf("OpenSSL Public_key_y bytes: \n");
	for(int i=0; i<32; i++)
		printf("%02X ", *(buff_y+i));
	printf("\n");

	printf("SGX Public_key_y bytes: \n");
	for(int i=0; i<32; i++)
		printf("%02X ", *((unsigned char *)ZT_public_key_gy+i));
	printf("\n");
	
	BN_CTX_free(bn_ctx);
	free(buff_x);
	free(buff_y);
	

}	

//void VerifySignatureOutside(uint32_t *signature_x, uint32_t signature_size_x, uint32_t *signature_y, uint32_t signature_size_y){

void openssl_sha256(char *string)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, 2);
    SHA256_Final(hash, &sha256);
    int i = 0;
    
    printf("SHA256 Output OPENSSL: \n");
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        //sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
	printf("%02x ", hash[i]);
    }
    printf("\n");
    //outputBuffer[64] = 0;
}

void PublishKey(unsigned char *bin_x, uint32_t bin_x_size, unsigned char *bin_y, uint32_t bin_y_size, unsigned char *signature_r, unsigned char *signature_s, uint32_t sig_r_size, uint32_t sig_s_size){
	
	//Publish file with keys and signature
	//(Keys and signature would need to be base 64 encoded and published)
	//Note : Eventually this would have to move to network stack

	//Move this declaration to a shared global file between Client and App
	FILE *fp = fopen(PUBLISH_FILE_NAME, "w");
	int ret;

	//Converting to Base64 = /3 * 4 + 1 (for Null byte added by EVP_EncodeBlock)
	unsigned char *bin_x_b64= (unsigned char*) malloc((ceil(float(bin_x_size)/float(3)) * 4) + 1);
	unsigned char *bin_y_b64= (unsigned char*) malloc((ceil(float(bin_y_size)/float(3)) * 4) + 1);
	unsigned char *signature_r_b64= (unsigned char*) malloc((ceil(float(sig_r_size)/float(3)) * 4)+1);
	unsigned char *signature_s_b64= (unsigned char*) malloc((ceil(float(sig_s_size)/float(3)) * 4+1));
	//Convert key and signature to base64 encoding.
	ret = EVP_EncodeBlock(bin_x_b64, bin_x, bin_x_size);
	ret = EVP_EncodeBlock(bin_y_b64, bin_y, bin_y_size);
	ret = EVP_EncodeBlock(signature_r_b64, signature_r, sig_r_size);
	ret = EVP_EncodeBlock(signature_s_b64, signature_s, sig_s_size);
	
	fprintf(fp,"%s\n%s\n%s\n%s\n",bin_x_b64, bin_y_b64, signature_r_b64, signature_s_b64);

	fclose(fp);
}

void VerifySignature(unsigned char* sig_x, unsigned char *sig_y, uint32_t sig_size_x, uint32_t sig_size_y){
	char file_name[] = "enclave_signing_pub.pem";
	char file_name2[] = "enclave_signing.pem";
	FILE *fp = fopen(file_name, "r");
	FILE *fp2 = fopen(file_name2, "r");
	BIGNUM *x, *y;
	int ret;
	EC_GROUP *curve;
	
	EC_KEY *ec_key = NULL;
	EC_KEY *ec_key_priv = NULL;
	BIGNUM *sig_r, *sig_s;
	ECDSA_SIG *sig = ECDSA_SIG_new();

	//Setup up EC_GROUP / curve
	if(NULL == (curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)))
		printf("Setting EC_GROUP failed \n");

	//Initialize BNs to obtain the coordinates of public key into them.
	x = BN_new();
	y = BN_new();

	//Setup up parameters of EC_KEY struct
	ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if(ec_key==NULL)
		printf("Setting EC_KEY_new_by_curve_name FAILED\n");

	//Load EC Public Key from File
	ec_key = PEM_read_EC_PUBKEY(fp, &ec_key, NULL, NULL);
	if(ec_key==NULL)
		printf("PEM_read_EC_PUBKEY failed/error\n\n");

	sig->r = BN_bin2bn((uint8_t*) sig_x, sig_size_x, NULL);
	sig->s = BN_bin2bn((uint8_t*) sig_y, sig_size_y, NULL);

	char text[3] = "HI";
	printf("Verifying signature from enclave :\n");
	ret = ECDSA_do_verify((const unsigned char*) text, 2, sig, ec_key);
	if(ret==1)
		printf("Valid Signature!\n");
	else{
		if(ret==0)
			printf("Invalid Signature!\n");
		else
			printf("ERROR with ECDSA_Verify\n");
	}
}

void VerifySignatureOutside(uint32_t key_size, unsigned char *signature_x, unsigned char *signature_y, unsigned char *private_key, unsigned char *public_key_x, unsigned char * public_key_y, unsigned char *signature_r, unsigned char* signature_s){

	char file_name[] = "enclave_signing_pub.pem";
	char file_name2[] = "enclave_signing.pem";
	FILE *fp = fopen(file_name, "r");
	FILE *fp2 = fopen(file_name2, "r");
	//EVP_PKEY *pkey;
	EC_KEY *ec_key = NULL;
	EC_KEY *ec_key_priv = NULL;
	BIGNUM *x, *y;
	BIGNUM *r, *s;
	ECDSA_SIG *sig = ECDSA_SIG_new();
	ECDSA_SIG *sig_der = NULL;	
	ECDSA_SIG *sig_openssl = NULL;	
	const EC_POINT *pub_point;
	EC_GROUP *curve;
	BN_CTX *bn_ctx = BN_CTX_new();

	//Setup up EC_GROUP / curve
	if(NULL == (curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)))
		printf("Setting EC_GROUP failed \n");

	//Initialize BNs to obtain the coordinates of public key into them.
	x = BN_new();
	y = BN_new();

	//Setup up parameters of EC_KEY struct
	ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if(ec_key==NULL)
		printf("Setting EC_KEY_new_by_curve_name FAILED\n");

	//Setup up parameters of EC_KEY struct
	ec_key_priv = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if(ec_key_priv==NULL)
		printf("Setting ec_key_priv EC_KEY_new_by_curve_name FAILED\n");

	//Load EC Public Key from File
	ec_key = PEM_read_EC_PUBKEY(fp, &ec_key, NULL, NULL);
	if(ec_key==NULL)
		printf("PEM_read_EC_PUBKEY failed/error\n\n");

	//Extract the point of public key into EC_POINT* struct
	pub_point = EC_KEY_get0_public_key(ec_key);

	//Extract the coordinates into the BNs x and y
 	if(EC_POINT_get_affine_coordinates_GFp(curve, pub_point, x, y, bn_ctx)==0)
		printf("EC_POINT_get_affine_coordinates_GFp failed\n");

	unsigned char *buff_x = (unsigned char*) malloc(key_size);	
	unsigned char *buff_y = (unsigned char*) malloc(key_size);	
		
	BN_bn2bin((const BIGNUM*) x, buff_x);
	BN_bn2bin((const BIGNUM*) y, buff_y);

	switchEndiannessEntire(signature_x, key_size);
	switchEndiannessEntire(signature_y, key_size);
	

	uint8_t sig_x_size = key_size, sig_y_size= key_size;
	unsigned char *sig_x, *sig_y, *sig_x_ptr, *sig_y_ptr;
	
	if(*signature_x >= 0x80){
		sig_x_size+=1;
		sig_x = (unsigned char*) malloc(sig_x_size);
		*sig_x = 0x00;
		sig_x_ptr = sig_x+1;
	}
	else{
	
		sig_x = (unsigned char*) malloc(sig_x_size);
		sig_x_ptr = sig_x;
	}

	if(*signature_y >= 0x80) {
		sig_y_size+=1;
		sig_y = (unsigned char*) malloc(sig_y_size);
		*sig_y = 0x00;
		sig_y_ptr = sig_y+1;
	}
	else{
		
		sig_y = (unsigned char*) malloc(sig_y_size);
		sig_y_ptr = sig_y;
	}
	memcpy(sig_x_ptr, signature_x, key_size);
	memcpy(sig_y_ptr, signature_y, key_size);

	/*
	//DER encoding: vr and vs in Big-endian
	//0x30 b1 0x02 b2 (vr) 0x02 b3 (vs)
	unsigned char *sig_x_y = (unsigned char*) malloc(sig_x_size + sig_y_size + 6);
	sig_x_y[0] = 0x30;
	sig_x_y[1] = 4 + sig_x_size + sig_y_size;	//68
	sig_x_y[2] = 0x02;
	sig_x_y[3] = sig_x_size;
	sig_x_y[4+sig_x_size] = 0x02;
	sig_x_y[4+sig_x_size+1] = sig_y_size; 
	memcpy(sig_x_y+4, sig_x, sig_x_size);
	memcpy(sig_x_y+4+sig_x_size, sig_y, sig_y_size);
	d2i_ECDSA_SIG(&sig_der, (const unsigned char **) &sig_x_y, 6 +sig_x_size + sig_y_size);
	*/

	printf("signature_x bytes: \n");
	for(int i=0; i<sig_x_size; i++)
		printf("%02X ", *(sig_x+i));
	printf("\n");

	printf("signature_y bytes: \n");
	for(int i=0; i<sig_y_size; i++)
		printf("%02X ", *(sig_y+i));
	printf("\n");
	//sig->r = BN_bin2bn((uint8_t*) sig_x, sig_x_size, NULL);
	//sig->s = BN_bin2bn((uint8_t*) sig_y, sig_y_size, NULL);

	int sig_size = i2d_ECDSA_SIG(sig, NULL);
	unsigned char *sig_bytes =(unsigned char*) malloc(sig_size);
	unsigned char *p;
	memset(sig_bytes, 6, sig_size);

	p = sig_bytes;
	int new_sig_size = i2d_ECDSA_SIG(sig, &p);
	

	char text[3] = "HI";
	int ret;
	ret = ECDSA_verify(0, (const unsigned char*) text, 2, p, new_sig_size, ec_key);
	printf("With DER encoded verify : ");
	if(ret==1)
		printf("Valid Signature!\n");
	else{
		if(ret==0)
			printf("Invalid Signature!\n");
		else
			printf("ERROR with ECDSA_Verify\n");
	}
	printf("\n");


	openssl_sha256(text);
	printf("\n");
	//int ret = ECDSA_verify(0, (const unsigned char*) text, 2, sig_x_y, key_size*2, ec_key);
	ret = ECDSA_do_verify((const unsigned char*) text, 2, sig_der, ec_key);
	if(ret==1)
		printf("Valid Signature!\n");
	else{
		if(ret==0)
			printf("Invalid Signature!\n");
		else
			printf("ERROR with ECDSA_Verify\n");
	}
	printf("\n");

	ec_key_priv = PEM_read_ECPrivateKey(fp2, &ec_key_priv, NULL, NULL);
	if(ec_key_priv==NULL)
		printf("PEM_read_ECPRIVATEKEY failed/error\n\n");
	
	sig_openssl = ECDSA_do_sign((const unsigned char *) text, 2, ec_key_priv);
	if(sig_openssl == NULL)
		printf("ECDSA_do_sign ERROR\n");

	ret = ECDSA_do_verify((const unsigned char*) text, 2, sig_openssl, ec_key);
	if(ret==1)
		printf("OPENSSL Valid Signature!\n");
	else{
		if(ret==0)
			printf("OPENSSL Invalid Signature!\n");
		else
			printf("OPENSSL ERROR with ECDSA_Verify\n");
	}
	
	printf("Bytes required = %d, %d \n", BN_num_bytes(sig_openssl->r), BN_num_bytes(sig_openssl->s));
	unsigned char *temp_buff_r = (unsigned char*) malloc(key_size);
	unsigned char *temp_buff_s = (unsigned char*) malloc(key_size);

	ret = BN_bn2bin(sig_openssl->r, temp_buff_r);
	ret = BN_bn2bin(sig_openssl->s, temp_buff_s);

	//switchEndianness((unsigned char*) temp_buff_r, 4, key_size/4);
	//switchEndianness((unsigned char*) temp_buff_s, 4, key_size/4);

	//switchEndiannessEntire(temp_buff_r, key_size);
	//switchEndiannessEntire(temp_buff_s, key_size);
	
	memcpy(signature_s, temp_buff_r, key_size);
	memcpy(signature_r, temp_buff_s, key_size);
	
	
	//VerifySignatureInsideEnclave();

	printf("OpenSSL Public_Key_X bytes: \n");
	for(int i=0; i<32; i++)
		printf("%02X ", *(buff_x+i));
	printf("\n");

	printf("OpenSSL Public_Key_Y bytes: \n");
	for(int i=0; i<32; i++)
		printf("%02X ", *(buff_y+i));
	printf("\n");

	printf("SGX Public_key_X bytes: \n");
	for(int i=0; i<32; i++)
		printf("%02X ", *((unsigned char *)public_key_x+i));
	printf("\n");

	printf("SGX Public_key_Y bytes: \n");
	for(int i=0; i<32; i++)
		printf("%02X ", *((unsigned char *)public_key_y+i));
	printf("\n");
	
	//Try converting the signature into the Openssl SIG Struct

	//Setup EC Context
	//Setup the pubkey from either PEM file or hard coded bytes
	//Verify Signature

	BN_free(x);
	BN_free(y);
	BN_CTX_free(bn_ctx);
	free(temp_buff_r);
	free(temp_buff_s);
	fclose(fp);
	fclose(fp2);
}

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret) {
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void) {
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str) {
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}

void *HandleRequest(void *arg) {
	//printf("In Handle Request thread\n");

	struct thread_data *data;
	data = (struct thread_data *) arg;
	unsigned char *ptr = data->resp->path;
	unsigned char *ptr_hash = data->resp->path_hash;
	uint32_t* id = data->req->id;
	uint32_t *level= data->req->level;
	uint32_t *d_lev = data->req->d_lev;
	bool *recursion = data->req->recursion;
	

	uint64_t path_hash_size = 2 * (*d_lev) * HASH_LENGTH; // 2 from siblings 		

	uint64_t i = 0;

	while(1) {
		//*id==-1 || *level == -1 || 
		while( *(data->req->block) ) {}
		//printf("APP : Recieved Request\n");

		ls.downloadPath(data->resp->path, *id, data->resp->path_hash, path_hash_size, *level , *d_lev);	
		//printf("APP : Downloaded Path\n");	
		*(data->req->block) = true;
				
		while(*(data->req->block)) {}
		ls.uploadPath(data->resp->new_path, *id, data->resp->new_path_hash, *level, *d_lev);
		//printf("APP : Uploaded Path\n");
		*(data->req->block) = true;

		//pthread_exit(NULL);
	}
		
}

uint64_t timediff(struct timeval *start, struct timeval *end) {
	long seconds,useconds;
	seconds  = end->tv_sec  - start->tv_sec;
	useconds = end->tv_usec - start->tv_usec;
	mtime = ((seconds) * 1000 + useconds/1000.0) + 0.5;
	return mtime;
}

double timetaken(timespec *start, timespec *end){
	long seconds, nseconds;
	seconds = end->tv_sec - start->tv_sec;
	nseconds = end->tv_nsec - start->tv_nsec;
	double mstime = ( double(seconds * 1000) + double(nseconds/MILLION) );
	return mstime;
}

void time_report(uint8_t point) {
	if(point==1) {
		ct_pos = clock();
		clock_gettime(CLOCK_MONOTONIC, &time_pos);
	}
	if(point==2) {
		ct_fetch = clock();
		clock_gettime(CLOCK_MONOTONIC, &time_fetch);
		clock_gettime(CLOCK_MONOTONIC, &time2);
	}
	if(point==3) {
		clock_gettime(CLOCK_MONOTONIC, &time3);
	}
	if(point==4) {
		clock_gettime(CLOCK_MONOTONIC, &time4);
	}
	if(point==5) {
		clock_gettime(CLOCK_MONOTONIC, &time5);
	}
}

uint8_t uploadPath(unsigned char* path_array, uint32_t pathSize, uint32_t leafLabel, unsigned char* path_hash, uint32_t path_hash_size, uint32_t level, uint32_t D_level) {
	clock_t s,e;
	s = clock();
	clock_gettime(CLOCK_MONOTONIC, &upload_start_time);
	ls.uploadPath(path_array,leafLabel,path_hash, level, D_level);
	e = clock();
	clock_gettime(CLOCK_MONOTONIC, &upload_end_time);
	double mtime = timetaken(&upload_start_time, &upload_end_time);

	if(recursion_levels_e >= 1) {
		upload_time += mtime;	
		cut += (e-s);
	}
	else {
		upload_time = mtime;
		cut = (e-s);
	}
	return 1;
}

uint8_t uploadObject(unsigned char* serialized_bucket, uint32_t bucket_size, uint32_t label, unsigned char* hash, uint32_t hashsize, uint32_t size_for_level, uint32_t recursion_level) {
	clock_gettime(CLOCK_MONOTONIC, &upload_start_time);
	ls.uploadObject(serialized_bucket, label, hash, hashsize, size_for_level, recursion_level);
	clock_gettime(CLOCK_MONOTONIC, &upload_end_time);
	double mtime = timetaken(&upload_start_time, &upload_end_time);
	upload_time = mtime;
	//printf("%ld\n",ut);
	return 1;
}

uint8_t downloadPath(unsigned char* path_array, uint32_t pathSize, uint32_t leafLabel, unsigned char *path_hash, uint32_t path_hash_size, uint32_t level, uint32_t D_level) {	
	clock_t s,e;
	s = clock();
	clock_gettime(CLOCK_MONOTONIC, &download_start_time);
	ls.downloadPath(path_array,leafLabel,path_hash, path_hash_size, level, D_level);
	e = clock();	
	clock_gettime(CLOCK_MONOTONIC, &download_end_time);
	double mtime = timetaken(&download_start_time, &download_end_time);
	if(recursion_levels_e >= 1) {
		download_time+= mtime;
		cdt+=(e-s);	
	}
	else {
		download_time = mtime;	
		cdt = (e-s);
	}
	return 1;
}

uint8_t downloadObject(unsigned char* serialized_bucket, uint32_t bucket_size, uint32_t label, unsigned char* hash, uint32_t hashsize, uint32_t size_for_level, uint32_t recursion_level) {
	clock_gettime(CLOCK_MONOTONIC, &download_start_time);
	serialized_bucket = ls.downloadObject(serialized_bucket, label, hash, hashsize, size_for_level, recursion_level);
	clock_gettime(CLOCK_MONOTONIC, &download_end_time);
	double mtime = timetaken(&download_start_time, &download_end_time);
	download_time = mtime;
	return 1;
}

void build_fetchChildHash(uint32_t left, uint32_t right, unsigned char* lchild, unsigned char* rchild, uint32_t hash_size, uint32_t recursion_level) {
	ls.fetchHash(left,lchild,hash_size, recursion_level);
	ls.fetchHash(right,rchild,hash_size, recursion_level);
}

int8_t computeRecursionLevels(uint32_t max_blocks, uint32_t recursion_data_size, uint64_t onchip_posmap_memory_limit){
    int8_t recursion_levels = -1;
    uint8_t x;
    
    if(recursion_data_size!=0) {		
            recursion_levels = 1;
            x = recursion_data_size / sizeof(uint32_t);
            uint64_t size_pmap0 = max_blocks * sizeof(uint32_t);
            uint64_t cur_pmap0_blocks = max_blocks;

            while(size_pmap0 > onchip_posmap_memory_limit) {
                cur_pmap0_blocks = (uint64_t) ceil((double)cur_pmap0_blocks/(double)x);
                recursion_levels++;
                size_pmap0 = cur_pmap0_blocks * sizeof(uint32_t);
            }

            if(recursion_levels==1)
                recursion_levels=-1;

            #ifdef RECURSION_LEVELS_DEBUG
                printf("IN App: max_blocks = %d\n", max_blocks);
                printf("Recursion Levels : %d\n",recursion_levels);
            #endif
        }
    return recursion_levels;
}

int8_t ZT_Initialize(){
    	// Initialize the enclave 
	if(initialize_enclave() < 0){
		printf("Enter a character before exit ...\n");
		getchar();
		return -1; 
	}

	// Utilize edger8r attributes
	edger8r_array_attributes();
	edger8r_pointer_attributes();
	edger8r_type_attributes();
	edger8r_function_attributes();

	// Utilize trusted libraries 
	ecall_libc_functions();
	ecall_libcxx_functions();
	ecall_thread_functions();
	InitializeKeys(global_eid);
    return 0;
}

void ZT_Close(){
        sgx_destroy_enclave(global_eid);
}

uint32_t ZT_New( uint32_t max_blocks, uint32_t data_size, uint32_t stash_size, uint32_t oblivious_flag, uint32_t recursion_data_size, uint32_t oram_type, uint8_t pZ){
	sgx_status_t sgx_return = SGX_SUCCESS;
	int8_t rt;
	uint8_t urt;
	uint32_t instance_id;
	int8_t recursion_levels;
    
	recursion_levels = computeRecursionLevels(max_blocks, recursion_data_size, MEM_POSMAP_LIMIT);
	printf("APP.cpp : ComputedRecursionLevels = %d", recursion_levels);
    
	uint32_t D = (uint32_t) ceil(log((double)max_blocks/4)/log((double)2));
	ls.setParams(max_blocks,D,pZ,stash_size,data_size + ADDITIONAL_METADATA_SIZE,inmem_flag, recursion_data_size + ADDITIONAL_METADATA_SIZE, recursion_levels);
    
	#ifdef EXITLESS_MODE
		int rc;
		pthread_t thread_hreq;
		req_struct.id = (uint32_t*) malloc (4);
		req_struct.level = (uint32_t*) malloc(4);
		req_struct.d_lev = (uint32_t*) malloc(4);
		req_struct.recursion = (bool *) malloc(1);
		req_struct.block = (bool *) malloc(1);

		resp_struct.path = (unsigned char*) malloc(PATH_SIZE_LIMIT);
		resp_struct.path_hash = (unsigned char*) malloc (PATH_SIZE_LIMIT);
		resp_struct.new_path = (unsigned char*) malloc (PATH_SIZE_LIMIT);
		resp_struct.new_path_hash = (unsigned char*) malloc (PATH_SIZE_LIMIT);
		td.req = &req_struct;
		td.resp = &resp_struct;

		*(req_struct.block) = true;
		*(req_struct.id) = 7;

		rc = pthread_create(&thread_hreq, NULL, HandleRequest, (void *)&td);
		if (rc){
		    std::cout << "Error:unable to create thread," << rc << std::endl;
		    exit(-1);
		}
		sgx_return = initialize_oram(global_eid, &urt, max_blocks, data_size,&req_struct, &resp_struct);		
	#else
		//Pass the On-chip Posmap Memory size limit as a parameter.    
		sgx_return = createNewORAMInstance(global_eid, &instance_id, max_blocks, data_size, stash_size, oblivious_flag, recursion_data_size, recursion_levels, MEM_POSMAP_LIMIT, oram_type, pZ);
		//sgx_return = createNewORAMInstance(global_eid, &instance_id, max_blocks, data_size, stash_size, oblivious_flag, recursion_data_size, recursion_levels, MEM_POSMAP_LIMIT, oram_type);
		printf("INSTANCE_ID returned = %d\n", instance_id);
	
		//(uint32_t max_blocks, uint32_t data_size, uint32_t stash_size, uint32_t oblivious_flag, uint32_t recursion_data_size, int8_t recursion_levels, uint64_t onchip_posmap_mem_limit, uint32_t oram_type)
		//sgx_return = createNewORAMInstance(global_eid, &urt, max_blocks, data_size, stash_size, oblivious_flag, recursion_data_size, recursion_levels, MEM_POSMAP_LIMIT, oram_type);
	#endif

    #ifdef DEBUG_PRINT
        printf("initialize_oram Successful\n");
    #endif
    return (instance_id);
}


void ZT_Access(uint32_t instance_id, uint8_t oram_type, unsigned char *encrypted_request, unsigned char *encrypted_response, unsigned char *tag_in, unsigned char* tag_out, uint32_t request_size, uint32_t response_size, uint32_t tag_size){
    accessInterface(global_eid, instance_id, oram_type, encrypted_request, encrypted_response, tag_in, tag_out, request_size, response_size, tag_size);
}

void ZT_Bulk_Read(uint32_t instance_id, uint8_t oram_type, uint32_t no_of_requests, unsigned char *encrypted_request, unsigned char *encrypted_response, unsigned char *tag_in, unsigned char* tag_out, uint32_t request_size, uint32_t response_size, uint32_t tag_size, unsigned char* encrypted_key, uint32_t encrypted_key_size){
    accessBulkReadInterface(global_eid, instance_id, oram_type, no_of_requests, encrypted_request, encrypted_response, tag_in, tag_out, request_size, response_size, tag_size, encrypted_key, encrypted_key_size);
}

/*
	uint32_t posmap_size = 4 * max_blocks;
	uint32_t stash_size =  (stashSize+1) * (dataSize_p+8);

*/

/*
if(resume_experiment) {
		
		//Determine if experiment is recursive , and setup parameters accordingly
		if(recursion_data_size!=0) {	
			uint32_t *posmap = (uint32_t*) malloc (MEM_POSMAP_LIMIT*16*4);
			unsigned char *merkle =(unsigned char*) malloc(hash_size + aes_key_size);
			ls.restoreMerkle(merkle,hash_size + aes_key_size);				
			ls.restorePosmap(posmap, MEM_POSMAP_LIMIT*16);
			//Print and test Posmap HERE
			
			//TODO : Fix restoreMerkle and restorePosmap in Enclave :
			//sgx_return = restoreEnclavePosmap(posmap,);			
			for(uint8_t k = 1; k <=recursion_levels_e;k++){
				uint32_t stash_size;
				unsigned char* stash = (unsigned char*) malloc (stash_size);
				//ls.restoreStash();	
				//TODO: Fix restore Stash in Enclave				
				//sgx_return = frestoreEnclaveStashLevel();
				free(stash);						
			}
			
			free(posmap);	
			free(merkle);
			
		}
		else {
		uint32_t current_stashSize = 0;
		uint32_t *posmap = (uint32_t*) malloc (posmap_size);
		uint32_t *stash = (uint32_t*) malloc(4 * 2 * stashSize);
		unsigned char *merkle =(unsigned char*) malloc(hash_size);
		ls.restoreState(posmap, max_blocks, stash, &current_stashSize, merkle, hash_size+aes_key_size);		
		//sgx_return = restore_enclave_state(global_eid, &rt32, max_blocks, dataSize_p, posmap, posmap_size, stash, current_stashSize * 8, merkle, hash_size+aes_key_size);
		//printf("Restore done\n");
		free(posmap);
		free(stash);
		free(merkle);
		}
	}
*/
