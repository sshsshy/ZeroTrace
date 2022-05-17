#
# Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

NASM ?= nasm
NASM_Flags ?= -f elf64
UNTRUSTED_DIR = /home/ssasy/Projects/oram_tester/eleos/eleos_core/trustedlib_lib_services/untrusted
COMMON_ELEOS = /home/ssasy/Projects/oram_tester/eleos/eleos_core/trustedlib_lib_services/common

######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
                SGXSSL_Library_Name := sgx_tsgxssld
                OpenSSL_Crypto_Library_Name := sgx_tsgxssl_cryptod
else
        SGX_COMMON_CFLAGS += -O2 -D_FORTIFY_SOURCE=2
                SGXSSL_Library_Name := sgx_tsgxssl
                OpenSSL_Crypto_Library_Name := sgx_tsgxssl_crypto
endif


######## App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

ZT_LIBRARY_PATH := ./Sample_App/
App_Cpp_Files := ZT_Untrusted/App.cpp ZT_Untrusted/LocalStorage.cpp ZT_Untrusted/RandomRequestSource.cpp $(wildcard ZT_Untrusted/Edger8rSyntax/*.cpp) $(wildcard ZT_Untrusted/TrustedLibrary/*.cpp)
Enclave_Asm_Files := ZT_Enclave/oblivious_functions.asm
Enclave_Asm_Objects := $(Enclave_Asm_Files:.asm=.o)
App_Include_Paths := -IInclude -I$(UNTRUSTED_DIR) -IApp -I$(SGX_SDK)/include

App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread


Lib_services_Cpp_Files := $(wildcard common/*.cpp) $(wildcard untrusted/*.cpp)
Lib_services_Cpp_Objects := $(Lib_services_Cpp_Files:.cpp=.o)

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

App_Name := app

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto
services_lib = /home/ssasy/Projects/oram_tester/eleos/eleos_core/trustedlib_lib_services
SGXSSL_INCLUDE_PATH := /opt/intel/sgxssl/include

Enclave_Cpp_Files := ZT_Enclave/Globals_Enclave.cpp ZT_Enclave/ZT_Enclave.cpp ZT_Enclave/Enclave_utils.cpp ZT_Enclave/Block.cpp ZT_Enclave/Bucket.cpp ZT_Enclave/Stash.cpp ZT_Enclave/ORAMTree.cpp ZT_Enclave/PathORAM_Enclave.cpp ZT_Enclave/CircuitORAM_Enclave.cpp ZT_Enclave/LinearScan_ORAM.cpp $(wildcard ZT_Enclave/Edger8rSyntax/*.cpp) $(wildcard ZT_Enclave/TrustedLibrary/*.cpp)
Enclave_Include_Paths := -IInclude -IEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/libcxx -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I$(SGXSSL_INCLUDE_PATH) 
#-I$(services_lib)/static_trusted -I$(services_lib)/common

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++11 -nostdinc++
SgxSSL_Link_Libraries := -L$(OPENSSL_LIBRARY_PATH) -Wl,--whole-archive -l$(SGXSSL_Library_Name) -Wl,--no-whole-archive \

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
        -Wl,--whole-archive -lsgx_tsgxssl -Wl,--no-whole-archive -lsgx_tsgxssl_crypto\
        -Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
        -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
        -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
        -Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
        -Wl,--defsym,__ImageBase=0 \
        -Wl,--version-script=ZT_Enclave/Enclave.lds


Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := ZT_Enclave/Enclave.config.xml

ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif
else
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = SIM_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = SIM_PRERELEASE
else
	Build_Mode = SIM_RELEASE
endif
endif


.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: .config_$(Build_Mode)_$(SGX_ARCH) $(App_Name) $(Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: .config_$(Build_Mode)_$(SGX_ARCH) $(App_Name) $(Signed_Enclave_Name)
ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in debug hardware mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(Build_Mode), HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
else ifeq ($(Build_Mode), SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else
	@echo "The project has been built in release simulation mode."
endif
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name)
	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

######## App Objects ########

$(UNTRUSTED_DIR)/lib_services_u.c: $(SGX_EDGER8R) static_trusted/lib_services.edl
	@mkdir -p $(UNTRUSTED_DIR)
	@cd $(UNTRUSTED_DIR) && $(SGX_EDGER8R) --search-path $(SGXSSL_INCLUDE_PATH) --untrusted ../static_trusted/lib_services.edl --search-path ../static_trusted --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

$(UNTRUSTED_DIR)/lib_services_u.o: $(UNTRUSTED_DIR)/lib_services_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@ $(App_Link_Flags)
	@echo "CC   <=  $<" 
	
#$(COMMON_ELEOS)/%.o: $(COMMON_ELEOS)/%.cpp
#	@$(CXX) $(App_Cpp_Flags) -c $< -o $@ $(App_Link_Flags)
#	@echo "CXX  <=  $<"	
	
$(UNTRUSTED_DIR)/%.o: $(UNTRUSTED_DIR)/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@ $(App_Link_Flags)
	@echo "CXX  <=  $<"
	
#lib_services.untrusted.a: $(UNTRUSTED_DIR)/lib_services_u.o $(Lib_services_Cpp_Objects)
#	ar rcs lib_services.untrusted.a $(Lib_services_Cpp_Objects) $(UNTRUSTED_DIR)/lib_services_u.o  
#	@echo "LINK =>  $@"

ZT_Untrusted/Enclave_u.c: $(SGX_EDGER8R) ZT_Enclave/Enclave.edl
	@cd ZT_Untrusted && $(SGX_EDGER8R) --untrusted ../ZT_Enclave/Enclave.edl --search-path ../ZT_Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

ZT_Untrusted/Enclave_u.o: ZT_Untrusted/Enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

ZT_Untrusted/%.o: ZT_Untrusted/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): ZT_Untrusted/Enclave_u.o $(App_Cpp_Objects)
	#To build a stand alone (non-lib) ZeroTrace:
	#@$(CXX) $^ -o $@ $(App_Link_Flags)
	#To build a dynamic-linked library ZeroTrace:
	@$(CXX) $^ -shared -o libZT.so $(App_Link_Flags)
	@echo "LINK =>  $@"
	cp libZT.so Sample_App/ 
	cp libZT.so ../
	$(MAKE) -C Sample_App/

.config_$(Build_Mode)_$(SGX_ARCH):
	@rm -f .config_* $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) ZT_Untrusted/Enclave_u.* $(Enclave_Cpp_Objects) ZT_Enclave/Enclave_t.*
	@touch .config_$(Build_Mode)_$(SGX_ARCH)

######## Enclave Objects ########

ZT_Enclave/Enclave_t.c: $(SGX_EDGER8R) ZT_Enclave/Enclave.edl
	@cd ZT_Enclave && $(SGX_EDGER8R) --trusted ../ZT_Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

ZT_Enclave/Enclave_t.o: ZT_Enclave/Enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"
	
ZT_Enclave/oblivious_functions.o: ZT_Enclave/oblivious_functions.asm
	@$(NASM) $(NASM_Flags) $< -o $@  

ZT_Enclave/%.o: ZT_Enclave/%.cpp $(Enclave_Asm_Objects)
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Enclave_Name): ZT_Enclave/Enclave_t.o $(Enclave_Cpp_Objects) $(Enclave_Asm_Objects)
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key ZT_Enclave/Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	cp $(Signed_Enclave_Name) Sample_App/
	cp $(Signed_Enclave_Name) ../
	cp $(Enclave_Name) ../
	@echo "SIGN =>  $@"

.PHONY: clean

clean:
	@rm -f .config_* $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) ZT_Untrusted/Enclave_u.* $(Enclave_Cpp_Objects) ZT_Enclave/Enclave_t.*

