# ZeroTrace

ZeroTrace(ZT) is the first system that enabled instantiations of Oblivious-RAMs(ORAMs) on a server-device that supports Intel-SGX. ZT is also secure against known side-channel attacks against SGX. Oblivous RAM or ORAMs have been theoretically known for a long while now [1], with the advent of secure hardware modules like Intel SGX, we notice an opportunity to make these incredible cryptographic primitives, deployable in practical scenarios.
(Caveat: That being said recently we have seen attacks against the Intel special service enclaves, that can compromise the enclaves key generation process. We expect Intel to patch these bugs, as these effectively cripple SGX as a whole.)

Sajin Sasy, Sergey Gorbunov, and Christopher Fletcher. "ZeroTrace: Oblivious memory primitives from Intel SGX." Symposium on Network and Distributed System Security (NDSS). 2018.

ZeroTrace employs an oblivious variant of traditional ORAM controller logic. To do so within an SGX environment, without being susceptible to side-channel attacks, the only truly TRUSTED space that we can use are the CPU registers. Hence function snippets that require conditional operations are rewritten to be oblivious via linear scans and assembly functions that leverage CMOV instructions wherever appropriate. 

Currently ZeroTrace supports two ORAM backends, PathORAM [2] and CircuitORAM [3]. Please refer the corresponding papers to get a more concrete understanding of how to parameterize these ORAMs for secure deployment scenarios.

## Pre-requisites:
ZeroTrace requires a fully functional Intel SGX-SDK stack
To set up your SGX-SDK stack, please refer to:  https://github.com/intel/linux-sgx 

Nasm
Tested with nasm version 2.11.08 (Almost all 2.+ versions of nasm should be sufficient)

## Getting Started
ZeroTrace takes a LOT of command line parameters. This was done in the interest of making it extremely easy to instantiate ORAMs with different parameters to test performance across a wide range of parameters. In order to make simpler to use, a shell script "exec_zt.sh" is provided, in which one can more conveniently customize the parameters to run ZeroTrace with. 

To build the ZeroTrace library:
In the ZeroTrace folder, execute:
  ```
  make clean
  make
  ```
This will produce the ZeroTrace library (libZT.so) and copy it to the Sample_App folder.
To execute the Sample_Application provided by us, simply execute
(Change the parameters in the zt_exec.sh script as needed by your application)
```
./zt_exec.sh
```
The Sample_App is a simple example code that shows how to integrate ZT with native C/C++ code. But it should be sufficient in demonstrating how to use this. Do let us know if we can help you in anyway integrate it with your application/product.

## Integrating the Library into your Application/Tool
**ZT_Initialize()** : An initialization function that sets up the ZeroTrace Enclave, before one can create and access ORAMs through it.

**ZT_New(args)** : This function creates a new ORAM instance with the provided parameters. Currently all data blocks of these instantiated trees are dummy data, to populate the tree one has to perform individual writes to the tree after instantiating it. ZeroTrace supports multiple ORAM instances, this function returns an _instance_id_ which is used to keep track of the ORAM instance of this newly created ORAM, so that the user can query this particular ORAM instance later.

**ZT_Access(args)** : This function is used to access (read/write) values to a previously-created ORAM Tree.

**ZT_Bulk_Read(args)** : This is a newly supported function that enables users to do bulk reads, without performing enclave exits and entry for each request individually. 

The file ZT.hpp can be used as a reference for the underlying arguments, the argument names are self-explanatory.
  
# References
1 - Goldreich, O. and Ostrovsky, R., 1996. Software protection and simulation on oblivious RAMs. Journal of the ACM (JACM), 43(3), pp.431-473.

2 - Stefanov, E., Van Dijk, M., Shi, E., Fletcher, C., Ren, L., Yu, X. and Devadas, S., 2013, November. Path ORAM: an extremely simple oblivious RAM protocol. In Proceedings of the 2013 ACM SIGSAC conference on Computer & communications security (pp. 299-310). ACM.

3 - Wang, X., Chan, H. and Shi, E., 2015, October. Circuit oram: On tightness of the goldreich-ostrovsky lower bound. In Proceedings of the 22nd ACM SIGSAC Conference on Computer and Communications Security (pp. 850-861). ACM.
