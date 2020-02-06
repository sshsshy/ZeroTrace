
.PHONY: all clean

all: Sample_App LS_Client HSORAM_Client Test_Correctness

Sample_App : Sample_App.cpp
	g++ -std=c++11 Sample_App.cpp utils.cpp -L=$(CURDIR) -lZT -lcrypto -Wl,--rpath=$(CURDIR) -o sampleapp

LS_Client : LS_Client.cpp utils.cpp
	g++ -std=c++11 LS_Client.cpp utils.cpp -L=$(CURDIR) -lZT -lcrypto -Wl,--rpath=$(CURDIR) -o lsclient

HSORAM_Client : HSORAM_Client.cpp utils.cpp
	g++ -std=c++11 HSORAM_Client.cpp utils.cpp -L=$(CURDIR) -lZT -lcrypto -Wl,--rpath=$(CURDIR) -o hsoramclient

Test_Correctness : Test_Correctness.cpp utils.cpp
	g++ -std=c++11 Test_Correctness.cpp utils.cpp -L=$(CURDIR) -lZT -lcrypto -Wl,--rpath=$(CURDIR) -o testcorrectness
