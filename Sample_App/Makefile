
all: Sample_App LS_Client HSORAM_Client

Sample_App : Sample_App.cpp
	g++ -std=c++11 Sample_App.cpp -L=$(CURDIR) -lZT -lcrypto -Wl,--rpath=$(CURDIR) -o sampleapp

LS_Client : LS_Client.cpp utils.cpp
	g++ -std=c++11 LS_Client.cpp utils.cpp -L=$(CURDIR) -lZT -lcrypto -Wl,--rpath=$(CURDIR) -o lsclient

HSORAM_Client : HSORAM_Client.cpp utils.cpp
	g++ -std=c++11 HSORAM_Client.cpp utils.cpp -L=$(CURDIR) -lZT -lcrypto -Wl,--rpath=$(CURDIR) -o hsoramclient

