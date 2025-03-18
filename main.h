#include <pcap.h>
#include <cstring>   
#include <unistd.h>  
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h> 
#include <cstdio>


int GetMacAddress(const char *interface, unsigned char* mac_addr);
int SendArpBroadcast(pcap_t* pcap, char* dev, char* tip);
pcap_t* PcapOpen(char* dev, int snaplen, int promisc, int to_ms);