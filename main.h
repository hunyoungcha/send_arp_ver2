#include <pcap.h>
#include <cstring>   
#include <unistd.h>  
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h> 
#include <cstdio>
#include "ethhdr.h"
#include "arphdr.h"



int GetSelfMacFromInterface(const char *interface, unsigned char* mac_addr);
void SetPacket(struct EthArpPacket &packet, Mac dmac, unsigned char smac[6], uint16_t op, char* sip, Mac tmac, char* tip);
Mac GetSourceMac(pcap_t* pcap);
void SendPacket(pcap_t* pcap, struct EthArpPacket packet);