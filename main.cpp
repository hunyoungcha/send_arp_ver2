#include "main.h"
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		usage();
		return EXIT_FAILURE;
	}

	char* dev = argv[1];

	//broad cast
	pcap_t* BroadPcap = PcapOpen(dev, 0, 0, 0);
	SendArpBroadcast(BroadPcap, dev, argv[2]);
	pcap_close(BroadPcap);

}

pcap_t* PcapOpen(char* dev, int snaplen, int promisc, int to_ms) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, snaplen, promisc, to_ms, errbuf);

	return pcap;
}

int SendArpBroadcast(pcap_t* pcap, char* dev, char* tip){
	EthArpPacket packet;

	unsigned char mac[6];
	GetMacAddress(dev, mac);

    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    packet.eth_.smac_ = Mac(mac);
	packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(mac);
    packet.arp_.sip_ = htonl(Ip("192.168.254.141"));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(Ip(tip));

	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
	}
}


int GetMacAddress(const char *interface, unsigned char* mac_addr) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    
    strcpy(ifr.ifr_name, interface);
    ioctl(sock, SIOCGIFHWADDR, &ifr);
    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
    
    close(sock);
    return 0;
}