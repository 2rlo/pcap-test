#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "pcap-test.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	char name[] = "조은영";
	char mobile[] = "0776";
	printf("[bob11]pcap-test[%s%s]", name, mobile);

	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		int offset = 0;		// offset of ipv4 header and tcp header
		int len = 0;		// length of packet

		struct libnet_ethernet_hdr* eth_hdr;	// ethernet header
		struct libnet_ipv4_hdr* ip_hdr;			// ipv4 header
		struct libnet_tcp_hdr* tcp_hdr;			// tcp header

		struct pcap_pkthdr* header;		// packet header
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		
		eth_hdr = (struct libnet_ethernet_hdr*)packet;		
		len = 14;
		packet = packet + 14;
		u_int16_t eth_type = ntohs(eth_hdr->ether_type);	// ethernet type
		if(eth_type != 0x0800)		// type check
		{
			printf("not ip packet\n");
			continue;
		}
		
		ip_hdr = (struct libnet_ipv4_hdr*)packet;
		offset = ip_hdr->ip_hl * 4;		// ip header length
		packet = packet + offset;
		len = len + offset;
		if(ip_hdr->ip_p != IPPROTO_TCP)		// tcp check
		{
			printf("not tcp packet\n");
			continue;
		}

		tcp_hdr = (struct libnet_tcp_hdr*)packet;
		offset = tcp_hdr->th_off * 4;	// tcp header length
		packet = packet + offset;
		len = len + offset;

		printf("========================================\n");
		// print dst mac
		printf("Ethernet dst mac: %2x:%2x:%2x:%2x:%2x:%2x\n",		
			eth_hdr->ether_dhost[0],
			eth_hdr->ether_dhost[1],
			eth_hdr->ether_dhost[2],
			eth_hdr->ether_dhost[3],
			eth_hdr->ether_dhost[4],
			eth_hdr->ether_dhost[5]);
		// print src mac
		printf("Ethernet src mac: %2x:%2x:%2x:%2x:%2x:%2x\n", 
			eth_hdr->ether_shost[0],
			eth_hdr->ether_shost[1],
			eth_hdr->ether_shost[2],
			eth_hdr->ether_shost[3],
			eth_hdr->ether_shost[4],
			eth_hdr->ether_shost[5]);

		// print ip src
		printf("Src IP Address: %s\n",
			inet_ntoa(ip_hdr->ip_src)
			);
		// print ip dst
		printf("Dst IP Address: %s\n",
			inet_ntoa(ip_hdr->ip_dst)
			);

		printf("Src Port: %d\n", ntohs(tcp_hdr->th_sport));	// print src port
		printf("Dst Port: %d\n", ntohs(tcp_hdr->th_dport));	// print dst port

		if(len >= header->caplen)	// print data
		{
			printf("No Data");
		}else{
			printf("Payload: ");
			for(int i=0;i<10; i++)
				printf("%02x ", packet[i]);
		}

		printf("\n");
		printf("========================================\n");
	}

	pcap_close(pcap);
}
