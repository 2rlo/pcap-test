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
	printf("[bob11]pcap-test[%s%s]\n", name, mobile);

	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		int offset = 0;
		int len = 0;
		struct libnet_ethernet_hdr* eth_hdr;
		struct libnet_ipv4_hdr* ip_hdr;
		struct libnet_tcp_hdr* tcp_hdr;

		struct pcap_pkthdr* header;
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
		u_int16_t eth_type = ntohs(eth_hdr->ether_type);
		if(eth_type != 0x0800)
		{
			printf("not ip packet\n");
			continue;
		}
		
		ip_hdr = (struct libnet_ipv4_hdr*)packet;
		offset = ip_hdr->ip_hl * 4;
		packet = packet + offset;
		len = len + offset;
		if(ip_hdr->ip_p != IPPROTO_TCP)
		{
			printf("not tcp packet\n");
			continue;
		}

		tcp_hdr = (struct libnet_tcp_hdr*)packet;
		offset = tcp_hdr->th_off * 4;
		packet = packet + offset;
		len = len + offset;

		printf("========================================\n");
		printf("Ethernet dst mac: %2x:%2x:%2x:%2x:%2x:%2x\n",
			eth_hdr->ether_dhost[0],
			eth_hdr->ether_dhost[1],
			eth_hdr->ether_dhost[2],
			eth_hdr->ether_dhost[3],
			eth_hdr->ether_dhost[4],
			eth_hdr->ether_dhost[5]);
		printf("Ethernet src mac: %2x:%2x:%2x:%2x:%2x:%2x\n", 
			eth_hdr->ether_shost[0],
			eth_hdr->ether_shost[1],
			eth_hdr->ether_shost[2],
			eth_hdr->ether_shost[3],
			eth_hdr->ether_shost[4],
			eth_hdr->ether_shost[5]);

		printf("Src IP Address: %s\n",
			inet_ntoa(ip_hdr->ip_src)
			);
		printf("Dst IP Address: %s\n",
			inet_ntoa(ip_hdr->ip_dst)
			);

		printf("Src Port: %d\n", ntohs(tcp_hdr->th_sport));
		printf("Dst Port: %d\n", ntohs(tcp_hdr->th_dport));

		if(len >= header->caplen)
		{
			printf("No Data");
		}else{
			printf("Payload: ");
			for(int i=0;i<10; i++)
				printf("%02x ", packet[i]);
		}

		printf("\n");
		printf("%u bytes captured\n", header->caplen);
		printf("========================================\n");
	}

	pcap_close(pcap);
}
