#include "yhs_libnet.h"

#define RPT 3
#define PROMISC 1
#define NONPROM 0

int print_devlist();		/* Print list of available network devices */
int print_netdev(char* dev);	/* Print Network Device Info */
void callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void getIPMAC(struct mac_addr* mymac, struct in_addr* myip);

int main() {

	int fd, j;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int8_t mymac[ETHER_ADDR_LEN];
	struct in_addr myip;
	struct bpf_program fp;
	struct libnet_ether_addr *mac_addr;

	bpf_u_int32 netp, maskp;
	pcap_t *handle;

	/*libnet_t *l;
	l=libnet_init(LIBNET_RAW4, NULL, errbuf);
	mac_addr = libnet_get_hwaddr(l); 
printf("MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",\
        mac_addr->ether_addr_octet[0],\
        mac_addr->ether_addr_octet[1],\
        mac_addr->ether_addr_octet[2],\
        mac_addr->ether_addr_octet[3],\
        mac_addr->ether_addr_octet[4],\
        mac_addr->ether_addr_octet[5]);
	/*getIPMAC(&s_mymac, &myip);
	mymac = s_mymac.maddr;

	printf("%s\n", inet_ntoa(myip));
	printf("%d\n", sizeof(mymac));
	printf("%02x %02x %02x %02x %02x %02x\n", mymac[0], mymac[1], mymac[2], mymac[3], mymac[4], mymac[5]);*/
	char filter_exp[] = "port 80";	/* *** FILTERING RULE *** */

	if((dev = pcap_lookupdev(errbuf)) == NULL){
		fprintf(stderr, "%s\n", errbuf);
		return -1;
	}
	if((pcap_lookupnet(dev, &netp, &maskp, errbuf)) == -1){
		fprintf(stderr, "%s\n", errbuf);
		return -1;
	}

	//if(print_devlist()) 	return -1;
	//if(print_netdev(dev)) 	return -1;
	
	handle = pcap_open_live(dev, BUFSIZ, NONPROM, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported.\n", dev);
		return -1;
	}
	if (pcap_compile(handle, &fp, filter_exp, 0, netp) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return -1;
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return -1;
	}
	
	
	pcap_loop(handle, RPT, callback, NULL);

	return 0;
}

void getIPMAC(u_int8_t* mymac, struct in_addr *myip){
	
	int fd;
	struct ifreq ifr;

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, "eth0", IFNAMSIZ-1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	*myip = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr;
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	mymac = (unsigned char*) ifr.ifr_hwaddr.sa_data;

	close(fd);

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
