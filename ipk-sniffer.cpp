#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string>
#include <string.h>
#include <stdbool.h>
#include <csignal>
#include <bitset>
#include <netinet/ether.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

enum PacketProtocol {
    Unset, TCP, UDP, ICMP, ICMPv6, ARP
};

/**
 * @brief the packet timestamp to UTC and prints it 
 * @param ts timestamp structure of the packet
 */
void print_timestamp(timeval ts){
    char tmbuf[64];
    time_t time = ts.tv_sec;
    struct tm *tm = gmtime(&time);
    strftime(tmbuf, sizeof tmbuf, "timestamp: %Y-%m-%dT%H:%M:%S", tm);
    printf("%s.%iZ\n", tmbuf, (int) ts.tv_usec/1000);
}

/**
 * @brief prints given mac address
 * @param addr the mac address string
 */
void print_mac_addr(unsigned char addr[6]){
    for (int i = 0; i < 6; i++)
    {
        if(addr[i] == (unsigned char)'0'){
            addr[i] = (unsigned char) 'A';
            // fprintf(stderr,"REPLACING");
        }
    }
    printf("%02x:%02x:%02x:%02x:%02x:%02x", addr[0],addr[1],addr[2],addr[3],addr[4],addr[5]);
}

/**
 * @brief prints IPv4 address from the numeric format
 * @param ip the ip address uint
 */
void print_ipv4(uint32_t ip){
    printf("%03d.%03d.%03d.%03d",(ip & 0xFF000000) >> 24,(ip & 0x00FF0000) >> 16,(ip & 0x0000FF00) >> 8,ip & 0x000000FF);
}

/**
 * @brief finds where the longest row of zeros starts and its length in IPv6
 * 
 * @param address the IPv6 which will be searched
 * @param zeros_start 
 * @param zeros_length 
 * @note for example in fe80:0000:0000:0000:0215:5dff:fec5:288d would return:
 * @note zeros_start = 1 (zeros start at the 1st pair (indexing from 0))
 * @note zeros_length = 2 (the last zero pair is 2 pairs from the first)
 */
void find_zeros(struct in6_addr* address, int* zeros_start,int* zeros_length){
    int longest_zero_start = -1;
    int longest_zero_len = -1;
    int current_zero_start = -1;
    bool previous_zero = false;
    for (int i = 0; i < 8; i++)
    {
        // fprintf(stderr,"%i ",i);
        int n0 = (int)address->s6_addr[2*i];
        int n1 = (int)address->s6_addr[2*i+1];
        if(n0 == 0 && n1 == 0){
            if(previous_zero){
                if(current_zero_start == -1){
                    current_zero_start = i-1;
                    // fprintf(stderr,"new current start at %i\n",current_zero_start);
                }
                int current_len = i - current_zero_start;
                if(current_len > longest_zero_len){
                    longest_zero_start = current_zero_start;
                    longest_zero_len = current_len;
                }
            }
        }else{
            current_zero_start = -1;
            // fprintf(stderr,"current zero reset at %i\n",i);
        }

        previous_zero = n0 == 0 && n1 == 0;
    }
    (*zeros_start) = longest_zero_start;
    (*zeros_length) = longest_zero_len;
}

/**
 * @brief prints two numbers together
 * 
 * @param n0 one 8bit number 
 * @param n1 second 8bit number
 * @note used for printing IPv6 address
 */
void print_pair(int n0, int n1){
    if(n0 == 0 && n1 == 0)
        putchar('0');
    else{
        if(n0 == 0)
            printf("%x",n1);
        printf("%x%02x",n0,n1);

    }
}

/**
 * @brief prints IPv6 address from numeric format
 * @param address the ipv6 to print
 * @note according to RFC5952
 */
void print_ipv6(struct in6_addr* address){
    int zeros_start = 0;
    int zeros_length = 0;

    find_zeros(address,&zeros_start,&zeros_length);
    // fprintf(stderr,"\nlongest zero start: %d, len: %d\n",zeros_start,zeros_length);
    
    for (int i = 0; i < 8; i++)
    {
        int n0 = (int)address->s6_addr[2*i];
        int n1 = (int)address->s6_addr[2*i+1];
        if(i >= zeros_start && zeros_length >= 0){
            //if there are zeros we will skip
            if(i == zeros_start)
                printf(":");
            zeros_length--;
        }else{
            //otherwise print normally
            print_pair(n0,n1);

            if(i < 7)
                putchar(':');
        }
    }
    
    // printf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
    // (int)address->s6_addr[0], (int)address->s6_addr[1],(int)address->s6_addr[2], (int)address->s6_addr[3],
    // (int)address->s6_addr[4], (int)address->s6_addr[5],(int)address->s6_addr[6], (int)address->s6_addr[7],
    // (int)address->s6_addr[8], (int)address->s6_addr[9],(int)address->s6_addr[10], (int)address->s6_addr[11],
    // (int)address->s6_addr[12], (int)address->s6_addr[13],(int)address->s6_addr[14], (int)address->s6_addr[15]);
}

/**
 * @brief Prints ethernet header of given frame
 * @param packet the packet of which header will be printed
 * @param packet_header pcap packet header
 */
void print_eth_header(const u_char* packet, struct pcap_pkthdr packet_header){
    struct ethhdr *eth = (struct ethhdr *)packet;

    print_timestamp(packet_header.ts);
    printf("src MAC: ");
    print_mac_addr(eth->h_source);
    printf("\ndst MAC: ");
    print_mac_addr(eth->h_dest);
    putchar('\n');
    printf("frame length: %d bytes\n", packet_header.len);
}

/**
 * @brief prints the internet protocol header
 * @param packet the packet of which the header will be printed
 */
void print_ip_header(const u_char* packet){
    struct iphdr* ip_header = (struct iphdr *) (packet + ETH_HLEN);
    sockaddr_in addr_src, addr_dst;
    
    memset(&addr_src, 0, sizeof(addr_src));
	addr_src.sin_addr.s_addr = ip_header->saddr;
	
	memset(&addr_dst, 0, sizeof(addr_dst));
	addr_dst.sin_addr.s_addr = ip_header->daddr;

    printf("src IP: %s", inet_ntoa(addr_src.sin_addr));
    printf("\ndst IP: %s",inet_ntoa(addr_dst.sin_addr));
    putchar('\n');
}

/**
 * @brief Prints header of IPv6 packet
 * @param packet the packet to print
 */
void print_ip6_header(const u_char* packet){
    struct ip6_hdr* ip6_header = (struct ip6_hdr *) (packet + ETH_HLEN);
    printf("src IP:");
    print_ipv6(&(ip6_header->ip6_src));
    printf("\ndst IP:");
    print_ipv6(&(ip6_header->ip6_dst));
    putchar('\n');
}

/**
 * @brief prints the list of all network interfaces
 */
void print_all_interfaces(){
    char errbuf[127];
    pcap_if_t *alldevsp , *interface;

	if( pcap_findalldevs( &alldevsp , errbuf) )
	{
		printf("Error while finding interfaces : %s" , errbuf);
		exit(1);
	}

    interface = alldevsp;
    while (interface != NULL)
    {
        printf("%-10s\n" , interface->name);
        interface = interface->next;
    }

    pcap_freealldevs(alldevsp);
}

/**
 * @brief checks if the packet has given port
 * 
 * @param packet the packet which will be checked
 * @param port number of checked port
 * @return true if packet's port == port
 * @return false otherwise
 */
bool has_port(const u_char* packet, uint16_t port){

    struct iphdr* ip_header = (struct iphdr *) (packet + ETH_HLEN);
    int ip_header_len = (int) ip_header->ihl*4;
    
    uint16_t source;
    uint16_t dest;
    
    if(ip_header->protocol == IPPROTO_TCP){
        struct tcphdr* tcp_header= (struct tcphdr*)(packet + ip_header_len + ETH_HLEN);
        source = ntohs(tcp_header->source);
        dest = ntohs(tcp_header->dest);
    }else if(ip_header->protocol == IPPROTO_UDP){
        struct udphdr* udp_header = (struct udphdr*)(packet + ip_header_len + ETH_HLEN);
        source = ntohs(udp_header->source);
        dest = ntohs(udp_header->dest);
    }else{
        return false;
    }

    return port == source || port == dest;

}

/**
 * @brief prints one line of packet
 * 
 * @param packet printed packet
 * @param len how many bytes to print
 * @param offset where to start printing from
 */
void print_payload_line(const u_char* packet, int len, int offset){
    for (int i = 0; i < 16; i++)
    {
        unsigned char c = (unsigned char) packet[i+offset];
        if(i == 8)
            putchar(' ');
        if(i < len)
            printf("%02x",c);
        else
            printf("  ");

        putchar(' ');
    }
    
    for (int i = 0; i < len; i++)
    {
        unsigned char c = (unsigned char) packet[i+offset];
        if(i == 8)
            putchar(' ');
        if(isprint(c))
            printf("%c",c);
        else
            putchar('.');
    }
    putchar('\n');
}

/**
 * @brief prints the whole packet
 * 
 * @param packet will be printed
 * @param len length of the packet
 */
void print_payload(const u_char* packet, int len){
    int len_remaining = len;
    int line_count = 0;
    printf("\n",len_remaining);
    while(len_remaining > 0){
        int offset = line_count * 16;
        int line_len = (len_remaining > 16) ? 16 : len_remaining;
        printf("0x%04x ",offset,offset,line_len);
        print_payload_line(packet, line_len, offset);

        len_remaining = len_remaining - 16;
        line_count++;
    }
}

/**
 * @brief prints TCP packet info
 * 
 * @param packet will be printed
 * @param packet_header header of the packet
 */
void print_tcp(const u_char* packet, pcap_pkthdr packet_header,bool is_ipv6){
    int ip_header_len;
    if(!is_ipv6){
        struct iphdr* ip_header = (struct iphdr *) (packet + ETH_HLEN);
        ip_header_len = (int) ip_header->ihl*4;
        print_ip_header(packet);
    }else{
        ip_header_len = 40;
        print_ip6_header(packet);
    }

    fprintf(stderr,"protocol: TCP\n");
    struct tcphdr* tcp_header= (struct tcphdr*)(packet + ip_header_len + ETH_HLEN);
    printf("src port: %u\n",ntohs(tcp_header->source));
    printf("dst port: %u\n",ntohs(tcp_header->dest));

    print_payload(packet,packet_header.len);
}

/**
 * @brief prints info about given UDP packet
 * 
 * @param packet the packet to be printed
 * @param packet_header header of the packet
 */
void print_udp(const u_char* packet, pcap_pkthdr packet_header, bool is_ipv6){
    int ip_header_len;
    if(!is_ipv6){
        struct iphdr* ip_header = (struct iphdr *) (packet + ETH_HLEN);
        ip_header_len = (int) ip_header->ihl*4;
        print_ip_header(packet);
    }else{
        ip_header_len = 40;
        print_ip6_header(packet);
    }

    fprintf(stderr,"protocol: UDP\n");
    struct udphdr* udp_header = (struct udphdr*)(packet + ip_header_len + ETH_HLEN);
    printf("src port: %u\n",ntohs(udp_header->source));
    printf("dst port: %u\n",ntohs(udp_header->dest));

    print_payload(packet,packet_header.len);
    
}

/**
 * @brief prints ARP protocol
 * 
 * @param packet 
 * @param packet_header 
 */
void print_arp(const u_char* packet, pcap_pkthdr packet_header){
    fprintf(stderr, "protocol: ARP\n");
    print_payload(packet,packet_header.len);
}

/**
 * @brief prints ICMP protocol
 * 
 * @param packet 
 * @param packet_header 
 */
void print_icmp(const u_char* packet, pcap_pkthdr packet_header, bool is_ipv6){
    fprintf(stderr,"protocol: %s\n", (is_ipv6) ? "ICMPv6" : "ICMP");
    if(!is_ipv6)
        print_ip_header(packet);
    else
        print_ip6_header(packet);

    print_payload(packet,packet_header.len);
}

int main(int argc, char *argv[])
{
    std::string interface = "";
    size_t n = 1;
    int port = -1;

    bool capture_icmp = false;
    bool capture_arp = false;
    bool capture_tcp = false;
    bool capture_udp = false;

    /**
     * PARSING ARGUMENTS
     */
    for (size_t i = 0; i < argc; i++)
    {
        char * current_arg = argv[i];
        if(!strcmp(current_arg,"--interface") || !strcmp(current_arg,"-i")){
            if(i+1 < argc){
                char * next_arg = argv[i+1];
                if (next_arg[0] != '-'){
                        interface.assign(next_arg);
                        i++;
                }
            }
        }else if(!strcmp(current_arg,"-p")){
            if(i+1 < argc){
                char * next_arg = argv[i+1];
                if (next_arg[0] != '-'){
                    port = atoi(next_arg);
                    i++;
                }
            }
        }else if(!strcmp(current_arg,"--tcp") || !strcmp(current_arg,"-t")){
            capture_tcp = true;
        }else if(!strcmp(current_arg,"--udp") || !strcmp(current_arg,"-u")){
            capture_udp = true;
        }else if(!strcmp(current_arg,"--icmp")){
            capture_icmp = true;
        }else if(!strcmp(current_arg,"--arp")){
            capture_arp = true;
        }else if(!strcmp(current_arg,"-n")){
            if(i+1 < argc){
                char * next_arg = argv[i+1];
                if (next_arg[0] != '-'){
                    n = atoi(next_arg);
                    i++;
               }
            }
        }   
    }

    if(!capture_arp && !capture_icmp && !capture_tcp && !capture_udp){
        capture_icmp = true;
        capture_arp = true;
        capture_tcp = true;
        capture_udp = true;
    }

    // fprintf(stderr,"capture icmp:%i\n",capture_icmp);
    // fprintf(stderr,"capture arp:%i\n",capture_arp);
    // fprintf(stderr,"capture tcp:%i\n",capture_tcp);
    // fprintf(stderr,"capture udp:%i\n",capture_udp);
   
    // fprintf(stderr,"MODE: %i\n",mode);
    // fprintf(stderr,"Interface: %s\n",interface.c_str());
    // fprintf(stderr,"n: %u\n",n);
    // fprintf(stderr,"port: %i\n",port);

    if(interface.empty()){
        print_all_interfaces();
        exit(0);
    }

    /**
     * SETTING UP LIBPCAP
     */
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    int timeout_limit = 100;

    handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, timeout_limit, error_buffer);
    if(handle == NULL){
        perror("ERROR: while opening pcap device");
        exit(1);
    }

    /**
     * PACKET CAPTURE
     */
    int packet_count = 0;
    while (packet_count < n){
        PacketProtocol protocol = Unset;
        bool is_ipv6 = false;

        packet = pcap_next(handle, &packet_header);
        if((packet != NULL) /*&& (&packet_header != NULL)*/){

            struct ether_header* eth_header = (struct ether_header *) packet;

            //DETERMINING AND FILTERING APPROPRIATE PROTOCOL AND PORT
            switch (ntohs(eth_header->ether_type))
            {
                case ETHERTYPE_IP:{
                    struct iphdr* ip_header = (struct iphdr *) (packet + ETH_HLEN);
                    if(ip_header->protocol == IPPROTO_ICMP && capture_icmp){
                        protocol = ICMP;
                    }else if(ip_header->protocol == IPPROTO_ICMPV6 && capture_icmp){
                        protocol = ICMPv6;
                    }else if(ip_header->protocol == IPPROTO_TCP && capture_tcp){
                        if(port == -1 || has_port(packet,port))
                            protocol = TCP;
                    }else if(ip_header->protocol == IPPROTO_UDP && capture_udp){
                        if(port == -1 || has_port(packet,port))
                            protocol = UDP;
                    }
                    break;
                }
                case ETHERTYPE_IPV6:{
                    {
                        struct ip6_hdr* ip6_header = (struct ip6_hdr *) (packet + ETH_HLEN);
                        if(ip6_header->ip6_nxt == IPPROTO_ICMPV6){
                            protocol = ICMPv6;
                        }else if(ip6_header->ip6_nxt == IPPROTO_TCP){
                            protocol = TCP;
                        }else if(ip6_header->ip6_nxt ==IPPROTO_UDP){
                            protocol = UDP;
                        }
                        is_ipv6 = true;
                    };
                    
                    break;
                }
                case ETHERTYPE_ARP:{
                    if(capture_arp)
                        protocol = ARP;
                    break;
                }
                // default:
                    // printf("ether type: %hu",ntohs(eth_header->ether_type));
            }
        }
        
        if(protocol != Unset){
            print_eth_header(packet,packet_header);

            if(protocol == ICMP || protocol == ICMPv6)
                print_icmp(packet,packet_header, is_ipv6);
            else if(protocol == TCP)
                print_tcp(packet,packet_header,is_ipv6);
            else if(protocol == UDP)
                print_udp(packet,packet_header,is_ipv6);
            else if(protocol == ARP)
                print_arp(packet,packet_header);
            packet_count++;
        }
    }
    
    pcap_close(handle);

    return 0;
}
