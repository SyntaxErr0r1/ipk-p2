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

void print_timestamp(timeval ts){
    char tmbuf[64];
    time_t time = ts.tv_sec;
    struct tm *tm = gmtime(&time);
    strftime(tmbuf, sizeof tmbuf, "timestamp: %Y-%m-%dT%H:%M:%S", tm);
    printf("%s.%iZ\n", tmbuf, (int) ts.tv_usec/1000);
}

void print_mac_addr(unsigned char addr[6]){
    for (int i = 0; i < 6; i++)
    {
        if(addr[i] == (unsigned char)'0'){
            addr[i] = (unsigned char) 'A';
            fprintf(stderr,"REPLACING");
        }
    }
    
    printf("%02x:%02x:%02x:%02x:%02x:%02x", addr[0],addr[1],addr[2],addr[3],addr[4],addr[5]);
}

void print_ipv4(uint32_t ip){
    printf("%03d.%03d.%03d.%03d",(ip & 0xFF000000) >> 24,(ip & 0x00FF0000) >> 16,(ip & 0x0000FF00) >> 8,ip & 0x000000FF);
}

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

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}

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

void print_arp(const u_char* packet, pcap_pkthdr packet_header){
}

void print_icmp(const u_char* packet, pcap_pkthdr packet_header){
    print_ip_header(packet);
    
}

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

void print_tcp(const u_char* packet, pcap_pkthdr packet_header){
    struct iphdr* ip_header = (struct iphdr *) (packet + ETH_HLEN);
    int ip_header_len = (int) ip_header->ihl*4;
    print_ip_header(packet);
    fprintf(stderr,"IP header length: %d\n",ip_header_len);

    fprintf(stderr,"protocol: TCP\n");
    struct tcphdr* tcp_header= (struct tcphdr*)(packet + ip_header_len + ETH_HLEN);
    printf("src port: %u\n",ntohs(tcp_header->source));
    printf("dst port: %u\n",ntohs(tcp_header->dest));
}

void print_udp(const u_char* packet, pcap_pkthdr packet_header){
    struct iphdr* ip_header = (struct iphdr *) (packet + ETH_HLEN);
    int ip_header_len = ip_header->ihl*4;
    print_ip_header(packet);

    fprintf(stderr,"protocol: UDP\n");
    struct udphdr* udp_header = (struct udphdr*)(packet + ip_header_len + ETH_HLEN);
    printf("src port: %u\n",ntohs(udp_header->source));
    printf("dst port: %u\n",ntohs(udp_header->dest));
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

    int packet_count = 0;
    while (packet_count < n){
        PacketProtocol protocol = Unset;

        packet = pcap_next(handle, &packet_header);
        if((packet != NULL) /*&& (&packet_header != NULL)*/){

            struct ether_header* eth_header = (struct ether_header *) packet;

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

            if(protocol == ICMP)
                print_icmp(packet,packet_header);
            else if(protocol == TCP)
                print_tcp(packet,packet_header);
            else if(protocol == UDP)
                print_udp(packet,packet_header);
            else if(protocol == ARP)
                print_arp(packet,packet_header);
            packet_count++;
        }
    }
    
    pcap_close(handle);

    return 0;
}
