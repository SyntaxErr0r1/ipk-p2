#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>
#include <csignal>
#include <bitset>
#include <netinet/ether.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

enum Mode {
    TCP, UDP, ICMP, ARP, ALL
};

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}

void print_timestamp(timeval ts){
    char tmbuf[64];
    time_t time = ts.tv_sec;
    struct tm *tm = gmtime(&time);
    strftime(tmbuf, sizeof tmbuf, "timestamp: %Y-%m-%dT%H:%M:%S", tm);
    printf("%s.%iZ\n", tmbuf, (int) ts.tv_usec/1000);
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

int main(int argc, char *argv[])
{
    Mode mode = ALL;
    std::string interface = "";
    size_t n = 1;
    int port = -1;

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
            mode = TCP;
        }else if(!strcmp(current_arg,"--udp") || !strcmp(current_arg,"-u")){
            mode = UDP;
        }else if(!strcmp(current_arg,"--icmp")){
            mode = ICMP;
        }else if(!strcmp(current_arg,"--arp")){
            mode = ARP;
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
    int timeout_limit = 100; /* In milliseconds */


    /*opens the packet capturing device*/
    handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, timeout_limit, error_buffer);
    if(handle == NULL){
        perror("ERROR: while opening pcap device");
        exit(1);
    }

    for(int i=0;i<n;i++){
        printf("\n===packet %d===\n", i+1);
        packet = pcap_next(handle, &packet_header);
        if((packet != NULL) /*&& (&packet_header != NULL)*/){
            printf("Got a %d byte packet\n", packet_header.len);
            print_timestamp(packet_header.ts);
            // &packet_header->
            // dump(packet, header->len);
            
        }
    }
    
    pcap_close(handle);

    return 0;
}
