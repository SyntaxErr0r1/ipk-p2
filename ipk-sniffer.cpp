#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>

enum Mode {
    TCP, UDP, ICMP, ARP, ALL
};

int main(int argc, char *argv[])
{
    Mode mode = ALL;
    std::string interface = "";
    size_t n = 1;
    int opt;
    int port = -1;

    struct option longopts[] = {
        { "interface", optional_argument, 0, 'i' },
        { "tcp", no_argument, NULL, 't' },
        { "udp", no_argument, NULL, 'u' },
        { "icmp", required_argument, NULL, true },
        { "arp", required_argument, NULL, true },
        { "n", required_argument, NULL, true },
        { 0 }
    };

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
   
    

    printf("MODE: %i\n",mode);
    printf("Interface: %s\n",interface.c_str());
    printf("n: %u\n",n);
    printf("port: %u\n",port);
    /* code */
    return 0;
}
