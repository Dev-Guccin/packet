#include <pcap.h>
#include <stdio.h>
#include "/usr/include/net/ethernet.h"
#include "/usr/include/netinet/ip.h"

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}
int print_eth(const u_char *packet){
    printf("[");
    for(int i=0; i<6; i++)
        printf("%x:",packet[i]);
    printf("] dst mac is \n");
    printf("[");
    for(int i=0; i<6; i++)
        printf("%x:", packet[i+6]);
    printf("] src mac is \n");
    uint16_t b=packet[12];
    b=(b<<8)+packet[13];
    printf("%04x",b);
    if(b==0x0800){
        printf(" : IP\n");
        return 1;
    }
    else {
        printf(" : not IP\n");
        return 0;
    }
}
int print_ip(const u_char*packet){
   //src ip
    for(int i=0; i<4; i++){
        printf("%3d.",packet[i+26]);
    }printf(" : src ip\n");
    //dst ip
    for(int i=0; i<4; i++){
        printf("%3d.",packet[i+30]);
    }printf(" : dst ip\n");
    printf("%x",packet[23]);
    if(packet[23]==0x11){
        printf(" : UDP\n");
        return 0;
    }
    else if(packet[23]==0x06){
        printf(" : TCP\n");
        return 1;
    }
    else {
        printf(" : ???\n");
        return 0;
    }
}
int print_tcp(const u_char*packet){
    //srcport
    u_int16_t a=packet[34];
    a=(a<<8)+packet[35];
    printf("%4d : src port\n",a);
    //dstport
    u_int16_t b=packet[36];
    b=(b<<8)+packet[37];
    printf("%4d : dst port\n",b);
    return 1;
}
void print_data(const u_char*packet){
    u_int16_t a=packet[56];
    a=(a<<8)+packet[57];
    printf("%d : data length\n",a);
    printf("[");
    for(int i=0; i<10; i++){
        printf("%x ",packet[58+i]);
        if(i>=a){
            printf("] : data\n");
            return;
        }
    }
    printf("] : data\n");
}
int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    //printf("%u bytes captured\n", header->caplen);
    printf("\n\n*************check packet yeah~~~~!!!************\n");
    if(print_eth(packet))//print ethernet
          if(print_ip(packet))//print ip(src dst ip...,protocol)
                 if(print_tcp(packet))//print tcp
                     print_data(packet);//print data
  }

  pcap_close(handle);
  return 0;
}
