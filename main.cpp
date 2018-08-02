#include <pcap.h>
#include <stdio.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>

void usage() {
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}

void mac_print(uint8_t mac[6]) {

    for(int i=0; i<6; i++){
        printf("%02x",mac[i]);
        if (i != 5)
            printf(":");
    }
}

void ip_print(uint32_t ip){
    char buf[20];
    inet_ntop(AF_INET, &ip, buf, sizeof(buf));
    printf("%s\n", buf);

}

void port_print(uint16_t port){
    printf("%d\n",ntohs(port));
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

    while (true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        printf("%u bytes captured\n", header->caplen);
        struct ether_header *ep = (struct ether_header*)packet;
        if (ntohs(ep->ether_type) == ETHERTYPE_IP)
        {
            packet +=sizeof(ether_header);
            struct iphdr *ip = (struct iphdr *)packet;
            if (ip->protocol == IPPROTO_TCP)
            {

                printf("src mac= ");
                mac_print(ep->ether_shost);
                printf("\n");
                printf("dst mac= ");
                mac_print(ep->ether_dhost);


                printf("\n");
                printf("src ip= ");
                ip_print(ip->saddr);
                printf("dst ip= ");
                ip_print(ip->daddr);

                packet += ip->ihl*4;
                struct tcphdr *tp = (struct tcphdr *)packet;


                printf("src port =");
                port_print(tp->source);
                printf("dst port =");
                port_print(tp->dest);

                if(ntohs(tp->dest) == 80 || ntohs(tp->source) == 80)
                {
                    packet += tp->doff*4;
                    if(((ntohs(ip->tot_len)) - (ip->ihl*4 + tp->doff*4)) >= 16)
                    {
                        printf("data = ");
                        for(int i=0; i<16; i++)
                            printf("%02x ", packet[i]);
                        printf("\n");
                        printf("------------------------------------");
                    }
                }

            }
        }

        printf("\n");
    }

    pcap_close(handle);
    return 0;
}

