// flow.c
//1

#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>  
#include <arpa/inet.h>
#include <time.h>
#include "packet_sniffer.h"


const char* get_protocol_name(unsigned int proto) {
    static char unknown_protocol[30];

    switch (proto) {
        case IPPROTO_ICMP:
            return "ICMP";
        case IPPROTO_IGMP:
            return "IGMP";
        case IPPROTO_IPIP:
            return "IPIP";
        case IPPROTO_TCP:
            return "TCP";
        case IPPROTO_EGP:
            return "EGP";
        case IPPROTO_PUP:
            return "PUP";
        case IPPROTO_UDP:
            return "UDP";
        case IPPROTO_IDP:
            return "IDP";
        case IPPROTO_TP:
            return "TP";
        case IPPROTO_DCCP:
            return "DCCP";
        case IPPROTO_IPV6:
            return "IPv6";
        case IPPROTO_RSVP:
            return "RSVP";
        case IPPROTO_GRE:
            return "GRE";
        case IPPROTO_ESP:
            return "ESP";
        case IPPROTO_AH:
            return "AH";
        case IPPROTO_MTP:
            return "MTP";
        case IPPROTO_BEETPH:
            return "BEETPH";
        case IPPROTO_ENCAP:
            return "ENCAP";
        case IPPROTO_PIM:
            return "PIM";
        case IPPROTO_COMP:
            return "COMP";
        case IPPROTO_SCTP:
            return "SCTP";
        case IPPROTO_UDPLITE:
            return "UDPLITE";
        case IPPROTO_MPLS:
            return "MPLS";
        case IPPROTO_RAW:
            return "RAW";
        default:
            snprintf(unknown_protocol, sizeof(unknown_protocol), "UNKNOWN(%u)", proto);
            return unknown_protocol;
    }
}

void print_tcp_packet(const u_char *packet, struct iphdr *ip_header) {
    unsigned short ip_header_len = ip_header->ihl * 4;
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + ip_header_len);
    printf("Source Port: %d\n", ntohs(tcp_header->source));
    printf("Destination Port: %d\n", ntohs(tcp_header->dest));
    printf("Sequence Number: %u\n", ntohl(tcp_header->seq));
    printf("Acknowledgment Number: %u\n", ntohl(tcp_header->ack_seq));
    printf("Flags: %c%c%c%c%c%c\n",
           (tcp_header->urg ? 'U' : '*'),
           (tcp_header->ack ? 'A' : '*'),
           (tcp_header->psh ? 'P' : '*'),
           (tcp_header->rst ? 'R' : '*'),
           (tcp_header->syn ? 'S' : '*'),
           (tcp_header->fin ? 'F' : '*'));
    printf("Window Size: %d\n", ntohs(tcp_header->window));
    printf("Urgent Pointer: %d\n", tcp_header->urg_ptr);
}

void print_udp_packet(const u_char *packet, struct iphdr *ip_header) {
    unsigned short ip_header_len = ip_header->ihl * 4;
    struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ethhdr) + ip_header_len);
    printf("Source Port: %d\n", ntohs(udp_header->source));
    printf("Destination Port: %d\n", ntohs(udp_header->dest));
}

void print_icmp_packet(const u_char *packet, struct iphdr *ip_header) {
    unsigned short ip_header_len = ip_header->ihl * 4;
    struct icmphdr *icmp_header = (struct icmphdr *)(packet + sizeof(struct ethhdr) + ip_header_len);
    printf("ICMP Type: %d\n", (unsigned int)(icmp_header->type));
    printf("ICMP Code: %d\n", (unsigned int)(icmp_header->code));
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
    
    // Ensure IP header is within the packet boundaries
    if ((unsigned char *)(ip_header + 1) > (packet + header->caplen)) {
        fprintf(stderr, "IP header exceeds packet size, skipping packet.\n");
        return;
    }

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    time_t now = header->ts.tv_sec;
    struct tm *ltime = localtime(&now);
    char timestr[16];
    strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);

    inet_ntop(AF_INET, &(ip_header->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->daddr), dst_ip, INET_ADDRSTRLEN);

    FILE *log_file = (FILE *)args;

    fprintf(log_file, "%s.%06ld,%d,%s,%s,%s,%d",
            timestr, (long)header->ts.tv_usec, ip_header->ttl,
            get_protocol_name(ip_header->protocol), src_ip, dst_ip,
            header->len);

    unsigned short source_port = 0, dest_port = 0;
    if (ip_header->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + ip_header->ihl * 4 + sizeof(struct ethhdr));
        source_port = ntohs(tcp_header->source);
        dest_port = ntohs(tcp_header->dest);
    } else if (ip_header->protocol == IPPROTO_UDP) {
        struct udphdr *udp_header = (struct udphdr *)(packet + ip_header->ihl * 4 + sizeof(struct ethhdr));
        source_port = ntohs(udp_header->source);
        dest_port = ntohs(udp_header->dest);
    }

    // If we have valid port information, print it.
    if (source_port && dest_port) {
        fprintf(log_file, ",%d,%d\n", source_port, dest_port);
    } else {
        fprintf(log_file, ",,\n");
    }
}



int main() {
    pcap_if_t *alldevsp, *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    
    FILE *log_file = fopen("traffic_log.csv", "w");
    if (!log_file) {
        fprintf(stderr, "Couldn't open log file for writing.\n");
        return 2;
    }
    
    // Write CSV header
    fprintf(log_file, "Time,TTL,Protocol,Source IP,Destination IP,Packet Size,Source Port,Destination Port\n");

    // 獲取網路介面卡
    if (pcap_findalldevs(&alldevsp, errbuf) == -1) {
        fprintf(stderr, "Not Found The Device: %s\n", errbuf);
        return(2);
    }

    // 自動選擇第一張網路介面卡
    device = alldevsp;
    if (device == NULL) {
        fprintf(stderr, "Not Found The Device\n");
        return(2);
    }
    printf("Dev: %s\n", device->name);

    // 針對當前網路介面卡進行流量的擷取
    handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "open error %s: %s\n", device->name, errbuf);
        return(2);
    }

    // 進行流量擷取
    pcap_loop(handle, -1, got_packet, (u_char *)log_file);
    

    // Write CSV header

    fclose(log_file);
    pcap_freealldevs(alldevsp); // 釋放當前網路介面卡
    pcap_close(handle); 
    return(0);
}
