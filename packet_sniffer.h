// packet_sniffer.h

#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include <pcap.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif

