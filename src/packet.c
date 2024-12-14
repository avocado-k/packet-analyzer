#include <stdio.h>
#include "packet.h"

const char* get_protocol_name(u_char protocol) {
    switch(protocol) {
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_TCP:  return "TCP";
        case IPPROTO_UDP:  return "UDP";
        default:           return "Unknown";
    }
}

void parse_ip_header(const u_char *packet) {
    struct ip *ip_header = (struct ip*)(packet + 14);  // Skip Ethernet header
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    
    // Convert IP addresses to string format
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    // Print IP header information
    printf("IP Header Info:\n");
    printf("  Protocol: %s\n", get_protocol_name(ip_header->ip_p));
    printf("  Source IP: %s\n", src_ip);
    printf("  Dest IP: %s\n", dst_ip);
    printf("  TTL: %d\n", ip_header->ip_ttl);
}