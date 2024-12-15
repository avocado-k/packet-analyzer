#include <stdio.h>
#include "packet.h"

const char* get_protocol_name(uint8_t protocol) {
    switch(protocol) {
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_TCP:  return "TCP";
        case IPPROTO_UDP:  return "UDP";
        default:           return "Unknown";
    }
}

void print_port_info(uint16_t src_port, uint16_t dst_port) {
    printf("  Source Port: %u\n", ntohs(src_port));
    printf("  Dest Port: %u\n", ntohs(dst_port));
}

void parse_tcp_header(const uint8_t *packet, int ip_header_length) {
    const struct tcphdr *tcp_header = (const struct tcphdr*)(packet + 14 + ip_header_length);
    
    printf("TCP Header Info:\n");
    print_port_info(tcp_header->source, tcp_header->dest);
    printf("  Sequence Number: %u\n", ntohl(tcp_header->seq));
    printf("  ACK Number: %u\n", ntohl(tcp_header->ack_seq));
    printf("  Flags:");
    if (tcp_header->fin) printf(" FIN");
    if (tcp_header->syn) printf(" SYN");
    if (tcp_header->rst) printf(" RST");
    if (tcp_header->psh) printf(" PSH");
    if (tcp_header->ack) printf(" ACK");
    if (tcp_header->urg) printf(" URG");
    printf("\n");
}

void parse_udp_header(const uint8_t *packet, int ip_header_length) {
    const struct udphdr *udp_header = (const struct udphdr*)(packet + 14 + ip_header_length);
    
    printf("UDP Header Info:\n");
    print_port_info(udp_header->source, udp_header->dest);
    printf("  Length: %u\n", ntohs(udp_header->len));
}

void parse_ip_header(const uint8_t *packet) {
    const struct ip *ip_header = (const struct ip*)(packet + 14);
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    printf("IP Header Info:\n");
    printf("  Protocol: %s\n", get_protocol_name(ip_header->ip_p));
    printf("  Source IP: %s\n", src_ip);
    printf("  Dest IP: %s\n", dst_ip);
    printf("  TTL: %u\n", ip_header->ip_ttl);
    
    int ip_header_length = ip_header->ip_hl * 4;
    
    switch(ip_header->ip_p) {
        case IPPROTO_TCP:
            parse_tcp_header(packet, ip_header_length);
            break;
        case IPPROTO_UDP:
            parse_udp_header(packet, ip_header_length);
            break;
    }
}