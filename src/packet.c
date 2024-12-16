#include <stdio.h>
#include "packet.h"


void print_hex_dump(const uint8_t *payload, int len) {
    int i;
    const int bytes_per_line = 16;
    
    for (i = 0; i < len; i++) {
        // 16바이트마다 새 줄 시작
        if (i % bytes_per_line == 0) {
            printf("\n%04x: ", i);
        }
        
        // 16진수로 출력
        printf("%02x ", payload[i]);
        
        // 줄의 마지막이면 ASCII 출력
        if ((i + 1) % bytes_per_line == 0 || i + 1 == len) {
            // 마지막 줄의 정렬을 위한 패딩
            for (int j = 0; j < bytes_per_line - (i % bytes_per_line) - 1; j++) {
                printf("   ");
            }
            printf(" |");
            // ASCII 출력
            for (int j = i - (i % bytes_per_line); j <= i; j++) {
                if (isprint(payload[j])) printf("%c", payload[j]);
                else printf(".");
            }
            printf("|");
        }
    }
    printf("\n");
}

int is_http_packet(uint16_t src_port, uint16_t dst_port) {
    return (src_port == 80 || dst_port == 80 ||    // HTTP
            src_port == 443 || dst_port == 443);   // HTTPS
}

void analyze_payload(const uint8_t *packet, int header_length, int total_length) {
    const uint8_t *payload = packet + header_length;
    int payload_length = total_length - header_length;
    
    if (payload_length <= 0) {
        printf("No payload\n");
        return;
    }
    
    printf("Payload (%d bytes):\n", payload_length);
    print_hex_dump(payload, payload_length < 128 ? payload_length : 128);
}

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
    int tcp_header_length = tcp_header->doff * 4;
    int total_header_length = 14 + ip_header_length + tcp_header_length;  // Ethernet + IP + TCP
    
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

    // HTTP 패킷인 경우 페이로드 분석
    if (is_http_packet(ntohs(tcp_header->source), ntohs(tcp_header->dest))) {
        printf("HTTP packet detected:\n");
        analyze_payload(packet, total_header_length, total_header_length + 1500);
    }
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