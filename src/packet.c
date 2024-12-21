#include <stdio.h>
#include "packet.h"


void init_rate_monitor(packet_rate_t *rate) {
    memset(rate, 0, sizeof(packet_rate_t));
    rate->last_update = time(NULL);
}

void update_rate(packet_rate_t *rate, uint32_t packet_len) {
    time_t current_time = time(NULL);
    rate->packet_count++;
    rate->byte_count += packet_len;
    
    // 1초마다 속도 계산
    double elapsed = difftime(current_time, rate->last_update);
    if (elapsed >= 1.0) {
        // PPS 계산
        rate->current_pps = rate->packet_count / elapsed;
        if (rate->current_pps > rate->peak_pps) {
            rate->peak_pps = rate->current_pps;
        }
        
        // BPS 계산 (bytes를 bits로 변환: * 8)
        rate->current_bps = (rate->byte_count * 8) / elapsed;
        if (rate->current_bps > rate->peak_bps) {
            rate->peak_bps = rate->current_bps;
        }
        
        // 카운터 리셋
        rate->packet_count = 0;
        rate->byte_count = 0;
        rate->last_update = current_time;
    }
}

void print_rate(const packet_rate_t *rate) {
    printf("\033[2K\r"); // 현재 줄 지우기
    printf("Current Rate: %.2f pps (Peak: %.2f) | ", 
           rate->current_pps, rate->peak_pps);
    
    // BPS를 적절한 단위로 변환
    if (rate->current_bps >= 1e9) {
        printf("%.2f Gbps", rate->current_bps / 1e9);
    } else if (rate->current_bps >= 1e6) {
        printf("%.2f Mbps", rate->current_bps / 1e6);
    } else if (rate->current_bps >= 1e3) {
        printf("%.2f Kbps", rate->current_bps / 1e3);
    } else {
        printf("%.2f bps", rate->current_bps);
    }
    
    fflush(stdout);  // 버퍼 즉시 출력
}


void init_stats(packet_stats_t *stats) {
    memset(stats, 0, sizeof(packet_stats_t));
}

void update_stats(packet_stats_t *stats, const uint8_t *packet, uint32_t packet_len) {
    const struct ip *ip_header = (const struct ip*)(packet + 14);
    stats->total_packets++;
    stats->total_bytes += packet_len;

    // 프로토콜별 카운트
    switch(ip_header->ip_p) {
        case IPPROTO_TCP: {
            stats->tcp_packets++;
            const struct tcphdr *tcp_header = 
                (const struct tcphdr*)(packet + 14 + ip_header->ip_hl * 4); //이더넷 헤더 구조 (총 14바이트)
            uint16_t src_port = ntohs(tcp_header->source);
            uint16_t dst_port = ntohs(tcp_header->dest);
            
            // HTTP/HTTPS 패킷 카운트
            if (src_port == 80 || dst_port == 80) {
                stats->http_packets++;
            } else if (src_port == 443 || dst_port == 443) {
                stats->https_packets++;
            }
            break;
        }
        case IPPROTO_UDP:
            stats->udp_packets++;
            break;
        case IPPROTO_ICMP:
            stats->icmp_packets++;
            break;
        default:
            stats->other_packets++;
            break;
    }
}

void print_stats(const packet_stats_t *stats) {
    printf("\n=== Packet Statistics ===\n");
    printf("Total Packets: %u\n", stats->total_packets);
    printf("Total Bytes: %lu\n", stats->total_bytes);
    printf("Average Packet Size: %.2f bytes\n", 
           stats->total_packets ? (float)stats->total_bytes/stats->total_packets : 0);
    
    printf("\nProtocol Distribution:\n");
    printf("TCP: %u (%.1f%%)\n", stats->tcp_packets, 
           stats->total_packets ? (float)stats->tcp_packets/stats->total_packets*100 : 0);
    printf("UDP: %u (%.1f%%)\n", stats->udp_packets,
           stats->total_packets ? (float)stats->udp_packets/stats->total_packets*100 : 0);
    printf("ICMP: %u (%.1f%%)\n", stats->icmp_packets,
           stats->total_packets ? (float)stats->icmp_packets/stats->total_packets*100 : 0);
    printf("Other: %u (%.1f%%)\n", stats->other_packets,
           stats->total_packets ? (float)stats->other_packets/stats->total_packets*100 : 0);
    
    printf("\nWeb Traffic:\n");
    printf("HTTP: %u packets\n", stats->http_packets);
    printf("HTTPS: %u packets\n", stats->https_packets);
}

void init_filter(packet_filter_t *filter) {
    filter->src_ip = NULL;
    filter->dst_ip = NULL;
    filter->src_port = 0;
    filter->dst_port = 0;
}

void set_filter(packet_filter_t *filter, const char *src_ip, 
                const char *dst_ip, uint16_t src_port, uint16_t dst_port) {
    filter->src_ip = src_ip ? strdup(src_ip) : NULL;
    filter->dst_ip = dst_ip ? strdup(dst_ip) : NULL;
    filter->src_port = src_port;
    filter->dst_port = dst_port;
}

int apply_filter(const uint8_t *packet, const packet_filter_t *filter) {
    const struct ip *ip_header = (const struct ip*)(packet + 14);
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    // IP 필터 체크
    if (filter->src_ip && strcmp(src_ip, filter->src_ip) != 0) return 0;
    if (filter->dst_ip && strcmp(dst_ip, filter->dst_ip) != 0) return 0;

    // 포트 필터 체크 (TCP/UDP인 경우만)
    if (filter->src_port || filter->dst_port) {
        if (ip_header->ip_p == IPPROTO_TCP) {
            const struct tcphdr *tcp_header = 
                (const struct tcphdr*)(packet + 14 + ip_header->ip_hl * 4);
            if (filter->src_port && ntohs(tcp_header->source) != filter->src_port) return 0;
            if (filter->dst_port && ntohs(tcp_header->dest) != filter->dst_port) return 0;
        }
        else if (ip_header->ip_p == IPPROTO_UDP) {
            const struct udphdr *udp_header = 
                (const struct udphdr*)(packet + 14 + ip_header->ip_hl * 4);
            if (filter->src_port && ntohs(udp_header->source) != filter->src_port) return 0;
            if (filter->dst_port && ntohs(udp_header->dest) != filter->dst_port) return 0;
        }
    }
    
    return 1;  // 모든 필터 조건 통과
}


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