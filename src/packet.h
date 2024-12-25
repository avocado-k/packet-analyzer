#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>  // uint8_t, uint16_t 등을 위한 헤더
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <netinet/ip_icmp.h> 
#include <netinet/ip6.h>

void parse_ipv6_header(const uint8_t *packet);
void print_ipv6_addr(const struct in6_addr *addr);

void parse_icmp_header(const uint8_t *packet, int ip_header_length);
const char* get_icmp_type(uint8_t type);

typedef struct {
    uint32_t total_packets;      // 전체 패킷 
    uint32_t tcp_packets;        // TCP 패킷 
    uint32_t udp_packets;        // UDP 패킷 
    uint32_t icmp_packets;       // ICMP 패킷 
    uint32_t other_packets;      // 기타 패킷 
    uint64_t total_bytes;        // 전체 바이트 
    uint32_t http_packets;       // HTTP 패킷 
    uint32_t https_packets;      // HTTPS 패킷 
} packet_stats_t;

typedef struct {
    char *src_ip;        // 출발지 IP (NULL이면 모든 IP)
    char *dst_ip;        // 목적지 IP (NULL이면 모든 IP)
    uint16_t src_port;   // 출발지 포트 (0이면 모든 포트)
    uint16_t dst_port;   // 목적지 포트 (0이면 모든 포트)
} packet_filter_t;

typedef struct {
    time_t last_update;         // 마지막 업데이트 시간
    uint32_t packet_count;      // 현재 구간의 패킷 수
    uint64_t byte_count;        // 현재 구간의 바이트 수
    float current_pps;          // 현재 PPS
    float current_bps;          // 현재 BPS
    float peak_pps;            // 최고 PPS
    float peak_bps;            // 최고 BPS
} packet_rate_t;

void init_rate_monitor(packet_rate_t *rate);
void update_rate(packet_rate_t *rate, uint32_t packet_len);
void print_rate(const packet_rate_t *rate);

void init_stats(packet_stats_t *stats);
void update_stats(packet_stats_t *stats, const uint8_t *packet, uint32_t packet_len);
void print_stats(const packet_stats_t *stats);

int apply_filter(const uint8_t *packet, const packet_filter_t *filter);
void init_filter(packet_filter_t *filter);
void set_filter(packet_filter_t *filter, const char *src_ip, 
                const char *dst_ip, uint16_t src_port, uint16_t dst_port);
                
void parse_ip_header(const uint8_t *packet);
const char* get_protocol_name(uint8_t protocol);
void parse_tcp_header(const uint8_t *packet, int ip_header_length);
void parse_udp_header(const uint8_t *packet, int ip_header_length);
void print_port_info(uint16_t src_port, uint16_t dst_port);

void analyze_payload(const uint8_t *packet, int header_length, int total_length);
int is_http_packet(uint16_t src_port, uint16_t dst_port);
void print_hex_dump(const uint8_t *payload, int len);

#endif // PACKET_H