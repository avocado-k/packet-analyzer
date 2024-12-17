#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>  // uint8_t, uint16_t 등을 위한 헤더
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>


typedef struct {
    char *src_ip;        // 출발지 IP (NULL이면 모든 IP)
    char *dst_ip;        // 목적지 IP (NULL이면 모든 IP)
    uint16_t src_port;   // 출발지 포트 (0이면 모든 포트)
    uint16_t dst_port;   // 목적지 포트 (0이면 모든 포트)
} packet_filter_t;


// uint8_t: 1바이트 unsigned 정수 (이전의 u_char)

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