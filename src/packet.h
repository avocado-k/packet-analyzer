#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>  // uint8_t, uint16_t 등을 위한 헤더
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// uint8_t: 1바이트 unsigned 정수 (이전의 u_char)
void parse_ip_header(const uint8_t *packet);
const char* get_protocol_name(uint8_t protocol);
void parse_tcp_header(const uint8_t *packet, int ip_header_length);
void parse_udp_header(const uint8_t *packet, int ip_header_length);
void print_port_info(uint16_t src_port, uint16_t dst_port);

#endif // PACKET_H