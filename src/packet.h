#ifndef PACKET_H
#define PACKET_H

#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Parse and print IP header information
void parse_ip_header(const u_char *packet);

// Convert protocol number to string
const char* get_protocol_name(u_char protocol);

#endif // PACKET_H