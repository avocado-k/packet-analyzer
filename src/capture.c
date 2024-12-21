#include <stdio.h>
#include <pcap.h>
#include "capture.h"
#include "packet.h"

static packet_rate_t rate_monitor; 

static void packet_handler(uint8_t *user, const struct pcap_pkthdr *header, const uint8_t *packet) {
    static int count = 1;
    
    // 패킷 속도 업데이트 및 출력
    update_rate(&rate_monitor, header->len);
    print_rate(&rate_monitor);
    
    printf("\nPacket #%d captured!\n", count++);
    printf("Packet length: %u\n", header->len);
    
    parse_ip_header(packet);
    
    fflush(stdout);
}


int start_capture(pcap_t *handle) {
    int ret = pcap_loop(handle, 0, (pcap_handler)packet_handler, NULL);
    if (ret < 0) {
        fprintf(stderr, "Error in packet capture loop: %s\n", pcap_geterr(handle));
        return -1;
    }
    return 0;
}