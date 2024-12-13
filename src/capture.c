#include <stdio.h>
#include <pcap.h>
#include "capture.h"
#include "packet.h"

// Callback function for packet processing
static void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    static int count = 1; // 패킷 카운터 추가
    printf("Packet #%d captured!\n", count++);
    printf("Packet length: %d\n", header->len);
    printf("Capture length: %d\n", header->caplen);
    printf("Timestamp: %ld.%06ld\n\n", header->ts.tv_sec, header->ts.tv_usec);
    fflush(stdout); // 즉시 출력하도록 버퍼 플러시
}

int start_capture(pcap_t *handle)
{
    printf("Capture loop starting...\n"); // 디버그 메시지 추가
    fflush(stdout);

    // 무한 루프 대신 10개의 패킷만 캡처하도록 수정
    int ret = pcap_loop(handle, 10, packet_handler, NULL);

    if (ret < 0)
    {
        fprintf(stderr, "Error in packet capture loop: %s\n", pcap_geterr(handle));
        return -1;
    }
    else if (ret == 0)
    {
        printf("Capture completed successfully\n");
    }

    return 0;
}