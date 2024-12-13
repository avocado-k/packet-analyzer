#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "capture.h"
#include "packet.h"

#define SNAP_LEN 1518 // Maximum bytes per packet to capture
#define PROMISC 1     // Promiscuous mode flag
#define TO_MS 1000    // Read timeout in milliseconds

int main(int argc, char *argv[])
{
    char *dev = NULL; // Capture device name
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle; // Packet capture handle
    pcap_if_t *alldevs;
    struct bpf_program fp; // Compiled filter program
    char filter_exp[] = "icmp or tcp or udp";
    bpf_u_int32 net = 0; // The IP of our sniffing device

    // Find all available devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    // Print all available devices
    printf("Available network interfaces:\n");
    pcap_if_t *d;
    for (d = alldevs; d != NULL; d = d->next)
    {
        printf("- %s", d->name);
        if (d->description)
            printf(" (%s)", d->description);
        printf("\n");
    }

    // Use the first device if none specified
    dev = alldevs->name;
    printf("\nSelected interface: %s\n", dev);

    // Open capture device
    handle = pcap_open_live(dev, SNAP_LEN, PROMISC, TO_MS, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        pcap_freealldevs(alldevs);
        return EXIT_FAILURE;
    }

    // Compile and set the filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        pcap_freealldevs(alldevs);
        return EXIT_FAILURE;
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        pcap_freealldevs(alldevs);
        return EXIT_FAILURE;
    }

    printf("\nStarting packet capture...\n");
    printf("Filter: %s\n", filter_exp);
    printf("Waiting for ICMP packets...\n\n");

    // Start packet processing loop
    if (start_capture(handle) < 0)
    {
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return EXIT_FAILURE;
    }

    // Cleanup
    pcap_freecode(&fp);
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return EXIT_SUCCESS;
}