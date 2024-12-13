#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>

// Start capturing packets on the given interface
int start_capture(pcap_t *handle);

#endif // CAPTURE_H