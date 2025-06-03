#ifndef SCANNER_H
#define SCANNER_H

#include <stdint.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
#endif


void start_scan_cidr(struct in_addr base_ip, uint32_t host_count, int threads, int verbosity);

#endif
// scanner.h