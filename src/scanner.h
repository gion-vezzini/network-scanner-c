#ifndef SCANNER_H
#define SCANNER_H

#include <arpa/inet.h>
#include <stdint.h>

void start_scan_cidr(struct in_addr base_ip, uint32_t host_count, int threads, int verbosity);

#endif
// scanner.h