#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdbool.h>

#include "scanner.h"

// Check if IP address is aligned to the subnet (e.g., .0 for /24)
bool is_ip_aligned(struct in_addr ip, int prefix_len) {
    unsigned char bytes[4];
    memcpy(bytes, &ip.s_addr, 4);

    // Convert to host byte order
    uint32_t ip_host = ntohl(ip.s_addr);
    bytes[0] = (ip_host >> 24) & 0xFF;
    bytes[1] = (ip_host >> 16) & 0xFF;
    bytes[2] = (ip_host >> 8) & 0xFF;
    bytes[3] = ip_host & 0xFF;

    if (prefix_len <= 8) {
        return (bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0);
    }
    if (prefix_len <= 16) {
        return (bytes[2] == 0 && bytes[3] == 0);
    }
    if (prefix_len <= 24) {
        return (bytes[3] == 0);
    }
    if (prefix_len < 32) {
        int host_bits = 32 - prefix_len;
        int mask = ~((1 << host_bits) - 1) & 0xFF;
        return (bytes[3] & ~mask) == 0;
    }

    return true;
}

bool parse_cidr(const char* pCidr, struct in_addr* pBase_ip, uint32_t* pHost_count) {
    char cidr_copy[32];
    strncpy(cidr_copy, pCidr, sizeof(cidr_copy) - 1);
    cidr_copy[sizeof(cidr_copy) - 1] = '\0';

    char* pSlash = strchr(cidr_copy, '/');
    if (!pSlash || *(pSlash + 1) == '\0') {
        fprintf(stderr, "CIDR format required (e.g., 192.168.0.0/24)\n");
        printf("Use '--help' flag to see further explanation\n");
        return false;
    }

    *pSlash = '\0';
    const char* pPrefix_str = pSlash + 1;
    for (int i = 0; pPrefix_str[i]; ++i) {
        if (pPrefix_str[i] < '0' || pPrefix_str[i] > '9') {
            fprintf(stderr, "Invalid characters in CIDR prefix: /%s\n", pPrefix_str);
            return false;
        }
    }

    int prefix_len = atoi(pPrefix_str);
    if (prefix_len < 0 || prefix_len > 32) {
        fprintf(stderr, "Invalid prefix length: /%d. Must be between 0 and 32.\n", prefix_len);
        return false;
    }

    if (inet_aton(cidr_copy, pBase_ip) == 0) {
        fprintf(stderr, "Invalid IP address: %s\n", cidr_copy);
        return false;
    }

    if (!is_ip_aligned(*pBase_ip, prefix_len)) {
        fprintf(stderr, "IP %s is not aligned with /%d subnet. Use correct base (e.g., .0 for /24).\n", cidr_copy, prefix_len);
        return false;
    }

    uint32_t num_hosts = (prefix_len == 32) ? 1 : (1U << (32 - prefix_len)) - 2;
    if (num_hosts == 0) {
        fprintf(stderr, "CIDR range results in zero usable hosts.\n");
        return false;
    }

    *pHost_count = num_hosts;
    return true;
}

void print_banner(char* pArg0) {
    printf("Usage: %s <CIDR> [OPTIONS]\n", pArg0);
    printf("Example: %s 192.168.1.0/24 -v\n", pArg0);
    printf("\nOptions:\n");
    printf("  <CIDR>            The network range to scan (e.g., 10.0.0.0/16)\n");
    printf("  -q, --quiet       Suppress all non-essential output\n");
    printf("  -v, --verbose     Enable verbose output for detailed info\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2 || strcmp(argv[1], "--help") == 0) {
        print_banner(argv[0]);
        return 0;
    }

    const char* cidr = argv[1];
    int verbosity = 1;

    // Parse optional verbosity flag
    if (argc > 2) {
        if (strcmp(argv[2], "--quiet") == 0 || strcmp(argv[2], "-q") == 0) {
            verbosity = 0;
        } else if (strcmp(argv[2], "--verbose") == 0 || strcmp(argv[2], "-v") == 0) {
            verbosity = 2;
        } else {
            printf("Unknown verbosity level: %s\n", argv[2]);
            return 1;
        }
    }

    struct in_addr base_ip;
    uint32_t host_count = 0;

    if (!parse_cidr(cidr, &base_ip, &host_count)) {
        return 1;
    }

    if (host_count == 0) {
        fprintf(stderr, "Host range is empty.\n");
        return 1;
    }

    // Dynamically determine thread count based on host count directly
    uint32_t threads;
    if (host_count <= 254) {
        threads = host_count;
    } else {
        threads = host_count / 8;
        if (threads < 256) threads = 256;
        if (threads > 1024) threads = 1024;
        if (threads > host_count) threads = host_count;
    }

    if (verbosity > 0) {
        printf("Scanning network: %s\n", cidr);
        printf("Total hosts to scan: %u\n\n", host_count);
        printf("Using %d threads\n\n", threads);
    }

    start_scan_cidr(base_ip, host_count, threads, verbosity);

    return 0;
}