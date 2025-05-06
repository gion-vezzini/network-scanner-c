#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <math.h>
#include "scanner.h"

// Parse CIDR like "192.168.0.0/24" -> base IP and range size
int parse_cidr(const char* cidr, struct in_addr* base_ip, uint32_t* host_count) {
    char cidr_copy[32];
    strncpy(cidr_copy, cidr, sizeof(cidr_copy) - 1);
    cidr_copy[sizeof(cidr_copy) - 1] = '\0';

    char* slash = strchr(cidr_copy, '/');
    if (!slash) {
        fprintf(stderr, "CIDR format required (e.g., 192.168.0.0/24)\n");
        printf("Use \'--help\' flag to see further explanation\n");
        return 0;
    }

    *slash = '\0';
    int prefix_len = atoi(slash + 1);
    if (prefix_len < 0 || prefix_len > 32) {
        fprintf(stderr, "Invalid prefix length: /%d\n", prefix_len);
        printf("Use \'--help\' flag to see further explanation\n");
        return 0;
    }

    if (inet_aton(cidr_copy, base_ip) == 0) {
        fprintf(stderr, "Invalid IP address: %s\n", cidr_copy);
        printf("Use \'--help\' flag to see further explanation\n");
        return 0;
    }

    uint32_t num_hosts = (prefix_len == 32) ? 1 : (1U << (32 - prefix_len)) - 2;
    *host_count = num_hosts;

    return 1;
}

int main(int argc, char *argv[]) {
    if (argc < 2 || strcmp(argv[1], "--help") == 0) {
        printf("Usage: %s <CIDR> [-v[0|1|2]]\n", argv[0]);
        printf("Example: %s 192.168.1.0/24 -v2\n", argv[0]);
        printf("\nOptions:\n");
        printf("  <CIDR>       The network range to scan (e.g., 10.0.0.0/16)\n");
        printf("  -v[0|1|2]    Optional verbosity level:\n");
        printf("                0 = Show alive hosts (default)\n");
        printf("                1 = Show alive hosts and number of threads and threads ID\n");
        printf("                2 = Show all hosts and number of threads and threads ID\n");
        return 0;
    }

    const char* cidr = argv[1];
    int verbosity = 0;

    // Parse optional verbosity flag
    if (argc >= 3) {
        if (strncmp(argv[2], "-v", 2) == 0) {
            if (argv[2][2] != '\0') {
                verbosity = atoi(&argv[2][2]);
            } else {
                verbosity = 1;
            }
            if (verbosity < 0 || verbosity > 2) {
                fprintf(stderr, "Verbosity must be 0, 1, or 2\n");
                return 1;
            }
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
    int threads;
    if (host_count <= 254) {
        threads = host_count;
    } else {
        threads = host_count / 8;
        if (threads < 256) threads = 256;
        if (threads > 1024) threads = 1024;
        if ((uint32_t)threads > host_count) threads = host_count;
    }

    printf("Scanning network: %s\n", cidr);
    printf("Total hosts to scan: %u\n", host_count);
    if (verbosity > 0) {
        printf("Using %d threads\n", threads);
        printf("Verbosity: %d\n\n", verbosity);
    }

    start_scan_cidr(base_ip, host_count, threads, verbosity);

    return 0;
}