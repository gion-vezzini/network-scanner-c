#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "scanner.h"
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>

#define MIN_HOST 1
#define MAX_HOST 254

typedef struct {
    struct in_addr base_ip;
    int start;
    int end;
    int verbosity;
} ScanParams;

unsigned short checksum(void* b, int len) {
    unsigned short* buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

void* scan_range(void* arg) {
    ScanParams* params = (ScanParams*) arg;

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return NULL;
    }


    for (int i = params->start; i <= params->end; i++) {
        // Setup destination address
        struct in_addr current_ip;
        current_ip.s_addr = htonl(ntohl(params->base_ip.s_addr) + i);

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &current_ip, ip_str, sizeof(ip_str));

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr = current_ip;

        // Build ICMP packet
        char sendbuf[64];
        struct icmphdr* icmp_hdr = (struct icmphdr*)sendbuf;
        memset(sendbuf, 0, sizeof(sendbuf));

        icmp_hdr->type = ICMP_ECHO;
        icmp_hdr->code = 0;
        icmp_hdr->un.echo.id = getpid() & 0xFFFF;
        icmp_hdr->un.echo.sequence = i;
        icmp_hdr->checksum = 0;
        icmp_hdr->checksum = checksum(icmp_hdr, sizeof(sendbuf));

        // Send ICMP packet
        if (sendto(sockfd, sendbuf, sizeof(sendbuf), 0,
                (struct sockaddr*)&addr, sizeof(addr)) <= 0) {
            if (params->verbosity >= 2)
                printf("[Thread %lu] Send failed: %s\n", pthread_self(), ip_str);
            continue;
        }

        // Wait for reply (timeout)
        fd_set readfds;
        struct timeval timeout = {.tv_sec = 1, .tv_usec = 0};
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);

        if (select(sockfd + 1, &readfds, NULL, NULL, &timeout) > 0) {
            char recvbuf[128];
            socklen_t addrlen = sizeof(addr);
            if (recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0,
                        (struct sockaddr*)&addr, &addrlen) > 0) {
                if (params->verbosity >= 1)
                    printf("[Thread %lu] Host alive: %s\n", pthread_self(), ip_str);
            }
        } else {
            if (params->verbosity >= 2)
                printf("[Thread %lu] Timeout: %s\n", pthread_self(), ip_str);
        }
    }
    close(sockfd);
    return NULL;
}

void start_scan(const char* network, int threads, int verbosity) {
    struct in_addr base_ip;
    if (inet_aton(network, &base_ip) == 0) {
        fprintf(stderr, "Invalid IP address: %s\n", network);
        return;
    }

    pthread_t thread_ids[threads];
    ScanParams params[threads];

    int total_hosts = MAX_HOST - MIN_HOST + 1;
    int hosts_per_thread = total_hosts / threads;
    int remainder = total_hosts % threads;

    int current_host = MIN_HOST;

    for (int i = 0; i < threads; i++) {
        int start = current_host;
        int end = start + hosts_per_thread - 1;
        if (i < remainder) end++;  // Distribute remainder

        params[i].base_ip = base_ip;
        params[i].start = start;
        params[i].end = end;
        params[i].verbosity = verbosity;

        pthread_create(&thread_ids[i], NULL, scan_range, &params[i]);

        current_host = end + 1;
    }

    for (int i = 0; i < threads; i++) {
        pthread_join(thread_ids[i], NULL);
    }
}
