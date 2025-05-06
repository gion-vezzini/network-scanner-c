#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include "scanner.h"
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>

#define MAX_PIDS 65536
pid_t ping_pids[MAX_PIDS];
int ping_pid_count = 0;
pthread_mutex_t pid_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    struct in_addr base_ip;
    uint32_t start_offset;
    uint32_t end_offset;
    int verbosity;
} ScanParams;

void register_pid(pid_t pid) {
    pthread_mutex_lock(&pid_mutex);
    if (ping_pid_count < MAX_PIDS) {
        ping_pids[ping_pid_count++] = pid;
    }
    pthread_mutex_unlock(&pid_mutex);
}

void kill_all_pings() {
    pthread_mutex_lock(&pid_mutex);
    for (int i = 0; i < ping_pid_count; i++) {
        kill(ping_pids[i], SIGKILL);
    }
    pthread_mutex_unlock(&pid_mutex);
}

void* scan_range(void* arg) {
    ScanParams* params = (ScanParams*) arg;

    for (uint32_t i = params->start_offset; i <= params->end_offset; i++) {
        struct in_addr current_ip;
        current_ip.s_addr = htonl(ntohl(params->base_ip.s_addr) + i);

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &current_ip, ip_str, sizeof(ip_str));

        pid_t pid = fork();
        if (pid == 0) {
            // In child: silence output
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull != -1) {
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);
                close(devnull);
            }

            execlp("ping", "ping", "-c", "1", "-W", "1", ip_str, NULL);
            exit(127);  // Only if execlp fails
        } else if (pid > 0) {
            register_pid(pid);
            int status;
            waitpid(pid, &status, 0);

            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                if (params->verbosity == 0) printf("Host alive: %s\n", ip_str);
                else if (params->verbosity >= 1) printf("[Thread %p] Host alive: %s\n", (void*)pthread_self(), ip_str);
            } else {
                if (params->verbosity >= 2)
                    printf("[Thread %p] No response: %s\n", (void*)pthread_self(), ip_str);
            }
        }
    }

    return NULL;
}

void start_scan_cidr(struct in_addr base_ip, uint32_t host_count, int threads, int verbosity) {
    pthread_t thread_ids[threads];
    ScanParams params[threads];

    uint32_t hosts_per_thread = host_count / threads;
    uint32_t remainder = host_count % threads;

    uint32_t current_offset = 1;  // Skip .0 (network) by default
    for (int i = 0; i < threads; i++) {
        uint32_t start = current_offset;
        uint32_t end = start + hosts_per_thread - 1;
        if (i < remainder) end++;  // Spread out remainder

        params[i].base_ip = base_ip;
        params[i].start_offset = start;
        params[i].end_offset = end;
        params[i].verbosity = verbosity;

        pthread_create(&thread_ids[i], NULL, scan_range, &params[i]);
        current_offset = end + 1;
    }

    for (int i = 0; i < threads; i++) {
        pthread_join(thread_ids[i], NULL);
    }
}