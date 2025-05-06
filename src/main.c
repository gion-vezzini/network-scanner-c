#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "scanner.h"

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s <network> <threads> <verbosity>\n", argv[0]);
        printf("Example: %s 192.168.1.0 10 1\n", argv[0]);
        return 1;
    }

    const char* network = argv[1];
    int threads = atoi(argv[2]);
    int verbosity = atoi(argv[3]);

    if (threads <= 0 || verbosity < 0 || verbosity > 2) {
        printf("Invalid arguments. Threads must be > 0, Verbosity must be between 0 and 2\n");
        return 1;
    }

    printf("Starting scan for network: %s\n", network);
    printf("Number of threads: %d\n", threads);
    printf("Verbosity level: %d\n", verbosity);

    // Start the scanner with parsed parameters
    start_scan(network, threads, verbosity);

    return 0;
}
