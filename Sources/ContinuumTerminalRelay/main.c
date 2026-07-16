#include <ContinuumTerminalRelayCore.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void print_usage(const char *program) {
    fprintf(stderr, "usage: %s --socket PATH\n", program);
}

int main(int argc, char **argv) {
    const char *socket_path = NULL;
    for (int index = 1; index < argc; index++) {
        if (strcmp(argv[index], "--socket") == 0 && index + 1 < argc) {
            socket_path = argv[++index];
        } else {
            print_usage(argv[0]);
            return 64;
        }
    }
    if (socket_path == NULL) {
        print_usage(argv[0]);
        return 64;
    }
    if (continuum_terminal_relay_run(socket_path, STDIN_FILENO, STDOUT_FILENO, 1) != 0) {
        fprintf(stderr, "ContinuumTerminalRelay: %s\n", strerror(errno));
        return 1;
    }
    return 0;
}
