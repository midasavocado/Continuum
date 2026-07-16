#ifndef CONTINUUM_TERMINAL_RELAY_CORE_H
#define CONTINUUM_TERMINAL_RELAY_CORE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum continuum_terminal_relay_frame_type {
    CONTINUUM_TERMINAL_RELAY_DATA = 1,
    CONTINUUM_TERMINAL_RELAY_RESIZE = 2,
    CONTINUUM_TERMINAL_RELAY_READY = 3,
    CONTINUUM_TERMINAL_RELAY_EOF = 4,
    CONTINUUM_TERMINAL_RELAY_ERROR = 5
};

/* Connects to socket_path and runs until either side reaches EOF. */
int continuum_terminal_relay_run(
    const char *socket_path,
    int terminal_input_fd,
    int terminal_output_fd,
    int install_signal_handler
);

#ifdef __cplusplus
}
#endif

#endif
