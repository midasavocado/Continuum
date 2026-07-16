#include "ContinuumTerminalRelayCore.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <termios.h>
#include <unistd.h>

#define RELAY_BUFFER_CAPACITY (256U * 1024U)
#define RELAY_DATA_CHUNK (16U * 1024U)
#define RELAY_HEADER_SIZE 5U

struct relay_buffer {
    uint8_t bytes[RELAY_BUFFER_CAPACITY];
    size_t start;
    size_t end;
};

static int relay_signal_write_fd = -1;

static size_t relay_buffer_size(const struct relay_buffer *buffer) {
    return buffer->end - buffer->start;
}

static void relay_buffer_compact(struct relay_buffer *buffer) {
    if (buffer->start == 0) return;
    if (buffer->start == buffer->end) {
        buffer->start = 0;
        buffer->end = 0;
        return;
    }
    memmove(buffer->bytes, buffer->bytes + buffer->start, relay_buffer_size(buffer));
    buffer->end -= buffer->start;
    buffer->start = 0;
}

static int relay_buffer_append(
    struct relay_buffer *buffer,
    const void *bytes,
    size_t length
) {
    if (length > RELAY_BUFFER_CAPACITY - relay_buffer_size(buffer)) return -1;
    if (length > RELAY_BUFFER_CAPACITY - buffer->end) relay_buffer_compact(buffer);
    memcpy(buffer->bytes + buffer->end, bytes, length);
    buffer->end += length;
    return 0;
}

static int relay_append_frame(
    struct relay_buffer *buffer,
    uint8_t type,
    const void *payload,
    uint32_t length
) {
    if ((size_t)length + RELAY_HEADER_SIZE >
        RELAY_BUFFER_CAPACITY - relay_buffer_size(buffer)) return -1;
    uint8_t header[RELAY_HEADER_SIZE];
    uint32_t network_length = htonl(length);
    header[0] = type;
    memcpy(header + 1, &network_length, sizeof(network_length));
    if (relay_buffer_append(buffer, header, sizeof(header)) != 0) return -1;
    if (length > 0 && relay_buffer_append(buffer, payload, length) != 0) return -1;
    return 0;
}

static void relay_winch_handler(int signal_number) {
    (void)signal_number;
    int saved_errno = errno;
    uint8_t byte = 1;
    if (relay_signal_write_fd >= 0) (void)write(relay_signal_write_fd, &byte, 1);
    errno = saved_errno;
}

static int relay_set_nonblocking(int fd, int *saved_flags) {
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) return -1;
    *saved_flags = flags;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int relay_connect(const char *path) {
    if (path == NULL || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    size_t length = strlen(path);
    if (length >= sizeof(address.sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(address.sun_path, path, length + 1);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int no_sigpipe = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe)) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    if (connect(fd, (const struct sockaddr *)&address, sizeof(address)) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
}

static int relay_append_resize(struct relay_buffer *socket_output, int terminal_fd) {
    struct winsize size;
    if (ioctl(terminal_fd, TIOCGWINSZ, &size) != 0) return -1;
    uint32_t payload[2] = { htonl(size.ws_row), htonl(size.ws_col) };
    return relay_append_frame(
        socket_output,
        CONTINUUM_TERMINAL_RELAY_RESIZE,
        payload,
        sizeof(payload)
    );
}

static int relay_write_buffer(int fd, struct relay_buffer *buffer) {
    ssize_t result = write(fd, buffer->bytes + buffer->start, relay_buffer_size(buffer));
    if (result > 0) {
        buffer->start += (size_t)result;
        relay_buffer_compact(buffer);
        return 0;
    }
    if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
    return -1;
}

static int relay_parse_socket_input(
    struct relay_buffer *socket_input,
    struct relay_buffer *terminal_output,
    int *received_eof
) {
    while (relay_buffer_size(socket_input) >= RELAY_HEADER_SIZE) {
        const uint8_t *header = socket_input->bytes + socket_input->start;
        uint32_t network_length;
        memcpy(&network_length, header + 1, sizeof(network_length));
        uint32_t length = ntohl(network_length);
        if (length > RELAY_BUFFER_CAPACITY - RELAY_HEADER_SIZE) return -1;
        if (relay_buffer_size(socket_input) < RELAY_HEADER_SIZE + length) return 0;
        uint8_t type = header[0];
        const uint8_t *payload = header + RELAY_HEADER_SIZE;
        if (type == CONTINUUM_TERMINAL_RELAY_DATA) {
            if (relay_buffer_append(terminal_output, payload, length) != 0) return 0;
        } else if (type == CONTINUUM_TERMINAL_RELAY_EOF) {
            *received_eof = 1;
        } else if (type == CONTINUUM_TERMINAL_RELAY_ERROR) {
            errno = EIO;
            return -1;
        }
        socket_input->start += RELAY_HEADER_SIZE + length;
        relay_buffer_compact(socket_input);
    }
    return 0;
}

int continuum_terminal_relay_run(
    const char *socket_path,
    int terminal_input_fd,
    int terminal_output_fd,
    int install_signal_handler
) {
    int result = -1;
    int saved_errno = 0;
    int socket_fd = -1;
    int signal_pipe[2] = { -1, -1 };
    int input_flags = -1, output_flags = -1, socket_flags = -1;
    struct termios saved_termios;
    int has_saved_termios = 0;
    struct sigaction saved_winch;
    int has_saved_winch = 0;
    struct relay_buffer *socket_input = calloc(1, sizeof(*socket_input));
    struct relay_buffer *socket_output = calloc(1, sizeof(*socket_output));
    struct relay_buffer *terminal_output = calloc(1, sizeof(*terminal_output));
    int terminal_eof = 0;
    int remote_eof = 0;
    int resize_pending = 0;

    if (socket_input == NULL || socket_output == NULL || terminal_output == NULL) {
        errno = ENOMEM;
        goto cleanup;
    }
    if (!isatty(terminal_input_fd) || !isatty(terminal_output_fd)) {
        errno = ENOTTY;
        goto cleanup;
    }
    if (tcgetattr(terminal_input_fd, &saved_termios) != 0) goto cleanup;
    has_saved_termios = 1;
    struct termios raw_termios = saved_termios;
    cfmakeraw(&raw_termios);
    raw_termios.c_lflag &= (tcflag_t)~ECHO;
    if (tcsetattr(terminal_input_fd, TCSANOW, &raw_termios) != 0) goto cleanup;

    socket_fd = relay_connect(socket_path);
    if (socket_fd < 0) goto cleanup;
    if (relay_set_nonblocking(terminal_input_fd, &input_flags) != 0 ||
        relay_set_nonblocking(terminal_output_fd, &output_flags) != 0 ||
        relay_set_nonblocking(socket_fd, &socket_flags) != 0) goto cleanup;

    if (pipe(signal_pipe) != 0) goto cleanup;
    int ignored;
    if (relay_set_nonblocking(signal_pipe[0], &ignored) != 0 ||
        relay_set_nonblocking(signal_pipe[1], &ignored) != 0) goto cleanup;

    if (install_signal_handler) {
        struct sigaction action;
        memset(&action, 0, sizeof(action));
        action.sa_handler = relay_winch_handler;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGWINCH, &action, &saved_winch) != 0) goto cleanup;
        has_saved_winch = 1;
        relay_signal_write_fd = signal_pipe[1];
    }

    if (relay_append_frame(socket_output, CONTINUUM_TERMINAL_RELAY_READY, NULL, 0) != 0 ||
        relay_append_resize(socket_output, terminal_input_fd) != 0) goto cleanup;

    while (1) {
        size_t socket_output_free = RELAY_BUFFER_CAPACITY - relay_buffer_size(socket_output);
        size_t socket_input_free = RELAY_BUFFER_CAPACITY - relay_buffer_size(socket_input);
        struct pollfd descriptors[4] = {
            {
                terminal_input_fd,
                (!terminal_eof && socket_output_free >= RELAY_HEADER_SIZE + RELAY_DATA_CHUNK)
                    ? POLLIN : 0,
                0
            },
            { terminal_output_fd, relay_buffer_size(terminal_output) ? POLLOUT : 0, 0 },
            {
                socket_fd,
                (socket_input_free > 0 ? POLLIN : 0) |
                    (relay_buffer_size(socket_output) ? POLLOUT : 0),
                0
            },
            { signal_pipe[0], POLLIN, 0 }
        };
        if (poll(descriptors, 4, -1) < 0) {
            if (errno == EINTR) continue;
            goto cleanup;
        }

        if (descriptors[3].revents & POLLIN) {
            uint8_t bytes[32];
            while (read(signal_pipe[0], bytes, sizeof(bytes)) > 0) {}
            resize_pending = 1;
        }
        if (descriptors[0].revents & (POLLIN | POLLHUP)) {
            uint8_t bytes[RELAY_DATA_CHUNK];
            ssize_t count = read(terminal_input_fd, bytes, sizeof(bytes));
            if (count > 0) {
                if (relay_append_frame(
                    socket_output,
                    CONTINUUM_TERMINAL_RELAY_DATA,
                    bytes,
                    (uint32_t)count
                ) != 0) goto cleanup;
            } else if (count == 0 || (count < 0 && errno == EIO)) {
                terminal_eof = 1;
                if (relay_append_frame(
                    socket_output,
                    CONTINUUM_TERMINAL_RELAY_EOF,
                    NULL,
                    0
                ) != 0) goto cleanup;
            } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                goto cleanup;
            }
        }
        if (descriptors[2].revents & POLLIN) {
            relay_buffer_compact(socket_input);
            ssize_t count = read(
                socket_fd,
                socket_input->bytes + socket_input->end,
                RELAY_BUFFER_CAPACITY - socket_input->end
            );
            if (count > 0) {
                socket_input->end += (size_t)count;
                if (relay_parse_socket_input(
                    socket_input,
                    terminal_output,
                    &remote_eof
                ) != 0) goto cleanup;
            } else if (count == 0) {
                remote_eof = 1;
            } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                goto cleanup;
            }
        }
        if (descriptors[2].revents & POLLHUP) remote_eof = 1;
        if (descriptors[1].revents & POLLOUT) {
            if (relay_write_buffer(terminal_output_fd, terminal_output) != 0) goto cleanup;
            if (relay_parse_socket_input(
                socket_input,
                terminal_output,
                &remote_eof
            ) != 0) goto cleanup;
        }
        if (descriptors[2].revents & POLLOUT) {
            if (relay_write_buffer(socket_fd, socket_output) != 0) goto cleanup;
        }
        if (descriptors[2].revents & (POLLERR | POLLNVAL)) goto cleanup;
        if (resize_pending &&
            RELAY_BUFFER_CAPACITY - relay_buffer_size(socket_output) >=
                RELAY_HEADER_SIZE + sizeof(uint32_t) * 2) {
            if (relay_append_resize(socket_output, terminal_input_fd) != 0) goto cleanup;
            resize_pending = 0;
        }

        if (remote_eof && relay_buffer_size(terminal_output) == 0) {
            result = 0;
            break;
        }
        if (terminal_eof && relay_buffer_size(socket_output) == 0) {
            result = 0;
            break;
        }
    }

cleanup:
    saved_errno = errno;
    if (result != 0 && socket_fd >= 0 && socket_output != NULL) {
        const char *description = strerror(saved_errno);
        socket_output->start = 0;
        socket_output->end = 0;
        if (relay_append_frame(
            socket_output,
            CONTINUUM_TERMINAL_RELAY_ERROR,
            description,
            (uint32_t)strlen(description)
        ) == 0) {
            (void)write(socket_fd, socket_output->bytes, socket_output->end);
        }
    }
    relay_signal_write_fd = -1;
    if (has_saved_winch) (void)sigaction(SIGWINCH, &saved_winch, NULL);
    if (signal_pipe[0] >= 0) close(signal_pipe[0]);
    if (signal_pipe[1] >= 0) close(signal_pipe[1]);
    if (socket_flags >= 0 && socket_fd >= 0) (void)fcntl(socket_fd, F_SETFL, socket_flags);
    if (output_flags >= 0) (void)fcntl(terminal_output_fd, F_SETFL, output_flags);
    if (input_flags >= 0) (void)fcntl(terminal_input_fd, F_SETFL, input_flags);
    if (socket_fd >= 0) close(socket_fd);
    if (has_saved_termios) (void)tcsetattr(terminal_input_fd, TCSANOW, &saved_termios);
    free(terminal_output);
    free(socket_output);
    free(socket_input);
    errno = saved_errno;
    return result;
}
