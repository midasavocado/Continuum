#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/mach.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

typedef struct target_state {
    uint8_t *arena;
    size_t length;
    char state;
    int probe_descriptor;
    int stable_descriptor;
    mach_port_t additive_port;
    char stable_path[PATH_MAX];
    int is_helper;
    pid_t helper_pid;
    FILE *helper_input;
    FILE *helper_output;
    uint64_t helper_address;
    size_t helper_length;
    char helper_state;
    char helper_digest[17];
    int helper_valid;
} target_state;

static uint64_t digest_bytes(const uint8_t *bytes, size_t length) {
    uint64_t value = UINT64_C(14695981039346656037);
    for (size_t index = 0; index < length; index += 1) {
        value ^= bytes[index];
        value *= UINT64_C(1099511628211);
    }
    return value;
}

static void write_state(target_state *target, char state) {
    const size_t multiplier = state == 'A' ? 31U : 73U;
    const size_t offset = state == 'A' ? 17U : 91U;
    for (size_t index = 0; index < target->length; index += 1) {
        target->arena[index] = (uint8_t)(index * multiplier + offset);
    }
    memcpy(target->arena, "CTMSTATE", 8);
    target->arena[8] = (uint8_t)state;
    uint64_t counter = state == 'A' ? UINT64_C(111) : UINT64_C(222);
    memcpy(target->arena + 16, &counter, sizeof(counter));
    target->state = state;
}

static void current_digest(const target_state *target, char output[17]) {
    snprintf(output, 17, "%016llx", digest_bytes(target->arena, target->length));
}

static int write_file_state(target_state *target, char state) {
    char bytes[32];
    int length = snprintf(bytes, sizeof(bytes), "continuum-file-%c\n", state);
    if (length <= 0
        || pwrite(target->stable_descriptor, bytes, (size_t)length, 0) != length
        || ftruncate(target->stable_descriptor, length) != 0
        || fsync(target->stable_descriptor) != 0) {
        return 0;
    }
    return 1;
}

static int validate_file_state(target_state *target, char state) {
    char expected[32];
    char actual[32] = {0};
    int length = snprintf(expected, sizeof(expected), "continuum-file-%c\n", state);
    if (length <= 0 || pread(target->stable_descriptor, actual, sizeof(actual), 0) != length) {
        return 0;
    }
    return memcmp(actual, expected, (size_t)length) == 0;
}

static int parse_command(const char *line, char command[32], char *state) {
    const char *command_key = strstr(line, "\"command\":\"");
    if (command_key == NULL) {
        return 0;
    }
    command_key += strlen("\"command\":\"");
    const char *command_end = strchr(command_key, '\"');
    if (command_end == NULL || command_end == command_key
        || (size_t)(command_end - command_key) >= 32) {
        return 0;
    }
    memcpy(command, command_key, (size_t)(command_end - command_key));
    command[command_end - command_key] = '\0';
    *state = '\0';
    const char *state_key = strstr(line, "\"state\":\"");
    if (state_key != NULL) {
        state_key += strlen("\"state\":\"");
        if (*state_key == 'A' || *state_key == 'B') {
            *state = *state_key;
        }
    }
    return 1;
}

static int parse_helper_reply(target_state *target, const char *line) {
    const char *pid_key = strstr(line, "\"processIdentifier\":");
    const char *address_key = strstr(line, "\"address\":");
    const char *length_key = strstr(line, "\"length\":");
    const char *state_key = strstr(line, "\"state\":\"");
    const char *digest_key = strstr(line, "\"digest\":\"");
    const char *valid_key = strstr(line, "\"valid\":");
    if (pid_key == NULL || state_key == NULL || digest_key == NULL) {
        return 0;
    }
    target->helper_pid = (pid_t)strtol(
        pid_key + strlen("\"processIdentifier\":"),
        NULL,
        10
    );
    if (address_key != NULL) {
        target->helper_address = strtoull(
            address_key + strlen("\"address\":"),
            NULL,
            10
        );
    }
    if (length_key != NULL) {
        target->helper_length = (size_t)strtoull(
            length_key + strlen("\"length\":"),
            NULL,
            10
        );
    }
    target->helper_state = state_key[strlen("\"state\":\"")];
    digest_key += strlen("\"digest\":\"");
    memcpy(target->helper_digest, digest_key, 16);
    target->helper_digest[16] = '\0';
    target->helper_valid = valid_key == NULL
        ? -1
        : (strncmp(valid_key + strlen("\"valid\":"), "true", 4) == 0 ? 1 : 0);
    return target->helper_pid > 0;
}

static void send_reply(
    target_state *target,
    const char *event,
    const char *command,
    int valid,
    const char *error
) {
    char digest[17];
    current_digest(target, digest);
    printf(
        "{\"protocolVersion\":1,\"event\":\"%s\","
        "\"command\":%s%s%s,\"processIdentifier\":%d,"
        "\"address\":%llu,\"length\":%zu,\"state\":\"%c\","
        "\"counter\":%d,\"digest\":\"%s\",\"valid\":%s",
        event,
        command == NULL ? "null" : "\"",
        command == NULL ? "" : command,
        command == NULL ? "" : "\"",
        getpid(),
        (unsigned long long)(uintptr_t)target->arena,
        target->length,
        (char)target->arena[8],
        target->arena[8] == 'A' ? 111 : 222,
        digest,
        valid < 0 ? "null" : (valid ? "true" : "false")
    );
    if (!target->is_helper && target->helper_pid > 0) {
        printf(
            ",\"helperProcessIdentifier\":%d,\"helperAddress\":%llu,"
            "\"helperLength\":%zu,\"helperState\":\"%c\","
            "\"helperDigest\":\"%s\",\"helperValid\":%s",
            target->helper_pid,
            (unsigned long long)target->helper_address,
            target->helper_length,
            target->helper_state,
            target->helper_digest,
            valid < 0 ? "null" : (valid ? "true" : "false")
        );
    }
    if (error == NULL) {
        printf(",\"error\":null}\n");
    } else {
        printf(",\"error\":\"%s\"}\n", error);
    }
    fflush(stdout);
}

static int helper_exchange(
    target_state *target,
    const char *command,
    char state
) {
    if (target->helper_input == NULL || target->helper_output == NULL) {
        return 0;
    }
    if (state == 'A' || state == 'B') {
        fprintf(
            target->helper_input,
            "{\"command\":\"%s\",\"state\":\"%c\"}\n",
            command,
            state
        );
    } else {
        fprintf(target->helper_input, "{\"command\":\"%s\"}\n", command);
    }
    fflush(target->helper_input);
    char line[4096];
    if (fgets(line, sizeof(line), target->helper_output) == NULL) {
        return 0;
    }
    return parse_helper_reply(target, line);
}

static int spawn_helper(target_state *target, const char *executable) {
    int input_pipe[2];
    int output_pipe[2];
    if (pipe(input_pipe) != 0 || pipe(output_pipe) != 0) {
        return 0;
    }
    posix_spawn_file_actions_t actions;
    if (posix_spawn_file_actions_init(&actions) != 0) {
        return 0;
    }
    posix_spawn_file_actions_adddup2(&actions, input_pipe[0], STDIN_FILENO);
    posix_spawn_file_actions_adddup2(&actions, output_pipe[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&actions, input_pipe[1]);
    posix_spawn_file_actions_addclose(&actions, output_pipe[0]);
    char *const arguments[] = {(char *)executable, "--continuum-helper", NULL};
    pid_t process_id = 0;
    int result = posix_spawn(
        &process_id,
        executable,
        &actions,
        NULL,
        arguments,
        environ
    );
    posix_spawn_file_actions_destroy(&actions);
    close(input_pipe[0]);
    close(output_pipe[1]);
    if (result != 0) {
        close(input_pipe[1]);
        close(output_pipe[0]);
        return 0;
    }
    target->helper_input = fdopen(input_pipe[1], "w");
    target->helper_output = fdopen(output_pipe[0], "r");
    target->helper_pid = process_id;
    char line[4096];
    if (target->helper_input == NULL || target->helper_output == NULL
        || fgets(line, sizeof(line), target->helper_output) == NULL
        || !parse_helper_reply(target, line)) {
        return 0;
    }
    return 1;
}

static int run_server(target_state *target) {
    send_reply(target, "ready", NULL, -1, NULL);
    char line[4096];
    while (fgets(line, sizeof(line), stdin) != NULL) {
        char command[32];
        char requested_state = '\0';
        if (!parse_command(line, command, &requested_state)) {
            send_reply(target, "error", NULL, 0, "invalid command");
            continue;
        }
        if (strcmp(command, "mutate") == 0) {
            if ((requested_state != 'A' && requested_state != 'B')
                || (!target->is_helper
                    && !helper_exchange(target, command, requested_state))) {
                send_reply(target, "error", command, 0, "mutation failed");
                continue;
            }
            write_state(target, requested_state);
            send_reply(target, "mutated", command, -1, NULL);
        } else if (strcmp(command, "validate-root") == 0) {
            int valid = target->arena[8] == (uint8_t)requested_state;
            send_reply(
                target,
                "validated",
                command,
                valid,
                valid ? NULL : "root state mismatch"
            );
        } else if (strcmp(command, "validate") == 0) {
            int helper_valid = target->is_helper
                || helper_exchange(target, command, requested_state);
            int valid = target->arena[8] == (uint8_t)requested_state
                && helper_valid
                && (target->is_helper || target->helper_state == requested_state);
            send_reply(target, "validated", command, valid, valid ? NULL : "state mismatch");
        } else if (strcmp(command, "mutate-file") == 0) {
            int helper_valid = target->is_helper
                || helper_exchange(target, command, requested_state);
            int valid = (requested_state == 'A' || requested_state == 'B')
                && helper_valid
                && write_file_state(target, requested_state);
            send_reply(
                target,
                "file-mutated",
                command,
                valid,
                valid ? NULL : "file mutation failed"
            );
        } else if (strcmp(command, "add-mach-port") == 0) {
            int helper_valid = target->is_helper
                || (helper_exchange(target, command, '\0')
                    && target->helper_valid == 1);
            kern_return_t result = mach_port_allocate(
                mach_task_self(),
                MACH_PORT_RIGHT_RECEIVE,
                &target->additive_port
            );
            int valid = helper_valid && result == KERN_SUCCESS;
            send_reply(
                target,
                "mach-port-added",
                command,
                valid,
                valid ? NULL : "Mach port allocation failed"
            );
        } else if (strcmp(command, "validate-file") == 0) {
            int helper_valid = target->is_helper
                ? validate_file_state(target, requested_state)
                : (helper_exchange(target, command, requested_state)
                    && target->helper_valid == 1);
            int valid = validate_file_state(target, requested_state)
                && helper_valid;
            send_reply(
                target,
                "file-validated",
                command,
                valid,
                valid ? NULL : "file state mismatch"
            );
        } else if (strcmp(command, "open-resource") == 0) {
            target->probe_descriptor = open("/dev/null", O_RDONLY | O_CLOEXEC);
            send_reply(
                target,
                target->probe_descriptor >= 0 ? "resource-opened" : "error",
                command,
                target->probe_descriptor >= 0,
                target->probe_descriptor >= 0 ? NULL : "open failed"
            );
        } else if (strcmp(command, "close-resource") == 0) {
            int closed = target->probe_descriptor >= 0
                && close(target->probe_descriptor) == 0;
            target->probe_descriptor = -1;
            send_reply(
                target,
                closed ? "resource-closed" : "error",
                command,
                closed,
                closed ? NULL : "close failed"
            );
        } else if (strcmp(command, "exit") == 0) {
            if (!target->is_helper) {
                (void)helper_exchange(target, command, '\0');
                int helper_status = 0;
                (void)waitpid(target->helper_pid, &helper_status, 0);
            }
            send_reply(target, "exiting", command, -1, NULL);
            return 1;
        } else {
            send_reply(target, "error", command, 0, "unknown command");
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    target_state target;
    memset(&target, 0, sizeof(target));
    target.probe_descriptor = -1;
    target.stable_descriptor = -1;
    target.is_helper = argc > 1 && strcmp(argv[1], "--continuum-helper") == 0;
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        return EXIT_FAILURE;
    }
    target.length = (size_t)page_size;
    target.arena = mmap(
        NULL,
        target.length,
        PROT_READ | PROT_WRITE,
        MAP_ANON | MAP_PRIVATE,
        -1,
        0
    );
    if (target.arena == MAP_FAILED) {
        return EXIT_FAILURE;
    }
    write_state(&target, 'A');
    snprintf(
        target.stable_path,
        sizeof(target.stable_path),
        "/private/tmp/continuum-external-target-%d-XXXXXX",
        getpid()
    );
    target.stable_descriptor = mkstemp(target.stable_path);
    if (target.stable_descriptor < 0
        || !write_file_state(&target, 'B')) {
        if (target.stable_descriptor >= 0) {
            close(target.stable_descriptor);
        }
        unlink(target.stable_path);
        munmap(target.arena, target.length);
        return EXIT_FAILURE;
    }
    if (!target.is_helper && !spawn_helper(&target, argv[0])) {
        return EXIT_FAILURE;
    }
    int succeeded = run_server(&target);
    close(target.stable_descriptor);
    unlink(target.stable_path);
    munmap(target.arena, target.length);
    return succeeded ? EXIT_SUCCESS : EXIT_FAILURE;
}
