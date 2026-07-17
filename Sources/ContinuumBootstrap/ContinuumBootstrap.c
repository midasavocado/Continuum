#include "ContinuumBootstrap.h"

#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach/vm_statistics.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <libproc.h>
#include <malloc/malloc.h>
#include <objc/message.h>
#include <objc/runtime.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/event.h>
#include <sys/proc.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

static volatile sig_atomic_t continuum_safepoint_release = 0;
static volatile sig_atomic_t continuum_safepoint_requested = 0;
static volatile sig_atomic_t continuum_preservation_active = 0;
static volatile sig_atomic_t continuum_rehydrate_stop_requested = 0;
static volatile sig_atomic_t continuum_rehydrate_idle_boundaries = 0;
static CFRunLoopObserverRef continuum_safepoint_observer = NULL;
static volatile int continuum_safepoint_claimed = 0;
static malloc_zone_t *continuum_app_state_zone = NULL;
static uintptr_t continuum_main_text_start = 0;
static uintptr_t continuum_main_text_end = 0;
static char continuum_main_image_path[PATH_MAX];
static volatile int continuum_allocator_interposition_active = 0;
static volatile int continuum_objc_interposition_active = 0;

extern char **environ;

enum {
    CONTINUUM_BROKER_MAGIC = 0x4342524b,
    CONTINUUM_BROKER_VERSION = 1,
    CONTINUUM_BROKER_SETUP = 1,
    CONTINUUM_BROKER_SPAWN_CHILD = 2,
    CONTINUUM_BROKER_RELEASE = 3,
    CONTINUUM_BROKER_ABORT = 4,
    CONTINUUM_BROKER_READY = 5,
    CONTINUUM_BROKER_CHILD_READY = 6,
    CONTINUUM_BROKER_RELEASED = 7,
    CONTINUUM_BROKER_FAILED = 8,
    CONTINUUM_BROKER_CHILD_TO_BOOTSTRAP = 9,
    CONTINUUM_BROKER_CHILD_BOOTSTRAP_RELEASED = 10,
    CONTINUUM_BROKER_ROOT_TO_BOOTSTRAP = 11,
    CONTINUUM_BROKER_ROOT_BOOTSTRAP_RELEASED = 12,
    CONTINUUM_BROKER_CHILD_TO_ENTRY = 13,
    CONTINUUM_BROKER_CHILD_ENTRY_REACHED = 14,
    CONTINUUM_BROKER_CHILD_DETACH = 15,
    CONTINUUM_BROKER_CHILD_DETACHED = 16,
    CONTINUUM_BROKER_MAX_REMAPS = 64,
    CONTINUUM_BROKER_MAX_ARGUMENTS = 64,
    CONTINUUM_BROKER_MAX_ENVIRONMENT = 256,
    CONTINUUM_BROKER_MAX_STRING_BYTES = 65536,
};

static int continuum_broker_wait_for_child_stop(
    pid_t process_id,
    int expected_signal
) {
    uint64_t deadline = clock_gettime_nsec_np(CLOCK_MONOTONIC)
        + UINT64_C(5000000000);
    for (;;) {
        int status = 0;
        pid_t waited = waitpid(process_id, &status, WUNTRACED | WNOHANG);
        if (waited == process_id) {
            return WIFSTOPPED(status) && WSTOPSIG(status) == expected_signal;
        }
        if (waited < 0 && errno != EINTR) return 0;
        if (clock_gettime_nsec_np(CLOCK_MONOTONIC) >= deadline) return 0;
        usleep(1000);
    }
}

static int continuum_broker_wait_for_stopped_state(pid_t process_id) {
    uint64_t deadline = clock_gettime_nsec_np(CLOCK_MONOTONIC)
        + UINT64_C(5000000000);
    for (;;) {
        struct proc_bsdinfo information;
        memset(&information, 0, sizeof(information));
        int copied = proc_pidinfo(
            process_id,
            PROC_PIDTBSDINFO,
            0,
            &information,
            (int)sizeof(information)
        );
        if (copied == (int)sizeof(information)
            && information.pbi_status == SSTOP) {
            return 1;
        }
        if (copied <= 0
            || clock_gettime_nsec_np(CLOCK_MONOTONIC) >= deadline) {
            return 0;
        }
        usleep(1000);
    }
}

typedef struct continuum_broker_header {
    uint32_t magic;
    uint16_t version;
    uint16_t type;
    uint32_t payload_length;
} continuum_broker_header;

typedef struct continuum_broker_setup {
    uint32_t create_session;
    uint32_t process_group_policy;
    int32_t process_group_id;
    int32_t captured_process_id;
    int32_t captured_process_group_id;
    int32_t foreground_process_group_id;
    int32_t controlling_terminal_descriptor;
    uint32_t remap_count;
} continuum_broker_setup;

typedef struct continuum_broker_child {
    uint32_t argument_count;
    uint32_t environment_count;
    uint32_t executable_length;
    uint32_t directory_length;
    uint32_t bootstrap_length;
    uint32_t string_bytes;
    uint32_t remap_count;
    uint32_t process_group_policy;
    int32_t process_group_id;
    int32_t captured_process_id;
    int32_t captured_process_group_id;
    uint8_t disable_aslr;
    uint8_t reserved[3];
} continuum_broker_child;

typedef struct continuum_broker_reply {
    int32_t process_id;
    int32_t parent_process_id;
    int32_t session_id;
    int32_t process_group_id;
    int32_t controlling_terminal_process_group;
    int32_t error_code;
} continuum_broker_reply;

static int continuum_broker_read_all(int descriptor, void *bytes, size_t length) {
    uint8_t *cursor = bytes;
    while (length > 0) {
        ssize_t result = read(descriptor, cursor, length);
        if (result > 0) {
            cursor += result;
            length -= (size_t)result;
        } else if (result < 0 && errno == EINTR) {
            continue;
        } else {
            return 0;
        }
    }
    return 1;
}

static int continuum_broker_write_all(int descriptor, const void *bytes, size_t length) {
    const uint8_t *cursor = bytes;
    while (length > 0) {
        ssize_t result = send(descriptor, cursor, length, MSG_NOSIGNAL);
        if (result > 0) {
            cursor += result;
            length -= (size_t)result;
        } else if (result < 0 && errno == EINTR) {
            continue;
        } else {
            return 0;
        }
    }
    return 1;
}

static int continuum_broker_send_reply(
    int descriptor,
    uint16_t type,
    const continuum_broker_reply *reply
) {
    continuum_broker_header header = {
        .magic = CONTINUUM_BROKER_MAGIC,
        .version = CONTINUUM_BROKER_VERSION,
        .type = type,
        .payload_length = sizeof(*reply),
    };
    return continuum_broker_write_all(descriptor, &header, sizeof(header))
        && continuum_broker_write_all(descriptor, reply, sizeof(*reply));
}

static int continuum_broker_receive_fds(
    int descriptor,
    int *descriptors,
    size_t count
) {
    if (count == 0) {
        return 1;
    }
    char marker = 0;
    char control[CMSG_SPACE(sizeof(int) * CONTINUUM_BROKER_MAX_REMAPS)];
    struct iovec iov = {.iov_base = &marker, .iov_len = 1};
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = (socklen_t)CMSG_SPACE(sizeof(int) * count);
    ssize_t received;
    do {
        received = recvmsg(descriptor, &message, 0);
    } while (received < 0 && errno == EINTR);
    struct cmsghdr *entry = CMSG_FIRSTHDR(&message);
    if (received != 1 || entry == NULL || entry->cmsg_level != SOL_SOCKET
        || entry->cmsg_type != SCM_RIGHTS
        || entry->cmsg_len != CMSG_LEN(sizeof(int) * count)) {
        return 0;
    }
    memcpy(descriptors, CMSG_DATA(entry), sizeof(int) * count);
    return 1;
}

static int continuum_broker_send_fds(
    int descriptor,
    const int *descriptors,
    size_t count
) {
    if (count == 0) {
        return 1;
    }
    char marker = 1;
    char control[CMSG_SPACE(sizeof(int) * CONTINUUM_BROKER_MAX_REMAPS)];
    struct iovec iov = {.iov_base = &marker, .iov_len = 1};
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = (socklen_t)CMSG_SPACE(sizeof(int) * count);
    struct cmsghdr *entry = CMSG_FIRSTHDR(&message);
    entry->cmsg_level = SOL_SOCKET;
    entry->cmsg_type = SCM_RIGHTS;
    entry->cmsg_len = (socklen_t)CMSG_LEN(sizeof(int) * count);
    memcpy(CMSG_DATA(entry), descriptors, sizeof(int) * count);
    ssize_t sent;
    do {
        sent = sendmsg(descriptor, &message, 0);
    } while (sent < 0 && errno == EINTR);
    return sent == 1;
}

static int continuum_broker_restore_environment(void) {
    const char *original = getenv("CONTINUUM_BROKER_ORIGINAL_DYLD");
    const char *present = getenv("CONTINUUM_BROKER_ORIGINAL_DYLD_PRESENT");
    char *copy = original == NULL ? NULL : strdup(original);
    int had_original = present != NULL && strcmp(present, "1") == 0;
    unsetenv("CONTINUUM_BROKER_FD");
    unsetenv("CONTINUUM_BROKER_ORIGINAL_DYLD");
    unsetenv("CONTINUUM_BROKER_ORIGINAL_DYLD_PRESENT");
    unsetenv("CONTINUUM_BROKER_IS_CHILD");
    if (had_original) {
        int result = copy == NULL ? -1 : setenv("DYLD_INSERT_LIBRARIES", copy, 1);
        free(copy);
        return result == 0;
    }
    free(copy);
    return unsetenv("DYLD_INSERT_LIBRARIES") == 0;
}

static int continuum_broker_apply_setup(
    int channel,
    const continuum_broker_setup *setup,
    const int32_t *targets
) {
    int sources[CONTINUUM_BROKER_MAX_REMAPS];
    if (setup->remap_count > CONTINUUM_BROKER_MAX_REMAPS
        || !continuum_broker_receive_fds(channel, sources, setup->remap_count)) {
        return EINVAL;
    }
    int highest = channel;
    for (size_t index = 0; index < setup->remap_count; index += 1) {
        if (targets[index] > highest) highest = targets[index];
    }
    for (size_t index = 0; index < setup->remap_count; index += 1) {
        int safe = fcntl(sources[index], F_DUPFD_CLOEXEC, highest + 1);
        if (safe < 0) {
            for (size_t prior = 0; prior < index; prior += 1) close(sources[prior]);
            for (size_t rest = index; rest < setup->remap_count; rest += 1) close(sources[rest]);
            return errno;
        }
        close(sources[index]);
        sources[index] = safe;
        highest = safe;
    }
    int error = 0;
    if (setup->create_session && setsid() < 0) {
        error = errno;
    } else if (!setup->create_session && setup->process_group_policy == 1
        && setpgid(0, 0) != 0) {
        error = errno;
    } else if (!setup->create_session && setup->process_group_policy == 2
        && setpgid(0, setup->process_group_id) != 0) {
        error = errno;
    }
    int controlling_source = -1;
    for (size_t index = 0; error == 0 && index < setup->remap_count; index += 1) {
        if (targets[index] == setup->controlling_terminal_descriptor) {
            controlling_source = sources[index];
        }
    }
    if (error == 0 && setup->controlling_terminal_descriptor >= 0) {
        if (controlling_source < 0 || ioctl(controlling_source, TIOCSCTTY, 0) != 0
            || tcsetpgrp(controlling_source, getpgrp()) != 0) {
            error = errno == 0 ? ENOTTY : errno;
        }
    }
    for (size_t index = 0; error == 0 && index < setup->remap_count; index += 1) {
        if (dup2(sources[index], targets[index]) < 0
            || fcntl(targets[index], F_SETFD, 0) != 0) {
            error = errno;
        }
    }
    for (size_t index = 0; index < setup->remap_count; index += 1) {
        if (sources[index] != channel) {
            close(sources[index]);
        }
    }
    return error;
}

static char **continuum_broker_decode_strings(
    const uint8_t **cursor,
    const uint8_t *limit,
    uint32_t count
) {
    char **values = calloc((size_t)count + 1, sizeof(char *));
    if (values == NULL) {
        return NULL;
    }
    for (uint32_t index = 0; index < count; index += 1) {
        if ((size_t)(limit - *cursor) < sizeof(uint32_t)) {
            free(values);
            return NULL;
        }
        uint32_t length;
        memcpy(&length, *cursor, sizeof(length));
        *cursor += sizeof(length);
        if (length == 0 || (size_t)(limit - *cursor) < length
            || (*cursor)[length - 1] != '\0') {
            free(values);
            return NULL;
        }
        values[index] = (char *)*cursor;
        *cursor += length;
    }
    return values;
}

static char **continuum_broker_child_environment(
    char *const *original,
    const char *bootstrap,
    int broker_fd
) {
    size_t count = 0;
    const char *old_dyld = NULL;
    for (; original[count] != NULL; count += 1) {
        if (strncmp(original[count], "DYLD_INSERT_LIBRARIES=", 22) == 0) {
            old_dyld = original[count] + 22;
        }
    }
    char **result = calloc(count + 6, sizeof(char *));
    if (result == NULL) return NULL;
    size_t output = 0;
    for (size_t index = 0; index < count; index += 1) {
        if (strncmp(original[index], "DYLD_INSERT_LIBRARIES=", 22) != 0
            && strncmp(original[index], "CONTINUUM_BROKER_", 17) != 0) {
            result[output++] = strdup(original[index]);
        }
    }
    if (asprintf(&result[output++], "DYLD_INSERT_LIBRARIES=%s%s%s", bootstrap,
        old_dyld == NULL || old_dyld[0] == '\0' ? "" : ":",
        old_dyld == NULL ? "" : old_dyld) < 0
        || asprintf(&result[output++], "CONTINUUM_BROKER_FD=%d", broker_fd) < 0
        || asprintf(&result[output++], "CONTINUUM_BROKER_ORIGINAL_DYLD_PRESENT=%d",
            old_dyld == NULL ? 0 : 1) < 0
        || asprintf(&result[output++], "CONTINUUM_BROKER_ORIGINAL_DYLD=%s",
            old_dyld == NULL ? "" : old_dyld) < 0
        || asprintf(&result[output++], "CONTINUUM_BROKER_IS_CHILD=1") < 0) {
        for (size_t index = 0; index < output; index += 1) free(result[index]);
        free(result);
        return NULL;
    }
    return result;
}

static void continuum_broker_free_environment(char **environment) {
    if (environment == NULL) return;
    for (size_t index = 0; environment[index] != NULL; index += 1) free(environment[index]);
    free(environment);
}

static int continuum_bootstrap_run_broker(int channel, int is_child) {
    uid_t peer_uid = (uid_t)-1;
    gid_t peer_gid = (gid_t)-1;
    if (getpeereid(channel, &peer_uid, &peer_gid) != 0
        || peer_uid != geteuid()) {
        return -1;
    }
    continuum_broker_header header;
    continuum_broker_setup setup;
    if (!continuum_broker_read_all(channel, &header, sizeof(header))
        || header.magic != CONTINUUM_BROKER_MAGIC
        || header.version != CONTINUUM_BROKER_VERSION
        || header.type != CONTINUUM_BROKER_SETUP
        || header.payload_length < sizeof(setup)
        || header.payload_length > sizeof(setup)
            + sizeof(int32_t) * CONTINUUM_BROKER_MAX_REMAPS
        || !continuum_broker_read_all(channel, &setup, sizeof(setup))
        || header.payload_length != sizeof(setup)
            + sizeof(int32_t) * setup.remap_count) {
        return -1;
    }
    if (setup.create_session > 1 || setup.process_group_policy > 2
        || setup.controlling_terminal_descriptor < -1
        || setup.remap_count > CONTINUUM_BROKER_MAX_REMAPS
        || setup.captured_process_id <= 0
        || setup.captured_process_group_id <= 0
        || setup.foreground_process_group_id <= 0) {
        return -1;
    }
    int32_t targets[CONTINUUM_BROKER_MAX_REMAPS];
    if (!continuum_broker_read_all(channel, targets,
            sizeof(int32_t) * setup.remap_count)) return -1;
    int error = continuum_broker_apply_setup(channel, &setup, targets);
    continuum_broker_reply reply = {
        .process_id = getpid(), .parent_process_id = getppid(),
        .session_id = getsid(0), .process_group_id = getpgrp(),
        .controlling_terminal_process_group = setup.controlling_terminal_descriptor < 0
            ? -1 : tcgetpgrp(setup.controlling_terminal_descriptor),
        .error_code = error,
    };
    if (error != 0 || !continuum_broker_send_reply(channel,
            error == 0 ? CONTINUUM_BROKER_READY : CONTINUUM_BROKER_FAILED, &reply)) {
        return -1;
    }
    if (is_child) {
        if (!continuum_broker_read_all(channel, &header, sizeof(header))
            || header.magic != CONTINUUM_BROKER_MAGIC
            || header.version != CONTINUUM_BROKER_VERSION
            || header.payload_length != 0) return -1;
        if (header.type == CONTINUUM_BROKER_ABORT) _exit(EXIT_FAILURE);
        if (header.type != CONTINUUM_BROKER_RELEASE
            || !continuum_broker_send_reply(channel,
                CONTINUUM_BROKER_RELEASED, &reply)) return -1;
        close(channel);
        return 0;
    }
    if (!continuum_broker_read_all(channel, &header, sizeof(header))
        || header.magic != CONTINUUM_BROKER_MAGIC
        || header.version != CONTINUUM_BROKER_VERSION
        || header.type != CONTINUUM_BROKER_SPAWN_CHILD
        || header.payload_length < sizeof(continuum_broker_child)
        || header.payload_length > sizeof(continuum_broker_child)
            + CONTINUUM_BROKER_MAX_STRING_BYTES
            + sizeof(int32_t) * CONTINUUM_BROKER_MAX_REMAPS) return -1;
    uint8_t *payload = malloc(header.payload_length);
    if (payload == NULL || !continuum_broker_read_all(channel, payload, header.payload_length)) {
        free(payload); return -1;
    }
    continuum_broker_child child;
    memcpy(&child, payload, sizeof(child));
    if (child.argument_count == 0 || child.argument_count > CONTINUUM_BROKER_MAX_ARGUMENTS
        || child.environment_count > CONTINUUM_BROKER_MAX_ENVIRONMENT
        || child.remap_count > CONTINUUM_BROKER_MAX_REMAPS
        || child.string_bytes > CONTINUUM_BROKER_MAX_STRING_BYTES
        || child.executable_length == 0 || child.directory_length == 0
        || child.bootstrap_length == 0 || child.process_group_policy > 2
        || child.captured_process_id <= 0
        || child.captured_process_group_id <= 0) {
        free(payload); return -1;
    }
    const uint8_t *cursor = payload + sizeof(child);
    const uint8_t *limit = payload + header.payload_length;
    char **argv = continuum_broker_decode_strings(&cursor, limit, child.argument_count);
    char **env = continuum_broker_decode_strings(&cursor, limit, child.environment_count);
    if (argv == NULL || env == NULL || (size_t)(limit - cursor)
        < child.executable_length + child.directory_length + child.bootstrap_length
            + sizeof(int32_t) * child.remap_count) {
        free(argv); free(env); free(payload); return -1;
    }
    char *executable = (char *)cursor; cursor += child.executable_length;
    char *directory = (char *)cursor; cursor += child.directory_length;
    char *bootstrap = (char *)cursor; cursor += child.bootstrap_length;
    int32_t *child_targets = (int32_t *)cursor;
    if (executable[child.executable_length - 1] != '\0'
        || directory[child.directory_length - 1] != '\0'
        || bootstrap[child.bootstrap_length - 1] != '\0') {
        free(argv); free(env); free(payload); return -1;
    }
    int forwarded[CONTINUUM_BROKER_MAX_REMAPS];
    if (!continuum_broker_receive_fds(channel, forwarded, child.remap_count)) {
        free(argv); free(env); free(payload); return -1;
    }
    int child_pair[2] = {-1, -1};
    pid_t child_pid = 0;
    int spawn_error = socketpair(AF_UNIX, SOCK_STREAM, 0, child_pair);
    if (spawn_error == 0) {
        int highest = child_pair[0];
        for (size_t index = 0; index < child.remap_count; index += 1) {
            if (child_targets[index] > highest) highest = child_targets[index];
        }
        int safe_child_channel = fcntl(child_pair[1], F_DUPFD_CLOEXEC, highest + 1);
        if (safe_child_channel < 0) {
            spawn_error = errno;
        } else {
            close(child_pair[1]);
            child_pair[1] = safe_child_channel;
        }
    }
    char **child_environment = spawn_error == 0
        ? continuum_broker_child_environment(env, bootstrap, child_pair[1]) : NULL;
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    int actions_initialized = 0;
    int attributes_initialized = 0;
    if (spawn_error == 0 && child_environment == NULL) spawn_error = ENOMEM;
    if (spawn_error == 0) {
        spawn_error = posix_spawn_file_actions_init(&actions);
        actions_initialized = spawn_error == 0;
    }
    if (spawn_error == 0) spawn_error = posix_spawn_file_actions_addchdir_np(&actions, directory);
    if (spawn_error == 0) spawn_error = posix_spawn_file_actions_addinherit_np(&actions, child_pair[1]);
    if (spawn_error == 0) {
        spawn_error = posix_spawnattr_init(&attributes);
        attributes_initialized = spawn_error == 0;
    }
    if (spawn_error == 0) {
        short flags = POSIX_SPAWN_CLOEXEC_DEFAULT;
        if (child.disable_aslr) flags |= 0x0100;
        spawn_error = posix_spawnattr_setflags(&attributes, flags);
    }
    if (spawn_error == 0) spawn_error = posix_spawn(&child_pid, executable,
        &actions, &attributes, argv, child_environment);
    if (child_environment != NULL) continuum_broker_free_environment(child_environment);
    if (attributes_initialized) posix_spawnattr_destroy(&attributes);
    if (actions_initialized) posix_spawn_file_actions_destroy(&actions);
    close(child_pair[1]);
    continuum_broker_setup child_setup = {
        .create_session = 0,
        .process_group_policy = child.process_group_policy,
        .process_group_id = child.process_group_policy == 2
            ? getpgrp() : child.process_group_id,
        .captured_process_id = child.captured_process_id,
        .captured_process_group_id = child.captured_process_group_id,
        .foreground_process_group_id = setup.foreground_process_group_id,
        .controlling_terminal_descriptor = -1,
        .remap_count = child.remap_count,
    };
    continuum_broker_header setup_header = {
        .magic = CONTINUUM_BROKER_MAGIC, .version = CONTINUUM_BROKER_VERSION,
        .type = CONTINUUM_BROKER_SETUP,
        .payload_length = sizeof(child_setup) + sizeof(int32_t) * child.remap_count,
    };
    if (spawn_error == 0 && (!continuum_broker_write_all(child_pair[0], &setup_header, sizeof(setup_header))
        || !continuum_broker_write_all(child_pair[0], &child_setup, sizeof(child_setup))
        || !continuum_broker_write_all(child_pair[0], child_targets, sizeof(int32_t) * child.remap_count)
        || !continuum_broker_send_fds(child_pair[0], forwarded, child.remap_count))) spawn_error = EIO;
    for (size_t index = 0; index < child.remap_count; index += 1) close(forwarded[index]);
    free(argv); free(env); free(payload);
    continuum_broker_header child_reply_header;
    continuum_broker_reply child_reply;
    if (spawn_error == 0 && (!continuum_broker_read_all(child_pair[0], &child_reply_header, sizeof(child_reply_header))
        || child_reply_header.type != CONTINUUM_BROKER_READY
        || !continuum_broker_read_all(child_pair[0], &child_reply, sizeof(child_reply)))) spawn_error = EIO;
    if (spawn_error == 0 && setup.controlling_terminal_descriptor >= 0) {
        pid_t foreground = 0;
        if (setup.foreground_process_group_id
                == setup.captured_process_group_id) {
            foreground = getpgrp();
        } else if (setup.foreground_process_group_id
                == child.captured_process_group_id) {
            foreground = child_reply.process_group_id;
        } else {
            spawn_error = EINVAL;
        }
        if (spawn_error == 0
            && tcsetpgrp(setup.controlling_terminal_descriptor, foreground)
                != 0) {
            spawn_error = errno;
        }
    }
    reply = child_reply;
    reply.error_code = spawn_error;
    if (spawn_error != 0 || !continuum_broker_send_reply(channel,
        spawn_error == 0 ? CONTINUUM_BROKER_CHILD_READY : CONTINUUM_BROKER_FAILED, &reply)) {
        if (child_pid > 0) { kill(child_pid, SIGKILL); waitpid(child_pid, NULL, 0); }
        close(child_pair[0]); return -1;
    }
    int child_released = 0;
    for (;;) {
        if (!continuum_broker_read_all(channel, &header, sizeof(header))
            || header.magic != CONTINUUM_BROKER_MAGIC
            || header.version != CONTINUUM_BROKER_VERSION
            || header.payload_length != 0) {
            kill(child_pid, SIGKILL);
            waitpid(child_pid, NULL, 0);
            close(child_pair[0]);
            return -1;
        }
        if (header.type == CONTINUUM_BROKER_ABORT) {
            if (!child_released) {
                if (!continuum_broker_write_all(
                        child_pair[0], &header, sizeof(header))) {
                    kill(child_pid, SIGKILL);
                }
            } else {
                kill(child_pid, SIGKILL);
            }
            waitpid(child_pid, NULL, 0);
            close(child_pair[0]);
            _exit(EXIT_FAILURE);
        }
        if ((header.type == CONTINUUM_BROKER_CHILD_TO_BOOTSTRAP
                || header.type == CONTINUUM_BROKER_RELEASE)
            && !child_released) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
            int traced_child = header.type == CONTINUUM_BROKER_CHILD_TO_BOOTSTRAP;
            if (traced_child
                && (ptrace(PT_ATTACH, child_pid, NULL, 0) != 0
                    || !continuum_broker_wait_for_child_stop(
                        child_pid, SIGSTOP))) {
                kill(child_pid, SIGKILL);
                waitpid(child_pid, NULL, 0);
                close(child_pair[0]);
                return -1;
            }
            continuum_broker_header child_command = header;
            child_command.type = CONTINUUM_BROKER_RELEASE;
            if (!continuum_broker_write_all(
                    child_pair[0], &child_command, sizeof(child_command))) {
                kill(child_pid, SIGKILL);
                waitpid(child_pid, NULL, 0);
                close(child_pair[0]);
                return -1;
            }
            if (traced_child
                && ptrace(PT_CONTINUE, child_pid, (caddr_t)1, 0) != 0) {
                kill(child_pid, SIGKILL);
                waitpid(child_pid, NULL, 0);
                close(child_pair[0]);
                return -1;
            }
            if (!continuum_broker_read_all(
                    child_pair[0], &child_reply_header,
                    sizeof(child_reply_header))
                || child_reply_header.type != CONTINUUM_BROKER_RELEASED
                || !continuum_broker_read_all(
                    child_pair[0], &child_reply, sizeof(child_reply))) {
                kill(child_pid, SIGKILL);
                waitpid(child_pid, NULL, 0);
                close(child_pair[0]);
                return -1;
            }
            close(child_pair[0]);
            child_pair[0] = -1;
            child_released = 1;
            if (header.type == CONTINUUM_BROKER_CHILD_TO_BOOTSTRAP) {
                if (!continuum_broker_wait_for_child_stop(
                        child_pid, SIGSTOP)) {
                    kill(child_pid, SIGKILL);
                    waitpid(child_pid, NULL, 0);
                    return -1;
                }
                if (!continuum_broker_send_reply(
                        channel,
                        CONTINUUM_BROKER_CHILD_BOOTSTRAP_RELEASED,
                        &child_reply)) {
                    kill(child_pid, SIGKILL);
                    waitpid(child_pid, NULL, 0);
                    return -1;
                }
                continue;
            }
#pragma clang diagnostic pop
        }
        if (header.type == CONTINUUM_BROKER_CHILD_TO_ENTRY
            && child_released) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
            if (ptrace(PT_CONTINUE, child_pid, (caddr_t)1, 0) != 0
                || !continuum_broker_wait_for_child_stop(
                    child_pid, SIGTRAP)
                || !continuum_broker_send_reply(
                    channel,
                    CONTINUUM_BROKER_CHILD_ENTRY_REACHED,
                    &child_reply)) {
                kill(child_pid, SIGKILL);
                waitpid(child_pid, NULL, 0);
                return -1;
            }
#pragma clang diagnostic pop
            continue;
        }
        if (header.type == CONTINUUM_BROKER_CHILD_DETACH
            && child_released) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
            if (kill(child_pid, SIGSTOP) != 0
                || ptrace(PT_DETACH, child_pid, (caddr_t)1, 0) != 0
                || !continuum_broker_wait_for_stopped_state(child_pid)
                || !continuum_broker_send_reply(
                    channel,
                    CONTINUUM_BROKER_CHILD_DETACHED,
                    &child_reply)) {
                kill(child_pid, SIGKILL);
                waitpid(child_pid, NULL, 0);
                return -1;
            }
#pragma clang diagnostic pop
            continue;
        }
        if ((header.type == CONTINUUM_BROKER_ROOT_TO_BOOTSTRAP
                || header.type == CONTINUUM_BROKER_RELEASE)
            && child_released) {
            reply.process_id = getpid();
            reply.parent_process_id = getppid();
            uint16_t reply_type = header.type
                    == CONTINUUM_BROKER_ROOT_TO_BOOTSTRAP
                ? CONTINUUM_BROKER_ROOT_BOOTSTRAP_RELEASED
                : CONTINUUM_BROKER_RELEASED;
            if (!continuum_broker_send_reply(channel, reply_type, &reply)) {
                kill(child_pid, SIGKILL);
                waitpid(child_pid, NULL, 0);
                return -1;
            }
            close(channel);
            return 0;
        }
        kill(child_pid, SIGKILL);
        waitpid(child_pid, NULL, 0);
        if (child_pair[0] >= 0) close(child_pair[0]);
        return -1;
    }
}

__attribute__((visibility("default")))
volatile continuum_bootstrap_pty_safepoint_status
    continuum_bootstrap_pty_safepoint_report = {
        .magic = CONTINUUM_BOOTSTRAP_PTY_STATUS_MAGIC,
        .version = 2,
        .structure_size = sizeof(continuum_bootstrap_pty_safepoint_status),
    };

__attribute__((visibility("default")))
volatile continuum_bootstrap_descriptor_safepoint_status
    continuum_bootstrap_descriptor_safepoint_report = {
        .magic = CONTINUUM_BOOTSTRAP_DESCRIPTOR_STATUS_MAGIC,
        .version = 1,
        .structure_size =
            sizeof(continuum_bootstrap_descriptor_safepoint_status),
    };

extern id objc_alloc(Class cls);
extern id objc_allocWithZone(Class cls);
extern id objc_alloc_init(Class cls);
extern id objc_opt_new(Class cls);

enum {
    CONTINUUM_APP_STATE_ALLOCATION_LIMIT = 16384,
};

#define CONTINUUM_APP_STATE_ARENA_SIZE UINT64_C(0x10000000)
#define CONTINUUM_APP_STATE_METADATA_SIZE UINT64_C(0x00100000)
#define CONTINUUM_APP_STATE_METADATA_MAGIC UINT64_C(0x434F4E544D455441)
#define CONTINUUM_APP_STATE_METADATA_VERSION UINT32_C(1)

typedef struct continuum_app_state_allocation {
    mach_vm_address_t address;
    mach_vm_size_t mapping_length;
    size_t requested_size;
    uint8_t active;
} continuum_app_state_allocation;

typedef struct continuum_app_state_metadata {
    uint64_t magic;
    uint32_t version;
    uint32_t reserved;
    mach_vm_address_t arena_base;
    mach_vm_address_t mapping_cursor;
    mach_vm_address_t mapping_limit;
    uint64_t allocation_count;
    continuum_app_state_allocation allocations[
        CONTINUUM_APP_STATE_ALLOCATION_LIMIT
    ];
} continuum_app_state_metadata;

_Static_assert(
    sizeof(continuum_app_state_metadata) <= CONTINUUM_APP_STATE_METADATA_SIZE,
    "app-state allocator metadata exceeds its fixed mapping"
);

static continuum_app_state_metadata *continuum_app_state_metadata_header = NULL;
static pthread_mutex_t continuum_app_state_lock = PTHREAD_MUTEX_INITIALIZER;

static const mach_vm_address_t continuum_app_state_candidates[] = {
    UINT64_C(0x0000000140000000),
    UINT64_C(0x0000000150000000),
    UINT64_C(0x0000000160000000),
    UINT64_C(0x0000000170000000),
};

static int continuum_app_state_metadata_is_valid(void) {
    const continuum_app_state_metadata *metadata =
        continuum_app_state_metadata_header;
    if (metadata == NULL
        || metadata->magic != CONTINUUM_APP_STATE_METADATA_MAGIC
        || metadata->version != CONTINUUM_APP_STATE_METADATA_VERSION
        || metadata->allocation_count > CONTINUUM_APP_STATE_ALLOCATION_LIMIT) {
        return 0;
    }
    const mach_vm_address_t page_size = (mach_vm_address_t)getpagesize();
    for (size_t index = 0;
         index < sizeof(continuum_app_state_candidates)
            / sizeof(continuum_app_state_candidates[0]);
         index += 1) {
        const mach_vm_address_t base = continuum_app_state_candidates[index];
        const mach_vm_address_t metadata_address =
            base + CONTINUUM_APP_STATE_ARENA_SIZE
                - CONTINUUM_APP_STATE_METADATA_SIZE;
        const mach_vm_address_t mapping_limit = metadata_address - page_size;
        if (metadata->arena_base == base
            && metadata->mapping_limit == mapping_limit
            && metadata->mapping_cursor >= base
            && metadata->mapping_cursor <= mapping_limit) {
            return 1;
        }
    }
    return 0;
}

static size_t continuum_app_state_size(
    malloc_zone_t *zone,
    const void *pointer
) {
    (void)zone;
    if (pointer == NULL) {
        return 0;
    }
    size_t result = 0;
    pthread_mutex_lock(&continuum_app_state_lock);
    if (!continuum_app_state_metadata_is_valid()) {
        pthread_mutex_unlock(&continuum_app_state_lock);
        return 0;
    }
    for (size_t index = 0;
         index < continuum_app_state_metadata_header->allocation_count;
         index += 1) {
        const continuum_app_state_allocation *allocation =
            &continuum_app_state_metadata_header->allocations[index];
        if (allocation->active
            && allocation->address == (mach_vm_address_t)(uintptr_t)pointer) {
            result = allocation->requested_size;
            break;
        }
    }
    pthread_mutex_unlock(&continuum_app_state_lock);
    return result;
}

static void *continuum_app_state_memalign(
    malloc_zone_t *zone,
    size_t alignment,
    size_t size
) {
    (void)zone;
    if (alignment < sizeof(void *)
        || (alignment & (alignment - 1)) != 0) {
        return NULL;
    }
    const size_t requested_size = size == 0 ? 1 : size;
    const size_t page_size = (size_t)getpagesize();
    if (requested_size > SIZE_MAX - (page_size - 1)) {
        return NULL;
    }
    const mach_vm_size_t mapping_length =
        (mach_vm_size_t)((requested_size + page_size - 1)
            & ~(page_size - 1));
    if (mapping_length > UINT64_C(0x10000000)) {
        return NULL;
    }
    const mach_vm_size_t effective_alignment = alignment > page_size
        ? (mach_vm_size_t)alignment
        : (mach_vm_size_t)page_size;

    pthread_mutex_lock(&continuum_app_state_lock);
    mach_vm_address_t allocation_address = 0;
    if (continuum_app_state_metadata_header == NULL) {
        for (size_t index = 0;
             index < sizeof(continuum_app_state_candidates)
                / sizeof(continuum_app_state_candidates[0]);
             index += 1) {
            const mach_vm_address_t arena_base =
                continuum_app_state_candidates[index];
            if ((arena_base & (effective_alignment - 1)) != 0) {
                continue;
            }
            const mach_vm_address_t metadata_address =
                arena_base + CONTINUUM_APP_STATE_ARENA_SIZE
                    - CONTINUUM_APP_STATE_METADATA_SIZE;
            const mach_vm_address_t mapping_limit =
                metadata_address - (mach_vm_address_t)page_size;
            if (mapping_length > mapping_limit - arena_base) {
                continue;
            }

            mach_vm_address_t candidate = arena_base;
            kern_return_t result = mach_vm_map(
                mach_task_self(),
                &candidate,
                mapping_length,
                0,
                VM_FLAGS_FIXED
                    | VM_MAKE_TAG(VM_MEMORY_APPLICATION_SPECIFIC_1),
                MEMORY_OBJECT_NULL,
                0,
                FALSE,
                VM_PROT_READ | VM_PROT_WRITE,
                VM_PROT_READ | VM_PROT_WRITE,
                VM_INHERIT_NONE
            );
            if (result != KERN_SUCCESS || candidate != arena_base) {
                continue;
            }

            mach_vm_address_t metadata_candidate = metadata_address;
            result = mach_vm_map(
                mach_task_self(),
                &metadata_candidate,
                CONTINUUM_APP_STATE_METADATA_SIZE,
                0,
                VM_FLAGS_FIXED
                    | VM_MAKE_TAG(VM_MEMORY_APPLICATION_SPECIFIC_2),
                MEMORY_OBJECT_NULL,
                0,
                FALSE,
                VM_PROT_READ | VM_PROT_WRITE,
                VM_PROT_READ | VM_PROT_WRITE,
                VM_INHERIT_NONE
            );
            if (result != KERN_SUCCESS
                || metadata_candidate != metadata_address) {
                (void)mach_vm_deallocate(
                    mach_task_self(),
                    arena_base,
                    mapping_length
                );
                continue;
            }

            continuum_app_state_metadata_header =
                (continuum_app_state_metadata *)(uintptr_t)metadata_address;
            memset(
                continuum_app_state_metadata_header,
                0,
                sizeof(*continuum_app_state_metadata_header)
            );
            continuum_app_state_metadata_header->magic =
                CONTINUUM_APP_STATE_METADATA_MAGIC;
            continuum_app_state_metadata_header->version =
                CONTINUUM_APP_STATE_METADATA_VERSION;
            continuum_app_state_metadata_header->arena_base = arena_base;
            continuum_app_state_metadata_header->mapping_cursor = arena_base;
            continuum_app_state_metadata_header->mapping_limit = mapping_limit;
            allocation_address = arena_base;
            break;
        }
        if (continuum_app_state_metadata_header == NULL) {
            pthread_mutex_unlock(&continuum_app_state_lock);
            return NULL;
        }
    } else {
        if (!continuum_app_state_metadata_is_valid()
            || continuum_app_state_metadata_header->allocation_count
                >= CONTINUUM_APP_STATE_ALLOCATION_LIMIT) {
            pthread_mutex_unlock(&continuum_app_state_lock);
            return NULL;
        }
        const mach_vm_address_t mapping_cursor =
            continuum_app_state_metadata_header->mapping_cursor;
        const mach_vm_address_t mapping_limit =
            continuum_app_state_metadata_header->mapping_limit;
        const mach_vm_address_t aligned =
            (mapping_cursor + effective_alignment - 1)
                & ~(effective_alignment - 1);
        if (aligned < mapping_cursor
            || aligned >= mapping_limit
            || mapping_length > mapping_limit - aligned) {
            pthread_mutex_unlock(&continuum_app_state_lock);
            return NULL;
        }
        mach_vm_address_t candidate = aligned;
        kern_return_t result = mach_vm_map(
            mach_task_self(),
            &candidate,
            mapping_length,
            0,
            VM_FLAGS_FIXED | VM_MAKE_TAG(VM_MEMORY_APPLICATION_SPECIFIC_1),
            MEMORY_OBJECT_NULL,
            0,
            FALSE,
            VM_PROT_READ | VM_PROT_WRITE,
            VM_PROT_READ | VM_PROT_WRITE,
            VM_INHERIT_NONE
        );
        if (result != KERN_SUCCESS || candidate != aligned) {
            pthread_mutex_unlock(&continuum_app_state_lock);
            return NULL;
        }
        allocation_address = candidate;
    }

    continuum_app_state_allocation *allocation =
        &continuum_app_state_metadata_header->allocations[
            continuum_app_state_metadata_header->allocation_count
        ];
    allocation->address = allocation_address;
    allocation->mapping_length = mapping_length;
    allocation->requested_size = requested_size;
    allocation->active = 1;
    continuum_app_state_metadata_header->allocation_count += 1;
    const mach_vm_address_t allocation_end =
        allocation_address + mapping_length;
    continuum_app_state_metadata_header->mapping_cursor =
        allocation_end
                <= continuum_app_state_metadata_header->mapping_limit
                    - page_size
            ? allocation_end + page_size
            : continuum_app_state_metadata_header->mapping_limit;
    void *result = (void *)(uintptr_t)allocation->address;
    pthread_mutex_unlock(&continuum_app_state_lock);
    return result;
}

static void *continuum_app_state_malloc(malloc_zone_t *zone, size_t size) {
    return continuum_app_state_memalign(zone, sizeof(max_align_t), size);
}

static void *continuum_app_state_calloc(
    malloc_zone_t *zone,
    size_t count,
    size_t size
) {
    if (count != 0 && size > SIZE_MAX / count) {
        return NULL;
    }
    return continuum_app_state_malloc(zone, count * size);
}

static void *continuum_app_state_valloc(malloc_zone_t *zone, size_t size) {
    return continuum_app_state_memalign(zone, (size_t)getpagesize(), size);
}

static void continuum_app_state_free(malloc_zone_t *zone, void *pointer) {
    (void)zone;
    if (pointer == NULL) {
        return;
    }
    pthread_mutex_lock(&continuum_app_state_lock);
    if (!continuum_app_state_metadata_is_valid()) {
        pthread_mutex_unlock(&continuum_app_state_lock);
        return;
    }
    for (size_t index = 0;
         index < continuum_app_state_metadata_header->allocation_count;
         index += 1) {
        continuum_app_state_allocation *allocation =
            &continuum_app_state_metadata_header->allocations[index];
        if (!allocation->active
            || allocation->address != (mach_vm_address_t)(uintptr_t)pointer) {
            continue;
        }
        allocation->active = 0;
        (void)mach_vm_deallocate(
            mach_task_self(),
            allocation->address,
            allocation->mapping_length
        );
        break;
    }
    pthread_mutex_unlock(&continuum_app_state_lock);
}

static void *continuum_app_state_realloc(
    malloc_zone_t *zone,
    void *pointer,
    size_t size
) {
    if (pointer == NULL) {
        return continuum_app_state_malloc(zone, size);
    }
    if (size == 0) {
        continuum_app_state_free(zone, pointer);
        return NULL;
    }
    const size_t old_size = continuum_app_state_size(zone, pointer);
    if (old_size == 0) {
        return NULL;
    }
    void *replacement = continuum_app_state_malloc(zone, size);
    if (replacement == NULL) {
        return NULL;
    }
    memcpy(replacement, pointer, old_size < size ? old_size : size);
    continuum_app_state_free(zone, pointer);
    return replacement;
}

static void continuum_app_state_destroy(malloc_zone_t *zone) {
    (void)zone;
}

static void continuum_app_state_free_definite_size(
    malloc_zone_t *zone,
    void *pointer,
    size_t size
) {
    (void)size;
    continuum_app_state_free(zone, pointer);
}

static size_t continuum_app_state_pressure_relief(
    malloc_zone_t *zone,
    size_t goal
) {
    (void)zone;
    (void)goal;
    return 0;
}

static boolean_t continuum_app_state_claimed_address(
    malloc_zone_t *zone,
    void *pointer
) {
    return continuum_app_state_size(zone, pointer) > 0;
}

#define CONTINUUM_INTERPOSE(replacement, replacee) \
    __attribute__((used)) static struct { \
        const void *replacement; \
        const void *replacee; \
    } continuum_interpose_##replacee \
        __attribute__((section("__DATA,__interpose"))) = { \
            (const void *)(uintptr_t)&replacement, \
            (const void *)(uintptr_t)&replacee \
        }

static int continuum_address_is_in_main_text(uintptr_t address) {
    return continuum_main_text_start != 0
        && address >= continuum_main_text_start
        && address < continuum_main_text_end;
}

static int continuum_allocation_is_app_owned(uintptr_t return_address) {
#if __has_feature(ptrauth_calls)
    return_address = (uintptr_t)ptrauth_strip(
        (void *)return_address,
        ptrauth_key_return_address
    );
#endif
    return continuum_address_is_in_main_text(return_address);
}

static void *continuum_state_malloc(size_t size) {
    malloc_zone_t *default_zone = malloc_default_zone();
    malloc_zone_t *zone = default_zone;
    uintptr_t return_address = (uintptr_t)__builtin_return_address(0);
    if (continuum_app_state_zone != NULL
        && __sync_lock_test_and_set(
            &continuum_allocator_interposition_active,
            1
        ) == 0) {
        if (continuum_allocation_is_app_owned(return_address)) {
            zone = continuum_app_state_zone;
        }
        __sync_lock_release(&continuum_allocator_interposition_active);
    }
    void *result = malloc_zone_malloc(zone, size);
    return result == NULL && zone == continuum_app_state_zone
        ? malloc_zone_malloc(default_zone, size)
        : result;
}

static void *continuum_state_calloc(size_t count, size_t size) {
    malloc_zone_t *default_zone = malloc_default_zone();
    malloc_zone_t *zone = default_zone;
    uintptr_t return_address = (uintptr_t)__builtin_return_address(0);
    if (continuum_app_state_zone != NULL
        && __sync_lock_test_and_set(
            &continuum_allocator_interposition_active,
            1
        ) == 0) {
        if (continuum_allocation_is_app_owned(return_address)) {
            zone = continuum_app_state_zone;
        }
        __sync_lock_release(&continuum_allocator_interposition_active);
    }
    void *result = malloc_zone_calloc(zone, count, size);
    return result == NULL && zone == continuum_app_state_zone
        ? malloc_zone_calloc(default_zone, count, size)
        : result;
}

static void *continuum_state_typed_malloc(
    size_t size,
    malloc_type_id_t type_id
) {
    (void)type_id;
    malloc_zone_t *default_zone = malloc_default_zone();
    malloc_zone_t *zone = default_zone;
    uintptr_t return_address = (uintptr_t)__builtin_return_address(0);
    if (continuum_app_state_zone != NULL
        && __sync_lock_test_and_set(
            &continuum_allocator_interposition_active,
            1
        ) == 0) {
        if (continuum_allocation_is_app_owned(return_address)) {
            zone = continuum_app_state_zone;
        }
        __sync_lock_release(&continuum_allocator_interposition_active);
    }
    void *result = malloc_zone_malloc(zone, size);
    return result == NULL && zone == continuum_app_state_zone
        ? malloc_zone_malloc(default_zone, size)
        : result;
}

static void *continuum_state_typed_calloc(
    size_t count,
    size_t size,
    malloc_type_id_t type_id
) {
    (void)type_id;
    malloc_zone_t *default_zone = malloc_default_zone();
    malloc_zone_t *zone = default_zone;
    uintptr_t return_address = (uintptr_t)__builtin_return_address(0);
    if (continuum_app_state_zone != NULL
        && __sync_lock_test_and_set(
            &continuum_allocator_interposition_active,
            1
        ) == 0) {
        if (continuum_allocation_is_app_owned(return_address)) {
            zone = continuum_app_state_zone;
        }
        __sync_lock_release(&continuum_allocator_interposition_active);
    }
    void *result = malloc_zone_calloc(zone, count, size);
    return result == NULL && zone == continuum_app_state_zone
        ? malloc_zone_calloc(default_zone, count, size)
        : result;
}

static int continuum_class_method_matches_root(
    Class cls,
    Class root,
    const char *selector_name
) {
    if (cls == Nil || root == Nil || selector_name == NULL) {
        return 0;
    }
    SEL selector = sel_registerName(selector_name);
    Method method = class_getClassMethod(cls, selector);
    Method root_method = class_getClassMethod(root, selector);
    return method != NULL && root_method != NULL
        && method_getImplementation(method)
            == method_getImplementation(root_method);
}

static int continuum_ivar_is_scalar(Ivar ivar) {
    const char *encoding = ivar == NULL ? NULL : ivar_getTypeEncoding(ivar);
    if (encoding == NULL || encoding[0] == '\0') {
        return 0;
    }
    switch (encoding[0]) {
    case 'c':
    case 'C':
    case 's':
    case 'S':
    case 'i':
    case 'I':
    case 'l':
    case 'L':
    case 'q':
    case 'Q':
    case 'f':
    case 'd':
    case 'B':
        return 1;
    default:
        return 0;
    }
}

static int continuum_class_has_only_scalar_ivars(Class cls, Class root) {
    if (cls == Nil || root == Nil || cls == root) {
        return 0;
    }
    int saw_declared_state = 0;
    for (Class current = cls;
         current != Nil && current != root;
         current = class_getSuperclass(current)) {
        unsigned int count = 0;
        Ivar *ivars = class_copyIvarList(current, &count);
        if (count > 0 && ivars == NULL) {
            return 0;
        }
        for (unsigned int index = 0; index < count; index += 1) {
            if (!continuum_ivar_is_scalar(ivars[index])) {
                free(ivars);
                return 0;
            }
            saw_declared_state = 1;
        }
        free(ivars);
    }
    return saw_declared_state;
}

static int continuum_class_uses_standard_allocation(Class cls) {
    if (cls == Nil || continuum_main_image_path[0] == '\0') {
        return 0;
    }
    const char *image_path = class_getImageName(cls);
    Class root = objc_getClass("NSObject");
    return image_path != NULL
        && strcmp(image_path, continuum_main_image_path) == 0
        && continuum_class_method_matches_root(cls, root, "alloc")
        && continuum_class_method_matches_root(cls, root, "allocWithZone:")
        && continuum_class_has_only_scalar_ivars(cls, root);
}

static id continuum_construct_app_object(Class cls) {
    if (continuum_app_state_zone == NULL
        || __sync_lock_test_and_set(
            &continuum_objc_interposition_active,
            1
        ) != 0) {
        return nil;
    }
    if (!continuum_class_uses_standard_allocation(cls)) {
        __sync_lock_release(&continuum_objc_interposition_active);
        return nil;
    }
    const size_t size = class_getInstanceSize(cls);
    if (size == 0) {
        __sync_lock_release(&continuum_objc_interposition_active);
        return nil;
    }
    void *bytes = malloc_zone_calloc(continuum_app_state_zone, 1, size);
    if (bytes == NULL) {
        __sync_lock_release(&continuum_objc_interposition_active);
        return nil;
    }
    id object = objc_constructInstance(cls, bytes);
    if (object == nil) {
        malloc_zone_free(continuum_app_state_zone, bytes);
    }
    __sync_lock_release(&continuum_objc_interposition_active);
    return object;
}

static id continuum_send_class_message(Class cls, const char *selector_name) {
    if (cls == Nil || selector_name == NULL) {
        return nil;
    }
    return ((id (*)(id, SEL))(void *)objc_msgSend)(
        (id)cls,
        sel_registerName(selector_name)
    );
}

static id continuum_state_objc_alloc(Class cls) {
    id object = continuum_construct_app_object(cls);
    if (object != nil) {
        return object;
    }
    return continuum_send_class_message(cls, "alloc");
}

static id continuum_state_objc_alloc_with_zone(Class cls) {
    id object = continuum_construct_app_object(cls);
    if (object != nil) {
        return object;
    }
    if (cls == Nil) {
        return nil;
    }
    return ((id (*)(id, SEL, void *))(void *)objc_msgSend)(
        (id)cls,
        sel_registerName("allocWithZone:"),
        NULL
    );
}

static id continuum_send_init(id object) {
    if (object == nil) {
        return nil;
    }
    return ((id (*)(id, SEL))(void *)objc_msgSend)(
        object,
        sel_registerName("init")
    );
}

static id continuum_state_objc_alloc_init(Class cls) {
    id object = continuum_construct_app_object(cls);
    if (object != nil) {
        return continuum_send_init(object);
    }
    return continuum_send_init(
        continuum_send_class_message(cls, "alloc")
    );
}

static id continuum_state_objc_opt_new(Class cls) {
    Class root = objc_getClass("NSObject");
    if (continuum_class_method_matches_root(cls, root, "new")) {
        id object = continuum_construct_app_object(cls);
        if (object != nil) {
            return continuum_send_init(object);
        }
    }
    return continuum_send_class_message(cls, "new");
}

CONTINUUM_INTERPOSE(continuum_state_malloc, malloc);
CONTINUUM_INTERPOSE(continuum_state_calloc, calloc);
CONTINUUM_INTERPOSE(continuum_state_typed_malloc, malloc_type_malloc);
CONTINUUM_INTERPOSE(continuum_state_typed_calloc, malloc_type_calloc);
CONTINUUM_INTERPOSE(continuum_state_objc_alloc, objc_alloc);
CONTINUUM_INTERPOSE(continuum_state_objc_alloc_with_zone, objc_allocWithZone);
CONTINUUM_INTERPOSE(continuum_state_objc_alloc_init, objc_alloc_init);
CONTINUUM_INTERPOSE(continuum_state_objc_opt_new, objc_opt_new);

static void continuum_prepare_app_state_zone(void) {
    const struct mach_header *header = NULL;
    uint32_t image_count = _dyld_image_count();
    for (uint32_t index = 0; index < image_count; index += 1) {
        const struct mach_header *candidate = _dyld_get_image_header(index);
        if (candidate != NULL && candidate->filetype == MH_EXECUTE) {
            header = candidate;
            const char *image_path = _dyld_get_image_name(index);
            if (image_path != NULL) {
                (void)strlcpy(
                    continuum_main_image_path,
                    image_path,
                    sizeof(continuum_main_image_path)
                );
            }
            break;
        }
    }
    if (header == NULL || header->magic != MH_MAGIC_64) {
        return;
    }
    const struct mach_header_64 *header64 =
        (const struct mach_header_64 *)header;
    const uint8_t *command_bytes = (const uint8_t *)(header64 + 1);
    const uint8_t *command_end = command_bytes + header64->sizeofcmds;
    const struct load_command *command =
        (const struct load_command *)command_bytes;
    for (uint32_t index = 0; index < header64->ncmds; index += 1) {
        const uint8_t *next = (const uint8_t *)command + command->cmdsize;
        if (command->cmdsize < sizeof(*command) || next > command_end) {
            return;
        }
        if (command->cmd == LC_SEGMENT_64
            && command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment =
                (const struct segment_command_64 *)command;
            if (strncmp(segment->segname, SEG_TEXT, sizeof(segment->segname))
                == 0
                && segment->vmsize > 0
                && (uintptr_t)header
                    <= UINTPTR_MAX - segment->vmsize) {
                continuum_main_text_start = (uintptr_t)header;
                continuum_main_text_end =
                    continuum_main_text_start + (uintptr_t)segment->vmsize;
            }
        }
        command = (const struct load_command *)next;
    }
    if (continuum_main_text_start == 0) {
        return;
    }
    continuum_app_state_zone = malloc_create_zone(0, 0);
    if (continuum_app_state_zone != NULL) {
        malloc_set_zone_name(
            continuum_app_state_zone,
            CONTINUUM_BOOTSTRAP_APP_STATE_ZONE_NAME
        );
        continuum_app_state_zone->size = continuum_app_state_size;
        continuum_app_state_zone->malloc = continuum_app_state_malloc;
        continuum_app_state_zone->calloc = continuum_app_state_calloc;
        continuum_app_state_zone->valloc = continuum_app_state_valloc;
        continuum_app_state_zone->free = continuum_app_state_free;
        continuum_app_state_zone->realloc = continuum_app_state_realloc;
        continuum_app_state_zone->destroy = continuum_app_state_destroy;
        continuum_app_state_zone->memalign = continuum_app_state_memalign;
        continuum_app_state_zone->free_definite_size =
            continuum_app_state_free_definite_size;
        continuum_app_state_zone->pressure_relief =
            continuum_app_state_pressure_relief;
        continuum_app_state_zone->claimed_address =
            continuum_app_state_claimed_address;
        continuum_app_state_zone->version = 10;
    }
}

__attribute__((visibility("default")))
void *continuum_bootstrap_allocate_app_state(size_t size) {
    return continuum_app_state_zone == NULL
        ? NULL
        : malloc_zone_malloc(continuum_app_state_zone, size);
}

static int continuum_should_preserve_receive_right(
    ipc_space_t task,
    mach_port_name_t name
) {
    if (!continuum_preservation_active || task != mach_task_self()
        || !MACH_PORT_VALID(name)) {
        return 0;
    }
    mach_port_type_t type = MACH_PORT_TYPE_NONE;
    return mach_port_type(task, name, &type) == KERN_SUCCESS
        && (type & MACH_PORT_TYPE_RECEIVE) != 0;
}

static int continuum_should_preserve_deallocatable_right(
    ipc_space_t task,
    mach_port_name_t name
) {
    if (!continuum_preservation_active || task != mach_task_self()
        || !MACH_PORT_VALID(name)) {
        return 0;
    }
    mach_port_type_t type = MACH_PORT_TYPE_NONE;
    return mach_port_type(task, name, &type) == KERN_SUCCESS
        && (type & (MACH_PORT_TYPE_SEND | MACH_PORT_TYPE_SEND_ONCE
            | MACH_PORT_TYPE_DEAD_NAME)) != 0;
}

static kern_return_t continuum_preserving_mach_port_destruct(
    ipc_space_t task,
    mach_port_name_t name,
    mach_port_delta_t send_right_delta,
    mach_port_context_t guard
) {
    if (continuum_should_preserve_receive_right(task, name)) {
        return KERN_SUCCESS;
    }
    return mach_port_destruct(task, name, send_right_delta, guard);
}

static kern_return_t continuum_preserving_mach_port_mod_refs(
    ipc_space_t task,
    mach_port_name_t name,
    mach_port_right_t right,
    mach_port_delta_t delta
) {
    if (delta < 0
        && (continuum_should_preserve_receive_right(task, name)
            || continuum_should_preserve_deallocatable_right(task, name))) {
        return KERN_SUCCESS;
    }
    return mach_port_mod_refs(task, name, right, delta);
}

static kern_return_t continuum_preserving_mach_port_deallocate(
    ipc_space_t task,
    mach_port_name_t name
) {
    if (continuum_should_preserve_deallocatable_right(task, name)) {
        return KERN_SUCCESS;
    }
    return mach_port_deallocate(task, name);
}

CONTINUUM_INTERPOSE(
    continuum_preserving_mach_port_destruct,
    mach_port_destruct
);
CONTINUUM_INTERPOSE(
    continuum_preserving_mach_port_mod_refs,
    mach_port_mod_refs
);
CONTINUUM_INTERPOSE(
    continuum_preserving_mach_port_deallocate,
    mach_port_deallocate
);

__attribute__((visibility("default"), noinline))
void continuum_bootstrap_safepoint_spin(void) {
    while (!continuum_safepoint_release) {
#if defined(__arm64__)
        const uint64_t marker = CONTINUUM_BOOTSTRAP_SAFEPOINT_MAGIC;
        __asm__ volatile("mov x28, %0" : : "r"(marker) : "x28", "memory");
#else
        __asm__ volatile("" : : : "memory");
#endif
    }
}

static void continuum_release_safepoint(int signal_number) {
    (void)signal_number;
    continuum_safepoint_release = 1;
}

static void continuum_request_safepoint(int signal_number) {
    (void)signal_number;
    continuum_safepoint_requested = 1;
}

static void continuum_publish_pty_safepoint_status(void) {
    uint64_t generation = continuum_bootstrap_pty_safepoint_report.generation;
    generation = generation == UINT64_MAX ? 1 : generation + 1;

    uint64_t safepoint_thread_identifier = 0;
    if (pthread_threadid_np(NULL, &safepoint_thread_identifier) != 0) {
        safepoint_thread_identifier = 0;
    }
    uint32_t pty_count = 0;
    int queue_state_known = 1;
    int all_queues_zero = 1;
    int required_bytes = proc_pidinfo(
        getpid(), PROC_PIDLISTFDS, 0, NULL, 0);
    size_t capacity = required_bytes > 0
        ? (size_t)required_bytes + 32U * sizeof(struct proc_fdinfo)
        : 0;
    struct proc_fdinfo *descriptors = capacity > 0 && capacity <= INT_MAX
        ? calloc(1, capacity)
        : NULL;
    int returned_bytes = descriptors == NULL ? -1 : proc_pidinfo(
        getpid(),
        PROC_PIDLISTFDS,
        0,
        descriptors,
        (int)capacity
    );
    uint32_t exported_descriptor_count = 0;
    int descriptor_overflow = 0;
    if (returned_bytes < 0
        || returned_bytes % (int)sizeof(struct proc_fdinfo) != 0
        || (size_t)returned_bytes > capacity) {
        queue_state_known = 0;
        descriptor_overflow = 1;
    } else {
        size_t descriptor_count =
            (size_t)returned_bytes / sizeof(struct proc_fdinfo);
        for (size_t index = 0; index < descriptor_count; index += 1) {
            int descriptor = descriptors[index].proc_fd;
            uint32_t kind = 0;
            switch (descriptors[index].proc_fdtype) {
                case PROX_FDTYPE_SOCKET:
                    kind = CONTINUUM_BOOTSTRAP_DESCRIPTOR_SOCKET;
                    break;
                case PROX_FDTYPE_PIPE:
                    kind = CONTINUUM_BOOTSTRAP_DESCRIPTOR_PIPE;
                    break;
                case PROX_FDTYPE_KQUEUE:
                    kind = CONTINUUM_BOOTSTRAP_DESCRIPTOR_KQUEUE;
                    break;
                default:
                    break;
            }
            if (kind != 0) {
                int descriptor_flags = fcntl(descriptor, F_GETFD);
                int status_flags = fcntl(descriptor, F_GETFL);
                if (status_flags >= 0
                    && (kind == CONTINUUM_BOOTSTRAP_DESCRIPTOR_PIPE
                        || kind == CONTINUUM_BOOTSTRAP_DESCRIPTOR_SOCKET)) {
                    /*
                     * Darwin exposes kernel-only fileglob history such as
                     * FWASWRITTEN through F_GETFL. Those bits describe what
                     * happened to a pipe or socket; F_SETFL cannot recreate
                     * them. Keep only access mode and user-settable behavior.
                     */
                    status_flags &= O_ACCMODE | O_NONBLOCK | O_ASYNC;
                }
                if (descriptor_flags < 0 || status_flags < 0
                    || exported_descriptor_count
                        >= CONTINUUM_BOOTSTRAP_DESCRIPTOR_STATUS_LIMIT) {
                    descriptor_overflow = 1;
                } else {
                    continuum_bootstrap_descriptor_status_entry entry = {
                        .file_descriptor = descriptor,
                        .descriptor_flags = descriptor_flags,
                        .status_flags = status_flags,
                        .kind = kind,
                    };
                    continuum_bootstrap_descriptor_safepoint_report
                        .descriptors[exported_descriptor_count] = entry;
                    exported_descriptor_count += 1;
                }
            }
            if (!isatty(descriptor)) {
                continue;
            }
            if (pty_count == UINT32_MAX) {
                queue_state_known = 0;
                break;
            }
            pty_count += 1;
            int readable_bytes = 0;
            int pending_output_bytes = 0;
            if (ioctl(descriptor, FIONREAD, &readable_bytes) != 0
                || ioctl(descriptor, TIOCOUTQ, &pending_output_bytes) != 0
                || readable_bytes < 0 || pending_output_bytes < 0) {
                queue_state_known = 0;
                continue;
            }
            if (readable_bytes != 0 || pending_output_bytes != 0) {
                all_queues_zero = 0;
            }
        }
    }
    free(descriptors);

    continuum_bootstrap_descriptor_safepoint_report.safepoint_active = 0;
    continuum_bootstrap_descriptor_safepoint_report.magic =
        CONTINUUM_BOOTSTRAP_DESCRIPTOR_STATUS_MAGIC;
    continuum_bootstrap_descriptor_safepoint_report.version = 1;
    continuum_bootstrap_descriptor_safepoint_report.structure_size =
        sizeof(continuum_bootstrap_descriptor_safepoint_status);
    continuum_bootstrap_descriptor_safepoint_report.generation = generation;
    continuum_bootstrap_descriptor_safepoint_report.descriptor_count =
        exported_descriptor_count;
    continuum_bootstrap_descriptor_safepoint_report.overflow =
        descriptor_overflow ? 1 : 0;
    continuum_bootstrap_descriptor_safepoint_report.reserved[0] = 0;
    continuum_bootstrap_descriptor_safepoint_report.reserved[1] = 0;
    __sync_synchronize();
    continuum_bootstrap_descriptor_safepoint_report.safepoint_active = 1;

    continuum_bootstrap_pty_safepoint_report.safepoint_active = 0;
    continuum_bootstrap_pty_safepoint_report.magic =
        CONTINUUM_BOOTSTRAP_PTY_STATUS_MAGIC;
    continuum_bootstrap_pty_safepoint_report.version = 2;
    continuum_bootstrap_pty_safepoint_report.structure_size =
        sizeof(continuum_bootstrap_pty_safepoint_status);
    continuum_bootstrap_pty_safepoint_report.generation = generation;
    continuum_bootstrap_pty_safepoint_report.safepoint_thread_identifier =
        safepoint_thread_identifier;
    continuum_bootstrap_pty_safepoint_report.pty_descriptor_count = pty_count;
    continuum_bootstrap_pty_safepoint_report.queue_state_known =
        queue_state_known ? 1 : 0;
    continuum_bootstrap_pty_safepoint_report.all_queues_zero =
        queue_state_known && all_queues_zero ? 1 : 0;
    continuum_bootstrap_pty_safepoint_report.reserved = 0;
    continuum_bootstrap_pty_safepoint_report.safepoint_active = 1;
}

static void continuum_run_loop_safepoint(
    CFRunLoopObserverRef observer,
    CFRunLoopActivity activity,
    void *context
) {
    (void)observer;
    (void)context;
    if (continuum_rehydrate_stop_requested
        && activity == kCFRunLoopBeforeWaiting) {
        continuum_rehydrate_idle_boundaries += 1;
        if (continuum_rehydrate_idle_boundaries >= 4) {
            continuum_rehydrate_stop_requested = 0;
            (void)kill(getpid(), SIGSTOP);
        }
    }
    if (!continuum_safepoint_requested
        || !__sync_bool_compare_and_swap(
            &continuum_safepoint_claimed, 0, 1)) {
        return;
    }
    if (!continuum_safepoint_requested) {
        __sync_lock_release(&continuum_safepoint_claimed);
        return;
    }
    continuum_preservation_active = 1;
    continuum_safepoint_requested = 0;
    continuum_safepoint_release = 0;
    continuum_publish_pty_safepoint_status();
    continuum_bootstrap_safepoint_spin();
    continuum_bootstrap_pty_safepoint_report.safepoint_active = 0;
    continuum_bootstrap_descriptor_safepoint_report.safepoint_active = 0;
    continuum_preservation_active = 0;
    __sync_lock_release(&continuum_safepoint_claimed);
}

static void *continuum_cli_safepoint_coordinator(void *context) {
    (void)context;
    sigset_t requests;
    sigemptyset(&requests);
    sigaddset(&requests, SIGUSR2);
    for (;;) {
        int signal_number = 0;
        if (sigwait(&requests, &signal_number) != 0
            || signal_number != SIGUSR2) {
            return NULL;
        }
        continuum_safepoint_requested = 1;
        continuum_run_loop_safepoint(NULL, 0, NULL);
    }
}

static void continuum_bootstrap_enable_safepoints(void) {
    const char *requested = getenv("CONTINUUM_ENABLE_CHECKPOINT_SAFEPOINTS");
    if (requested == NULL || strcmp(requested, "1") != 0) {
        return;
    }

    const int is_cli_process = objc_getClass("NSApplication") == Nil;

    // A managed executable may inherit its launching worker thread's signal
    // mask across exec. CLI processes consume checkpoint requests on one
    // dedicated coordinator with sigwait; future threads inherit that blocked
    // request signal. GUI processes keep the main-run-loop handler path.
    (void)signal(SIGUSR1, continuum_release_safepoint);
    sigset_t control_signals;
    sigemptyset(&control_signals);
    sigaddset(&control_signals, SIGUSR1);
    (void)pthread_sigmask(SIG_UNBLOCK, &control_signals, NULL);
    if (is_cli_process) {
        sigemptyset(&control_signals);
        sigaddset(&control_signals, SIGUSR2);
        (void)pthread_sigmask(SIG_BLOCK, &control_signals, NULL);
    } else {
        (void)signal(SIGUSR2, continuum_request_safepoint);
        sigemptyset(&control_signals);
        sigaddset(&control_signals, SIGUSR2);
        (void)pthread_sigmask(SIG_UNBLOCK, &control_signals, NULL);
    }
    CFRunLoopObserverContext context = {
        .version = 0,
        .info = NULL,
        .retain = NULL,
        .release = NULL,
        .copyDescription = NULL,
    };
    continuum_safepoint_observer = CFRunLoopObserverCreate(
        kCFAllocatorDefault,
        kCFRunLoopBeforeWaiting | kCFRunLoopAfterWaiting,
        true,
        0,
        continuum_run_loop_safepoint,
        &context
    );
    if (continuum_safepoint_observer != NULL) {
        CFRunLoopAddObserver(
            CFRunLoopGetMain(),
            continuum_safepoint_observer,
            kCFRunLoopCommonModes
        );
    }
    if (is_cli_process) {
        pthread_t coordinator;
        if (pthread_create(
                &coordinator,
                NULL,
                continuum_cli_safepoint_coordinator,
                NULL) == 0) {
            (void)pthread_detach(coordinator);
        }
    }
}

__attribute__((visibility("default"), noinline, noreturn))
void continuum_bootstrap_copy_and_trap(
    void *destination,
    const void *source,
    size_t length
) {
    volatile uint8_t *destination_bytes = destination;
    const volatile uint8_t *source_bytes = source;
    for (size_t index = 0; index < length; index += 1) {
        destination_bytes[index] = source_bytes[index];
    }
    __builtin_debugtrap();
    __builtin_unreachable();
}

static int continuum_bootstrap_region(
    uintptr_t point,
    uint64_t *out_region_address,
    uint64_t *out_region_length
) {
    if (point == 0 || out_region_address == NULL
        || out_region_length == NULL) {
        return EINVAL;
    }

    mach_vm_address_t region_address = point;
    mach_vm_size_t region_length = 0;
    natural_t depth = 0;
    vm_region_submap_info_data_64_t info;
    kern_return_t result;
    for (;;) {
        memset(&info, 0, sizeof(info));
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        result = mach_vm_region_recurse(
            mach_task_self(),
            &region_address,
            &region_length,
            &depth,
            (vm_region_recurse_info_t)&info,
            &count
        );
        if (result != KERN_SUCCESS || !info.is_submap) {
            break;
        }
        depth += 1;
    }
    uint64_t region_end = region_address + region_length;
    if (result != KERN_SUCCESS || region_length == 0
        || region_end < region_address || point < region_address
        || point >= region_end
        || (info.protection & (VM_PROT_READ | VM_PROT_WRITE))
            != (VM_PROT_READ | VM_PROT_WRITE)) {
        return EINVAL;
    }
    *out_region_address = region_address;
    *out_region_length = region_length;
    return 0;
}

static int continuum_bootstrap_pthread_geometry(
    pthread_t thread,
    uint64_t *out_stack_base,
    uint64_t *out_stack_length,
    uint64_t *out_stack_region_address,
    uint64_t *out_stack_region_length,
    uint64_t *out_pthread_region_address,
    uint64_t *out_pthread_region_length
) {
    uintptr_t stack_top = (uintptr_t)pthread_get_stackaddr_np(thread);
    size_t stack_length = pthread_get_stacksize_np(thread);
    uintptr_t pthread_address = (uintptr_t)thread;
    if (stack_top == 0 || stack_length == 0 || stack_length > stack_top
        || pthread_address == 0 || out_stack_base == NULL
        || out_stack_length == NULL || out_stack_region_address == NULL
        || out_stack_region_length == NULL
        || out_pthread_region_address == NULL
        || out_pthread_region_length == NULL) {
        return EINVAL;
    }

    uint64_t stack_base = stack_top - stack_length;
    int result = continuum_bootstrap_region(
        stack_base,
        out_stack_region_address,
        out_stack_region_length
    );
    if (result != 0) {
        return result;
    }
    uint64_t stack_region_end =
        *out_stack_region_address + *out_stack_region_length;
    if (stack_region_end < *out_stack_region_address
        || stack_base < *out_stack_region_address
        || stack_top > stack_region_end) {
        return EINVAL;
    }
    result = continuum_bootstrap_region(
        pthread_address,
        out_pthread_region_address,
        out_pthread_region_length
    );
    if (result != 0) {
        return result;
    }
    *out_stack_base = stack_base;
    *out_stack_length = stack_length;
    return 0;
}

static void *continuum_bootstrap_placeholder_start(void *context) {
    return context;
}

int continuum_bootstrap_prepare_suspended_pthreads(
    continuum_bootstrap_pthread_report *report,
    size_t report_length,
    uint32_t requested_count
) {
    if (report == NULL || report_length < sizeof(*report)
        || requested_count > CONTINUUM_BOOTSTRAP_PTHREAD_LIMIT) {
        return EINVAL;
    }
    memset(report, 0, sizeof(*report));
    report->version = 3;
    report->requested_count = requested_count;

    pthread_t primary = pthread_self();
    report->primary_pthread_address = (uint64_t)(uintptr_t)primary;
    report->primary_mach_thread_port = pthread_mach_thread_np(primary);
    if (primary == NULL
        || !MACH_PORT_VALID(report->primary_mach_thread_port)) {
        report->error_code = EINVAL;
        return report->error_code;
    }
    int result = continuum_bootstrap_pthread_geometry(
        primary,
        &report->primary_stack_base_address,
        &report->primary_stack_length,
        &report->primary_stack_region_address,
        &report->primary_stack_region_length,
        &report->primary_pthread_region_address,
        &report->primary_pthread_region_length
    );
    if (result != 0) {
        report->error_code = result;
        return report->error_code;
    }

    for (uint32_t index = 0; index < requested_count; index += 1) {
        pthread_t thread = NULL;
        result = pthread_create_suspended_np(
            &thread,
            NULL,
            continuum_bootstrap_placeholder_start,
            NULL
        );
        if (result != 0 || thread == NULL) {
            report->error_code = result == 0 ? EINVAL : result;
            return report->error_code;
        }
        report->pthread_addresses[index] = (uint64_t)(uintptr_t)thread;
        mach_port_t mach_thread = pthread_mach_thread_np(thread);
        report->mach_thread_ports[index] = mach_thread;
        report->created_count += 1;
        if (!MACH_PORT_VALID(mach_thread)) {
            report->error_code = EINVAL;
            return report->error_code;
        }
        result = continuum_bootstrap_pthread_geometry(
            thread,
            &report->stack_base_addresses[index],
            &report->stack_lengths[index],
            &report->stack_region_addresses[index],
            &report->stack_region_lengths[index],
            &report->pthread_region_addresses[index],
            &report->pthread_region_lengths[index]
        );
        if (result != 0) {
            report->error_code = result;
            return report->error_code;
        }
    }
    return 0;
}

__attribute__((visibility("default"), noinline, noreturn))
void continuum_bootstrap_prepare_pthreads_and_trap(
    continuum_bootstrap_pthread_report *report,
    size_t report_length,
    uint32_t requested_count
) {
    (void)continuum_bootstrap_prepare_suspended_pthreads(
        report,
        report_length,
        requested_count
    );
    __builtin_debugtrap();
    __builtin_unreachable();
}

static int continuum_bootstrap_write_all(
    int descriptor,
    const char *bytes,
    size_t length
) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(descriptor, bytes + offset, length - offset);
        if (written <= 0) {
            return 0;
        }
        offset += (size_t)written;
    }
    return 1;
}

enum {
    CONTINUUM_BOOTSTRAP_MAX_PLAN_BYTES = 1024 * 1024,
    CONTINUUM_BOOTSTRAP_MAX_DESCRIPTORS = 1024
};

typedef struct continuum_bootstrap_descriptor_record {
    int target_descriptor;
    uint32_t open_flags;
    int64_t offset;
    uint64_t device;
    uint64_t inode;
    uint32_t mode;
    char path[PATH_MAX];
} continuum_bootstrap_descriptor_record;

typedef enum continuum_bootstrap_resource_kind {
    CONTINUUM_BOOTSTRAP_RESOURCE_PIPE = 1,
    CONTINUUM_BOOTSTRAP_RESOURCE_SOCKET = 2,
    CONTINUUM_BOOTSTRAP_RESOURCE_KQUEUE = 3
} continuum_bootstrap_resource_kind;

typedef struct continuum_bootstrap_resource_descriptor_record {
    continuum_bootstrap_resource_kind kind;
    int target_descriptor;
    int descriptor_flags;
    int status_flags;
    uint32_t kqueue_state;
    uint32_t registration_count;
} continuum_bootstrap_resource_descriptor_record;

typedef struct continuum_bootstrap_kqueue_registration_record {
    int queue_descriptor;
    uint64_t ident;
    int16_t filter;
    uint16_t flags;
    uint32_t fflags;
    int64_t data;
    uint64_t udata;
    uint32_t qos;
    int64_t saved_data;
    uint32_t saved_fflags;
    uint32_t status;
} continuum_bootstrap_kqueue_registration_record;

static int continuum_bootstrap_hex_value(char value) {
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

static int continuum_bootstrap_decode_path(
    const char *hex,
    char output[PATH_MAX]
) {
    size_t length = strlen(hex);
    if (length == 0 || (length % 2) != 0 || length / 2 >= PATH_MAX) {
        return 0;
    }
    for (size_t index = 0; index < length; index += 2) {
        int high = continuum_bootstrap_hex_value(hex[index]);
        int low = continuum_bootstrap_hex_value(hex[index + 1]);
        if (high < 0 || low < 0 || (high == 0 && low == 0)) {
            return 0;
        }
        output[index / 2] = (char)((high << 4) | low);
    }
    output[length / 2] = '\0';
    return output[0] == '/';
}

__attribute__((visibility("default")))
int continuum_bootstrap_apply_descriptor_plan(
    int descriptor,
    uint32_t *out_restored_count
) {
    if (out_restored_count == NULL) {
        close(descriptor);
        return -1;
    }
    *out_restored_count = 0;
    struct stat metadata;
    if (fstat(descriptor, &metadata) != 0
        || !S_ISREG(metadata.st_mode)
        || metadata.st_uid != geteuid()
        || metadata.st_nlink != 0
        || (metadata.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO))
            != (S_IRUSR | S_IWUSR)
        || metadata.st_size < 0
        || metadata.st_size > CONTINUUM_BOOTSTRAP_MAX_PLAN_BYTES) {
        close(descriptor);
        return -1;
    }

    size_t plan_length = (size_t)metadata.st_size;
    char *plan = calloc(plan_length + 1, 1);
    if (plan == NULL) {
        close(descriptor);
        return -1;
    }
    if (plan_length > 0
        && pread(descriptor, plan, plan_length, 0) != (ssize_t)plan_length) {
        free(plan);
        close(descriptor);
        return -1;
    }

    uint32_t count = 0;
    uint32_t resource_count = 0;
    uint32_t registration_count = 0;
    int plan_version = 0;
    continuum_bootstrap_descriptor_record *records = NULL;
    continuum_bootstrap_resource_descriptor_record *resource_records = NULL;
    continuum_bootstrap_kqueue_registration_record *registration_records = NULL;
    int maximum_target = 63;
    if (plan_length > 0) {
        char *context = NULL;
        char *line = strtok_r(plan, "\n", &context);
        char trailing = '\0';
        if (line != NULL
            && sscanf(
                line,
                "CONTINUUM_FD_PLAN_V4 %u %u %u %c",
                &count,
                &resource_count,
                &registration_count,
                &trailing
            ) == 3) {
            plan_version = 4;
        } else if (line != NULL
            && sscanf(
                line,
                "CONTINUUM_FD_PLAN_V3 %u %u %c",
                &count,
                &resource_count,
                &trailing
            ) == 2) {
            plan_version = 3;
        } else if (line != NULL
            && sscanf(
                line,
                "CONTINUUM_FD_PLAN_V2 %u %u %c",
                &count,
                &resource_count,
                &trailing
            ) == 2) {
            plan_version = 2;
        } else if (line != NULL
            && sscanf(
                line,
                "CONTINUUM_FD_PLAN_V1 %u %c",
                &count,
                &trailing
            ) == 1) {
            plan_version = 1;
            resource_count = 0;
        }
        if (plan_version == 0
            || count > CONTINUUM_BOOTSTRAP_MAX_DESCRIPTORS
            || resource_count > CONTINUUM_BOOTSTRAP_MAX_DESCRIPTORS
            || registration_count > CONTINUUM_BOOTSTRAP_MAX_DESCRIPTORS
            || count > CONTINUUM_BOOTSTRAP_MAX_DESCRIPTORS - resource_count) {
            free(plan);
            close(descriptor);
            return plan_version >= 2 ? -2 : -1;
        }
        records = calloc(count, sizeof(*records));
        resource_records = calloc(resource_count, sizeof(*resource_records));
        registration_records = calloc(
            registration_count, sizeof(*registration_records)
        );
        if ((count > 0 && records == NULL)
            || (resource_count > 0 && resource_records == NULL)
            || (registration_count > 0 && registration_records == NULL)) {
            free(records);
            free(resource_records);
            free(registration_records);
            free(plan);
            close(descriptor);
            return plan_version >= 2 ? -2 : -1;
        }
        for (uint32_t index = 0; index < count; index += 1) {
            line = strtok_r(NULL, "\n", &context);
            char path_hex[PATH_MAX * 2];
            long long offset = 0;
            unsigned long long device = 0;
            unsigned long long inode = 0;
            trailing = '\0';
            int parsed = line == NULL ? 0 : sscanf(
                line,
                "%d %u %lld %llu %llu %u %2046s %c",
                &records[index].target_descriptor,
                &records[index].open_flags,
                &offset,
                &device,
                &inode,
                &records[index].mode,
                path_hex,
                &trailing
            );
            if (parsed != 7 || records[index].target_descriptor < 0
                || offset < 0
                || !continuum_bootstrap_decode_path(
                    path_hex,
                    records[index].path
                )) {
                free(records);
                free(resource_records);
                free(registration_records);
                free(plan);
                close(descriptor);
                return plan_version >= 2 ? -2 : -1;
            }
            records[index].offset = offset;
            records[index].device = device;
            records[index].inode = inode;
            for (uint32_t prior = 0; prior < index; prior += 1) {
                if (records[prior].target_descriptor
                    == records[index].target_descriptor) {
                    free(records);
                    free(resource_records);
                    free(registration_records);
                    free(plan);
                    close(descriptor);
                    return plan_version >= 2 ? -2 : -1;
                }
            }
            if (records[index].target_descriptor > maximum_target) {
                maximum_target = records[index].target_descriptor;
            }
        }
        for (uint32_t index = 0; index < resource_count; index += 1) {
            line = strtok_r(NULL, "\n", &context);
            trailing = '\0';
            int kind = CONTINUUM_BOOTSTRAP_RESOURCE_PIPE;
            int parsed = 0;
            if (plan_version == 2) {
                parsed = line == NULL ? 0 : sscanf(
                    line,
                    "PIPE %d %d %d %c",
                    &resource_records[index].target_descriptor,
                    &resource_records[index].descriptor_flags,
                    &resource_records[index].status_flags,
                    &trailing
                );
            } else {
                if (plan_version == 4) {
                    parsed = line == NULL ? 0 : sscanf(
                        line,
                        "RESOURCE %d %d %d %d %u %u %c",
                        &kind,
                        &resource_records[index].target_descriptor,
                        &resource_records[index].descriptor_flags,
                        &resource_records[index].status_flags,
                        &resource_records[index].kqueue_state,
                        &resource_records[index].registration_count,
                        &trailing
                    );
                } else {
                    parsed = line == NULL ? 0 : sscanf(
                        line,
                        "RESOURCE %d %d %d %d %c",
                        &kind,
                        &resource_records[index].target_descriptor,
                        &resource_records[index].descriptor_flags,
                        &resource_records[index].status_flags,
                        &trailing
                    );
                }
            }
            resource_records[index].kind =
                (continuum_bootstrap_resource_kind)kind;
            int target = resource_records[index].target_descriptor;
            int descriptor_flags = resource_records[index].descriptor_flags;
            int status_flags = resource_records[index].status_flags;
            const int mutable_status_flags = O_NONBLOCK | O_ASYNC;
            int expected_fields = plan_version == 2 ? 3
                : kind == CONTINUUM_BOOTSTRAP_RESOURCE_KQUEUE ? 6 : 4;
            if (parsed != expected_fields || target < 0
                || (kind != CONTINUUM_BOOTSTRAP_RESOURCE_PIPE
                    && kind != CONTINUUM_BOOTSTRAP_RESOURCE_SOCKET
                    && (plan_version != 4
                        || kind != CONTINUUM_BOOTSTRAP_RESOURCE_KQUEUE))
                || (descriptor_flags
                    & ~(FD_CLOEXEC
                        | (kind == CONTINUUM_BOOTSTRAP_RESOURCE_KQUEUE
                            ? FD_CLOFORK : 0))) != 0
                || (status_flags & ~(O_ACCMODE | mutable_status_flags)) != 0
                || (kind == CONTINUUM_BOOTSTRAP_RESOURCE_KQUEUE
                    && (status_flags != O_RDWR
                        || resource_records[index].kqueue_state != 0x0010U))) {
                free(records);
                free(resource_records);
                free(registration_records);
                free(plan);
                close(descriptor);
                return -2;
            }
            for (uint32_t prior = 0; prior < count; prior += 1) {
                if (records[prior].target_descriptor == target) {
                    free(records);
                    free(resource_records);
                    free(registration_records);
                    free(plan);
                    close(descriptor);
                    return -2;
                }
            }
            for (uint32_t prior = 0; prior < index; prior += 1) {
                if (resource_records[prior].target_descriptor == target) {
                    free(records);
                    free(resource_records);
                    free(registration_records);
                    free(plan);
                    close(descriptor);
                    return -2;
                }
            }
            if (target > maximum_target) maximum_target = target;
        }
        uint32_t declared_registrations = 0;
        for (uint32_t index = 0; index < resource_count; index += 1) {
            if (resource_records[index].kind
                == CONTINUUM_BOOTSTRAP_RESOURCE_KQUEUE) {
                if (resource_records[index].registration_count
                    > registration_count - declared_registrations) {
                    free(records);
                    free(resource_records);
                    free(registration_records);
                    free(plan);
                    close(descriptor);
                    return -2;
                }
                declared_registrations +=
                    resource_records[index].registration_count;
            }
        }
        if (declared_registrations != registration_count) {
            free(records);
            free(resource_records);
            free(registration_records);
            free(plan);
            close(descriptor);
            return -2;
        }
        for (uint32_t index = 0; index < registration_count; index += 1) {
            line = strtok_r(NULL, "\n", &context);
            unsigned long long ident = 0;
            long long data = 0;
            unsigned long long udata = 0;
            long long saved_data = 0;
            trailing = '\0';
            int filter = 0;
            unsigned int flags = 0;
            int parsed = line == NULL ? 0 : sscanf(
                line,
                "KREG %d %llu %d %u %u %lld %llu %u %lld %u %u %c",
                &registration_records[index].queue_descriptor,
                &ident,
                &filter,
                &flags,
                &registration_records[index].fflags,
                &data,
                &udata,
                &registration_records[index].qos,
                &saved_data,
                &registration_records[index].saved_fflags,
                &registration_records[index].status,
                &trailing
            );
            registration_records[index].ident = ident;
            registration_records[index].filter = (int16_t)filter;
            registration_records[index].flags = (uint16_t)flags;
            registration_records[index].data = data;
            registration_records[index].udata = udata;
            registration_records[index].saved_data = saved_data;
            const uint16_t supported_flags = EV_ADD | EV_ENABLE | EV_DISABLE
                | EV_ONESHOT | EV_CLEAR | EV_DISPATCH | EV_UDATA_SPECIFIC;
            int found_queue = 0;
            int found_read_descriptor = filter != EVFILT_READ;
            for (uint32_t resource = 0; resource < resource_count; resource += 1) {
                const continuum_bootstrap_resource_descriptor_record *candidate =
                    &resource_records[resource];
                if (candidate->kind == CONTINUUM_BOOTSTRAP_RESOURCE_KQUEUE
                    && candidate->target_descriptor
                        == registration_records[index].queue_descriptor) {
                    found_queue = 1;
                }
                if ((candidate->kind == CONTINUUM_BOOTSTRAP_RESOURCE_PIPE
                        || candidate->kind
                            == CONTINUUM_BOOTSTRAP_RESOURCE_SOCKET)
                    && candidate->target_descriptor == (int)ident) {
                    found_read_descriptor = 1;
                }
            }
            int valid_filter = filter == EVFILT_USER || filter == EVFILT_READ;
            int valid_filter_state = filter == EVFILT_USER
                ? (registration_records[index].fflags & 0xff000000U) == 0
                    && (registration_records[index].saved_fflags
                        & 0xff000000U) == 0
                : registration_records[index].data == 0
                    && registration_records[index].saved_data >= 0
                    && (registration_records[index].fflags & ~NOTE_LOWAT) == 0
                    && (registration_records[index].saved_fflags & ~NOTE_LOWAT)
                        == 0;
            if (parsed != 11 || !found_queue || !found_read_descriptor
                || !valid_filter || !valid_filter_state
                || flags > UINT16_MAX || filter < INT16_MIN || filter > INT16_MAX
                || (flags & ~supported_flags) != 0
                || (flags & (EV_DELETE | EV_RECEIPT)) != 0
                || registration_records[index].qos != 0
                || registration_records[index].status != 0) {
                free(records);
                free(resource_records);
                free(registration_records);
                free(plan);
                close(descriptor);
                return -2;
            }
        }
        if (strtok_r(NULL, "\n", &context) != NULL) {
            free(records);
            free(resource_records);
            free(registration_records);
            free(plan);
            close(descriptor);
            return plan_version >= 2 ? -2 : -1;
        }
    }
    free(plan);

    if (maximum_target == INT_MAX) {
        free(records);
        free(resource_records);
        free(registration_records);
        close(descriptor);
        return plan_version >= 2 ? -2 : -1;
    }
    int report_descriptor = fcntl(
        descriptor,
        F_DUPFD_CLOEXEC,
        maximum_target + 1
    );
    close(descriptor);
    if (report_descriptor < 0) {
        free(records);
        free(resource_records);
        free(registration_records);
        return plan_version >= 2 ? -2 : -1;
    }

    for (uint32_t index = 0; index < count; index += 1) {
        int access_mode = records[index].open_flags & O_ACCMODE;
        if (access_mode != O_WRONLY && access_mode != O_RDWR) {
            free(records);
            free(resource_records);
            free(registration_records);
            close(report_descriptor);
            return plan_version >= 2 ? -2 : -1;
        }
        int safe_flags = access_mode | O_CLOEXEC | O_NOFOLLOW;
        if ((records[index].open_flags & O_APPEND) != 0) {
            safe_flags |= O_APPEND;
        }
        int opened = open(records[index].path, safe_flags);
        struct stat file_metadata;
        if (opened < 0 || fstat(opened, &file_metadata) != 0
            || !S_ISREG(file_metadata.st_mode)
            || (uint64_t)file_metadata.st_dev != records[index].device
            || (uint64_t)file_metadata.st_ino != records[index].inode
            || ((uint32_t)file_metadata.st_mode & (S_IFMT | 07777))
                != (records[index].mode & (S_IFMT | 07777))
            || lseek(opened, records[index].offset, SEEK_SET) < 0
            || (opened != records[index].target_descriptor
                && dup2(opened, records[index].target_descriptor) < 0)
            || fcntl(records[index].target_descriptor, F_SETFD, 0) != 0) {
            if (opened >= 0) {
                close(opened);
            }
            free(records);
            free(resource_records);
            free(registration_records);
            close(report_descriptor);
            return plan_version >= 2 ? -2 : -1;
        }
        if (opened != records[index].target_descriptor) {
            close(opened);
        }
        *out_restored_count += 1;
    }
    free(records);
    for (uint32_t index = 0; index < resource_count; index += 1) {
        const continuum_bootstrap_resource_descriptor_record *record =
            &resource_records[index];
        if (record->kind == CONTINUUM_BOOTSTRAP_RESOURCE_KQUEUE) {
            int created = kqueue();
            if (created < 0
                || (created != record->target_descriptor
                    && dup2(created, record->target_descriptor) < 0)) {
                if (created >= 0) close(created);
                free(resource_records);
                free(registration_records);
                close(report_descriptor);
                return -2;
            }
            if (created != record->target_descriptor) close(created);
        }
        struct stat descriptor_metadata;
        int current_status_flags = fcntl(record->target_descriptor, F_GETFL);
        int desired_access_mode = record->status_flags & O_ACCMODE;
        int socket_type = 0;
        socklen_t socket_type_length = sizeof(socket_type);
        int resource_matches = 1;
        if (record->kind == CONTINUUM_BOOTSTRAP_RESOURCE_PIPE) {
            resource_matches =
                fstat(record->target_descriptor, &descriptor_metadata) == 0
                && S_ISFIFO(descriptor_metadata.st_mode);
        } else if (record->kind == CONTINUUM_BOOTSTRAP_RESOURCE_SOCKET) {
            resource_matches = getsockopt(
                    record->target_descriptor,
                    SOL_SOCKET,
                    SO_TYPE,
                    &socket_type,
                    &socket_type_length
                ) == 0 && socket_type == SOCK_STREAM;
        }
        if (!resource_matches
            || current_status_flags < 0
            || (current_status_flags & O_ACCMODE) != desired_access_mode
            || (record->kind != CONTINUUM_BOOTSTRAP_RESOURCE_KQUEUE
                && fcntl(
                    record->target_descriptor,
                    F_SETFL,
                    record->status_flags & (O_NONBLOCK | O_ASYNC)
                ) != 0)
            || fcntl(
                record->target_descriptor,
                F_SETFD,
                record->descriptor_flags
            ) != 0
            || fcntl(record->target_descriptor, F_GETFL)
                != record->status_flags
            || fcntl(record->target_descriptor, F_GETFD)
                != record->descriptor_flags) {
            free(resource_records);
            free(registration_records);
            close(report_descriptor);
            return -2;
        }
        *out_restored_count += 1;
    }
    free(resource_records);
    for (uint32_t index = 0; index < registration_count; index += 1) {
        const continuum_bootstrap_kqueue_registration_record *record =
            &registration_records[index];
        struct kevent64_s change;
        memset(&change, 0, sizeof(change));
        change.ident = record->ident;
        change.filter = record->filter;
        change.flags = record->flags | EV_ADD;
        change.fflags = record->filter == EVFILT_USER
            ? NOTE_FFCOPY | record->saved_fflags
            : record->saved_fflags;
        change.data = record->saved_data;
        change.udata = record->udata;
        if (kevent64(
                record->queue_descriptor,
                &change,
                1,
                NULL,
                0,
                KEVENT_FLAG_NONE,
                NULL
            ) != 0) {
            free(registration_records);
            close(report_descriptor);
            return -2;
        }
    }
    free(registration_records);
    if (ftruncate(report_descriptor, 0) != 0
        || lseek(report_descriptor, 0, SEEK_SET) != 0) {
        close(report_descriptor);
        return plan_version >= 2 ? -2 : -1;
    }
    return report_descriptor;
}

static void continuum_bootstrap_report_copy_address(void) {
    const char *descriptor_text = getenv("CONTINUUM_BOOTSTRAP_DESCRIPTOR_FD");
    if (descriptor_text == NULL || descriptor_text[0] == '\0') {
        return;
    }
    errno = 0;
    char *end = NULL;
    long descriptor_value = strtol(descriptor_text, &end, 10);
    if (errno != 0 || end == descriptor_text || end == NULL || *end != '\0'
        || descriptor_value < 0 || descriptor_value > INT_MAX) {
        return;
    }
    uint32_t restored_descriptor_count = 0;
    int descriptor = continuum_bootstrap_apply_descriptor_plan(
        (int)descriptor_value,
        &restored_descriptor_count
    );
    if (descriptor == -2) {
        _exit(EXIT_FAILURE);
    }
    if (descriptor < 0) {
        return;
    }

    uintptr_t copy_address =
        (uintptr_t)(void *)&continuum_bootstrap_copy_and_trap;
#if __has_feature(ptrauth_calls)
    copy_address = (uintptr_t)ptrauth_strip(
        (void *)copy_address,
        ptrauth_key_function_pointer
    );
#endif
    uintptr_t pthread_prepare_address =
        (uintptr_t)(void *)&continuum_bootstrap_prepare_pthreads_and_trap;
#if __has_feature(ptrauth_calls)
    pthread_prepare_address = (uintptr_t)ptrauth_strip(
        (void *)pthread_prepare_address,
        ptrauth_key_function_pointer
    );
#endif
    Dl_info image;
    memset(&image, 0, sizeof(image));
    if (dladdr((void *)copy_address, &image) == 0
        || image.dli_fbase == NULL) {
        close(descriptor);
        return;
    }
    uintptr_t image_base = (uintptr_t)image.dli_fbase;
    if (copy_address <= image_base
        || pthread_prepare_address <= image_base) {
        close(descriptor);
        return;
    }

    char report[192];
    int length = snprintf(
        report,
        sizeof(report),
        "CONTINUUM_BOOTSTRAP_V4 %d 0x%llx 0x%llx 0x%llx %u\n",
        getpid(),
        (unsigned long long)image_base,
        (unsigned long long)copy_address,
        (unsigned long long)pthread_prepare_address,
        restored_descriptor_count
    );
    if (length > 0 && (size_t)length < sizeof(report)
        && continuum_bootstrap_write_all(
            descriptor,
            report,
            (size_t)length
        )) {
        (void)fsync(descriptor);
    }
    close(descriptor);
}

/// dyld runs this after mapping the executable and its launch-time libraries,
/// but before entering application main. Continuum uses that narrow window to
/// replace the disposable process image without executing app code.
__attribute__((constructor))
static void continuum_bootstrap_stop_before_main(void) {
    const char *broker_text = getenv("CONTINUUM_BROKER_FD");
    if (broker_text != NULL && broker_text[0] != '\0') {
        errno = 0;
        char *end = NULL;
        long value = strtol(broker_text, &end, 10);
        int is_child = getenv("CONTINUUM_BROKER_IS_CHILD") != NULL;
        if (errno != 0 || end == broker_text || end == NULL || *end != '\0'
            || value < 0 || value > INT_MAX
            || !continuum_broker_restore_environment()
            || continuum_bootstrap_run_broker((int)value, is_child) != 0) {
            _exit(EXIT_FAILURE);
        }
    }
    continuum_prepare_app_state_zone();
    continuum_bootstrap_enable_safepoints();
    const char *rehydrate = getenv("CONTINUUM_BOOTSTRAP_REHYDRATE_STOP");
    if (rehydrate != NULL && strcmp(rehydrate, "1") == 0) {
        continuum_rehydrate_stop_requested = 1;
        continuum_rehydrate_idle_boundaries = 0;
        unsetenv("CONTINUUM_BOOTSTRAP_REHYDRATE_STOP");
    }
    const char *requested = getenv("CONTINUUM_BOOTSTRAP_STOP");
    if (requested == NULL || strcmp(requested, "1") != 0) {
        return;
    }
    continuum_bootstrap_report_copy_address();
    unsetenv("CONTINUUM_BOOTSTRAP_DESCRIPTOR_FD");
    unsetenv("CONTINUUM_BOOTSTRAP_STOP");
    (void)kill(getpid(), SIGSTOP);
}
