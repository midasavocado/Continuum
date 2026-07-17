#include "ContinuumRuntime.h"

#include <CommonCrypto/CommonDigest.h>
#include <Security/Security.h>
#include <libproc.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/shared_region.h>
#include <mach-o/dyld_images.h>
#include <mach-o/dyld.h>
#include <mach/thread_info.h>
#include <mach/vm_region.h>
#include <mach/vm_statistics.h>
#include <mach-o/loader.h>
#include <mach_debug/ipc_info.h>
#include <malloc/malloc.h>
#if defined(__arm64__)
#include <mach/arm/thread_status.h>
#endif
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/proc.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <time.h>
#include <unistd.h>
#include <util.h>

extern char **environ;
extern int posix_spawnattr_disable_ptr_auth_a_keys_np(
    posix_spawnattr_t *attributes,
    uint32_t flags
);

#define CONTINUUM_WRITE_CHUNK_SIZE (64U * 1024U * 1024U)
#define CONTINUUM_FNV_OFFSET UINT64_C(1469598103934665603)
#define CONTINUUM_FNV_PRIME UINT64_C(1099511628211)
#define CONTINUUM_RESUME_ATTEMPT_LIMIT 3U
#define CONTINUUM_DESTROY_RESUME_ATTEMPT_LIMIT 32U
#define CONTINUUM_POSIX_SPAWN_DISABLE_ASLR 0x0100

/* Apple exposes this through proc_pidfdinfo but omits the ABI from the public
   SDK. Keep this byte-for-byte aligned with XNU's proc_info_private.h. */
#define CONTINUUM_PROC_PIDFDKQUEUE_EXTINFO 9
#define CONTINUUM_PROC_KQUEUE_WORKQ 0x0040U
#define CONTINUUM_PROC_KQUEUE_WORKLOOP 0x0080U
#define CONTINUUM_PROC_KQUEUE_SLEEP 0x0002U
#define CONTINUUM_PROC_KQUEUE_KEV64 0x0010U
#define CONTINUUM_KNOTE_ACTIVE 0x001U
#define CONTINUUM_KNOTE_QUEUED 0x002U
#define CONTINUUM_KNOTE_DISABLED 0x004U
#define CONTINUUM_KNOTE_PENDING_MASK 0xFFBU

typedef struct continuum_kevent_qos_private {
    uint64_t ident;
    int16_t filter;
    uint16_t flags;
    uint32_t qos;
    uint64_t udata;
    uint32_t fflags;
    uint32_t xflags;
    int64_t data;
    uint64_t ext[4];
} continuum_kevent_qos_private;

typedef struct continuum_kevent_extinfo_private {
    continuum_kevent_qos_private event;
    uint64_t saved_data;
    int32_t status;
    int32_t saved_fflags;
    uint64_t reserved[2];
} continuum_kevent_extinfo_private;

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

struct continuum_brokered_pair {
    int channel;
    pid_t root_process_id;
    pid_t child_process_id;
    uint64_t root_start_seconds;
    uint64_t root_start_microseconds;
    uint64_t child_start_seconds;
    uint64_t child_start_microseconds;
    uint8_t state;
    uint8_t root_released;
    uint8_t child_released;
};

enum {
    CONTINUUM_BROKER_PAIR_PREPARED = 1,
    CONTINUUM_BROKER_PAIR_ENTRY_STOPPED = 2,
    CONTINUUM_BROKER_PAIR_FAILED = 3,
};

enum {
    CONTINUUM_REPLACEMENT_STOP_DIRECT_PTRACE = 0,
    CONTINUUM_REPLACEMENT_STOP_BROKER_SIGNAL = 1,
};

static continuum_status continuum_advance_bootstrap_stopped_process_to_entry(
    int32_t process_id,
    uint32_t timeout_milliseconds,
    int already_traced,
    int broker_channel
);
static continuum_status continuum_wait_for_child_signal_stop(
    int32_t process_id,
    uint64_t deadline,
    int expected_signal
);
static void continuum_broker_kill_and_reap_traced_child(
    pid_t process_id,
    uint64_t deadline
);

static continuum_status continuum_spawn_process_suspended_internal(
    const char *executable_path,
    const char *const arguments[],
    const char *const environment[],
    const char *working_directory,
    int32_t inherited_descriptor,
    const continuum_spawn_descriptor_remap *descriptor_remaps,
    size_t descriptor_remap_count,
    const continuum_spawn_process_topology *topology,
    int disable_aslr,
    int start_suspended,
    int32_t *out_process_id
) {
    if (executable_path == NULL || executable_path[0] == '\0'
        || arguments == NULL || arguments[0] == NULL
        || working_directory == NULL || working_directory[0] == '\0'
        || out_process_id == NULL
        || descriptor_remap_count > CONTINUUM_SPAWN_DESCRIPTOR_REMAP_LIMIT
        || (descriptor_remap_count > 0 && descriptor_remaps == NULL)) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    *out_process_id = 0;

    if (topology != NULL) {
        if (topology->structure_size != sizeof(*topology)
            || topology->create_session > 1
            || topology->process_group_policy
                < CONTINUUM_SPAWN_PROCESS_GROUP_INHERIT
            || topology->process_group_policy
                > CONTINUUM_SPAWN_PROCESS_GROUP_JOIN
            || topology->controlling_terminal_descriptor < -1) {
            return CONTINUUM_STATUS_INVALID_ARGUMENT;
        }
        if (topology->controlling_terminal_descriptor >= 0) {
            // XNU applies spawn file actions before POSIX_SPAWN_SETSID. A PTY
            // opened or duplicated there is detached again by setsid and
            // cannot become the replacement's controlling terminal.
            return CONTINUUM_STATUS_UNSUPPORTED_DESCRIPTOR;
        }
        if ((topology->process_group_policy
                == CONTINUUM_SPAWN_PROCESS_GROUP_INHERIT
                && topology->process_group_id != 0)
            || (topology->process_group_policy
                    == CONTINUUM_SPAWN_PROCESS_GROUP_CREATE
                && topology->process_group_id != 0)
            || (topology->process_group_policy
                    == CONTINUUM_SPAWN_PROCESS_GROUP_JOIN
                && topology->process_group_id <= 0)
            || (topology->create_session
                && topology->process_group_policy
                    != CONTINUUM_SPAWN_PROCESS_GROUP_CREATE)) {
            return CONTINUUM_STATUS_INVALID_ARGUMENT;
        }
    }

    for (size_t index = 0; index < descriptor_remap_count; index += 1) {
        const continuum_spawn_descriptor_remap remap = descriptor_remaps[index];
        if (remap.source_descriptor < 0 || remap.target_descriptor < 0
            || fcntl(remap.source_descriptor, F_GETFD) < 0
            || remap.target_descriptor == inherited_descriptor) {
            return CONTINUUM_STATUS_INVALID_ARGUMENT;
        }
        for (size_t other = 0; other < descriptor_remap_count; other += 1) {
            if (other != index
                && descriptor_remaps[other].target_descriptor
                    == remap.target_descriptor) {
                return CONTINUUM_STATUS_INVALID_ARGUMENT;
            }
            if (other != index
                && remap.target_descriptor
                    == descriptor_remaps[other].source_descriptor) {
                // posix_spawn file actions are ordered. Reject an overlap that
                // could overwrite a later source before it is duplicated.
                return CONTINUUM_STATUS_INVALID_ARGUMENT;
            }
        }
    }

    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    int result = posix_spawn_file_actions_init(&actions);
    if (result != 0) {
        return CONTINUUM_STATUS_SPAWN_FAILED;
    }
    result = posix_spawn_file_actions_addchdir_np(&actions, working_directory);
    if (result == 0 && inherited_descriptor >= 0) {
        result = posix_spawn_file_actions_addinherit_np(
            &actions,
            inherited_descriptor
        );
    }
    for (size_t index = 0;
         result == 0 && index < descriptor_remap_count;
         index += 1) {
        const continuum_spawn_descriptor_remap remap = descriptor_remaps[index];
        if (remap.source_descriptor == remap.target_descriptor) {
            result = posix_spawn_file_actions_addinherit_np(
                &actions,
                remap.source_descriptor
            );
        } else {
            result = posix_spawn_file_actions_adddup2(
                &actions,
                remap.source_descriptor,
                remap.target_descriptor
            );
        }
    }
    if (result != 0) {
        posix_spawn_file_actions_destroy(&actions);
        return CONTINUUM_STATUS_SPAWN_FAILED;
    }
    result = posix_spawnattr_init(&attributes);
    if (result != 0) {
        posix_spawn_file_actions_destroy(&actions);
        return CONTINUUM_STATUS_SPAWN_FAILED;
    }

    short flags = POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGMASK;
    if (start_suspended) {
        flags |= POSIX_SPAWN_START_SUSPENDED;
    }
    if (disable_aslr) {
        flags |= CONTINUUM_POSIX_SPAWN_DISABLE_ASLR;
    }
    if (topology != NULL && topology->create_session) {
        flags |= POSIX_SPAWN_SETSID;
    } else if (topology != NULL
        && topology->process_group_policy
            != CONTINUUM_SPAWN_PROCESS_GROUP_INHERIT) {
        flags |= POSIX_SPAWN_SETPGROUP;
    }
    result = posix_spawnattr_setflags(&attributes, flags);
    if (result == 0) {
        sigset_t empty_signal_mask;
        sigemptyset(&empty_signal_mask);
        result = posix_spawnattr_setsigmask(
            &attributes,
            &empty_signal_mask
        );
    }
    if (result == 0) {
        result = posix_spawnattr_disable_ptr_auth_a_keys_np(&attributes, 0);
    }
    if (result == 0 && topology != NULL && !topology->create_session
        && topology->process_group_policy
            != CONTINUUM_SPAWN_PROCESS_GROUP_INHERIT) {
        pid_t process_group = topology->process_group_policy
                == CONTINUUM_SPAWN_PROCESS_GROUP_CREATE
            ? 0
            : (pid_t)topology->process_group_id;
        result = posix_spawnattr_setpgroup(&attributes, process_group);
    }
    pid_t process_id = 0;
    if (result == 0) {
        result = posix_spawn(
            &process_id,
            executable_path,
            &actions,
            &attributes,
            (char *const *)arguments,
            environment == NULL ? environ : (char *const *)environment
        );
    }

    posix_spawnattr_destroy(&attributes);
    posix_spawn_file_actions_destroy(&actions);
    if (result != 0 || process_id <= 0) {
        return CONTINUUM_STATUS_SPAWN_FAILED;
    }
    *out_process_id = (int32_t)process_id;
    return CONTINUUM_STATUS_OK;
}

static void continuum_broker_kill_and_reap_traced_child(
    pid_t process_id,
    uint64_t deadline
) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    // Leave ptrace ownership while delivering SIGKILL, then reap the ordinary
    // BSD child. A traced SIGKILL may otherwise surface as another wait stop
    // before exit and remain observable as a zombie until this controller dies.
    if (ptrace(PT_DETACH, process_id, (caddr_t)1, SIGKILL) != 0) {
        (void)ptrace(PT_KILL, process_id, (caddr_t)1, 0);
        (void)kill(process_id, SIGKILL);
    }
    for (;;) {
        int wait_status = 0;
        pid_t waited = waitpid(
            process_id, &wait_status, WUNTRACED | WNOHANG);
        if (waited == process_id) {
            if (WIFEXITED(wait_status) || WIFSIGNALED(wait_status)) break;
            if (WIFSTOPPED(wait_status)) {
                if (ptrace(
                        PT_DETACH,
                        process_id,
                        (caddr_t)1,
                        SIGKILL
                    ) != 0) {
                    (void)ptrace(PT_KILL, process_id, (caddr_t)1, 0);
                    (void)kill(process_id, SIGKILL);
                }
            }
        } else if (waited < 0 && errno != EINTR) {
            break;
        }
        if (clock_gettime_nsec_np(CLOCK_MONOTONIC) >= deadline) break;
        usleep(1000);
    }
#pragma clang diagnostic pop
}

continuum_status continuum_spawn_process_suspended(
    const char *executable_path,
    const char *const arguments[],
    const char *const environment[],
    const char *working_directory,
    int32_t *out_process_id
) {
    return continuum_spawn_process_suspended_internal(
        executable_path,
        arguments,
        environment,
        working_directory,
        -1,
        NULL,
        0,
        NULL,
        1,
        1,
        out_process_id
    );
}

continuum_status continuum_spawn_process_suspended_with_inherited_descriptor(
    const char *executable_path,
    const char *const arguments[],
    const char *const environment[],
    const char *working_directory,
    int32_t inherited_descriptor,
    int32_t *out_process_id
) {
    return continuum_spawn_process_suspended_with_inherited_descriptor_and_remaps(
        executable_path,
        arguments,
        environment,
        working_directory,
        inherited_descriptor,
        NULL,
        0,
        out_process_id
    );
}

continuum_status
continuum_spawn_process_suspended_with_inherited_descriptor_and_remaps(
    const char *executable_path,
    const char *const arguments[],
    const char *const environment[],
    const char *working_directory,
    int32_t inherited_descriptor,
    const continuum_spawn_descriptor_remap descriptor_remaps[],
    size_t descriptor_remap_count,
    int32_t *out_process_id
) {
    if (inherited_descriptor < 0
        || fcntl(inherited_descriptor, F_GETFD) < 0) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    return continuum_spawn_process_suspended_internal(
        executable_path,
        arguments,
        environment,
        working_directory,
        inherited_descriptor,
        descriptor_remaps,
        descriptor_remap_count,
        NULL,
        1,
        1,
        out_process_id
    );
}

continuum_status
continuum_spawn_process_suspended_with_inherited_descriptor_system_aslr(
    const char *executable_path,
    const char *const arguments[],
    const char *const environment[],
    const char *working_directory,
    int32_t inherited_descriptor,
    int32_t *out_process_id
) {
    return continuum_spawn_process_suspended_with_inherited_descriptor_and_remaps_system_aslr(
        executable_path,
        arguments,
        environment,
        working_directory,
        inherited_descriptor,
        NULL,
        0,
        out_process_id
    );
}

continuum_status
continuum_spawn_process_suspended_with_inherited_descriptor_and_remaps_system_aslr(
    const char *executable_path,
    const char *const arguments[],
    const char *const environment[],
    const char *working_directory,
    int32_t inherited_descriptor,
    const continuum_spawn_descriptor_remap descriptor_remaps[],
    size_t descriptor_remap_count,
    int32_t *out_process_id
) {
    if (inherited_descriptor < 0
        || fcntl(inherited_descriptor, F_GETFD) < 0) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    return continuum_spawn_process_suspended_internal(
        executable_path,
        arguments,
        environment,
        working_directory,
        inherited_descriptor,
        descriptor_remaps,
        descriptor_remap_count,
        NULL,
        0,
        1,
        out_process_id
    );
}

continuum_status continuum_spawn_process(
    const char *executable_path,
    const char *const arguments[],
    const char *const environment[],
    const char *working_directory,
    int disable_aslr,
    int32_t *out_process_id
) {
    return continuum_spawn_process_suspended_internal(
        executable_path,
        arguments,
        environment,
        working_directory,
        -1,
        NULL,
        0,
        NULL,
        disable_aslr != 0,
        0,
        out_process_id
    );
}

continuum_status continuum_spawn_process_with_remaps(
    const char *executable_path,
    const char *const arguments[],
    const char *const environment[],
    const char *working_directory,
    const continuum_spawn_descriptor_remap descriptor_remaps[],
    size_t descriptor_remap_count,
    int disable_aslr,
    int32_t *out_process_id
) {
    return continuum_spawn_process_suspended_internal(
        executable_path,
        arguments,
        environment,
        working_directory,
        -1,
        descriptor_remaps,
        descriptor_remap_count,
        NULL,
        disable_aslr != 0,
        0,
        out_process_id
    );
}

continuum_status
continuum_spawn_process_suspended_with_inherited_descriptor_remaps_and_topology(
    const char *executable_path,
    const char *const arguments[],
    const char *const environment[],
    const char *working_directory,
    int32_t inherited_descriptor,
    const continuum_spawn_descriptor_remap descriptor_remaps[],
    size_t descriptor_remap_count,
    const continuum_spawn_process_topology *topology,
    int32_t *out_process_id
) {
    if (inherited_descriptor < 0
        || fcntl(inherited_descriptor, F_GETFD) < 0 || topology == NULL) {
        if (out_process_id != NULL) {
            *out_process_id = 0;
        }
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    return continuum_spawn_process_suspended_internal(
        executable_path,
        arguments,
        environment,
        working_directory,
        inherited_descriptor,
        descriptor_remaps,
        descriptor_remap_count,
        topology,
        1,
        1,
        out_process_id
    );
}

continuum_status
continuum_spawn_process_suspended_with_inherited_descriptor_remaps_and_topology_system_aslr(
    const char *executable_path,
    const char *const arguments[],
    const char *const environment[],
    const char *working_directory,
    int32_t inherited_descriptor,
    const continuum_spawn_descriptor_remap descriptor_remaps[],
    size_t descriptor_remap_count,
    const continuum_spawn_process_topology *topology,
    int32_t *out_process_id
) {
    if (inherited_descriptor < 0
        || fcntl(inherited_descriptor, F_GETFD) < 0 || topology == NULL) {
        if (out_process_id != NULL) {
            *out_process_id = 0;
        }
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    return continuum_spawn_process_suspended_internal(
        executable_path,
        arguments,
        environment,
        working_directory,
        inherited_descriptor,
        descriptor_remaps,
        descriptor_remap_count,
        topology,
        0,
        1,
        out_process_id
    );
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

static int continuum_broker_send_fds(
    int descriptor,
    const continuum_spawn_descriptor_remap *remaps,
    size_t count
) {
    if (count == 0) return 1;
    int sources[CONTINUUM_BROKER_MAX_REMAPS];
    for (size_t index = 0; index < count; index += 1) {
        sources[index] = remaps[index].source_descriptor;
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
    memcpy(CMSG_DATA(entry), sources, sizeof(int) * count);
    ssize_t sent;
    do {
        sent = sendmsg(descriptor, &message, 0);
    } while (sent < 0 && errno == EINTR);
    return sent == 1;
}

static size_t continuum_broker_string_count(
    const char *const values[],
    size_t limit
) {
    if (values == NULL) return 0;
    size_t count = 0;
    while (count < limit && values[count] != NULL) count += 1;
    return count;
}

static int continuum_broker_validate_spec(
    const continuum_brokered_process_spec *spec,
    int is_root
) {
    if (spec == NULL || spec->structure_size != sizeof(*spec)
        || spec->captured_process_id <= 0
        || spec->captured_process_group_id <= 0
        || spec->foreground_process_group_id <= 0
        || spec->executable_path == NULL
        || spec->executable_path[0] == '\0' || spec->arguments == NULL
        || spec->arguments[0] == NULL || spec->working_directory == NULL
        || spec->working_directory[0] == '\0'
        || spec->descriptor_remap_count > CONTINUUM_BROKER_MAX_REMAPS
        || (spec->descriptor_remap_count > 0 && spec->descriptor_remaps == NULL)
        || spec->disable_aslr > 1
        || spec->topology.structure_size != sizeof(spec->topology)
        || spec->topology.create_session > 1
        || spec->topology.process_group_policy < CONTINUUM_SPAWN_PROCESS_GROUP_INHERIT
        || spec->topology.process_group_policy > CONTINUUM_SPAWN_PROCESS_GROUP_JOIN
        || spec->topology.controlling_terminal_descriptor < -1
        || (!is_root && spec->topology.create_session)) return 0;
    if (is_root
        && spec->topology.process_group_policy
            == CONTINUUM_SPAWN_PROCESS_GROUP_JOIN) return 0;
    if (spec->topology.create_session
        && spec->topology.process_group_policy != CONTINUUM_SPAWN_PROCESS_GROUP_CREATE) return 0;
    if (spec->topology.controlling_terminal_descriptor >= 0
        && (!spec->topology.create_session || !is_root)) return 0;
    size_t argc = continuum_broker_string_count(spec->arguments,
        CONTINUUM_BROKER_MAX_ARGUMENTS + 1);
    const char *const *effective_environment = spec->environment == NULL
        ? (const char *const *)environ : spec->environment;
    size_t envc = continuum_broker_string_count(effective_environment,
        CONTINUUM_BROKER_MAX_ENVIRONMENT + 1);
    if (argc == 0 || argc > CONTINUUM_BROKER_MAX_ARGUMENTS
        || envc > CONTINUUM_BROKER_MAX_ENVIRONMENT) return 0;
    for (size_t index = 0; index < envc; index += 1) {
        if (strncmp(effective_environment[index], "CONTINUUM_BROKER_", 17) == 0) {
            return 0;
        }
    }
    int found_tty = spec->topology.controlling_terminal_descriptor < 0;
    for (size_t index = 0; index < spec->descriptor_remap_count; index += 1) {
        continuum_spawn_descriptor_remap remap = spec->descriptor_remaps[index];
        if (remap.source_descriptor < 0 || remap.target_descriptor < 0
            || remap.target_descriptor >= getdtablesize()
            || fcntl(remap.source_descriptor, F_GETFD) < 0) return 0;
        if (remap.target_descriptor == spec->topology.controlling_terminal_descriptor) found_tty = 1;
        for (size_t other = index + 1; other < spec->descriptor_remap_count; other += 1) {
            if (remap.target_descriptor == spec->descriptor_remaps[other].target_descriptor) return 0;
        }
    }
    return found_tty;
}

static char **continuum_broker_launch_environment(
    const char *const original[],
    const char *bootstrap,
    int channel
) {
    const char *const *source = original == NULL
        ? (const char *const *)environ : original;
    size_t count = continuum_broker_string_count(source,
        CONTINUUM_BROKER_MAX_ENVIRONMENT + 1);
    if (count > CONTINUUM_BROKER_MAX_ENVIRONMENT) return NULL;
    const char *old_dyld = NULL;
    for (size_t index = 0; index < count; index += 1) {
        if (strncmp(source[index], "DYLD_INSERT_LIBRARIES=", 22) == 0) old_dyld = source[index] + 22;
    }
    char **result = calloc(count + 5, sizeof(char *));
    if (result == NULL) return NULL;
    size_t output = 0;
    for (size_t index = 0; index < count; index += 1) {
        if (strncmp(source[index], "DYLD_INSERT_LIBRARIES=", 22) != 0
            && strncmp(source[index], "CONTINUUM_BROKER_", 17) != 0) {
            result[output++] = strdup(source[index]);
        }
    }
    if (asprintf(&result[output++], "DYLD_INSERT_LIBRARIES=%s%s%s", bootstrap,
            old_dyld == NULL || old_dyld[0] == '\0' ? "" : ":",
            old_dyld == NULL ? "" : old_dyld) < 0
        || asprintf(&result[output++], "CONTINUUM_BROKER_FD=%d", channel) < 0
        || asprintf(&result[output++], "CONTINUUM_BROKER_ORIGINAL_DYLD_PRESENT=%d",
            old_dyld == NULL ? 0 : 1) < 0
        || asprintf(&result[output++], "CONTINUUM_BROKER_ORIGINAL_DYLD=%s",
            old_dyld == NULL ? "" : old_dyld) < 0) {
        for (size_t index = 0; index < output; index += 1) free(result[index]);
        free(result); return NULL;
    }
    return result;
}

static void continuum_broker_free_environment(char **environment) {
    if (environment == NULL) return;
    for (size_t index = 0; environment[index] != NULL; index += 1) free(environment[index]);
    free(environment);
}

static int continuum_broker_send_setup(
    int channel,
    const continuum_brokered_process_spec *spec,
    int32_t mapped_process_group
) {
    continuum_broker_setup setup = {
        .create_session = spec->topology.create_session,
        .process_group_policy = spec->topology.process_group_policy,
        .process_group_id = mapped_process_group,
        .captured_process_id = spec->captured_process_id,
        .captured_process_group_id = spec->captured_process_group_id,
        .foreground_process_group_id = spec->foreground_process_group_id,
        .controlling_terminal_descriptor = spec->topology.controlling_terminal_descriptor,
        .remap_count = (uint32_t)spec->descriptor_remap_count,
    };
    continuum_broker_header header = {
        .magic = CONTINUUM_BROKER_MAGIC, .version = CONTINUUM_BROKER_VERSION,
        .type = CONTINUUM_BROKER_SETUP,
        .payload_length = sizeof(setup)
            + (uint32_t)(sizeof(int32_t) * spec->descriptor_remap_count),
    };
    if (!continuum_broker_write_all(channel, &header, sizeof(header))
        || !continuum_broker_write_all(channel, &setup, sizeof(setup))) return 0;
    int32_t targets[CONTINUUM_BROKER_MAX_REMAPS];
    for (size_t index = 0; index < spec->descriptor_remap_count; index += 1) {
        targets[index] = spec->descriptor_remaps[index].target_descriptor;
    }
    return continuum_broker_write_all(channel, targets,
        sizeof(int32_t) * spec->descriptor_remap_count)
        && continuum_broker_send_fds(channel, spec->descriptor_remaps,
            spec->descriptor_remap_count);
}

static int continuum_broker_receive_reply(
    int channel,
    uint16_t expected,
    continuum_broker_reply *reply
) {
    continuum_broker_header header;
    return continuum_broker_read_all(channel, &header, sizeof(header))
        && header.magic == CONTINUUM_BROKER_MAGIC
        && header.version == CONTINUUM_BROKER_VERSION
        && header.type == expected && header.payload_length == sizeof(*reply)
        && continuum_broker_read_all(channel, reply, sizeof(*reply))
        && reply->error_code == 0;
}

static int continuum_broker_append_string(
    uint8_t **cursor,
    const uint8_t *limit,
    const char *value
) {
    size_t length = strlen(value) + 1;
    if (length > UINT32_MAX || (size_t)(limit - *cursor) < sizeof(uint32_t) + length) return 0;
    uint32_t wire_length = (uint32_t)length;
    memcpy(*cursor, &wire_length, sizeof(wire_length)); *cursor += sizeof(wire_length);
    memcpy(*cursor, value, length); *cursor += length;
    return 1;
}

static int continuum_broker_send_child(
    int channel,
    const char *bootstrap,
    const continuum_brokered_process_spec *child
) {
    const char *const *environment = child->environment == NULL
        ? (const char *const *)environ : child->environment;
    size_t argc = continuum_broker_string_count(child->arguments, CONTINUUM_BROKER_MAX_ARGUMENTS);
    size_t envc = continuum_broker_string_count(environment, CONTINUUM_BROKER_MAX_ENVIRONMENT);
    size_t string_bytes = strlen(child->executable_path) + 1
        + strlen(child->working_directory) + 1 + strlen(bootstrap) + 1;
    for (size_t index = 0; index < argc; index += 1) string_bytes += sizeof(uint32_t) + strlen(child->arguments[index]) + 1;
    for (size_t index = 0; index < envc; index += 1) string_bytes += sizeof(uint32_t) + strlen(environment[index]) + 1;
    size_t payload_length = sizeof(continuum_broker_child) + string_bytes
        + sizeof(int32_t) * child->descriptor_remap_count;
    if (string_bytes > CONTINUUM_BROKER_MAX_STRING_BYTES || payload_length > UINT32_MAX) return 0;
    uint8_t *payload = calloc(1, payload_length);
    if (payload == NULL) return 0;
    continuum_broker_child wire = {
        .argument_count = (uint32_t)argc, .environment_count = (uint32_t)envc,
        .executable_length = (uint32_t)(strlen(child->executable_path) + 1),
        .directory_length = (uint32_t)(strlen(child->working_directory) + 1),
        .bootstrap_length = (uint32_t)(strlen(bootstrap) + 1),
        .string_bytes = (uint32_t)string_bytes,
        .remap_count = (uint32_t)child->descriptor_remap_count,
        .process_group_policy = child->topology.process_group_policy,
        .process_group_id = child->topology.process_group_id,
        .captured_process_id = child->captured_process_id,
        .captured_process_group_id = child->captured_process_group_id,
        .disable_aslr = child->disable_aslr,
    };
    memcpy(payload, &wire, sizeof(wire));
    uint8_t *cursor = payload + sizeof(wire);
    const uint8_t *limit = payload + payload_length;
    int valid = 1;
    for (size_t index = 0; valid && index < argc; index += 1) valid = continuum_broker_append_string(&cursor, limit, child->arguments[index]);
    for (size_t index = 0; valid && index < envc; index += 1) valid = continuum_broker_append_string(&cursor, limit, environment[index]);
    if (valid) { memcpy(cursor, child->executable_path, wire.executable_length); cursor += wire.executable_length; }
    if (valid) { memcpy(cursor, child->working_directory, wire.directory_length); cursor += wire.directory_length; }
    if (valid) { memcpy(cursor, bootstrap, wire.bootstrap_length); cursor += wire.bootstrap_length; }
    for (size_t index = 0; valid && index < child->descriptor_remap_count; index += 1) {
        int32_t target = child->descriptor_remaps[index].target_descriptor;
        memcpy(cursor, &target, sizeof(target)); cursor += sizeof(target);
    }
    continuum_broker_header header = {
        .magic = CONTINUUM_BROKER_MAGIC, .version = CONTINUUM_BROKER_VERSION,
        .type = CONTINUUM_BROKER_SPAWN_CHILD, .payload_length = (uint32_t)payload_length,
    };
    valid = valid && cursor == limit
        && continuum_broker_write_all(channel, &header, sizeof(header))
        && continuum_broker_write_all(channel, payload, payload_length)
        && continuum_broker_send_fds(channel, child->descriptor_remaps,
            child->descriptor_remap_count);
    free(payload);
    return valid;
}

continuum_status continuum_brokered_pair_prepare(
    const char *bootstrap_library_path,
    const continuum_brokered_process_spec *root,
    const continuum_brokered_process_spec *child,
    continuum_brokered_pair **out_pair
) {
    if (out_pair == NULL) return CONTINUUM_STATUS_INVALID_ARGUMENT;
    *out_pair = NULL;
    struct stat bootstrap_stat;
    if (bootstrap_library_path == NULL || bootstrap_library_path[0] == '\0'
        || stat(bootstrap_library_path, &bootstrap_stat) != 0
        || !S_ISREG(bootstrap_stat.st_mode)
        || !continuum_broker_validate_spec(root, 1)
        || !continuum_broker_validate_spec(child, 0)
        || (child->topology.process_group_policy == CONTINUUM_SPAWN_PROCESS_GROUP_JOIN
            && child->topology.process_group_id != root->captured_process_id)) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    int channels[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, channels) != 0) return CONTINUUM_STATUS_SPAWN_FAILED;
    int highest_target = channels[0];
    for (size_t index = 0; index < root->descriptor_remap_count; index += 1) {
        if (root->descriptor_remaps[index].target_descriptor > highest_target) {
            highest_target = root->descriptor_remaps[index].target_descriptor;
        }
    }
    int safe_child_channel = fcntl(channels[1], F_DUPFD_CLOEXEC,
        highest_target + 1);
    if (safe_child_channel < 0) {
        close(channels[0]); close(channels[1]);
        return CONTINUUM_STATUS_SPAWN_FAILED;
    }
    close(channels[1]);
    channels[1] = safe_child_channel;
    char **environment = continuum_broker_launch_environment(root->environment,
        bootstrap_library_path, channels[1]);
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    int actions_initialized = 0;
    int attributes_initialized = 0;
    int result = environment == NULL ? ENOMEM : posix_spawn_file_actions_init(&actions);
    actions_initialized = result == 0;
    if (result == 0) result = posix_spawn_file_actions_addchdir_np(&actions, root->working_directory);
    if (result == 0) result = posix_spawn_file_actions_addinherit_np(&actions, channels[1]);
    if (result == 0) {
        result = posix_spawnattr_init(&attributes);
        attributes_initialized = result == 0;
    }
    if (result == 0) {
        short flags = POSIX_SPAWN_CLOEXEC_DEFAULT;
        if (root->disable_aslr) flags |= CONTINUUM_POSIX_SPAWN_DISABLE_ASLR;
        result = posix_spawnattr_setflags(&attributes, flags);
    }
    pid_t root_pid = 0;
    if (result == 0) result = posix_spawn(&root_pid, root->executable_path,
        &actions, &attributes, (char *const *)root->arguments, environment);
    if (environment != NULL) continuum_broker_free_environment(environment);
    if (attributes_initialized) posix_spawnattr_destroy(&attributes);
    if (actions_initialized) posix_spawn_file_actions_destroy(&actions);
    close(channels[1]);
    if (result != 0 || root_pid <= 0) {
        close(channels[0]); return CONTINUUM_STATUS_SPAWN_FAILED;
    }
    continuum_broker_reply root_reply;
    continuum_broker_reply child_reply;
    int root_ready = continuum_broker_send_setup(channels[0], root, 0)
        && continuum_broker_receive_reply(channels[0], CONTINUUM_BROKER_READY, &root_reply)
        && root_reply.process_id == root_pid
        && root_reply.parent_process_id == getpid();
    int child_ready = root_ready
        && continuum_broker_send_child(channels[0], bootstrap_library_path, child)
        && continuum_broker_receive_reply(channels[0], CONTINUUM_BROKER_CHILD_READY, &child_reply)
        && child_reply.parent_process_id == root_pid && child_reply.process_id > 0;
    int prepared = root_ready && child_ready;
    if (!prepared) {
        if (child_ready) {
            continuum_broker_header abort_header = {
                .magic = CONTINUUM_BROKER_MAGIC,
                .version = CONTINUUM_BROKER_VERSION,
                .type = CONTINUUM_BROKER_ABORT,
                .payload_length = 0,
            };
            (void)continuum_broker_write_all(channels[0], &abort_header,
                sizeof(abort_header));
        } else {
            kill(root_pid, SIGKILL);
        }
        waitpid(root_pid, NULL, 0); close(channels[0]);
        return CONTINUUM_STATUS_SPAWN_FAILED;
    }
    struct proc_bsdinfo root_info;
    struct proc_bsdinfo child_info;
    memset(&root_info, 0, sizeof(root_info));
    memset(&child_info, 0, sizeof(child_info));
    if (proc_pidinfo(root_pid, PROC_PIDTBSDINFO, 0, &root_info,
            (int)sizeof(root_info)) != (int)sizeof(root_info)
        || proc_pidinfo(child_reply.process_id, PROC_PIDTBSDINFO, 0,
            &child_info, (int)sizeof(child_info)) != (int)sizeof(child_info)
        || root_info.pbi_ppid != getpid()
        || child_info.pbi_ppid != (uint32_t)root_pid) {
        continuum_broker_header abort_header = {
            .magic = CONTINUUM_BROKER_MAGIC,
            .version = CONTINUUM_BROKER_VERSION,
            .type = CONTINUUM_BROKER_ABORT,
            .payload_length = 0,
        };
        (void)continuum_broker_write_all(channels[0], &abort_header,
            sizeof(abort_header));
        waitpid(root_pid, NULL, 0);
        close(channels[0]);
        return CONTINUUM_STATUS_PROCESS_IDENTITY_CHANGED;
    }
    continuum_brokered_pair *pair = calloc(1, sizeof(*pair));
    if (pair == NULL) {
        continuum_broker_header abort_header = {
            .magic = CONTINUUM_BROKER_MAGIC,
            .version = CONTINUUM_BROKER_VERSION,
            .type = CONTINUUM_BROKER_ABORT,
            .payload_length = 0,
        };
        (void)continuum_broker_write_all(channels[0], &abort_header,
            sizeof(abort_header));
        waitpid(root_pid, NULL, 0); close(channels[0]);
        return CONTINUUM_STATUS_OUT_OF_MEMORY;
    }
    pair->channel = channels[0]; pair->root_process_id = root_pid;
    pair->child_process_id = child_reply.process_id;
    pair->root_start_seconds = root_info.pbi_start_tvsec;
    pair->root_start_microseconds = root_info.pbi_start_tvusec;
    pair->child_start_seconds = child_info.pbi_start_tvsec;
    pair->child_start_microseconds = child_info.pbi_start_tvusec;
    pair->state = CONTINUUM_BROKER_PAIR_PREPARED;
    *out_pair = pair;
    return CONTINUUM_STATUS_OK;
}

continuum_status continuum_brokered_pair_process_identifiers(
    const continuum_brokered_pair *pair,
    int32_t *out_root_process_id,
    int32_t *out_child_process_id
) {
    if (pair == NULL || out_root_process_id == NULL || out_child_process_id == NULL)
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    *out_root_process_id = pair->root_process_id;
    *out_child_process_id = pair->child_process_id;
    return CONTINUUM_STATUS_OK;
}

static int continuum_broker_process_matches(
    pid_t process_id,
    pid_t expected_parent,
    uint64_t start_seconds,
    uint64_t start_microseconds,
    int require_stopped
) {
    struct proc_bsdinfo info;
    memset(&info, 0, sizeof(info));
    return proc_pidinfo(process_id, PROC_PIDTBSDINFO, 0, &info,
            (int)sizeof(info)) == (int)sizeof(info)
        && info.pbi_ppid == (uint32_t)expected_parent
        && info.pbi_uid == geteuid()
        && info.pbi_start_tvsec == start_seconds
        && info.pbi_start_tvusec == start_microseconds
        && (!require_stopped || info.pbi_status == SSTOP);
}

static continuum_status continuum_broker_wait_for_stop(
    pid_t process_id,
    pid_t expected_parent,
    uint64_t start_seconds,
    uint64_t start_microseconds,
    uint64_t deadline
) {
    for (;;) {
        if (continuum_broker_process_matches(
                process_id,
                expected_parent,
                start_seconds,
                start_microseconds,
                1)) {
            return CONTINUUM_STATUS_OK;
        }
        if (!continuum_broker_process_matches(
                process_id,
                expected_parent,
                start_seconds,
                start_microseconds,
                0)) {
            return CONTINUUM_STATUS_PROCESS_IDENTITY_CHANGED;
        }
        if (clock_gettime_nsec_np(CLOCK_MONOTONIC) >= deadline) {
            return CONTINUUM_STATUS_SUSPEND_FAILED;
        }
        usleep(1000);
    }
}

static continuum_status continuum_broker_send_empty_command(
    int channel,
    uint16_t command,
    uint16_t expected_reply
) {
    continuum_broker_header header = {
        .magic = CONTINUUM_BROKER_MAGIC,
        .version = CONTINUUM_BROKER_VERSION,
        .type = command,
        .payload_length = 0,
    };
    continuum_broker_reply reply;
    if (continuum_broker_write_all(channel, &header, sizeof(header))
        && continuum_broker_receive_reply(channel, expected_reply, &reply)) {
        return CONTINUUM_STATUS_OK;
    }
    if (command == CONTINUUM_BROKER_CHILD_TO_ENTRY) {
        return CONTINUUM_STATUS_VALIDATION_FAILED;
    }
    if (command == CONTINUUM_BROKER_CHILD_DETACH) {
        return CONTINUUM_STATUS_RESUME_FAILED;
    }
    return CONTINUUM_STATUS_SPAWN_FAILED;
}

continuum_status continuum_brokered_pair_advance_to_entry_stops(
    continuum_brokered_pair *pair,
    uint32_t timeout_milliseconds
) {
    if (pair == NULL || timeout_milliseconds == 0
        || pair->state != CONTINUUM_BROKER_PAIR_PREPARED) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    struct timeval receive_timeout = {
        .tv_sec = (time_t)(timeout_milliseconds / 1000),
        .tv_usec = (suseconds_t)(timeout_milliseconds % 1000) * 1000,
    };
    if (setsockopt(
            pair->channel,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &receive_timeout,
            sizeof(receive_timeout)) != 0) {
        return CONTINUUM_STATUS_SPAWN_FAILED;
    }
    uint64_t now = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    uint64_t timeout = (uint64_t)timeout_milliseconds * UINT64_C(1000000);
    if (UINT64_MAX - now < timeout) {
        (void)kill(pair->child_process_id, SIGKILL);
        (void)kill(pair->root_process_id, SIGKILL);
        (void)waitpid(pair->root_process_id, NULL, 0);
        close(pair->channel);
        pair->channel = -1;
        pair->state = CONTINUUM_BROKER_PAIR_FAILED;
        return CONTINUUM_STATUS_RANGE_ERROR;
    }
    uint64_t deadline = now + timeout;
    int root_traced = 0;
    continuum_status status = continuum_broker_process_matches(
            pair->child_process_id,
            pair->root_process_id,
            pair->child_start_seconds,
            pair->child_start_microseconds,
            0)
        ? CONTINUUM_STATUS_OK
        : CONTINUUM_STATUS_PROCESS_IDENTITY_CHANGED;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    continuum_broker_header command = {
        .magic = CONTINUUM_BROKER_MAGIC,
        .version = CONTINUUM_BROKER_VERSION,
        .type = CONTINUUM_BROKER_CHILD_TO_BOOTSTRAP,
        .payload_length = 0,
    };
    if (status == CONTINUUM_STATUS_OK
        && !continuum_broker_write_all(
            pair->channel, &command, sizeof(command))) {
        status = CONTINUUM_STATUS_SPAWN_FAILED;
    }
    continuum_broker_reply reply;
    if (status == CONTINUUM_STATUS_OK
        && !continuum_broker_receive_reply(
            pair->channel,
            CONTINUUM_BROKER_CHILD_BOOTSTRAP_RELEASED,
            &reply)) {
        status = CONTINUUM_STATUS_SPAWN_FAILED;
    }
    if (status == CONTINUUM_STATUS_OK) {
        uint64_t current = clock_gettime_nsec_np(CLOCK_MONOTONIC);
        uint64_t remaining = deadline > current ? deadline - current : 0;
        status = remaining == 0
            ? CONTINUUM_STATUS_SUSPEND_FAILED
            : continuum_advance_bootstrap_stopped_process_to_entry(
                pair->child_process_id,
                (uint32_t)(remaining / UINT64_C(1000000) + 1),
                1,
                pair->channel
            );
    }
    if (status == CONTINUUM_STATUS_OK) {
        if (ptrace(PT_ATTACH, pair->root_process_id, NULL, 0) == 0) {
            root_traced = 1;
            status = continuum_wait_for_child_signal_stop(
                pair->root_process_id,
                deadline,
                SIGSTOP
            );
        } else {
            status = CONTINUUM_STATUS_ACCESS_DENIED;
        }
    }
    command.type = CONTINUUM_BROKER_ROOT_TO_BOOTSTRAP;
    if (status == CONTINUUM_STATUS_OK
        && !continuum_broker_write_all(
            pair->channel, &command, sizeof(command))) {
        status = CONTINUUM_STATUS_SPAWN_FAILED;
    }
    if (status == CONTINUUM_STATUS_OK
        && ptrace(PT_CONTINUE, pair->root_process_id, (caddr_t)1, 0) != 0) {
        status = CONTINUUM_STATUS_RESUME_FAILED;
    }
    if (status == CONTINUUM_STATUS_OK
        && !continuum_broker_receive_reply(
            pair->channel,
            CONTINUUM_BROKER_ROOT_BOOTSTRAP_RELEASED,
            &reply)) {
        status = CONTINUUM_STATUS_SPAWN_FAILED;
    }
    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_wait_for_child_signal_stop(
            pair->root_process_id,
            deadline,
            SIGSTOP
        );
    }
    if (status == CONTINUUM_STATUS_OK) {
        uint64_t current = clock_gettime_nsec_np(CLOCK_MONOTONIC);
        uint64_t remaining = deadline > current ? deadline - current : 0;
        status = remaining == 0
            ? CONTINUUM_STATUS_SUSPEND_FAILED
            : continuum_advance_bootstrap_stopped_process_to_entry(
                pair->root_process_id,
                (uint32_t)(remaining / UINT64_C(1000000) + 1),
                1,
                -1
            );
    }
    if (status != CONTINUUM_STATUS_OK) {
        continuum_broker_header abort_command = {
            .magic = CONTINUUM_BROKER_MAGIC,
            .version = CONTINUUM_BROKER_VERSION,
            .type = CONTINUUM_BROKER_ABORT,
            .payload_length = 0,
        };
        (void)continuum_broker_write_all(
            pair->channel, &abort_command, sizeof(abort_command));
        (void)kill(pair->child_process_id, SIGKILL);
        (void)waitpid(pair->child_process_id, NULL, 0);
        if (root_traced) {
            continuum_broker_kill_and_reap_traced_child(
                pair->root_process_id,
                clock_gettime_nsec_np(CLOCK_MONOTONIC)
                    + UINT64_C(2000000000)
            );
        } else {
            (void)kill(pair->root_process_id, SIGKILL);
            (void)waitpid(pair->root_process_id, NULL, 0);
        }
    }
#pragma clang diagnostic pop
    close(pair->channel);
    pair->channel = -1;
    pair->state = status == CONTINUUM_STATUS_OK
        ? CONTINUUM_BROKER_PAIR_ENTRY_STOPPED
        : CONTINUUM_BROKER_PAIR_FAILED;
    return status;
}

static continuum_status continuum_brokered_pair_command(
    continuum_brokered_pair *pair,
    uint16_t type,
    uint32_t timeout_milliseconds
) {
    if (pair == NULL || pair->state != CONTINUUM_BROKER_PAIR_PREPARED
        || (type != CONTINUUM_BROKER_RELEASE && type != CONTINUUM_BROKER_ABORT))
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    continuum_broker_header header = {
        .magic = CONTINUUM_BROKER_MAGIC, .version = CONTINUUM_BROKER_VERSION,
        .type = type, .payload_length = 0,
    };
    int sent = continuum_broker_write_all(pair->channel, &header, sizeof(header));
    continuum_status status = CONTINUUM_STATUS_OK;
    if (type == CONTINUUM_BROKER_RELEASE) {
        continuum_broker_reply reply;
        if (!sent || !continuum_broker_receive_reply(pair->channel,
            CONTINUUM_BROKER_RELEASED, &reply)) {
            status = CONTINUUM_STATUS_RESUME_FAILED;
            close(pair->channel);
            pair->channel = -1;
            kill(pair->child_process_id, SIGKILL);
            kill(pair->root_process_id, SIGKILL);
            waitpid(pair->root_process_id, NULL, 0);
        }
    } else {
        uint64_t deadline = clock_gettime_nsec_np(CLOCK_MONOTONIC)
            + (uint64_t)timeout_milliseconds * UINT64_C(1000000);
        int wait_status = 0;
        for (;;) {
            pid_t waited = waitpid(pair->root_process_id, &wait_status, WNOHANG);
            if (waited == pair->root_process_id) break;
            if (waited < 0 || clock_gettime_nsec_np(CLOCK_MONOTONIC) >= deadline) {
                kill(pair->root_process_id, SIGKILL);
                waitpid(pair->root_process_id, NULL, 0);
                status = CONTINUUM_STATUS_TARGET_EXITED;
                break;
            }
            usleep(1000);
        }
    }
    if (pair->channel >= 0) close(pair->channel);
    free(pair);
    return status;
}

continuum_status continuum_brokered_pair_release(continuum_brokered_pair *pair) {
    return continuum_brokered_pair_command(pair, CONTINUUM_BROKER_RELEASE, 0);
}

continuum_status continuum_brokered_pair_abort(
    continuum_brokered_pair *pair,
    uint32_t timeout_milliseconds
) {
    if (timeout_milliseconds == 0) return CONTINUUM_STATUS_INVALID_ARGUMENT;
    if (pair == NULL) return CONTINUUM_STATUS_INVALID_ARGUMENT;
    if (pair->state != CONTINUUM_BROKER_PAIR_PREPARED) {
        if (continuum_broker_process_matches(
                pair->child_process_id,
                pair->root_process_id,
                pair->child_start_seconds,
                pair->child_start_microseconds,
                0)) {
            (void)kill(pair->child_process_id, SIGKILL);
        } else if (continuum_broker_process_matches(
                pair->child_process_id,
                getpid(),
                pair->child_start_seconds,
                pair->child_start_microseconds,
                0)) {
            continuum_broker_kill_and_reap_traced_child(
                pair->child_process_id,
                clock_gettime_nsec_np(CLOCK_MONOTONIC)
                    + (uint64_t)timeout_milliseconds * UINT64_C(1000000)
            );
        }
        if (continuum_broker_process_matches(
                pair->root_process_id,
                getpid(),
                pair->root_start_seconds,
                pair->root_start_microseconds,
                0)) {
            continuum_broker_kill_and_reap_traced_child(
                pair->root_process_id,
                clock_gettime_nsec_np(CLOCK_MONOTONIC)
                    + (uint64_t)timeout_milliseconds * UINT64_C(1000000)
            );
        }
        if (pair->channel >= 0) close(pair->channel);
        free(pair);
        return CONTINUUM_STATUS_OK;
    }
    return continuum_brokered_pair_command(pair, CONTINUUM_BROKER_ABORT,
        timeout_milliseconds);
}

continuum_status continuum_brokered_pair_note_released_process(
    continuum_brokered_pair *pair,
    int32_t process_id
) {
    if (pair == NULL || pair->state != CONTINUUM_BROKER_PAIR_ENTRY_STOPPED) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    if (process_id == pair->root_process_id) {
        if (pair->root_released) return CONTINUUM_STATUS_INVALID_ARGUMENT;
        pair->root_released = 1;
        return CONTINUUM_STATUS_OK;
    }
    if (process_id == pair->child_process_id) {
        if (pair->child_released) return CONTINUUM_STATUS_INVALID_ARGUMENT;
        pair->child_released = 1;
        return CONTINUUM_STATUS_OK;
    }
    return CONTINUUM_STATUS_PROCESS_IDENTITY_CHANGED;
}

continuum_status continuum_brokered_pair_finish(
    continuum_brokered_pair *pair
) {
    if (pair == NULL || pair->state != CONTINUUM_BROKER_PAIR_ENTRY_STOPPED
        || !pair->root_released || !pair->child_released) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    if (pair->channel >= 0) close(pair->channel);
    free(pair);
    return CONTINUUM_STATUS_OK;
}

continuum_status continuum_wait_for_process_stop(
    int32_t process_id,
    uint32_t timeout_milliseconds
) {
    if (process_id <= 0 || timeout_milliseconds == 0) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    uint64_t timeout_nanoseconds =
        (uint64_t)timeout_milliseconds * UINT64_C(1000000);
    uint64_t now = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    if (UINT64_MAX - now < timeout_nanoseconds) {
        return CONTINUUM_STATUS_RANGE_ERROR;
    }
    uint64_t deadline = now + timeout_nanoseconds;
    for (;;) {
        int wait_status = 0;
        pid_t waited = waitpid(
            process_id,
            &wait_status,
            WUNTRACED | WNOHANG
        );
        if (waited == process_id) {
            if (WIFSTOPPED(wait_status)) {
                return WSTOPSIG(wait_status) == SIGSTOP
                    ? CONTINUUM_STATUS_OK
                    : CONTINUUM_STATUS_SUSPEND_FAILED;
            }
            if (WIFEXITED(wait_status) || WIFSIGNALED(wait_status)) {
                return CONTINUUM_STATUS_TARGET_EXITED;
            }
        } else if (waited < 0 && errno != EINTR) {
            return errno == ECHILD
                ? CONTINUUM_STATUS_TARGET_EXITED
                : CONTINUUM_STATUS_SUSPEND_FAILED;
        }
        if (clock_gettime_nsec_np(CLOCK_MONOTONIC) >= deadline) {
            return CONTINUUM_STATUS_SUSPEND_FAILED;
        }
        usleep(1000);
    }
}

continuum_status continuum_terminate_direct_child(
    int32_t process_id,
    uint32_t timeout_milliseconds
) {
    if (process_id <= 0 || timeout_milliseconds == 0) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    struct proc_bsdinfo process_info;
    memset(&process_info, 0, sizeof(process_info));
    int copied = proc_pidinfo(
        process_id,
        PROC_PIDTBSDINFO,
        0,
        &process_info,
        (int)sizeof(process_info)
    );
    if (copied != (int)sizeof(process_info)) {
        int wait_status = 0;
        pid_t waited = waitpid(process_id, &wait_status, WNOHANG);
        if (waited == process_id
            && (WIFEXITED(wait_status) || WIFSIGNALED(wait_status))) {
            return CONTINUUM_STATUS_OK;
        }
        return CONTINUUM_STATUS_TARGET_EXITED;
    }
    if (process_info.pbi_ppid != getpid()) {
        return CONTINUUM_STATUS_ACCESS_DENIED;
    }

    uint64_t timeout_nanoseconds =
        (uint64_t)timeout_milliseconds * UINT64_C(1000000);
    uint64_t now = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    if (UINT64_MAX - now < timeout_nanoseconds) {
        return CONTINUUM_STATUS_RANGE_ERROR;
    }
    uint64_t deadline = now + timeout_nanoseconds;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    int trace_result = ptrace(PT_KILL, process_id, (caddr_t)1, 0);
#pragma clang diagnostic pop
    if (trace_result != 0 && kill(process_id, SIGKILL) != 0
        && errno != ESRCH) {
        return CONTINUUM_STATUS_RESUME_FAILED;
    }

    int wait_status = 0;
    for (;;) {
        pid_t waited = waitpid(
            process_id,
            &wait_status,
            WUNTRACED | WNOHANG
        );
        if (waited == process_id) {
            if (WIFEXITED(wait_status) || WIFSIGNALED(wait_status)) {
                return CONTINUUM_STATUS_OK;
            }
            if (WIFSTOPPED(wait_status)) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
                (void)ptrace(PT_KILL, process_id, (caddr_t)1, 0);
#pragma clang diagnostic pop
                (void)kill(process_id, SIGKILL);
            }
        } else if (waited < 0 && errno != EINTR) {
            return errno == ECHILD
                ? CONTINUUM_STATUS_OK
                : CONTINUUM_STATUS_SUSPEND_FAILED;
        }
        if (clock_gettime_nsec_np(CLOCK_MONOTONIC) >= deadline) {
            return CONTINUUM_STATUS_SUSPEND_FAILED;
        }
        usleep(1000);
    }
}

continuum_status continuum_advance_process_to_bootstrap_stop(
    int32_t process_id,
    uint32_t timeout_milliseconds
) {
    if (process_id <= 0 || timeout_milliseconds == 0) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    struct proc_bsdinfo process_info;
    memset(&process_info, 0, sizeof(process_info));
    int copied = proc_pidinfo(
        process_id,
        PROC_PIDTBSDINFO,
        0,
        &process_info,
        (int)sizeof(process_info)
    );
    if (copied != (int)sizeof(process_info)) {
        return CONTINUUM_STATUS_TARGET_EXITED;
    }
    if (process_info.pbi_ppid != getpid()) {
        if (process_info.pbi_status != SSTOP) {
            return CONTINUUM_STATUS_ACCESS_DENIED;
        }
        return kill(process_id, SIGCONT) == 0
            ? CONTINUUM_STATUS_OK
            : CONTINUUM_STATUS_RESUME_FAILED;
    }

    uint64_t timeout_nanoseconds =
        (uint64_t)timeout_milliseconds * UINT64_C(1000000);
    uint64_t now = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    if (UINT64_MAX - now < timeout_nanoseconds) {
        return CONTINUUM_STATUS_RANGE_ERROR;
    }
    uint64_t deadline = now + timeout_nanoseconds;
    int wait_status = 0;
    for (;;) {
        pid_t waited = waitpid(
            process_id,
            &wait_status,
            WUNTRACED | WNOHANG
        );
        if (waited == process_id) {
            if (WIFSTOPPED(wait_status)) {
                int launch_signal = WSTOPSIG(wait_status);
                if (launch_signal != 0 && launch_signal != SIGSTOP) {
                    return CONTINUUM_STATUS_SUSPEND_FAILED;
                }
                break;
            }
            if (WIFEXITED(wait_status) || WIFSIGNALED(wait_status)) {
                return CONTINUUM_STATUS_TARGET_EXITED;
            }
        } else if (waited < 0 && errno != EINTR) {
            return errno == ECHILD
                ? CONTINUUM_STATUS_TARGET_EXITED
                : CONTINUUM_STATUS_SUSPEND_FAILED;
        }
        if (clock_gettime_nsec_np(CLOCK_MONOTONIC) >= deadline) {
            return CONTINUUM_STATUS_SUSPEND_FAILED;
        }
        usleep(1000);
    }

    if (kill(process_id, SIGCONT) != 0) {
        return errno == ESRCH
            ? CONTINUUM_STATUS_TARGET_EXITED
            : CONTINUUM_STATUS_RESUME_FAILED;
    }
    for (;;) {
        pid_t waited = waitpid(
            process_id,
            &wait_status,
            WUNTRACED | WCONTINUED | WNOHANG
        );
        if (waited == process_id) {
            if (WIFSTOPPED(wait_status)) {
                return WSTOPSIG(wait_status) == SIGSTOP
                    ? CONTINUUM_STATUS_OK
                    : CONTINUUM_STATUS_SUSPEND_FAILED;
            }
            if (WIFEXITED(wait_status) || WIFSIGNALED(wait_status)) {
                return CONTINUUM_STATUS_TARGET_EXITED;
            }
        } else if (waited < 0 && errno != EINTR) {
            return errno == ECHILD
                ? CONTINUUM_STATUS_TARGET_EXITED
                : CONTINUUM_STATUS_SUSPEND_FAILED;
        }
        if (clock_gettime_nsec_np(CLOCK_MONOTONIC) >= deadline) {
            return CONTINUUM_STATUS_SUSPEND_FAILED;
        }
        usleep(1000);
    }
}

typedef struct continuum_checkpoint {
    uint64_t identifier;
    uint8_t *bytes;
} continuum_checkpoint;

typedef struct continuum_remote_thread_entry {
    uint64_t identifier;
    uint64_t thread_handle;
    uint64_t pthread_object_address;
    uint64_t dispatch_queue_address;
    continuum_remote_thread_origin origin;
    uint32_t general_flavor;
    uint8_t *general_bytes;
    size_t general_length;
    uint32_t vector_flavor;
    uint8_t *vector_bytes;
    size_t vector_length;
    uint8_t is_userspace_safepoint;
    uint8_t preserves_kernel_continuation;
} continuum_remote_thread_entry;

static int continuum_program_counter_is_kernel_wait(uintptr_t program_counter) {
    if (program_counter == 0) {
        return 0;
    }
    Dl_info info;
    memset(&info, 0, sizeof(info));
    if (dladdr((const void *)program_counter, &info) == 0
        || info.dli_fname == NULL) {
        return 0;
    }
    const char *name = strrchr(info.dli_fname, '/');
    name = name == NULL ? info.dli_fname : name + 1;
    return strcmp(name, "libsystem_kernel.dylib") == 0;
}

typedef struct continuum_pthread_layout_offsets {
    uint16_t version;
    uint16_t pthread_tsd_base_offset;
    uint16_t pthread_tsd_base_address_offset;
    uint16_t pthread_tsd_entry_size;
} continuum_pthread_layout_offsets;

static uint64_t continuum_pthread_object_address(uint64_t thread_handle) {
    if (thread_handle == 0) {
        return 0;
    }
    const continuum_pthread_layout_offsets *layout = dlsym(
        RTLD_DEFAULT,
        "pthread_layout_offsets"
    );
    if (layout == NULL || layout->version < 1
        || layout->pthread_tsd_base_offset == 0
        || layout->pthread_tsd_base_address_offset != 0
        || thread_handle < layout->pthread_tsd_base_offset) {
        return 0;
    }
    return thread_handle - layout->pthread_tsd_base_offset;
}

static continuum_remote_thread_origin continuum_thread_origin(
    mach_port_t task,
    uint64_t thread_handle,
    uint64_t pthread_object_address
) {
    // Apple libpthread layout v1 places its flags word 78 bytes from pthread_t.
    // Refuse classification unless the exported TSD geometry also matches.
    enum {
        CONTINUUM_PTHREAD_TSD_OFFSET_V1 = 224,
        CONTINUUM_PTHREAD_FLAGS_OFFSET_V1 = 78,
        CONTINUUM_PTHREAD_WORKQUEUE_MASK_V1 = 1 << 10
    };
    if (thread_handle == 0) {
        return CONTINUUM_REMOTE_THREAD_ORIGIN_RAW_MACH;
    }
    const continuum_pthread_layout_offsets *layout = dlsym(
        RTLD_DEFAULT,
        "pthread_layout_offsets"
    );
    if (pthread_object_address == 0 || layout == NULL
        || layout->version != 1
        || layout->pthread_tsd_base_offset
            != CONTINUUM_PTHREAD_TSD_OFFSET_V1
        || layout->pthread_tsd_base_address_offset != 0) {
        return CONTINUUM_REMOTE_THREAD_ORIGIN_UNKNOWN;
    }

    uint64_t observed_pthread_self = 0;
    mach_vm_size_t copied = 0;
    kern_return_t result = mach_vm_read_overwrite(
        task,
        thread_handle,
        sizeof(observed_pthread_self),
        (mach_vm_address_t)&observed_pthread_self,
        &copied
    );
    if (result != KERN_SUCCESS || copied != sizeof(observed_pthread_self)
        || observed_pthread_self != pthread_object_address) {
        return CONTINUUM_REMOTE_THREAD_ORIGIN_UNKNOWN;
    }

    uint16_t flags = 0;
    copied = 0;
    result = mach_vm_read_overwrite(
        task,
        pthread_object_address + CONTINUUM_PTHREAD_FLAGS_OFFSET_V1,
        sizeof(flags),
        (mach_vm_address_t)&flags,
        &copied
    );
    if (result != KERN_SUCCESS || copied != sizeof(flags)) {
        return CONTINUUM_REMOTE_THREAD_ORIGIN_UNKNOWN;
    }
    return (flags & CONTINUUM_PTHREAD_WORKQUEUE_MASK_V1) != 0
        ? CONTINUUM_REMOTE_THREAD_ORIGIN_WORKQUEUE
        : CONTINUUM_REMOTE_THREAD_ORIGIN_PTHREAD;
}

typedef struct continuum_remote_process_region {
    uint64_t address;
    uint64_t length;
    int32_t protection;
    int32_t maximum_protection;
    int32_t inheritance;
    uint32_t share_mode;
    uint32_t user_tag;
    uint8_t *bytes;
    int *page_dispositions;
    size_t page_count;
    uint8_t is_cow_mapping;
    uint8_t preserves_live_derived_graphics;
    uint8_t is_app_owned_state;
    vm_range_t *app_state_allocations;
    size_t app_state_allocation_count;
} continuum_remote_process_region;

static continuum_status continuum_read_task_bytes(
    mach_port_t task,
    mach_vm_address_t address,
    mach_vm_size_t length,
    void *destination
);
static continuum_status continuum_read_task_cstring(
    mach_port_t task,
    mach_vm_address_t address,
    char *destination,
    size_t capacity
);

typedef struct continuum_vm_range_set {
    vm_range_t *ranges;
    size_t count;
    size_t capacity;
    int failed;
} continuum_vm_range_set;

typedef struct continuum_malloc_reader_allocation {
    void *bytes;
    struct continuum_malloc_reader_allocation *next;
} continuum_malloc_reader_allocation;

static _Thread_local continuum_malloc_reader_allocation
    *continuum_malloc_reader_allocations = NULL;

static void continuum_clear_malloc_reader_allocations(void) {
    while (continuum_malloc_reader_allocations != NULL) {
        continuum_malloc_reader_allocation *allocation =
            continuum_malloc_reader_allocations;
        continuum_malloc_reader_allocations = allocation->next;
        free(allocation->bytes);
        free(allocation);
    }
}

static kern_return_t continuum_malloc_remote_reader(
    task_t task,
    vm_address_t remote_address,
    vm_size_t size,
    void **local_memory
) {
    if (task == MACH_PORT_NULL || remote_address == 0 || size == 0
        || local_memory == NULL) {
        return KERN_INVALID_ARGUMENT;
    }
    continuum_malloc_reader_allocation *allocation = malloc(
        sizeof(*allocation)
    );
    if (allocation == NULL) {
        return KERN_RESOURCE_SHORTAGE;
    }
    allocation->bytes = malloc((size_t)size);
    if (allocation->bytes == NULL) {
        free(allocation);
        return KERN_RESOURCE_SHORTAGE;
    }
    allocation->next = continuum_malloc_reader_allocations;
    continuum_malloc_reader_allocations = allocation;
    mach_vm_size_t copied = 0;
    kern_return_t result = mach_vm_read_overwrite(
        task,
        remote_address,
        size,
        (mach_vm_address_t)(uintptr_t)allocation->bytes,
        &copied
    );
    if (result != KERN_SUCCESS || copied != size) {
        return result == KERN_SUCCESS ? KERN_FAILURE : result;
    }
    *local_memory = allocation->bytes;
    return KERN_SUCCESS;
}

static void continuum_record_malloc_ranges(
    task_t task,
    void *context,
    unsigned type,
    vm_range_t *ranges,
    unsigned count
) {
    (void)task;
    (void)type;
    continuum_vm_range_set *set = context;
    if (set == NULL || ranges == NULL || count == 0 || set->failed) {
        return;
    }
    if (set->count > SIZE_MAX - count) {
        set->failed = 1;
        return;
    }
    size_t required = set->count + count;
    if (required > set->capacity) {
        size_t capacity = set->capacity == 0 ? 32 : set->capacity;
        while (capacity < required) {
            if (capacity > SIZE_MAX / 2) {
                set->failed = 1;
                return;
            }
            capacity *= 2;
        }
        vm_range_t *resized = realloc(
            set->ranges,
            capacity * sizeof(*set->ranges)
        );
        if (resized == NULL) {
            set->failed = 1;
            return;
        }
        set->ranges = resized;
        set->capacity = capacity;
    }
    memcpy(
        set->ranges + set->count,
        ranges,
        count * sizeof(*ranges)
    );
    set->count = required;
}

static continuum_status continuum_collect_named_malloc_zone_ranges(
    mach_port_t task,
    const char *zone_name,
    unsigned range_type,
    continuum_vm_range_set *out_ranges
) {
    if (task == MACH_PORT_NULL || zone_name == NULL || zone_name[0] == '\0'
        || out_ranges == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    memset(out_ranges, 0, sizeof(*out_ranges));
    continuum_clear_malloc_reader_allocations();

    vm_address_t *remote_zones = NULL;
    unsigned zone_count = 0;
    kern_return_t result = malloc_get_all_zones(
        task,
        continuum_malloc_remote_reader,
        &remote_zones,
        &zone_count
    );
    if (result != KERN_SUCCESS || (zone_count > 0 && remote_zones == NULL)
        || zone_count > UINT32_C(1048576)) {
        continuum_clear_malloc_reader_allocations();
        return CONTINUUM_STATUS_MACH_ERROR;
    }
    vm_address_t *zones = NULL;
    if (zone_count > 0) {
        zones = malloc((size_t)zone_count * sizeof(*zones));
        if (zones == NULL) {
            continuum_clear_malloc_reader_allocations();
            return CONTINUUM_STATUS_OUT_OF_MEMORY;
        }
        memcpy(zones, remote_zones, (size_t)zone_count * sizeof(*zones));
    }
    continuum_status status = CONTINUUM_STATUS_OK;
    for (unsigned index = 0; index < zone_count; index += 1) {
        malloc_zone_t zone;
        memset(&zone, 0, sizeof(zone));
        status = continuum_read_task_bytes(
            task,
            zones[index],
            sizeof(zone),
            &zone
        );
        if (status != CONTINUUM_STATUS_OK) {
            status = CONTINUUM_STATUS_OK;
            continue;
        }
        if (zone.zone_name == NULL || zone.introspect == NULL) {
            continue;
        }
        char name[64];
        memset(name, 0, sizeof(name));
        status = continuum_read_task_bytes(
            task,
            (mach_vm_address_t)(uintptr_t)zone.zone_name,
            sizeof(name) - 1,
            name
        );
        if (status != CONTINUUM_STATUS_OK) {
            status = CONTINUUM_STATUS_OK;
            continue;
        }
        if (strcmp(name, zone_name) != 0) {
            continue;
        }
        malloc_introspection_t *introspection = zone.introspect;
        if (introspection->enumerator == NULL) {
            status = CONTINUUM_STATUS_VALIDATION_FAILED;
            break;
        }
        result = introspection->enumerator(
            task,
            out_ranges,
            range_type,
            zones[index],
            continuum_malloc_remote_reader,
            continuum_record_malloc_ranges
        );
        if (result != KERN_SUCCESS || out_ranges->failed) {
            status = out_ranges->failed
                ? CONTINUUM_STATUS_OUT_OF_MEMORY
                : CONTINUUM_STATUS_MACH_ERROR;
            break;
        }
    }
    free(zones);
    continuum_clear_malloc_reader_allocations();
    if (status != CONTINUUM_STATUS_OK) {
        free(out_ranges->ranges);
        memset(out_ranges, 0, sizeof(*out_ranges));
    }
    return status;
}

static continuum_status continuum_collect_quartzcore_ranges(
    mach_port_t task,
    continuum_vm_range_set *out_ranges
) {
    // malloc_get_all_zones derives remote allocator globals from this
    // process's libmalloc slide. That is not valid for Continuum targets
    // launched with a private dyld shared region. QuartzCore ranges are only
    // an optional derived-graphics optimization; VM tags remain the reliable
    // remote classification, so do not run the allocator probe cross-task.
    if (task != mach_task_self()) {
        if (out_ranges == NULL) {
            return CONTINUUM_STATUS_INVALID_ARGUMENT;
        }
        memset(out_ranges, 0, sizeof(*out_ranges));
        return CONTINUUM_STATUS_OK;
    }
    return continuum_collect_named_malloc_zone_ranges(
        task,
        "QuartzCore",
        MALLOC_PTR_REGION_RANGE_TYPE,
        out_ranges
    );
}

static int continuum_ranges_overlap(
    uint64_t left_address,
    uint64_t left_length,
    uint64_t right_address,
    uint64_t right_length
) {
    if (left_length == 0 || right_length == 0) {
        return 0;
    }
    uint64_t left_end = left_address + left_length;
    uint64_t right_end = right_address + right_length;
    return left_end >= left_address && right_end >= right_address
        && left_address < right_end && right_address < left_end;
}

static int continuum_region_is_derived_graphics(
    uint64_t address,
    uint64_t length,
    uint32_t user_tag,
    const continuum_vm_range_set *quartzcore_ranges
) {
    switch (user_tag) {
    case 42:
    case 51:
    case 52:
    case 54:
    case 55:
    case 56:
    case 57:
    case 58:
    case 68:
    case 88:
    case 100:
        return 1;
    default:
        break;
    }
    if (quartzcore_ranges == NULL) {
        return 0;
    }
    for (size_t index = 0; index < quartzcore_ranges->count; index += 1) {
        if (continuum_ranges_overlap(
                address,
                length,
                quartzcore_ranges->ranges[index].address,
                quartzcore_ranges->ranges[index].size
            )) {
            return 1;
        }
    }
    return 0;
}

struct continuum_tracked_region {
    uint8_t *address;
    size_t length;
    continuum_checkpoint *checkpoints;
    size_t checkpoint_count;
    size_t checkpoint_capacity;
    uint64_t next_identifier;
};

typedef struct continuum_bootstrap_pthread_wire_report {
    uint32_t version;
    uint32_t requested_count;
    uint32_t created_count;
    int32_t error_code;
    uint64_t primary_pthread_address;
    uint32_t primary_mach_thread_port;
    uint64_t primary_stack_base_address;
    uint64_t primary_stack_length;
    uint64_t primary_stack_region_address;
    uint64_t primary_stack_region_length;
    uint64_t primary_pthread_region_address;
    uint64_t primary_pthread_region_length;
    uint64_t pthread_addresses[CONTINUUM_REMOTE_PTHREAD_LIMIT];
    uint32_t mach_thread_ports[CONTINUUM_REMOTE_PTHREAD_LIMIT];
    uint64_t stack_base_addresses[CONTINUUM_REMOTE_PTHREAD_LIMIT];
    uint64_t stack_lengths[CONTINUUM_REMOTE_PTHREAD_LIMIT];
    uint64_t stack_region_addresses[CONTINUUM_REMOTE_PTHREAD_LIMIT];
    uint64_t stack_region_lengths[CONTINUUM_REMOTE_PTHREAD_LIMIT];
    uint64_t pthread_region_addresses[CONTINUUM_REMOTE_PTHREAD_LIMIT];
    uint64_t pthread_region_lengths[CONTINUUM_REMOTE_PTHREAD_LIMIT];
} continuum_bootstrap_pthread_wire_report;

#define CONTINUUM_BOOTSTRAP_PTY_STATUS_MAGIC UINT64_C(0x434F4E5450545951)
#define CONTINUUM_BOOTSTRAP_DESCRIPTOR_STATUS_MAGIC \
    UINT64_C(0x434F4E5446445354)
#define CONTINUUM_BOOTSTRAP_DESCRIPTOR_STATUS_LIMIT 1024

typedef struct continuum_bootstrap_pty_safepoint_wire_status {
    uint64_t magic;
    uint32_t version;
    uint32_t structure_size;
    uint64_t generation;
    uint64_t safepoint_thread_identifier;
    uint32_t pty_descriptor_count;
    uint8_t queue_state_known;
    uint8_t all_queues_zero;
    uint8_t safepoint_active;
    uint8_t reserved;
} continuum_bootstrap_pty_safepoint_wire_status;

typedef struct continuum_bootstrap_descriptor_status_wire_entry {
    int32_t file_descriptor;
    int32_t descriptor_flags;
    int32_t status_flags;
    uint32_t kind;
} continuum_bootstrap_descriptor_status_wire_entry;

typedef struct continuum_bootstrap_descriptor_safepoint_wire_status {
    uint64_t magic;
    uint32_t version;
    uint32_t structure_size;
    uint64_t generation;
    uint32_t descriptor_count;
    uint8_t overflow;
    uint8_t safepoint_active;
    uint8_t reserved[2];
    continuum_bootstrap_descriptor_status_wire_entry
        descriptors[CONTINUUM_BOOTSTRAP_DESCRIPTOR_STATUS_LIMIT];
} continuum_bootstrap_descriptor_safepoint_wire_status;

struct continuum_remote_session {
    mach_port_t task;
    int owns_task_port;
    int is_self;
    continuum_remote_identity identity;
    continuum_remote_region_descriptor registered_region;
    uint64_t bootstrap_copy_address;
    uint64_t bootstrap_pthread_prepare_address;
    uint64_t reconstruction_address;
    uint64_t reconstruction_length;
    uint32_t owned_suspend_count;
    int has_registered_region;
    int has_active_reconstruction;
    int has_prepared_pthread_set;
    int has_reconstructed_thread_set;
    uint8_t replacement_stop_kind;
    uint8_t has_brokered_stop_authorization;
    uint8_t owns_ptrace_attachment;
    int32_t brokered_expected_parent_process_id;
    uint64_t brokered_start_seconds;
    uint64_t brokered_start_microseconds;
    continuum_remote_pthread_bootstrap_report prepared_pthreads;
};

struct continuum_remote_thread_snapshot {
    continuum_remote_thread_entry *entries;
    size_t count;
    uint64_t set_hash;
};

typedef struct continuum_remote_mach_right_entry {
    mach_port_name_t name;
    mach_port_type_t type;
    natural_t object;
} continuum_remote_mach_right_entry;

struct continuum_remote_process_snapshot {
    continuum_remote_identity identity;
    continuum_remote_process_region *regions;
    size_t region_count;
    continuum_remote_thread_snapshot *threads;
    continuum_remote_mach_right_entry *mach_rights;
    size_t mach_right_count;
    continuum_remote_resource_fingerprint resources;
    continuum_remote_process_snapshot_info info;
    uint8_t has_isolated_app_state;
};

typedef struct continuum_remote_process_tree_entry {
    int32_t process_id;
    int32_t parent_process_id;
    uint32_t depth;
} continuum_remote_process_tree_entry;

typedef struct continuum_remote_process_group_member {
    int32_t parent_process_id;
    continuum_remote_session *session;
    continuum_remote_process_snapshot *snapshot;
    task_suspension_token_t suspension_token;
} continuum_remote_process_group_member;

struct continuum_remote_process_group_snapshot {
    int32_t *root_process_ids;
    size_t root_process_count;
    continuum_remote_process_group_member *members;
    size_t member_count;
    continuum_remote_process_group_snapshot_info info;
};

static continuum_status continuum_capture_mach_rights(
    mach_port_t task,
    continuum_remote_mach_right_entry **out_entries,
    size_t *out_count
) {
    if (task == MACH_PORT_NULL || out_entries == NULL || out_count == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    *out_entries = NULL;
    *out_count = 0;

    ipc_info_space_t space_info;
    memset(&space_info, 0, sizeof(space_info));
    ipc_info_name_array_t table = NULL;
    mach_msg_type_number_t table_count = 0;
    ipc_info_tree_name_array_t tree = NULL;
    mach_msg_type_number_t tree_count = 0;
    kern_return_t result = mach_port_space_info(
        task,
        &space_info,
        &table,
        &table_count,
        &tree,
        &tree_count
    );
    if (result != KERN_SUCCESS) {
        return CONTINUUM_STATUS_MACH_ERROR;
    }

    continuum_remote_mach_right_entry *entries = table_count == 0
        ? NULL
        : calloc(table_count, sizeof(*entries));
    continuum_status status = table_count > 0 && entries == NULL
        ? CONTINUUM_STATUS_OUT_OF_MEMORY
        : CONTINUUM_STATUS_OK;
    size_t count = 0;
    for (mach_msg_type_number_t index = 0;
         status == CONTINUUM_STATUS_OK && index < table_count;
         index += 1) {
        if (table[index].iin_type == MACH_PORT_TYPE_NONE) {
            continue;
        }
        entries[count].name = table[index].iin_name;
        entries[count].type = table[index].iin_type;
        entries[count].object = table[index].iin_object;
        count += 1;
    }
    if (table != NULL) {
        (void)vm_deallocate(
            mach_task_self(),
            (vm_address_t)table,
            (vm_size_t)(table_count * sizeof(*table))
        );
    }
    if (tree != NULL) {
        (void)vm_deallocate(
            mach_task_self(),
            (vm_address_t)tree,
            (vm_size_t)(tree_count * sizeof(*tree))
        );
    }
    if (status != CONTINUUM_STATUS_OK) {
        free(entries);
        return status;
    }
    *out_entries = entries;
    *out_count = count;
    return CONTINUUM_STATUS_OK;
}

static int continuum_saved_mach_rights_remain_valid(
    const continuum_remote_process_snapshot *saved,
    const continuum_remote_process_snapshot *current
) {
    if (saved == NULL || current == NULL) {
        return 0;
    }
    const mach_port_type_t identity_types = MACH_PORT_TYPE_SEND
        | MACH_PORT_TYPE_RECEIVE
        | MACH_PORT_TYPE_SEND_ONCE
        | MACH_PORT_TYPE_PORT_SET
        | MACH_PORT_TYPE_DEAD_NAME;
    for (size_t saved_index = 0;
         saved_index < saved->mach_right_count;
         saved_index += 1) {
        const continuum_remote_mach_right_entry *required =
            &saved->mach_rights[saved_index];
        int found = 0;
        for (size_t current_index = 0;
             current_index < current->mach_right_count;
             current_index += 1) {
            const continuum_remote_mach_right_entry *candidate =
                &current->mach_rights[current_index];
            if (candidate->name == required->name) {
                found = candidate->object == required->object
                    && (candidate->type & identity_types)
                        == (required->type & identity_types);
                break;
            }
        }
        if (!found) {
            const mach_port_type_t identity =
                required->type & identity_types;
            if (identity == MACH_PORT_TYPE_SEND_ONCE) {
                continue;
            }
            return 0;
        }
    }
    return 1;
}

static const continuum_remote_process_region *
continuum_find_process_region(
    const continuum_remote_process_snapshot *snapshot,
    uint64_t address,
    uint64_t length
) {
    if (snapshot == NULL) {
        return NULL;
    }
    for (size_t index = 0; index < snapshot->region_count; index += 1) {
        const continuum_remote_process_region *region =
            &snapshot->regions[index];
        if (region->address == address && region->length == length) {
            return region;
        }
    }
    return NULL;
}

static const continuum_remote_thread_entry *continuum_find_thread_entry(
    const continuum_remote_thread_snapshot *snapshot,
    uint64_t identifier
) {
    if (snapshot == NULL || identifier == 0) {
        return NULL;
    }
    for (size_t index = 0; index < snapshot->count; index += 1) {
        if (snapshot->entries[index].identifier == identifier) {
            return &snapshot->entries[index];
        }
    }
    return NULL;
}

static int continuum_stable_threads_remain_valid(
    const continuum_remote_thread_snapshot *saved,
    const continuum_remote_thread_snapshot *current
) {
    if (saved == NULL || current == NULL) {
        return 0;
    }
    for (size_t index = 0; index < saved->count; index += 1) {
        const continuum_remote_thread_entry *thread = &saved->entries[index];
        if (thread->origin != CONTINUUM_REMOTE_THREAD_ORIGIN_WORKQUEUE
            && continuum_find_thread_entry(current, thread->identifier) == NULL) {
            return 0;
        }
    }
    for (size_t index = 0; index < current->count; index += 1) {
        const continuum_remote_thread_entry *thread = &current->entries[index];
        if (thread->origin != CONTINUUM_REMOTE_THREAD_ORIGIN_WORKQUEUE
            && thread->origin != CONTINUUM_REMOTE_THREAD_ORIGIN_RAW_MACH
            && continuum_find_thread_entry(saved, thread->identifier) == NULL) {
            return 0;
        }
    }
    return 1;
}

static continuum_status continuum_capture_resource_fingerprint_suspended(
    continuum_remote_session *session,
    continuum_remote_resource_fingerprint *out_fingerprint
);

static int continuum_add_u64(uint64_t left, uint64_t right, uint64_t *result) {
    if (result == NULL || UINT64_MAX - left < right) {
        return 0;
    }
    *result = left + right;
    return 1;
}

static void continuum_hash_u64(uint64_t *hash, uint64_t value) {
    if (hash == NULL) {
        return;
    }
    for (size_t byte = 0; byte < sizeof(value); byte += 1) {
        *hash ^= (value >> (byte * 8)) & UINT64_C(0xFF);
        *hash *= CONTINUUM_FNV_PRIME;
    }
}

static void continuum_hash_bytes(
    uint64_t *hash,
    const void *bytes,
    size_t length
) {
    if (hash == NULL || bytes == NULL) {
        return;
    }
    const uint8_t *cursor = bytes;
    for (size_t index = 0; index < length; index += 1) {
        *hash ^= cursor[index];
        *hash *= CONTINUUM_FNV_PRIME;
    }
}

static int continuum_identity_equal(
    const continuum_remote_identity *left,
    const continuum_remote_identity *right
) {
    return left->process_id == right->process_id
        && left->start_seconds == right->start_seconds
        && left->start_microseconds == right->start_microseconds
        && left->executable_device == right->executable_device
        && left->executable_inode == right->executable_inode;
}

static int continuum_is_private_or_cow_share_mode(uint32_t share_mode) {
    return share_mode == SM_PRIVATE || share_mode == SM_COW;
}

static int continuum_is_reconstruction_destination_share_mode(
    uint32_t share_mode
) {
    return continuum_is_private_or_cow_share_mode(share_mode)
        || share_mode == SM_EMPTY;
}

static uint32_t continuum_canonical_share_mode(uint32_t share_mode) {
    return continuum_is_private_or_cow_share_mode(share_mode)
        ? UINT32_C(1)
        : share_mode;
}

static int continuum_region_is_app_state(
    mach_vm_address_t address,
    mach_vm_size_t size,
    uint32_t user_tag
) {
    static const mach_vm_address_t arena_bases[] = {
        UINT64_C(0x0000000140000000),
        UINT64_C(0x0000000150000000),
        UINT64_C(0x0000000160000000),
        UINT64_C(0x0000000170000000),
    };
    if (user_tag != VM_MEMORY_APPLICATION_SPECIFIC_1 || size == 0) {
        return 0;
    }
    uint64_t end = 0;
    if (!continuum_add_u64(address, size, &end)) {
        return 0;
    }
    for (size_t index = 0;
         index < sizeof(arena_bases) / sizeof(arena_bases[0]);
         index += 1) {
        const uint64_t arena_end = arena_bases[index] + UINT64_C(0x10000000);
        if (address >= arena_bases[index] && end <= arena_end) {
            return 1;
        }
    }
    return 0;
}

static int continuum_region_is_app_state_metadata(
    mach_vm_address_t address,
    mach_vm_size_t size,
    uint32_t user_tag
) {
    static const mach_vm_address_t arena_bases[] = {
        UINT64_C(0x0000000140000000),
        UINT64_C(0x0000000150000000),
        UINT64_C(0x0000000160000000),
        UINT64_C(0x0000000170000000),
    };
    if (user_tag != VM_MEMORY_APPLICATION_SPECIFIC_2
        || size != UINT64_C(0x00100000)) {
        return 0;
    }
    for (size_t index = 0;
         index < sizeof(arena_bases) / sizeof(arena_bases[0]);
         index += 1) {
        if (address == arena_bases[index]
                + UINT64_C(0x10000000)
                - UINT64_C(0x00100000)) {
            return 1;
        }
    }
    return 0;
}

static void continuum_hash_vm_region(
    uint64_t *hash,
    mach_vm_address_t address,
    mach_vm_size_t region_size,
    const vm_region_submap_info_data_64_t *info
) {
    if (hash == NULL || info == NULL) {
        return;
    }
    continuum_hash_u64(hash, address);
    continuum_hash_u64(hash, region_size);
    continuum_hash_u64(hash, (uint64_t)(uint32_t)info->protection);
    continuum_hash_u64(hash, (uint64_t)(uint32_t)info->max_protection);
    continuum_hash_u64(hash, (uint64_t)(uint32_t)info->inheritance);
    continuum_hash_u64(
        hash,
        continuum_canonical_share_mode(info->share_mode)
    );
    continuum_hash_u64(hash, info->user_tag);
}

static continuum_status continuum_read_process_identity(
    int32_t process_id,
    continuum_remote_identity *out_identity
) {
    if (process_id <= 0 || out_identity == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }

    struct proc_bsdinfo bsd_info;
    memset(&bsd_info, 0, sizeof(bsd_info));
    int result = proc_pidinfo(
        process_id,
        PROC_PIDTBSDINFO,
        0,
        &bsd_info,
        (int)sizeof(bsd_info)
    );
    if (result != (int)sizeof(bsd_info)) {
        return CONTINUUM_STATUS_TARGET_EXITED;
    }

    char executable_path[PROC_PIDPATHINFO_MAXSIZE];
    memset(executable_path, 0, sizeof(executable_path));
    int path_length = proc_pidpath(
        process_id,
        executable_path,
        (uint32_t)sizeof(executable_path)
    );
    if (path_length <= 0) {
        return CONTINUUM_STATUS_TARGET_EXITED;
    }

    struct stat executable_stat;
    memset(&executable_stat, 0, sizeof(executable_stat));
    if (stat(executable_path, &executable_stat) != 0) {
        return CONTINUUM_STATUS_TARGET_EXITED;
    }

    continuum_remote_identity identity;
    memset(&identity, 0, sizeof(identity));
    identity.process_id = process_id;
    identity.start_seconds = (uint64_t)bsd_info.pbi_start_tvsec;
    identity.start_microseconds = (uint64_t)bsd_info.pbi_start_tvusec;
    identity.executable_device = (uint64_t)executable_stat.st_dev;
    identity.executable_inode = (uint64_t)executable_stat.st_ino;
    *out_identity = identity;
    return CONTINUUM_STATUS_OK;
}

static continuum_status continuum_validate_session_identity(
    const continuum_remote_session *session
) {
    if (session == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }

    continuum_remote_identity current;
    continuum_status status = continuum_read_process_identity(
        session->identity.process_id,
        &current
    );
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }
    if (continuum_identity_equal(&session->identity, &current)) {
        return CONTINUUM_STATUS_OK;
    }
    if (getenv("CONTINUUM_CAPTURE_TRACE") != NULL) {
        fprintf(
            stderr,
            "continuum identity pid=%d expected-start=%llu.%06llu "
            "actual-start=%llu.%06llu expected-executable=%llu:%llu "
            "actual-executable=%llu:%llu\n",
            session->identity.process_id,
            (unsigned long long)session->identity.start_seconds,
            (unsigned long long)session->identity.start_microseconds,
            (unsigned long long)current.start_seconds,
            (unsigned long long)current.start_microseconds,
            (unsigned long long)session->identity.executable_device,
            (unsigned long long)session->identity.executable_inode,
            (unsigned long long)current.executable_device,
            (unsigned long long)current.executable_inode
        );
    }
    return CONTINUUM_STATUS_PROCESS_IDENTITY_CHANGED;
}

static continuum_status continuum_query_region(
    mach_port_t task,
    mach_vm_address_t requested_address,
    mach_vm_size_t requested_length,
    continuum_remote_region_descriptor *out_descriptor
) {
    if (task == MACH_PORT_NULL || requested_address == 0
        || requested_length == 0 || out_descriptor == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }

    uint64_t requested_end = 0;
    if (!continuum_add_u64(requested_address, requested_length, &requested_end)) {
        return CONTINUUM_STATUS_RANGE_ERROR;
    }

    mach_vm_address_t query_address = requested_address;
    natural_t depth = 0;
    for (;;) {
        mach_vm_size_t region_size = 0;
        vm_region_submap_info_data_64_t info;
        memset(&info, 0, sizeof(info));
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t result = mach_vm_region_recurse(
            task,
            &query_address,
            &region_size,
            &depth,
            (vm_region_recurse_info_t)&info,
            &count
        );
        if (result == KERN_INVALID_ADDRESS) {
            return CONTINUUM_STATUS_REGION_UNMAPPED;
        }
        if (result != KERN_SUCCESS) {
            return CONTINUUM_STATUS_MACH_ERROR;
        }
        if (info.is_submap) {
            depth += 1;
            continue;
        }
        if (region_size == 0 || query_address > requested_address) {
            return CONTINUUM_STATUS_REGION_UNMAPPED;
        }

        uint64_t region_end = 0;
        if (!continuum_add_u64(query_address, region_size, &region_end)) {
            return CONTINUUM_STATUS_RANGE_ERROR;
        }
        if (requested_end > region_end) {
            return CONTINUUM_STATUS_REGION_UNMAPPED;
        }
        if ((info.protection & (VM_PROT_READ | VM_PROT_WRITE))
            != (VM_PROT_READ | VM_PROT_WRITE)) {
            return CONTINUUM_STATUS_REGION_PROTECTION_CHANGED;
        }
        if (!continuum_is_private_or_cow_share_mode(info.share_mode)) {
            return CONTINUUM_STATUS_REGION_NOT_PRIVATE;
        }

        continuum_remote_region_descriptor descriptor;
        memset(&descriptor, 0, sizeof(descriptor));
        descriptor.address = requested_address;
        descriptor.length = requested_length;
        descriptor.mapping_address = query_address;
        descriptor.mapping_length = region_size;
        descriptor.protection = info.protection;
        descriptor.maximum_protection = info.max_protection;
        descriptor.share_mode = info.share_mode;
        *out_descriptor = descriptor;
        return CONTINUUM_STATUS_OK;
    }
}

static continuum_status continuum_validate_region_unchanged(
    const continuum_remote_region_descriptor *expected,
    const continuum_remote_region_descriptor *current
) {
    if (expected == NULL || current == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    if (expected->address != current->address
        || expected->length != current->length
        || expected->mapping_address != current->mapping_address
        || expected->mapping_length != current->mapping_length) {
        return CONTINUUM_STATUS_REGION_MAPPING_CHANGED;
    }
    if (expected->protection != current->protection
        || expected->maximum_protection != current->maximum_protection) {
        return CONTINUUM_STATUS_REGION_PROTECTION_CHANGED;
    }
    if (!continuum_is_private_or_cow_share_mode(expected->share_mode)
        || !continuum_is_private_or_cow_share_mode(current->share_mode)) {
        return CONTINUUM_STATUS_REGION_NOT_PRIVATE;
    }
    return CONTINUUM_STATUS_OK;
}

static continuum_status continuum_read_task_bytes(
    mach_port_t task,
    mach_vm_address_t address,
    mach_vm_size_t length,
    void *destination
) {
    if (task == MACH_PORT_NULL || address == 0 || length == 0
        || destination == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }

    mach_vm_size_t copied = 0;
    kern_return_t result = mach_vm_read_overwrite(
        task,
        address,
        length,
        (mach_vm_address_t)(uintptr_t)destination,
        &copied
    );
    if (result != KERN_SUCCESS) {
        return CONTINUUM_STATUS_MACH_ERROR;
    }
    return copied == length
        ? CONTINUUM_STATUS_OK
        : CONTINUUM_STATUS_SHORT_READ;
}

static continuum_status continuum_read_task_cstring(
    mach_port_t task,
    mach_vm_address_t address,
    char *destination,
    size_t capacity
) {
    if (task == MACH_PORT_NULL || address == 0 || destination == NULL
        || capacity < 2) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }

    size_t offset = 0;
    while (offset < capacity - 1) {
        uint64_t current_address = 0;
        if (!continuum_add_u64(address, (uint64_t)offset, &current_address)) {
            return CONTINUUM_STATUS_RANGE_ERROR;
        }
        mach_vm_address_t mapping_address = current_address;
        mach_vm_size_t mapping_length = 0;
        vm_region_submap_info_data_64_t info;
        natural_t depth = 0;
        kern_return_t result;
        for (;;) {
            memset(&info, 0, sizeof(info));
            mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
            result = mach_vm_region_recurse(
                task,
                &mapping_address,
                &mapping_length,
                &depth,
                (vm_region_recurse_info_t)&info,
                &count
            );
            if (result != KERN_SUCCESS || !info.is_submap) {
                break;
            }
            depth += 1;
        }
        if (result != KERN_SUCCESS || mapping_address > current_address
            || mapping_length == 0
            || (info.protection & VM_PROT_READ) == 0) {
            return result == KERN_SUCCESS
                ? CONTINUUM_STATUS_REGION_UNMAPPED
                : CONTINUUM_STATUS_MACH_ERROR;
        }
        uint64_t mapping_end = 0;
        if (!continuum_add_u64(
                mapping_address,
                mapping_length,
                &mapping_end
            ) || mapping_end <= current_address) {
            return CONTINUUM_STATUS_RANGE_ERROR;
        }

        size_t remaining_capacity = capacity - 1 - offset;
        uint64_t available = mapping_end - current_address;
        size_t chunk = available < remaining_capacity
            ? (size_t)available
            : remaining_capacity;
        if (chunk > 256U) {
            chunk = 256U;
        }
        mach_vm_size_t copied = 0;
        result = mach_vm_read_overwrite(
            task,
            current_address,
            chunk,
            (mach_vm_address_t)(uintptr_t)(destination + offset),
            &copied
        );
        if (result != KERN_SUCCESS) {
            return CONTINUUM_STATUS_MACH_ERROR;
        }
        if (copied != chunk) {
            return CONTINUUM_STATUS_SHORT_READ;
        }
        for (size_t index = 0; index < chunk; index += 1) {
            if (destination[offset + index] == '\0') {
                return CONTINUUM_STATUS_OK;
            }
        }
        offset += chunk;
    }
    destination[capacity - 1] = '\0';
    return CONTINUUM_STATUS_RANGE_ERROR;
}

static continuum_status continuum_copy_local_image_uuid(
    const struct mach_header_64 *header,
    uint8_t out_uuid[16]
) {
    if (header == NULL || out_uuid == NULL || header->magic != MH_MAGIC_64
        || header->ncmds == 0 || header->ncmds > UINT32_C(65536)
        || header->sizeofcmds < sizeof(struct load_command)
        || header->sizeofcmds > UINT32_C(64 * 1024 * 1024)) {
        return CONTINUUM_STATUS_VALIDATION_FAILED;
    }

    const uint8_t *commands = (const uint8_t *)header + sizeof(*header);
    size_t offset = 0;
    int found_uuid = 0;
    for (uint32_t index = 0; index < header->ncmds; index += 1) {
        if (offset > header->sizeofcmds - sizeof(struct load_command)) {
            return CONTINUUM_STATUS_RANGE_ERROR;
        }
        const struct load_command *command =
            (const struct load_command *)(commands + offset);
        if (command->cmdsize < sizeof(struct load_command)
            || command->cmdsize > header->sizeofcmds - offset) {
            return CONTINUUM_STATUS_RANGE_ERROR;
        }
        if (command->cmd == LC_UUID) {
            if (found_uuid
                || command->cmdsize < sizeof(struct uuid_command)) {
                return CONTINUUM_STATUS_VALIDATION_FAILED;
            }
            const struct uuid_command *uuid =
                (const struct uuid_command *)command;
            memcpy(out_uuid, uuid->uuid, sizeof(uuid->uuid));
            found_uuid = 1;
        }
        offset += command->cmdsize;
    }
    return found_uuid
        ? CONTINUUM_STATUS_OK
        : CONTINUUM_STATUS_VALIDATION_FAILED;
}

static continuum_status continuum_copy_remote_image_uuid(
    mach_port_t task,
    mach_vm_address_t image_base,
    uint8_t out_uuid[16]
) {
    if (task == MACH_PORT_NULL || image_base == 0 || out_uuid == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    struct mach_header_64 header;
    memset(&header, 0, sizeof(header));
    continuum_status status = continuum_read_task_bytes(
        task,
        image_base,
        sizeof(header),
        &header
    );
    if (status != CONTINUUM_STATUS_OK || header.magic != MH_MAGIC_64
        || header.filetype != MH_DYLIB || header.ncmds == 0
        || header.ncmds > UINT32_C(65536)
        || header.sizeofcmds < sizeof(struct load_command)
        || header.sizeofcmds > UINT32_C(64 * 1024 * 1024)) {
        return status == CONTINUUM_STATUS_OK
            ? CONTINUUM_STATUS_VALIDATION_FAILED
            : status;
    }
    uint64_t commands_address = 0;
    if (!continuum_add_u64(
            image_base,
            sizeof(header),
            &commands_address
        )) {
        return CONTINUUM_STATUS_RANGE_ERROR;
    }
    uint8_t *commands = malloc(header.sizeofcmds);
    if (commands == NULL) {
        return CONTINUUM_STATUS_OUT_OF_MEMORY;
    }
    status = continuum_read_task_bytes(
        task,
        commands_address,
        header.sizeofcmds,
        commands
    );
    size_t offset = 0;
    int found_uuid = 0;
    for (uint32_t index = 0;
         status == CONTINUUM_STATUS_OK && index < header.ncmds;
         index += 1) {
        if (offset > header.sizeofcmds - sizeof(struct load_command)) {
            status = CONTINUUM_STATUS_RANGE_ERROR;
            break;
        }
        struct load_command *command =
            (struct load_command *)(commands + offset);
        if (command->cmdsize < sizeof(struct load_command)
            || command->cmdsize > header.sizeofcmds - offset) {
            status = CONTINUUM_STATUS_RANGE_ERROR;
            break;
        }
        if (command->cmd == LC_UUID) {
            if (found_uuid
                || command->cmdsize < sizeof(struct uuid_command)) {
                status = CONTINUUM_STATUS_VALIDATION_FAILED;
                break;
            }
            struct uuid_command *uuid = (struct uuid_command *)command;
            memcpy(out_uuid, uuid->uuid, sizeof(uuid->uuid));
            found_uuid = 1;
        }
        offset += command->cmdsize;
    }
    free(commands);
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }
    return found_uuid
        ? CONTINUUM_STATUS_OK
        : CONTINUUM_STATUS_VALIDATION_FAILED;
}

continuum_status continuum_inspect_local_bootstrap_library(
    const char *library_path,
    continuum_bootstrap_identity *out_identity
) {
    if (library_path == NULL || library_path[0] == '\0'
        || out_identity == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    memset(out_identity, 0, sizeof(*out_identity));

    char expected_path[PATH_MAX];
    if (realpath(library_path, expected_path) == NULL) {
        return CONTINUUM_STATUS_VALIDATION_FAILED;
    }
    void *handle = dlopen(expected_path, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        return CONTINUUM_STATUS_VALIDATION_FAILED;
    }
    continuum_status status = CONTINUUM_STATUS_VALIDATION_FAILED;
    void *symbol = dlsym(handle, "continuum_bootstrap_copy_and_trap");
    void *pthread_symbol = dlsym(
        handle, "continuum_bootstrap_prepare_pthreads_and_trap");
    void *pty_status_symbol = dlsym(
        handle, "continuum_bootstrap_pty_safepoint_report");
    void *descriptor_status_symbol = dlsym(
        handle, "continuum_bootstrap_descriptor_safepoint_report");
    Dl_info info;
    memset(&info, 0, sizeof(info));
    if (symbol == NULL || pthread_symbol == NULL || pty_status_symbol == NULL
        || descriptor_status_symbol == NULL
        || dladdr(symbol, &info) == 0
        || info.dli_fbase == NULL || info.dli_fname == NULL) {
        goto cleanup;
    }

    char loaded_path[PATH_MAX];
    if (realpath(info.dli_fname, loaded_path) == NULL
        || strcmp(expected_path, loaded_path) != 0) {
        goto cleanup;
    }

    uintptr_t copy_address = (uintptr_t)symbol;
#if __has_feature(ptrauth_calls)
    copy_address = (uintptr_t)ptrauth_strip(
        symbol,
        ptrauth_key_function_pointer
    );
#endif
    uintptr_t pthread_prepare_address = (uintptr_t)pthread_symbol;
#if __has_feature(ptrauth_calls)
    pthread_prepare_address = (uintptr_t)ptrauth_strip(
        pthread_symbol,
        ptrauth_key_function_pointer
    );
#endif
    uintptr_t pty_status_address = (uintptr_t)pty_status_symbol;
    uintptr_t descriptor_status_address =
        (uintptr_t)descriptor_status_symbol;
    uintptr_t image_base = (uintptr_t)info.dli_fbase;
    Dl_info pthread_info;
    Dl_info pty_status_info;
    Dl_info descriptor_status_info;
    memset(&pthread_info, 0, sizeof(pthread_info));
    memset(&pty_status_info, 0, sizeof(pty_status_info));
    memset(&descriptor_status_info, 0, sizeof(descriptor_status_info));
    if (copy_address <= image_base || pthread_prepare_address <= image_base
        || pty_status_address <= image_base
        || descriptor_status_address <= image_base
        || dladdr(pthread_symbol, &pthread_info) == 0
        || dladdr(pty_status_symbol, &pty_status_info) == 0
        || dladdr(descriptor_status_symbol, &descriptor_status_info) == 0
        || pthread_info.dli_fbase != info.dli_fbase
        || pty_status_info.dli_fbase != info.dli_fbase
        || descriptor_status_info.dli_fbase != info.dli_fbase) {
        goto cleanup;
    }
    status = continuum_copy_local_image_uuid(
        (const struct mach_header_64 *)info.dli_fbase,
        out_identity->image_uuid
    );
    if (status != CONTINUUM_STATUS_OK) {
        goto cleanup;
    }
    out_identity->image_base = image_base;
    out_identity->copy_address = copy_address;
    out_identity->copy_offset = copy_address - image_base;
    out_identity->pthread_prepare_address = pthread_prepare_address;
    out_identity->pthread_prepare_offset =
        pthread_prepare_address - image_base;
    out_identity->pty_safepoint_status_address = pty_status_address;
    out_identity->pty_safepoint_status_offset =
        pty_status_address - image_base;
    out_identity->descriptor_safepoint_status_address =
        descriptor_status_address;
    out_identity->descriptor_safepoint_status_offset =
        descriptor_status_address - image_base;

cleanup:
    dlclose(handle);
    if (status != CONTINUUM_STATUS_OK) {
        memset(out_identity, 0, sizeof(*out_identity));
    }
    return status;
}

static int continuum_digest_update(
    CC_SHA256_CTX *context,
    const void *bytes,
    size_t length
) {
    if (context == NULL || (bytes == NULL && length != 0)) {
        return 0;
    }
    const uint8_t *cursor = bytes;
    while (length > 0) {
        size_t chunk = length > UINT32_MAX ? UINT32_MAX : length;
        if (CC_SHA256_Update(context, cursor, (CC_LONG)chunk) != 1) {
            return 0;
        }
        cursor += chunk;
        length -= chunk;
    }
    return 1;
}

static int continuum_digest_u64(CC_SHA256_CTX *context, uint64_t value) {
    uint8_t encoded[8];
    for (size_t index = 0; index < sizeof(encoded); index += 1) {
        encoded[sizeof(encoded) - 1 - index] = (uint8_t)(value & UINT64_C(0xff));
        value >>= 8;
    }
    return continuum_digest_update(context, encoded, sizeof(encoded));
}

static int continuum_copy_code_directory_hash(
    const char *path,
    uint8_t out_hash[32],
    size_t *out_length
) {
    if (path == NULL || path[0] == '\0' || out_hash == NULL
        || out_length == NULL) {
        return 0;
    }
    *out_length = 0;
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        kCFAllocatorDefault,
        (const UInt8 *)path,
        (CFIndex)strlen(path),
        false
    );
    if (url == NULL) {
        return 0;
    }
    SecStaticCodeRef code = NULL;
    OSStatus security_status = SecStaticCodeCreateWithPath(
        url,
        kSecCSDefaultFlags,
        &code
    );
    CFRelease(url);
    if (security_status != errSecSuccess || code == NULL) {
        return 0;
    }

    security_status = SecStaticCodeCheckValidity(
        code,
        kSecCSStrictValidate,
        NULL
    );
    if (security_status != errSecSuccess) {
        CFRelease(code);
        return 0;
    }

    CFDictionaryRef information = NULL;
    security_status = SecCodeCopySigningInformation(
        code,
        kSecCSSigningInformation,
        &information
    );
    CFRelease(code);
    if (security_status != errSecSuccess || information == NULL) {
        return 0;
    }
    CFTypeRef value = CFDictionaryGetValue(information, kSecCodeInfoUnique);
    int copied = 0;
    if (value != NULL && CFGetTypeID(value) == CFDataGetTypeID()) {
        CFDataRef data = (CFDataRef)value;
        CFIndex length = CFDataGetLength(data);
        if (length > 0 && length <= 32) {
            CFDataGetBytes(
                data,
                CFRangeMake(0, length),
                out_hash
            );
            *out_length = (size_t)length;
            copied = 1;
        }
    }
    CFRelease(information);
    return copied;
}

static continuum_status continuum_digest_remote_range(
    mach_port_t task,
    mach_vm_address_t address,
    uint64_t length,
    CC_SHA256_CTX *context
) {
    if (task == MACH_PORT_NULL || address == 0 || length == 0
        || context == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    uint8_t *buffer = malloc(1024U * 1024U);
    if (buffer == NULL) {
        return CONTINUUM_STATUS_OUT_OF_MEMORY;
    }

    continuum_status status = CONTINUUM_STATUS_OK;
    uint64_t offset = 0;
    while (offset < length) {
        uint64_t current_address = 0;
        if (!continuum_add_u64(address, offset, &current_address)) {
            status = CONTINUUM_STATUS_RANGE_ERROR;
            break;
        }
        mach_vm_address_t mapping_address = current_address;
        mach_vm_size_t mapping_length = 0;
        vm_region_submap_info_data_64_t info;
        natural_t depth = 0;
        kern_return_t result;
        for (;;) {
            memset(&info, 0, sizeof(info));
            mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
            result = mach_vm_region_recurse(
                task,
                &mapping_address,
                &mapping_length,
                &depth,
                (vm_region_recurse_info_t)&info,
                &count
            );
            if (result != KERN_SUCCESS || !info.is_submap) {
                break;
            }
            depth += 1;
        }
        if (result != KERN_SUCCESS) {
            status = CONTINUUM_STATUS_MACH_ERROR;
            break;
        }
        if (mapping_address > current_address || mapping_length == 0
            || (info.protection & VM_PROT_READ) == 0) {
            status = CONTINUUM_STATUS_REGION_UNMAPPED;
            break;
        }
        uint64_t mapping_end = 0;
        if (!continuum_add_u64(
                mapping_address,
                mapping_length,
                &mapping_end
            ) || mapping_end <= current_address) {
            status = CONTINUUM_STATUS_RANGE_ERROR;
            break;
        }

        uint64_t remaining = length - offset;
        uint64_t available = mapping_end - current_address;
        size_t chunk = 1024U * 1024U;
        if (remaining < chunk) {
            chunk = (size_t)remaining;
        }
        if (available < chunk) {
            chunk = (size_t)available;
        }
        status = continuum_read_task_bytes(
            task,
            current_address,
            chunk,
            buffer
        );
        if (status != CONTINUUM_STATUS_OK
            || !continuum_digest_update(context, buffer, chunk)) {
            if (status == CONTINUUM_STATUS_OK) {
                status = CONTINUUM_STATUS_VALIDATION_FAILED;
            }
            break;
        }
        offset += chunk;
    }
    memset(buffer, 0, 1024U * 1024U);
    free(buffer);
    return status;
}

static continuum_status continuum_digest_remote_image_identity(
    mach_port_t task,
    const struct dyld_image_info *image,
    const uint8_t shared_cache_uuid[16],
    CC_SHA256_CTX *context
) {
    if (task == MACH_PORT_NULL || image == NULL || context == NULL
        || image->imageLoadAddress == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }

    mach_vm_address_t load_address =
        (mach_vm_address_t)(uintptr_t)image->imageLoadAddress;
    char path[PATH_MAX];
    memset(path, 0, sizeof(path));
    continuum_status status = image->imageFilePath == NULL
        ? CONTINUUM_STATUS_REGION_UNMAPPED
        : continuum_read_task_cstring(
            task,
            (mach_vm_address_t)(uintptr_t)image->imageFilePath,
            path,
            sizeof(path)
        );
    int has_path = status == CONTINUUM_STATUS_OK;
    if (!has_path) {
        pid_t process_id = 0;
        if (pid_for_task(task, &process_id) == KERN_SUCCESS
            && process_id > 0
            && proc_regionfilename(
                process_id,
                load_address,
                path,
                (uint32_t)sizeof(path)
            ) > 0) {
            has_path = 1;
        }
    }
    if (has_path) {
        char canonical_path[PATH_MAX];
        if (realpath(path, canonical_path) != NULL) {
            strlcpy(path, canonical_path, sizeof(path));
        }
    }
    size_t path_length = has_path ? strlen(path) : 0;
    if (!continuum_digest_u64(context, has_path ? 1 : 0)
        || !continuum_digest_u64(context, path_length)
        || (has_path
            && !continuum_digest_update(context, path, path_length))) {
        return CONTINUUM_STATUS_VALIDATION_FAILED;
    }
    status = CONTINUUM_STATUS_OK;
    int has_shared_cache_uuid = 0;
    for (size_t index = 0; index < 16; index += 1) {
        has_shared_cache_uuid |= shared_cache_uuid[index] != 0;
    }
    uint64_t shared_region_end = 0;
    int in_shared_region = continuum_add_u64(
            SHARED_REGION_BASE,
            SHARED_REGION_SIZE,
            &shared_region_end
        ) && load_address >= SHARED_REGION_BASE
        && load_address < shared_region_end;
    int in_shared_cache = (has_path
            && (_dyld_shared_cache_contains_path(path)
                || strstr(path, "dyld_shared_cache") != NULL))
        || (has_shared_cache_uuid && in_shared_region);
    struct mach_header_64 header;
    memset(&header, 0, sizeof(header));
    status = continuum_read_task_bytes(
        task,
        load_address,
        sizeof(header),
        &header
    );
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }
    if (header.magic != MH_MAGIC_64 || header.ncmds == 0
        || header.ncmds > UINT32_C(65536)
        || header.sizeofcmds < sizeof(struct load_command)
        || header.sizeofcmds > UINT32_C(64 * 1024 * 1024)) {
        return CONTINUUM_STATUS_VALIDATION_FAILED;
    }
    uint64_t commands_address = 0;
    if (!continuum_add_u64(
            load_address,
            sizeof(header),
            &commands_address
        )) {
        return CONTINUUM_STATUS_RANGE_ERROR;
    }
    uint8_t *commands = malloc(header.sizeofcmds);
    if (commands == NULL) {
        return CONTINUUM_STATUS_OUT_OF_MEMORY;
    }
    status = continuum_read_task_bytes(
        task,
        commands_address,
        header.sizeofcmds,
        commands
    );
    if (status != CONTINUUM_STATUS_OK) {
        free(commands);
        return status;
    }

    uint8_t image_uuid[16];
    memset(image_uuid, 0, sizeof(image_uuid));
    int found_uuid = 0;
    int found_base_segment = 0;
    uint64_t image_slide = 0;
    size_t offset = 0;
    for (uint32_t index = 0; index < header.ncmds; index += 1) {
        if (offset > header.sizeofcmds - sizeof(struct load_command)) {
            status = CONTINUUM_STATUS_RANGE_ERROR;
            break;
        }
        struct load_command *command =
            (struct load_command *)(commands + offset);
        if (command->cmdsize < sizeof(struct load_command)
            || command->cmdsize > header.sizeofcmds - offset) {
            status = CONTINUUM_STATUS_RANGE_ERROR;
            break;
        }
        if (command->cmd == LC_UUID) {
            if (found_uuid
                || command->cmdsize < sizeof(struct uuid_command)) {
                status = CONTINUUM_STATUS_VALIDATION_FAILED;
                break;
            }
            struct uuid_command *uuid = (struct uuid_command *)command;
            memcpy(image_uuid, uuid->uuid, sizeof(image_uuid));
            found_uuid = 1;
        } else if (command->cmd == LC_SEGMENT_64) {
            if (command->cmdsize < sizeof(struct segment_command_64)) {
                status = CONTINUUM_STATUS_RANGE_ERROR;
                break;
            }
            struct segment_command_64 *segment =
                (struct segment_command_64 *)command;
            if (segment->fileoff == 0
                && segment->filesize >= sizeof(header) + header.sizeofcmds) {
                if (found_base_segment || load_address < segment->vmaddr) {
                    status = CONTINUUM_STATUS_VALIDATION_FAILED;
                    break;
                }
                image_slide = load_address - segment->vmaddr;
                found_base_segment = 1;
            }
        }
        offset += command->cmdsize;
    }
    if (status != CONTINUUM_STATUS_OK
        || (!in_shared_cache && (!found_uuid || !found_base_segment))) {
        free(commands);
        return status == CONTINUUM_STATUS_OK
            ? CONTINUUM_STATUS_VALIDATION_FAILED
            : status;
    }

    if (!continuum_digest_u64(context, (uint64_t)(uint32_t)header.cputype)
        || !continuum_digest_u64(
            context,
            (uint64_t)(uint32_t)header.cpusubtype
        ) || !continuum_digest_u64(context, header.filetype)
        || !continuum_digest_u64(context, found_uuid ? 1 : 0)
        || (found_uuid
            && !continuum_digest_update(
                context,
                image_uuid,
                sizeof(image_uuid)
            ))) {
        free(commands);
        return CONTINUUM_STATUS_VALIDATION_FAILED;
    }

    uint64_t identity_kind = in_shared_cache ? 1 : 2;
    if (!continuum_digest_u64(context, identity_kind)) {
        free(commands);
        return CONTINUUM_STATUS_VALIDATION_FAILED;
    }
    if (in_shared_cache) {
        status = continuum_digest_update(
            context,
            shared_cache_uuid,
            16
        ) ? CONTINUUM_STATUS_OK : CONTINUUM_STATUS_VALIDATION_FAILED;
        free(commands);
        return status;
    }

    uint8_t code_hash[32];
    memset(code_hash, 0, sizeof(code_hash));
    size_t code_hash_length = 0;
    int has_code_hash = has_path && continuum_copy_code_directory_hash(
            path,
            code_hash,
            &code_hash_length
        );
    if (!continuum_digest_u64(context, has_code_hash ? code_hash_length : 0)
        || (has_code_hash
            && !continuum_digest_update(
                context,
                code_hash,
                code_hash_length
            ))) {
        free(commands);
        return CONTINUUM_STATUS_VALIDATION_FAILED;
    }

    int immutable_segment_count = 0;
    offset = 0;
    for (uint32_t index = 0; index < header.ncmds; index += 1) {
        struct load_command *command =
            (struct load_command *)(commands + offset);
        if (command->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *segment =
                (struct segment_command_64 *)command;
            if (segment->filesize > 0
                && segment->filesize <= segment->vmsize
                && strncmp(segment->segname, "__TEXT", 6) == 0
                && (segment->initprot & VM_PROT_READ) != 0
                && (segment->initprot & VM_PROT_WRITE) == 0) {
                uint64_t remote_address = 0;
                if (!continuum_add_u64(
                        image_slide,
                        segment->vmaddr,
                        &remote_address
                    ) || !continuum_digest_update(
                        context,
                        segment->segname,
                        sizeof(segment->segname)
                    ) || !continuum_digest_u64(context, segment->vmaddr)
                    || !continuum_digest_u64(context, segment->vmsize)
                    || !continuum_digest_u64(context, segment->filesize)
                    || !continuum_digest_u64(
                        context,
                        (uint64_t)(uint32_t)segment->initprot
                    ) || !continuum_digest_u64(
                        context,
                        (uint64_t)(uint32_t)segment->maxprot
                    )) {
                    status = CONTINUUM_STATUS_RANGE_ERROR;
                    break;
                }
                status = continuum_digest_remote_range(
                    task,
                    remote_address,
                    segment->filesize,
                    context
                );
                if (status != CONTINUUM_STATUS_OK) {
                    break;
                }
                immutable_segment_count += 1;
            }
        }
        offset += command->cmdsize;
    }
    memset(code_hash, 0, sizeof(code_hash));
    free(commands);
    return status == CONTINUUM_STATUS_OK && immutable_segment_count > 0
        ? CONTINUUM_STATUS_OK
        : (status == CONTINUUM_STATUS_OK
            ? CONTINUUM_STATUS_VALIDATION_FAILED
            : status);
}

static continuum_status continuum_capture_image_layout_digest(
    mach_port_t task,
    continuum_sha256_digest *out_digest,
    int allow_empty
) {
    if (task == MACH_PORT_NULL || out_digest == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    memset(out_digest, 0, sizeof(*out_digest));

    task_dyld_info_data_t dyld_info;
    memset(&dyld_info, 0, sizeof(dyld_info));
    mach_msg_type_number_t dyld_info_count = TASK_DYLD_INFO_COUNT;
    kern_return_t result = task_info(
        task,
        TASK_DYLD_INFO,
        (task_info_t)&dyld_info,
        &dyld_info_count
    );
    if (result != KERN_SUCCESS || dyld_info.all_image_info_addr == 0) {
        return CONTINUUM_STATUS_MACH_ERROR;
    }

    struct dyld_all_image_infos all_images;
    memset(&all_images, 0, sizeof(all_images));
    continuum_status status = continuum_read_task_bytes(
        task,
        dyld_info.all_image_info_addr,
        sizeof(all_images),
        &all_images
    );
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }
    if (all_images.infoArrayCount > UINT32_C(1048576)
        || (all_images.infoArrayCount > 0
            && all_images.infoArray == NULL)
        || (all_images.infoArrayCount == 0 && !allow_empty)) {
        return CONTINUUM_STATUS_RANGE_ERROR;
    }

    CC_SHA256_CTX context;
    static const char domain[] = "CONTINUUM_IMAGE_LAYOUT_V2";
    if (CC_SHA256_Init(&context) != 1
        || !continuum_digest_update(&context, domain, sizeof(domain) - 1)
        || !continuum_digest_u64(&context, all_images.infoArrayCount)
        || !continuum_digest_u64(
            &context,
            (uint64_t)(uintptr_t)all_images.dyldImageLoadAddress
        ) || !continuum_digest_u64(
            &context,
            (uint64_t)all_images.sharedCacheSlide
        ) || !continuum_digest_u64(
            &context,
            (uint64_t)(uintptr_t)all_images.sharedCacheBaseAddress
        ) || !continuum_digest_update(
            &context,
            all_images.sharedCacheUUID,
            sizeof(all_images.sharedCacheUUID)
        )) {
        return CONTINUUM_STATUS_VALIDATION_FAILED;
    }

    if (all_images.infoArrayCount == 0) {
        return CC_SHA256_Final(out_digest->bytes, &context) == 1
            ? CONTINUUM_STATUS_OK
            : CONTINUUM_STATUS_VALIDATION_FAILED;
    }

    size_t byte_count =
        (size_t)all_images.infoArrayCount * sizeof(struct dyld_image_info);
    struct dyld_image_info *entries = malloc(byte_count);
    if (entries == NULL) {
        return CONTINUUM_STATUS_OUT_OF_MEMORY;
    }
    status = continuum_read_task_bytes(
        task,
        (mach_vm_address_t)(uintptr_t)all_images.infoArray,
        byte_count,
        entries
    );
    if (status == CONTINUUM_STATUS_OK
        && getenv("CONTINUUM_CAPTURE_TRACE") != NULL) {
        fprintf(
            stderr,
            "continuum image-layout count=%u dyld=0x%llx cache=0x%llx slide=0x%llx\n",
            all_images.infoArrayCount,
            (unsigned long long)(uintptr_t)all_images.dyldImageLoadAddress,
            (unsigned long long)(uintptr_t)all_images.sharedCacheBaseAddress,
            (unsigned long long)all_images.sharedCacheSlide
        );
    }
    if (status == CONTINUUM_STATUS_OK) {
        for (uint32_t index = 0;
             index < all_images.infoArrayCount;
             index += 1) {
            if (!continuum_digest_u64(
                    &context,
                    (uint64_t)(uintptr_t)entries[index].imageLoadAddress
                ) || !continuum_digest_u64(
                    &context,
                    (uint64_t)entries[index].imageFileModDate
                )) {
                status = CONTINUUM_STATUS_VALIDATION_FAILED;
                break;
            }
            status = continuum_digest_remote_image_identity(
                task,
                &entries[index],
                all_images.sharedCacheUUID,
                &context
            );
            if (status != CONTINUUM_STATUS_OK) {
                break;
            }
        }
    }
    free(entries);
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }
    return CC_SHA256_Final(out_digest->bytes, &context) == 1
        ? CONTINUUM_STATUS_OK
        : CONTINUUM_STATUS_VALIDATION_FAILED;
}

static continuum_status continuum_capture_main_entry_address(
    mach_port_t task,
    mach_vm_address_t *out_entry_address
) {
    if (task == MACH_PORT_NULL || out_entry_address == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    *out_entry_address = 0;

    task_dyld_info_data_t dyld_info;
    memset(&dyld_info, 0, sizeof(dyld_info));
    mach_msg_type_number_t dyld_info_count = TASK_DYLD_INFO_COUNT;
    kern_return_t result = task_info(
        task,
        TASK_DYLD_INFO,
        (task_info_t)&dyld_info,
        &dyld_info_count
    );
    if (result != KERN_SUCCESS || dyld_info.all_image_info_addr == 0) {
        return CONTINUUM_STATUS_MACH_ERROR;
    }

    struct dyld_all_image_infos all_images;
    memset(&all_images, 0, sizeof(all_images));
    continuum_status status = continuum_read_task_bytes(
        task,
        dyld_info.all_image_info_addr,
        sizeof(all_images),
        &all_images
    );
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }
    if (all_images.infoArrayCount == 0
        || all_images.infoArrayCount > UINT32_C(1048576)
        || all_images.infoArray == NULL) {
        return CONTINUUM_STATUS_RANGE_ERROR;
    }

    size_t image_bytes =
        (size_t)all_images.infoArrayCount * sizeof(struct dyld_image_info);
    struct dyld_image_info *images = malloc(image_bytes);
    if (images == NULL) {
        return CONTINUUM_STATUS_OUT_OF_MEMORY;
    }
    status = continuum_read_task_bytes(
        task,
        (mach_vm_address_t)(uintptr_t)all_images.infoArray,
        image_bytes,
        images
    );
    if (status != CONTINUUM_STATUS_OK) {
        free(images);
        return status;
    }

    for (uint32_t image_index = 0;
         image_index < all_images.infoArrayCount;
         image_index += 1) {
        mach_vm_address_t load_address =
            (mach_vm_address_t)(uintptr_t)images[image_index].imageLoadAddress;
        struct mach_header_64 header;
        memset(&header, 0, sizeof(header));
        status = continuum_read_task_bytes(
            task,
            load_address,
            sizeof(header),
            &header
        );
        if (status != CONTINUUM_STATUS_OK
            || header.magic != MH_MAGIC_64
            || header.filetype != MH_EXECUTE) {
            continue;
        }
        if (header.ncmds == 0 || header.ncmds > UINT32_C(65536)
            || header.sizeofcmds < sizeof(struct load_command)
            || header.sizeofcmds > UINT32_C(64 * 1024 * 1024)) {
            status = CONTINUUM_STATUS_RANGE_ERROR;
            break;
        }

        uint8_t *commands = malloc(header.sizeofcmds);
        if (commands == NULL) {
            status = CONTINUUM_STATUS_OUT_OF_MEMORY;
            break;
        }
        uint64_t commands_address = 0;
        if (!continuum_add_u64(
                load_address,
                sizeof(header),
                &commands_address
            )) {
            free(commands);
            status = CONTINUUM_STATUS_RANGE_ERROR;
            break;
        }
        status = continuum_read_task_bytes(
            task,
            commands_address,
            header.sizeofcmds,
            commands
        );
        if (status != CONTINUUM_STATUS_OK) {
            free(commands);
            break;
        }

        size_t offset = 0;
        for (uint32_t command_index = 0;
             command_index < header.ncmds;
             command_index += 1) {
            if (offset > header.sizeofcmds - sizeof(struct load_command)) {
                status = CONTINUUM_STATUS_RANGE_ERROR;
                break;
            }
            struct load_command *command =
                (struct load_command *)(commands + offset);
            if (command->cmdsize < sizeof(struct load_command)
                || command->cmdsize > header.sizeofcmds - offset) {
                status = CONTINUUM_STATUS_RANGE_ERROR;
                break;
            }
            if (command->cmd == LC_MAIN) {
                if (command->cmdsize < sizeof(struct entry_point_command)) {
                    status = CONTINUUM_STATUS_RANGE_ERROR;
                    break;
                }
                struct entry_point_command *entry =
                    (struct entry_point_command *)command;
                if (!continuum_add_u64(
                        load_address,
                        entry->entryoff,
                        out_entry_address
                    )) {
                    status = CONTINUUM_STATUS_RANGE_ERROR;
                } else {
                    status = CONTINUUM_STATUS_OK;
                }
                break;
            }
            offset += command->cmdsize;
        }
        free(commands);
        if (*out_entry_address != 0 || status != CONTINUUM_STATUS_OK) {
            break;
        }
    }
    free(images);
    return *out_entry_address == 0 && status == CONTINUUM_STATUS_OK
        ? CONTINUUM_STATUS_VALIDATION_FAILED
        : status;
}

static continuum_status continuum_wait_for_child_signal_stop(
    int32_t process_id,
    uint64_t deadline,
    int expected_signal
) {
    int wait_status = 0;
    for (;;) {
        pid_t waited = waitpid(
            process_id,
            &wait_status,
            WUNTRACED | WNOHANG
        );
        if (waited == process_id) {
            if (WIFSTOPPED(wait_status)) {
                return WSTOPSIG(wait_status) == expected_signal
                    ? CONTINUUM_STATUS_OK
                    : CONTINUUM_STATUS_SUSPEND_FAILED;
            }
            if (WIFEXITED(wait_status) || WIFSIGNALED(wait_status)) {
                return CONTINUUM_STATUS_TARGET_EXITED;
            }
        } else if (waited < 0 && errno != EINTR) {
            return errno == ECHILD
                ? CONTINUUM_STATUS_TARGET_EXITED
                : CONTINUUM_STATUS_SUSPEND_FAILED;
        }
        if (clock_gettime_nsec_np(CLOCK_MONOTONIC) >= deadline) {
            return CONTINUUM_STATUS_SUSPEND_FAILED;
        }
        usleep(1000);
    }
}

static continuum_status continuum_advance_bootstrap_stopped_process_to_entry(
    int32_t process_id,
    uint32_t timeout_milliseconds,
    int already_traced,
    int broker_channel
) {
#if !defined(__arm64__)
    (void)process_id;
    (void)timeout_milliseconds;
    return CONTINUUM_STATUS_UNSUPPORTED_ARCHITECTURE;
#else
    continuum_status status = CONTINUUM_STATUS_OK;

    mach_port_t task = MACH_PORT_NULL;
    kern_return_t result = task_for_pid(
        mach_task_self(),
        process_id,
        &task
    );
    if (result != KERN_SUCCESS || task == MACH_PORT_NULL) {
        return CONTINUUM_STATUS_ACCESS_DENIED;
    }

    mach_vm_address_t entry_address = 0;
    status = continuum_capture_main_entry_address(task, &entry_address);
    if (status != CONTINUUM_STATUS_OK) {
        mach_port_deallocate(mach_task_self(), task);
        return status;
    }

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    int attach_result = already_traced
        ? 0
        : ptrace(PT_ATTACH, process_id, NULL, 0);
#pragma clang diagnostic pop
    if (attach_result != 0) {
        mach_port_deallocate(mach_task_self(), task);
        return CONTINUUM_STATUS_ACCESS_DENIED;
    }
    uint64_t timeout_nanoseconds =
        (uint64_t)timeout_milliseconds * UINT64_C(1000000);
    uint64_t now = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    if (UINT64_MAX - now < timeout_nanoseconds) {
        mach_port_deallocate(mach_task_self(), task);
        return CONTINUUM_STATUS_RANGE_ERROR;
    }
    uint64_t deadline = now + timeout_nanoseconds;
    if (!already_traced) {
        status = continuum_wait_for_child_signal_stop(
            process_id,
            deadline,
            SIGSTOP
        );
        if (status != CONTINUUM_STATUS_OK) {
            mach_port_deallocate(mach_task_self(), task);
            return status;
        }
    }

    thread_act_array_t threads = NULL;
    mach_msg_type_number_t thread_count = 0;
    result = task_threads(task, &threads, &thread_count);
    if (result != KERN_SUCCESS || thread_count != 1) {
        if (threads != NULL) {
            for (mach_msg_type_number_t index = 0;
                 index < thread_count;
                 index += 1) {
                mach_port_deallocate(mach_task_self(), threads[index]);
            }
            vm_deallocate(
                mach_task_self(),
                (vm_address_t)threads,
                (vm_size_t)(thread_count * sizeof(thread_act_t))
            );
        }
        mach_port_deallocate(mach_task_self(), task);
        return result == KERN_SUCCESS
            ? CONTINUUM_STATUS_THREAD_SET_CHANGED
            : CONTINUUM_STATUS_THREAD_STATE_FAILED;
    }

    arm_debug_state64_t debug_state;
    memset(&debug_state, 0, sizeof(debug_state));
    mach_msg_type_number_t debug_count = ARM_DEBUG_STATE64_COUNT;
    result = thread_get_state(
        threads[0],
        ARM_DEBUG_STATE64,
        (thread_state_t)&debug_state,
        &debug_count
    );
    size_t breakpoint_slot = 16;
    if (result == KERN_SUCCESS) {
        for (size_t slot = 0; slot < 16; slot += 1) {
            if ((debug_state.__bcr[slot] & UINT64_C(1)) == 0) {
                breakpoint_slot = slot;
                break;
            }
        }
    }
    if (result != KERN_SUCCESS || breakpoint_slot == 16) {
        status = CONTINUUM_STATUS_THREAD_STATE_FAILED;
    } else {
        debug_state.__bvr[breakpoint_slot] =
            entry_address & UINT64_C(0xFFFFFFFFFFFFFFFC);
        debug_state.__bcr[breakpoint_slot] = UINT64_C(0x1E5);
        result = thread_set_state(
            threads[0],
            ARM_DEBUG_STATE64,
            (thread_state_t)&debug_state,
            ARM_DEBUG_STATE64_COUNT
        );
        if (result != KERN_SUCCESS) {
            status = CONTINUUM_STATUS_THREAD_STATE_FAILED;
        }
    }

    if (status == CONTINUUM_STATUS_OK && broker_channel >= 0) {
        status = continuum_broker_send_empty_command(
            broker_channel,
            CONTINUUM_BROKER_CHILD_TO_ENTRY,
            CONTINUUM_BROKER_CHILD_ENTRY_REACHED
        );
    } else if (status == CONTINUUM_STATUS_OK) {
        if (ptrace(PT_CONTINUE, process_id, (caddr_t)1, 0) != 0) {
            status = CONTINUUM_STATUS_RESUME_FAILED;
        } else {
            status = continuum_wait_for_child_signal_stop(
                process_id,
                deadline,
                SIGTRAP
            );
        }
    }

    if (status == CONTINUUM_STATUS_OK) {
        debug_state.__bvr[breakpoint_slot] = 0;
        debug_state.__bcr[breakpoint_slot] = 0;
        result = thread_set_state(
            threads[0],
            ARM_DEBUG_STATE64,
            (thread_state_t)&debug_state,
            ARM_DEBUG_STATE64_COUNT
        );
        if (result != KERN_SUCCESS) {
            status = CONTINUUM_STATUS_THREAD_STATE_FAILED;
        }
    }
    if (status == CONTINUUM_STATUS_OK) {
        arm_thread_state64_t general_state;
        memset(&general_state, 0, sizeof(general_state));
        mach_msg_type_number_t general_count = ARM_THREAD_STATE64_COUNT;
        result = thread_get_state(
            threads[0],
            ARM_THREAD_STATE64,
            (thread_state_t)&general_state,
            &general_count
        );
        if (result != KERN_SUCCESS
            || arm_thread_state64_get_pc(general_state) != entry_address) {
            status = CONTINUUM_STATUS_VALIDATION_FAILED;
        }
    }
    if (status == CONTINUUM_STATUS_OK && broker_channel >= 0) {
        status = continuum_broker_send_empty_command(
            broker_channel,
            CONTINUUM_BROKER_CHILD_DETACH,
            CONTINUUM_BROKER_CHILD_DETACHED
        );
    }

    mach_port_deallocate(mach_task_self(), threads[0]);
    vm_deallocate(
        mach_task_self(),
        (vm_address_t)threads,
        (vm_size_t)sizeof(thread_act_t)
    );
    mach_port_deallocate(mach_task_self(), task);
    return status;
#endif
}

continuum_status continuum_advance_process_to_entry_stop(
    int32_t process_id,
    uint32_t timeout_milliseconds
) {
    continuum_status status = continuum_advance_process_to_bootstrap_stop(
        process_id,
        timeout_milliseconds
    );
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }
    return continuum_advance_bootstrap_stopped_process_to_entry(
        process_id,
        timeout_milliseconds,
        0,
        -1
    );
}

continuum_status continuum_release_entry_stopped_child(
    int32_t process_id
) {
    if (process_id <= 0) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    struct proc_bsdinfo process_info;
    memset(&process_info, 0, sizeof(process_info));
    int copied = proc_pidinfo(
        process_id,
        PROC_PIDTBSDINFO,
        0,
        &process_info,
        (int)sizeof(process_info)
    );
    if (copied != (int)sizeof(process_info)) {
        return CONTINUUM_STATUS_TARGET_EXITED;
    }
    if (process_info.pbi_ppid != getpid()) {
        if (process_info.pbi_status != SSTOP) {
            return CONTINUUM_STATUS_ACCESS_DENIED;
        }
        return kill(process_id, SIGCONT) == 0
            ? CONTINUUM_STATUS_OK
            : CONTINUUM_STATUS_RESUME_FAILED;
    }

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    int detach_result = ptrace(
        PT_DETACH,
        process_id,
        (caddr_t)1,
        0
    );
#pragma clang diagnostic pop
    if (detach_result != 0) {
        return errno == ESRCH
            ? CONTINUUM_STATUS_TARGET_EXITED
            : CONTINUUM_STATUS_RESUME_FAILED;
    }
    return kill(process_id, 0) == 0 || errno == EPERM
        ? CONTINUUM_STATUS_OK
        : CONTINUUM_STATUS_TARGET_EXITED;
}

static continuum_status continuum_write_task_bytes(
    mach_port_t task,
    mach_vm_address_t address,
    const void *source,
    size_t length,
    uint64_t *out_bytes_written
) {
    if (task == MACH_PORT_NULL || address == 0 || source == NULL
        || length == 0 || out_bytes_written == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }

    *out_bytes_written = 0;
    uint64_t range_end = 0;
    if (!continuum_add_u64(address, (uint64_t)length, &range_end)
        || range_end <= address) {
        return CONTINUUM_STATUS_RANGE_ERROR;
    }
    const uint8_t *source_bytes = source;
    size_t offset = 0;
    while (offset < length) {
        size_t remaining = length - offset;
        size_t chunk = remaining < CONTINUUM_WRITE_CHUNK_SIZE
            ? remaining
            : CONTINUUM_WRITE_CHUNK_SIZE;
        uint64_t current_address = 0;
        if (!continuum_add_u64(address, (uint64_t)offset, &current_address)) {
            return CONTINUUM_STATUS_RANGE_ERROR;
        }
        kern_return_t result = mach_vm_write(
            task,
            current_address,
            (vm_offset_t)(uintptr_t)(source_bytes + offset),
            (mach_msg_type_number_t)chunk
        );
        if (result != KERN_SUCCESS) {
            return CONTINUUM_STATUS_SHORT_WRITE;
        }
        offset += chunk;
        *out_bytes_written = offset;
    }
    return CONTINUUM_STATUS_OK;
}

static continuum_status continuum_reconstruction_leaf_span(
    mach_port_t task,
    mach_vm_address_t address,
    mach_vm_size_t maximum_length,
    vm_prot_t required_protection,
    mach_vm_size_t *out_length,
    kern_return_t *out_mach_result
) {
    if (task == MACH_PORT_NULL || address == 0 || maximum_length == 0
        || out_length == NULL || out_mach_result == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }

    *out_length = 0;
    *out_mach_result = KERN_SUCCESS;
    mach_vm_address_t mapping_address = address;
    mach_vm_size_t mapping_length = 0;
    vm_region_submap_info_data_64_t info;
    natural_t depth = 0;
    kern_return_t result;
    for (;;) {
        memset(&info, 0, sizeof(info));
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        result = mach_vm_region_recurse(
            task,
            &mapping_address,
            &mapping_length,
            &depth,
            (vm_region_recurse_info_t)&info,
            &count
        );
        if (result != KERN_SUCCESS || !info.is_submap) {
            break;
        }
        depth += 1;
    }
    if (result != KERN_SUCCESS) {
        *out_mach_result = result;
        return CONTINUUM_STATUS_MACH_ERROR;
    }
    if (mapping_address > address || mapping_length == 0) {
        return CONTINUUM_STATUS_REGION_UNMAPPED;
    }
    uint64_t mapping_end = 0;
    if (!continuum_add_u64(mapping_address, mapping_length, &mapping_end)
        || mapping_end <= address) {
        return CONTINUUM_STATUS_RANGE_ERROR;
    }
    if ((info.protection & required_protection) != required_protection) {
        return CONTINUUM_STATUS_REGION_PROTECTION_CHANGED;
    }

    mach_vm_size_t available = mapping_end - address;
    *out_length = available < maximum_length ? available : maximum_length;
    return CONTINUUM_STATUS_OK;
}

static continuum_status continuum_validate_reconstruction_range(
    mach_port_t task,
    mach_vm_address_t address,
    mach_vm_size_t length,
    vm_prot_t required_protection,
    kern_return_t *out_mach_result
) {
    if (task == MACH_PORT_NULL || address == 0 || length == 0
        || out_mach_result == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }

    mach_vm_size_t offset = 0;
    while (offset < length) {
        uint64_t current_address = 0;
        if (!continuum_add_u64(address, offset, &current_address)) {
            return CONTINUUM_STATUS_RANGE_ERROR;
        }
        mach_vm_size_t leaf_length = 0;
        continuum_status status = continuum_reconstruction_leaf_span(
            task,
            current_address,
            length - offset,
            required_protection,
            &leaf_length,
            out_mach_result
        );
        if (status != CONTINUUM_STATUS_OK) {
            return status;
        }
        if (leaf_length == 0) {
            return CONTINUUM_STATUS_REGION_UNMAPPED;
        }
        offset += leaf_length;
    }
    return CONTINUUM_STATUS_OK;
}

static continuum_status continuum_write_reconstructed_task_bytes(
    mach_port_t task,
    mach_vm_address_t address,
    const void *source,
    size_t length,
    uint64_t *out_bytes_written,
    kern_return_t *out_mach_result
) {
    if (task == MACH_PORT_NULL || address == 0 || source == NULL
        || length == 0 || out_bytes_written == NULL
        || out_mach_result == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }

    *out_bytes_written = 0;
    *out_mach_result = KERN_SUCCESS;
    uint64_t range_end = 0;
    if (!continuum_add_u64(address, (uint64_t)length, &range_end)
        || range_end <= address) {
        return CONTINUUM_STATUS_RANGE_ERROR;
    }
    const uint8_t *source_bytes = source;
    size_t offset = 0;
    while (offset < length) {
        mach_vm_size_t remaining = length - offset;
        uint64_t current_address = 0;
        if (!continuum_add_u64(address, (uint64_t)offset, &current_address)) {
            return CONTINUUM_STATUS_RANGE_ERROR;
        }
        mach_vm_size_t leaf_length = 0;
        continuum_status status = continuum_reconstruction_leaf_span(
            task,
            current_address,
            remaining,
            VM_PROT_WRITE,
            &leaf_length,
            out_mach_result
        );
        if (status != CONTINUUM_STATUS_OK) {
            return status;
        }
        size_t chunk = leaf_length < CONTINUUM_WRITE_CHUNK_SIZE
            ? (size_t)leaf_length
            : CONTINUUM_WRITE_CHUNK_SIZE;
        kern_return_t result = mach_vm_write(
            task,
            current_address,
            (vm_offset_t)(uintptr_t)(source_bytes + offset),
            (mach_msg_type_number_t)chunk
        );
        if (result != KERN_SUCCESS) {
            *out_mach_result = result;
            return CONTINUUM_STATUS_SHORT_WRITE;
        }
        offset += chunk;
        *out_bytes_written = offset;
    }
    return CONTINUUM_STATUS_OK;
}

static continuum_status continuum_read_reconstructed_task_bytes(
    mach_port_t task,
    mach_vm_address_t address,
    mach_vm_size_t length,
    void *destination,
    kern_return_t *out_mach_result
) {
    if (task == MACH_PORT_NULL || address == 0 || length == 0
        || destination == NULL || out_mach_result == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }

    *out_mach_result = KERN_SUCCESS;
    uint64_t range_end = 0;
    if (!continuum_add_u64(address, length, &range_end)
        || range_end <= address) {
        return CONTINUUM_STATUS_RANGE_ERROR;
    }
    uint8_t *destination_bytes = destination;
    mach_vm_size_t offset = 0;
    while (offset < length) {
        uint64_t current_address = 0;
        if (!continuum_add_u64(address, offset, &current_address)) {
            return CONTINUUM_STATUS_RANGE_ERROR;
        }
        mach_vm_size_t leaf_length = 0;
        continuum_status status = continuum_reconstruction_leaf_span(
            task,
            current_address,
            length - offset,
            VM_PROT_READ,
            &leaf_length,
            out_mach_result
        );
        if (status != CONTINUUM_STATUS_OK) {
            return status;
        }
        mach_vm_size_t copied = 0;
        kern_return_t result = mach_vm_read_overwrite(
            task,
            current_address,
            leaf_length,
            (mach_vm_address_t)(uintptr_t)(destination_bytes + offset),
            &copied
        );
        if (result != KERN_SUCCESS) {
            *out_mach_result = result;
            return CONTINUUM_STATUS_MACH_ERROR;
        }
        if (copied != leaf_length) {
            return CONTINUUM_STATUS_SHORT_READ;
        }
        offset += copied;
    }
    return CONTINUUM_STATUS_OK;
}

static continuum_status continuum_copy_reconstructed_task_bytes_in_process(
    continuum_remote_session *session,
    mach_vm_address_t destination,
    const void *source,
    size_t length,
    kern_return_t *out_mach_result
) {
#if !defined(__arm64__)
    (void)session;
    (void)destination;
    (void)source;
    (void)length;
    (void)out_mach_result;
    return CONTINUUM_STATUS_UNSUPPORTED_ARCHITECTURE;
#else
    if (session == NULL || session->task == MACH_PORT_NULL
        || session->bootstrap_copy_address == 0 || destination == 0
        || source == NULL || length == 0 || out_mach_result == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }

    *out_mach_result = KERN_SUCCESS;
    continuum_status status = CONTINUUM_STATUS_OK;
    int target_stopped = 1;
    mach_vm_address_t scratch_address = 0;
    mach_vm_address_t stack_address = 0;
    const mach_vm_size_t stack_length = 64U * 1024U;
    kern_return_t result = mach_vm_allocate(
        session->task,
        &scratch_address,
        length,
        VM_FLAGS_ANYWHERE
    );
    if (result != KERN_SUCCESS) {
        *out_mach_result = result;
        return CONTINUUM_STATUS_MACH_ERROR;
    }
    result = mach_vm_allocate(
        session->task,
        &stack_address,
        stack_length,
        VM_FLAGS_ANYWHERE
    );
    if (result != KERN_SUCCESS) {
        *out_mach_result = result;
        mach_vm_deallocate(session->task, scratch_address, length);
        return CONTINUUM_STATUS_MACH_ERROR;
    }

    uint64_t scratch_bytes_written = 0;
    status = continuum_write_task_bytes(
        session->task,
        scratch_address,
        source,
        length,
        &scratch_bytes_written
    );
    if (status != CONTINUUM_STATUS_OK
        || scratch_bytes_written != length) {
        status = CONTINUUM_STATUS_SHORT_WRITE;
        goto cleanup_allocations;
    }

    thread_act_array_t threads = NULL;
    mach_msg_type_number_t thread_count = 0;
    result = task_threads(session->task, &threads, &thread_count);
    if (result != KERN_SUCCESS) {
        *out_mach_result = result;
        status = CONTINUUM_STATUS_THREAD_STATE_FAILED;
        goto cleanup_allocations;
    }
    mach_msg_type_number_t copy_thread_index = 0;
    if (session->has_prepared_pthread_set) {
        copy_thread_index = UINT32_MAX;
        for (mach_msg_type_number_t index = 0; index < thread_count; index += 1) {
            thread_identifier_info_data_t identity;
            memset(&identity, 0, sizeof(identity));
            mach_msg_type_number_t identity_count =
                THREAD_IDENTIFIER_INFO_COUNT;
            if (thread_info(
                    threads[index],
                    THREAD_IDENTIFIER_INFO,
                    (thread_info_t)&identity,
                    &identity_count
                ) != KERN_SUCCESS) {
                status = CONTINUUM_STATUS_THREAD_STATE_FAILED;
                goto cleanup_threads;
            }
            if (identity.thread_handle
                == session->prepared_pthreads.primary_thread_handle) {
                if (copy_thread_index != UINT32_MAX) {
                    status = CONTINUUM_STATUS_THREAD_SET_CHANGED;
                    goto cleanup_threads;
                }
                copy_thread_index = index;
            }
        }
        if (copy_thread_index == UINT32_MAX) {
            status = CONTINUUM_STATUS_THREAD_SET_CHANGED;
            goto cleanup_threads;
        }
    } else if (thread_count != 1) {
        status = CONTINUUM_STATUS_THREAD_SET_CHANGED;
        goto cleanup_threads;
    }

    arm_thread_state64_t saved_state;
    memset(&saved_state, 0, sizeof(saved_state));
    mach_msg_type_number_t state_count = ARM_THREAD_STATE64_COUNT;
    result = thread_get_state(
        threads[copy_thread_index],
        ARM_THREAD_STATE64,
        (thread_state_t)&saved_state,
        &state_count
    );
    if (result != KERN_SUCCESS) {
        *out_mach_result = result;
        status = CONTINUUM_STATUS_THREAD_STATE_FAILED;
        goto cleanup_threads;
    }

    arm_thread_state64_t copy_state = saved_state;
    copy_state.__x[0] = destination;
    copy_state.__x[1] = scratch_address;
    copy_state.__x[2] = length;
    uintptr_t stack_pointer = (uintptr_t)(stack_address + stack_length - 16U);
    arm_thread_state64_set_sp(copy_state, (void *)stack_pointer);
    arm_thread_state64_set_fp(copy_state, (void *)stack_pointer);
    arm_thread_state64_set_lr_fptr(copy_state, NULL);
    arm_thread_state64_set_pc_fptr(
        copy_state,
        (void (*)(void))(uintptr_t)session->bootstrap_copy_address
    );
    result = thread_set_state(
        threads[copy_thread_index],
        ARM_THREAD_STATE64,
        (thread_state_t)&copy_state,
        ARM_THREAD_STATE64_COUNT
    );
    if (result != KERN_SUCCESS) {
        *out_mach_result = result;
        status = CONTINUUM_STATUS_THREAD_STATE_FAILED;
        goto cleanup_threads;
    }

    uint64_t now = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    uint64_t deadline = now + UINT64_C(5000000000);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    int continue_result = ptrace(
        PT_CONTINUE,
        session->identity.process_id,
        (caddr_t)1,
        0
    );
#pragma clang diagnostic pop
    if (continue_result != 0) {
        status = CONTINUUM_STATUS_RESUME_FAILED;
    } else {
        target_stopped = 0;
        status = continuum_wait_for_child_signal_stop(
            session->identity.process_id,
            deadline,
            SIGTRAP
        );
        if (status == CONTINUUM_STATUS_OK) {
            target_stopped = 1;
        }
    }

    if (target_stopped) {
        result = thread_set_state(
            threads[copy_thread_index],
            ARM_THREAD_STATE64,
            (thread_state_t)&saved_state,
            ARM_THREAD_STATE64_COUNT
        );
        if (result != KERN_SUCCESS) {
            *out_mach_result = result;
            status = CONTINUUM_STATUS_THREAD_STATE_FAILED;
        }
    }

cleanup_threads:
    if (threads != NULL) {
        for (mach_msg_type_number_t index = 0; index < thread_count; index += 1) {
            mach_port_deallocate(mach_task_self(), threads[index]);
        }
        vm_deallocate(
            mach_task_self(),
            (vm_address_t)threads,
            (vm_size_t)(thread_count * sizeof(thread_act_t))
        );
    }
cleanup_allocations:
    if (target_stopped) {
        mach_vm_deallocate(session->task, stack_address, stack_length);
        mach_vm_deallocate(session->task, scratch_address, length);
    }
    return status;
#endif
}

static int continuum_thread_entry_compare(const void *left, const void *right) {
    const continuum_remote_thread_entry *left_entry = left;
    const continuum_remote_thread_entry *right_entry = right;
    if (left_entry->identifier < right_entry->identifier) {
        return -1;
    }
    if (left_entry->identifier > right_entry->identifier) {
        return 1;
    }
    return 0;
}

static void continuum_thread_entry_clear(continuum_remote_thread_entry *entry) {
    if (entry == NULL) {
        return;
    }
    if (entry->general_bytes != NULL) {
        memset(entry->general_bytes, 0, entry->general_length);
        free(entry->general_bytes);
    }
    if (entry->vector_bytes != NULL) {
        memset(entry->vector_bytes, 0, entry->vector_length);
        free(entry->vector_bytes);
    }
    memset(entry, 0, sizeof(*entry));
}

void continuum_remote_thread_snapshot_destroy(
    continuum_remote_thread_snapshot *snapshot
) {
    if (snapshot == NULL) {
        return;
    }
    for (size_t index = 0; index < snapshot->count; index += 1) {
        continuum_thread_entry_clear(&snapshot->entries[index]);
    }
    free(snapshot->entries);
    memset(snapshot, 0, sizeof(*snapshot));
    free(snapshot);
}

static continuum_status continuum_capture_thread_snapshot(
    mach_port_t task,
    continuum_remote_thread_snapshot **out_snapshot
) {
    if (task == MACH_PORT_NULL || out_snapshot == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    *out_snapshot = NULL;

#if !defined(__arm64__)
    return CONTINUUM_STATUS_UNSUPPORTED_ARCHITECTURE;
#else
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t thread_count = 0;
    kern_return_t result = task_threads(task, &threads, &thread_count);
    if (result != KERN_SUCCESS) {
        return CONTINUUM_STATUS_THREAD_STATE_FAILED;
    }

    continuum_remote_thread_snapshot *snapshot = calloc(1, sizeof(*snapshot));
    if (snapshot == NULL) {
        for (mach_msg_type_number_t index = 0; index < thread_count; index += 1) {
            mach_port_deallocate(mach_task_self(), threads[index]);
        }
        vm_deallocate(
            mach_task_self(),
            (vm_address_t)threads,
            (vm_size_t)(thread_count * sizeof(thread_act_t))
        );
        return CONTINUUM_STATUS_OUT_OF_MEMORY;
    }

    if (thread_count > 0) {
        snapshot->entries = calloc(thread_count, sizeof(*snapshot->entries));
        if (snapshot->entries == NULL) {
            free(snapshot);
            for (mach_msg_type_number_t index = 0; index < thread_count; index += 1) {
                mach_port_deallocate(mach_task_self(), threads[index]);
            }
            vm_deallocate(
                mach_task_self(),
                (vm_address_t)threads,
                (vm_size_t)(thread_count * sizeof(thread_act_t))
            );
            return CONTINUUM_STATUS_OUT_OF_MEMORY;
        }
    }
    snapshot->count = thread_count;

    continuum_status status = CONTINUUM_STATUS_OK;
    for (mach_msg_type_number_t index = 0; index < thread_count; index += 1) {
        continuum_remote_thread_entry *entry = &snapshot->entries[index];

        thread_identifier_info_data_t identifier_info;
        mach_msg_type_number_t identifier_count = THREAD_IDENTIFIER_INFO_COUNT;
        result = thread_info(
            threads[index],
            THREAD_IDENTIFIER_INFO,
            (thread_info_t)&identifier_info,
            &identifier_count
        );
        if (result != KERN_SUCCESS) {
            status = CONTINUUM_STATUS_THREAD_STATE_FAILED;
            break;
        }
        entry->identifier = identifier_info.thread_id;
        entry->thread_handle = identifier_info.thread_handle;
        entry->pthread_object_address = continuum_pthread_object_address(
            identifier_info.thread_handle
        );
        entry->dispatch_queue_address = identifier_info.dispatch_qaddr;
        entry->origin = continuum_thread_origin(
            task,
            entry->thread_handle,
            entry->pthread_object_address
        );

        mach_msg_type_number_t general_count = ARM_THREAD_STATE64_COUNT;
        entry->general_length = general_count * sizeof(natural_t);
        entry->general_bytes = calloc(1, entry->general_length);
        if (entry->general_bytes == NULL) {
            status = CONTINUUM_STATUS_OUT_OF_MEMORY;
            break;
        }
        result = thread_get_state(
            threads[index],
            ARM_THREAD_STATE64,
            (thread_state_t)entry->general_bytes,
            &general_count
        );
        if (result != KERN_SUCCESS) {
            status = CONTINUUM_STATUS_THREAD_STATE_FAILED;
            break;
        }
        entry->general_flavor = ARM_THREAD_STATE64;
        entry->general_length = general_count * sizeof(natural_t);
        arm_thread_state64_t captured_general;
        memcpy(
            &captured_general,
            entry->general_bytes,
            sizeof(captured_general)
        );
        entry->is_userspace_safepoint =
            captured_general.__x[28]
                == UINT64_C(0x434F4E5453414645);
        entry->preserves_kernel_continuation =
            !entry->is_userspace_safepoint
            && continuum_program_counter_is_kernel_wait(
                arm_thread_state64_get_pc(captured_general)
            );

        mach_msg_type_number_t vector_count = ARM_NEON_STATE64_COUNT;
        entry->vector_length = vector_count * sizeof(natural_t);
        entry->vector_bytes = calloc(1, entry->vector_length);
        if (entry->vector_bytes == NULL) {
            status = CONTINUUM_STATUS_OUT_OF_MEMORY;
            break;
        }
        result = thread_get_state(
            threads[index],
            ARM_NEON_STATE64,
            (thread_state_t)entry->vector_bytes,
            &vector_count
        );
        if (result != KERN_SUCCESS) {
            status = CONTINUUM_STATUS_THREAD_STATE_FAILED;
            break;
        }
        entry->vector_flavor = ARM_NEON_STATE64;
        entry->vector_length = vector_count * sizeof(natural_t);
    }

    for (mach_msg_type_number_t index = 0; index < thread_count; index += 1) {
        mach_port_deallocate(mach_task_self(), threads[index]);
    }
    if (threads != NULL) {
        vm_deallocate(
            mach_task_self(),
            (vm_address_t)threads,
            (vm_size_t)(thread_count * sizeof(thread_act_t))
        );
    }

    if (status != CONTINUUM_STATUS_OK) {
        continuum_remote_thread_snapshot_destroy(snapshot);
        return status;
    }

    qsort(
        snapshot->entries,
        snapshot->count,
        sizeof(*snapshot->entries),
        continuum_thread_entry_compare
    );
    uint64_t hash = CONTINUUM_FNV_OFFSET;
    for (size_t index = 0; index < snapshot->count; index += 1) {
        uint64_t identifier = snapshot->entries[index].identifier;
        for (size_t byte = 0; byte < sizeof(identifier); byte += 1) {
            hash ^= (identifier >> (byte * 8)) & UINT64_C(0xFF);
            hash *= CONTINUUM_FNV_PRIME;
        }
    }
    snapshot->set_hash = hash;
    *out_snapshot = snapshot;
    return CONTINUUM_STATUS_OK;
#endif
}

static int continuum_region_contains_thread_stack(
    const continuum_remote_thread_snapshot *threads,
    mach_vm_address_t address,
    mach_vm_size_t length
) {
#if !defined(__arm64__)
    (void)threads;
    (void)address;
    (void)length;
    return 0;
#else
    uint64_t end = 0;
    if (threads == NULL || length == 0
        || !continuum_add_u64(address, length, &end)) {
        return 0;
    }
    for (size_t index = 0; index < threads->count; index += 1) {
        const continuum_remote_thread_entry *entry = &threads->entries[index];
        if (entry->general_flavor != ARM_THREAD_STATE64
            || entry->general_bytes == NULL
            || entry->general_length != sizeof(arm_thread_state64_t)) {
            continue;
        }
        arm_thread_state64_t state;
        memcpy(&state, entry->general_bytes, sizeof(state));
        uintptr_t stack_pointer = arm_thread_state64_get_sp(state);
        if (stack_pointer > address && stack_pointer <= end) {
            return 1;
        }
    }
    return 0;
#endif
}

static int continuum_region_contains_workqueue_runtime_state(
    const continuum_remote_thread_snapshot *threads,
    mach_vm_address_t address,
    mach_vm_size_t length
) {
#if !defined(__arm64__)
    (void)threads;
    (void)address;
    (void)length;
    return 0;
#else
    uint64_t end = 0;
    if (threads == NULL || length == 0
        || !continuum_add_u64(address, length, &end)) {
        return 0;
    }
    for (size_t index = 0; index < threads->count; index += 1) {
        const continuum_remote_thread_entry *entry = &threads->entries[index];
        if (entry->origin != CONTINUUM_REMOTE_THREAD_ORIGIN_WORKQUEUE) {
            continue;
        }
        if (entry->pthread_object_address >= address
            && entry->pthread_object_address < end) {
            return 1;
        }
        if (entry->general_flavor == ARM_THREAD_STATE64
            && entry->general_bytes != NULL
            && entry->general_length == sizeof(arm_thread_state64_t)) {
            arm_thread_state64_t state;
            memcpy(&state, entry->general_bytes, sizeof(state));
            uintptr_t stack_pointer = arm_thread_state64_get_sp(state);
            if (stack_pointer > address && stack_pointer <= end) {
                return 1;
            }
        }
    }
    return 0;
#endif
}

static int continuum_region_overlaps_shared_cache(
    mach_vm_address_t address,
    mach_vm_size_t length
) {
    return continuum_ranges_overlap(
        address,
        length,
        SHARED_REGION_BASE,
        SHARED_REGION_SIZE
    );
}

void continuum_remote_process_snapshot_destroy(
    continuum_remote_process_snapshot *snapshot
) {
    if (snapshot == NULL) {
        return;
    }
    for (size_t index = 0; index < snapshot->region_count; index += 1) {
        continuum_remote_process_region *region = &snapshot->regions[index];
        if (region->bytes != NULL) {
            if (region->is_cow_mapping) {
                (void)mach_vm_deallocate(
                    mach_task_self(),
                    (mach_vm_address_t)(uintptr_t)region->bytes,
                    region->length
                );
            } else {
                memset(region->bytes, 0, (size_t)region->length);
                free(region->bytes);
            }
        }
        free(region->page_dispositions);
        free(region->app_state_allocations);
        memset(region, 0, sizeof(*region));
    }
    free(snapshot->regions);
    continuum_remote_thread_snapshot_destroy(snapshot->threads);
    free(snapshot->mach_rights);
    memset(snapshot, 0, sizeof(*snapshot));
    free(snapshot);
}

size_t continuum_remote_process_snapshot_region_count(
    const continuum_remote_process_snapshot *snapshot
) {
    return snapshot == NULL ? 0 : snapshot->region_count;
}

continuum_status continuum_remote_process_snapshot_region_info(
    const continuum_remote_process_snapshot *snapshot,
    size_t index,
    continuum_remote_process_region_info *out_info
) {
    if (snapshot == NULL || out_info == NULL || index >= snapshot->region_count) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    const continuum_remote_process_region *region = &snapshot->regions[index];
    out_info->address = region->address;
    out_info->length = region->length;
    out_info->protection = region->protection;
    out_info->maximum_protection = region->maximum_protection;
    out_info->inheritance = region->inheritance;
    out_info->share_mode = region->share_mode;
    out_info->user_tag = region->user_tag;
    out_info->is_app_owned_state = region->is_app_owned_state;
    out_info->preserves_live_derived_graphics =
        region->preserves_live_derived_graphics;
    return CONTINUUM_STATUS_OK;
}

static int continuum_process_region_metadata_equal(
    const continuum_remote_process_region *left,
    const continuum_remote_process_region *right
) {
    return left != NULL && right != NULL
        && left->address == right->address
        && left->length == right->length
        && left->protection == right->protection
        && left->maximum_protection == right->maximum_protection
        && left->inheritance == right->inheritance
        && continuum_canonical_share_mode(left->share_mode)
            == continuum_canonical_share_mode(right->share_mode)
        && left->user_tag == right->user_tag;
}

static continuum_status continuum_validate_captured_process_layout_suspended(
    continuum_remote_session *session,
    const continuum_remote_process_snapshot *snapshot
) {
    if (session == NULL || snapshot == NULL || session->task == MACH_PORT_NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    uint64_t captured_bytes = 0;
    uint64_t excluded_bytes = 0;
    uint64_t excluded_count = 0;
    uint64_t layout_hash = CONTINUUM_FNV_OFFSET;
    size_t region_index = 0;
    mach_vm_address_t address = 0;
    natural_t depth = 0;
    for (;;) {
        mach_vm_size_t region_size = 0;
        vm_region_submap_info_data_64_t info;
        memset(&info, 0, sizeof(info));
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t result = mach_vm_region_recurse(
            session->task,
            &address,
            &region_size,
            &depth,
            (vm_region_recurse_info_t)&info,
            &count
        );
        if (result == KERN_INVALID_ADDRESS) {
            break;
        }
        if (result != KERN_SUCCESS || region_size == 0) {
            return CONTINUUM_STATUS_MACH_ERROR;
        }
        if (info.is_submap) {
            depth += 1;
            continue;
        }

        const int writable =
            (info.protection & (VM_PROT_READ | VM_PROT_WRITE))
                == (VM_PROT_READ | VM_PROT_WRITE);
        const int eligible = writable
            && !continuum_region_overlaps_shared_cache(address, region_size)
            && !continuum_region_contains_workqueue_runtime_state(
                snapshot->threads,
                address,
                region_size
            )
            && (continuum_is_private_or_cow_share_mode(info.share_mode)
                || (info.share_mode == SM_EMPTY
                    && continuum_region_contains_thread_stack(
                        snapshot->threads,
                        address,
                        region_size
                    )));
        if (eligible) {
            if (region_index >= snapshot->region_count) {
                return CONTINUUM_STATUS_REGION_MAPPING_CHANGED;
            }
            continuum_remote_process_region current;
            memset(&current, 0, sizeof(current));
            current.address = address;
            current.length = region_size;
            current.protection = info.protection;
            current.maximum_protection = info.max_protection;
            current.inheritance = info.inheritance;
            current.share_mode = info.share_mode;
            current.user_tag = info.user_tag;
            if (!continuum_process_region_metadata_equal(
                    &snapshot->regions[region_index],
                    &current
                )) {
                return CONTINUUM_STATUS_REGION_MAPPING_CHANGED;
            }
            continuum_hash_u64(&layout_hash, address);
            continuum_hash_u64(&layout_hash, region_size);
            continuum_hash_u64(
                &layout_hash,
                (uint64_t)(uint32_t)info.protection
            );
            continuum_hash_u64(
                &layout_hash,
                (uint64_t)(uint32_t)info.max_protection
            );
            continuum_hash_u64(
                &layout_hash,
                (uint64_t)(uint32_t)info.inheritance
            );
            continuum_hash_u64(
                &layout_hash,
                continuum_canonical_share_mode(info.share_mode)
            );
            continuum_hash_u64(&layout_hash, info.user_tag);
            if (!continuum_add_u64(captured_bytes, region_size, &captured_bytes)) {
                return CONTINUUM_STATUS_RANGE_ERROR;
            }
            region_index += 1;
        } else {
            if (!continuum_add_u64(excluded_bytes, region_size, &excluded_bytes)) {
                return CONTINUUM_STATUS_RANGE_ERROR;
            }
            excluded_count += 1;
        }
        if (UINT64_MAX - address < region_size) {
            break;
        }
        address += region_size;
    }
    if (region_index != snapshot->region_count
        || captured_bytes != snapshot->info.captured_bytes
        || excluded_count != snapshot->info.excluded_region_count
        || excluded_bytes != snapshot->info.excluded_bytes
        || layout_hash != snapshot->info.vm_layout_hash) {
        return CONTINUUM_STATUS_REGION_MAPPING_CHANGED;
    }
    return CONTINUUM_STATUS_OK;
}

static continuum_status continuum_query_page_dispositions(
    mach_port_t task,
    mach_vm_address_t address,
    mach_vm_size_t length,
    int *dispositions,
    size_t page_count
) {
    if (task == MACH_PORT_NULL || address == 0 || length == 0
        || dispositions == NULL || page_count == 0) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }

    mach_vm_size_t returned_count = page_count;
    kern_return_t result = mach_vm_page_range_query(
        task,
        address,
        length,
        (mach_vm_address_t)(uintptr_t)dispositions,
        &returned_count
    );
    if (result != KERN_SUCCESS || returned_count != page_count) {
        return CONTINUUM_STATUS_MACH_ERROR;
    }
    return CONTINUUM_STATUS_OK;
}

static continuum_status continuum_capture_process_snapshot_suspended(
    continuum_remote_session *session,
    uint64_t maximum_captured_bytes,
    continuum_remote_process_snapshot **out_snapshot
) {
    if (session == NULL || out_snapshot == NULL || maximum_captured_bytes == 0
        || session->is_self || session->task == MACH_PORT_NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    *out_snapshot = NULL;

    continuum_status status = continuum_validate_session_identity(session);
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }

    continuum_remote_process_snapshot *snapshot = calloc(1, sizeof(*snapshot));
    if (snapshot == NULL) {
        return CONTINUUM_STATUS_OUT_OF_MEMORY;
    }
    snapshot->identity = session->identity;
    snapshot->info.vm_layout_hash = CONTINUUM_FNV_OFFSET;

    status = continuum_capture_thread_snapshot(
        session->task,
        &snapshot->threads
    );
    if (getenv("CONTINUUM_CAPTURE_TRACE") != NULL) {
        fprintf(
            stderr,
            "continuum capture pid=%d phase=threads status=%d\n",
            session->identity.process_id,
            status
        );
    }
    if (status != CONTINUUM_STATUS_OK) {
        continuum_remote_process_snapshot_destroy(snapshot);
        return status;
    }
    snapshot->info.thread_count = snapshot->threads->count;
    snapshot->info.thread_set_hash = snapshot->threads->set_hash;

    continuum_vm_range_set quartzcore_ranges;
    status = continuum_collect_quartzcore_ranges(
        session->task,
        &quartzcore_ranges
    );
    if (status != CONTINUUM_STATUS_OK) {
        memset(&quartzcore_ranges, 0, sizeof(quartzcore_ranges));
        status = CONTINUUM_STATUS_OK;
    }

    continuum_vm_range_set app_state_ranges;
    memset(&app_state_ranges, 0, sizeof(app_state_ranges));

    size_t capacity = 0;
    mach_vm_address_t address = 0;
    natural_t depth = 0;
    for (;;) {
        mach_vm_size_t region_size = 0;
        vm_region_submap_info_data_64_t info;
        memset(&info, 0, sizeof(info));
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t result = mach_vm_region_recurse(
            session->task,
            &address,
            &region_size,
            &depth,
            (vm_region_recurse_info_t)&info,
            &count
        );
        if (result == KERN_INVALID_ADDRESS) {
            break;
        }
        if (result != KERN_SUCCESS || region_size == 0) {
            status = CONTINUUM_STATUS_MACH_ERROR;
            break;
        }
        if (info.is_submap) {
            depth += 1;
            continue;
        }

        const int writable =
            (info.protection & (VM_PROT_READ | VM_PROT_WRITE))
                == (VM_PROT_READ | VM_PROT_WRITE);
        const int app_payload_state = continuum_region_is_app_state(
            address,
            region_size,
            info.user_tag
        );
        const int app_owned_state = app_payload_state
            || continuum_region_is_app_state_metadata(
                address,
                region_size,
                info.user_tag
            );
        const int eligible_memory = writable
            && !continuum_region_overlaps_shared_cache(address, region_size)
            && !continuum_region_contains_workqueue_runtime_state(
                snapshot->threads,
                address,
                region_size
            )
            && (continuum_is_private_or_cow_share_mode(info.share_mode)
                || (info.share_mode == SM_EMPTY
                    && continuum_region_contains_thread_stack(
                        snapshot->threads,
                        address,
                        region_size
                    )));
        // A durable process image must retain writable globals, stacks, runtime
        // bookkeeping, and allocations outside Continuum's optimization zone.
        // The isolated zone remains useful for dirty-page attribution, but it
        // must never narrow the truth of a cold checkpoint.
        const int eligible = eligible_memory;
        if (eligible) {
            continuum_hash_vm_region(
                &snapshot->info.vm_layout_hash,
                address,
                region_size,
                &info
            );
            uint64_t total = 0;
            if (!continuum_add_u64(
                    snapshot->info.captured_bytes,
                    region_size,
                    &total
                )) {
                status = CONTINUUM_STATUS_RANGE_ERROR;
                break;
            }
            if (total > maximum_captured_bytes || region_size > SIZE_MAX) {
                status = CONTINUUM_STATUS_SNAPSHOT_BUDGET_EXCEEDED;
                break;
            }
            if (snapshot->region_count == capacity) {
                size_t new_capacity = capacity == 0 ? 32 : capacity * 2;
                if (new_capacity < capacity
                    || new_capacity > SIZE_MAX / sizeof(*snapshot->regions)) {
                    status = CONTINUUM_STATUS_RANGE_ERROR;
                    break;
                }
                continuum_remote_process_region *resized = realloc(
                    snapshot->regions,
                    new_capacity * sizeof(*snapshot->regions)
                );
                if (resized == NULL) {
                    status = CONTINUUM_STATUS_OUT_OF_MEMORY;
                    break;
                }
                memset(
                    resized + capacity,
                    0,
                    (new_capacity - capacity) * sizeof(*snapshot->regions)
                );
                snapshot->regions = resized;
                capacity = new_capacity;
            }

            continuum_remote_process_region *region =
                &snapshot->regions[snapshot->region_count];
            region->address = address;
            region->length = region_size;
            region->protection = info.protection;
            region->maximum_protection = info.max_protection;
            region->inheritance = info.inheritance;
            region->share_mode = info.share_mode;
            region->user_tag = info.user_tag;
            region->preserves_live_derived_graphics =
                continuum_region_is_derived_graphics(
                    address,
                    region_size,
                    info.user_tag,
                    &quartzcore_ranges
                );
            region->is_app_owned_state = app_owned_state;
            if (app_owned_state) {
                vm_range_t *resized = realloc(
                    region->app_state_allocations,
                    (region->app_state_allocation_count + 1)
                        * sizeof(*region->app_state_allocations)
                );
                if (resized == NULL) {
                    status = CONTINUUM_STATUS_OUT_OF_MEMORY;
                    break;
                }
                region->app_state_allocations = resized;
                region->app_state_allocations[
                    region->app_state_allocation_count
                ] = (vm_range_t) {
                    .address = address,
                    .size = region_size,
                };
                region->app_state_allocation_count += 1;
                if (app_payload_state) {
                    snapshot->has_isolated_app_state = 1;
                }
            }
            if (status != CONTINUUM_STATUS_OK) {
                break;
            }
            snapshot->region_count += 1;
            const size_t page_size = (size_t)getpagesize();
            region->page_count = (size_t)(region_size / page_size);
            if (region_size % page_size != 0) {
                region->page_count += 1;
            }
            if (region->page_count == 0
                || region->page_count > SIZE_MAX / sizeof(int)) {
                status = CONTINUUM_STATUS_RANGE_ERROR;
                break;
            }
            region->page_dispositions = calloc(
                region->page_count,
                sizeof(*region->page_dispositions)
            );
            if (region->page_dispositions == NULL) {
                status = CONTINUUM_STATUS_OUT_OF_MEMORY;
                break;
            }
            status = continuum_query_page_dispositions(
                session->task,
                address,
                region_size,
                region->page_dispositions,
                region->page_count
            );
            if (status != CONTINUUM_STATUS_OK) {
                break;
            }

            region->bytes = malloc((size_t)region_size);
            if (region->bytes == NULL) {
                status = CONTINUUM_STATUS_OUT_OF_MEMORY;
                break;
            }
            region->is_cow_mapping = 0;
            status = continuum_read_task_bytes(
                session->task,
                address,
                region_size,
                region->bytes
            );
            if (status != CONTINUUM_STATUS_OK) {
                break;
            }

            snapshot->info.captured_region_count += 1;
            snapshot->info.captured_bytes = total;
        } else {
            uint64_t total = 0;
            if (!continuum_add_u64(
                    snapshot->info.excluded_bytes,
                    region_size,
                    &total
                )) {
                status = CONTINUUM_STATUS_RANGE_ERROR;
                break;
            }
            snapshot->info.excluded_region_count += 1;
            snapshot->info.excluded_bytes = total;
        }

        if (UINT64_MAX - address < region_size) {
            break;
        }
        address += region_size;
    }

    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_capture_image_layout_digest(
            session->task,
            &snapshot->info.immutable_layout_digest,
            0
        );
        if (getenv("CONTINUUM_CAPTURE_TRACE") != NULL) {
            fprintf(
                stderr,
                "continuum capture pid=%d phase=image-layout status=%d regions=%zu bytes=%llu\n",
                session->identity.process_id,
                status,
                snapshot->region_count,
                (unsigned long long)snapshot->info.captured_bytes
            );
        }
    }
    if (status == CONTINUUM_STATUS_OK
        && !snapshot->has_isolated_app_state) {
        status = continuum_capture_resource_fingerprint_suspended(
            session,
            &snapshot->resources
        );
    }
    if (status == CONTINUUM_STATUS_OK
        && !snapshot->has_isolated_app_state) {
        status = continuum_capture_mach_rights(
            session->task,
            &snapshot->mach_rights,
            &snapshot->mach_right_count
        );
    }
    if (status == CONTINUUM_STATUS_OK
        && !snapshot->has_isolated_app_state) {
        status = continuum_validate_captured_process_layout_suspended(
            session,
            snapshot
        );
    }
    free(app_state_ranges.ranges);
    free(quartzcore_ranges.ranges);
    if (status != CONTINUUM_STATUS_OK) {
        continuum_remote_process_snapshot_destroy(snapshot);
        return status;
    }

    *out_snapshot = snapshot;
    return CONTINUUM_STATUS_OK;
}

static void continuum_prewarm_process_snapshot(
    const continuum_remote_process_snapshot *snapshot
) {
    if (snapshot == NULL) {
        return;
    }
    const size_t page_size = (size_t)getpagesize();
    volatile uint8_t sink = 0;
    for (size_t index = 0; index < snapshot->region_count; index += 1) {
        const continuum_remote_process_region *region = &snapshot->regions[index];
        // malloc-backed captures were already faulted in by
        // mach_vm_read_overwrite. Only a future COW-backed capture can need
        // prewarming before the target resumes.
        if (!region->is_cow_mapping
            || region->bytes == NULL
            || region->length == 0) {
            continue;
        }
        (void)madvise(region->bytes, (size_t)region->length, MADV_WILLNEED);
        for (uint64_t offset = 0; offset < region->length; offset += page_size) {
            sink ^= region->bytes[offset];
        }
    }
    (void)sink;
}

static int continuum_fd_info_compare(const void *left, const void *right) {
    const struct proc_fdinfo *left_info = left;
    const struct proc_fdinfo *right_info = right;
    if (left_info->proc_fd < right_info->proc_fd) {
        return -1;
    }
    if (left_info->proc_fd > right_info->proc_fd) {
        return 1;
    }
    return 0;
}

static void continuum_hash_file_info(
    uint64_t *hash,
    const struct proc_fileinfo *info,
    continuum_remote_resource_fingerprint *fingerprint
) {
    /* XNU's fi_openflags includes FWASWRITTEN, a mutable observation bit
       rather than descriptor identity. File contents remain live across a
       Continuum restore, so ordinary writes must not invalidate a snapshot. */
    const uint32_t continuum_file_flag_was_written = 0x00010000U;
    continuum_hash_u64(
        hash,
        info->fi_openflags & ~continuum_file_flag_was_written
    );
    continuum_hash_u64(hash, (uint64_t)(uint32_t)info->fi_type);
    continuum_hash_u64(hash, info->fi_guardflags);
    if ((info->fi_status & PROC_FP_GUARDED) != 0 || info->fi_guardflags != 0) {
        fingerprint->guarded_descriptor_count += 1;
    }
}

static continuum_status continuum_capture_descriptor_fingerprint(
    int32_t process_id,
    continuum_remote_resource_fingerprint *fingerprint
) {
    int required_bytes = proc_pidinfo(
        process_id,
        PROC_PIDLISTFDS,
        0,
        NULL,
        0
    );
    if (required_bytes < 0) {
        return CONTINUUM_STATUS_MACH_ERROR;
    }

    size_t capacity = (size_t)required_bytes
        + 32U * sizeof(struct proc_fdinfo);
    if (capacity < sizeof(struct proc_fdinfo) || capacity > INT_MAX) {
        return CONTINUUM_STATUS_RANGE_ERROR;
    }
    struct proc_fdinfo *descriptors = calloc(1, capacity);
    if (descriptors == NULL) {
        return CONTINUUM_STATUS_OUT_OF_MEMORY;
    }

    int returned_bytes = proc_pidinfo(
        process_id,
        PROC_PIDLISTFDS,
        0,
        descriptors,
        (int)capacity
    );
    if (returned_bytes < 0
        || returned_bytes % (int)sizeof(struct proc_fdinfo) != 0) {
        free(descriptors);
        return CONTINUUM_STATUS_MACH_ERROR;
    }
    size_t descriptor_count =
        (size_t)returned_bytes / sizeof(struct proc_fdinfo);
    qsort(
        descriptors,
        descriptor_count,
        sizeof(*descriptors),
        continuum_fd_info_compare
    );

    uint64_t hash = CONTINUUM_FNV_OFFSET;
    continuum_status status = CONTINUUM_STATUS_OK;
    for (size_t index = 0; index < descriptor_count; index += 1) {
        const struct proc_fdinfo descriptor = descriptors[index];
        continuum_hash_u64(&hash, (uint64_t)(uint32_t)descriptor.proc_fd);
        continuum_hash_u64(&hash, descriptor.proc_fdtype);

        switch (descriptor.proc_fdtype) {
            case PROX_FDTYPE_VNODE: {
                struct vnode_fdinfowithpath info;
                memset(&info, 0, sizeof(info));
                int bytes = proc_pidfdinfo(
                    process_id,
                    descriptor.proc_fd,
                    PROC_PIDFDVNODEPATHINFO,
                    &info,
                    sizeof(info)
                );
                if (bytes != (int)sizeof(info)) {
                    status = CONTINUUM_STATUS_MACH_ERROR;
                    break;
                }
                fingerprint->vnode_count += 1;
                continuum_hash_file_info(&hash, &info.pfi, fingerprint);
                continuum_hash_u64(&hash, info.pvip.vip_vi.vi_stat.vst_dev);
                continuum_hash_u64(&hash, info.pvip.vip_vi.vi_stat.vst_ino);
                /* vnode generation/content revisions can advance on writes;
                   device+inode+path remain the descriptor identity guard. */
                /* File length is mutable content state restored by the file
                   checkpoint layer, not immutable descriptor identity. */
                continuum_hash_bytes(
                    &hash,
                    info.pvip.vip_path,
                    strnlen(info.pvip.vip_path, sizeof(info.pvip.vip_path))
                );
                break;
            }
            case PROX_FDTYPE_SOCKET: {
                struct socket_fdinfo info;
                memset(&info, 0, sizeof(info));
                int bytes = proc_pidfdinfo(
                    process_id,
                    descriptor.proc_fd,
                    PROC_PIDFDSOCKETINFO,
                    &info,
                    sizeof(info)
                );
                if (bytes != (int)sizeof(info)) {
                    status = CONTINUUM_STATUS_MACH_ERROR;
                    break;
                }
                fingerprint->socket_count += 1;
                continuum_hash_file_info(&hash, &info.pfi, fingerprint);
                continuum_hash_u64(&hash, info.psi.soi_so);
                continuum_hash_u64(&hash, info.psi.soi_pcb);
                continuum_hash_u64(&hash, (uint64_t)(uint32_t)info.psi.soi_type);
                continuum_hash_u64(&hash, (uint64_t)(uint32_t)info.psi.soi_protocol);
                continuum_hash_u64(&hash, (uint64_t)(uint32_t)info.psi.soi_family);
                break;
            }
            case PROX_FDTYPE_PIPE: {
                struct pipe_fdinfo info;
                memset(&info, 0, sizeof(info));
                int bytes = proc_pidfdinfo(
                    process_id,
                    descriptor.proc_fd,
                    PROC_PIDFDPIPEINFO,
                    &info,
                    sizeof(info)
                );
                if (bytes != (int)sizeof(info)) {
                    status = CONTINUUM_STATUS_MACH_ERROR;
                    break;
                }
                fingerprint->pipe_count += 1;
                continuum_hash_file_info(&hash, &info.pfi, fingerprint);
                continuum_hash_u64(&hash, info.pipeinfo.pipe_handle);
                continuum_hash_u64(&hash, info.pipeinfo.pipe_peerhandle);
                break;
            }
            case PROX_FDTYPE_KQUEUE: {
                struct kqueue_fdinfo info;
                memset(&info, 0, sizeof(info));
                int bytes = proc_pidfdinfo(
                    process_id,
                    descriptor.proc_fd,
                    PROC_PIDFDKQUEUEINFO,
                    &info,
                    sizeof(info)
                );
                if (bytes != (int)sizeof(info)) {
                    status = CONTINUUM_STATUS_MACH_ERROR;
                    break;
                }
                fingerprint->kqueue_count += 1;
                continuum_hash_file_info(&hash, &info.pfi, fingerprint);
                continuum_hash_u64(&hash, info.kqueueinfo.kq_stat.vst_ino);
                break;
            }
            case PROX_FDTYPE_PSHM: {
                struct pshm_fdinfo info;
                memset(&info, 0, sizeof(info));
                int bytes = proc_pidfdinfo(
                    process_id,
                    descriptor.proc_fd,
                    PROC_PIDFDPSHMINFO,
                    &info,
                    sizeof(info)
                );
                if (bytes != (int)sizeof(info)) {
                    status = CONTINUUM_STATUS_MACH_ERROR;
                    break;
                }
                fingerprint->shared_memory_count += 1;
                continuum_hash_file_info(&hash, &info.pfi, fingerprint);
                continuum_hash_u64(&hash, info.pshminfo.pshm_stat.vst_ino);
                continuum_hash_u64(&hash, info.pshminfo.pshm_mappaddr);
                continuum_hash_bytes(
                    &hash,
                    info.pshminfo.pshm_name,
                    strnlen(info.pshminfo.pshm_name, sizeof(info.pshminfo.pshm_name))
                );
                break;
            }
            case PROX_FDTYPE_PSEM: {
                struct psem_fdinfo info;
                memset(&info, 0, sizeof(info));
                int bytes = proc_pidfdinfo(
                    process_id,
                    descriptor.proc_fd,
                    PROC_PIDFDPSEMINFO,
                    &info,
                    sizeof(info)
                );
                if (bytes != (int)sizeof(info)) {
                    status = CONTINUUM_STATUS_MACH_ERROR;
                    break;
                }
                fingerprint->semaphore_count += 1;
                continuum_hash_file_info(&hash, &info.pfi, fingerprint);
                continuum_hash_u64(&hash, info.pseminfo.psem_stat.vst_ino);
                continuum_hash_bytes(
                    &hash,
                    info.pseminfo.psem_name,
                    strnlen(info.pseminfo.psem_name, sizeof(info.pseminfo.psem_name))
                );
                break;
            }
            default:
                fingerprint->unsupported_descriptor_count += 1;
                break;
        }
        if (status != CONTINUUM_STATUS_OK) {
            break;
        }
    }

    if (status == CONTINUUM_STATUS_OK) {
        fingerprint->file_descriptor_count = descriptor_count;
        fingerprint->descriptor_table_hash = hash;
    }
    free(descriptors);
    return status;
}

static int continuum_ipc_name_compare(const void *left, const void *right) {
    const ipc_info_name_t *left_info = left;
    const ipc_info_name_t *right_info = right;
    if (left_info->iin_name < right_info->iin_name) {
        return -1;
    }
    if (left_info->iin_name > right_info->iin_name) {
        return 1;
    }
    return 0;
}

static continuum_status continuum_capture_mach_space_fingerprint(
    mach_port_t task,
    continuum_remote_resource_fingerprint *fingerprint
) {
    ipc_info_space_t space_info;
    memset(&space_info, 0, sizeof(space_info));
    ipc_info_name_array_t table = NULL;
    mach_msg_type_number_t table_count = 0;
    ipc_info_tree_name_array_t tree = NULL;
    mach_msg_type_number_t tree_count = 0;
    kern_return_t result = mach_port_space_info(
        task,
        &space_info,
        &table,
        &table_count,
        &tree,
        &tree_count
    );
    if (result != KERN_SUCCESS) {
        return CONTINUUM_STATUS_MACH_ERROR;
    }

    qsort(table, table_count, sizeof(*table), continuum_ipc_name_compare);
    uint64_t hash = CONTINUUM_FNV_OFFSET;
    continuum_hash_u64(&hash, space_info.iis_genno_mask);
    for (mach_msg_type_number_t index = 0; index < table_count; index += 1) {
        const ipc_info_name_t entry = table[index];
        if (entry.iin_type == MACH_PORT_TYPE_NONE) {
            continue;
        }
        fingerprint->mach_name_count += 1;
        continuum_hash_u64(&hash, entry.iin_name);
        continuum_hash_u64(&hash, entry.iin_type);
        continuum_hash_u64(&hash, entry.iin_urefs);
        continuum_hash_u64(&hash, entry.iin_object);
        if ((entry.iin_type & MACH_PORT_TYPE_SEND) != 0) {
            fingerprint->mach_send_right_count += 1;
        }
        if ((entry.iin_type & MACH_PORT_TYPE_RECEIVE) != 0) {
            fingerprint->mach_receive_right_count += 1;
        }
        if ((entry.iin_type & MACH_PORT_TYPE_SEND_ONCE) != 0) {
            fingerprint->mach_send_once_right_count += 1;
        }
        if ((entry.iin_type & MACH_PORT_TYPE_PORT_SET) != 0) {
            fingerprint->mach_port_set_count += 1;
        }
        if ((entry.iin_type & MACH_PORT_TYPE_DEAD_NAME) != 0) {
            fingerprint->mach_dead_name_count += 1;
        }
    }
    fingerprint->mach_space_hash = hash;

    if (table != NULL) {
        (void)vm_deallocate(
            mach_task_self(),
            (vm_address_t)table,
            (vm_size_t)(table_count * sizeof(*table))
        );
    }
    if (tree != NULL) {
        (void)vm_deallocate(
            mach_task_self(),
            (vm_address_t)tree,
            (vm_size_t)(tree_count * sizeof(*tree))
        );
    }
    return CONTINUUM_STATUS_OK;
}

static continuum_status continuum_capture_resource_fingerprint_suspended(
    continuum_remote_session *session,
    continuum_remote_resource_fingerprint *out_fingerprint
) {
    if (session == NULL || out_fingerprint == NULL
        || session->task == MACH_PORT_NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    memset(out_fingerprint, 0, sizeof(*out_fingerprint));

    continuum_status status = continuum_validate_session_identity(session);
    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_capture_descriptor_fingerprint(
            session->identity.process_id,
            out_fingerprint
        );
    }
    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_capture_mach_space_fingerprint(
            session->task,
            out_fingerprint
        );
    }

    continuum_remote_thread_snapshot *threads = NULL;
    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_capture_thread_snapshot(session->task, &threads);
    }
    if (status == CONTINUUM_STATUS_OK) {
        out_fingerprint->thread_count = threads->count;
        out_fingerprint->thread_set_hash = threads->set_hash;
    }
    continuum_remote_thread_snapshot_destroy(threads);
    return status;
}

typedef struct continuum_remote_thread_port_entry {
    uint64_t identifier;
    thread_act_t port;
} continuum_remote_thread_port_entry;

static int continuum_thread_port_entry_compare(const void *left, const void *right) {
    const continuum_remote_thread_port_entry *left_entry = left;
    const continuum_remote_thread_port_entry *right_entry = right;
    if (left_entry->identifier < right_entry->identifier) {
        return -1;
    }
    if (left_entry->identifier > right_entry->identifier) {
        return 1;
    }
    return 0;
}

static continuum_status continuum_restore_thread_snapshot(
    mach_port_t task,
    const continuum_remote_thread_snapshot *snapshot,
    const continuum_remote_thread_snapshot *current,
    uint64_t *out_restored_count
) {
    if (task == MACH_PORT_NULL || snapshot == NULL || current == NULL
        || out_restored_count == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    *out_restored_count = 0;

#if !defined(__arm64__)
    return CONTINUUM_STATUS_UNSUPPORTED_ARCHITECTURE;
#else
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t thread_count = 0;
    kern_return_t result = task_threads(task, &threads, &thread_count);
    if (result != KERN_SUCCESS) {
        return CONTINUUM_STATUS_THREAD_STATE_FAILED;
    }

    continuum_status status = CONTINUUM_STATUS_OK;
    continuum_remote_thread_port_entry *entries = NULL;
    if (thread_count > 0) {
        entries = calloc(thread_count, sizeof(*entries));
        if (entries == NULL) {
            status = CONTINUUM_STATUS_OUT_OF_MEMORY;
        }
    }

    for (mach_msg_type_number_t index = 0;
         status == CONTINUUM_STATUS_OK && index < thread_count;
         index += 1) {
        thread_identifier_info_data_t identifier_info;
        mach_msg_type_number_t identifier_count = THREAD_IDENTIFIER_INFO_COUNT;
        result = thread_info(
            threads[index],
            THREAD_IDENTIFIER_INFO,
            (thread_info_t)&identifier_info,
            &identifier_count
        );
        if (result != KERN_SUCCESS) {
            status = CONTINUUM_STATUS_THREAD_STATE_FAILED;
            break;
        }
        entries[index].identifier = identifier_info.thread_id;
        entries[index].port = threads[index];
    }
    if (status == CONTINUUM_STATUS_OK) {
        qsort(entries, thread_count, sizeof(*entries), continuum_thread_port_entry_compare);
    }

    for (size_t index = 0;
         status == CONTINUUM_STATUS_OK && index < snapshot->count;
         index += 1) {
        const continuum_remote_thread_entry *saved = &snapshot->entries[index];
        const continuum_remote_thread_entry *live =
            continuum_find_thread_entry(current, saved->identifier);
        mach_port_t port = MACH_PORT_NULL;
        for (mach_msg_type_number_t port_index = 0;
             port_index < thread_count;
             port_index += 1) {
            if (entries[port_index].identifier == saved->identifier) {
                port = entries[port_index].port;
                break;
            }
        }
        if (live == NULL || port == MACH_PORT_NULL) {
            if (saved->origin == CONTINUUM_REMOTE_THREAD_ORIGIN_WORKQUEUE) {
                *out_restored_count += 1;
                continue;
            }
            status = CONTINUUM_STATUS_THREAD_SET_CHANGED;
            break;
        }
        if (saved->preserves_kernel_continuation) {
            if (!live->preserves_kernel_continuation
                || live->identifier != saved->identifier) {
                status = CONTINUUM_STATUS_THREAD_STATE_FAILED;
                break;
            }
            *out_restored_count += 1;
            continue;
        }
        mach_msg_type_number_t vector_count =
            (mach_msg_type_number_t)(saved->vector_length / sizeof(natural_t));
        result = thread_set_state(
            port,
            saved->vector_flavor,
            (thread_state_t)saved->vector_bytes,
            vector_count
        );
        if (result != KERN_SUCCESS) {
            status = CONTINUUM_STATUS_THREAD_RESTORE_FAILED;
            break;
        }

        mach_msg_type_number_t general_count =
            (mach_msg_type_number_t)(saved->general_length / sizeof(natural_t));
        result = thread_set_state(
            port,
            saved->general_flavor,
            (thread_state_t)saved->general_bytes,
            general_count
        );
        if (result != KERN_SUCCESS) {
            status = CONTINUUM_STATUS_THREAD_RESTORE_FAILED;
            break;
        }
        *out_restored_count += 1;
    }

    free(entries);
    for (mach_msg_type_number_t index = 0; index < thread_count; index += 1) {
        mach_port_deallocate(mach_task_self(), threads[index]);
    }
    if (threads != NULL) {
        vm_deallocate(
            mach_task_self(),
            (vm_address_t)threads,
            (vm_size_t)(thread_count * sizeof(thread_act_t))
        );
    }
    return status;
#endif
}

static continuum_status continuum_validate_process_snapshot_layout(
    const continuum_remote_process_snapshot *current,
    const continuum_remote_process_snapshot *saved
) {
    if (current == NULL || saved == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    if (!continuum_identity_equal(&current->identity, &saved->identity)) {
        return CONTINUUM_STATUS_PROCESS_IDENTITY_CHANGED;
    }
    if (saved->has_isolated_app_state
        && current->has_isolated_app_state) {
        for (size_t index = 0; index < saved->region_count; index += 1) {
            const continuum_remote_process_region *saved_region =
                &saved->regions[index];
            if (!saved_region->is_app_owned_state) {
                continue;
            }
            const continuum_remote_process_region *current_region =
                continuum_find_process_region(
                    current,
                    saved_region->address,
                    saved_region->length
                );
            if (current_region == NULL
                || !current_region->is_app_owned_state
                || !continuum_process_region_metadata_equal(
                    current_region,
                    saved_region
                )) {
                return CONTINUUM_STATUS_REGION_MAPPING_CHANGED;
            }
        }
        return CONTINUUM_STATUS_OK;
    }
    uint32_t resource_changes = continuum_remote_resource_fingerprint_changes(
        &saved->resources,
        &current->resources
    );
    if ((resource_changes
            & CONTINUUM_RESOURCE_CHANGE_UNSUPPORTED_DESCRIPTOR) != 0) {
        return CONTINUUM_STATUS_VALIDATION_FAILED;
    }
    if ((resource_changes & CONTINUUM_RESOURCE_CHANGE_DESCRIPTOR_TABLE) != 0) {
        return CONTINUUM_STATUS_DESCRIPTOR_TABLE_CHANGED;
    }
    if ((resource_changes & CONTINUUM_RESOURCE_CHANGE_MACH_SPACE) != 0
        && !continuum_saved_mach_rights_remain_valid(saved, current)) {
        return CONTINUUM_STATUS_MACH_NAMESPACE_CHANGED;
    }
    if ((resource_changes & CONTINUUM_RESOURCE_CHANGE_THREAD_SET) != 0
        && !continuum_stable_threads_remain_valid(
            saved->threads,
            current->threads
        )) {
        return CONTINUUM_STATUS_THREAD_SET_CHANGED;
    }
    for (size_t index = 0; index < saved->region_count; index += 1) {
        const continuum_remote_process_region *current_region =
            continuum_find_process_region(
                current,
                saved->regions[index].address,
                saved->regions[index].length
            );
        if (current_region == NULL) {
            return CONTINUUM_STATUS_REGION_MAPPING_CHANGED;
        }
        if (!continuum_process_region_metadata_equal(
                current_region,
                &saved->regions[index]
            )) {
            return CONTINUUM_STATUS_REGION_MAPPING_CHANGED;
        }
    }
    return CONTINUUM_STATUS_OK;
}

static int continuum_region_contains_address(
    const continuum_remote_process_region *region,
    uint64_t address
) {
    if (region == NULL || address == 0 || region->length == 0) {
        return 0;
    }
    uint64_t end = region->address + region->length;
    return end >= region->address
        && address >= region->address
        && address < end;
}

static int continuum_region_preserves_kernel_thread_state(
    const continuum_remote_process_region *region,
    const continuum_remote_thread_snapshot *threads
) {
    if (region == NULL || threads == NULL) {
        return 0;
    }
    for (size_t index = 0; index < threads->count; index += 1) {
        const continuum_remote_thread_entry *thread = &threads->entries[index];
        if (!thread->preserves_kernel_continuation) {
            continue;
        }
#if defined(__arm64__)
        if (thread->general_flavor == ARM_THREAD_STATE64
            && thread->general_length == sizeof(arm_thread_state64_t)) {
            arm_thread_state64_t state;
            memcpy(&state, thread->general_bytes, sizeof(state));
            if (continuum_region_contains_address(
                    region,
                    arm_thread_state64_get_sp(state)
                )) {
                return 1;
            }
        }
#endif
    }
    return 0;
}

static continuum_status continuum_clear_preserved_workqueue_caches(
    mach_port_t task,
    const continuum_remote_thread_snapshot *saved,
    const continuum_remote_thread_snapshot *current
) {
    if (task == MACH_PORT_NULL || saved == NULL || current == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    enum { CONTINUUM_LIBDISPATCH_CACHE_TSD_SLOT = 22 };
    const uintptr_t empty_cache = 0;
    for (size_t index = 0; index < saved->count; index += 1) {
        const continuum_remote_thread_entry *saved_thread =
            &saved->entries[index];
        const continuum_remote_thread_entry *current_thread =
            continuum_find_thread_entry(current, saved_thread->identifier);
        if (!saved_thread->preserves_kernel_continuation
            || saved_thread->origin != CONTINUUM_REMOTE_THREAD_ORIGIN_WORKQUEUE
            || current_thread == NULL
            || current_thread->thread_handle == 0) {
            continue;
        }
        uint64_t cache_address = 0;
        if (!continuum_add_u64(
                current_thread->thread_handle,
                CONTINUUM_LIBDISPATCH_CACHE_TSD_SLOT * sizeof(uintptr_t),
                &cache_address
            )) {
            return CONTINUUM_STATUS_RANGE_ERROR;
        }
        uint64_t written = 0;
        continuum_status status = continuum_write_task_bytes(
            task,
            cache_address,
            &empty_cache,
            sizeof(empty_cache),
            &written
        );
        if (status != CONTINUUM_STATUS_OK || written != sizeof(empty_cache)) {
            return status == CONTINUUM_STATUS_OK
                ? CONTINUUM_STATUS_SHORT_WRITE
                : status;
        }
    }
    return CONTINUUM_STATUS_OK;
}

static int continuum_process_region_page_is_rewindable(
    const continuum_remote_process_region *region,
    uint64_t offset,
    size_t length
) {
    if (region == NULL || length == 0 || offset >= region->length) {
        return 0;
    }
    uint64_t page_address = 0;
    if (!continuum_add_u64(region->address, offset, &page_address)) {
        return 0;
    }
    for (size_t index = 0;
         index < region->app_state_allocation_count;
         index += 1) {
        if (continuum_ranges_overlap(
                page_address,
                length,
                region->app_state_allocations[index].address,
                region->app_state_allocations[index].size
            )) {
            return 1;
        }
    }
    return 0;
}

static continuum_status continuum_apply_process_snapshot(
    mach_port_t task,
    const continuum_remote_process_snapshot *snapshot,
    const continuum_remote_process_snapshot *current,
    continuum_remote_process_restore_report *out_report
) {
    if (task == MACH_PORT_NULL || snapshot == NULL || current == NULL
        || out_report == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    memset(out_report, 0, sizeof(*out_report));

    const size_t page_size = (size_t)getpagesize();

    continuum_status status = CONTINUUM_STATUS_OK;
    for (size_t index = 0;
        status == CONTINUUM_STATUS_OK && index < snapshot->region_count;
         index += 1) {
        const continuum_remote_process_region *region = &snapshot->regions[index];
        const continuum_remote_process_region *current_region =
            continuum_find_process_region(
                current,
                region->address,
                region->length
            );
        if (current_region == NULL) {
            /* A safety snapshot may contain regions allocated after the
               checkpoint. Forward restore leaves them live, so rollback has
               nothing to write for those unmatched regions. */
            continue;
        }
        if (continuum_region_preserves_kernel_thread_state(
                region,
                snapshot->threads
            )) {
            continue;
        }
        if (snapshot->has_isolated_app_state) {
            if (!region->is_app_owned_state
                || !current_region->is_app_owned_state) {
                continue;
            }
        } else {
            if (region->preserves_live_derived_graphics
                || current_region->preserves_live_derived_graphics) {
                continue;
            }
        }
        if (!continuum_process_region_metadata_equal(region, current_region)
            || region->bytes == NULL
            || region->page_dispositions == NULL
            || current_region->bytes == NULL
            || current_region->page_dispositions == NULL
            || region->page_count != current_region->page_count) {
            status = CONTINUUM_STATUS_REGION_MAPPING_CHANGED;
            break;
        }

        int region_written = 0;
        size_t page = 0;
        while (page < region->page_count) {
            uint64_t offset = (uint64_t)page * page_size;
            size_t length = (size_t)((region->length - offset) < page_size
                ? (region->length - offset)
                : page_size);
            if (snapshot->has_isolated_app_state
                && !continuum_process_region_page_is_rewindable(
                    region,
                    offset,
                    length
                )) {
                page += 1;
                continue;
            }
            if (memcmp(
                    region->bytes + offset,
                    current_region->bytes + offset,
                    length
                ) == 0) {
                page += 1;
                continue;
            }

            const size_t run_start_page = page;
            page += 1;
            while (page < region->page_count) {
                offset = (uint64_t)page * page_size;
                length = (size_t)((region->length - offset) < page_size
                    ? (region->length - offset)
                    : page_size);
                if (snapshot->has_isolated_app_state
                    && !continuum_process_region_page_is_rewindable(
                        region,
                        offset,
                        length
                    )) {
                    break;
                }
                if (memcmp(
                        region->bytes + offset,
                        current_region->bytes + offset,
                        length
                    ) == 0) {
                    break;
                }
                page += 1;
            }

            const uint64_t run_offset = (uint64_t)run_start_page * page_size;
            const uint64_t run_end = ((uint64_t)page * page_size) < region->length
                ? (uint64_t)page * page_size
                : region->length;
            const size_t run_length = (size_t)(run_end - run_offset);
            uint64_t run_address = 0;
            if (!continuum_add_u64(
                    region->address,
                    run_offset,
                    &run_address
                )) {
                status = CONTINUUM_STATUS_RANGE_ERROR;
                break;
            }
            uint64_t written = 0;
            status = continuum_write_task_bytes(
                task,
                run_address,
                region->bytes + run_offset,
                run_length,
                &written
            );
            out_report->bytes_written += written;
            if (status != CONTINUUM_STATUS_OK || written != run_length) {
                if (status == CONTINUUM_STATUS_OK) {
                    status = CONTINUUM_STATUS_SHORT_WRITE;
                }
                break;
            }
            region_written = 1;
        }
        if (region_written) {
            out_report->regions_written += 1;
        }

        if (status == CONTINUUM_STATUS_OK && region_written) {
            mach_vm_address_t verification_address = 0;
            vm_prot_t current_protection = VM_PROT_NONE;
            vm_prot_t maximum_protection = VM_PROT_NONE;
            kern_return_t result = mach_vm_remap(
                mach_task_self(),
                &verification_address,
                region->length,
                0,
                VM_FLAGS_ANYWHERE,
                task,
                region->address,
                FALSE,
                &current_protection,
                &maximum_protection,
                VM_INHERIT_NONE
            );
            if (result != KERN_SUCCESS || verification_address == 0) {
                status = CONTINUUM_STATUS_MACH_ERROR;
                break;
            }
            result = mach_vm_protect(
                mach_task_self(),
                verification_address,
                region->length,
                FALSE,
                VM_PROT_READ
            );
            if (result != KERN_SUCCESS) {
                status = CONTINUUM_STATUS_MACH_ERROR;
            } else {
                const uint8_t *verified =
                    (const uint8_t *)(uintptr_t)verification_address;
                for (page = 0; page < region->page_count; page += 1) {
                    uint64_t offset = (uint64_t)page * page_size;
                    size_t length = (size_t)((region->length - offset) < page_size
                        ? (region->length - offset)
                        : page_size);
                    if (snapshot->has_isolated_app_state
                        && !continuum_process_region_page_is_rewindable(
                            region,
                            offset,
                            length
                        )) {
                        continue;
                    }
                    if (memcmp(
                            region->bytes + offset,
                            current_region->bytes + offset,
                            length
                        ) != 0
                        && memcmp(region->bytes + offset, verified + offset, length)
                            != 0) {
                        status = CONTINUUM_STATUS_VALIDATION_FAILED;
                        break;
                    }
                }
            }
            (void)mach_vm_deallocate(
                mach_task_self(),
                verification_address,
                region->length
            );
        }
    }
    if (status == CONTINUUM_STATUS_OK) {
        out_report->memory_readback_verified = 1;
    }
    if (status == CONTINUUM_STATUS_OK
        && !snapshot->has_isolated_app_state) {
        status = continuum_clear_preserved_workqueue_caches(
            task,
            snapshot->threads,
            current->threads
        );
    }
    if (status == CONTINUUM_STATUS_OK
        && !snapshot->has_isolated_app_state) {
        status = continuum_restore_thread_snapshot(
            task,
            snapshot->threads,
            current->threads,
            &out_report->thread_states_restored
        );
    } else if (status == CONTINUUM_STATUS_OK) {
        out_report->thread_states_restored = snapshot->threads->count;
    }
    return status;
}

static continuum_status continuum_discharge_owned_suspensions(
    continuum_remote_session *session,
    uint32_t maximum_attempts
) {
    if (session == NULL || maximum_attempts == 0) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    if (session->is_self || session->owned_suspend_count == 0) {
        return CONTINUUM_STATUS_OK;
    }

    uint32_t attempts = 0;
    while (session->owned_suspend_count > 0 && attempts < maximum_attempts) {
        attempts += 1;
        if (task_resume(session->task) == KERN_SUCCESS) {
            session->owned_suspend_count -= 1;
        }
    }
    return session->owned_suspend_count == 0
        ? CONTINUUM_STATUS_OK
        : CONTINUUM_STATUS_RESUME_FAILED;
}

static continuum_status continuum_suspend_session(
    continuum_remote_session *session,
    int *out_did_suspend
) {
    if (session == NULL || out_did_suspend == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    *out_did_suspend = 0;
    if (session->is_self) {
        return CONTINUUM_STATUS_OK;
    }
    if (session->owned_suspend_count > 0) {
        continuum_status recovery_status = continuum_discharge_owned_suspensions(
            session,
            CONTINUUM_RESUME_ATTEMPT_LIMIT
        );
        if (recovery_status != CONTINUUM_STATUS_OK) {
            return recovery_status;
        }
    }
    kern_return_t result = task_suspend(session->task);
    if (result != KERN_SUCCESS) {
        return CONTINUUM_STATUS_SUSPEND_FAILED;
    }
    session->owned_suspend_count += 1;
    *out_did_suspend = 1;
    return CONTINUUM_STATUS_OK;
}

static continuum_status continuum_resume_session(
    continuum_remote_session *session,
    int did_suspend
) {
    if (session == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    if (!did_suspend) {
        return CONTINUUM_STATUS_OK;
    }
    if (session->owned_suspend_count == 0) {
        return CONTINUUM_STATUS_RESUME_FAILED;
    }
    return continuum_discharge_owned_suspensions(
        session,
        CONTINUUM_RESUME_ATTEMPT_LIMIT
    );
}

continuum_status continuum_runtime_inspect_self(continuum_runtime_info *out_info) {
    if (out_info == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }

    continuum_runtime_info result;
    memset(&result, 0, sizeof(result));
    result.page_size = (uint64_t)getpagesize();

    mach_port_t task = mach_task_self();
    mach_vm_address_t address = 0;
    for (;;) {
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object_name = MACH_PORT_NULL;
        kern_return_t status = mach_vm_region(
            task,
            &address,
            &size,
            VM_REGION_BASIC_INFO_64,
            (vm_region_info_t)&info,
            &count,
            &object_name
        );
        if (status == KERN_INVALID_ADDRESS) {
            break;
        }
        if (status != KERN_SUCCESS) {
            return CONTINUUM_STATUS_MACH_ERROR;
        }
        if (object_name != MACH_PORT_NULL) {
            mach_port_deallocate(task, object_name);
        }

        result.region_count += 1;
        if ((info.protection & VM_PROT_READ) != 0) {
            result.readable_region_count += 1;
        }
        if ((info.protection & VM_PROT_WRITE) != 0) {
            result.writable_region_count += 1;
            if (!continuum_add_u64(result.writable_bytes, size, &result.writable_bytes)) {
                return CONTINUUM_STATUS_RANGE_ERROR;
            }
        }
        if ((info.protection & VM_PROT_EXECUTE) != 0) {
            result.executable_region_count += 1;
        }
        if (!continuum_add_u64(result.virtual_bytes, size, &result.virtual_bytes)) {
            return CONTINUUM_STATUS_RANGE_ERROR;
        }
        if (size == 0 || UINT64_MAX - address < size) {
            break;
        }
        address += size;
    }

    thread_act_array_t threads = NULL;
    mach_msg_type_number_t thread_count = 0;
    kern_return_t thread_status = task_threads(task, &threads, &thread_count);
    if (thread_status != KERN_SUCCESS) {
        return CONTINUUM_STATUS_MACH_ERROR;
    }
    result.thread_count = thread_count;
    for (mach_msg_type_number_t index = 0; index < thread_count; index += 1) {
        mach_port_deallocate(task, threads[index]);
    }
    if (threads != NULL) {
        vm_deallocate(
            task,
            (vm_address_t)threads,
            (vm_size_t)(thread_count * sizeof(thread_act_t))
        );
    }
    *out_info = result;
    return CONTINUUM_STATUS_OK;
}

continuum_status continuum_tracked_region_create(
    void *address,
    size_t length,
    continuum_tracked_region **out_region
) {
    if (address == NULL || length == 0 || out_region == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    *out_region = NULL;

    continuum_tracked_region *region = calloc(1, sizeof(*region));
    if (region == NULL) {
        return CONTINUUM_STATUS_OUT_OF_MEMORY;
    }
    region->address = address;
    region->length = length;
    region->next_identifier = 1;
    *out_region = region;
    return CONTINUUM_STATUS_OK;
}

continuum_status continuum_tracked_region_checkpoint(
    continuum_tracked_region *region,
    uint64_t *out_checkpoint_id
) {
    if (region == NULL || out_checkpoint_id == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }

    if (region->checkpoint_count == region->checkpoint_capacity) {
        size_t new_capacity = region->checkpoint_capacity == 0
            ? 4
            : region->checkpoint_capacity * 2;
        if (new_capacity < region->checkpoint_capacity
            || new_capacity > SIZE_MAX / sizeof(continuum_checkpoint)) {
            return CONTINUUM_STATUS_RANGE_ERROR;
        }
        continuum_checkpoint *resized = realloc(
            region->checkpoints,
            new_capacity * sizeof(continuum_checkpoint)
        );
        if (resized == NULL) {
            return CONTINUUM_STATUS_OUT_OF_MEMORY;
        }
        region->checkpoints = resized;
        region->checkpoint_capacity = new_capacity;
    }

    uint8_t *copy = malloc(region->length);
    if (copy == NULL) {
        return CONTINUUM_STATUS_OUT_OF_MEMORY;
    }
    continuum_status read_status = continuum_read_task_bytes(
        mach_task_self(),
        (mach_vm_address_t)(uintptr_t)region->address,
        region->length,
        copy
    );
    if (read_status != CONTINUUM_STATUS_OK) {
        free(copy);
        return read_status;
    }

    uint64_t identifier = region->next_identifier;
    if (identifier == UINT64_MAX) {
        memset(copy, 0, region->length);
        free(copy);
        return CONTINUUM_STATUS_RANGE_ERROR;
    }
    region->next_identifier += 1;
    region->checkpoints[region->checkpoint_count].identifier = identifier;
    region->checkpoints[region->checkpoint_count].bytes = copy;
    region->checkpoint_count += 1;
    *out_checkpoint_id = identifier;
    return CONTINUUM_STATUS_OK;
}

continuum_status continuum_tracked_region_restore(
    continuum_tracked_region *region,
    uint64_t checkpoint_id
) {
    if (region == NULL || checkpoint_id == 0) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    for (size_t index = 0; index < region->checkpoint_count; index += 1) {
        if (region->checkpoints[index].identifier == checkpoint_id) {
            uint64_t written = 0;
            return continuum_write_task_bytes(
                mach_task_self(),
                (mach_vm_address_t)(uintptr_t)region->address,
                region->checkpoints[index].bytes,
                region->length,
                &written
            );
        }
    }
    return CONTINUUM_STATUS_CHECKPOINT_NOT_FOUND;
}

size_t continuum_tracked_region_checkpoint_count(
    const continuum_tracked_region *region
) {
    return region == NULL ? 0 : region->checkpoint_count;
}

void continuum_tracked_region_destroy(continuum_tracked_region *region) {
    if (region == NULL) {
        return;
    }
    for (size_t index = 0; index < region->checkpoint_count; index += 1) {
        if (region->checkpoints[index].bytes != NULL) {
            memset(region->checkpoints[index].bytes, 0, region->length);
            free(region->checkpoints[index].bytes);
        }
    }
    free(region->checkpoints);
    memset(region, 0, sizeof(*region));
    free(region);
}

continuum_status continuum_remote_session_open(
    int32_t process_id,
    continuum_remote_session **out_session
) {
    if (process_id <= 0 || out_session == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    *out_session = NULL;

    continuum_remote_identity identity;
    continuum_status status = continuum_read_process_identity(process_id, &identity);
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }

    continuum_remote_session *session = calloc(1, sizeof(*session));
    if (session == NULL) {
        return CONTINUUM_STATUS_OUT_OF_MEMORY;
    }

    session->is_self = process_id == getpid();
    if (session->is_self) {
        session->task = mach_task_self();
    } else {
        kern_return_t result = task_for_pid(
            mach_task_self(),
            process_id,
            &session->task
        );
        if (result != KERN_SUCCESS || session->task == MACH_PORT_NULL) {
            free(session);
            return CONTINUUM_STATUS_ACCESS_DENIED;
        }
        session->owns_task_port = 1;
    }

    session->identity = identity;
    status = continuum_validate_session_identity(session);
    if (status != CONTINUUM_STATUS_OK) {
        if (session->owns_task_port) {
            mach_port_deallocate(mach_task_self(), session->task);
        }
        memset(session, 0, sizeof(*session));
        free(session);
        return status;
    }
    *out_session = session;
    return CONTINUUM_STATUS_OK;
}

continuum_status continuum_remote_process_has_app_state_zone(
    int32_t process_id,
    uint8_t *out_has_app_state_zone
) {
    if (process_id <= 0 || out_has_app_state_zone == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    *out_has_app_state_zone = 0;

    continuum_remote_session *session = NULL;
    continuum_status status = continuum_remote_session_open(
        process_id,
        &session
    );
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }

    mach_vm_address_t address = 0;
    natural_t depth = 0;
    while (status == CONTINUUM_STATUS_OK) {
        mach_vm_size_t region_size = 0;
        vm_region_submap_info_data_64_t info;
        memset(&info, 0, sizeof(info));
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t result = mach_vm_region_recurse(
            session->task,
            &address,
            &region_size,
            &depth,
            (vm_region_recurse_info_t)&info,
            &count
        );
        if (result == KERN_INVALID_ADDRESS) {
            break;
        }
        if (result != KERN_SUCCESS || region_size == 0) {
            status = CONTINUUM_STATUS_MACH_ERROR;
            break;
        }
        if (info.is_submap) {
            depth += 1;
            continue;
        }
        if (continuum_region_is_app_state(
                address,
                region_size,
                info.user_tag
            )) {
            *out_has_app_state_zone = 1;
            break;
        }
        if (UINT64_MAX - address < region_size) {
            break;
        }
        address += region_size;
    }
    continuum_remote_session_destroy(session);
    return status;
}

continuum_status continuum_remote_process_has_bootstrap(
    int32_t process_id,
    const char *library_path,
    uint8_t *out_has_bootstrap
) {
    if (process_id <= 0 || library_path == NULL || library_path[0] == '\0'
        || out_has_bootstrap == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    *out_has_bootstrap = 0;

    continuum_bootstrap_identity local_identity;
    continuum_status status = continuum_inspect_local_bootstrap_library(
        library_path,
        &local_identity
    );
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }

    char expected_path[PATH_MAX];
    if (realpath(library_path, expected_path) == NULL) {
        return CONTINUUM_STATUS_VALIDATION_FAILED;
    }
    continuum_remote_session *session = NULL;
    status = continuum_remote_session_open(process_id, &session);
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }

    task_dyld_info_data_t dyld_info;
    memset(&dyld_info, 0, sizeof(dyld_info));
    mach_msg_type_number_t dyld_info_count = TASK_DYLD_INFO_COUNT;
    kern_return_t result = task_info(
        session->task,
        TASK_DYLD_INFO,
        (task_info_t)&dyld_info,
        &dyld_info_count
    );
    if (result != KERN_SUCCESS || dyld_info.all_image_info_addr == 0) {
        continuum_remote_session_destroy(session);
        return CONTINUUM_STATUS_MACH_ERROR;
    }

    struct dyld_all_image_infos all_images;
    memset(&all_images, 0, sizeof(all_images));
    status = continuum_read_task_bytes(
        session->task,
        dyld_info.all_image_info_addr,
        sizeof(all_images),
        &all_images
    );
    if (status != CONTINUUM_STATUS_OK || all_images.infoArrayCount == 0
        || all_images.infoArrayCount > UINT32_C(1048576)
        || all_images.infoArray == NULL) {
        continuum_remote_session_destroy(session);
        return status == CONTINUUM_STATUS_OK
            ? CONTINUUM_STATUS_RANGE_ERROR
            : status;
    }

    size_t byte_count =
        (size_t)all_images.infoArrayCount * sizeof(struct dyld_image_info);
    struct dyld_image_info *entries = malloc(byte_count);
    if (entries == NULL) {
        continuum_remote_session_destroy(session);
        return CONTINUUM_STATUS_OUT_OF_MEMORY;
    }
    status = continuum_read_task_bytes(
        session->task,
        (mach_vm_address_t)(uintptr_t)all_images.infoArray,
        byte_count,
        entries
    );
    for (uint32_t index = 0;
         status == CONTINUUM_STATUS_OK && index < all_images.infoArrayCount;
         index += 1) {
        if (entries[index].imageLoadAddress == NULL
            || entries[index].imageFilePath == NULL) {
            continue;
        }
        char observed_path[PATH_MAX];
        char observed_canonical[PATH_MAX];
        status = continuum_read_task_cstring(
            session->task,
            (mach_vm_address_t)(uintptr_t)entries[index].imageFilePath,
            observed_path,
            sizeof(observed_path)
        );
        if (status != CONTINUUM_STATUS_OK) {
            // dyld may retain a transient or already-unmapped image-path
            // pointer while another image is being unloaded. It cannot be
            // the authenticated match because its canonical path is
            // unreadable, so skip it and continue searching. Failure to find
            // the expected path still fails closed below.
            status = CONTINUUM_STATUS_OK;
            continue;
        }
        if (realpath(observed_path, observed_canonical) == NULL
            || strcmp(expected_path, observed_canonical) != 0) {
            continue;
        }
        uint8_t remote_uuid[16];
        status = continuum_copy_remote_image_uuid(
            session->task,
            (mach_vm_address_t)(uintptr_t)entries[index].imageLoadAddress,
            remote_uuid
        );
        if (status == CONTINUUM_STATUS_OK
            && memcmp(
                remote_uuid,
                local_identity.image_uuid,
                sizeof(remote_uuid)
            ) == 0) {
            *out_has_bootstrap = 1;
        }
        break;
    }
    free(entries);
    continuum_remote_session_destroy(session);
    return status;
}

continuum_status continuum_remote_session_identity(
    const continuum_remote_session *session,
    continuum_remote_identity *out_identity
) {
    if (session == NULL || out_identity == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    continuum_status status = continuum_validate_session_identity(session);
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }
    *out_identity = session->identity;
    return CONTINUUM_STATUS_OK;
}

continuum_status continuum_remote_session_inspect_process_layout(
    continuum_remote_session *session,
    continuum_remote_process_layout_info *out_info
) {
    if (session == NULL || out_info == NULL || session->task == MACH_PORT_NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    memset(out_info, 0, sizeof(*out_info));
    continuum_status status = continuum_validate_session_identity(session);
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }
    if (session->has_active_reconstruction) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }

    int did_suspend = 0;
    status = continuum_suspend_session(session, &did_suspend);
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }

    uint64_t hash = CONTINUUM_FNV_OFFSET;
    mach_vm_address_t address = 0;
    natural_t depth = 0;
    while (status == CONTINUUM_STATUS_OK) {
        mach_vm_size_t region_size = 0;
        vm_region_submap_info_data_64_t info;
        memset(&info, 0, sizeof(info));
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t result = mach_vm_region_recurse(
            session->task,
            &address,
            &region_size,
            &depth,
            (vm_region_recurse_info_t)&info,
            &count
        );
        if (result == KERN_INVALID_ADDRESS) {
            break;
        }
        if (result != KERN_SUCCESS || region_size == 0) {
            status = CONTINUUM_STATUS_MACH_ERROR;
            break;
        }
        if (info.is_submap) {
            depth += 1;
            continue;
        }

        continuum_hash_vm_region(&hash, address, region_size, &info);
        out_info->region_count += 1;
        if (!continuum_add_u64(
                out_info->virtual_bytes,
                region_size,
                &out_info->virtual_bytes
            )) {
            status = CONTINUUM_STATUS_RANGE_ERROR;
            break;
        }
        if (UINT64_MAX - address < region_size) {
            break;
        }
        address += region_size;
    }
    out_info->layout_hash = hash;
    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_capture_image_layout_digest(
            session->task,
            &out_info->immutable_layout_digest,
            1
        );
    }

    continuum_status resume_status = continuum_resume_session(session, did_suspend);
    if (resume_status != CONTINUUM_STATUS_OK) {
        status = resume_status;
    }
    if (status != CONTINUUM_STATUS_OK) {
        memset(out_info, 0, sizeof(*out_info));
    }
    return status;
}

continuum_status continuum_remote_session_region_matches(
    continuum_remote_session *session,
    const continuum_remote_process_region_info *region,
    uint8_t *out_matches
) {
    if (session == NULL || region == NULL || out_matches == NULL
        || region->address == 0 || region->length == 0) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    *out_matches = 0;
    continuum_status status = continuum_validate_session_identity(session);
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }
    int did_suspend = 0;
    status = continuum_suspend_session(session, &did_suspend);
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }

    mach_vm_address_t address = region->address;
    mach_vm_size_t length = 0;
    natural_t depth = 0;
    vm_region_submap_info_data_64_t info;
    kern_return_t result;
    for (;;) {
        memset(&info, 0, sizeof(info));
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        result = mach_vm_region_recurse(
            session->task,
            &address,
            &length,
            &depth,
            (vm_region_recurse_info_t)&info,
            &count
        );
        if (result != KERN_SUCCESS || !info.is_submap) {
            break;
        }
        depth += 1;
    }
    if (result != KERN_SUCCESS) {
        status = CONTINUUM_STATUS_MACH_ERROR;
    } else {
        *out_matches = address == region->address
            && length == region->length
            && info.protection == region->protection
            && info.max_protection == region->maximum_protection
            && info.inheritance == region->inheritance
            && info.share_mode == region->share_mode
            && info.user_tag == region->user_tag;
    }
    continuum_status resume_status = continuum_resume_session(
        session,
        did_suspend
    );
    return status == CONTINUUM_STATUS_OK ? resume_status : status;
}

continuum_status continuum_remote_session_range_is_unmapped(
    continuum_remote_session *session,
    uint64_t address,
    uint64_t length,
    uint8_t *out_is_unmapped
) {
    if (session == NULL || address == 0 || length == 0
        || out_is_unmapped == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    *out_is_unmapped = 0;
    uint64_t requested_end = 0;
    if (!continuum_add_u64(address, length, &requested_end)) {
        return CONTINUUM_STATUS_RANGE_ERROR;
    }
    continuum_status status = continuum_validate_session_identity(session);
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }
    int did_suspend = 0;
    status = continuum_suspend_session(session, &did_suspend);
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }

    mach_vm_address_t mapping_address = address;
    mach_vm_size_t mapping_length = 0;
    vm_region_submap_info_data_64_t info;
    natural_t depth = 0;
    kern_return_t result;
    for (;;) {
        memset(&info, 0, sizeof(info));
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        result = mach_vm_region_recurse(
            session->task,
            &mapping_address,
            &mapping_length,
            &depth,
            (vm_region_recurse_info_t)&info,
            &count
        );
        if (result != KERN_SUCCESS || !info.is_submap) {
            break;
        }
        depth += 1;
    }
    if (result == KERN_INVALID_ADDRESS
        || (result == KERN_SUCCESS && mapping_address >= requested_end)) {
        *out_is_unmapped = 1;
        status = CONTINUUM_STATUS_OK;
    } else {
        status = result == KERN_SUCCESS
            ? CONTINUUM_STATUS_OK
            : CONTINUUM_STATUS_MACH_ERROR;
    }
    continuum_status resume_status = continuum_resume_session(
        session,
        did_suspend
    );
    return status == CONTINUUM_STATUS_OK ? resume_status : status;
}

continuum_status continuum_brokered_pair_authorize_remote_session(
    continuum_brokered_pair *pair,
    continuum_remote_session *session,
    continuum_brokered_process_role role
) {
    if (pair == NULL || session == NULL
        || pair->state != CONTINUUM_BROKER_PAIR_ENTRY_STOPPED
        || (role != CONTINUUM_BROKERED_PROCESS_ROOT
            && role != CONTINUUM_BROKERED_PROCESS_CHILD)
        || session->has_brokered_stop_authorization) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    pid_t process_id = role == CONTINUUM_BROKERED_PROCESS_ROOT
        ? pair->root_process_id : pair->child_process_id;
    pid_t expected_parent = role == CONTINUUM_BROKERED_PROCESS_ROOT
        ? getpid() : pair->root_process_id;
    uint64_t start_seconds = role == CONTINUUM_BROKERED_PROCESS_ROOT
        ? pair->root_start_seconds : pair->child_start_seconds;
    uint64_t start_microseconds = role == CONTINUUM_BROKERED_PROCESS_ROOT
        ? pair->root_start_microseconds : pair->child_start_microseconds;
    if (session->identity.process_id != process_id
        || session->identity.start_seconds != start_seconds
        || session->identity.start_microseconds != start_microseconds
        || !continuum_broker_process_matches(
            process_id,
            expected_parent,
            start_seconds,
            start_microseconds,
            1
        )) {
        return CONTINUUM_STATUS_PROCESS_IDENTITY_CHANGED;
    }
    if (role == CONTINUUM_BROKERED_PROCESS_CHILD) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        int attach_result = ptrace(PT_ATTACH, process_id, NULL, 0);
#pragma clang diagnostic pop
        if (attach_result != 0) {
            return CONTINUUM_STATUS_ACCESS_DENIED;
        }
        uint64_t deadline = clock_gettime_nsec_np(CLOCK_MONOTONIC)
            + UINT64_C(5000000000);
        for (;;) {
            struct proc_bsdinfo process_info;
            memset(&process_info, 0, sizeof(process_info));
            int copied = proc_pidinfo(
                process_id,
                PROC_PIDTBSDINFO,
                0,
                &process_info,
                (int)sizeof(process_info)
            );
            if (copied == (int)sizeof(process_info)
                && process_info.pbi_ppid == (uint32_t)getpid()
                && process_info.pbi_status == SSTOP
                && process_info.pbi_start_tvsec == start_seconds
                && process_info.pbi_start_tvusec == start_microseconds) {
                break;
            }
            if (copied != (int)sizeof(process_info)
                || clock_gettime_nsec_np(CLOCK_MONOTONIC) >= deadline) {
                continuum_broker_kill_and_reap_traced_child(
                    process_id,
                    clock_gettime_nsec_np(CLOCK_MONOTONIC)
                        + UINT64_C(1000000000)
                );
                return copied == (int)sizeof(process_info)
                    ? CONTINUUM_STATUS_SUSPEND_FAILED
                    : CONTINUUM_STATUS_TARGET_EXITED;
            }
            usleep(1000);
        }
    }
    session->replacement_stop_kind =
        CONTINUUM_REPLACEMENT_STOP_DIRECT_PTRACE;
    session->has_brokered_stop_authorization = 1;
    session->owns_ptrace_attachment = 1;
    session->brokered_expected_parent_process_id = expected_parent;
    session->brokered_start_seconds = start_seconds;
    session->brokered_start_microseconds = start_microseconds;
    return CONTINUUM_STATUS_OK;
}

static continuum_status continuum_validate_stopped_replacement_session(
    continuum_remote_session *session
) {
    if (session == NULL || session->task == MACH_PORT_NULL || session->is_self) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    continuum_status status = continuum_validate_session_identity(session);
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }
    struct proc_bsdinfo process_info;
    memset(&process_info, 0, sizeof(process_info));
    int copied = proc_pidinfo(
        session->identity.process_id,
        PROC_PIDTBSDINFO,
        0,
        &process_info,
        (int)sizeof(process_info)
    );
    if (copied != (int)sizeof(process_info)
        || process_info.pbi_status != SSTOP) {
        return CONTINUUM_STATUS_ACCESS_DENIED;
    }
    if (!session->has_brokered_stop_authorization) {
        return process_info.pbi_ppid == getpid()
            ? CONTINUUM_STATUS_OK
            : CONTINUUM_STATUS_ACCESS_DENIED;
    }
    if (process_info.pbi_ppid != (uint32_t)getpid()
        || process_info.pbi_start_tvsec != session->brokered_start_seconds
        || process_info.pbi_start_tvusec
            != session->brokered_start_microseconds) {
        return CONTINUUM_STATUS_PROCESS_IDENTITY_CHANGED;
    }
    return CONTINUUM_STATUS_OK;
}

static continuum_status continuum_validate_reconstruction_target(
    continuum_remote_session *session,
    const continuum_remote_process_region_info *region
) {
    if (region == NULL || region->address == 0 || region->length == 0
        || (region->address % (uint64_t)getpagesize()) != 0
        || (region->length % (uint64_t)getpagesize()) != 0
        || (region->protection & (VM_PROT_READ | VM_PROT_WRITE))
            != (VM_PROT_READ | VM_PROT_WRITE)
        || (!continuum_is_private_or_cow_share_mode(region->share_mode)
            && region->share_mode != SM_EMPTY)
        || session->has_reconstructed_thread_set) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    if (session->has_prepared_pthread_set) {
        const continuum_remote_pthread_bootstrap_report *prepared =
            &session->prepared_pthreads;
        if (prepared->version != 3
            || prepared->requested_count > CONTINUUM_REMOTE_PTHREAD_LIMIT
            || prepared->created_count != prepared->requested_count
            || prepared->error_code != 0) {
            return CONTINUUM_STATUS_VALIDATION_FAILED;
        }

        uint64_t requested_end = 0;
        if (!continuum_add_u64(
                region->address,
                region->length,
                &requested_end
            )) {
            return CONTINUUM_STATUS_RANGE_ERROR;
        }
        uint64_t protected_addresses[2] = {
            prepared->primary_stack_region_address,
            prepared->primary_pthread_region_address
        };
        uint64_t protected_lengths[2] = {
            prepared->primary_stack_region_length,
            prepared->primary_pthread_region_length
        };
        for (size_t index = 0; index < 2; index += 1) {
            uint64_t protected_end = 0;
            if (protected_addresses[index] == 0
                || protected_lengths[index] == 0
                || !continuum_add_u64(
                    protected_addresses[index],
                    protected_lengths[index],
                    &protected_end
                )) {
                return CONTINUUM_STATUS_VALIDATION_FAILED;
            }
            if (region->address < protected_end
                && protected_addresses[index] < requested_end) {
                return CONTINUUM_STATUS_INVALID_ARGUMENT;
            }
        }
        for (uint32_t worker = 0;
             worker < prepared->created_count;
             worker += 1) {
            protected_addresses[0] =
                prepared->stack_region_addresses[worker];
            protected_lengths[0] = prepared->stack_region_lengths[worker];
            protected_addresses[1] =
                prepared->pthread_region_addresses[worker];
            protected_lengths[1] =
                prepared->pthread_region_lengths[worker];
            for (size_t index = 0; index < 2; index += 1) {
                uint64_t protected_end = 0;
                if (protected_addresses[index] == 0
                    || protected_lengths[index] == 0
                    || !continuum_add_u64(
                        protected_addresses[index],
                        protected_lengths[index],
                        &protected_end
                    )) {
                    return CONTINUUM_STATUS_VALIDATION_FAILED;
                }
                if (region->address < protected_end
                    && protected_addresses[index] < requested_end) {
                    return CONTINUUM_STATUS_INVALID_ARGUMENT;
                }
            }
        }
    }
    return continuum_validate_stopped_replacement_session(session);
}

static continuum_status continuum_prepare_reconstruction_range(
    continuum_remote_session *session,
    const continuum_remote_process_region_info *region,
    continuum_remote_restore_report *out_report
) {
    uint64_t requested_end = 0;
    if (!continuum_add_u64(
            region->address,
            region->length,
            &requested_end
        )) {
        return CONTINUUM_STATUS_RANGE_ERROR;
    }

    mach_vm_address_t cursor = region->address;
    while (cursor < requested_end) {
        mach_vm_address_t mapping_address = cursor;
        mach_vm_size_t mapping_length = 0;
        vm_region_submap_info_data_64_t info;
        natural_t depth = 0;
        kern_return_t result;
        for (;;) {
            memset(&info, 0, sizeof(info));
            mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
            result = mach_vm_region_recurse(
                session->task,
                &mapping_address,
                &mapping_length,
                &depth,
                (vm_region_recurse_info_t)&info,
                &count
            );
            if (result != KERN_SUCCESS || !info.is_submap) {
                break;
            }
            depth += 1;
        }

        mach_vm_address_t hole_end = requested_end;
        if (result == KERN_SUCCESS && mapping_address > cursor) {
            hole_end = mapping_address < requested_end
                ? mapping_address
                : requested_end;
        }
        if (result == KERN_INVALID_ADDRESS
            || (result == KERN_SUCCESS && mapping_address > cursor)) {
            mach_vm_address_t allocation_address = cursor;
            result = mach_vm_map(
                session->task,
                &allocation_address,
                hole_end - cursor,
                0,
                VM_FLAGS_FIXED | VM_MAKE_TAG(region->user_tag),
                MEMORY_OBJECT_NULL,
                0,
                FALSE,
                VM_PROT_READ | VM_PROT_WRITE,
                VM_PROT_ALL,
                region->inheritance
            );
            if (result != KERN_SUCCESS || allocation_address != cursor) {
                out_report->reconstruction_stage =
                    CONTINUUM_RECONSTRUCTION_STAGE_ALLOCATE;
                out_report->mach_result = result;
                return CONTINUUM_STATUS_MACH_ERROR;
            }
            cursor = hole_end;
            continue;
        }
        if (result != KERN_SUCCESS || mapping_length == 0) {
            out_report->mach_result = result;
            return CONTINUUM_STATUS_MACH_ERROR;
        }

        out_report->observed_mapping_address = mapping_address;
        out_report->observed_mapping_length = mapping_length;
        out_report->observed_protection = info.protection;
        out_report->observed_maximum_protection = info.max_protection;
        out_report->observed_inheritance = info.inheritance;
        out_report->observed_share_mode = info.share_mode;
        out_report->observed_user_tag = info.user_tag;
        out_report->observed_offset = info.offset;
        out_report->observed_flags = info.flags;
        out_report->observed_external_pager = info.external_pager;

        uint64_t mapping_end = 0;
        if (!continuum_add_u64(
                mapping_address,
                mapping_length,
                &mapping_end
            ) || mapping_end <= cursor) {
            return CONTINUUM_STATUS_RANGE_ERROR;
        }
        mach_vm_address_t covered_end = mapping_end < requested_end
            ? mapping_end
            : requested_end;

        int is_disposable_malloc_reservation =
            info.protection == VM_PROT_NONE
            && (info.max_protection == VM_PROT_NONE
                || (info.max_protection & (VM_PROT_READ | VM_PROT_WRITE))
                    == (VM_PROT_READ | VM_PROT_WRITE))
            && info.inheritance == VM_INHERIT_COPY
            && info.user_tag == VM_MEMORY_MALLOC
            && info.external_pager == 0
            && info.flags == 0
            && info.share_mode == SM_TRUESHARED;
        if (is_disposable_malloc_reservation) {
            result = mach_vm_deallocate(
                session->task,
                cursor,
                covered_end - cursor
            );
            if (result != KERN_SUCCESS) {
                out_report->reconstruction_stage =
                    CONTINUUM_RECONSTRUCTION_STAGE_DEALLOCATE;
                out_report->mach_result = result;
                return CONTINUUM_STATUS_MACH_ERROR;
            }

            mach_vm_address_t allocation_address = cursor;
            result = mach_vm_map(
                session->task,
                &allocation_address,
                covered_end - cursor,
                0,
                VM_FLAGS_FIXED | VM_MAKE_TAG(region->user_tag),
                MEMORY_OBJECT_NULL,
                0,
                FALSE,
                VM_PROT_READ | VM_PROT_WRITE,
                VM_PROT_ALL,
                region->inheritance
            );
            if (result != KERN_SUCCESS || allocation_address != cursor) {
                out_report->reconstruction_stage =
                    CONTINUUM_RECONSTRUCTION_STAGE_ALLOCATE;
                out_report->mach_result = result;
                return CONTINUUM_STATUS_MACH_ERROR;
            }
            cursor = covered_end;
            continue;
        }
        if (!continuum_is_reconstruction_destination_share_mode(
                info.share_mode
            )) {
            return CONTINUUM_STATUS_REGION_NOT_PRIVATE;
        }
        if ((info.protection & (VM_PROT_READ | VM_PROT_WRITE))
            != (VM_PROT_READ | VM_PROT_WRITE)) {
            if ((info.max_protection & (VM_PROT_READ | VM_PROT_WRITE))
                != (VM_PROT_READ | VM_PROT_WRITE)) {
                return CONTINUUM_STATUS_REGION_PROTECTION_CHANGED;
            }
            result = mach_vm_protect(
                session->task,
                cursor,
                covered_end - cursor,
                FALSE,
                info.protection | VM_PROT_READ | VM_PROT_WRITE
            );
            if (result != KERN_SUCCESS) {
                out_report->reconstruction_stage =
                    CONTINUUM_RECONSTRUCTION_STAGE_PROTECT;
                out_report->mach_result = result;
                return CONTINUUM_STATUS_MACH_ERROR;
            }
        }
        cursor = covered_end;
    }
    return CONTINUUM_STATUS_OK;
}

continuum_status continuum_remote_session_begin_reconstruct_region(
    continuum_remote_session *session,
    const continuum_remote_process_region_info *region,
    continuum_remote_restore_report *out_report
) {
    if (out_report == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    memset(out_report, 0, sizeof(*out_report));
    continuum_status status = continuum_validate_reconstruction_target(
        session,
        region
    );
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }
    if (session->has_active_reconstruction) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }

    int did_suspend = 0;
    status = continuum_suspend_session(session, &did_suspend);
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }

    status = continuum_prepare_reconstruction_range(
        session,
        region,
        out_report
    );

    continuum_status resume_status = continuum_resume_session(session, did_suspend);
    if (resume_status != CONTINUUM_STATUS_OK) {
        status = resume_status;
    }
    if (status == CONTINUUM_STATUS_OK) {
        session->reconstruction_address = region->address;
        session->reconstruction_length = region->length;
        session->has_active_reconstruction = 1;
    }
    return status;
}

static continuum_status continuum_validate_remote_bootstrap_image(
    continuum_remote_session *session,
    const continuum_bootstrap_identity *identity,
    const char *expected_library_path
) {
    task_dyld_info_data_t dyld_info;
    memset(&dyld_info, 0, sizeof(dyld_info));
    mach_msg_type_number_t dyld_info_count = TASK_DYLD_INFO_COUNT;
    kern_return_t result = task_info(
        session->task,
        TASK_DYLD_INFO,
        (task_info_t)&dyld_info,
        &dyld_info_count
    );
    if (result != KERN_SUCCESS || dyld_info.all_image_info_addr == 0) {
        return CONTINUUM_STATUS_MACH_ERROR;
    }

    struct dyld_all_image_infos all_images;
    memset(&all_images, 0, sizeof(all_images));
    continuum_status status = continuum_read_task_bytes(
        session->task,
        dyld_info.all_image_info_addr,
        sizeof(all_images),
        &all_images
    );
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }
    if (all_images.infoArrayCount == 0
        || all_images.infoArrayCount > UINT32_C(1048576)
        || all_images.infoArray == NULL) {
        return CONTINUUM_STATUS_RANGE_ERROR;
    }

    size_t byte_count =
        (size_t)all_images.infoArrayCount * sizeof(struct dyld_image_info);
    struct dyld_image_info *entries = malloc(byte_count);
    if (entries == NULL) {
        return CONTINUUM_STATUS_OUT_OF_MEMORY;
    }
    status = continuum_read_task_bytes(
        session->task,
        (mach_vm_address_t)(uintptr_t)all_images.infoArray,
        byte_count,
        entries
    );

    char observed_path[PATH_MAX];
    memset(observed_path, 0, sizeof(observed_path));
    int found_image = 0;
    for (uint32_t index = 0;
         status == CONTINUUM_STATUS_OK && index < all_images.infoArrayCount;
         index += 1) {
        if ((uint64_t)(uintptr_t)entries[index].imageLoadAddress
                != identity->image_base) {
            continue;
        }
        if (found_image || entries[index].imageFilePath == NULL) {
            status = CONTINUUM_STATUS_VALIDATION_FAILED;
            break;
        }
        found_image = 1;
        status = continuum_read_task_cstring(
            session->task,
            (mach_vm_address_t)(uintptr_t)entries[index].imageFilePath,
            observed_path,
            sizeof(observed_path)
        );
    }
    free(entries);
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }
    if (!found_image) {
        return CONTINUUM_STATUS_VALIDATION_FAILED;
    }

    char expected_canonical[PATH_MAX];
    char observed_canonical[PATH_MAX];
    if (realpath(expected_library_path, expected_canonical) == NULL
        || realpath(observed_path, observed_canonical) == NULL
        || strcmp(expected_canonical, observed_canonical) != 0) {
        return CONTINUUM_STATUS_VALIDATION_FAILED;
    }

    uint8_t remote_uuid[16];
    memset(remote_uuid, 0, sizeof(remote_uuid));
    status = continuum_copy_remote_image_uuid(
        session->task,
        identity->image_base,
        remote_uuid
    );
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }
    return memcmp(
        remote_uuid,
        identity->image_uuid,
        sizeof(remote_uuid)
    ) == 0
        ? CONTINUUM_STATUS_OK
        : CONTINUUM_STATUS_VALIDATION_FAILED;
}

continuum_status continuum_remote_session_set_bootstrap_copy_identity(
    continuum_remote_session *session,
    const continuum_bootstrap_identity *identity,
    const char *expected_library_path
) {
    continuum_status status = continuum_validate_session_identity(session);
    if (status != CONTINUUM_STATUS_OK || identity == NULL
        || expected_library_path == NULL || expected_library_path[0] == '\0'
        || identity->image_base == 0 || identity->copy_address == 0
        || identity->copy_offset == 0
        || identity->pthread_prepare_address == 0
        || identity->pthread_prepare_offset == 0) {
        return status == CONTINUUM_STATUS_OK
            ? CONTINUUM_STATUS_INVALID_ARGUMENT
            : status;
    }

    uint64_t expected_copy_address = 0;
    if (!continuum_add_u64(
            identity->image_base,
            identity->copy_offset,
            &expected_copy_address
        ) || expected_copy_address != identity->copy_address) {
        return CONTINUUM_STATUS_VALIDATION_FAILED;
    }
    uint64_t expected_pthread_prepare_address = 0;
    if (!continuum_add_u64(
            identity->image_base,
            identity->pthread_prepare_offset,
            &expected_pthread_prepare_address
        ) || expected_pthread_prepare_address
            != identity->pthread_prepare_address) {
        return CONTINUUM_STATUS_VALIDATION_FAILED;
    }
    status = continuum_validate_remote_bootstrap_image(
        session,
        identity,
        expected_library_path
    );
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }

    mach_vm_size_t executable_length = 0;
    kern_return_t mach_result = KERN_SUCCESS;
    status = continuum_reconstruction_leaf_span(
        session->task,
        identity->copy_address,
        1,
        VM_PROT_READ | VM_PROT_EXECUTE,
        &executable_length,
        &mach_result
    );
    if (status != CONTINUUM_STATUS_OK || executable_length != 1) {
        return status == CONTINUUM_STATUS_OK
            ? CONTINUUM_STATUS_VALIDATION_FAILED
            : status;
    }
    executable_length = 0;
    status = continuum_reconstruction_leaf_span(
        session->task,
        identity->pthread_prepare_address,
        1,
        VM_PROT_READ | VM_PROT_EXECUTE,
        &executable_length,
        &mach_result
    );
    if (status != CONTINUUM_STATUS_OK || executable_length != 1) {
        return status == CONTINUUM_STATUS_OK
            ? CONTINUUM_STATUS_VALIDATION_FAILED
            : status;
    }
    session->bootstrap_copy_address = identity->copy_address;
    session->bootstrap_pthread_prepare_address =
        identity->pthread_prepare_address;
    return CONTINUUM_STATUS_OK;
}

static continuum_status continuum_validate_remote_pthread_geometry(
    mach_port_t task,
    uint64_t pthread_address,
    uint64_t stack_base,
    uint64_t stack_length,
    uint64_t stack_region_address,
    uint64_t stack_region_length,
    uint64_t pthread_region_address,
    uint64_t pthread_region_length
) {
    uint64_t stack_end = 0;
    uint64_t stack_region_end = 0;
    uint64_t pthread_region_end = 0;
    if (task == MACH_PORT_NULL || pthread_address == 0 || stack_base == 0
        || stack_length == 0 || stack_region_address == 0
        || stack_region_length == 0 || pthread_region_address == 0
        || pthread_region_length == 0
        || !continuum_add_u64(stack_base, stack_length, &stack_end)
        || !continuum_add_u64(
            stack_region_address,
            stack_region_length,
            &stack_region_end
        )
        || !continuum_add_u64(
            pthread_region_address,
            pthread_region_length,
            &pthread_region_end
        )
        || stack_base < stack_region_address
        || stack_end > stack_region_end
        || pthread_address < pthread_region_address
        || pthread_address >= pthread_region_end) {
        return CONTINUUM_STATUS_VALIDATION_FAILED;
    }

    mach_vm_size_t writable_span = 0;
    kern_return_t mach_result = KERN_SUCCESS;
    continuum_status status = continuum_reconstruction_leaf_span(
        task,
        stack_region_address,
        stack_region_length,
        VM_PROT_READ | VM_PROT_WRITE,
        &writable_span,
        &mach_result
    );
    if (status != CONTINUUM_STATUS_OK
        || writable_span != stack_region_length) {
        return status == CONTINUUM_STATUS_OK
            ? CONTINUUM_STATUS_VALIDATION_FAILED
            : status;
    }
    if (pthread_region_address == stack_region_address
        && pthread_region_length == stack_region_length) {
        return CONTINUUM_STATUS_OK;
    }

    writable_span = 0;
    status = continuum_reconstruction_leaf_span(
        task,
        pthread_region_address,
        pthread_region_length,
        VM_PROT_READ | VM_PROT_WRITE,
        &writable_span,
        &mach_result
    );
    if (status != CONTINUUM_STATUS_OK
        || writable_span != pthread_region_length) {
        return status == CONTINUUM_STATUS_OK
            ? CONTINUUM_STATUS_VALIDATION_FAILED
            : status;
    }
    return CONTINUUM_STATUS_OK;
}

continuum_status continuum_plan_exact_pthread_reconstruction(
    const continuum_saved_pthread_geometry *saved,
    size_t saved_count,
    const continuum_remote_pthread_bootstrap_report *replacement,
    continuum_pthread_reconstruction_plan *out_plan
) {
    if (out_plan == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    memset(out_plan, 0, sizeof(*out_plan));
    if (saved == NULL || replacement == NULL || saved_count == 0
        || saved_count > CONTINUUM_PTHREAD_PLAN_LIMIT
        || replacement->version != 3
        || replacement->requested_count > CONTINUUM_REMOTE_PTHREAD_LIMIT
        || replacement->created_count != replacement->requested_count
        || replacement->error_code != 0
        || saved_count != (size_t)replacement->created_count + 1U
        || replacement->primary_pthread_address == 0
        || replacement->primary_thread_identifier == 0
        || replacement->primary_thread_handle == 0) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }

    uint64_t used_workers = 0;
    int used_primary = 0;
    continuum_status status = CONTINUUM_STATUS_OK;
    for (size_t index = 0; index < saved_count; index += 1) {
        const continuum_saved_pthread_geometry *candidate = &saved[index];
        uint64_t saved_stack_region_end = 0;
        uint64_t saved_pthread_region_end = 0;
        if (candidate->saved_thread_identifier == 0
            || candidate->pthread_address == 0
            || candidate->stack_pointer == 0
            || candidate->stack_region_address == 0
            || candidate->stack_region_length == 0
            || candidate->pthread_region_address == 0
            || candidate->pthread_region_length == 0
            || !continuum_add_u64(
                candidate->stack_region_address,
                candidate->stack_region_length,
                &saved_stack_region_end
            )
            || !continuum_add_u64(
                candidate->pthread_region_address,
                candidate->pthread_region_length,
                &saved_pthread_region_end
            )
            || candidate->stack_pointer < candidate->stack_region_address
            || candidate->stack_pointer >= saved_stack_region_end
            || candidate->pthread_address
                < candidate->pthread_region_address
            || candidate->pthread_address >= saved_pthread_region_end) {
            status = CONTINUUM_STATUS_VALIDATION_FAILED;
            break;
        }
        for (size_t prior = 0; prior < index; prior += 1) {
            if (saved[prior].saved_thread_identifier
                    == candidate->saved_thread_identifier
                || saved[prior].pthread_address
                    == candidate->pthread_address) {
                status = CONTINUUM_STATUS_VALIDATION_FAILED;
                break;
            }
        }
        if (status != CONTINUUM_STATUS_OK) {
            break;
        }

        uint64_t replacement_thread_identifier = 0;
        uint64_t replacement_thread_handle = 0;
        uint64_t replacement_stack_base = 0;
        uint64_t replacement_stack_length = 0;
        uint64_t replacement_stack_region_address = 0;
        uint64_t replacement_stack_region_length = 0;
        uint64_t replacement_pthread_region_address = 0;
        uint64_t replacement_pthread_region_length = 0;
        int is_primary = candidate->pthread_address
            == replacement->primary_pthread_address;
        if (is_primary) {
            if (used_primary) {
                status = CONTINUUM_STATUS_VALIDATION_FAILED;
                break;
            }
            used_primary = 1;
            replacement_thread_identifier =
                replacement->primary_thread_identifier;
            replacement_thread_handle =
                replacement->primary_thread_handle;
            replacement_stack_base =
                replacement->primary_stack_base_address;
            replacement_stack_length =
                replacement->primary_stack_length;
            replacement_stack_region_address =
                replacement->primary_stack_region_address;
            replacement_stack_region_length =
                replacement->primary_stack_region_length;
            replacement_pthread_region_address =
                replacement->primary_pthread_region_address;
            replacement_pthread_region_length =
                replacement->primary_pthread_region_length;
        } else {
            size_t worker_index = SIZE_MAX;
            for (uint32_t worker = 0;
                 worker < replacement->created_count;
                 worker += 1) {
                if (replacement->pthread_addresses[worker]
                    == candidate->pthread_address) {
                    if (worker_index != SIZE_MAX) {
                        status = CONTINUUM_STATUS_VALIDATION_FAILED;
                        break;
                    }
                    worker_index = worker;
                }
            }
            if (status != CONTINUUM_STATUS_OK || worker_index == SIZE_MAX
                || (used_workers & (UINT64_C(1) << worker_index)) != 0) {
                status = CONTINUUM_STATUS_VALIDATION_FAILED;
                break;
            }
            used_workers |= UINT64_C(1) << worker_index;
            replacement_thread_identifier =
                replacement->thread_identifiers[worker_index];
            replacement_thread_handle =
                replacement->thread_handles[worker_index];
            replacement_stack_base =
                replacement->stack_base_addresses[worker_index];
            replacement_stack_length =
                replacement->stack_lengths[worker_index];
            replacement_stack_region_address =
                replacement->stack_region_addresses[worker_index];
            replacement_stack_region_length =
                replacement->stack_region_lengths[worker_index];
            replacement_pthread_region_address =
                replacement->pthread_region_addresses[worker_index];
            replacement_pthread_region_length =
                replacement->pthread_region_lengths[worker_index];
        }

        uint64_t replacement_stack_end = 0;
        uint64_t replacement_stack_region_end = 0;
        uint64_t replacement_pthread_region_end = 0;
        if (replacement_thread_identifier == 0
            || replacement_thread_handle == 0
            || replacement_stack_region_address
                != candidate->stack_region_address
            || replacement_stack_region_length
                != candidate->stack_region_length
            || replacement_pthread_region_address
                != candidate->pthread_region_address
            || replacement_pthread_region_length
                != candidate->pthread_region_length
            || !continuum_add_u64(
                replacement_stack_base,
                replacement_stack_length,
                &replacement_stack_end
            )
            || !continuum_add_u64(
                replacement_stack_region_address,
                replacement_stack_region_length,
                &replacement_stack_region_end
            )
            || !continuum_add_u64(
                replacement_pthread_region_address,
                replacement_pthread_region_length,
                &replacement_pthread_region_end
            )
            || replacement_stack_base < replacement_stack_region_address
            || replacement_stack_end > replacement_stack_region_end
            || candidate->stack_pointer < replacement_stack_base
            || candidate->stack_pointer >= replacement_stack_end
            || (replacement_stack_region_address
                    != replacement_pthread_region_address
                && replacement_stack_region_address
                    < replacement_pthread_region_end
                && replacement_pthread_region_address
                    < replacement_stack_region_end)
            || (replacement_stack_region_address
                    == replacement_pthread_region_address
                && (replacement_stack_region_length
                        != replacement_pthread_region_length
                    || candidate->pthread_address
                        <= replacement_stack_region_address
                    || candidate->pthread_address
                        >= replacement_stack_region_end))) {
            status = CONTINUUM_STATUS_VALIDATION_FAILED;
            break;
        }

        uint64_t stack_copy_address = replacement_stack_region_address;
        uint64_t stack_copy_length = replacement_stack_region_length;
        uint64_t preserved_pthread_address =
            replacement_pthread_region_address;
        if (replacement_stack_region_address
            == replacement_pthread_region_address) {
            stack_copy_length = candidate->pthread_address
                - replacement_stack_region_address;
            preserved_pthread_address = candidate->pthread_address;
        }
        uint64_t preserved_pthread_length =
            replacement_pthread_region_end - preserved_pthread_address;
        uint64_t next_stack_bytes = 0;
        uint64_t next_preserved_bytes = 0;
        if (preserved_pthread_length == 0
            || !continuum_add_u64(
                out_plan->stack_copy_bytes,
                stack_copy_length,
                &next_stack_bytes
            )
            || !continuum_add_u64(
                out_plan->preserved_pthread_bytes,
                preserved_pthread_length,
                &next_preserved_bytes
            )) {
            status = CONTINUUM_STATUS_RANGE_ERROR;
            break;
        }

        continuum_pthread_reconstruction_plan_entry *entry =
            &out_plan->entries[index];
        entry->saved_thread_identifier =
            candidate->saved_thread_identifier;
        entry->replacement_thread_identifier =
            replacement_thread_identifier;
        entry->replacement_thread_handle = replacement_thread_handle;
        entry->pthread_address = candidate->pthread_address;
        entry->stack_copy_address = stack_copy_address;
        entry->stack_copy_length = stack_copy_length;
        entry->preserved_pthread_address = preserved_pthread_address;
        entry->preserved_pthread_length = preserved_pthread_length;
        entry->is_primary = is_primary;
        out_plan->stack_copy_bytes = next_stack_bytes;
        out_plan->preserved_pthread_bytes = next_preserved_bytes;
        if (is_primary) {
            out_plan->primary_saved_thread_identifier =
                candidate->saved_thread_identifier;
        }
    }

    uint64_t expected_workers = replacement->created_count == 64
        ? UINT64_MAX
        : ((UINT64_C(1) << replacement->created_count) - 1U);
    if (status == CONTINUUM_STATUS_OK
        && (!used_primary || used_workers != expected_workers)) {
        status = CONTINUUM_STATUS_VALIDATION_FAILED;
    }
    if (status != CONTINUUM_STATUS_OK) {
        memset(out_plan, 0, sizeof(*out_plan));
        return status;
    }
    out_plan->entry_count = (uint32_t)saved_count;
    return CONTINUUM_STATUS_OK;
}

continuum_status continuum_remote_session_prepare_suspended_pthreads(
    continuum_remote_session *session,
    uint32_t requested_count,
    continuum_remote_pthread_bootstrap_report *out_report
) {
    if (out_report == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    memset(out_report, 0, sizeof(*out_report));
#if !defined(__arm64__)
    (void)session;
    (void)requested_count;
    return CONTINUUM_STATUS_UNSUPPORTED_ARCHITECTURE;
#else
    if (session == NULL || requested_count > CONTINUUM_REMOTE_PTHREAD_LIMIT
        || session->bootstrap_pthread_prepare_address == 0
        || session->has_active_reconstruction
        || session->has_prepared_pthread_set
        || session->has_reconstructed_thread_set
        || session->owned_suspend_count != 0) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    continuum_status status = continuum_validate_stopped_replacement_session(
        session
    );
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }

    thread_act_array_t original_threads = NULL;
    mach_msg_type_number_t original_thread_count = 0;
    kern_return_t mach_result = task_threads(
        session->task,
        &original_threads,
        &original_thread_count
    );
    if (mach_result != KERN_SUCCESS || original_thread_count != 1) {
        status = CONTINUUM_STATUS_THREAD_SET_CHANGED;
        goto cleanup_original_threads;
    }

    arm_thread_state64_t saved_state;
    memset(&saved_state, 0, sizeof(saved_state));
    mach_msg_type_number_t state_count = ARM_THREAD_STATE64_COUNT;
    mach_result = thread_get_state(
        original_threads[0],
        ARM_THREAD_STATE64,
        (thread_state_t)&saved_state,
        &state_count
    );
    if (mach_result != KERN_SUCCESS
        || state_count != ARM_THREAD_STATE64_COUNT) {
        status = CONTINUUM_STATUS_THREAD_STATE_FAILED;
        goto cleanup_original_threads;
    }

    mach_vm_address_t report_address = 0;
    mach_vm_address_t stack_address = 0;
    const mach_vm_size_t stack_length = 64U * 1024U;
    mach_result = mach_vm_allocate(
        session->task,
        &report_address,
        sizeof(continuum_bootstrap_pthread_wire_report),
        VM_FLAGS_ANYWHERE
    );
    if (mach_result != KERN_SUCCESS) {
        status = CONTINUUM_STATUS_MACH_ERROR;
        goto cleanup_original_threads;
    }
    mach_result = mach_vm_allocate(
        session->task,
        &stack_address,
        stack_length,
        VM_FLAGS_ANYWHERE
    );
    if (mach_result != KERN_SUCCESS) {
        status = CONTINUUM_STATUS_MACH_ERROR;
        mach_vm_deallocate(
            session->task,
            report_address,
            sizeof(continuum_bootstrap_pthread_wire_report)
        );
        goto cleanup_original_threads;
    }

    int target_stopped = 1;
    arm_thread_state64_t call_state = saved_state;
    call_state.__x[0] = report_address;
    call_state.__x[1] = sizeof(continuum_bootstrap_pthread_wire_report);
    call_state.__x[2] = requested_count;
    uintptr_t stack_pointer = (uintptr_t)(stack_address + stack_length - 16U);
    arm_thread_state64_set_sp(call_state, (void *)stack_pointer);
    arm_thread_state64_set_fp(call_state, (void *)stack_pointer);
    arm_thread_state64_set_lr_fptr(call_state, NULL);
    arm_thread_state64_set_pc_fptr(
        call_state,
        (void (*)(void))(uintptr_t)
            session->bootstrap_pthread_prepare_address
    );
    mach_result = thread_set_state(
        original_threads[0],
        ARM_THREAD_STATE64,
        (thread_state_t)&call_state,
        ARM_THREAD_STATE64_COUNT
    );
    if (mach_result != KERN_SUCCESS) {
        status = CONTINUUM_STATUS_THREAD_STATE_FAILED;
        goto cleanup_allocations;
    }

    uint64_t deadline =
        clock_gettime_nsec_np(CLOCK_MONOTONIC) + UINT64_C(5000000000);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    int continue_result = ptrace(
        PT_CONTINUE,
        session->identity.process_id,
        (caddr_t)1,
        0
    );
#pragma clang diagnostic pop
    if (continue_result != 0) {
        status = CONTINUUM_STATUS_RESUME_FAILED;
        goto cleanup_allocations;
    }
    target_stopped = 0;
    status = continuum_wait_for_child_signal_stop(
        session->identity.process_id,
        deadline,
        SIGTRAP
    );
    if (status != CONTINUUM_STATUS_OK) {
        goto cleanup_allocations;
    }
    target_stopped = 1;

    mach_result = thread_set_state(
        original_threads[0],
        ARM_THREAD_STATE64,
        (thread_state_t)&saved_state,
        ARM_THREAD_STATE64_COUNT
    );
    if (mach_result != KERN_SUCCESS) {
        status = CONTINUUM_STATUS_THREAD_STATE_FAILED;
        goto cleanup_allocations;
    }

    continuum_bootstrap_pthread_wire_report wire_report;
    memset(&wire_report, 0, sizeof(wire_report));
    status = continuum_read_reconstructed_task_bytes(
        session->task,
        report_address,
        sizeof(wire_report),
        &wire_report,
        &mach_result
    );
    if (status != CONTINUUM_STATUS_OK) {
        goto cleanup_allocations;
    }
    if (wire_report.version != 3
        || wire_report.requested_count != requested_count
        || wire_report.created_count != requested_count
        || wire_report.error_code != 0) {
        status = CONTINUUM_STATUS_VALIDATION_FAILED;
        goto cleanup_allocations;
    }

    thread_act_array_t prepared_threads = NULL;
    mach_msg_type_number_t prepared_thread_count = 0;
    mach_result = task_threads(
        session->task,
        &prepared_threads,
        &prepared_thread_count
    );
    if (mach_result != KERN_SUCCESS
        || prepared_thread_count != requested_count + 1U) {
        status = CONTINUUM_STATUS_THREAD_SET_CHANGED;
        goto cleanup_prepared_threads;
    }

    if (!MACH_PORT_VALID(wire_report.primary_mach_thread_port)) {
        status = CONTINUUM_STATUS_VALIDATION_FAILED;
        goto cleanup_prepared_threads;
    }
    status = continuum_validate_remote_pthread_geometry(
        session->task,
        wire_report.primary_pthread_address,
        wire_report.primary_stack_base_address,
        wire_report.primary_stack_length,
        wire_report.primary_stack_region_address,
        wire_report.primary_stack_region_length,
        wire_report.primary_pthread_region_address,
        wire_report.primary_pthread_region_length
    );
    if (status != CONTINUUM_STATUS_OK) {
        goto cleanup_prepared_threads;
    }

    thread_identifier_info_data_t primary_identity;
    memset(&primary_identity, 0, sizeof(primary_identity));
    mach_msg_type_number_t primary_identity_count =
        THREAD_IDENTIFIER_INFO_COUNT;
    mach_result = thread_info(
        original_threads[0],
        THREAD_IDENTIFIER_INFO,
        (thread_info_t)&primary_identity,
        &primary_identity_count
    );
    if (mach_result != KERN_SUCCESS || primary_identity.thread_id == 0
        || primary_identity.thread_handle == 0
        || continuum_pthread_object_address(primary_identity.thread_handle)
            != wire_report.primary_pthread_address) {
        status = CONTINUUM_STATUS_VALIDATION_FAILED;
        goto cleanup_prepared_threads;
    }

    mach_port_t reported_primary_port = MACH_PORT_NULL;
    mach_msg_type_name_t reported_primary_type = 0;
    mach_result = mach_port_extract_right(
        session->task,
        wire_report.primary_mach_thread_port,
        MACH_MSG_TYPE_COPY_SEND,
        &reported_primary_port,
        &reported_primary_type
    );
    if (mach_result != KERN_SUCCESS
        || !MACH_PORT_VALID(reported_primary_port)
        || reported_primary_type != MACH_MSG_TYPE_PORT_SEND) {
        if (MACH_PORT_VALID(reported_primary_port)) {
            mach_port_deallocate(
                mach_task_self(),
                reported_primary_port
            );
        }
        status = CONTINUUM_STATUS_THREAD_STATE_FAILED;
        goto cleanup_prepared_threads;
    }
    thread_identifier_info_data_t reported_primary_identity;
    memset(&reported_primary_identity, 0, sizeof(reported_primary_identity));
    mach_msg_type_number_t reported_primary_identity_count =
        THREAD_IDENTIFIER_INFO_COUNT;
    mach_result = thread_info(
        reported_primary_port,
        THREAD_IDENTIFIER_INFO,
        (thread_info_t)&reported_primary_identity,
        &reported_primary_identity_count
    );
    mach_port_deallocate(mach_task_self(), reported_primary_port);
    if (mach_result != KERN_SUCCESS
        || reported_primary_identity.thread_id
            != primary_identity.thread_id
        || reported_primary_identity.thread_handle
            != primary_identity.thread_handle) {
        status = CONTINUUM_STATUS_VALIDATION_FAILED;
        goto cleanup_prepared_threads;
    }

    out_report->version = wire_report.version;
    out_report->requested_count = wire_report.requested_count;
    out_report->created_count = wire_report.created_count;
    out_report->error_code = wire_report.error_code;
    out_report->primary_pthread_address =
        wire_report.primary_pthread_address;
    out_report->primary_thread_identifier = primary_identity.thread_id;
    out_report->primary_thread_handle = primary_identity.thread_handle;
    out_report->primary_stack_base_address =
        wire_report.primary_stack_base_address;
    out_report->primary_stack_length = wire_report.primary_stack_length;
    out_report->primary_stack_region_address =
        wire_report.primary_stack_region_address;
    out_report->primary_stack_region_length =
        wire_report.primary_stack_region_length;
    out_report->primary_pthread_region_address =
        wire_report.primary_pthread_region_address;
    out_report->primary_pthread_region_length =
        wire_report.primary_pthread_region_length;
    for (uint32_t index = 0; index < requested_count; index += 1) {
        if (!MACH_PORT_VALID(wire_report.mach_thread_ports[index])) {
            status = CONTINUUM_STATUS_VALIDATION_FAILED;
            break;
        }
        status = continuum_validate_remote_pthread_geometry(
            session->task,
            wire_report.pthread_addresses[index],
            wire_report.stack_base_addresses[index],
            wire_report.stack_lengths[index],
            wire_report.stack_region_addresses[index],
            wire_report.stack_region_lengths[index],
            wire_report.pthread_region_addresses[index],
            wire_report.pthread_region_lengths[index]
        );
        if (status != CONTINUUM_STATUS_OK) {
            break;
        }
        mach_port_t thread_port = MACH_PORT_NULL;
        mach_msg_type_name_t acquired_type = 0;
        mach_result = mach_port_extract_right(
            session->task,
            wire_report.mach_thread_ports[index],
            MACH_MSG_TYPE_COPY_SEND,
            &thread_port,
            &acquired_type
        );
        if (mach_result != KERN_SUCCESS || !MACH_PORT_VALID(thread_port)
            || acquired_type != MACH_MSG_TYPE_PORT_SEND) {
            if (MACH_PORT_VALID(thread_port)) {
                mach_port_deallocate(mach_task_self(), thread_port);
            }
            status = CONTINUUM_STATUS_THREAD_STATE_FAILED;
            break;
        }
        thread_identifier_info_data_t identity;
        thread_basic_info_data_t basic;
        memset(&identity, 0, sizeof(identity));
        memset(&basic, 0, sizeof(basic));
        mach_msg_type_number_t identity_count = THREAD_IDENTIFIER_INFO_COUNT;
        mach_msg_type_number_t basic_count = THREAD_BASIC_INFO_COUNT;
        mach_result = thread_info(
            thread_port,
            THREAD_IDENTIFIER_INFO,
            (thread_info_t)&identity,
            &identity_count
        );
        if (mach_result == KERN_SUCCESS) {
            mach_result = thread_info(
                thread_port,
                THREAD_BASIC_INFO,
                (thread_info_t)&basic,
                &basic_count
            );
        }
        mach_port_deallocate(mach_task_self(), thread_port);
        if (mach_result != KERN_SUCCESS || identity.thread_id == 0
            || identity.thread_handle == 0 || basic.suspend_count < 1
            || continuum_pthread_object_address(identity.thread_handle)
                != wire_report.pthread_addresses[index]
            || wire_report.pthread_addresses[index]
                == wire_report.primary_pthread_address
            || identity.thread_id == primary_identity.thread_id
            || identity.thread_handle == primary_identity.thread_handle) {
            status = CONTINUUM_STATUS_VALIDATION_FAILED;
            break;
        }
        for (uint32_t prior = 0; prior < index; prior += 1) {
            if (out_report->pthread_addresses[prior]
                    == wire_report.pthread_addresses[index]
                || out_report->thread_identifiers[prior]
                    == identity.thread_id
                || out_report->thread_handles[prior]
                    == identity.thread_handle
                || out_report->pthread_region_addresses[prior]
                    == wire_report.pthread_region_addresses[index]) {
                status = CONTINUUM_STATUS_VALIDATION_FAILED;
                break;
            }
        }
        if (status != CONTINUUM_STATUS_OK) {
            break;
        }

        out_report->pthread_addresses[index] =
            wire_report.pthread_addresses[index];
        out_report->thread_identifiers[index] = identity.thread_id;
        out_report->thread_handles[index] = identity.thread_handle;
        out_report->stack_base_addresses[index] =
            wire_report.stack_base_addresses[index];
        out_report->stack_lengths[index] =
            wire_report.stack_lengths[index];
        out_report->stack_region_addresses[index] =
            wire_report.stack_region_addresses[index];
        out_report->stack_region_lengths[index] =
            wire_report.stack_region_lengths[index];
        out_report->pthread_region_addresses[index] =
            wire_report.pthread_region_addresses[index];
        out_report->pthread_region_lengths[index] =
            wire_report.pthread_region_lengths[index];
    }
    if (status == CONTINUUM_STATUS_OK) {
        session->prepared_pthreads = *out_report;
        session->has_prepared_pthread_set = 1;
    } else {
        memset(out_report, 0, sizeof(*out_report));
    }

cleanup_prepared_threads:
    if (prepared_threads != NULL) {
        for (mach_msg_type_number_t index = 0;
             index < prepared_thread_count;
             index += 1) {
            mach_port_deallocate(mach_task_self(), prepared_threads[index]);
        }
        vm_deallocate(
            mach_task_self(),
            (vm_address_t)prepared_threads,
            (vm_size_t)(prepared_thread_count * sizeof(thread_act_t))
        );
    }
cleanup_allocations:
    if (target_stopped) {
        mach_vm_deallocate(session->task, stack_address, stack_length);
        mach_vm_deallocate(
            session->task,
            report_address,
            sizeof(continuum_bootstrap_pthread_wire_report)
        );
    }
cleanup_original_threads:
    if (original_threads != NULL) {
        for (mach_msg_type_number_t index = 0;
             index < original_thread_count;
             index += 1) {
            mach_port_deallocate(mach_task_self(), original_threads[index]);
        }
        vm_deallocate(
            mach_task_self(),
            (vm_address_t)original_threads,
            (vm_size_t)(original_thread_count * sizeof(thread_act_t))
        );
    }
    return status;
#endif
}

static continuum_status continuum_prepared_pthread_stack_range(
    continuum_remote_session *session,
    const continuum_pthread_reconstruction_plan_entry *entry,
    uint64_t *out_address,
    uint64_t *out_length
) {
    if (session == NULL || entry == NULL || out_address == NULL
        || out_length == NULL || !session->has_prepared_pthread_set
        || session->prepared_pthreads.version != 3
        || entry->is_primary > 1) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }

    const continuum_remote_pthread_bootstrap_report *prepared =
        &session->prepared_pthreads;
    uint64_t pthread_address = 0;
    uint64_t replacement_identifier = 0;
    uint64_t replacement_handle = 0;
    uint64_t stack_region_address = 0;
    uint64_t stack_region_length = 0;
    uint64_t pthread_region_address = 0;
    uint64_t pthread_region_length = 0;
    if (entry->is_primary != 0) {
        pthread_address = prepared->primary_pthread_address;
        replacement_identifier = prepared->primary_thread_identifier;
        replacement_handle = prepared->primary_thread_handle;
        stack_region_address = prepared->primary_stack_region_address;
        stack_region_length = prepared->primary_stack_region_length;
        pthread_region_address = prepared->primary_pthread_region_address;
        pthread_region_length = prepared->primary_pthread_region_length;
    } else {
        size_t match = SIZE_MAX;
        for (uint32_t index = 0; index < prepared->created_count; index += 1) {
            if (prepared->thread_identifiers[index]
                    == entry->replacement_thread_identifier
                && prepared->thread_handles[index]
                    == entry->replacement_thread_handle
                && prepared->pthread_addresses[index]
                    == entry->pthread_address) {
                if (match != SIZE_MAX) {
                    return CONTINUUM_STATUS_VALIDATION_FAILED;
                }
                match = index;
            }
        }
        if (match == SIZE_MAX) {
            return CONTINUUM_STATUS_VALIDATION_FAILED;
        }
        pthread_address = prepared->pthread_addresses[match];
        replacement_identifier = prepared->thread_identifiers[match];
        replacement_handle = prepared->thread_handles[match];
        stack_region_address = prepared->stack_region_addresses[match];
        stack_region_length = prepared->stack_region_lengths[match];
        pthread_region_address = prepared->pthread_region_addresses[match];
        pthread_region_length = prepared->pthread_region_lengths[match];
    }

    uint64_t stack_region_end = 0;
    uint64_t pthread_region_end = 0;
    if (pthread_address == 0 || replacement_identifier == 0
        || replacement_handle == 0 || stack_region_address == 0
        || stack_region_length == 0 || pthread_region_address == 0
        || pthread_region_length == 0
        || !continuum_add_u64(
            stack_region_address,
            stack_region_length,
            &stack_region_end
        )
        || !continuum_add_u64(
            pthread_region_address,
            pthread_region_length,
            &pthread_region_end
        )) {
        return CONTINUUM_STATUS_VALIDATION_FAILED;
    }

    uint64_t stack_copy_length = stack_region_length;
    uint64_t preserved_address = pthread_region_address;
    if (stack_region_address == pthread_region_address) {
        if (stack_region_length != pthread_region_length
            || pthread_address <= stack_region_address
            || pthread_address >= stack_region_end) {
            return CONTINUUM_STATUS_VALIDATION_FAILED;
        }
        stack_copy_length = pthread_address - stack_region_address;
        preserved_address = pthread_address;
    } else if (stack_region_address < pthread_region_end
        && pthread_region_address < stack_region_end) {
        return CONTINUUM_STATUS_VALIDATION_FAILED;
    }
    uint64_t preserved_length = pthread_region_end - preserved_address;
    if (stack_copy_length == 0 || preserved_length == 0
        || entry->replacement_thread_identifier != replacement_identifier
        || entry->replacement_thread_handle != replacement_handle
        || entry->pthread_address != pthread_address
        || entry->stack_copy_address != stack_region_address
        || entry->stack_copy_length != stack_copy_length
        || entry->preserved_pthread_address != preserved_address
        || entry->preserved_pthread_length != preserved_length) {
        return CONTINUUM_STATUS_VALIDATION_FAILED;
    }

    kern_return_t mach_result = KERN_SUCCESS;
    continuum_status status = continuum_validate_reconstruction_range(
        session->task,
        stack_region_address,
        stack_copy_length,
        VM_PROT_READ | VM_PROT_WRITE,
        &mach_result
    );
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }
    *out_address = stack_region_address;
    *out_length = stack_copy_length;
    return CONTINUUM_STATUS_OK;
}

continuum_status continuum_remote_session_write_prepared_pthread_stack(
    continuum_remote_session *session,
    const continuum_pthread_reconstruction_plan_entry *entry,
    uint64_t offset,
    const void *bytes,
    size_t length,
    continuum_remote_restore_report *out_report
) {
    if (bytes == NULL || length == 0 || out_report == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    memset(out_report, 0, sizeof(*out_report));
    if (session == NULL || session->has_active_reconstruction
        || session->has_reconstructed_thread_set
        || session->owned_suspend_count != 0) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    continuum_status status = continuum_validate_stopped_replacement_session(
        session
    );
    uint64_t stack_address = 0;
    uint64_t stack_length = 0;
    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_prepared_pthread_stack_range(
            session,
            entry,
            &stack_address,
            &stack_length
        );
    }
    uint64_t end = 0;
    uint64_t write_address = 0;
    if (status == CONTINUUM_STATUS_OK
        && (!continuum_add_u64(offset, length, &end)
            || end > stack_length
            || !continuum_add_u64(
                stack_address,
                offset,
                &write_address
            ))) {
        status = CONTINUUM_STATUS_RANGE_ERROR;
    }
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }

    uint64_t bytes_written = 0;
    status = continuum_copy_reconstructed_task_bytes_in_process(
        session,
        write_address,
        bytes,
        length,
        &out_report->mach_result
    );
    if (status == CONTINUUM_STATUS_OK) {
        bytes_written = length;
    }
    if (status != CONTINUUM_STATUS_OK) {
        out_report->reconstruction_stage =
            CONTINUUM_RECONSTRUCTION_STAGE_WRITE;
    }

    uint8_t *readback = NULL;
    if (status == CONTINUUM_STATUS_OK) {
        readback = malloc(length);
        if (readback == NULL) {
            status = CONTINUUM_STATUS_OUT_OF_MEMORY;
        }
    }
    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_read_reconstructed_task_bytes(
            session->task,
            write_address,
            length,
            readback,
            &out_report->mach_result
        );
        if (status != CONTINUUM_STATUS_OK) {
            out_report->reconstruction_stage =
                CONTINUUM_RECONSTRUCTION_STAGE_READBACK;
        }
    }
    if (status == CONTINUUM_STATUS_OK && memcmp(readback, bytes, length) != 0) {
        const uint8_t *expected = bytes;
        size_t mismatch = 0;
        while (mismatch < length && readback[mismatch] == expected[mismatch]) {
            mismatch += 1;
        }
        out_report->reconstruction_stage =
            CONTINUUM_RECONSTRUCTION_STAGE_READBACK;
        out_report->observed_offset = mismatch;
        out_report->observed_flags = expected[mismatch];
        out_report->observed_user_tag = readback[mismatch];
        out_report->bytes_written = bytes_written;
        status = CONTINUUM_STATUS_VALIDATION_FAILED;
    }
    free(readback);

    if (status == CONTINUUM_STATUS_OK) {
        out_report->bytes_written = bytes_written;
        out_report->readback_verified = 1;
    }
    return status;
}

continuum_status continuum_remote_session_write_reconstructed_region(
    continuum_remote_session *session,
    const continuum_remote_process_region_info *region,
    uint64_t offset,
    const void *bytes,
    size_t length,
    continuum_remote_restore_report *out_report
) {
    if (bytes == NULL || length == 0 || out_report == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    memset(out_report, 0, sizeof(*out_report));
    continuum_status status = continuum_validate_reconstruction_target(
        session,
        region
    );
    uint64_t end = 0;
    if (status == CONTINUUM_STATUS_OK
        && (!continuum_add_u64(offset, length, &end)
            || end > region->length)) {
        status = CONTINUUM_STATUS_RANGE_ERROR;
    }
    uint64_t address = 0;
    if (status == CONTINUUM_STATUS_OK
        && !continuum_add_u64(region->address, offset, &address)) {
        status = CONTINUUM_STATUS_RANGE_ERROR;
    }
    if (status == CONTINUUM_STATUS_OK
        && (!session->has_active_reconstruction
            || session->reconstruction_address != region->address
            || session->reconstruction_length != region->length)) {
        status = CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }
    int did_suspend = 0;
    status = continuum_suspend_session(session, &did_suspend);
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }

    uint64_t bytes_written = 0;
    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_write_reconstructed_task_bytes(
            session->task,
            address,
            bytes,
            length,
            &bytes_written,
            &out_report->mach_result
        );
        if (status == CONTINUUM_STATUS_SHORT_WRITE
            && out_report->mach_result == KERN_PROTECTION_FAILURE
            && session->bootstrap_copy_address != 0) {
            continuum_status resume_status = continuum_resume_session(
                session,
                did_suspend
            );
            if (resume_status == CONTINUUM_STATUS_OK) {
                did_suspend = 0;
                status = continuum_copy_reconstructed_task_bytes_in_process(
                    session,
                    address,
                    bytes,
                    length,
                    &out_report->mach_result
                );
                if (status == CONTINUUM_STATUS_OK) {
                    bytes_written = length;
                }
            } else {
                status = resume_status;
            }
        }
        if (status != CONTINUUM_STATUS_OK) {
            out_report->reconstruction_stage =
                CONTINUUM_RECONSTRUCTION_STAGE_WRITE;
        }
    }

    uint8_t *readback = NULL;
    if (status == CONTINUUM_STATUS_OK) {
        readback = malloc(length);
        if (readback == NULL) {
            status = CONTINUUM_STATUS_OUT_OF_MEMORY;
        }
    }
    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_read_reconstructed_task_bytes(
            session->task,
            address,
            length,
            readback,
            &out_report->mach_result
        );
        if (status != CONTINUUM_STATUS_OK) {
            out_report->reconstruction_stage =
                CONTINUUM_RECONSTRUCTION_STAGE_READBACK;
        }
    }
    if (status == CONTINUUM_STATUS_OK && memcmp(readback, bytes, length) != 0) {
        status = CONTINUUM_STATUS_VALIDATION_FAILED;
    }
    free(readback);

    continuum_status resume_status = continuum_resume_session(session, did_suspend);
    if (resume_status != CONTINUUM_STATUS_OK) {
        status = resume_status;
    }
    if (status == CONTINUUM_STATUS_OK) {
        out_report->bytes_written = bytes_written;
        out_report->readback_verified = 1;
    }
    return status;
}

continuum_status continuum_remote_session_finish_reconstruct_region(
    continuum_remote_session *session,
    const continuum_remote_process_region_info *region,
    continuum_remote_restore_report *out_report
) {
    if (out_report == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    memset(out_report, 0, sizeof(*out_report));
    continuum_status status = continuum_validate_reconstruction_target(
        session,
        region
    );
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }
    if (!session->has_active_reconstruction
        || session->reconstruction_address != region->address
        || session->reconstruction_length != region->length) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }

    int did_suspend = 0;
    status = continuum_suspend_session(session, &did_suspend);
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }

    if (status == CONTINUUM_STATUS_OK) {
        kern_return_t result = mach_vm_inherit(
            session->task,
            region->address,
            region->length,
            region->inheritance
        );
        if (result != KERN_SUCCESS) {
            out_report->reconstruction_stage =
                CONTINUUM_RECONSTRUCTION_STAGE_INHERIT;
            out_report->mach_result = result;
            status = CONTINUUM_STATUS_MACH_ERROR;
        }
    }
    if (status == CONTINUUM_STATUS_OK) {
        vm_prot_t access_protection = region->protection
            & (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
        kern_return_t result = mach_vm_protect(
            session->task,
            region->address,
            region->length,
            FALSE,
            access_protection
        );
        if (result != KERN_SUCCESS) {
            out_report->reconstruction_stage =
                CONTINUUM_RECONSTRUCTION_STAGE_PROTECT;
            out_report->mach_result = result;
            status = CONTINUUM_STATUS_MACH_ERROR;
        }
    }
    if (status == CONTINUUM_STATUS_OK) {
        vm_prot_t maximum_access_protection = region->maximum_protection
            & (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
        kern_return_t result = mach_vm_protect(
            session->task,
            region->address,
            region->length,
            TRUE,
            maximum_access_protection
        );
        if (result != KERN_SUCCESS) {
            out_report->reconstruction_stage =
                CONTINUUM_RECONSTRUCTION_STAGE_MAX_PROTECT;
            out_report->mach_result = result;
            if (result != KERN_PROTECTION_FAILURE) {
                status = CONTINUUM_STATUS_MACH_ERROR;
            }
        } else {
            out_report->max_protection_verified = 1;
        }
    }

    continuum_status resume_status = continuum_resume_session(
        session,
        did_suspend
    );
    if (resume_status != CONTINUUM_STATUS_OK) {
        status = resume_status;
    }
    session->reconstruction_address = 0;
    session->reconstruction_length = 0;
    session->has_active_reconstruction = 0;
    return status;
}

#if defined(__arm64__)
static int continuum_arm64_general_states_equal(
    const arm_thread_state64_t *saved,
    const arm_thread_state64_t *observed
) {
    if (saved == NULL || observed == NULL
        || memcmp(saved->__x, observed->__x, sizeof(saved->__x)) != 0
        || saved->__cpsr != observed->__cpsr) {
        return 0;
    }
    return arm_thread_state64_get_pc(*saved)
            == arm_thread_state64_get_pc(*observed)
        && arm_thread_state64_get_lr(*saved)
            == arm_thread_state64_get_lr(*observed)
        && arm_thread_state64_get_sp(*saved)
            == arm_thread_state64_get_sp(*observed)
        && arm_thread_state64_get_fp(*saved)
            == arm_thread_state64_get_fp(*observed);
}
#endif

continuum_status continuum_remote_session_reconstruct_single_thread(
    continuum_remote_session *session,
    uint32_t general_state_flavor,
    const void *general_state,
    size_t general_state_length,
    uint32_t vector_state_flavor,
    const void *vector_state,
    size_t vector_state_length,
    continuum_remote_thread_reconstruction_report *out_report
) {
    if (out_report == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    memset(out_report, 0, sizeof(*out_report));
#if !defined(__arm64__)
    (void)session;
    (void)general_state_flavor;
    (void)general_state;
    (void)general_state_length;
    (void)vector_state_flavor;
    (void)vector_state;
    (void)vector_state_length;
    return CONTINUUM_STATUS_UNSUPPORTED_ARCHITECTURE;
#else
    if (general_state == NULL || vector_state == NULL
        || general_state_flavor != ARM_THREAD_STATE64
        || vector_state_flavor != ARM_NEON_STATE64
        || general_state_length != sizeof(arm_thread_state64_t)
        || vector_state_length != sizeof(arm_neon_state64_t)) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    continuum_status status = continuum_validate_stopped_replacement_session(
        session
    );
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }
    if (session->has_active_reconstruction
        || session->has_prepared_pthread_set
        || session->has_reconstructed_thread_set) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }

    arm_thread_state64_t saved_general;
    arm_neon_state64_t saved_vector;
    memcpy(&saved_general, general_state, sizeof(saved_general));
    memcpy(&saved_vector, vector_state, sizeof(saved_vector));

    uintptr_t program_counter = arm_thread_state64_get_pc(saved_general);
    uintptr_t stack_pointer = arm_thread_state64_get_sp(saved_general);
    if (program_counter == 0 || (program_counter & UINT64_C(3)) != 0
        || stack_pointer < 16 || (stack_pointer & UINT64_C(15)) != 0) {
        return CONTINUUM_STATUS_VALIDATION_FAILED;
    }
    mach_vm_size_t span = 0;
    kern_return_t mach_result = KERN_SUCCESS;
    status = continuum_reconstruction_leaf_span(
        session->task,
        program_counter,
        sizeof(uint32_t),
        VM_PROT_READ | VM_PROT_EXECUTE,
        &span,
        &mach_result
    );
    if (status != CONTINUUM_STATUS_OK || span != sizeof(uint32_t)) {
        return status == CONTINUUM_STATUS_OK
            ? CONTINUUM_STATUS_VALIDATION_FAILED
            : status;
    }
    status = continuum_reconstruction_leaf_span(
        session->task,
        stack_pointer - 16,
        16,
        VM_PROT_READ | VM_PROT_WRITE,
        &span,
        &mach_result
    );
    if (status != CONTINUUM_STATUS_OK || span != 16) {
        return status == CONTINUUM_STATUS_OK
            ? CONTINUUM_STATUS_VALIDATION_FAILED
            : status;
    }

    thread_act_array_t threads = NULL;
    mach_msg_type_number_t thread_count = 0;
    mach_result = task_threads(session->task, &threads, &thread_count);
    if (mach_result != KERN_SUCCESS) {
        return CONTINUUM_STATUS_THREAD_STATE_FAILED;
    }

    int did_suspend = 0;
    if (thread_count != 1) {
        status = CONTINUUM_STATUS_THREAD_SET_CHANGED;
    } else {
        thread_identifier_info_data_t identifier_info;
        memset(&identifier_info, 0, sizeof(identifier_info));
        mach_msg_type_number_t identifier_count = THREAD_IDENTIFIER_INFO_COUNT;
        mach_result = thread_info(
            threads[0],
            THREAD_IDENTIFIER_INFO,
            (thread_info_t)&identifier_info,
            &identifier_count
        );
        if (mach_result != KERN_SUCCESS) {
            status = CONTINUUM_STATUS_THREAD_STATE_FAILED;
        } else {
            out_report->replacement_thread_identifier = identifier_info.thread_id;
            status = continuum_suspend_session(session, &did_suspend);
        }
    }

    if (status == CONTINUUM_STATUS_OK) {
        mach_result = thread_set_state(
            threads[0],
            ARM_NEON_STATE64,
            (thread_state_t)&saved_vector,
            ARM_NEON_STATE64_COUNT
        );
        if (mach_result != KERN_SUCCESS) {
            status = CONTINUUM_STATUS_THREAD_RESTORE_FAILED;
        }
    }
    if (status == CONTINUUM_STATUS_OK) {
        mach_result = thread_set_state(
            threads[0],
            ARM_THREAD_STATE64,
            (thread_state_t)&saved_general,
            ARM_THREAD_STATE64_COUNT
        );
        if (mach_result != KERN_SUCCESS) {
            status = CONTINUUM_STATUS_THREAD_RESTORE_FAILED;
        }
    }

    arm_neon_state64_t observed_vector;
    arm_thread_state64_t observed_general;
    memset(&observed_vector, 0, sizeof(observed_vector));
    memset(&observed_general, 0, sizeof(observed_general));
    if (status == CONTINUUM_STATUS_OK) {
        mach_msg_type_number_t vector_count = ARM_NEON_STATE64_COUNT;
        mach_result = thread_get_state(
            threads[0],
            ARM_NEON_STATE64,
            (thread_state_t)&observed_vector,
            &vector_count
        );
        if (mach_result != KERN_SUCCESS
            || vector_count != ARM_NEON_STATE64_COUNT
            || memcmp(&saved_vector, &observed_vector, sizeof(saved_vector)) != 0) {
            status = CONTINUUM_STATUS_VALIDATION_FAILED;
        } else {
            out_report->vector_state_bytes = sizeof(saved_vector);
            out_report->vector_state_verified = 1;
        }
    }
    if (status == CONTINUUM_STATUS_OK) {
        mach_msg_type_number_t general_count = ARM_THREAD_STATE64_COUNT;
        mach_result = thread_get_state(
            threads[0],
            ARM_THREAD_STATE64,
            (thread_state_t)&observed_general,
            &general_count
        );
        if (mach_result != KERN_SUCCESS
            || general_count != ARM_THREAD_STATE64_COUNT
            || !continuum_arm64_general_states_equal(
                &saved_general,
                &observed_general
            )) {
            status = CONTINUUM_STATUS_VALIDATION_FAILED;
        } else {
            out_report->general_state_bytes = sizeof(saved_general);
            out_report->general_state_verified = 1;
        }
    }

    continuum_status resume_status = continuum_resume_session(session, did_suspend);
    if (resume_status != CONTINUUM_STATUS_OK) {
        status = resume_status;
    }
    for (mach_msg_type_number_t index = 0; index < thread_count; index += 1) {
        mach_port_deallocate(mach_task_self(), threads[index]);
    }
    if (threads != NULL) {
        vm_deallocate(
            mach_task_self(),
            (vm_address_t)threads,
            (vm_size_t)(thread_count * sizeof(thread_act_t))
        );
    }
    return status;
#endif
}

continuum_status continuum_remote_session_reconstruct_raw_thread_set(
    continuum_remote_session *session,
    const continuum_remote_thread_reconstruction_input *inputs,
    size_t thread_count,
    continuum_remote_thread_set_reconstruction_report *out_report
) {
    if (out_report == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    memset(out_report, 0, sizeof(*out_report));
#if !defined(__arm64__)
    (void)session;
    (void)inputs;
    (void)thread_count;
    return CONTINUUM_STATUS_UNSUPPORTED_ARCHITECTURE;
#else
    enum { CONTINUUM_RAW_THREAD_PROOF_LIMIT = 64 };
    if (session == NULL || inputs == NULL || thread_count == 0
        || thread_count > CONTINUUM_RAW_THREAD_PROOF_LIMIT
        || session->has_active_reconstruction
        || session->has_prepared_pthread_set
        || session->has_reconstructed_thread_set
        || session->owned_suspend_count != 0) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    continuum_status status = continuum_validate_stopped_replacement_session(
        session
    );
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }

    thread_act_t *ports = calloc(thread_count, sizeof(*ports));
    if (ports == NULL) {
        return CONTINUUM_STATUS_OUT_OF_MEMORY;
    }
    uint64_t general_state_bytes = 0;
    uint64_t vector_state_bytes = 0;
    for (size_t index = 0; index < thread_count; index += 1) {
        const continuum_remote_thread_reconstruction_input *input =
            &inputs[index];
        if (input->general_state == NULL || input->vector_state == NULL
            || input->general_state_flavor != ARM_THREAD_STATE64
            || input->vector_state_flavor != ARM_NEON_STATE64
            || input->general_state_length != sizeof(arm_thread_state64_t)
            || input->vector_state_length != sizeof(arm_neon_state64_t)
            || !continuum_add_u64(
                general_state_bytes,
                input->general_state_length,
                &general_state_bytes
            )
            || !continuum_add_u64(
                vector_state_bytes,
                input->vector_state_length,
                &vector_state_bytes
            )) {
            free(ports);
            return CONTINUUM_STATUS_INVALID_ARGUMENT;
        }

        arm_thread_state64_t general_state;
        memcpy(
            &general_state,
            input->general_state,
            sizeof(general_state)
        );
        uintptr_t program_counter = arm_thread_state64_get_pc(general_state);
        uintptr_t stack_pointer = arm_thread_state64_get_sp(general_state);
        if (program_counter == 0 || (program_counter & UINT64_C(3)) != 0
            || stack_pointer < 16 || (stack_pointer & UINT64_C(15)) != 0) {
            free(ports);
            return CONTINUUM_STATUS_VALIDATION_FAILED;
        }

        mach_vm_size_t span = 0;
        kern_return_t mach_result = KERN_SUCCESS;
        status = continuum_reconstruction_leaf_span(
            session->task,
            program_counter,
            sizeof(uint32_t),
            VM_PROT_READ | VM_PROT_EXECUTE,
            &span,
            &mach_result
        );
        if (status != CONTINUUM_STATUS_OK || span != sizeof(uint32_t)) {
            free(ports);
            return status == CONTINUUM_STATUS_OK
                ? CONTINUUM_STATUS_VALIDATION_FAILED
                : status;
        }
        status = continuum_reconstruction_leaf_span(
            session->task,
            stack_pointer - 16,
            16,
            VM_PROT_READ | VM_PROT_WRITE,
            &span,
            &mach_result
        );
        if (status != CONTINUUM_STATUS_OK || span != 16) {
            free(ports);
            return status == CONTINUUM_STATUS_OK
                ? CONTINUUM_STATUS_VALIDATION_FAILED
                : status;
        }
    }

    int did_suspend = 0;
    status = continuum_suspend_session(session, &did_suspend);
    if (status != CONTINUUM_STATUS_OK) {
        free(ports);
        return status;
    }

    thread_act_array_t existing_threads = NULL;
    mach_msg_type_number_t existing_count = 0;
    kern_return_t mach_result = task_threads(
        session->task,
        &existing_threads,
        &existing_count
    );
    size_t primary_index = SIZE_MAX;
    arm_thread_state64_t original_general;
    arm_neon_state64_t original_vector;
    memset(&original_general, 0, sizeof(original_general));
    memset(&original_vector, 0, sizeof(original_vector));
    uint64_t replacement_thread_identifier = 0;
    size_t created_count = 0;
    int primary_was_modified = 0;
    if (mach_result != KERN_SUCCESS || existing_count != 1) {
        status = CONTINUUM_STATUS_THREAD_SET_CHANGED;
        goto rollback;
    }

    thread_identifier_info_data_t replacement_identity;
    memset(&replacement_identity, 0, sizeof(replacement_identity));
    mach_msg_type_number_t identity_count = THREAD_IDENTIFIER_INFO_COUNT;
    mach_result = thread_info(
        existing_threads[0],
        THREAD_IDENTIFIER_INFO,
        (thread_info_t)&replacement_identity,
        &identity_count
    );
    if (mach_result != KERN_SUCCESS || replacement_identity.thread_handle == 0) {
        status = CONTINUUM_STATUS_THREAD_STATE_FAILED;
        goto rollback;
    }
    replacement_thread_identifier = replacement_identity.thread_id;
    for (size_t index = 0; index < thread_count; index += 1) {
        if (inputs[index].thread_handle == replacement_identity.thread_handle) {
            if (primary_index != SIZE_MAX) {
                status = CONTINUUM_STATUS_VALIDATION_FAILED;
                goto rollback;
            }
            primary_index = index;
        } else if (inputs[index].thread_handle != 0
            || inputs[index].dispatch_queue_address != 0) {
            status = CONTINUUM_STATUS_UNSUPPORTED_DESCRIPTOR;
            goto rollback;
        }
    }
    if (primary_index == SIZE_MAX) {
        status = CONTINUUM_STATUS_VALIDATION_FAILED;
        goto rollback;
    }

    ports[primary_index] = existing_threads[0];
    existing_threads[0] = MACH_PORT_NULL;
    mach_msg_type_number_t original_general_count = ARM_THREAD_STATE64_COUNT;
    mach_result = thread_get_state(
        ports[primary_index],
        ARM_THREAD_STATE64,
        (thread_state_t)&original_general,
        &original_general_count
    );
    if (mach_result != KERN_SUCCESS
        || original_general_count != ARM_THREAD_STATE64_COUNT) {
        status = CONTINUUM_STATUS_THREAD_STATE_FAILED;
        goto rollback;
    }
    mach_msg_type_number_t original_vector_count = ARM_NEON_STATE64_COUNT;
    mach_result = thread_get_state(
        ports[primary_index],
        ARM_NEON_STATE64,
        (thread_state_t)&original_vector,
        &original_vector_count
    );
    if (mach_result != KERN_SUCCESS
        || original_vector_count != ARM_NEON_STATE64_COUNT) {
        status = CONTINUUM_STATUS_THREAD_STATE_FAILED;
        goto rollback;
    }

    for (size_t index = 0; index < thread_count; index += 1) {
        arm_thread_state64_t saved_general;
        arm_neon_state64_t saved_vector;
        memcpy(
            &saved_general,
            inputs[index].general_state,
            sizeof(saved_general)
        );
        memcpy(
            &saved_vector,
            inputs[index].vector_state,
            sizeof(saved_vector)
        );

        if (index == primary_index) {
            mach_result = thread_set_state(
                ports[index],
                ARM_NEON_STATE64,
                (thread_state_t)&saved_vector,
                ARM_NEON_STATE64_COUNT
            );
            if (mach_result == KERN_SUCCESS) {
                mach_result = thread_set_state(
                    ports[index],
                    ARM_THREAD_STATE64,
                    (thread_state_t)&saved_general,
                    ARM_THREAD_STATE64_COUNT
                );
            }
            primary_was_modified = 1;
        } else {
            mach_result = thread_create_running(
                session->task,
                ARM_THREAD_STATE64,
                (thread_state_t)&saved_general,
                ARM_THREAD_STATE64_COUNT,
                &ports[index]
            );
            if (mach_result == KERN_SUCCESS) {
                created_count += 1;
                mach_result = thread_set_state(
                    ports[index],
                    ARM_NEON_STATE64,
                    (thread_state_t)&saved_vector,
                    ARM_NEON_STATE64_COUNT
                );
            }
        }
        if (mach_result != KERN_SUCCESS) {
            status = CONTINUUM_STATUS_THREAD_RESTORE_FAILED;
            goto rollback;
        }
    }

    for (size_t index = 0; index < thread_count; index += 1) {
        arm_thread_state64_t saved_general;
        arm_neon_state64_t saved_vector;
        arm_thread_state64_t observed_general;
        arm_neon_state64_t observed_vector;
        memcpy(
            &saved_general,
            inputs[index].general_state,
            sizeof(saved_general)
        );
        memcpy(
            &saved_vector,
            inputs[index].vector_state,
            sizeof(saved_vector)
        );
        memset(&observed_general, 0, sizeof(observed_general));
        memset(&observed_vector, 0, sizeof(observed_vector));

        mach_msg_type_number_t vector_count = ARM_NEON_STATE64_COUNT;
        mach_result = thread_get_state(
            ports[index],
            ARM_NEON_STATE64,
            (thread_state_t)&observed_vector,
            &vector_count
        );
        mach_msg_type_number_t general_count = ARM_THREAD_STATE64_COUNT;
        if (mach_result == KERN_SUCCESS) {
            mach_result = thread_get_state(
                ports[index],
                ARM_THREAD_STATE64,
                (thread_state_t)&observed_general,
                &general_count
            );
        }
        if (mach_result != KERN_SUCCESS
            || vector_count != ARM_NEON_STATE64_COUNT
            || general_count != ARM_THREAD_STATE64_COUNT
            || memcmp(
                &saved_vector,
                &observed_vector,
                sizeof(saved_vector)
            ) != 0
            || !continuum_arm64_general_states_equal(
                &saved_general,
                &observed_general
            )) {
            status = CONTINUUM_STATUS_VALIDATION_FAILED;
            goto rollback;
        }
    }

    thread_act_array_t verified_threads = NULL;
    mach_msg_type_number_t verified_count = 0;
    mach_result = task_threads(
        session->task,
        &verified_threads,
        &verified_count
    );
    if (mach_result != KERN_SUCCESS
        || (size_t)verified_count != thread_count) {
        status = CONTINUUM_STATUS_THREAD_SET_CHANGED;
    }
    if (verified_threads != NULL) {
        for (mach_msg_type_number_t index = 0;
             index < verified_count;
             index += 1) {
            mach_port_deallocate(mach_task_self(), verified_threads[index]);
        }
        vm_deallocate(
            mach_task_self(),
            (vm_address_t)verified_threads,
            (vm_size_t)(verified_count * sizeof(thread_act_t))
        );
    }
    if (status != CONTINUUM_STATUS_OK) {
        goto rollback;
    }

    session->has_reconstructed_thread_set = 1;
    out_report->reconstructed_thread_count = thread_count;
    out_report->created_raw_thread_count = created_count;
    out_report->general_state_bytes = general_state_bytes;
    out_report->vector_state_bytes = vector_state_bytes;
    out_report->primary_replacement_thread_identifier =
        replacement_thread_identifier;
    out_report->all_states_verified = 1;

    if (existing_threads != NULL) {
        vm_deallocate(
            mach_task_self(),
            (vm_address_t)existing_threads,
            (vm_size_t)(existing_count * sizeof(thread_act_t))
        );
    }
    for (size_t index = 0; index < thread_count; index += 1) {
        if (ports[index] != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), ports[index]);
        }
    }
    free(ports);
    return CONTINUUM_STATUS_OK;

rollback:
    out_report->rollback_attempted = 1;
    int rollback_verified = 1;
    for (size_t index = 0; index < thread_count; index += 1) {
        if (index != primary_index && ports[index] != MACH_PORT_NULL
            && thread_terminate(ports[index]) != KERN_SUCCESS) {
            rollback_verified = 0;
        }
    }
    if (primary_was_modified && primary_index != SIZE_MAX
        && ports[primary_index] != MACH_PORT_NULL) {
        if (thread_set_state(
                ports[primary_index],
                ARM_NEON_STATE64,
                (thread_state_t)&original_vector,
                ARM_NEON_STATE64_COUNT
            ) != KERN_SUCCESS
            || thread_set_state(
                ports[primary_index],
                ARM_THREAD_STATE64,
                (thread_state_t)&original_general,
                ARM_THREAD_STATE64_COUNT
            ) != KERN_SUCCESS) {
            rollback_verified = 0;
        }
    }

    if (primary_was_modified && primary_index != SIZE_MAX
        && ports[primary_index] != MACH_PORT_NULL) {
        arm_thread_state64_t observed_general;
        arm_neon_state64_t observed_vector;
        memset(&observed_general, 0, sizeof(observed_general));
        memset(&observed_vector, 0, sizeof(observed_vector));
        mach_msg_type_number_t general_count = ARM_THREAD_STATE64_COUNT;
        mach_msg_type_number_t vector_count = ARM_NEON_STATE64_COUNT;
        if (thread_get_state(
                ports[primary_index],
                ARM_THREAD_STATE64,
                (thread_state_t)&observed_general,
                &general_count
            ) != KERN_SUCCESS
            || thread_get_state(
                ports[primary_index],
                ARM_NEON_STATE64,
                (thread_state_t)&observed_vector,
                &vector_count
            ) != KERN_SUCCESS
            || general_count != ARM_THREAD_STATE64_COUNT
            || vector_count != ARM_NEON_STATE64_COUNT
            || !continuum_arm64_general_states_equal(
                &original_general,
                &observed_general
            )
            || memcmp(
                &original_vector,
                &observed_vector,
                sizeof(original_vector)
            ) != 0) {
            rollback_verified = 0;
        }
    }

    if (primary_was_modified || created_count > 0) {
        thread_act_array_t rollback_threads = NULL;
        mach_msg_type_number_t rollback_count = 0;
        mach_result = task_threads(
            session->task,
            &rollback_threads,
            &rollback_count
        );
        if (mach_result != KERN_SUCCESS || rollback_count != 1) {
            rollback_verified = 0;
        } else if (replacement_thread_identifier != 0) {
            thread_identifier_info_data_t rollback_identity;
            memset(&rollback_identity, 0, sizeof(rollback_identity));
            mach_msg_type_number_t rollback_identity_count =
                THREAD_IDENTIFIER_INFO_COUNT;
            if (thread_info(
                    rollback_threads[0],
                    THREAD_IDENTIFIER_INFO,
                    (thread_info_t)&rollback_identity,
                    &rollback_identity_count
                ) != KERN_SUCCESS
                || rollback_identity.thread_id
                    != replacement_thread_identifier) {
                rollback_verified = 0;
            }
        }
        if (rollback_threads != NULL) {
            for (mach_msg_type_number_t index = 0;
                 index < rollback_count;
                 index += 1) {
                mach_port_deallocate(
                    mach_task_self(),
                    rollback_threads[index]
                );
            }
            vm_deallocate(
                mach_task_self(),
                (vm_address_t)rollback_threads,
                (vm_size_t)(rollback_count * sizeof(thread_act_t))
            );
        }
    }

    if (existing_threads != NULL) {
        for (mach_msg_type_number_t index = 0;
             index < existing_count;
             index += 1) {
            if (existing_threads[index] != MACH_PORT_NULL) {
                mach_port_deallocate(
                    mach_task_self(),
                    existing_threads[index]
                );
            }
        }
        vm_deallocate(
            mach_task_self(),
            (vm_address_t)existing_threads,
            (vm_size_t)(existing_count * sizeof(thread_act_t))
        );
    }
    for (size_t index = 0; index < thread_count; index += 1) {
        if (ports[index] != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), ports[index]);
        }
    }
    free(ports);

    continuum_status resume_status = continuum_resume_session(
        session,
        did_suspend
    );
    if (resume_status != CONTINUUM_STATUS_OK) {
        rollback_verified = 0;
    }
    out_report->rollback_verified = rollback_verified ? 1 : 0;
    return rollback_verified ? status : CONTINUUM_STATUS_ROLLBACK_FAILED;
#endif
}

continuum_status continuum_remote_session_reconstruct_prepared_thread_set(
    continuum_remote_session *session,
    const continuum_remote_thread_reconstruction_input *inputs,
    size_t thread_count,
    continuum_remote_thread_set_reconstruction_report *out_report
) {
    if (out_report == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    memset(out_report, 0, sizeof(*out_report));
#if !defined(__arm64__)
    (void)session;
    (void)inputs;
    (void)thread_count;
    return CONTINUUM_STATUS_UNSUPPORTED_ARCHITECTURE;
#else
    if (session == NULL || inputs == NULL || thread_count == 0
        || thread_count > CONTINUUM_PTHREAD_PLAN_LIMIT
        || session->has_active_reconstruction
        || !session->has_prepared_pthread_set
        || session->prepared_pthreads.version != 3
        || session->has_reconstructed_thread_set
        || session->owned_suspend_count != 0) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    continuum_status status = continuum_validate_stopped_replacement_session(
        session
    );
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }

    const size_t prepared_count =
        (size_t)session->prepared_pthreads.created_count + 1U;
    if (prepared_count > thread_count
        || prepared_count > CONTINUUM_PTHREAD_PLAN_LIMIT) {
        return CONTINUUM_STATUS_VALIDATION_FAILED;
    }

    thread_act_t *ports = calloc(thread_count, sizeof(*ports));
    arm_thread_state64_t *original_general = calloc(
        thread_count,
        sizeof(*original_general)
    );
    arm_neon_state64_t *original_vector = calloc(
        thread_count,
        sizeof(*original_vector)
    );
    uint8_t *is_existing = calloc(thread_count, sizeof(*is_existing));
    uint8_t *was_modified = calloc(thread_count, sizeof(*was_modified));
    if (ports == NULL || original_general == NULL || original_vector == NULL
        || is_existing == NULL || was_modified == NULL) {
        free(ports);
        free(original_general);
        free(original_vector);
        free(is_existing);
        free(was_modified);
        return CONTINUUM_STATUS_OUT_OF_MEMORY;
    }

    uint64_t general_state_bytes = 0;
    uint64_t vector_state_bytes = 0;
    size_t pthread_input_count = 0;
    for (size_t index = 0; index < thread_count; index += 1) {
        const continuum_remote_thread_reconstruction_input *input =
            &inputs[index];
        if (input->general_state == NULL || input->vector_state == NULL
            || input->general_state_flavor != ARM_THREAD_STATE64
            || input->vector_state_flavor != ARM_NEON_STATE64
            || input->general_state_length != sizeof(arm_thread_state64_t)
            || input->vector_state_length != sizeof(arm_neon_state64_t)
            || (input->thread_handle == 0
                && input->dispatch_queue_address != 0)
            || !continuum_add_u64(
                general_state_bytes,
                input->general_state_length,
                &general_state_bytes
            )
            || !continuum_add_u64(
                vector_state_bytes,
                input->vector_state_length,
                &vector_state_bytes
            )) {
            status = CONTINUUM_STATUS_INVALID_ARGUMENT;
            goto cleanup_allocations;
        }
        if (input->thread_handle != 0) {
            pthread_input_count += 1;
            for (size_t prior = 0; prior < index; prior += 1) {
                if (inputs[prior].thread_handle == input->thread_handle) {
                    status = CONTINUUM_STATUS_VALIDATION_FAILED;
                    goto cleanup_allocations;
                }
            }
        }

        arm_thread_state64_t general_state;
        memcpy(&general_state, input->general_state, sizeof(general_state));
        uintptr_t program_counter = arm_thread_state64_get_pc(general_state);
        uintptr_t stack_pointer = arm_thread_state64_get_sp(general_state);
        if (program_counter == 0 || (program_counter & UINT64_C(3)) != 0
            || stack_pointer < 16 || (stack_pointer & UINT64_C(15)) != 0) {
            status = CONTINUUM_STATUS_VALIDATION_FAILED;
            goto cleanup_allocations;
        }

        mach_vm_size_t span = 0;
        kern_return_t mach_result = KERN_SUCCESS;
        status = continuum_reconstruction_leaf_span(
            session->task,
            program_counter,
            sizeof(uint32_t),
            VM_PROT_READ | VM_PROT_EXECUTE,
            &span,
            &mach_result
        );
        if (status != CONTINUUM_STATUS_OK || span != sizeof(uint32_t)) {
            out_report->validation_thread_index = index;
            out_report->validation_address = program_counter;
            out_report->validation_kind = 1;
            if (status == CONTINUUM_STATUS_OK) {
                status = CONTINUUM_STATUS_VALIDATION_FAILED;
            }
            goto cleanup_allocations;
        }
        status = continuum_reconstruction_leaf_span(
            session->task,
            stack_pointer - 16,
            16,
            VM_PROT_READ | VM_PROT_WRITE,
            &span,
            &mach_result
        );
        if (status != CONTINUUM_STATUS_OK || span != 16) {
            out_report->validation_thread_index = index;
            out_report->validation_address = stack_pointer - 16;
            out_report->validation_kind = 2;
            if (status == CONTINUUM_STATUS_OK) {
                status = CONTINUUM_STATUS_VALIDATION_FAILED;
            }
            goto cleanup_allocations;
        }
    }
    if (pthread_input_count != prepared_count) {
        status = CONTINUUM_STATUS_VALIDATION_FAILED;
        goto cleanup_allocations;
    }

    int did_suspend = 0;
    status = continuum_suspend_session(session, &did_suspend);
    if (status != CONTINUUM_STATUS_OK) {
        goto cleanup_allocations;
    }

    thread_act_array_t existing_threads = NULL;
    mach_msg_type_number_t existing_count = 0;
    kern_return_t mach_result = task_threads(
        session->task,
        &existing_threads,
        &existing_count
    );
    size_t created_count = 0;
    uint64_t primary_identifier = 0;
    if (mach_result != KERN_SUCCESS || existing_count != prepared_count) {
        status = CONTINUUM_STATUS_THREAD_SET_CHANGED;
        goto rollback;
    }

    for (mach_msg_type_number_t existing_index = 0;
         existing_index < existing_count;
         existing_index += 1) {
        thread_identifier_info_data_t identity;
        memset(&identity, 0, sizeof(identity));
        mach_msg_type_number_t identity_count = THREAD_IDENTIFIER_INFO_COUNT;
        mach_result = thread_info(
            existing_threads[existing_index],
            THREAD_IDENTIFIER_INFO,
            (thread_info_t)&identity,
            &identity_count
        );
        if (mach_result != KERN_SUCCESS || identity.thread_id == 0
            || identity.thread_handle == 0) {
            status = CONTINUUM_STATUS_THREAD_STATE_FAILED;
            goto rollback;
        }

        int matches_prepared =
            identity.thread_handle
                == session->prepared_pthreads.primary_thread_handle
            && identity.thread_id
                == session->prepared_pthreads.primary_thread_identifier;
        if (matches_prepared) {
            primary_identifier = identity.thread_id;
        }
        for (uint32_t worker = 0;
             !matches_prepared
                && worker < session->prepared_pthreads.created_count;
             worker += 1) {
            matches_prepared = identity.thread_handle
                    == session->prepared_pthreads.thread_handles[worker]
                && identity.thread_id
                    == session->prepared_pthreads.thread_identifiers[worker];
        }
        if (!matches_prepared) {
            status = CONTINUUM_STATUS_THREAD_SET_CHANGED;
            goto rollback;
        }

        size_t input_index = SIZE_MAX;
        for (size_t candidate = 0; candidate < thread_count; candidate += 1) {
            if (inputs[candidate].thread_handle == identity.thread_handle) {
                if (input_index != SIZE_MAX) {
                    status = CONTINUUM_STATUS_VALIDATION_FAILED;
                    goto rollback;
                }
                input_index = candidate;
            }
        }
        if (input_index == SIZE_MAX || ports[input_index] != MACH_PORT_NULL) {
            status = CONTINUUM_STATUS_VALIDATION_FAILED;
            goto rollback;
        }

        ports[input_index] = existing_threads[existing_index];
        existing_threads[existing_index] = MACH_PORT_NULL;
        is_existing[input_index] = 1;
        mach_msg_type_number_t general_count = ARM_THREAD_STATE64_COUNT;
        mach_result = thread_get_state(
            ports[input_index],
            ARM_THREAD_STATE64,
            (thread_state_t)&original_general[input_index],
            &general_count
        );
        if (mach_result != KERN_SUCCESS
            || general_count != ARM_THREAD_STATE64_COUNT) {
            status = CONTINUUM_STATUS_THREAD_STATE_FAILED;
            goto rollback;
        }
        mach_msg_type_number_t vector_count = ARM_NEON_STATE64_COUNT;
        mach_result = thread_get_state(
            ports[input_index],
            ARM_NEON_STATE64,
            (thread_state_t)&original_vector[input_index],
            &vector_count
        );
        if (mach_result != KERN_SUCCESS
            || vector_count != ARM_NEON_STATE64_COUNT) {
            status = CONTINUUM_STATUS_THREAD_STATE_FAILED;
            goto rollback;
        }
    }
    if (primary_identifier == 0) {
        status = CONTINUUM_STATUS_VALIDATION_FAILED;
        goto rollback;
    }

    for (size_t index = 0; index < thread_count; index += 1) {
        arm_thread_state64_t saved_general;
        arm_neon_state64_t saved_vector;
        memcpy(&saved_general, inputs[index].general_state, sizeof(saved_general));
        memcpy(&saved_vector, inputs[index].vector_state, sizeof(saved_vector));
        if (is_existing[index]) {
            was_modified[index] = 1;
            mach_result = thread_set_state(
                ports[index],
                ARM_NEON_STATE64,
                (thread_state_t)&saved_vector,
                ARM_NEON_STATE64_COUNT
            );
            if (mach_result == KERN_SUCCESS) {
                mach_result = thread_set_state(
                    ports[index],
                    ARM_THREAD_STATE64,
                    (thread_state_t)&saved_general,
                    ARM_THREAD_STATE64_COUNT
                );
            }
        } else {
            mach_result = thread_create_running(
                session->task,
                ARM_THREAD_STATE64,
                (thread_state_t)&saved_general,
                ARM_THREAD_STATE64_COUNT,
                &ports[index]
            );
            if (mach_result == KERN_SUCCESS) {
                created_count += 1;
                mach_result = thread_set_state(
                    ports[index],
                    ARM_NEON_STATE64,
                    (thread_state_t)&saved_vector,
                    ARM_NEON_STATE64_COUNT
                );
            }
        }
        if (mach_result != KERN_SUCCESS) {
            status = CONTINUUM_STATUS_THREAD_RESTORE_FAILED;
            goto rollback;
        }
    }

    for (size_t index = 0; index < thread_count; index += 1) {
        arm_thread_state64_t saved_general;
        arm_neon_state64_t saved_vector;
        arm_thread_state64_t observed_general;
        arm_neon_state64_t observed_vector;
        memcpy(&saved_general, inputs[index].general_state, sizeof(saved_general));
        memcpy(&saved_vector, inputs[index].vector_state, sizeof(saved_vector));
        memset(&observed_general, 0, sizeof(observed_general));
        memset(&observed_vector, 0, sizeof(observed_vector));
        mach_msg_type_number_t vector_count = ARM_NEON_STATE64_COUNT;
        mach_result = thread_get_state(
            ports[index],
            ARM_NEON_STATE64,
            (thread_state_t)&observed_vector,
            &vector_count
        );
        mach_msg_type_number_t general_count = ARM_THREAD_STATE64_COUNT;
        if (mach_result == KERN_SUCCESS) {
            mach_result = thread_get_state(
                ports[index],
                ARM_THREAD_STATE64,
                (thread_state_t)&observed_general,
                &general_count
            );
        }
        if (mach_result != KERN_SUCCESS
            || vector_count != ARM_NEON_STATE64_COUNT
            || general_count != ARM_THREAD_STATE64_COUNT
            || memcmp(&saved_vector, &observed_vector, sizeof(saved_vector)) != 0
            || !continuum_arm64_general_states_equal(
                &saved_general,
                &observed_general
            )) {
            status = CONTINUUM_STATUS_VALIDATION_FAILED;
            goto rollback;
        }
    }

    thread_act_array_t verified_threads = NULL;
    mach_msg_type_number_t verified_count = 0;
    mach_result = task_threads(
        session->task,
        &verified_threads,
        &verified_count
    );
    if (mach_result != KERN_SUCCESS || (size_t)verified_count != thread_count) {
        status = CONTINUUM_STATUS_THREAD_SET_CHANGED;
    }
    if (verified_threads != NULL) {
        for (mach_msg_type_number_t index = 0;
             index < verified_count;
             index += 1) {
            mach_port_deallocate(mach_task_self(), verified_threads[index]);
        }
        vm_deallocate(
            mach_task_self(),
            (vm_address_t)verified_threads,
            (vm_size_t)(verified_count * sizeof(thread_act_t))
        );
    }
    if (status != CONTINUUM_STATUS_OK) {
        goto rollback;
    }

    session->has_reconstructed_thread_set = 1;
    out_report->reconstructed_thread_count = thread_count;
    out_report->created_raw_thread_count = created_count;
    out_report->general_state_bytes = general_state_bytes;
    out_report->vector_state_bytes = vector_state_bytes;
    out_report->primary_replacement_thread_identifier = primary_identifier;
    out_report->all_states_verified = 1;
    if (existing_threads != NULL) {
        vm_deallocate(
            mach_task_self(),
            (vm_address_t)existing_threads,
            (vm_size_t)(existing_count * sizeof(thread_act_t))
        );
    }
    for (size_t index = 0; index < thread_count; index += 1) {
        if (ports[index] != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), ports[index]);
        }
    }
    free(ports);
    free(original_general);
    free(original_vector);
    free(is_existing);
    free(was_modified);
    return CONTINUUM_STATUS_OK;

rollback:
    out_report->rollback_attempted = 1;
    int rollback_verified = 1;
    for (size_t index = 0; index < thread_count; index += 1) {
        if (!is_existing[index] && ports[index] != MACH_PORT_NULL
            && thread_terminate(ports[index]) != KERN_SUCCESS) {
            rollback_verified = 0;
        }
    }
    for (size_t index = 0; index < thread_count; index += 1) {
        if (!was_modified[index] || ports[index] == MACH_PORT_NULL) {
            continue;
        }
        if (thread_set_state(
                ports[index],
                ARM_NEON_STATE64,
                (thread_state_t)&original_vector[index],
                ARM_NEON_STATE64_COUNT
            ) != KERN_SUCCESS
            || thread_set_state(
                ports[index],
                ARM_THREAD_STATE64,
                (thread_state_t)&original_general[index],
                ARM_THREAD_STATE64_COUNT
            ) != KERN_SUCCESS) {
            rollback_verified = 0;
            continue;
        }

        arm_thread_state64_t observed_general;
        arm_neon_state64_t observed_vector;
        memset(&observed_general, 0, sizeof(observed_general));
        memset(&observed_vector, 0, sizeof(observed_vector));
        mach_msg_type_number_t general_count = ARM_THREAD_STATE64_COUNT;
        mach_msg_type_number_t vector_count = ARM_NEON_STATE64_COUNT;
        if (thread_get_state(
                ports[index],
                ARM_THREAD_STATE64,
                (thread_state_t)&observed_general,
                &general_count
            ) != KERN_SUCCESS
            || thread_get_state(
                ports[index],
                ARM_NEON_STATE64,
                (thread_state_t)&observed_vector,
                &vector_count
            ) != KERN_SUCCESS
            || general_count != ARM_THREAD_STATE64_COUNT
            || vector_count != ARM_NEON_STATE64_COUNT
            || !continuum_arm64_general_states_equal(
                &original_general[index],
                &observed_general
            )
            || memcmp(
                &original_vector[index],
                &observed_vector,
                sizeof(original_vector[index])
            ) != 0) {
            rollback_verified = 0;
        }
    }

    thread_act_array_t rollback_threads = NULL;
    mach_msg_type_number_t rollback_count = 0;
    mach_result = task_threads(
        session->task,
        &rollback_threads,
        &rollback_count
    );
    if (mach_result != KERN_SUCCESS || rollback_count != prepared_count) {
        rollback_verified = 0;
    }
    if (rollback_threads != NULL) {
        for (mach_msg_type_number_t index = 0;
             index < rollback_count;
             index += 1) {
            mach_port_deallocate(mach_task_self(), rollback_threads[index]);
        }
        vm_deallocate(
            mach_task_self(),
            (vm_address_t)rollback_threads,
            (vm_size_t)(rollback_count * sizeof(thread_act_t))
        );
    }
    if (existing_threads != NULL) {
        for (mach_msg_type_number_t index = 0;
             index < existing_count;
             index += 1) {
            if (existing_threads[index] != MACH_PORT_NULL) {
                mach_port_deallocate(mach_task_self(), existing_threads[index]);
            }
        }
        vm_deallocate(
            mach_task_self(),
            (vm_address_t)existing_threads,
            (vm_size_t)(existing_count * sizeof(thread_act_t))
        );
    }
    for (size_t index = 0; index < thread_count; index += 1) {
        if (ports[index] != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), ports[index]);
        }
    }
    free(ports);
    free(original_general);
    free(original_vector);
    free(is_existing);
    free(was_modified);
    if (continuum_resume_session(session, did_suspend) != CONTINUUM_STATUS_OK) {
        rollback_verified = 0;
    }
    out_report->rollback_verified = rollback_verified ? 1 : 0;
    return rollback_verified ? status : CONTINUUM_STATUS_ROLLBACK_FAILED;

cleanup_allocations:
    free(ports);
    free(original_general);
    free(original_vector);
    free(is_existing);
    free(was_modified);
    return status;
#endif
}

continuum_status continuum_remote_session_release_entry_stopped_child(
    continuum_remote_session *session,
    int32_t process_id
) {
    if (session == NULL || process_id <= 0
        || session->identity.process_id != process_id
        || !session->has_reconstructed_thread_set
        || session->owned_suspend_count == 0) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    continuum_status status = continuum_validate_stopped_replacement_session(
        session
    );
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }

    thread_act_t prepared_worker_ports[CONTINUUM_REMOTE_PTHREAD_LIMIT];
    memset(prepared_worker_ports, 0, sizeof(prepared_worker_ports));
    uint32_t prepared_worker_count = 0;
    uint32_t resumed_worker_count = 0;
    if (session->has_prepared_pthread_set) {
        prepared_worker_count = session->prepared_pthreads.created_count;
        if (session->prepared_pthreads.version != 3
            || prepared_worker_count > CONTINUUM_REMOTE_PTHREAD_LIMIT) {
            return CONTINUUM_STATUS_VALIDATION_FAILED;
        }

        thread_act_array_t threads = NULL;
        mach_msg_type_number_t thread_count = 0;
        kern_return_t mach_result = task_threads(
            session->task,
            &threads,
            &thread_count
        );
        if (mach_result != KERN_SUCCESS) {
            return CONTINUUM_STATUS_THREAD_STATE_FAILED;
        }
        for (mach_msg_type_number_t thread_index = 0;
             thread_index < thread_count;
             thread_index += 1) {
            thread_identifier_info_data_t identity;
            memset(&identity, 0, sizeof(identity));
            mach_msg_type_number_t identity_count =
                THREAD_IDENTIFIER_INFO_COUNT;
            mach_result = thread_info(
                threads[thread_index],
                THREAD_IDENTIFIER_INFO,
                (thread_info_t)&identity,
                &identity_count
            );
            if (mach_result != KERN_SUCCESS) {
                status = CONTINUUM_STATUS_THREAD_STATE_FAILED;
                break;
            }
            for (uint32_t worker = 0;
                 worker < prepared_worker_count;
                 worker += 1) {
                if (identity.thread_handle
                    != session->prepared_pthreads.thread_handles[worker]) {
                    continue;
                }
                if (identity.thread_id
                        != session->prepared_pthreads
                            .thread_identifiers[worker]
                    || prepared_worker_ports[worker] != MACH_PORT_NULL) {
                    status = CONTINUUM_STATUS_THREAD_SET_CHANGED;
                    break;
                }
                prepared_worker_ports[worker] = threads[thread_index];
                threads[thread_index] = MACH_PORT_NULL;
            }
            if (status != CONTINUUM_STATUS_OK) {
                break;
            }
        }
        if (status == CONTINUUM_STATUS_OK) {
            for (uint32_t worker = 0;
                 worker < prepared_worker_count;
                 worker += 1) {
                if (prepared_worker_ports[worker] == MACH_PORT_NULL) {
                    status = CONTINUUM_STATUS_THREAD_SET_CHANGED;
                    break;
                }
            }
        }
        if (threads != NULL) {
            for (mach_msg_type_number_t index = 0;
                 index < thread_count;
                 index += 1) {
                if (threads[index] != MACH_PORT_NULL) {
                    mach_port_deallocate(mach_task_self(), threads[index]);
                }
            }
            vm_deallocate(
                mach_task_self(),
                (vm_address_t)threads,
                (vm_size_t)(thread_count * sizeof(thread_act_t))
            );
        }
        if (status != CONTINUUM_STATUS_OK) {
            for (uint32_t worker = 0;
                 worker < prepared_worker_count;
                 worker += 1) {
                if (prepared_worker_ports[worker] != MACH_PORT_NULL) {
                    mach_port_deallocate(
                        mach_task_self(),
                        prepared_worker_ports[worker]
                    );
                }
            }
            return status;
        }

        for (uint32_t worker = 0;
             worker < prepared_worker_count;
             worker += 1) {
            if (thread_resume(prepared_worker_ports[worker]) != KERN_SUCCESS) {
                status = CONTINUUM_STATUS_RESUME_FAILED;
                break;
            }
            resumed_worker_count += 1;
        }
        if (status != CONTINUUM_STATUS_OK) {
            int rollback_verified = 1;
            while (resumed_worker_count > 0) {
                resumed_worker_count -= 1;
                if (thread_suspend(
                        prepared_worker_ports[resumed_worker_count]
                    ) != KERN_SUCCESS) {
                    rollback_verified = 0;
                }
            }
            for (uint32_t worker = 0;
                 worker < prepared_worker_count;
                 worker += 1) {
                mach_port_deallocate(
                    mach_task_self(),
                    prepared_worker_ports[worker]
                );
            }
            return rollback_verified
                ? status
                : CONTINUUM_STATUS_ROLLBACK_FAILED;
        }
    }
    int stop_release_result = 0;
    if (session->replacement_stop_kind
            == CONTINUUM_REPLACEMENT_STOP_BROKER_SIGNAL) {
        stop_release_result = kill(process_id, SIGCONT);
    } else {
        stop_release_result = ptrace(PT_DETACH, process_id, (caddr_t)1, 0);
    }
    if (stop_release_result != 0) {
        status = errno == ESRCH
            ? CONTINUUM_STATUS_TARGET_EXITED
            : (session->replacement_stop_kind
                    == CONTINUUM_REPLACEMENT_STOP_BROKER_SIGNAL
                ? CONTINUUM_STATUS_RESUME_FAILED
                : CONTINUUM_STATUS_ACCESS_DENIED);
        int rollback_verified = 1;
        while (resumed_worker_count > 0) {
            resumed_worker_count -= 1;
            if (thread_suspend(
                    prepared_worker_ports[resumed_worker_count]
                ) != KERN_SUCCESS) {
                rollback_verified = 0;
            }
        }
        for (uint32_t worker = 0;
             worker < prepared_worker_count;
             worker += 1) {
            mach_port_deallocate(
                mach_task_self(),
                prepared_worker_ports[worker]
            );
        }
        return rollback_verified
            ? status
            : CONTINUUM_STATUS_ROLLBACK_FAILED;
    }
    session->owns_ptrace_attachment = 0;
    for (uint32_t worker = 0;
         worker < prepared_worker_count;
         worker += 1) {
        mach_port_deallocate(
            mach_task_self(),
            prepared_worker_ports[worker]
        );
    }
    status = continuum_discharge_owned_suspensions(
        session,
        CONTINUUM_RESUME_ATTEMPT_LIMIT
    );
    if (status == CONTINUUM_STATUS_OK) {
        session->has_reconstructed_thread_set = 0;
    } else if (task_terminate(session->task) == KERN_SUCCESS) {
        // The ptrace or signal-stop transition already committed. If the owned
        // task suspension cannot be released exactly, fail closed so no later
        // session cleanup can accidentally run a partially released process.
        session->owned_suspend_count = 0;
        session->has_reconstructed_thread_set = 0;
    }
    return status;
}

continuum_status continuum_remote_session_reconstruct_region(
    continuum_remote_session *session,
    const continuum_remote_process_region_info *region,
    const void *bytes,
    size_t length,
    continuum_remote_restore_report *out_report
) {
    if (region == NULL || bytes == NULL || out_report == NULL
        || region->length != length) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }

    continuum_remote_restore_report report;
    continuum_status status = continuum_remote_session_begin_reconstruct_region(
        session,
        region,
        &report
    );
    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_remote_session_write_reconstructed_region(
            session,
            region,
            0,
            bytes,
            length,
            &report
        );
    }
    uint64_t bytes_written = report.bytes_written;
    uint8_t readback_verified = report.readback_verified;
    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_remote_session_finish_reconstruct_region(
            session,
            region,
            &report
        );
    } else if (session != NULL
        && session->has_active_reconstruction
        && session->reconstruction_address == region->address
        && session->reconstruction_length == region->length) {
        // The one-shot API owns this transaction. Its replacement child is
        // disposable, so release the session state after a failed stream and
        // let the caller discard the child instead of deadlocking later work.
        session->reconstruction_address = 0;
        session->reconstruction_length = 0;
        session->has_active_reconstruction = 0;
    }
    *out_report = report;
    out_report->bytes_written = bytes_written;
    out_report->readback_verified = readback_verified;
    return status;
}

continuum_status continuum_remote_session_capture_resource_fingerprint(
    continuum_remote_session *session,
    continuum_remote_resource_fingerprint *out_fingerprint
) {
    if (session == NULL || out_fingerprint == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    memset(out_fingerprint, 0, sizeof(*out_fingerprint));

    continuum_status status = continuum_validate_session_identity(session);
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }

    int did_suspend = 0;
    status = continuum_suspend_session(session, &did_suspend);
    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_capture_resource_fingerprint_suspended(
            session,
            out_fingerprint
        );
    }

    continuum_status resume_status = continuum_resume_session(
        session,
        did_suspend
    );
    if (resume_status != CONTINUUM_STATUS_OK) {
        status = resume_status;
    }
    if (status != CONTINUUM_STATUS_OK) {
        memset(out_fingerprint, 0, sizeof(*out_fingerprint));
    }
    return status;
}

uint32_t continuum_remote_resource_fingerprint_changes(
    const continuum_remote_resource_fingerprint *saved,
    const continuum_remote_resource_fingerprint *current
) {
    const uint32_t all_changes =
        CONTINUUM_RESOURCE_CHANGE_DESCRIPTOR_TABLE
        | CONTINUUM_RESOURCE_CHANGE_MACH_SPACE
        | CONTINUUM_RESOURCE_CHANGE_THREAD_SET
        | CONTINUUM_RESOURCE_CHANGE_UNSUPPORTED_DESCRIPTOR;
    if (saved == NULL || current == NULL) {
        return all_changes;
    }

    uint32_t changes = CONTINUUM_RESOURCE_CHANGE_NONE;
    if (saved->file_descriptor_count != current->file_descriptor_count
        || saved->vnode_count != current->vnode_count
        || saved->socket_count != current->socket_count
        || saved->pipe_count != current->pipe_count
        || saved->kqueue_count != current->kqueue_count
        || saved->shared_memory_count != current->shared_memory_count
        || saved->semaphore_count != current->semaphore_count
        || saved->guarded_descriptor_count != current->guarded_descriptor_count
        || saved->descriptor_table_hash != current->descriptor_table_hash) {
        changes |= CONTINUUM_RESOURCE_CHANGE_DESCRIPTOR_TABLE;
    }
    if (saved->mach_name_count != current->mach_name_count
        || saved->mach_send_right_count != current->mach_send_right_count
        || saved->mach_receive_right_count != current->mach_receive_right_count
        || saved->mach_send_once_right_count
            != current->mach_send_once_right_count
        || saved->mach_port_set_count != current->mach_port_set_count
        || saved->mach_dead_name_count != current->mach_dead_name_count
        || saved->mach_space_hash != current->mach_space_hash) {
        changes |= CONTINUUM_RESOURCE_CHANGE_MACH_SPACE;
    }
    if (saved->thread_count != current->thread_count
        || saved->thread_set_hash != current->thread_set_hash) {
        changes |= CONTINUUM_RESOURCE_CHANGE_THREAD_SET;
    }
    if (saved->unsupported_descriptor_count > 0
        || current->unsupported_descriptor_count > 0) {
        changes |= CONTINUUM_RESOURCE_CHANGE_UNSUPPORTED_DESCRIPTOR;
    }
    return changes;
}

continuum_status continuum_remote_session_register_region(
    continuum_remote_session *session,
    uint64_t address,
    uint64_t length
) {
    if (session == NULL || address == 0 || length == 0) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    continuum_status status = continuum_validate_session_identity(session);
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }

    continuum_remote_region_descriptor descriptor;
    status = continuum_query_region(session->task, address, length, &descriptor);
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }
    session->registered_region = descriptor;
    session->has_registered_region = 1;
    return CONTINUUM_STATUS_OK;
}

continuum_status continuum_remote_session_capture(
    continuum_remote_session *session,
    continuum_remote_region_descriptor *out_descriptor,
    continuum_owned_buffer *out_bytes,
    continuum_remote_thread_snapshot **out_threads
) {
    if (session == NULL || out_descriptor == NULL || out_bytes == NULL
        || out_threads == NULL || !session->has_registered_region) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    memset(out_descriptor, 0, sizeof(*out_descriptor));
    memset(out_bytes, 0, sizeof(*out_bytes));
    *out_threads = NULL;

    continuum_status status = continuum_validate_session_identity(session);
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }

    int did_suspend = 0;
    status = continuum_suspend_session(session, &did_suspend);
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }

    continuum_remote_region_descriptor descriptor;
    memset(&descriptor, 0, sizeof(descriptor));
    continuum_owned_buffer bytes;
    memset(&bytes, 0, sizeof(bytes));
    continuum_remote_thread_snapshot *threads = NULL;

    status = continuum_validate_session_identity(session);
    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_query_region(
            session->task,
            session->registered_region.address,
            session->registered_region.length,
            &descriptor
        );
    }
    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_validate_region_unchanged(
            &session->registered_region,
            &descriptor
        );
    }
    if (status == CONTINUUM_STATUS_OK) {
        if (session->registered_region.length > SIZE_MAX) {
            status = CONTINUUM_STATUS_RANGE_ERROR;
        } else {
            bytes.bytes = malloc((size_t)session->registered_region.length);
        }
        if (bytes.bytes == NULL) {
            if (status == CONTINUUM_STATUS_OK) {
                status = CONTINUUM_STATUS_OUT_OF_MEMORY;
            }
        } else {
            bytes.length = (size_t)session->registered_region.length;
        }
    }
    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_read_task_bytes(
            session->task,
            session->registered_region.address,
            session->registered_region.length,
            bytes.bytes
        );
    }
    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_capture_thread_snapshot(session->task, &threads);
    }
    if (status == CONTINUUM_STATUS_OK) {
        descriptor.thread_set_hash = threads->set_hash;
    }

    continuum_status resume_status = continuum_resume_session(session, did_suspend);
    if (resume_status != CONTINUUM_STATUS_OK) {
        status = resume_status;
    }
    if (status != CONTINUUM_STATUS_OK) {
        continuum_owned_buffer_destroy(&bytes);
        continuum_remote_thread_snapshot_destroy(threads);
        return status;
    }

    *out_descriptor = descriptor;
    *out_bytes = bytes;
    *out_threads = threads;
    return CONTINUUM_STATUS_OK;
}

continuum_status continuum_remote_session_capture_process(
    continuum_remote_session *session,
    uint64_t maximum_captured_bytes,
    continuum_remote_process_snapshot **out_snapshot,
    continuum_remote_process_snapshot_info *out_info
) {
    if (session == NULL || out_snapshot == NULL || out_info == NULL
        || maximum_captured_bytes == 0 || session->is_self) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    *out_snapshot = NULL;
    memset(out_info, 0, sizeof(*out_info));

    continuum_status status = continuum_validate_session_identity(session);
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }

    int did_suspend = 0;
    status = continuum_suspend_session(session, &did_suspend);
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }

    continuum_remote_process_snapshot *snapshot = NULL;
    status = continuum_capture_process_snapshot_suspended(
        session,
        maximum_captured_bytes,
        &snapshot
    );

    continuum_status resume_status = continuum_resume_session(session, did_suspend);
    if (resume_status != CONTINUUM_STATUS_OK) {
        status = resume_status;
    }
    if (status != CONTINUUM_STATUS_OK) {
        continuum_remote_process_snapshot_destroy(snapshot);
        return status;
    }

    // The coherent cut is complete and the target is already running again.
    // Fault historical COW views into the guardian now so later restores do
    // not pay thousands of mapping faults while the app is frozen.
    continuum_prewarm_process_snapshot(snapshot);

    *out_info = snapshot->info;
    *out_snapshot = snapshot;
    return CONTINUUM_STATUS_OK;
}

continuum_status continuum_remote_session_restore_process(
    continuum_remote_session *session,
    const continuum_remote_process_snapshot *snapshot,
    continuum_remote_process_restore_report *out_report
) {
    if (session == NULL || snapshot == NULL || out_report == NULL
        || session->is_self || snapshot->info.captured_bytes == 0) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    memset(out_report, 0, sizeof(*out_report));

    continuum_status status = continuum_validate_session_identity(session);
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }
    if (!continuum_identity_equal(&session->identity, &snapshot->identity)) {
        return CONTINUUM_STATUS_PROCESS_IDENTITY_CHANGED;
    }

    int did_suspend = 0;
    status = continuum_suspend_session(session, &did_suspend);
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }

    continuum_remote_process_snapshot *safety = NULL;
    status = continuum_capture_process_snapshot_suspended(
        session,
        snapshot->info.captured_bytes,
        &safety
    );
    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_validate_process_snapshot_layout(safety, snapshot);
    }
    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_apply_process_snapshot(
            session->task,
            snapshot,
            safety,
            out_report
        );
    }

    if (status != CONTINUUM_STATUS_OK && safety != NULL
        && (out_report->bytes_written > 0
            || out_report->thread_states_restored > 0)) {
        continuum_status original_status = status;
        out_report->rollback_attempted = 1;
        continuum_remote_process_restore_report rollback_report;
        continuum_status rollback_status = continuum_apply_process_snapshot(
            session->task,
            safety,
            snapshot,
            &rollback_report
        );
        if (rollback_status == CONTINUUM_STATUS_OK
            && rollback_report.memory_readback_verified == 1
            && rollback_report.thread_states_restored
                == safety->info.thread_count) {
            out_report->rollback_verified = 1;
            status = original_status;
        } else {
            status = CONTINUUM_STATUS_ROLLBACK_FAILED;
        }
    }

    continuum_remote_process_snapshot_destroy(safety);
    continuum_status resume_status = continuum_resume_session(session, did_suspend);
    if (resume_status != CONTINUUM_STATUS_OK) {
        return resume_status;
    }
    return status;
}

static int continuum_process_tree_entry_compare(
    const void *left,
    const void *right
) {
    const continuum_remote_process_tree_entry *left_entry = left;
    const continuum_remote_process_tree_entry *right_entry = right;
    if (left_entry->depth < right_entry->depth) {
        return -1;
    }
    if (left_entry->depth > right_entry->depth) {
        return 1;
    }
    if (left_entry->process_id < right_entry->process_id) {
        return -1;
    }
    if (left_entry->process_id > right_entry->process_id) {
        return 1;
    }
    return 0;
}

static int continuum_process_tree_contains(
    const continuum_remote_process_tree_entry *entries,
    size_t count,
    int32_t process_id,
    uint32_t *out_depth
) {
    for (size_t index = 0; index < count; index += 1) {
        if (entries[index].process_id == process_id) {
            if (out_depth != NULL) {
                *out_depth = entries[index].depth;
            }
            return 1;
        }
    }
    return 0;
}

static continuum_status continuum_discover_process_forest(
    const int32_t *root_process_ids,
    size_t root_process_count,
    continuum_remote_process_tree_entry **out_entries,
    size_t *out_count
) {
    if (root_process_ids == NULL || root_process_count == 0
        || out_entries == NULL || out_count == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    for (size_t root_index = 0;
         root_index < root_process_count;
         root_index += 1) {
        if (root_process_ids[root_index] <= 1) {
            return CONTINUUM_STATUS_INVALID_ARGUMENT;
        }
    }
    *out_entries = NULL;
    *out_count = 0;

    int estimated_count = proc_listallpids(NULL, 0);
    if (estimated_count <= 0 || estimated_count > INT_MAX / 2) {
        return CONTINUUM_STATUS_MACH_ERROR;
    }
    size_t capacity = (size_t)estimated_count + 128U;
    if (capacity > INT_MAX / sizeof(pid_t)) {
        return CONTINUUM_STATUS_RANGE_ERROR;
    }
    pid_t *process_ids = calloc(capacity, sizeof(*process_ids));
    if (process_ids == NULL) {
        return CONTINUUM_STATUS_OUT_OF_MEMORY;
    }
    int process_count = proc_listallpids(
        process_ids,
        (int)(capacity * sizeof(*process_ids))
    );
    if (process_count <= 0 || (size_t)process_count > capacity) {
        free(process_ids);
        return CONTINUUM_STATUS_MACH_ERROR;
    }

    continuum_remote_process_tree_entry *all_entries = calloc(
        (size_t)process_count,
        sizeof(*all_entries)
    );
    if (all_entries == NULL) {
        free(process_ids);
        return CONTINUUM_STATUS_OUT_OF_MEMORY;
    }
    size_t all_count = 0;
    for (int index = 0; index < process_count; index += 1) {
        if (process_ids[index] <= 0) {
            continue;
        }
        struct proc_bsdinfo info;
        memset(&info, 0, sizeof(info));
        int bytes = proc_pidinfo(
            process_ids[index],
            PROC_PIDTBSDINFO,
            0,
            &info,
            sizeof(info)
        );
        if (bytes != (int)sizeof(info)) {
            continue;
        }
        all_entries[all_count].process_id = process_ids[index];
        all_entries[all_count].parent_process_id = (int32_t)info.pbi_ppid;
        all_count += 1;
    }
    free(process_ids);

    continuum_remote_process_tree_entry *tree = calloc(
        all_count == 0 ? 1 : all_count,
        sizeof(*tree)
    );
    if (tree == NULL) {
        free(all_entries);
        return CONTINUUM_STATUS_OUT_OF_MEMORY;
    }

    size_t tree_count = 0;
    for (size_t root_index = 0;
         root_index < root_process_count;
         root_index += 1) {
        const int32_t root_process_id = root_process_ids[root_index];
        int found = 0;
        for (size_t index = 0; index < all_count; index += 1) {
            if (all_entries[index].process_id != root_process_id) {
                continue;
            }
            found = 1;
            if (!continuum_process_tree_contains(
                    tree,
                    tree_count,
                    root_process_id,
                    NULL
                )) {
                tree[tree_count] = all_entries[index];
                tree_count += 1;
            }
            break;
        }
        if (!found) {
            free(tree);
            free(all_entries);
            return CONTINUUM_STATUS_TARGET_EXITED;
        }
    }

    int added = 1;
    while (added) {
        added = 0;
        for (size_t index = 0; index < all_count; index += 1) {
            const continuum_remote_process_tree_entry candidate =
                all_entries[index];
            if (continuum_process_tree_contains(
                    tree,
                    tree_count,
                    candidate.process_id,
                    NULL
                )) {
                continue;
            }
            if (!continuum_process_tree_contains(
                    tree,
                    tree_count,
                    candidate.parent_process_id,
                    NULL
                )) {
                continue;
            }
            tree[tree_count] = candidate;
            tree_count += 1;
            added = 1;
        }
    }
    free(all_entries);

    // Depth is derived from captured parent links after the complete union is
    // known. This keeps an explicitly named descendant behind its captured
    // ancestor when roots overlap, while independent roots remain depth zero.
    for (size_t index = 0; index < tree_count; index += 1) {
        uint32_t depth = 0;
        int32_t parent_process_id = tree[index].parent_process_id;
        for (size_t step = 0; step < tree_count; step += 1) {
            int parent_found = 0;
            for (size_t parent_index = 0;
                 parent_index < tree_count;
                 parent_index += 1) {
                if (tree[parent_index].process_id != parent_process_id) {
                    continue;
                }
                parent_found = 1;
                parent_process_id = tree[parent_index].parent_process_id;
                depth += 1;
                break;
            }
            if (!parent_found) {
                break;
            }
            if (step + 1 == tree_count) {
                free(tree);
                return CONTINUUM_STATUS_PROCESS_TREE_CHANGED;
            }
        }
        tree[index].depth = depth;
    }
    qsort(
        tree,
        tree_count,
        sizeof(*tree),
        continuum_process_tree_entry_compare
    );
    *out_entries = tree;
    *out_count = tree_count;
    return CONTINUUM_STATUS_OK;
}

static int continuum_process_tree_matches_group(
    const continuum_remote_process_tree_entry *entries,
    size_t entry_count,
    const continuum_remote_process_group_snapshot *group
) {
    if (entries == NULL || group == NULL
        || entry_count != group->member_count) {
        return 0;
    }
    for (size_t index = 0; index < entry_count; index += 1) {
        if (group->members[index].session == NULL
            || entries[index].process_id
                != group->members[index].session->identity.process_id
            || entries[index].parent_process_id
                != group->members[index].parent_process_id) {
            return 0;
        }
    }
    return 1;
}

static int continuum_process_tree_contains_group(
    const continuum_remote_process_tree_entry *entries,
    size_t entry_count,
    const continuum_remote_process_group_snapshot *group
) {
    if (entries == NULL || group == NULL
        || entry_count < group->member_count) {
        return 0;
    }
    for (size_t member_index = 0;
         member_index < group->member_count;
         member_index += 1) {
        const continuum_remote_process_group_member *member =
            &group->members[member_index];
        if (member->session == NULL) {
            return 0;
        }
        int found = 0;
        for (size_t entry_index = 0; entry_index < entry_count; entry_index += 1) {
            if (entries[entry_index].process_id
                    == member->session->identity.process_id
                && entries[entry_index].parent_process_id
                    == member->parent_process_id) {
                found = 1;
                break;
            }
        }
        if (!found) {
            return 0;
        }
    }
    return 1;
}

static continuum_status continuum_suspend_process_group(
    continuum_remote_process_group_snapshot *group,
    size_t *out_suspended_count
) {
    if (group == NULL || out_suspended_count == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    *out_suspended_count = 0;
    for (size_t index = 0; index < group->member_count; index += 1) {
        continuum_remote_process_group_member *member = &group->members[index];
        if (member->session == NULL
            || member->suspension_token != MACH_PORT_NULL) {
            return CONTINUUM_STATUS_INVALID_ARGUMENT;
        }
        continuum_status status = continuum_validate_session_identity(
            member->session
        );
        if (status != CONTINUUM_STATUS_OK) {
            return status;
        }
        kern_return_t result = task_suspend2(
            member->session->task,
            &member->suspension_token
        );
        if (result != KERN_SUCCESS
            || member->suspension_token == MACH_PORT_NULL) {
            member->suspension_token = MACH_PORT_NULL;
            return CONTINUUM_STATUS_SUSPEND_FAILED;
        }
        *out_suspended_count += 1;
    }
    return CONTINUUM_STATUS_OK;
}

static continuum_status continuum_resume_process_group(
    continuum_remote_process_group_snapshot *group,
    size_t suspended_count
) {
    if (group == NULL || suspended_count > group->member_count) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    continuum_status status = CONTINUUM_STATUS_OK;
    while (suspended_count > 0) {
        suspended_count -= 1;
        continuum_remote_process_group_member *member =
            &group->members[suspended_count];
        if (member->suspension_token == MACH_PORT_NULL) {
            continue;
        }
        kern_return_t result = task_resume2(member->suspension_token);
        if (result == KERN_SUCCESS) {
            member->suspension_token = MACH_PORT_NULL;
        } else if (status == CONTINUUM_STATUS_OK) {
            status = CONTINUUM_STATUS_RESUME_FAILED;
        }
    }
    return status;
}

void continuum_remote_process_group_snapshot_destroy(
    continuum_remote_process_group_snapshot *snapshot
) {
    if (snapshot == NULL) {
        return;
    }
    (void)continuum_resume_process_group(snapshot, snapshot->member_count);
    for (size_t index = 0; index < snapshot->member_count; index += 1) {
        continuum_remote_process_snapshot_destroy(
            snapshot->members[index].snapshot
        );
        continuum_remote_session_destroy(snapshot->members[index].session);
        memset(&snapshot->members[index], 0, sizeof(snapshot->members[index]));
    }
    free(snapshot->members);
    free(snapshot->root_process_ids);
    memset(snapshot, 0, sizeof(*snapshot));
    free(snapshot);
}

static continuum_status continuum_capture_process_group_attempt(
    const int32_t *root_process_ids,
    size_t root_process_count,
    uint64_t maximum_captured_bytes,
    continuum_remote_resource_capture_callback resource_callback,
    void *resource_context,
    continuum_remote_process_group_snapshot **out_snapshot
) {
    continuum_remote_process_tree_entry *tree = NULL;
    size_t tree_count = 0;
    continuum_status status = continuum_discover_process_forest(
        root_process_ids,
        root_process_count,
        &tree,
        &tree_count
    );
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }

    continuum_remote_process_group_snapshot *group = calloc(1, sizeof(*group));
    if (group == NULL) {
        free(tree);
        return CONTINUUM_STATUS_OUT_OF_MEMORY;
    }
    group->root_process_ids = calloc(
        root_process_count,
        sizeof(*group->root_process_ids)
    );
    if (group->root_process_ids == NULL) {
        free(tree);
        free(group);
        return CONTINUUM_STATUS_OUT_OF_MEMORY;
    }
    memcpy(
        group->root_process_ids,
        root_process_ids,
        root_process_count * sizeof(*group->root_process_ids)
    );
    group->root_process_count = root_process_count;
    group->member_count = tree_count;
    group->members = calloc(tree_count, sizeof(*group->members));
    if (group->members == NULL) {
        free(tree);
        free(group->root_process_ids);
        free(group);
        return CONTINUUM_STATUS_OUT_OF_MEMORY;
    }

    for (size_t index = 0;
         status == CONTINUUM_STATUS_OK && index < tree_count;
         index += 1) {
        group->members[index].parent_process_id = tree[index].parent_process_id;
        status = continuum_remote_session_open(
            tree[index].process_id,
            &group->members[index].session
        );
    }

    size_t suspended_count = 0;
    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_suspend_process_group(group, &suspended_count);
    }
    continuum_remote_process_tree_entry *verified_tree = NULL;
    size_t verified_count = 0;
    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_discover_process_forest(
            root_process_ids,
            root_process_count,
            &verified_tree,
            &verified_count
        );
    }
    if (status == CONTINUUM_STATUS_OK
        && !continuum_process_tree_matches_group(
            verified_tree,
            verified_count,
            group
        )) {
        status = CONTINUUM_STATUS_PROCESS_TREE_CHANGED;
    }
    free(verified_tree);
    free(tree);

    uint64_t captured_bytes = 0;
    for (size_t index = 0;
         status == CONTINUUM_STATUS_OK && index < group->member_count;
         index += 1) {
        if (captured_bytes >= maximum_captured_bytes) {
            status = CONTINUUM_STATUS_SNAPSHOT_BUDGET_EXCEEDED;
            break;
        }
        status = continuum_capture_process_snapshot_suspended(
            group->members[index].session,
            maximum_captured_bytes - captured_bytes,
            &group->members[index].snapshot
        );
        if (getenv("CONTINUUM_CAPTURE_TRACE") != NULL) {
            fprintf(
                stderr,
                "continuum capture member=%zu pid=%d phase=memory status=%d\n",
                index,
                group->members[index].session->identity.process_id,
                status
            );
        }
        if (status != CONTINUUM_STATUS_OK) {
            break;
        }
        const continuum_remote_process_snapshot_info info =
            group->members[index].snapshot->info;
        if (!continuum_add_u64(captured_bytes, info.captured_bytes, &captured_bytes)) {
            status = CONTINUUM_STATUS_RANGE_ERROR;
            break;
        }
        group->info.process_count += 1;
        group->info.captured_region_count += info.captured_region_count;
        group->info.captured_bytes = captured_bytes;
        group->info.excluded_region_count += info.excluded_region_count;
        group->info.excluded_bytes += info.excluded_bytes;
        group->info.thread_count += info.thread_count;
    }

    if (status == CONTINUUM_STATUS_OK && resource_callback != NULL) {
        status = resource_callback(group, resource_context);
        if (getenv("CONTINUUM_CAPTURE_TRACE") != NULL) {
            fprintf(
                stderr,
                "continuum capture phase=resources status=%d\n",
                status
            );
        }
    }

    continuum_status resume_status = continuum_resume_process_group(
        group,
        suspended_count
    );
    if (resume_status != CONTINUUM_STATUS_OK) {
        status = resume_status;
    }
    if (status != CONTINUUM_STATUS_OK) {
        continuum_remote_process_group_snapshot_destroy(group);
        return status;
    }

    for (size_t index = 0; index < group->member_count; index += 1) {
        continuum_prewarm_process_snapshot(group->members[index].snapshot);
    }
    *out_snapshot = group;
    return CONTINUUM_STATUS_OK;
}

static continuum_status continuum_remote_process_group_capture_internal(
    const int32_t *root_process_ids,
    size_t root_process_count,
    uint64_t maximum_captured_bytes,
    continuum_remote_resource_capture_callback resource_callback,
    void *resource_context,
    continuum_remote_process_group_snapshot **out_snapshot,
    continuum_remote_process_group_snapshot_info *out_info
) {
    if (root_process_ids == NULL || root_process_count == 0
        || root_process_count > SIZE_MAX / sizeof(*root_process_ids)
        || maximum_captured_bytes == 0 || out_snapshot == NULL
        || out_info == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    *out_snapshot = NULL;
    memset(out_info, 0, sizeof(*out_info));

    int32_t *unique_roots = calloc(root_process_count, sizeof(*unique_roots));
    if (unique_roots == NULL) {
        return CONTINUUM_STATUS_OUT_OF_MEMORY;
    }
    size_t unique_root_count = 0;
    for (size_t root_index = 0;
         root_index < root_process_count;
         root_index += 1) {
        const int32_t process_id = root_process_ids[root_index];
        if (process_id <= 1 || process_id == getpid()) {
            free(unique_roots);
            return CONTINUUM_STATUS_INVALID_ARGUMENT;
        }
        int duplicate = 0;
        for (size_t existing_index = 0;
             existing_index < unique_root_count;
             existing_index += 1) {
            if (unique_roots[existing_index] == process_id) {
                duplicate = 1;
                break;
            }
        }
        if (!duplicate) {
            unique_roots[unique_root_count] = process_id;
            unique_root_count += 1;
        }
    }

    continuum_status status = CONTINUUM_STATUS_PROCESS_TREE_CHANGED;
    for (size_t attempt = 0; attempt < 3; attempt += 1) {
        status = continuum_capture_process_group_attempt(
            unique_roots,
            unique_root_count,
            maximum_captured_bytes,
            resource_callback,
            resource_context,
            out_snapshot
        );
        if (status != CONTINUUM_STATUS_PROCESS_TREE_CHANGED
            && status != CONTINUUM_STATUS_REGION_MAPPING_CHANGED) {
            break;
        }
    }
    free(unique_roots);
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }
    *out_info = (*out_snapshot)->info;
    return CONTINUUM_STATUS_OK;
}

continuum_status continuum_remote_process_group_capture(
    int32_t root_process_id,
    uint64_t maximum_captured_bytes,
    continuum_remote_process_group_snapshot **out_snapshot,
    continuum_remote_process_group_snapshot_info *out_info
) {
    const int32_t roots[] = { root_process_id };
    return continuum_remote_process_group_capture_internal(
        roots,
        1,
        maximum_captured_bytes,
        NULL,
        NULL,
        out_snapshot,
        out_info
    );
}

continuum_status continuum_remote_process_group_capture_roots(
    const int32_t root_process_ids[],
    size_t root_process_count,
    uint64_t maximum_captured_bytes,
    continuum_remote_process_group_snapshot **out_snapshot,
    continuum_remote_process_group_snapshot_info *out_info
) {
    return continuum_remote_process_group_capture_internal(
        root_process_ids,
        root_process_count,
        maximum_captured_bytes,
        NULL,
        NULL,
        out_snapshot,
        out_info
    );
}

continuum_status continuum_remote_process_group_capture_with_resources(
    int32_t root_process_id,
    uint64_t maximum_captured_bytes,
    continuum_remote_resource_capture_callback callback,
    void *callback_context,
    continuum_remote_process_group_snapshot **out_snapshot,
    continuum_remote_process_group_snapshot_info *out_info
) {
    if (callback == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    const int32_t roots[] = { root_process_id };
    return continuum_remote_process_group_capture_internal(
        roots,
        1,
        maximum_captured_bytes,
        callback,
        callback_context,
        out_snapshot,
        out_info
    );
}

continuum_status continuum_remote_process_group_capture_roots_with_resources(
    const int32_t root_process_ids[],
    size_t root_process_count,
    uint64_t maximum_captured_bytes,
    continuum_remote_resource_capture_callback callback,
    void *callback_context,
    continuum_remote_process_group_snapshot **out_snapshot,
    continuum_remote_process_group_snapshot_info *out_info
) {
    if (callback == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    return continuum_remote_process_group_capture_internal(
        root_process_ids,
        root_process_count,
        maximum_captured_bytes,
        callback,
        callback_context,
        out_snapshot,
        out_info
    );
}

size_t continuum_remote_process_group_member_count(
    const continuum_remote_process_group_snapshot *snapshot
) {
    return snapshot == NULL ? 0 : snapshot->member_count;
}

continuum_status continuum_remote_process_group_live_status(
    const continuum_remote_process_group_snapshot *snapshot
) {
    if (snapshot == NULL || snapshot->member_count == 0) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    for (size_t index = 0; index < snapshot->member_count; index += 1) {
        continuum_status status = continuum_validate_session_identity(
            snapshot->members[index].session
        );
        if (status != CONTINUUM_STATUS_OK) {
            return status;
        }
    }
    return CONTINUUM_STATUS_OK;
}

static continuum_status continuum_find_authenticated_bootstrap_base(
    continuum_remote_session *session,
    const char *library_path,
    const uint8_t expected_uuid[16],
    mach_vm_address_t *out_image_base
) {
    if (session == NULL || library_path == NULL || library_path[0] == '\0'
        || expected_uuid == NULL || out_image_base == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    *out_image_base = 0;
    char expected_path[PATH_MAX];
    if (realpath(library_path, expected_path) == NULL) {
        return CONTINUUM_STATUS_VALIDATION_FAILED;
    }

    task_dyld_info_data_t dyld_info;
    memset(&dyld_info, 0, sizeof(dyld_info));
    mach_msg_type_number_t dyld_info_count = TASK_DYLD_INFO_COUNT;
    kern_return_t result = task_info(
        session->task,
        TASK_DYLD_INFO,
        (task_info_t)&dyld_info,
        &dyld_info_count
    );
    if (result != KERN_SUCCESS || dyld_info.all_image_info_addr == 0) {
        return CONTINUUM_STATUS_MACH_ERROR;
    }

    struct dyld_all_image_infos all_images;
    memset(&all_images, 0, sizeof(all_images));
    continuum_status status = continuum_read_task_bytes(
        session->task,
        dyld_info.all_image_info_addr,
        sizeof(all_images),
        &all_images
    );
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }
    if (all_images.infoArrayCount == 0
        || all_images.infoArrayCount > UINT32_C(1048576)
        || all_images.infoArray == NULL) {
        return CONTINUUM_STATUS_RANGE_ERROR;
    }

    size_t byte_count =
        (size_t)all_images.infoArrayCount * sizeof(struct dyld_image_info);
    struct dyld_image_info *entries = malloc(byte_count);
    if (entries == NULL) {
        return CONTINUUM_STATUS_OUT_OF_MEMORY;
    }
    status = continuum_read_task_bytes(
        session->task,
        (mach_vm_address_t)(uintptr_t)all_images.infoArray,
        byte_count,
        entries
    );
    for (uint32_t index = 0;
         status == CONTINUUM_STATUS_OK && index < all_images.infoArrayCount;
         index += 1) {
        if (entries[index].imageLoadAddress == NULL
            || entries[index].imageFilePath == NULL) {
            continue;
        }
        char observed_path[PATH_MAX];
        char observed_canonical[PATH_MAX];
        status = continuum_read_task_cstring(
            session->task,
            (mach_vm_address_t)(uintptr_t)entries[index].imageFilePath,
            observed_path,
            sizeof(observed_path)
        );
        if (status != CONTINUUM_STATUS_OK) {
            status = CONTINUUM_STATUS_OK;
            continue;
        }
        if (realpath(observed_path, observed_canonical) == NULL
            || strcmp(expected_path, observed_canonical) != 0) {
            continue;
        }
        uint8_t remote_uuid[16];
        status = continuum_copy_remote_image_uuid(
            session->task,
            (mach_vm_address_t)(uintptr_t)entries[index].imageLoadAddress,
            remote_uuid
        );
        if (status != CONTINUUM_STATUS_OK) {
            break;
        }
        if (memcmp(remote_uuid, expected_uuid, sizeof(remote_uuid)) != 0
            || *out_image_base != 0) {
            status = CONTINUUM_STATUS_VALIDATION_FAILED;
            break;
        }
        *out_image_base =
            (mach_vm_address_t)(uintptr_t)entries[index].imageLoadAddress;
    }
    free(entries);
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }
    return *out_image_base != 0
        ? CONTINUUM_STATUS_OK
        : CONTINUUM_STATUS_VALIDATION_FAILED;
}

continuum_status continuum_remote_process_group_copy_pty_safepoint_status(
    const continuum_remote_process_group_snapshot *snapshot,
    const char *bootstrap_library_path,
    continuum_remote_pty_safepoint_status *out_status
) {
    if (snapshot == NULL || snapshot->member_count == 0
        || bootstrap_library_path == NULL
        || bootstrap_library_path[0] == '\0' || out_status == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    memset(out_status, 0, sizeof(*out_status));

    continuum_bootstrap_identity local_identity;
    continuum_status status = continuum_inspect_local_bootstrap_library(
        bootstrap_library_path,
        &local_identity
    );
    if (status != CONTINUUM_STATUS_OK
        || local_identity.pty_safepoint_status_offset == 0) {
        return status == CONTINUUM_STATUS_OK
            ? CONTINUUM_STATUS_VALIDATION_FAILED
            : status;
    }

    out_status->process_count = snapshot->member_count;
    out_status->queue_state_known = 1;
    out_status->all_queues_zero = 1;
    for (size_t member_index = 0;
         member_index < snapshot->member_count;
         member_index += 1) {
        const continuum_remote_process_group_member *member =
            &snapshot->members[member_index];
        if (member->session == NULL || member->snapshot == NULL
            || member->snapshot->threads == NULL) {
            memset(out_status, 0, sizeof(*out_status));
            return CONTINUUM_STATUS_INVALID_ARGUMENT;
        }
        status = continuum_validate_session_identity(member->session);
        if (status != CONTINUUM_STATUS_OK) {
            memset(out_status, 0, sizeof(*out_status));
            return status;
        }

        mach_vm_address_t remote_image_base = 0;
        status = continuum_find_authenticated_bootstrap_base(
            member->session,
            bootstrap_library_path,
            local_identity.image_uuid,
            &remote_image_base
        );
        uint64_t remote_status_address = 0;
        if (status != CONTINUUM_STATUS_OK
            || !continuum_add_u64(
                remote_image_base,
                local_identity.pty_safepoint_status_offset,
                &remote_status_address
            )) {
            memset(out_status, 0, sizeof(*out_status));
            return status == CONTINUUM_STATUS_OK
                ? CONTINUUM_STATUS_RANGE_ERROR
                : status;
        }
        continuum_bootstrap_pty_safepoint_wire_status remote_status;
        memset(&remote_status, 0, sizeof(remote_status));
        status = continuum_read_task_bytes(
            member->session->task,
            remote_status_address,
            sizeof(remote_status),
            &remote_status
        );
        if (status != CONTINUUM_STATUS_OK
            || remote_status.magic != CONTINUUM_BOOTSTRAP_PTY_STATUS_MAGIC
            || remote_status.version != 2
            || remote_status.structure_size != sizeof(remote_status)
            || remote_status.generation == 0
            || remote_status.safepoint_thread_identifier == 0
            || remote_status.safepoint_active != 1) {
            memset(out_status, 0, sizeof(*out_status));
            return status == CONTINUUM_STATUS_OK
                ? CONTINUUM_STATUS_VALIDATION_FAILED
                : status;
        }
        size_t matching_safepoint_threads = 0;
        const continuum_remote_thread_snapshot *threads =
            member->snapshot->threads;
        for (size_t thread_index = 0;
             thread_index < threads->count;
             thread_index += 1) {
            if (threads->entries[thread_index].identifier
                == remote_status.safepoint_thread_identifier) {
                matching_safepoint_threads += 1;
            }
        }
        if (matching_safepoint_threads != 1) {
            memset(out_status, 0, sizeof(*out_status));
            return CONTINUUM_STATUS_VALIDATION_FAILED;
        }
        if (UINT64_MAX - out_status->pty_descriptor_count
                < remote_status.pty_descriptor_count) {
            memset(out_status, 0, sizeof(*out_status));
            return CONTINUUM_STATUS_RANGE_ERROR;
        }
        out_status->pty_descriptor_count +=
            remote_status.pty_descriptor_count;
        if (!remote_status.queue_state_known) {
            out_status->queue_state_known = 0;
            out_status->all_queues_zero = 0;
        } else if (!remote_status.all_queues_zero) {
            out_status->all_queues_zero = 0;
        }
    }
    return CONTINUUM_STATUS_OK;
}

continuum_status continuum_remote_process_safepoint_is_active(
    int32_t process_id,
    const char *bootstrap_library_path,
    uint8_t *out_is_active
) {
    if (process_id <= 0 || bootstrap_library_path == NULL
        || bootstrap_library_path[0] == '\0' || out_is_active == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    *out_is_active = 0;

    continuum_bootstrap_identity identity;
    continuum_status status = continuum_inspect_local_bootstrap_library(
        bootstrap_library_path,
        &identity
    );
    if (status != CONTINUUM_STATUS_OK
        || identity.pty_safepoint_status_offset == 0) {
        return status == CONTINUUM_STATUS_OK
            ? CONTINUUM_STATUS_VALIDATION_FAILED
            : status;
    }

    continuum_remote_session *session = NULL;
    status = continuum_remote_session_open(process_id, &session);
    if (status != CONTINUUM_STATUS_OK) return status;

    mach_vm_address_t image_base = 0;
    status = continuum_find_authenticated_bootstrap_base(
        session,
        bootstrap_library_path,
        identity.image_uuid,
        &image_base
    );
    uint64_t report_address = 0;
    if (status == CONTINUUM_STATUS_OK
        && !continuum_add_u64(
            image_base,
            identity.pty_safepoint_status_offset,
            &report_address
        )) {
        status = CONTINUUM_STATUS_RANGE_ERROR;
    }
    continuum_bootstrap_pty_safepoint_wire_status report;
    memset(&report, 0, sizeof(report));
    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_read_task_bytes(
            session->task,
            report_address,
            sizeof(report),
            &report
        );
    }
    if (status == CONTINUUM_STATUS_OK
        && report.magic == CONTINUUM_BOOTSTRAP_PTY_STATUS_MAGIC
        && report.version == 2
        && report.structure_size == sizeof(report)
        && report.generation != 0
        && report.safepoint_thread_identifier != 0
        && report.safepoint_active == 1) {
        *out_is_active = 1;
    }
    continuum_remote_session_destroy(session);
    return status;
}

continuum_status continuum_remote_process_group_copy_member_info(
    const continuum_remote_process_group_snapshot *snapshot,
    size_t index,
    continuum_remote_process_group_member_info *out_info
) {
    if (snapshot == NULL || out_info == NULL || index >= snapshot->member_count
        || snapshot->members[index].session == NULL
        || snapshot->members[index].snapshot == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    memset(out_info, 0, sizeof(*out_info));
    const continuum_remote_process_snapshot *process_snapshot =
        snapshot->members[index].snapshot;
    out_info->process_id = snapshot->members[index].session->identity.process_id;
    out_info->parent_process_id = snapshot->members[index].parent_process_id;
    out_info->start_seconds =
        snapshot->members[index].session->identity.start_seconds;
    out_info->start_microseconds =
        snapshot->members[index].session->identity.start_microseconds;
    out_info->executable_device =
        snapshot->members[index].session->identity.executable_device;
    out_info->executable_inode =
        snapshot->members[index].session->identity.executable_inode;
    out_info->captured_region_count =
        process_snapshot->info.captured_region_count;
    out_info->captured_bytes = process_snapshot->info.captured_bytes;
    out_info->thread_count = process_snapshot->info.thread_count;
    out_info->vm_layout_hash = process_snapshot->info.vm_layout_hash;
    out_info->immutable_layout_digest =
        process_snapshot->info.immutable_layout_digest;
    out_info->thread_set_hash = process_snapshot->info.thread_set_hash;
    out_info->file_descriptor_count =
        process_snapshot->resources.file_descriptor_count;
    out_info->descriptor_table_hash =
        process_snapshot->resources.descriptor_table_hash;
    out_info->mach_name_count = process_snapshot->resources.mach_name_count;
    out_info->mach_space_hash = process_snapshot->resources.mach_space_hash;
    return CONTINUUM_STATUS_OK;
}

continuum_status continuum_remote_process_group_copy_member_procargs(
    const continuum_remote_process_group_snapshot *snapshot,
    size_t member_index,
    void *destination,
    size_t destination_capacity,
    size_t *out_required_length
) {
    if (snapshot == NULL || out_required_length == NULL
        || member_index >= snapshot->member_count
        || snapshot->members[member_index].session == NULL
        || (destination == NULL && destination_capacity != 0)) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    continuum_status status = continuum_validate_session_identity(
        snapshot->members[member_index].session
    );
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }

    int mib[] = {
        CTL_KERN,
        KERN_PROCARGS2,
        snapshot->members[member_index].session->identity.process_id
    };
    size_t length = 0;
    if (sysctl(mib, 3, NULL, &length, NULL, 0) != 0 || length == 0) {
        return CONTINUUM_STATUS_ACCESS_DENIED;
    }
    *out_required_length = length;
    if (destination == NULL) {
        return CONTINUUM_STATUS_OK;
    }
    if (destination_capacity < length) {
        return CONTINUUM_STATUS_RANGE_ERROR;
    }
    size_t copied_length = length;
    if (sysctl(mib, 3, destination, &copied_length, NULL, 0) != 0) {
        return CONTINUUM_STATUS_ACCESS_DENIED;
    }
    *out_required_length = copied_length;
    return copied_length <= destination_capacity
        ? CONTINUUM_STATUS_OK
        : CONTINUUM_STATUS_RANGE_ERROR;
}

continuum_status continuum_remote_process_group_copy_member_working_directory(
    const continuum_remote_process_group_snapshot *snapshot,
    size_t member_index,
    void *destination,
    size_t destination_capacity,
    size_t *out_required_length
) {
    if (snapshot == NULL || out_required_length == NULL
        || member_index >= snapshot->member_count
        || snapshot->members[member_index].session == NULL
        || (destination == NULL && destination_capacity != 0)) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    continuum_status status = continuum_validate_session_identity(
        snapshot->members[member_index].session
    );
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }

    struct proc_vnodepathinfo paths;
    memset(&paths, 0, sizeof(paths));
    int copied = proc_pidinfo(
        snapshot->members[member_index].session->identity.process_id,
        PROC_PIDVNODEPATHINFO,
        0,
        &paths,
        (int)sizeof(paths)
    );
    if (copied != (int)sizeof(paths) || paths.pvi_cdir.vip_path[0] == '\0') {
        return CONTINUUM_STATUS_ACCESS_DENIED;
    }
    size_t length = strnlen(paths.pvi_cdir.vip_path, MAXPATHLEN) + 1;
    *out_required_length = length;
    if (destination == NULL) {
        return CONTINUUM_STATUS_OK;
    }
    if (destination_capacity < length) {
        return CONTINUUM_STATUS_RANGE_ERROR;
    }
    memcpy(destination, paths.pvi_cdir.vip_path, length);
    return CONTINUUM_STATUS_OK;
}
continuum_status continuum_find_writable_vnode_conflict(
    const char *path,
    int32_t allowed_process_id,
    int32_t *out_conflicting_process_id
) {
    if (path == NULL || path[0] != '/' || allowed_process_id < 0
        || out_conflicting_process_id == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    *out_conflicting_process_id = 0;
    struct stat target;
    memset(&target, 0, sizeof(target));
    if (lstat(path, &target) != 0 || (target.st_mode & S_IFMT) != S_IFREG) {
        return CONTINUUM_STATUS_VALIDATION_FAILED;
    }

    int required_bytes = proc_listpidspath(
        PROC_ALL_PIDS,
        0,
        path,
        PROC_LISTPIDSPATH_EXCLUDE_EVTONLY,
        NULL,
        0
    );
    if (required_bytes < 0) {
        return errno == EPERM
            ? CONTINUUM_STATUS_ACCESS_DENIED
            : CONTINUUM_STATUS_MACH_ERROR;
    }
    size_t capacity = (size_t)required_bytes + 128U * sizeof(pid_t);
    if (capacity < sizeof(pid_t) || capacity > INT_MAX) {
        return CONTINUUM_STATUS_RANGE_ERROR;
    }
    pid_t *process_ids = calloc(1, capacity);
    if (process_ids == NULL) {
        return CONTINUUM_STATUS_OUT_OF_MEMORY;
    }
    int returned_bytes = proc_listpidspath(
        PROC_ALL_PIDS,
        0,
        path,
        PROC_LISTPIDSPATH_EXCLUDE_EVTONLY,
        process_ids,
        (int)capacity
    );
    if (returned_bytes < 0
        || returned_bytes % (int)sizeof(pid_t) != 0
        || (size_t)returned_bytes > capacity) {
        free(process_ids);
        return errno == EPERM
            ? CONTINUUM_STATUS_ACCESS_DENIED
            : CONTINUUM_STATUS_MACH_ERROR;
    }

    size_t process_count = (size_t)returned_bytes / sizeof(pid_t);
    for (size_t process_index = 0;
         process_index < process_count;
         process_index += 1) {
        pid_t process_id = process_ids[process_index];
        if (process_id <= 0 || process_id == getpid()
            || process_id == allowed_process_id) {
            continue;
        }
        int descriptor_bytes = proc_pidinfo(
            process_id,
            PROC_PIDLISTFDS,
            0,
            NULL,
            0
        );
        if (descriptor_bytes <= 0) {
            if (kill(process_id, 0) == 0 || errno == EPERM) {
                free(process_ids);
                return CONTINUUM_STATUS_ACCESS_DENIED;
            }
            continue;
        }
        size_t descriptor_capacity = (size_t)descriptor_bytes
            + 16U * sizeof(struct proc_fdinfo);
        if (descriptor_capacity > INT_MAX) {
            free(process_ids);
            return CONTINUUM_STATUS_RANGE_ERROR;
        }
        struct proc_fdinfo *descriptors = calloc(1, descriptor_capacity);
        if (descriptors == NULL) {
            free(process_ids);
            return CONTINUUM_STATUS_OUT_OF_MEMORY;
        }
        int copied = proc_pidinfo(
            process_id,
            PROC_PIDLISTFDS,
            0,
            descriptors,
            (int)descriptor_capacity
        );
        if (copied < 0 || copied % (int)sizeof(*descriptors) != 0) {
            free(descriptors);
            free(process_ids);
            return CONTINUUM_STATUS_ACCESS_DENIED;
        }
        size_t descriptor_count = (size_t)copied / sizeof(*descriptors);
        for (size_t descriptor_index = 0;
             descriptor_index < descriptor_count;
             descriptor_index += 1) {
            if (descriptors[descriptor_index].proc_fdtype != PROX_FDTYPE_VNODE) {
                continue;
            }
            struct vnode_fdinfowithpath info;
            memset(&info, 0, sizeof(info));
            int bytes = proc_pidfdinfo(
                process_id,
                descriptors[descriptor_index].proc_fd,
                PROC_PIDFDVNODEPATHINFO,
                &info,
                sizeof(info)
            );
            if (bytes != (int)sizeof(info)) {
                continue;
            }
            uint32_t flags = (uint32_t)info.pfi.fi_openflags;
            if (info.pvip.vip_vi.vi_stat.vst_dev == target.st_dev
                && info.pvip.vip_vi.vi_stat.vst_ino == target.st_ino
                && (flags & O_ACCMODE) != O_RDONLY) {
                *out_conflicting_process_id = process_id;
                free(descriptors);
                free(process_ids);
                return CONTINUUM_STATUS_FILE_WRITER_CONFLICT;
            }
        }
        free(descriptors);
    }
    free(process_ids);
    return CONTINUUM_STATUS_OK;
}

continuum_status continuum_remote_process_group_copy_writable_vnodes(
    const continuum_remote_process_group_snapshot *snapshot,
    continuum_remote_writable_vnode_info *entries,
    size_t entry_capacity,
    size_t *out_entry_count
) {
    if (snapshot == NULL || out_entry_count == NULL
        || (entries == NULL && entry_capacity != 0)) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    *out_entry_count = 0;
    size_t result_count = 0;

    for (size_t member_index = 0;
         member_index < snapshot->member_count;
         member_index += 1) {
        const continuum_remote_process_group_member *member =
            &snapshot->members[member_index];
        if (member->session == NULL) {
            return CONTINUUM_STATUS_INVALID_ARGUMENT;
        }
        const int32_t process_id = member->session->identity.process_id;
        int required_bytes = proc_pidinfo(
            process_id,
            PROC_PIDLISTFDS,
            0,
            NULL,
            0
        );
        if (required_bytes < 0) {
            return CONTINUUM_STATUS_MACH_ERROR;
        }
        size_t capacity = (size_t)required_bytes
            + 32U * sizeof(struct proc_fdinfo);
        if (capacity < sizeof(struct proc_fdinfo) || capacity > INT_MAX) {
            return CONTINUUM_STATUS_RANGE_ERROR;
        }
        struct proc_fdinfo *descriptors = calloc(1, capacity);
        if (descriptors == NULL) {
            return CONTINUUM_STATUS_OUT_OF_MEMORY;
        }
        int returned_bytes = proc_pidinfo(
            process_id,
            PROC_PIDLISTFDS,
            0,
            descriptors,
            (int)capacity
        );
        if (returned_bytes < 0
            || returned_bytes % (int)sizeof(struct proc_fdinfo) != 0) {
            free(descriptors);
            return CONTINUUM_STATUS_MACH_ERROR;
        }
        const size_t descriptor_count =
            (size_t)returned_bytes / sizeof(struct proc_fdinfo);
        qsort(
            descriptors,
            descriptor_count,
            sizeof(*descriptors),
            continuum_fd_info_compare
        );

        for (size_t descriptor_index = 0;
             descriptor_index < descriptor_count;
             descriptor_index += 1) {
            const struct proc_fdinfo descriptor = descriptors[descriptor_index];
            if (descriptor.proc_fdtype != PROX_FDTYPE_VNODE) {
                continue;
            }
            struct vnode_fdinfowithpath info;
            memset(&info, 0, sizeof(info));
            int bytes = proc_pidfdinfo(
                process_id,
                descriptor.proc_fd,
                PROC_PIDFDVNODEPATHINFO,
                &info,
                sizeof(info)
            );
            if (bytes != (int)sizeof(info)) {
                free(descriptors);
                return CONTINUUM_STATUS_MACH_ERROR;
            }
            const uint32_t open_flags = (uint32_t)info.pfi.fi_openflags;
            const uint32_t mode = info.pvip.vip_vi.vi_stat.vst_mode;
            if ((open_flags & O_ACCMODE) == O_RDONLY
                || (mode & S_IFMT) != S_IFREG
                || info.pvip.vip_path[0] == '\0') {
                continue;
            }

            if (entries != NULL) {
                if (result_count >= entry_capacity) {
                    free(descriptors);
                    return CONTINUUM_STATUS_RANGE_ERROR;
                }
                continuum_remote_writable_vnode_info *result =
                    &entries[result_count];
                memset(result, 0, sizeof(*result));
                result->process_id = process_id;
                result->file_descriptor = descriptor.proc_fd;
                result->open_flags = open_flags;
                result->offset = info.pfi.fi_offset;
                result->device = info.pvip.vip_vi.vi_stat.vst_dev;
                result->inode = info.pvip.vip_vi.vi_stat.vst_ino;
                result->byte_count = info.pvip.vip_vi.vi_stat.vst_size;
                result->mode = mode;
                (void)strlcpy(
                    result->path,
                    info.pvip.vip_path,
                    sizeof(result->path)
                );
            }
            result_count += 1;
        }
        free(descriptors);
    }

    *out_entry_count = result_count;
    return CONTINUUM_STATUS_OK;
}

static continuum_remote_pty_role continuum_pty_role_for_vnode(
    const struct vnode_fdinfowithpath *info
) {
    if (info == NULL
        || (info->pvip.vip_vi.vi_stat.vst_mode & S_IFMT) != S_IFCHR) {
        return CONTINUUM_REMOTE_PTY_ROLE_UNKNOWN;
    }
    if (strcmp(info->pvip.vip_path, "/dev/ptmx") == 0) {
        return CONTINUUM_REMOTE_PTY_ROLE_MASTER;
    }
    if (strncmp(info->pvip.vip_path, "/dev/ttys", 9) == 0
        && info->pvip.vip_path[9] != '\0') {
        return CONTINUUM_REMOTE_PTY_ROLE_SLAVE;
    }
    return CONTINUUM_REMOTE_PTY_ROLE_UNKNOWN;
}

static uint64_t continuum_pty_alias_identity(
    uint32_t tty_index,
    continuum_remote_pty_role role
) {
    uint64_t hash = CONTINUUM_FNV_OFFSET;
    continuum_hash_u64(&hash, UINT64_C(0x505459414C494153));
    continuum_hash_u64(&hash, tty_index);
    continuum_hash_u64(&hash, (uint64_t)role);
    return hash;
}

static void continuum_copy_pty_terminal_state(
    const char *observed_path,
    uint32_t tty_index,
    continuum_remote_pty_descriptor_info *result
) {
    if (result == NULL) {
        return;
    }
    char slave_path[64];
    const char *path = observed_path;
    if (result->role == CONTINUUM_REMOTE_PTY_ROLE_MASTER) {
        int length = snprintf(
            slave_path,
            sizeof(slave_path),
            "/dev/ttys%03x",
            tty_index
        );
        if (length <= 0 || (size_t)length >= sizeof(slave_path)) {
            return;
        }
        path = slave_path;
    }
    if (path == NULL || path[0] == '\0') {
        return;
    }

    struct stat status;
    memset(&status, 0, sizeof(status));
    if (stat(path, &status) != 0 || !S_ISCHR(status.st_mode)
        || (uint32_t)minor(status.st_rdev) != tty_index) {
        return;
    }
    int descriptor = open(
        path,
        O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC
    );
    if (descriptor < 0) {
        return;
    }
    struct termios attributes;
    memset(&attributes, 0, sizeof(attributes));
    if (tcgetattr(descriptor, &attributes) == 0) {
        result->terminal_attributes = attributes;
        result->terminal_attributes_known = 1;
    }
    struct winsize window_size;
    memset(&window_size, 0, sizeof(window_size));
    if (ioctl(descriptor, TIOCGWINSZ, &window_size) == 0) {
        result->window_size = window_size;
        result->window_size_known = 1;
    }
    close(descriptor);

    // libproc exposes remote vnode identity but no operation equivalent to
    // dup(2) for an arbitrary target fd. Opening the slave path can safely
    // read termios/winsize, but its queue ioctls do not identify which bytes
    // belong to the captured master/slave fileglob. Leave both counts unknown.
    result->input_queue_known = 0;
    result->output_queue_known = 0;
}

continuum_status continuum_remote_process_group_copy_pty_descriptors(
    const continuum_remote_process_group_snapshot *snapshot,
    continuum_remote_pty_descriptor_info *entries,
    size_t entry_capacity,
    size_t *out_entry_count
) {
    if (snapshot == NULL || out_entry_count == NULL
        || (entries == NULL && entry_capacity != 0)) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    *out_entry_count = 0;
    size_t result_count = 0;

    for (size_t member_index = 0;
         member_index < snapshot->member_count;
         member_index += 1) {
        const continuum_remote_process_group_member *member =
            &snapshot->members[member_index];
        if (member->session == NULL) {
            return CONTINUUM_STATUS_INVALID_ARGUMENT;
        }
        continuum_status status = continuum_validate_session_identity(
            member->session
        );
        if (status != CONTINUUM_STATUS_OK) {
            return status;
        }

        const int32_t process_id = member->session->identity.process_id;
        int required_bytes = proc_pidinfo(
            process_id,
            PROC_PIDLISTFDS,
            0,
            NULL,
            0
        );
        if (required_bytes < 0) {
            return CONTINUUM_STATUS_MACH_ERROR;
        }
        size_t capacity = (size_t)required_bytes
            + 32U * sizeof(struct proc_fdinfo);
        if (capacity < sizeof(struct proc_fdinfo) || capacity > INT_MAX) {
            return CONTINUUM_STATUS_RANGE_ERROR;
        }
        struct proc_fdinfo *descriptors = calloc(1, capacity);
        if (descriptors == NULL) {
            return CONTINUUM_STATUS_OUT_OF_MEMORY;
        }
        int returned_bytes = proc_pidinfo(
            process_id,
            PROC_PIDLISTFDS,
            0,
            descriptors,
            (int)capacity
        );
        if (returned_bytes < 0
            || returned_bytes % (int)sizeof(struct proc_fdinfo) != 0) {
            free(descriptors);
            return CONTINUUM_STATUS_MACH_ERROR;
        }
        const size_t descriptor_count =
            (size_t)returned_bytes / sizeof(struct proc_fdinfo);
        qsort(
            descriptors,
            descriptor_count,
            sizeof(*descriptors),
            continuum_fd_info_compare
        );

        for (size_t descriptor_index = 0;
             descriptor_index < descriptor_count;
             descriptor_index += 1) {
            const struct proc_fdinfo descriptor = descriptors[descriptor_index];
            if (descriptor.proc_fdtype != PROX_FDTYPE_VNODE) {
                continue;
            }
            struct vnode_fdinfowithpath info;
            memset(&info, 0, sizeof(info));
            int bytes = proc_pidfdinfo(
                process_id,
                descriptor.proc_fd,
                PROC_PIDFDVNODEPATHINFO,
                &info,
                sizeof(info)
            );
            if (bytes != (int)sizeof(info)) {
                free(descriptors);
                return CONTINUUM_STATUS_MACH_ERROR;
            }
            continuum_remote_pty_role role = continuum_pty_role_for_vnode(
                &info
            );
            if (role == CONTINUUM_REMOTE_PTY_ROLE_UNKNOWN) {
                continue;
            }

            if (entries != NULL && result_count >= entry_capacity) {
                free(descriptors);
                return CONTINUUM_STATUS_RANGE_ERROR;
            }
            if (entries != NULL) {
                continuum_remote_pty_descriptor_info *result =
                    &entries[result_count];
                memset(result, 0, sizeof(*result));
                const uint32_t raw_device =
                    info.pvip.vip_vi.vi_stat.vst_rdev;
                result->process_id = process_id;
                result->file_descriptor = descriptor.proc_fd;
                result->open_flags = info.pfi.fi_openflags;
                result->role = role;
                result->device = info.pvip.vip_vi.vi_stat.vst_dev;
                result->inode = info.pvip.vip_vi.vi_stat.vst_ino;
                result->raw_device = raw_device;
                result->device_major = (uint32_t)major(raw_device);
                result->device_minor = (uint32_t)minor(raw_device);
                result->tty_index = result->device_minor;
                result->alias_identity = continuum_pty_alias_identity(
                    result->tty_index,
                    role
                );
                continuum_copy_pty_terminal_state(
                    info.pvip.vip_path,
                    result->tty_index,
                    result
                );
            }
            result_count += 1;
        }
        free(descriptors);
    }

    *out_entry_count = result_count;
    return CONTINUUM_STATUS_OK;
}

static continuum_status continuum_copy_tcp_endpoint_address(
    const struct in_sockinfo *internet_info,
    int local,
    uint8_t destination[CONTINUUM_REMOTE_SOCKET_ADDRESS_MAX],
    uint32_t *out_length
) {
    if (internet_info == NULL || destination == NULL || out_length == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    memset(destination, 0, CONTINUUM_REMOTE_SOCKET_ADDRESS_MAX);
    *out_length = 0;

    if (internet_info->insi_vflag == INI_IPV4) {
        struct sockaddr_in address;
        memset(&address, 0, sizeof(address));
        address.sin_len = sizeof(address);
        address.sin_family = AF_INET;
        address.sin_port = (in_port_t)(local
            ? internet_info->insi_lport
            : internet_info->insi_fport);
        address.sin_addr = local
            ? internet_info->insi_laddr.ina_46.i46a_addr4
            : internet_info->insi_faddr.ina_46.i46a_addr4;
        if (sizeof(address) > CONTINUUM_REMOTE_SOCKET_ADDRESS_MAX) {
            return CONTINUUM_STATUS_RANGE_ERROR;
        }
        memcpy(destination, &address, sizeof(address));
        *out_length = (uint32_t)sizeof(address);
        return CONTINUUM_STATUS_OK;
    }

    if (internet_info->insi_vflag == INI_IPV6) {
        struct sockaddr_in6 address;
        memset(&address, 0, sizeof(address));
        address.sin6_len = sizeof(address);
        address.sin6_family = AF_INET6;
        address.sin6_port = (in_port_t)(local
            ? internet_info->insi_lport
            : internet_info->insi_fport);
        address.sin6_addr = local
            ? internet_info->insi_laddr.ina_6
            : internet_info->insi_faddr.ina_6;
        address.sin6_scope_id = internet_info->insi_v6.in6_ifindex;
        if (sizeof(address) > CONTINUUM_REMOTE_SOCKET_ADDRESS_MAX) {
            return CONTINUUM_STATUS_RANGE_ERROR;
        }
        memcpy(destination, &address, sizeof(address));
        *out_length = (uint32_t)sizeof(address);
        return CONTINUUM_STATUS_OK;
    }
    return CONTINUUM_STATUS_UNSUPPORTED_DESCRIPTOR;
}

continuum_status continuum_remote_process_group_copy_tcp_endpoints(
    const continuum_remote_process_group_snapshot *snapshot,
    continuum_remote_tcp_endpoint_info *entries,
    size_t entry_capacity,
    size_t *out_entry_count
) {
    if (snapshot == NULL || out_entry_count == NULL
        || (entries == NULL && entry_capacity != 0)) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    *out_entry_count = 0;
    size_t result_count = 0;

    for (size_t member_index = 0;
         member_index < snapshot->member_count;
         member_index += 1) {
        const continuum_remote_process_group_member *member =
            &snapshot->members[member_index];
        if (member->session == NULL) {
            return CONTINUUM_STATUS_INVALID_ARGUMENT;
        }
        continuum_status status = continuum_validate_session_identity(
            member->session
        );
        if (status != CONTINUUM_STATUS_OK) {
            return status;
        }

        const int32_t process_id = member->session->identity.process_id;
        int required_bytes = proc_pidinfo(
            process_id,
            PROC_PIDLISTFDS,
            0,
            NULL,
            0
        );
        if (required_bytes < 0) {
            return CONTINUUM_STATUS_MACH_ERROR;
        }
        size_t capacity = (size_t)required_bytes
            + 32U * sizeof(struct proc_fdinfo);
        if (capacity < sizeof(struct proc_fdinfo) || capacity > INT_MAX) {
            return CONTINUUM_STATUS_RANGE_ERROR;
        }
        struct proc_fdinfo *descriptors = calloc(1, capacity);
        if (descriptors == NULL) {
            return CONTINUUM_STATUS_OUT_OF_MEMORY;
        }
        int returned_bytes = proc_pidinfo(
            process_id,
            PROC_PIDLISTFDS,
            0,
            descriptors,
            (int)capacity
        );
        if (returned_bytes < 0
            || returned_bytes % (int)sizeof(struct proc_fdinfo) != 0) {
            free(descriptors);
            return CONTINUUM_STATUS_MACH_ERROR;
        }
        const size_t descriptor_count =
            (size_t)returned_bytes / sizeof(struct proc_fdinfo);
        qsort(
            descriptors,
            descriptor_count,
            sizeof(*descriptors),
            continuum_fd_info_compare
        );

        for (size_t descriptor_index = 0;
             descriptor_index < descriptor_count;
             descriptor_index += 1) {
            const struct proc_fdinfo descriptor = descriptors[descriptor_index];
            if (descriptor.proc_fdtype != PROX_FDTYPE_SOCKET) {
                continue;
            }
            struct socket_fdinfo info;
            memset(&info, 0, sizeof(info));
            int bytes = proc_pidfdinfo(
                process_id,
                descriptor.proc_fd,
                PROC_PIDFDSOCKETINFO,
                &info,
                sizeof(info)
            );
            if (bytes != (int)sizeof(info)) {
                free(descriptors);
                return CONTINUUM_STATUS_MACH_ERROR;
            }
            if (info.psi.soi_kind != SOCKINFO_TCP
                || info.psi.soi_type != SOCK_STREAM
                || info.psi.soi_protocol != IPPROTO_TCP
                || (info.psi.soi_family != AF_INET
                    && info.psi.soi_family != AF_INET6)
                || info.psi.soi_proto.pri_tcp.tcpsi_state
                    != TSI_S_ESTABLISHED) {
                continue;
            }

            if (entries != NULL && result_count >= entry_capacity) {
                free(descriptors);
                return CONTINUUM_STATUS_RANGE_ERROR;
            }
            if (entries != NULL) {
                continuum_remote_tcp_endpoint_info *result =
                    &entries[result_count];
                memset(result, 0, sizeof(*result));
                result->process_id = process_id;
                result->file_descriptor = descriptor.proc_fd;
                result->domain = info.psi.soi_family;
                result->socket_type = info.psi.soi_type;
                result->protocol = info.psi.soi_protocol;
                result->tcp_state = info.psi.soi_proto.pri_tcp.tcpsi_state;
                result->socket_state = (uint32_t)(uint16_t)info.psi.soi_state;
                result->receive_shutdown =
                    (info.psi.soi_state & SOI_S_CANTRCVMORE) != 0;
                result->send_shutdown =
                    (info.psi.soi_state & SOI_S_CANTSENDMORE) != 0;
                result->receive_queue_bytes = info.psi.soi_rcv.sbi_cc;
                result->send_queue_bytes = info.psi.soi_snd.sbi_cc;

                const struct in_sockinfo *internet_info =
                    &info.psi.soi_proto.pri_tcp.tcpsi_ini;
                status = continuum_copy_tcp_endpoint_address(
                    internet_info,
                    1,
                    result->local_address,
                    &result->local_address_length
                );
                if (status == CONTINUUM_STATUS_OK) {
                    status = continuum_copy_tcp_endpoint_address(
                        internet_info,
                        0,
                        result->remote_address,
                        &result->remote_address_length
                    );
                }
                if (status != CONTINUUM_STATUS_OK) {
                    free(descriptors);
                    return status;
                }
            }
            result_count += 1;
        }
        free(descriptors);
    }

    *out_entry_count = result_count;
    return CONTINUUM_STATUS_OK;
}

struct continuum_remote_descriptor_graph {
    continuum_remote_descriptor_handle_info *handles;
    size_t handle_count;
    continuum_remote_socket_resource_info *sockets;
    size_t socket_count;
    continuum_remote_pipe_resource_info *pipes;
    size_t pipe_count;
    continuum_remote_kqueue_resource_info *kqueues;
    size_t kqueue_count;
    continuum_remote_kqueue_registration_info *kqueue_registrations;
    size_t kqueue_registration_count;
};

static continuum_status continuum_descriptor_graph_append(
    void **storage,
    size_t *count,
    size_t element_size,
    const void *element
) {
    if (storage == NULL || count == NULL || element == NULL
        || element_size == 0 || *count == SIZE_MAX) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    if (*count > SIZE_MAX / element_size - 1) {
        return CONTINUUM_STATUS_RANGE_ERROR;
    }
    void *grown = realloc(*storage, (*count + 1) * element_size);
    if (grown == NULL) return CONTINUUM_STATUS_OUT_OF_MEMORY;
    *storage = grown;
    memcpy((uint8_t *)grown + *count * element_size, element, element_size);
    *count += 1;
    return CONTINUUM_STATUS_OK;
}

static ssize_t continuum_descriptor_socket_index(
    const continuum_remote_descriptor_graph *graph,
    uint64_t identity
) {
    if (graph == NULL || identity == 0) return -1;
    for (size_t index = 0; index < graph->socket_count; index += 1) {
        if (graph->sockets[index].resource_identity == identity) {
            return (ssize_t)index;
        }
    }
    return -1;
}

static ssize_t continuum_descriptor_pipe_index(
    const continuum_remote_descriptor_graph *graph,
    uint64_t identity
) {
    if (graph == NULL || identity == 0) return -1;
    for (size_t index = 0; index < graph->pipe_count; index += 1) {
        if (graph->pipes[index].resource_identity == identity) {
            return (ssize_t)index;
        }
    }
    return -1;
}

static uint64_t continuum_descriptor_kqueue_identity(
    int32_t process_id,
    int32_t file_descriptor
) {
    /* libproc intentionally hides the kqueue object pointer. This identity is
       stable for the frozen cut, but it does not claim that duplicated kqueue
       descriptors are independent resources. PROC_FP_SHARED is rejected below. */
    uint64_t identity = UINT64_C(0x4b51000000000000)
        ^ ((uint64_t)(uint32_t)process_id << 24)
        ^ (uint64_t)(uint32_t)file_descriptor;
    return identity == 0 ? 1 : identity;
}

static int continuum_descriptor_address_equal(
    const uint8_t *first,
    uint32_t first_length,
    const uint8_t *second,
    uint32_t second_length
) {
    return first_length == second_length
        && first_length <= CONTINUUM_REMOTE_DESCRIPTOR_ADDRESS_MAX
        && memcmp(first, second, first_length) == 0;
}

static continuum_status continuum_copy_unix_address(
    const struct sockaddr_un *address,
    uint8_t destination[CONTINUUM_REMOTE_DESCRIPTOR_ADDRESS_MAX],
    uint32_t *out_length
) {
    if (address == NULL || destination == NULL || out_length == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    memset(destination, 0, CONTINUUM_REMOTE_DESCRIPTOR_ADDRESS_MAX);
    *out_length = 0;
    if (address->sun_len == 0) return CONTINUUM_STATUS_OK;
    if (address->sun_family != AF_UNIX
        || address->sun_len > sizeof(*address)) {
        return CONTINUUM_STATUS_UNSUPPORTED_DESCRIPTOR;
    }
    memcpy(destination, address, address->sun_len);
    *out_length = address->sun_len;
    return CONTINUUM_STATUS_OK;
}

static int continuum_unix_address_has_path(
    const uint8_t bytes[CONTINUUM_REMOTE_DESCRIPTOR_ADDRESS_MAX],
    uint32_t length
) {
    if (length <= offsetof(struct sockaddr_un, sun_path)
        || length > sizeof(struct sockaddr_un)) {
        return 0;
    }
    const struct sockaddr_un *address =
        (const struct sockaddr_un *)(const void *)bytes;
    return address->sun_family == AF_UNIX && address->sun_path[0] != '\0';
}

static continuum_status continuum_descriptor_graph_add_handle(
    continuum_remote_descriptor_graph *graph,
    int32_t process_id,
    int32_t file_descriptor,
    int32_t status_flags,
    continuum_remote_descriptor_resource_kind kind,
    uint64_t identity
) {
    if (graph == NULL || identity == 0) {
        return CONTINUUM_STATUS_UNSUPPORTED_DESCRIPTOR;
    }
    continuum_remote_descriptor_handle_info handle;
    memset(&handle, 0, sizeof(handle));
    handle.resource_identity = identity;
    handle.process_id = process_id;
    handle.file_descriptor = file_descriptor;
    /* Remote libproc metadata does not expose an authenticated F_GETFD value. */
    handle.descriptor_flags = -1;
    handle.status_flags = status_flags;
    handle.resource_kind = kind;
    return continuum_descriptor_graph_append(
        (void **)&graph->handles,
        &graph->handle_count,
        sizeof(handle),
        &handle
    );
}

static continuum_status continuum_descriptor_graph_add_socket(
    continuum_remote_descriptor_graph *graph,
    int32_t process_id,
    int32_t file_descriptor,
    const struct socket_fdinfo *info
) {
    if (graph == NULL || info == NULL) return CONTINUUM_STATUS_INVALID_ARGUMENT;
    const struct socket_info *socket = &info->psi;
    if (socket->soi_so == 0 || socket->soi_type != SOCK_STREAM) {
        return CONTINUUM_STATUS_UNSUPPORTED_DESCRIPTOR;
    }

    continuum_remote_socket_resource_info resource;
    memset(&resource, 0, sizeof(resource));
    resource.resource_identity = socket->soi_so;
    resource.domain = socket->soi_family;
    resource.socket_type = socket->soi_type;
    resource.protocol = socket->soi_protocol;
    resource.socket_state = (uint32_t)(uint16_t)socket->soi_state;
    resource.receive_shutdown =
        (socket->soi_state & SOI_S_CANTRCVMORE) != 0;
    resource.send_shutdown =
        (socket->soi_state & SOI_S_CANTSENDMORE) != 0;
    resource.receive_queue_bytes = socket->soi_rcv.sbi_cc;
    resource.send_queue_bytes = socket->soi_snd.sbi_cc;
    resource.backlog = socket->soi_qlimit;

    continuum_status status = CONTINUUM_STATUS_OK;
    if ((socket->soi_family == AF_INET || socket->soi_family == AF_INET6)
        && socket->soi_kind == SOCKINFO_TCP
        && socket->soi_protocol == IPPROTO_TCP) {
        const struct tcp_sockinfo *tcp = &socket->soi_proto.pri_tcp;
        if (tcp->tcpsi_state == TSI_S_LISTEN) {
            if (socket->soi_qlen != 0 || socket->soi_incqlen != 0) {
                return CONTINUUM_STATUS_UNSUPPORTED_DESCRIPTOR;
            }
            resource.kind = CONTINUUM_REMOTE_SOCKET_TCP_LISTENER;
        } else if (tcp->tcpsi_state == TSI_S_ESTABLISHED) {
            resource.kind = CONTINUUM_REMOTE_SOCKET_TCP_CONNECTED;
        } else {
            return CONTINUUM_STATUS_UNSUPPORTED_DESCRIPTOR;
        }
        uint8_t address[CONTINUUM_REMOTE_SOCKET_ADDRESS_MAX];
        uint32_t length = 0;
        status = continuum_copy_tcp_endpoint_address(
            &tcp->tcpsi_ini, 1, address, &length
        );
        if (status == CONTINUUM_STATUS_OK) {
            memcpy(resource.local_address, address, length);
            resource.local_address_length = length;
        }
        if (status == CONTINUUM_STATUS_OK
            && resource.kind == CONTINUUM_REMOTE_SOCKET_TCP_CONNECTED) {
            status = continuum_copy_tcp_endpoint_address(
                &tcp->tcpsi_ini, 0, address, &length
            );
            if (status == CONTINUUM_STATUS_OK) {
                memcpy(resource.remote_address, address, length);
                resource.remote_address_length = length;
            }
        }
    } else if (socket->soi_family == AF_UNIX
               && socket->soi_kind == SOCKINFO_UN) {
        const struct un_sockinfo *unix_info = &socket->soi_proto.pri_un;
        if ((socket->soi_options & SO_ACCEPTCONN) != 0) {
            if (socket->soi_qlen != 0 || socket->soi_incqlen != 0) {
                return CONTINUUM_STATUS_UNSUPPORTED_DESCRIPTOR;
            }
            resource.kind = CONTINUUM_REMOTE_SOCKET_UNIX_LISTENER;
        } else if ((socket->soi_state & SOI_S_ISCONNECTED) != 0) {
            resource.kind = CONTINUUM_REMOTE_SOCKET_UNIX_CONNECTED;
            resource.peer_identity = unix_info->unsi_conn_so;
        } else {
            return CONTINUUM_STATUS_UNSUPPORTED_DESCRIPTOR;
        }
        status = continuum_copy_unix_address(
            &unix_info->unsi_addr.ua_sun,
            resource.local_address,
            &resource.local_address_length
        );
        if (status == CONTINUUM_STATUS_OK
            && resource.kind == CONTINUUM_REMOTE_SOCKET_UNIX_CONNECTED) {
            status = continuum_copy_unix_address(
                &unix_info->unsi_caddr.ua_sun,
                resource.remote_address,
                &resource.remote_address_length
            );
        }
    } else {
        return CONTINUUM_STATUS_UNSUPPORTED_DESCRIPTOR;
    }
    if (status != CONTINUUM_STATUS_OK) return status;

    const ssize_t existing = continuum_descriptor_socket_index(
        graph, resource.resource_identity
    );
    if (existing >= 0) {
        if (memcmp(&graph->sockets[existing], &resource, sizeof(resource)) != 0) {
            return CONTINUUM_STATUS_VALIDATION_FAILED;
        }
    } else {
        status = continuum_descriptor_graph_append(
            (void **)&graph->sockets,
            &graph->socket_count,
            sizeof(resource),
            &resource
        );
        if (status != CONTINUUM_STATUS_OK) return status;
    }
    return continuum_descriptor_graph_add_handle(
        graph,
        process_id,
        file_descriptor,
        (int32_t)info->pfi.fi_openflags,
        CONTINUUM_REMOTE_DESCRIPTOR_RESOURCE_SOCKET,
        resource.resource_identity
    );
}

static continuum_status continuum_descriptor_graph_add_pipe(
    continuum_remote_descriptor_graph *graph,
    int32_t process_id,
    int32_t file_descriptor,
    const struct pipe_fdinfo *info
) {
    if (graph == NULL || info == NULL
        || info->pipeinfo.pipe_handle == 0
        || info->pipeinfo.pipe_peerhandle == 0) {
        return CONTINUUM_STATUS_UNSUPPORTED_DESCRIPTOR;
    }
    continuum_remote_pipe_resource_info resource;
    memset(&resource, 0, sizeof(resource));
    resource.resource_identity = info->pipeinfo.pipe_handle;
    resource.peer_identity = info->pipeinfo.pipe_peerhandle;
    resource.capacity = info->pipeinfo.pipe_stat.vst_blksize;
    resource.queued_bytes = info->pipeinfo.pipe_stat.vst_size;
    resource.status = (uint32_t)info->pipeinfo.pipe_status;

    const ssize_t existing = continuum_descriptor_pipe_index(
        graph, resource.resource_identity
    );
    continuum_status status = CONTINUUM_STATUS_OK;
    if (existing >= 0) {
        if (memcmp(&graph->pipes[existing], &resource, sizeof(resource)) != 0) {
            return CONTINUUM_STATUS_VALIDATION_FAILED;
        }
    } else {
        status = continuum_descriptor_graph_append(
            (void **)&graph->pipes,
            &graph->pipe_count,
            sizeof(resource),
            &resource
        );
        if (status != CONTINUUM_STATUS_OK) return status;
    }
    return continuum_descriptor_graph_add_handle(
        graph,
        process_id,
        file_descriptor,
        (int32_t)info->pfi.fi_openflags,
        CONTINUUM_REMOTE_DESCRIPTOR_RESOURCE_PIPE,
        resource.resource_identity
    );
}

static continuum_status continuum_descriptor_graph_add_kqueue(
    continuum_remote_descriptor_graph *graph,
    int32_t process_id,
    int32_t file_descriptor,
    const struct kqueue_fdinfo *info
) {
    if (graph == NULL || info == NULL) return CONTINUUM_STATUS_INVALID_ARGUMENT;
    if ((info->kqueueinfo.kq_state & ~CONTINUUM_PROC_KQUEUE_SLEEP)
            != CONTINUUM_PROC_KQUEUE_KEV64
        || (info->pfi.fi_status & PROC_FP_SHARED) != 0) {
        return CONTINUUM_STATUS_UNSUPPORTED_DESCRIPTOR;
    }

    const uint64_t identity = continuum_descriptor_kqueue_identity(
        process_id, file_descriptor
    );
    int measured_count = proc_pidfdinfo(
        process_id,
        file_descriptor,
        CONTINUUM_PROC_PIDFDKQUEUE_EXTINFO,
        NULL,
        0
    );
    if (measured_count < 0) return CONTINUUM_STATUS_MACH_ERROR;
    const size_t registration_count = (size_t)measured_count;
    if (registration_count
        > (size_t)INT_MAX / sizeof(continuum_kevent_extinfo_private)) {
        return CONTINUUM_STATUS_RANGE_ERROR;
    }
    continuum_kevent_extinfo_private *registrations = NULL;
    if (registration_count != 0) {
        registrations = calloc(
            (size_t)registration_count, sizeof(*registrations)
        );
        if (registrations == NULL) return CONTINUUM_STATUS_OUT_OF_MEMORY;
        int returned_count = proc_pidfdinfo(
            process_id,
            file_descriptor,
            CONTINUUM_PROC_PIDFDKQUEUE_EXTINFO,
            registrations,
            (int)(registration_count
                * sizeof(continuum_kevent_extinfo_private))
        );
        if (returned_count != measured_count) {
            free(registrations);
            return returned_count < 0
                ? CONTINUUM_STATUS_MACH_ERROR
                : CONTINUUM_STATUS_VALIDATION_FAILED;
        }
    }

    continuum_remote_kqueue_resource_info resource;
    memset(&resource, 0, sizeof(resource));
    resource.resource_identity = identity;
    resource.process_id = process_id;
    resource.state = info->kqueueinfo.kq_state;
    resource.registration_start = graph->kqueue_registration_count;
    resource.registration_count = registration_count;

    continuum_status status = CONTINUUM_STATUS_OK;
    for (size_t index = 0; index < registration_count; index += 1) {
        const continuum_kevent_extinfo_private *raw = &registrations[index];
        const int16_t filter = raw->event.filter;
        if (filter != EVFILT_READ && filter != EVFILT_WRITE
            && filter != EVFILT_USER) {
            status = CONTINUUM_STATUS_UNSUPPORTED_DESCRIPTOR;
            break;
        }
        if (((uint32_t)raw->status & CONTINUUM_KNOTE_PENDING_MASK) != 0) {
            status = CONTINUUM_STATUS_UNSUPPORTED_DESCRIPTOR;
            break;
        }
        if (filter == EVFILT_USER
            && (((uint32_t)raw->status
                    & (CONTINUUM_KNOTE_ACTIVE | CONTINUUM_KNOTE_QUEUED)) != 0
                || (raw->event.fflags & NOTE_TRIGGER) != 0)) {
            status = CONTINUUM_STATUS_UNSUPPORTED_DESCRIPTOR;
            break;
        }
        continuum_remote_kqueue_registration_info registration;
        memset(&registration, 0, sizeof(registration));
        registration.resource_identity = identity;
        registration.ident = raw->event.ident;
        registration.filter = filter;
        registration.flags = raw->event.flags;
        registration.fflags = raw->event.fflags;
        registration.data = raw->event.data;
        registration.udata = raw->event.udata;
        registration.qos = raw->event.qos;
        registration.saved_data = (int64_t)raw->saved_data;
        registration.saved_fflags = (uint32_t)raw->saved_fflags;
        registration.status = (uint32_t)raw->status;
        status = continuum_descriptor_graph_append(
            (void **)&graph->kqueue_registrations,
            &graph->kqueue_registration_count,
            sizeof(registration),
            &registration
        );
        if (status != CONTINUUM_STATUS_OK) break;
    }
    free(registrations);
    if (status != CONTINUUM_STATUS_OK) return status;

    status = continuum_descriptor_graph_append(
        (void **)&graph->kqueues,
        &graph->kqueue_count,
        sizeof(resource),
        &resource
    );
    if (status != CONTINUUM_STATUS_OK) return status;
    return continuum_descriptor_graph_add_handle(
        graph,
        process_id,
        file_descriptor,
        (int32_t)info->pfi.fi_openflags,
        CONTINUUM_REMOTE_DESCRIPTOR_RESOURCE_KQUEUE,
        identity
    );
}

static continuum_status continuum_descriptor_graph_validate(
    continuum_remote_descriptor_graph *graph
) {
    if (graph == NULL) return CONTINUUM_STATUS_INVALID_ARGUMENT;
    for (size_t index = 0; index < graph->pipe_count; index += 1) {
        const continuum_remote_pipe_resource_info *pipe = &graph->pipes[index];
        if (pipe->queued_bytes != 0
            || continuum_descriptor_pipe_index(graph, pipe->peer_identity) < 0) {
            return CONTINUUM_STATUS_UNSUPPORTED_DESCRIPTOR;
        }
    }
    for (size_t index = 0; index < graph->socket_count; index += 1) {
        continuum_remote_socket_resource_info *socket = &graph->sockets[index];
        if (socket->receive_queue_bytes != 0 || socket->send_queue_bytes != 0) {
            return CONTINUUM_STATUS_UNSUPPORTED_DESCRIPTOR;
        }
        if (socket->kind == CONTINUUM_REMOTE_SOCKET_TCP_CONNECTED) {
            ssize_t peer = -1;
            for (size_t candidate = 0; candidate < graph->socket_count; candidate += 1) {
                if (candidate == index) continue;
                const continuum_remote_socket_resource_info *other =
                    &graph->sockets[candidate];
                if (other->kind == CONTINUUM_REMOTE_SOCKET_TCP_CONNECTED
                    && other->domain == socket->domain
                    && continuum_descriptor_address_equal(
                        socket->local_address, socket->local_address_length,
                        other->remote_address, other->remote_address_length
                    )
                    && continuum_descriptor_address_equal(
                        socket->remote_address, socket->remote_address_length,
                        other->local_address, other->local_address_length
                    )) {
                    if (peer >= 0) return CONTINUUM_STATUS_UNSUPPORTED_DESCRIPTOR;
                    peer = (ssize_t)candidate;
                }
            }
            if (peer < 0) return CONTINUUM_STATUS_UNSUPPORTED_DESCRIPTOR;
            socket->peer_identity = graph->sockets[peer].resource_identity;
        } else if (socket->kind == CONTINUUM_REMOTE_SOCKET_UNIX_CONNECTED) {
            if (continuum_descriptor_socket_index(graph, socket->peer_identity) < 0) {
                const int externally_reconnectable =
                    socket->local_address_length == 0
                    && continuum_unix_address_has_path(
                        socket->remote_address, socket->remote_address_length
                    );
                if (!externally_reconnectable) {
                    return CONTINUUM_STATUS_UNSUPPORTED_DESCRIPTOR;
                }
                socket->peer_identity = 0;
            }
        }
    }
    return CONTINUUM_STATUS_OK;
}

static continuum_status continuum_descriptor_graph_merge_bootstrap_flags(
    const continuum_remote_process_group_snapshot *snapshot,
    const char *bootstrap_library_path,
    continuum_remote_descriptor_graph *graph
) {
    continuum_bootstrap_identity identity;
    continuum_status status = continuum_inspect_local_bootstrap_library(
        bootstrap_library_path,
        &identity
    );
    if (status != CONTINUUM_STATUS_OK
        || identity.pty_safepoint_status_offset == 0
        || identity.descriptor_safepoint_status_offset == 0) {
        return status == CONTINUUM_STATUS_OK
            ? CONTINUUM_STATUS_VALIDATION_FAILED
            : status;
    }

    continuum_bootstrap_descriptor_safepoint_wire_status *descriptor_report =
        calloc(1, sizeof(*descriptor_report));
    if (descriptor_report == NULL) return CONTINUUM_STATUS_OUT_OF_MEMORY;
    for (size_t member_index = 0;
         member_index < snapshot->member_count;
         member_index += 1) {
        const continuum_remote_process_group_member *member =
            &snapshot->members[member_index];
        if (member->session == NULL || member->snapshot == NULL
            || member->snapshot->threads == NULL) {
            status = CONTINUUM_STATUS_INVALID_ARGUMENT;
            break;
        }
        status = continuum_validate_session_identity(member->session);
        if (status != CONTINUUM_STATUS_OK) break;

        mach_vm_address_t image_base = 0;
        status = continuum_find_authenticated_bootstrap_base(
            member->session,
            bootstrap_library_path,
            identity.image_uuid,
            &image_base
        );
        uint64_t pty_address = 0;
        uint64_t descriptor_address = 0;
        if (status == CONTINUUM_STATUS_OK
            && (!continuum_add_u64(
                    image_base,
                    identity.pty_safepoint_status_offset,
                    &pty_address
                )
                || !continuum_add_u64(
                    image_base,
                    identity.descriptor_safepoint_status_offset,
                    &descriptor_address
                ))) {
            status = CONTINUUM_STATUS_RANGE_ERROR;
        }
        if (status != CONTINUUM_STATUS_OK) break;

        continuum_bootstrap_pty_safepoint_wire_status pty_report;
        memset(&pty_report, 0, sizeof(pty_report));
        memset(descriptor_report, 0, sizeof(*descriptor_report));
        status = continuum_read_task_bytes(
            member->session->task,
            pty_address,
            sizeof(pty_report),
            &pty_report
        );
        if (status == CONTINUUM_STATUS_OK) {
            status = continuum_read_task_bytes(
                member->session->task,
                descriptor_address,
                sizeof(*descriptor_report),
                descriptor_report
            );
        }
        if (status != CONTINUUM_STATUS_OK) break;
        if (getenv("CONTINUUM_CAPTURE_TRACE") != NULL) {
            fprintf(
                stderr,
                "continuum descriptor pid=%d pty-gen=%llu desc-gen=%llu pty-active=%u desc-active=%u desc-count=%u\n",
                member->session->identity.process_id,
                (unsigned long long)pty_report.generation,
                (unsigned long long)descriptor_report->generation,
                pty_report.safepoint_active,
                descriptor_report->safepoint_active,
                descriptor_report->descriptor_count
            );
        }
        if (pty_report.magic != CONTINUUM_BOOTSTRAP_PTY_STATUS_MAGIC
            || pty_report.version != 2
            || pty_report.structure_size != sizeof(pty_report)
            || pty_report.generation == 0
            || pty_report.safepoint_thread_identifier == 0
            || pty_report.safepoint_active != 1
            || descriptor_report->magic
                != CONTINUUM_BOOTSTRAP_DESCRIPTOR_STATUS_MAGIC
            || descriptor_report->version != 1
            || descriptor_report->structure_size != sizeof(*descriptor_report)
            || descriptor_report->generation != pty_report.generation
            || descriptor_report->descriptor_count
                > CONTINUUM_BOOTSTRAP_DESCRIPTOR_STATUS_LIMIT
            || descriptor_report->overflow != 0
            || descriptor_report->safepoint_active != 1) {
            status = CONTINUUM_STATUS_VALIDATION_FAILED;
            break;
        }

        size_t matching_safepoint_threads = 0;
        for (size_t thread_index = 0;
             thread_index < member->snapshot->threads->count;
             thread_index += 1) {
            if (member->snapshot->threads->entries[thread_index].identifier
                == pty_report.safepoint_thread_identifier) {
                matching_safepoint_threads += 1;
            }
        }
        if (matching_safepoint_threads != 1) {
            status = CONTINUUM_STATUS_VALIDATION_FAILED;
            break;
        }

        const int32_t process_id = member->session->identity.process_id;
        size_t expected_count = 0;
        for (size_t index = 0; index < graph->handle_count; index += 1) {
            if (graph->handles[index].process_id == process_id) {
                graph->handles[index].descriptor_flags = -1;
                expected_count += 1;
            }
        }
        if (expected_count != descriptor_report->descriptor_count) {
            if (getenv("CONTINUUM_CAPTURE_TRACE") != NULL) {
                fprintf(
                    stderr,
                    "continuum descriptor pid=%d expected-count=%zu report-count=%u\n",
                    process_id,
                    expected_count,
                    descriptor_report->descriptor_count
                );
            }
            status = CONTINUUM_STATUS_VALIDATION_FAILED;
            break;
        }
        for (uint32_t entry_index = 0;
             entry_index < descriptor_report->descriptor_count;
             entry_index += 1) {
            const continuum_bootstrap_descriptor_status_wire_entry *entry =
                &descriptor_report->descriptors[entry_index];
            if (getenv("CONTINUUM_CAPTURE_TRACE") != NULL) {
                fprintf(
                    stderr,
                    "continuum descriptor pid=%d fd=%d fd-flags=%d status-flags=%d kind=%u\n",
                    process_id,
                    entry->file_descriptor,
                    entry->descriptor_flags,
                    entry->status_flags,
                    entry->kind
                );
            }
            continuum_remote_descriptor_handle_info *match = NULL;
            if (entry->file_descriptor < 0 || entry->descriptor_flags < 0
                || entry->status_flags < 0
                || entry->kind < CONTINUUM_REMOTE_DESCRIPTOR_RESOURCE_SOCKET
                || entry->kind > CONTINUUM_REMOTE_DESCRIPTOR_RESOURCE_KQUEUE) {
                status = CONTINUUM_STATUS_VALIDATION_FAILED;
                break;
            }
            for (size_t handle_index = 0;
                 handle_index < graph->handle_count;
                 handle_index += 1) {
                continuum_remote_descriptor_handle_info *candidate =
                    &graph->handles[handle_index];
                if (candidate->process_id == process_id
                    && candidate->file_descriptor == entry->file_descriptor) {
                    if (match != NULL
                        || (uint32_t)candidate->resource_kind != entry->kind) {
                        status = CONTINUUM_STATUS_VALIDATION_FAILED;
                        break;
                    }
                    match = candidate;
                }
            }
            if (status != CONTINUUM_STATUS_OK) break;
            if (match == NULL || match->descriptor_flags >= 0) {
                status = CONTINUUM_STATUS_VALIDATION_FAILED;
                break;
            }
            match->descriptor_flags = entry->descriptor_flags;
            match->status_flags = entry->status_flags;
        }
        if (status != CONTINUUM_STATUS_OK) break;
        for (size_t index = 0; index < graph->handle_count; index += 1) {
            if (graph->handles[index].process_id == process_id
                && graph->handles[index].descriptor_flags < 0) {
                status = CONTINUUM_STATUS_VALIDATION_FAILED;
                break;
            }
        }
        if (status != CONTINUUM_STATUS_OK) break;
    }
    free(descriptor_report);
    return status;
}

static continuum_status continuum_capture_descriptor_graph_internal(
    const continuum_remote_process_group_snapshot *snapshot,
    const char *bootstrap_library_path,
    continuum_remote_descriptor_graph **out_graph
) {
    if (snapshot == NULL || out_graph == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    *out_graph = NULL;
    continuum_remote_descriptor_graph *graph = calloc(1, sizeof(*graph));
    if (graph == NULL) return CONTINUUM_STATUS_OUT_OF_MEMORY;
    continuum_status status = CONTINUUM_STATUS_OK;

    for (size_t member_index = 0;
         member_index < snapshot->member_count && status == CONTINUUM_STATUS_OK;
         member_index += 1) {
        const continuum_remote_process_group_member *member =
            &snapshot->members[member_index];
        if (member->session == NULL) {
            status = CONTINUUM_STATUS_INVALID_ARGUMENT;
            break;
        }
        status = continuum_validate_session_identity(member->session);
        if (status != CONTINUUM_STATUS_OK) break;
        const int32_t process_id = member->session->identity.process_id;

        int required_bytes = proc_pidinfo(
            process_id, PROC_PIDLISTFDS, 0, NULL, 0
        );
        if (required_bytes < 0) {
            status = CONTINUUM_STATUS_MACH_ERROR;
            break;
        }
        size_t capacity = (size_t)required_bytes
            + 32U * sizeof(struct proc_fdinfo);
        if (capacity < sizeof(struct proc_fdinfo) || capacity > INT_MAX) {
            status = CONTINUUM_STATUS_RANGE_ERROR;
            break;
        }
        struct proc_fdinfo *descriptors = calloc(1, capacity);
        if (descriptors == NULL) {
            status = CONTINUUM_STATUS_OUT_OF_MEMORY;
            break;
        }
        int returned_bytes = proc_pidinfo(
            process_id,
            PROC_PIDLISTFDS,
            0,
            descriptors,
            (int)capacity
        );
        if (returned_bytes < 0
            || returned_bytes % (int)sizeof(struct proc_fdinfo) != 0) {
            free(descriptors);
            status = CONTINUUM_STATUS_MACH_ERROR;
            break;
        }
        const size_t descriptor_count =
            (size_t)returned_bytes / sizeof(struct proc_fdinfo);
        qsort(
            descriptors,
            descriptor_count,
            sizeof(*descriptors),
            continuum_fd_info_compare
        );
        for (size_t descriptor_index = 0;
             descriptor_index < descriptor_count;
             descriptor_index += 1) {
            const struct proc_fdinfo descriptor = descriptors[descriptor_index];
            if (descriptor.proc_fdtype == PROX_FDTYPE_SOCKET) {
                struct socket_fdinfo info;
                memset(&info, 0, sizeof(info));
                int bytes = proc_pidfdinfo(
                    process_id,
                    descriptor.proc_fd,
                    PROC_PIDFDSOCKETINFO,
                    &info,
                    sizeof(info)
                );
                if (bytes != (int)sizeof(info)) {
                    status = CONTINUUM_STATUS_MACH_ERROR;
                    break;
                }
                status = continuum_descriptor_graph_add_socket(
                    graph, process_id, descriptor.proc_fd, &info
                );
            } else if (descriptor.proc_fdtype == PROX_FDTYPE_PIPE) {
                struct pipe_fdinfo info;
                memset(&info, 0, sizeof(info));
                int bytes = proc_pidfdinfo(
                    process_id,
                    descriptor.proc_fd,
                    PROC_PIDFDPIPEINFO,
                    &info,
                    sizeof(info)
                );
                if (bytes != (int)sizeof(info)) {
                    status = CONTINUUM_STATUS_MACH_ERROR;
                    break;
                }
                status = continuum_descriptor_graph_add_pipe(
                    graph, process_id, descriptor.proc_fd, &info
                );
            } else if (descriptor.proc_fdtype == PROX_FDTYPE_KQUEUE) {
                struct kqueue_fdinfo info;
                memset(&info, 0, sizeof(info));
                int bytes = proc_pidfdinfo(
                    process_id,
                    descriptor.proc_fd,
                    PROC_PIDFDKQUEUEINFO,
                    &info,
                    sizeof(info)
                );
                if (bytes != (int)sizeof(info)) {
                    status = CONTINUUM_STATUS_MACH_ERROR;
                    break;
                }
                status = continuum_descriptor_graph_add_kqueue(
                    graph, process_id, descriptor.proc_fd, &info
                );
            }
            if (status != CONTINUUM_STATUS_OK) break;
        }
        free(descriptors);
    }
    if (status == CONTINUUM_STATUS_OK && bootstrap_library_path != NULL) {
        status = continuum_descriptor_graph_merge_bootstrap_flags(
            snapshot,
            bootstrap_library_path,
            graph
        );
        if (getenv("CONTINUUM_CAPTURE_TRACE") != NULL) {
            fprintf(
                stderr,
                "continuum descriptor phase=merge status=%d handles=%zu pipes=%zu\n",
                status,
                graph->handle_count,
                graph->pipe_count
            );
        }
    }
    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_descriptor_graph_validate(graph);
    }
    if (status != CONTINUUM_STATUS_OK) {
        continuum_remote_descriptor_graph_destroy(graph);
        return status;
    }
    *out_graph = graph;
    return CONTINUUM_STATUS_OK;
}

continuum_status continuum_remote_process_group_capture_descriptor_graph(
    const continuum_remote_process_group_snapshot *snapshot,
    continuum_remote_descriptor_graph **out_graph
) {
    return continuum_capture_descriptor_graph_internal(snapshot, NULL, out_graph);
}

continuum_status
continuum_remote_process_group_capture_descriptor_graph_authenticated(
    const continuum_remote_process_group_snapshot *snapshot,
    const char *bootstrap_library_path,
    continuum_remote_descriptor_graph **out_graph
) {
    if (bootstrap_library_path == NULL || bootstrap_library_path[0] == '\0') {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    return continuum_capture_descriptor_graph_internal(
        snapshot,
        bootstrap_library_path,
        out_graph
    );
}

size_t continuum_remote_descriptor_graph_handle_count(
    const continuum_remote_descriptor_graph *graph
) {
    return graph == NULL ? 0 : graph->handle_count;
}

size_t continuum_remote_descriptor_graph_socket_count(
    const continuum_remote_descriptor_graph *graph
) {
    return graph == NULL ? 0 : graph->socket_count;
}

size_t continuum_remote_descriptor_graph_pipe_count(
    const continuum_remote_descriptor_graph *graph
) {
    return graph == NULL ? 0 : graph->pipe_count;
}

size_t continuum_remote_descriptor_graph_kqueue_count(
    const continuum_remote_descriptor_graph *graph
) {
    return graph == NULL ? 0 : graph->kqueue_count;
}

size_t continuum_remote_descriptor_graph_kqueue_registration_count(
    const continuum_remote_descriptor_graph *graph
) {
    return graph == NULL ? 0 : graph->kqueue_registration_count;
}

continuum_status continuum_remote_descriptor_graph_copy_handles(
    const continuum_remote_descriptor_graph *graph,
    continuum_remote_descriptor_handle_info *entries,
    size_t entry_capacity
) {
    if (graph == NULL || (entries == NULL && entry_capacity != 0)) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    if (entry_capacity < graph->handle_count) return CONTINUUM_STATUS_RANGE_ERROR;
    if (graph->handle_count != 0) {
        memcpy(entries, graph->handles, graph->handle_count * sizeof(*entries));
    }
    return CONTINUUM_STATUS_OK;
}

continuum_status continuum_remote_descriptor_graph_copy_sockets(
    const continuum_remote_descriptor_graph *graph,
    continuum_remote_socket_resource_info *entries,
    size_t entry_capacity
) {
    if (graph == NULL || (entries == NULL && entry_capacity != 0)) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    if (entry_capacity < graph->socket_count) return CONTINUUM_STATUS_RANGE_ERROR;
    if (graph->socket_count != 0) {
        memcpy(entries, graph->sockets, graph->socket_count * sizeof(*entries));
    }
    return CONTINUUM_STATUS_OK;
}

continuum_status continuum_remote_descriptor_graph_copy_pipes(
    const continuum_remote_descriptor_graph *graph,
    continuum_remote_pipe_resource_info *entries,
    size_t entry_capacity
) {
    if (graph == NULL || (entries == NULL && entry_capacity != 0)) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    if (entry_capacity < graph->pipe_count) return CONTINUUM_STATUS_RANGE_ERROR;
    if (graph->pipe_count != 0) {
        memcpy(entries, graph->pipes, graph->pipe_count * sizeof(*entries));
    }
    return CONTINUUM_STATUS_OK;
}

continuum_status continuum_remote_descriptor_graph_copy_kqueues(
    const continuum_remote_descriptor_graph *graph,
    continuum_remote_kqueue_resource_info *entries,
    size_t entry_capacity
) {
    if (graph == NULL || (entries == NULL && entry_capacity != 0)) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    if (entry_capacity < graph->kqueue_count) return CONTINUUM_STATUS_RANGE_ERROR;
    if (graph->kqueue_count != 0) {
        memcpy(entries, graph->kqueues, graph->kqueue_count * sizeof(*entries));
    }
    return CONTINUUM_STATUS_OK;
}

continuum_status continuum_remote_descriptor_graph_copy_kqueue_registrations(
    const continuum_remote_descriptor_graph *graph,
    continuum_remote_kqueue_registration_info *entries,
    size_t entry_capacity
) {
    if (graph == NULL || (entries == NULL && entry_capacity != 0)) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    if (entry_capacity < graph->kqueue_registration_count) {
        return CONTINUUM_STATUS_RANGE_ERROR;
    }
    if (graph->kqueue_registration_count != 0) {
        memcpy(
            entries,
            graph->kqueue_registrations,
            graph->kqueue_registration_count * sizeof(*entries)
        );
    }
    return CONTINUUM_STATUS_OK;
}

void continuum_remote_descriptor_graph_destroy(
    continuum_remote_descriptor_graph *graph
) {
    if (graph == NULL) return;
    free(graph->handles);
    free(graph->sockets);
    free(graph->pipes);
    free(graph->kqueues);
    free(graph->kqueue_registrations);
    free(graph);
}

static int continuum_saved_tcp_address_is_valid(
    const uint8_t bytes[CONTINUUM_REMOTE_SOCKET_ADDRESS_MAX],
    uint32_t length,
    int32_t domain
) {
    if (bytes == NULL) {
        return 0;
    }
    if (domain == AF_INET) {
        if (length != sizeof(struct sockaddr_in)) {
            return 0;
        }
        const struct sockaddr_in *address =
            (const struct sockaddr_in *)(const void *)bytes;
        return address->sin_len == sizeof(*address)
            && address->sin_family == AF_INET;
    }
    if (domain == AF_INET6) {
        if (length != sizeof(struct sockaddr_in6)) {
            return 0;
        }
        const struct sockaddr_in6 *address =
            (const struct sockaddr_in6 *)(const void *)bytes;
        return address->sin6_len == sizeof(*address)
            && address->sin6_family == AF_INET6;
    }
    return 0;
}

static int continuum_saved_tcp_address_is_loopback(
    const uint8_t bytes[CONTINUUM_REMOTE_SOCKET_ADDRESS_MAX],
    int32_t domain
) {
    if (domain == AF_INET) {
        const struct sockaddr_in *address =
            (const struct sockaddr_in *)(const void *)bytes;
        return IN_LOOPBACK(ntohl(address->sin_addr.s_addr));
    }
    if (domain == AF_INET6) {
        const struct sockaddr_in6 *address =
            (const struct sockaddr_in6 *)(const void *)bytes;
        return IN6_IS_ADDR_LOOPBACK(&address->sin6_addr);
    }
    return 0;
}

static int continuum_tcp_address_matches(
    const struct sockaddr_storage *observed,
    socklen_t observed_length,
    const uint8_t expected[CONTINUUM_REMOTE_SOCKET_ADDRESS_MAX],
    uint32_t expected_length
) {
    return observed != NULL && expected != NULL
        && observed_length == expected_length
        && memcmp(observed, expected, expected_length) == 0;
}

static int continuum_process_is_absent(int32_t process_id) {
    errno = 0;
    if (kill(process_id, 0) == 0) {
        return 0;
    }
    return errno == ESRCH;
}

static int continuum_apply_tcp_half_shutdowns(
    int descriptor,
    const continuum_remote_tcp_endpoint_info *endpoint
) {
    if (endpoint->receive_shutdown && endpoint->send_shutdown) {
        return shutdown(descriptor, SHUT_RDWR);
    }
    if (endpoint->receive_shutdown
        && shutdown(descriptor, SHUT_RD) != 0) {
        return -1;
    }
    if (endpoint->send_shutdown
        && shutdown(descriptor, SHUT_WR) != 0) {
        return -1;
    }
    return 0;
}

static void continuum_make_tcp_address_ephemeral(
    uint8_t address[CONTINUUM_REMOTE_SOCKET_ADDRESS_MAX],
    int32_t domain
) {
    if (domain == AF_INET) {
        ((struct sockaddr_in *)(void *)address)->sin_port = 0;
    } else {
        ((struct sockaddr_in6 *)(void *)address)->sin6_port = 0;
    }
}

static int continuum_create_loopback_tcp_pair(
    const continuum_remote_tcp_endpoint_info *first_endpoint,
    const continuum_remote_tcp_endpoint_info *second_endpoint,
    int preserve_saved_ports,
    int32_t *out_first_descriptor,
    int32_t *out_second_descriptor,
    int *out_error
) {
    int listener = -1;
    int client = -1;
    int accepted = -1;
    int success = 0;
    int reuse_address = 1;
    uint8_t listener_address[CONTINUUM_REMOTE_SOCKET_ADDRESS_MAX];
    uint8_t client_address[CONTINUUM_REMOTE_SOCKET_ADDRESS_MAX];
    memcpy(
        listener_address,
        first_endpoint->local_address,
        sizeof(listener_address)
    );
    memcpy(
        client_address,
        second_endpoint->local_address,
        sizeof(client_address)
    );
    if (!preserve_saved_ports) {
        continuum_make_tcp_address_ephemeral(
            listener_address,
            first_endpoint->domain
        );
        continuum_make_tcp_address_ephemeral(
            client_address,
            second_endpoint->domain
        );
    }
    *out_error = 0;

    listener = socket(
        first_endpoint->domain,
        first_endpoint->socket_type,
        first_endpoint->protocol
    );
    if (listener < 0) {
        *out_error = errno;
        goto cleanup;
    }
    client = socket(
        second_endpoint->domain,
        second_endpoint->socket_type,
        second_endpoint->protocol
    );
    if (client < 0
        || fcntl(listener, F_SETFD, FD_CLOEXEC) != 0
        || fcntl(client, F_SETFD, FD_CLOEXEC) != 0
        || setsockopt(
            listener,
            SOL_SOCKET,
            SO_REUSEADDR,
            &reuse_address,
            sizeof(reuse_address)
        ) != 0
        || setsockopt(
            client,
            SOL_SOCKET,
            SO_REUSEADDR,
            &reuse_address,
            sizeof(reuse_address)
        ) != 0
        || setsockopt(
            listener,
            SOL_SOCKET,
            SO_REUSEPORT,
            &reuse_address,
            sizeof(reuse_address)
        ) != 0
        || setsockopt(
            client,
            SOL_SOCKET,
            SO_REUSEPORT,
            &reuse_address,
            sizeof(reuse_address)
        ) != 0
        || bind(
            listener,
            (const struct sockaddr *)(const void *)listener_address,
            (socklen_t)first_endpoint->local_address_length
        ) != 0
        || listen(listener, 1) != 0) {
        *out_error = errno;
        goto cleanup;
    }

    struct sockaddr_storage listener_bound_address;
    memset(&listener_bound_address, 0, sizeof(listener_bound_address));
    socklen_t listener_bound_length = sizeof(listener_bound_address);
    if (getsockname(
            listener,
            (struct sockaddr *)&listener_bound_address,
            &listener_bound_length
        ) != 0
        || bind(
            client,
            (const struct sockaddr *)(const void *)client_address,
            (socklen_t)second_endpoint->local_address_length
        ) != 0
        || connect(
            client,
            (const struct sockaddr *)&listener_bound_address,
            listener_bound_length
        ) != 0) {
        *out_error = errno;
        goto cleanup;
    }
    accepted = accept(listener, NULL, NULL);
    if (accepted < 0 || fcntl(accepted, F_SETFD, FD_CLOEXEC) != 0) {
        *out_error = errno;
        goto cleanup;
    }

    struct sockaddr_storage first_local;
    struct sockaddr_storage first_peer;
    struct sockaddr_storage second_local;
    struct sockaddr_storage second_peer;
    memset(&first_local, 0, sizeof(first_local));
    memset(&first_peer, 0, sizeof(first_peer));
    memset(&second_local, 0, sizeof(second_local));
    memset(&second_peer, 0, sizeof(second_peer));
    socklen_t first_local_length = sizeof(first_local);
    socklen_t first_peer_length = sizeof(first_peer);
    socklen_t second_local_length = sizeof(second_local);
    socklen_t second_peer_length = sizeof(second_peer);
    if (getsockname(
            accepted,
            (struct sockaddr *)&first_local,
            &first_local_length
        ) != 0
        || getpeername(
            accepted,
            (struct sockaddr *)&first_peer,
            &first_peer_length
        ) != 0
        || getsockname(
            client,
            (struct sockaddr *)&second_local,
            &second_local_length
        ) != 0
        || getpeername(
            client,
            (struct sockaddr *)&second_peer,
            &second_peer_length
        ) != 0) {
        *out_error = errno;
        goto cleanup;
    }

    if (preserve_saved_ports) {
        if (!continuum_tcp_address_matches(
                &first_local,
                first_local_length,
                first_endpoint->local_address,
                first_endpoint->local_address_length
            )
            || !continuum_tcp_address_matches(
                &first_peer,
                first_peer_length,
                first_endpoint->remote_address,
                first_endpoint->remote_address_length
            )
            || !continuum_tcp_address_matches(
                &second_local,
                second_local_length,
                second_endpoint->local_address,
                second_endpoint->local_address_length
            )
            || !continuum_tcp_address_matches(
                &second_peer,
                second_peer_length,
                second_endpoint->remote_address,
                second_endpoint->remote_address_length
            )) {
            *out_error = EINVAL;
            goto cleanup;
        }
    } else if (first_local_length != second_peer_length
        || first_peer_length != second_local_length
        || memcmp(&first_local, &second_peer, first_local_length) != 0
        || memcmp(&first_peer, &second_local, first_peer_length) != 0) {
        *out_error = EINVAL;
        goto cleanup;
    }

    if (continuum_apply_tcp_half_shutdowns(accepted, first_endpoint) != 0
        || continuum_apply_tcp_half_shutdowns(client, second_endpoint) != 0) {
        *out_error = errno;
        goto cleanup;
    }

    *out_first_descriptor = accepted;
    *out_second_descriptor = client;
    accepted = -1;
    client = -1;
    success = 1;

cleanup:
    if (accepted >= 0) {
        close(accepted);
    }
    if (client >= 0) {
        close(client);
    }
    if (listener >= 0) {
        close(listener);
    }
    return success;
}

continuum_status continuum_recreate_closed_empty_pipe_pair(
    const continuum_remote_pipe_resource_info *first_resource,
    const continuum_remote_pipe_resource_info *second_resource,
    int32_t *out_first_descriptor,
    int32_t *out_second_descriptor
) {
    if (first_resource == NULL || second_resource == NULL
        || first_resource == second_resource
        || out_first_descriptor == NULL || out_second_descriptor == NULL
        || out_first_descriptor == out_second_descriptor) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    *out_first_descriptor = -1;
    *out_second_descriptor = -1;

    if (first_resource->resource_identity == 0
        || second_resource->resource_identity == 0
        || first_resource->resource_identity
            == second_resource->resource_identity
        || first_resource->peer_identity
            != second_resource->resource_identity
        || second_resource->peer_identity
            != first_resource->resource_identity
        || first_resource->queued_bytes != 0
        || second_resource->queued_bytes != 0
        || first_resource->capacity == 0
        || first_resource->capacity != second_resource->capacity) {
        return CONTINUUM_STATUS_VALIDATION_FAILED;
    }

    int descriptors[2] = {-1, -1};
    struct stat first_stat;
    struct stat second_stat;
    continuum_status status = CONTINUUM_STATUS_VALIDATION_FAILED;
    if (pipe(descriptors) != 0
        || fcntl(descriptors[0], F_SETFD, FD_CLOEXEC) != 0
        || fcntl(descriptors[1], F_SETFD, FD_CLOEXEC) != 0
        || fstat(descriptors[0], &first_stat) != 0
        || fstat(descriptors[1], &second_stat) != 0) {
        status = CONTINUUM_STATUS_MACH_ERROR;
        goto cleanup;
    }
    if (!S_ISFIFO(first_stat.st_mode) || !S_ISFIFO(second_stat.st_mode)
        || first_stat.st_blksize <= 0 || second_stat.st_blksize <= 0
        || (uint64_t)first_stat.st_blksize != first_resource->capacity
        || (uint64_t)second_stat.st_blksize != second_resource->capacity) {
        goto cleanup;
    }

    *out_first_descriptor = descriptors[0];
    *out_second_descriptor = descriptors[1];
    descriptors[0] = -1;
    descriptors[1] = -1;
    status = CONTINUUM_STATUS_OK;

cleanup:
    if (descriptors[0] >= 0) {
        close(descriptors[0]);
    }
    if (descriptors[1] >= 0) {
        close(descriptors[1]);
    }
    return status;
}

continuum_status continuum_recreate_closed_loopback_tcp_pair(
    const continuum_remote_tcp_endpoint_info *first_endpoint,
    const continuum_remote_tcp_endpoint_info *second_endpoint,
    int32_t *out_first_descriptor,
    int32_t *out_second_descriptor
) {
    if (first_endpoint == NULL || second_endpoint == NULL
        || first_endpoint == second_endpoint
        || out_first_descriptor == NULL || out_second_descriptor == NULL
        || out_first_descriptor == out_second_descriptor) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    *out_first_descriptor = -1;
    *out_second_descriptor = -1;

    if (first_endpoint->process_id <= 0
        || second_endpoint->process_id <= 0
        || first_endpoint->file_descriptor < 0
        || second_endpoint->file_descriptor < 0
        || (first_endpoint->process_id == second_endpoint->process_id
            && first_endpoint->file_descriptor
                == second_endpoint->file_descriptor)
        || !continuum_saved_tcp_address_is_valid(
            first_endpoint->local_address,
            first_endpoint->local_address_length,
            first_endpoint->domain
        )
        || !continuum_saved_tcp_address_is_valid(
            first_endpoint->remote_address,
            first_endpoint->remote_address_length,
            first_endpoint->domain
        )
        || !continuum_saved_tcp_address_is_valid(
            second_endpoint->local_address,
            second_endpoint->local_address_length,
            second_endpoint->domain
        )
        || !continuum_saved_tcp_address_is_valid(
            second_endpoint->remote_address,
            second_endpoint->remote_address_length,
            second_endpoint->domain
        )) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }

    if (first_endpoint->domain != second_endpoint->domain
        || first_endpoint->socket_type != SOCK_STREAM
        || second_endpoint->socket_type != SOCK_STREAM
        || first_endpoint->socket_type != second_endpoint->socket_type
        || first_endpoint->protocol != IPPROTO_TCP
        || second_endpoint->protocol != IPPROTO_TCP
        || first_endpoint->protocol != second_endpoint->protocol
        || first_endpoint->tcp_state != TSI_S_ESTABLISHED
        || second_endpoint->tcp_state != TSI_S_ESTABLISHED
        || first_endpoint->receive_queue_bytes != 0
        || first_endpoint->send_queue_bytes != 0
        || second_endpoint->receive_queue_bytes != 0
        || second_endpoint->send_queue_bytes != 0
        || first_endpoint->local_address_length
            != second_endpoint->remote_address_length
        || first_endpoint->remote_address_length
            != second_endpoint->local_address_length
        || memcmp(
            first_endpoint->local_address,
            second_endpoint->remote_address,
            first_endpoint->local_address_length
        ) != 0
        || memcmp(
            first_endpoint->remote_address,
            second_endpoint->local_address,
            first_endpoint->remote_address_length
        ) != 0
        || !continuum_saved_tcp_address_is_loopback(
            first_endpoint->local_address,
            first_endpoint->domain
        )
        || !continuum_saved_tcp_address_is_loopback(
            second_endpoint->local_address,
            second_endpoint->domain
        )
        || !continuum_process_is_absent(first_endpoint->process_id)
        || (second_endpoint->process_id != first_endpoint->process_id
            && !continuum_process_is_absent(second_endpoint->process_id))) {
        return CONTINUUM_STATUS_VALIDATION_FAILED;
    }

    int exact_error = 0;
    if (continuum_create_loopback_tcp_pair(
            first_endpoint,
            second_endpoint,
            1,
            out_first_descriptor,
            out_second_descriptor,
            &exact_error
        )) {
        return CONTINUUM_STATUS_OK;
    }
    if (exact_error != EADDRINUSE) {
        return CONTINUUM_STATUS_VALIDATION_FAILED;
    }

    // TIME_WAIT can make an otherwise closed exact four-tuple unavailable.
    // Keep the stream and reverse-peer relationship on fresh loopback ports.
    // A later descriptor virtualizer must report the saved sockaddr identity
    // to app code that calls getsockname or getpeername.
    int fallback_error = 0;
    return continuum_create_loopback_tcp_pair(
        first_endpoint,
        second_endpoint,
        0,
        out_first_descriptor,
        out_second_descriptor,
        &fallback_error
    ) ? CONTINUUM_STATUS_OK : CONTINUUM_STATUS_VALIDATION_FAILED;
}

continuum_status continuum_recreate_closed_pty_pair(
    const continuum_remote_pty_descriptor_info *master_descriptor,
    const continuum_remote_pty_descriptor_info *slave_descriptor,
    int32_t *out_master_descriptor,
    int32_t *out_slave_descriptor
) {
    if (master_descriptor == NULL || slave_descriptor == NULL
        || master_descriptor == slave_descriptor
        || out_master_descriptor == NULL || out_slave_descriptor == NULL
        || out_master_descriptor == out_slave_descriptor) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    *out_master_descriptor = -1;
    *out_slave_descriptor = -1;

    if (master_descriptor->process_id <= 0
        || slave_descriptor->process_id <= 0
        || master_descriptor->file_descriptor < 0
        || slave_descriptor->file_descriptor < 0
        || master_descriptor->role != CONTINUUM_REMOTE_PTY_ROLE_MASTER
        || slave_descriptor->role != CONTINUUM_REMOTE_PTY_ROLE_SLAVE
        || master_descriptor->tty_index != master_descriptor->device_minor
        || slave_descriptor->tty_index != slave_descriptor->device_minor
        || master_descriptor->tty_index != slave_descriptor->tty_index
        || master_descriptor->alias_identity
            != continuum_pty_alias_identity(
                master_descriptor->tty_index,
                CONTINUUM_REMOTE_PTY_ROLE_MASTER
            )
        || slave_descriptor->alias_identity
            != continuum_pty_alias_identity(
                slave_descriptor->tty_index,
                CONTINUUM_REMOTE_PTY_ROLE_SLAVE
            )) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }

    if (!continuum_process_is_absent(master_descriptor->process_id)
        || (slave_descriptor->process_id != master_descriptor->process_id
            && !continuum_process_is_absent(slave_descriptor->process_id))
        || (master_descriptor->input_queue_known
            && master_descriptor->input_queue_bytes != 0)
        || (master_descriptor->output_queue_known
            && master_descriptor->output_queue_bytes != 0)
        || (slave_descriptor->input_queue_known
            && slave_descriptor->input_queue_bytes != 0)
        || (slave_descriptor->output_queue_known
            && slave_descriptor->output_queue_bytes != 0)
        || (!master_descriptor->terminal_attributes_known
            && !slave_descriptor->terminal_attributes_known)
        || (!master_descriptor->window_size_known
            && !slave_descriptor->window_size_known)
        || (master_descriptor->terminal_attributes_known
            && slave_descriptor->terminal_attributes_known
            && memcmp(
                &master_descriptor->terminal_attributes,
                &slave_descriptor->terminal_attributes,
                sizeof(struct termios)
            ) != 0)
        || (master_descriptor->window_size_known
            && slave_descriptor->window_size_known
            && memcmp(
                &master_descriptor->window_size,
                &slave_descriptor->window_size,
                sizeof(struct winsize)
            ) != 0)) {
        return CONTINUUM_STATUS_VALIDATION_FAILED;
    }

    const struct termios *attributes =
        master_descriptor->terminal_attributes_known
            ? &master_descriptor->terminal_attributes
            : &slave_descriptor->terminal_attributes;
    const struct winsize *window_size = master_descriptor->window_size_known
        ? &master_descriptor->window_size
        : &slave_descriptor->window_size;
    int master = -1;
    int slave = -1;
    if (openpty(
            &master,
            &slave,
            NULL,
            (struct termios *)(uintptr_t)attributes,
            (struct winsize *)(uintptr_t)window_size
        ) != 0
        || fcntl(master, F_SETFD, FD_CLOEXEC) != 0
        || fcntl(slave, F_SETFD, FD_CLOEXEC) != 0) {
        if (master >= 0) {
            close(master);
        }
        if (slave >= 0) {
            close(slave);
        }
        return CONTINUUM_STATUS_VALIDATION_FAILED;
    }
    *out_master_descriptor = master;
    *out_slave_descriptor = slave;
    return CONTINUUM_STATUS_OK;
}

continuum_status continuum_recreate_closed_pty_from_slave(
    const continuum_remote_pty_descriptor_info *slave_descriptor,
    int32_t *out_master_descriptor,
    int32_t *out_slave_descriptor
) {
    if (slave_descriptor == NULL || out_master_descriptor == NULL
        || out_slave_descriptor == NULL
        || slave_descriptor->role != CONTINUUM_REMOTE_PTY_ROLE_SLAVE) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    continuum_remote_pty_descriptor_info master = *slave_descriptor;
    master.file_descriptor = slave_descriptor->file_descriptor == INT32_MAX
        ? INT32_MAX - 1
        : slave_descriptor->file_descriptor + 1;
    master.role = CONTINUUM_REMOTE_PTY_ROLE_MASTER;
    master.alias_identity = continuum_pty_alias_identity(
        master.tty_index,
        CONTINUUM_REMOTE_PTY_ROLE_MASTER
    );
    return continuum_recreate_closed_pty_pair(
        &master,
        slave_descriptor,
        out_master_descriptor,
        out_slave_descriptor
    );
}

size_t continuum_remote_process_group_member_region_count(
    const continuum_remote_process_group_snapshot *snapshot,
    size_t member_index
) {
    if (snapshot == NULL || member_index >= snapshot->member_count
        || snapshot->members[member_index].snapshot == NULL) {
        return 0;
    }
    return snapshot->members[member_index].snapshot->region_count;
}

continuum_status continuum_remote_process_group_copy_member_region_info(
    const continuum_remote_process_group_snapshot *snapshot,
    size_t member_index,
    size_t region_index,
    continuum_remote_process_region_info *out_info
) {
    if (snapshot == NULL || member_index >= snapshot->member_count) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    return continuum_remote_process_snapshot_region_info(
        snapshot->members[member_index].snapshot,
        region_index,
        out_info
    );
}

continuum_status continuum_remote_process_group_copy_member_region_bytes(
    const continuum_remote_process_group_snapshot *snapshot,
    size_t member_index,
    size_t region_index,
    void *destination,
    size_t destination_capacity,
    size_t *out_required_length
) {
    if (snapshot == NULL || out_required_length == NULL
        || member_index >= snapshot->member_count
        || snapshot->members[member_index].snapshot == NULL
        || (destination == NULL && destination_capacity != 0)) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    const continuum_remote_process_snapshot *process =
        snapshot->members[member_index].snapshot;
    if (region_index >= process->region_count) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    const continuum_remote_process_region *region = &process->regions[region_index];
    *out_required_length = (size_t)region->length;
    if (destination == NULL) {
        return CONTINUUM_STATUS_OK;
    }
    if (destination_capacity < region->length || region->bytes == NULL) {
        return CONTINUUM_STATUS_RANGE_ERROR;
    }
    memcpy(destination, region->bytes, (size_t)region->length);
    return CONTINUUM_STATUS_OK;
}

continuum_status continuum_remote_process_group_copy_member_region_bytes_range(
    const continuum_remote_process_group_snapshot *snapshot,
    size_t member_index,
    size_t region_index,
    uint64_t offset,
    void *destination,
    size_t length
) {
    if (snapshot == NULL || destination == NULL || length == 0
        || member_index >= snapshot->member_count
        || snapshot->members[member_index].snapshot == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    const continuum_remote_process_snapshot *process =
        snapshot->members[member_index].snapshot;
    if (region_index >= process->region_count) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    const continuum_remote_process_region *region = &process->regions[region_index];
    if (region->bytes == NULL || offset > region->length
        || length > region->length - offset) {
        return CONTINUUM_STATUS_RANGE_ERROR;
    }
    memcpy(destination, region->bytes + offset, length);
    return CONTINUUM_STATUS_OK;
}

size_t continuum_remote_process_group_member_thread_count(
    const continuum_remote_process_group_snapshot *snapshot,
    size_t member_index
) {
    if (snapshot == NULL || member_index >= snapshot->member_count
        || snapshot->members[member_index].snapshot == NULL
        || snapshot->members[member_index].snapshot->threads == NULL) {
        return 0;
    }
    return snapshot->members[member_index].snapshot->threads->count;
}

static const continuum_remote_thread_snapshot *continuum_group_member_threads(
    const continuum_remote_process_group_snapshot *snapshot,
    size_t member_index
) {
    if (snapshot == NULL || member_index >= snapshot->member_count
        || snapshot->members[member_index].snapshot == NULL) {
        return NULL;
    }
    return snapshot->members[member_index].snapshot->threads;
}

continuum_status continuum_remote_process_group_copy_member_thread_info(
    const continuum_remote_process_group_snapshot *snapshot,
    size_t member_index,
    size_t thread_index,
    continuum_remote_thread_state_info *out_info
) {
    return continuum_remote_thread_snapshot_info(
        continuum_group_member_threads(snapshot, member_index),
        thread_index,
        out_info
    );
}

continuum_status continuum_remote_process_group_copy_member_thread_general_state(
    const continuum_remote_process_group_snapshot *snapshot,
    size_t member_index,
    size_t thread_index,
    void *destination,
    size_t destination_capacity,
    size_t *out_required_length
) {
    return continuum_remote_thread_snapshot_copy_general_state(
        continuum_group_member_threads(snapshot, member_index),
        thread_index,
        destination,
        destination_capacity,
        out_required_length
    );
}

continuum_status continuum_remote_process_group_copy_member_thread_vector_state(
    const continuum_remote_process_group_snapshot *snapshot,
    size_t member_index,
    size_t thread_index,
    void *destination,
    size_t destination_capacity,
    size_t *out_required_length
) {
    return continuum_remote_thread_snapshot_copy_vector_state(
        continuum_group_member_threads(snapshot, member_index),
        thread_index,
        destination,
        destination_capacity,
        out_required_length
    );
}

static continuum_status continuum_remote_process_group_restore_internal(
    continuum_remote_process_group_snapshot *snapshot,
    continuum_remote_resource_restore_callback resource_callback,
    void *resource_context,
    continuum_remote_process_group_restore_report *out_report
) {
    if (snapshot == NULL || out_report == NULL || snapshot->member_count == 0) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    memset(out_report, 0, sizeof(*out_report));

    size_t suspended_count = 0;
    continuum_status status = continuum_suspend_process_group(
        snapshot,
        &suspended_count
    );
    continuum_remote_process_tree_entry *tree = NULL;
    size_t tree_count = 0;
    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_discover_process_forest(
            snapshot->root_process_ids,
            snapshot->root_process_count,
            &tree,
            &tree_count
        );
    }
    if (status == CONTINUUM_STATUS_OK
        && !continuum_process_tree_contains_group(
            tree,
            tree_count,
            snapshot
        )) {
        status = CONTINUUM_STATUS_PROCESS_TREE_CHANGED;
    }
    free(tree);

    continuum_remote_process_snapshot **safety = calloc(
        snapshot->member_count,
        sizeof(*safety)
    );
    if (status == CONTINUUM_STATUS_OK && safety == NULL) {
        status = CONTINUUM_STATUS_OUT_OF_MEMORY;
    }
    for (size_t index = 0;
         status == CONTINUUM_STATUS_OK && index < snapshot->member_count;
         index += 1) {
        uint64_t budget = 0;
        if (!continuum_add_u64(
                snapshot->members[index].snapshot->info.captured_bytes,
                UINT64_C(64) * 1024U * 1024U,
                &budget
            )) {
            status = CONTINUUM_STATUS_RANGE_ERROR;
            break;
        }
        status = continuum_capture_process_snapshot_suspended(
            snapshot->members[index].session,
            budget,
            &safety[index]
        );
    }
    for (size_t index = 0;
         status == CONTINUUM_STATUS_OK && index < snapshot->member_count;
         index += 1) {
        status = continuum_validate_process_snapshot_layout(
            safety[index],
            snapshot->members[index].snapshot
        );
    }

    size_t touched_count = 0;
    for (size_t offset = 0;
         status == CONTINUUM_STATUS_OK && offset < snapshot->member_count;
         offset += 1) {
        const size_t index = snapshot->member_count - 1 - offset;
        continuum_remote_process_restore_report member_report;
        memset(&member_report, 0, sizeof(member_report));
        touched_count = offset + 1;
        status = continuum_apply_process_snapshot(
            snapshot->members[index].session->task,
            snapshot->members[index].snapshot,
            safety[index],
            &member_report
        );
        out_report->regions_written += member_report.regions_written;
        out_report->bytes_written += member_report.bytes_written;
        out_report->thread_states_restored +=
            member_report.thread_states_restored;
        if (status == CONTINUUM_STATUS_OK) {
            out_report->processes_restored += 1;
        }
    }
    if (status == CONTINUUM_STATUS_OK) {
        out_report->memory_readback_verified = 1;
    }
    if (status == CONTINUUM_STATUS_OK && resource_callback != NULL) {
        status = resource_callback(snapshot, resource_context);
    }

    if (status != CONTINUUM_STATUS_OK && touched_count > 0) {
        continuum_status original_status = status;
        out_report->rollback_attempted = 1;
        int rollback_valid = 1;
        while (touched_count > 0) {
            const size_t rollback_index =
                snapshot->member_count - touched_count;
            continuum_remote_process_restore_report rollback_report;
            memset(&rollback_report, 0, sizeof(rollback_report));
            continuum_status rollback_status = continuum_apply_process_snapshot(
                snapshot->members[rollback_index].session->task,
                safety[rollback_index],
                snapshot->members[rollback_index].snapshot,
                &rollback_report
            );
            if (rollback_status != CONTINUUM_STATUS_OK
                || rollback_report.memory_readback_verified != 1
                || rollback_report.thread_states_restored
                    != safety[rollback_index]->info.thread_count) {
                rollback_valid = 0;
            }
            touched_count -= 1;
        }
        if (rollback_valid) {
            out_report->rollback_verified = 1;
            status = original_status;
        } else {
            status = CONTINUUM_STATUS_ROLLBACK_FAILED;
        }
    }

    if (safety != NULL) {
        for (size_t index = 0; index < snapshot->member_count; index += 1) {
            continuum_remote_process_snapshot_destroy(safety[index]);
        }
    }
    free(safety);

    continuum_status resume_status = continuum_resume_process_group(
        snapshot,
        suspended_count
    );
    if (resume_status != CONTINUUM_STATUS_OK) {
        return resume_status;
    }
    return status;
}

continuum_status continuum_remote_process_group_restore(
    continuum_remote_process_group_snapshot *snapshot,
    continuum_remote_process_group_restore_report *out_report
) {
    return continuum_remote_process_group_restore_internal(
        snapshot,
        NULL,
        NULL,
        out_report
    );
}

continuum_status continuum_remote_process_group_with_suspended_resources(
    continuum_remote_process_group_snapshot *snapshot,
    continuum_remote_resource_capture_callback callback,
    void *callback_context
) {
    if (snapshot == NULL || callback == NULL || snapshot->member_count == 0) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }

    size_t suspended_count = 0;
    continuum_status status = continuum_suspend_process_group(
        snapshot,
        &suspended_count
    );
    continuum_remote_process_tree_entry *tree = NULL;
    size_t tree_count = 0;
    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_discover_process_forest(
            snapshot->root_process_ids,
            snapshot->root_process_count,
            &tree,
            &tree_count
        );
    }
    if (status == CONTINUUM_STATUS_OK
        && !continuum_process_tree_contains_group(tree, tree_count, snapshot)) {
        status = CONTINUUM_STATUS_PROCESS_TREE_CHANGED;
    }
    free(tree);
    if (status == CONTINUUM_STATUS_OK) {
        status = callback(snapshot, callback_context);
    }

    continuum_status resume_status = continuum_resume_process_group(
        snapshot,
        suspended_count
    );
    return resume_status == CONTINUUM_STATUS_OK ? status : resume_status;
}

continuum_status continuum_remote_process_group_restore_with_resources(
    continuum_remote_process_group_snapshot *snapshot,
    continuum_remote_resource_restore_callback callback,
    void *callback_context,
    continuum_remote_process_group_restore_report *out_report
) {
    if (callback == NULL) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    return continuum_remote_process_group_restore_internal(
        snapshot,
        callback,
        callback_context,
        out_report
    );
}

continuum_status continuum_remote_session_restore(
    continuum_remote_session *session,
    const continuum_remote_region_descriptor *descriptor,
    const void *bytes,
    size_t length,
    continuum_remote_restore_report *out_report
) {
    if (session == NULL || descriptor == NULL || bytes == NULL
        || length == 0 || out_report == NULL || !session->has_registered_region) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    memset(out_report, 0, sizeof(*out_report));
    if (descriptor->address != session->registered_region.address
        || descriptor->length != session->registered_region.length
        || descriptor->mapping_address != session->registered_region.mapping_address
        || descriptor->mapping_length != session->registered_region.mapping_length
        || descriptor->protection != session->registered_region.protection
        || descriptor->maximum_protection
            != session->registered_region.maximum_protection
        || !continuum_is_private_or_cow_share_mode(descriptor->share_mode)
        || !continuum_is_private_or_cow_share_mode(
            session->registered_region.share_mode
        )
        || descriptor->length != length
        || descriptor->thread_set_hash == 0) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }

    continuum_status status = continuum_validate_session_identity(session);
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }

    int did_suspend = 0;
    status = continuum_suspend_session(session, &did_suspend);
    if (status != CONTINUUM_STATUS_OK) {
        return status;
    }

    uint8_t *rollback = NULL;
    uint8_t *verification = NULL;
    continuum_remote_thread_snapshot *threads = NULL;
    continuum_remote_region_descriptor current;
    memset(&current, 0, sizeof(current));

    status = continuum_validate_session_identity(session);
    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_query_region(
            session->task,
            session->registered_region.address,
            session->registered_region.length,
            &current
        );
    }
    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_validate_region_unchanged(descriptor, &current);
    }
    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_capture_thread_snapshot(session->task, &threads);
    }
    if (status == CONTINUUM_STATUS_OK
        && threads->set_hash != descriptor->thread_set_hash) {
        status = CONTINUUM_STATUS_THREAD_SET_CHANGED;
    }

    if (status == CONTINUUM_STATUS_OK) {
        rollback = malloc(length);
        verification = malloc(length);
        if (rollback == NULL || verification == NULL) {
            status = CONTINUUM_STATUS_OUT_OF_MEMORY;
        }
    }
    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_read_task_bytes(
            session->task,
            session->registered_region.address,
            session->registered_region.length,
            rollback
        );
    }

    uint64_t bytes_written = 0;
    int write_attempted = 0;
    if (status == CONTINUUM_STATUS_OK) {
        write_attempted = 1;
        status = continuum_write_task_bytes(
            session->task,
            session->registered_region.address,
            bytes,
            length,
            &bytes_written
        );
        out_report->bytes_written = bytes_written;
    }
    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_read_task_bytes(
            session->task,
            session->registered_region.address,
            session->registered_region.length,
            verification
        );
        if (status == CONTINUUM_STATUS_OK && memcmp(bytes, verification, length) != 0) {
            status = CONTINUUM_STATUS_VALIDATION_FAILED;
        }
        if (status == CONTINUUM_STATUS_OK) {
            out_report->readback_verified = 1;
        }
    }

    if (status != CONTINUUM_STATUS_OK && rollback != NULL && verification != NULL
        && write_attempted) {
        continuum_status original_status = status;
        out_report->rollback_attempted = 1;
        uint64_t rollback_written = 0;
        continuum_status rollback_status = continuum_write_task_bytes(
            session->task,
            session->registered_region.address,
            rollback,
            length,
            &rollback_written
        );
        if (rollback_status == CONTINUUM_STATUS_OK) {
            rollback_status = continuum_read_task_bytes(
                session->task,
                session->registered_region.address,
                session->registered_region.length,
                verification
            );
        }
        if (rollback_status == CONTINUUM_STATUS_OK
            && memcmp(rollback, verification, length) == 0) {
            out_report->rollback_verified = 1;
            status = original_status;
        } else {
            status = CONTINUUM_STATUS_ROLLBACK_FAILED;
        }
    }

    continuum_remote_thread_snapshot_destroy(threads);
    if (rollback != NULL) {
        memset(rollback, 0, length);
        free(rollback);
    }
    if (verification != NULL) {
        memset(verification, 0, length);
        free(verification);
    }

    continuum_status resume_status = continuum_resume_session(session, did_suspend);
    if (resume_status != CONTINUUM_STATUS_OK) {
        return resume_status;
    }
    return status;
}

void continuum_remote_session_destroy(continuum_remote_session *session) {
    if (session == NULL) {
        return;
    }
    if (session->owns_ptrace_attachment
        && continuum_validate_session_identity(session)
            == CONTINUUM_STATUS_OK) {
        continuum_broker_kill_and_reap_traced_child(
            session->identity.process_id,
            clock_gettime_nsec_np(CLOCK_MONOTONIC)
                + UINT64_C(1000000000)
        );
        session->owns_ptrace_attachment = 0;
    }
    if (session->owns_task_port && session->task != MACH_PORT_NULL) {
        (void)continuum_discharge_owned_suspensions(
            session,
            CONTINUUM_DESTROY_RESUME_ATTEMPT_LIMIT
        );
        mach_port_deallocate(mach_task_self(), session->task);
    }
    memset(session, 0, sizeof(*session));
    free(session);
}

size_t continuum_remote_thread_snapshot_count(
    const continuum_remote_thread_snapshot *snapshot
) {
    return snapshot == NULL ? 0 : snapshot->count;
}

continuum_status continuum_remote_thread_snapshot_info(
    const continuum_remote_thread_snapshot *snapshot,
    size_t index,
    continuum_remote_thread_state_info *out_info
) {
    if (snapshot == NULL || out_info == NULL || index >= snapshot->count) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    const continuum_remote_thread_entry *entry = &snapshot->entries[index];
    memset(out_info, 0, sizeof(*out_info));
    out_info->thread_identifier = entry->identifier;
    out_info->thread_handle = entry->thread_handle;
    out_info->pthread_object_address = entry->pthread_object_address;
    out_info->dispatch_queue_address = entry->dispatch_queue_address;
    out_info->origin = entry->origin;
    out_info->general_state_flavor = entry->general_flavor;
    out_info->general_state_length = entry->general_length;
    out_info->vector_state_flavor = entry->vector_flavor;
    out_info->vector_state_length = entry->vector_length;
    out_info->is_userspace_safepoint = entry->is_userspace_safepoint;
    out_info->preserves_kernel_continuation =
        entry->preserves_kernel_continuation;
#if defined(__arm64__)
    if (entry->general_flavor == ARM_THREAD_STATE64
        && entry->general_length == sizeof(arm_thread_state64_t)) {
        arm_thread_state64_t state;
        memcpy(&state, entry->general_bytes, sizeof(state));
        out_info->stack_pointer = (uint64_t)(uintptr_t)
            arm_thread_state64_get_sp(state);
    }
#endif
    return CONTINUUM_STATUS_OK;
}

static continuum_status continuum_copy_thread_state(
    const continuum_remote_thread_snapshot *snapshot,
    size_t index,
    int vector_state,
    void *destination,
    size_t destination_capacity,
    size_t *out_required_length
) {
    if (snapshot == NULL || out_required_length == NULL || index >= snapshot->count) {
        return CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    const continuum_remote_thread_entry *entry = &snapshot->entries[index];
    const uint8_t *source = vector_state ? entry->vector_bytes : entry->general_bytes;
    size_t source_length = vector_state ? entry->vector_length : entry->general_length;
    *out_required_length = source_length;
    if (destination == NULL) {
        return destination_capacity == 0
            ? CONTINUUM_STATUS_OK
            : CONTINUUM_STATUS_INVALID_ARGUMENT;
    }
    if (destination_capacity < source_length) {
        return CONTINUUM_STATUS_RANGE_ERROR;
    }
    memcpy(destination, source, source_length);
    return CONTINUUM_STATUS_OK;
}

continuum_status continuum_remote_thread_snapshot_copy_general_state(
    const continuum_remote_thread_snapshot *snapshot,
    size_t index,
    void *destination,
    size_t destination_capacity,
    size_t *out_required_length
) {
    return continuum_copy_thread_state(
        snapshot,
        index,
        0,
        destination,
        destination_capacity,
        out_required_length
    );
}

continuum_status continuum_remote_thread_snapshot_copy_vector_state(
    const continuum_remote_thread_snapshot *snapshot,
    size_t index,
    void *destination,
    size_t destination_capacity,
    size_t *out_required_length
) {
    return continuum_copy_thread_state(
        snapshot,
        index,
        1,
        destination,
        destination_capacity,
        out_required_length
    );
}

void continuum_owned_buffer_destroy(continuum_owned_buffer *buffer) {
    if (buffer == NULL) {
        return;
    }
    if (buffer->bytes != NULL) {
        memset(buffer->bytes, 0, buffer->length);
        free(buffer->bytes);
    }
    memset(buffer, 0, sizeof(*buffer));
}

const char *continuum_status_string(continuum_status status) {
    switch (status) {
        case CONTINUUM_STATUS_OK:
            return "ok";
        case CONTINUUM_STATUS_INVALID_ARGUMENT:
            return "invalid argument";
        case CONTINUUM_STATUS_OUT_OF_MEMORY:
            return "out of memory";
        case CONTINUUM_STATUS_MACH_ERROR:
            return "Mach operation failed";
        case CONTINUUM_STATUS_CHECKPOINT_NOT_FOUND:
            return "checkpoint not found";
        case CONTINUUM_STATUS_RANGE_ERROR:
            return "numeric range exceeded";
        case CONTINUUM_STATUS_ACCESS_DENIED:
            return "task access denied";
        case CONTINUUM_STATUS_TARGET_EXITED:
            return "target process exited";
        case CONTINUUM_STATUS_PROCESS_IDENTITY_CHANGED:
            return "target process identity changed";
        case CONTINUUM_STATUS_REGION_UNMAPPED:
            return "registered region is unmapped";
        case CONTINUUM_STATUS_REGION_PROTECTION_CHANGED:
            return "registered region protection changed";
        case CONTINUUM_STATUS_REGION_NOT_PRIVATE:
            return "registered region is not private or copy-on-write";
        case CONTINUUM_STATUS_THREAD_SET_CHANGED:
            return "target thread set changed";
        case CONTINUUM_STATUS_SHORT_READ:
            return "Mach read returned fewer bytes than requested";
        case CONTINUUM_STATUS_SHORT_WRITE:
            return "Mach write did not complete";
        case CONTINUUM_STATUS_VALIDATION_FAILED:
            return "restored bytes failed readback validation";
        case CONTINUUM_STATUS_ROLLBACK_FAILED:
            return "emergency rollback failed validation";
        case CONTINUUM_STATUS_UNSUPPORTED_ARCHITECTURE:
            return "architecture is unsupported";
        case CONTINUUM_STATUS_SUSPEND_FAILED:
            return "target suspension failed";
        case CONTINUUM_STATUS_RESUME_FAILED:
            return "target resume failed";
        case CONTINUUM_STATUS_THREAD_STATE_FAILED:
            return "thread state capture failed";
        case CONTINUUM_STATUS_REGION_MAPPING_CHANGED:
            return "registered virtual-memory mapping changed";
        case CONTINUUM_STATUS_SNAPSHOT_BUDGET_EXCEEDED:
            return "process snapshot exceeded its capture budget";
        case CONTINUUM_STATUS_THREAD_RESTORE_FAILED:
            return "thread register restore failed";
        case CONTINUUM_STATUS_DESCRIPTOR_TABLE_CHANGED:
            return "target descriptor table changed";
        case CONTINUUM_STATUS_MACH_NAMESPACE_CHANGED:
            return "target Mach port namespace changed";
        case CONTINUUM_STATUS_UNSUPPORTED_DESCRIPTOR:
            return "target has an unsupported descriptor type";
        case CONTINUUM_STATUS_PROCESS_TREE_CHANGED:
            return "target process tree changed";
        case CONTINUUM_STATUS_SPAWN_FAILED:
            return "replacement process spawn failed";
        case CONTINUUM_STATUS_FILE_WRITER_CONFLICT:
            return "another process is writing the target file";
    }
    return "unknown status";
}
