#include <CommonCrypto/CommonDigest.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <libproc.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

static void fail(int status, const char *message) {
    fprintf(stderr, "ContinuumManagedExec: %s\n", message);
    exit(status);
}

static void fail_errno(int status, const char *operation) {
    fprintf(stderr, "ContinuumManagedExec: %s: %s\n", operation, strerror(errno));
    exit(status);
}

static int write_all(int descriptor, const void *bytes, size_t count) {
    const uint8_t *cursor = bytes;
    while (count != 0) {
        ssize_t written = write(descriptor, cursor, count);
        if (written < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        cursor += (size_t)written;
        count -= (size_t)written;
    }
    return 0;
}

static int is_mach_o_magic(uint32_t magic) {
    return magic == MH_MAGIC || magic == MH_CIGAM ||
           magic == MH_MAGIC_64 || magic == MH_CIGAM_64 ||
           magic == FAT_MAGIC || magic == FAT_CIGAM ||
           magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64;
}

static int secure_directory_at(int parent, const char *name, uid_t owner, mode_t mode) {
    if (mkdirat(parent, name, mode) != 0 && errno != EEXIST) return -1;

    int descriptor = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0) return -1;

    struct stat information;
    if (fstat(descriptor, &information) != 0 || !S_ISDIR(information.st_mode) ||
        information.st_uid != owner) {
        close(descriptor);
        errno = EPERM;
        return -1;
    }
    return descriptor;
}

static int application_support_root(char path[PATH_MAX], uid_t owner) {
    struct passwd password;
    struct passwd *result = NULL;
    char buffer[16384];
    if (getpwuid_r(owner, &password, buffer, sizeof(buffer), &result) != 0 || result == NULL) {
        errno = ENOENT;
        return -1;
    }
    if (snprintf(path, PATH_MAX, "%s/Library/Application Support", password.pw_dir) >= PATH_MAX) {
        errno = ENAMETOOLONG;
        return -1;
    }
    int descriptor = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0) return -1;
    struct stat information;
    if (fstat(descriptor, &information) != 0 || !S_ISDIR(information.st_mode) ||
        information.st_uid != owner) {
        close(descriptor);
        errno = EPERM;
        return -1;
    }
    return descriptor;
}

static void digest_source(int source, const char *identity, unsigned char digest[CC_SHA256_DIGEST_LENGTH]) {
    CC_SHA256_CTX context;
    CC_SHA256_Init(&context);
    static const char domain[] = "ContinuumManagedExec-v1\0";
    CC_SHA256_Update(&context, domain, (CC_LONG)sizeof(domain));
    CC_SHA256_Update(&context, identity, (CC_LONG)strlen(identity));

    if (lseek(source, 0, SEEK_SET) < 0) fail_errno(EX_IOERR, "rewind source");
    uint8_t buffer[1024 * 64];
    for (;;) {
        ssize_t count = read(source, buffer, sizeof(buffer));
        if (count < 0) {
            if (errno == EINTR) continue;
            fail_errno(EX_IOERR, "hash source");
        }
        if (count == 0) break;
        CC_SHA256_Update(&context, buffer, (CC_LONG)count);
    }
    CC_SHA256_Final(digest, &context);
}

static void hex_digest(const unsigned char digest[CC_SHA256_DIGEST_LENGTH], char output[65]) {
    static const char digits[] = "0123456789abcdef";
    for (size_t index = 0; index < CC_SHA256_DIGEST_LENGTH; ++index) {
        output[index * 2] = digits[digest[index] >> 4];
        output[index * 2 + 1] = digits[digest[index] & 0xf];
    }
    output[64] = '\0';
}

static int compare_descriptors(int left, int right) {
    if (lseek(left, 0, SEEK_SET) < 0 || lseek(right, 0, SEEK_SET) < 0) return -1;
    uint8_t left_buffer[1024 * 64];
    uint8_t right_buffer[1024 * 64];
    for (;;) {
        ssize_t left_count;
        do left_count = read(left, left_buffer, sizeof(left_buffer)); while (left_count < 0 && errno == EINTR);
        if (left_count < 0) return -1;

        size_t received = 0;
        while (received < (size_t)left_count) {
            ssize_t count;
            do count = read(right, right_buffer + received, (size_t)left_count - received);
            while (count < 0 && errno == EINTR);
            if (count <= 0) return -1;
            received += (size_t)count;
        }
        if (left_count == 0) {
            uint8_t byte;
            ssize_t extra;
            do extra = read(right, &byte, 1); while (extra < 0 && errno == EINTR);
            return extra == 0 ? 0 : -1;
        }
        if (memcmp(left_buffer, right_buffer, (size_t)left_count) != 0) return -1;
    }
}

static int run_codesign(const char *operation, const char *path) {
    pid_t process = 0;
    char *const sign_arguments[] = {
        "/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", (char *)path, NULL
    };
    char *const verify_arguments[] = {
        "/usr/bin/codesign", "--verify", "--strict", (char *)path, NULL
    };
    char *const *arguments = strcmp(operation, "sign") == 0 ? sign_arguments : verify_arguments;
    int error = posix_spawn(&process, "/usr/bin/codesign", NULL, NULL, arguments, environ);
    if (error != 0) {
        errno = error;
        return -1;
    }
    int status = 0;
    while (waitpid(process, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

static int validate_managed_executable(int directory, uid_t owner, const char *path) {
    int descriptor = openat(directory, "executable", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0) return -1;
    struct stat information;
    int valid = fstat(descriptor, &information) == 0 && S_ISREG(information.st_mode) &&
                information.st_uid == owner && (information.st_mode & S_IXUSR) != 0;
    close(descriptor);
    if (!valid) {
        errno = EPERM;
        return -1;
    }
    return run_codesign("verify", path);
}

static void prepare_managed_executable(const char *source_path, char final_path[PATH_MAX]) {
    uid_t owner = geteuid();
    struct stat path_information;
    if (lstat(source_path, &path_information) != 0) fail_errno(EX_NOINPUT, "inspect source");
    if (!S_ISREG(path_information.st_mode) || path_information.st_uid != owner ||
        (path_information.st_mode & S_IXUSR) == 0) {
        fail(EX_NOPERM, "source must be a regular, owner-owned executable (symlinks are rejected)");
    }

    int source = open(source_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (source < 0) fail_errno(EX_NOINPUT, "open source");
    struct stat source_information;
    if (fstat(source, &source_information) != 0 || !S_ISREG(source_information.st_mode) ||
        source_information.st_uid != owner || source_information.st_dev != path_information.st_dev ||
        source_information.st_ino != path_information.st_ino) {
        close(source);
        fail(EX_NOPERM, "source changed while it was being opened");
    }

    uint32_t magic = 0;
    if (pread(source, &magic, sizeof(magic), 0) != sizeof(magic) || !is_mach_o_magic(magic)) {
        close(source);
        fail(EX_DATAERR, "source is not a Mach-O executable");
    }

    char identity[PATH_MAX];
    if (fcntl(source, F_GETPATH, identity) != 0) {
        close(source);
        fail_errno(EX_NOINPUT, "resolve source identity");
    }
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    digest_source(source, identity, digest);
    char key[65];
    hex_digest(digest, key);

    char support_path[PATH_MAX];
    int support = application_support_root(support_path, owner);
    if (support < 0) {
        close(source);
        fail_errno(EX_CANTCREAT, "open Application Support");
    }
    int continuum = secure_directory_at(support, "Continuum", owner, 0700);
    int root = continuum < 0 ? -1 : secure_directory_at(continuum, "ManagedExecutables", owner, 0700);
    close(support);
    if (continuum >= 0) close(continuum);
    if (root < 0) {
        close(source);
        fail_errno(EX_CANTCREAT, "open managed executable store");
    }
    if (fchmod(root, 0700) != 0) {
        close(root);
        close(source);
        fail_errno(EX_NOPERM, "make managed executable store private");
    }

    if (snprintf(final_path, PATH_MAX, "%s/Continuum/ManagedExecutables/%s/executable",
                 support_path, key) >= PATH_MAX) {
        close(root);
        close(source);
        fail(EX_CANTCREAT, "managed executable path is too long");
    }

    int managed_directory = openat(root, key, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (managed_directory < 0 && errno == ENOENT) {
        char temporary[96];
        snprintf(temporary, sizeof(temporary), ".new.%ld.%s", (long)getpid(), key);
        if (mkdirat(root, temporary, 0700) != 0) {
            close(root);
            close(source);
            fail_errno(EX_CANTCREAT, "create managed executable transaction");
        }
        int transaction = openat(root, temporary, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        int copy = transaction < 0 ? -1 : openat(transaction, "executable",
            O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, source_information.st_mode & 0700);
        if (copy < 0) {
            if (transaction >= 0) close(transaction);
            unlinkat(root, temporary, AT_REMOVEDIR);
            close(root);
            close(source);
            fail_errno(EX_CANTCREAT, "create managed executable copy");
        }

        if (lseek(source, 0, SEEK_SET) < 0) fail_errno(EX_IOERR, "rewind source");
        uint8_t buffer[1024 * 64];
        for (;;) {
            ssize_t count = read(source, buffer, sizeof(buffer));
            if (count < 0) {
                if (errno == EINTR) continue;
                fail_errno(EX_IOERR, "read source");
            }
            if (count == 0) break;
            if (write_all(copy, buffer, (size_t)count) != 0) fail_errno(EX_IOERR, "write managed copy");
        }
        if (fsync(copy) != 0 || compare_descriptors(source, copy) != 0) {
            fail(EX_IOERR, "managed copy did not match the source before signing");
        }
        unsigned char digest_after_copy[CC_SHA256_DIGEST_LENGTH];
        digest_source(source, identity, digest_after_copy);
        if (memcmp(digest, digest_after_copy, sizeof(digest)) != 0) {
            fail(EX_TEMPFAIL, "source changed while it was being copied");
        }
        struct stat source_after_copy;
        if (fstat(source, &source_after_copy) != 0 || source_after_copy.st_dev != source_information.st_dev ||
            source_after_copy.st_ino != source_information.st_ino ||
            source_after_copy.st_size != source_information.st_size ||
            source_after_copy.st_mtimespec.tv_sec != source_information.st_mtimespec.tv_sec ||
            source_after_copy.st_mtimespec.tv_nsec != source_information.st_mtimespec.tv_nsec) {
            fail(EX_TEMPFAIL, "source changed while it was being copied");
        }
        close(copy);

        char temporary_path[PATH_MAX];
        if (snprintf(temporary_path, sizeof(temporary_path), "%s/Continuum/ManagedExecutables/%s/executable",
                     support_path, temporary) >= (int)sizeof(temporary_path) ||
            run_codesign("sign", temporary_path) != 0 || run_codesign("verify", temporary_path) != 0) {
            fail_errno(EX_CANTCREAT, "ad-hoc sign managed executable");
        }
        if (renameat(root, temporary, root, key) != 0) {
            if (errno != EEXIST && errno != ENOTEMPTY) fail_errno(EX_CANTCREAT, "publish managed executable");
            unlinkat(transaction, "executable", 0);
            close(transaction);
            unlinkat(root, temporary, AT_REMOVEDIR);
        } else {
            close(transaction);
        }
        managed_directory = openat(root, key, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    }

    close(root);
    close(source);
    struct stat managed_directory_information;
    if (managed_directory < 0 || fstat(managed_directory, &managed_directory_information) != 0 ||
        !S_ISDIR(managed_directory_information.st_mode) ||
        managed_directory_information.st_uid != owner ||
        (managed_directory_information.st_mode & 077) != 0 ||
        validate_managed_executable(managed_directory, owner, final_path) != 0) {
        if (managed_directory >= 0) close(managed_directory);
        fail_errno(EX_NOPERM, "validate managed executable");
    }
    close(managed_directory);

}

typedef enum readiness_kind {
    READINESS_NONE = 0,
    READINESS_TCP = 1,
    READINESS_UNIX = 2
} readiness_kind;

typedef struct readiness_endpoint {
    readiness_kind kind;
    struct addrinfo *tcp_addresses;
    struct sockaddr_un unix_address;
    socklen_t unix_length;
} readiness_endpoint;

typedef struct supervised_child {
    pid_t process;
    int reaped;
    int status;
} supervised_child;

typedef struct process_identity {
    pid_t process;
    uint64_t start_seconds;
    uint64_t start_microseconds;
} process_identity;

#define SUPERVISED_FOREST_CAPACITY 4096

typedef struct supervised_forest {
    process_identity entries[SUPERVISED_FOREST_CAPACITY];
    size_t count;
} supervised_forest;

static volatile sig_atomic_t received_signal = 0;

static void record_signal(int signal_number) {
    received_signal = signal_number;
}

static uint64_t monotonic_milliseconds(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return 0;
    return (uint64_t)value.tv_sec * 1000 + (uint64_t)value.tv_nsec / 1000000;
}

static void sleep_milliseconds(unsigned milliseconds) {
    struct timespec delay = {
        .tv_sec = milliseconds / 1000,
        .tv_nsec = (long)(milliseconds % 1000) * 1000000
    };
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR && received_signal == 0) {}
}

static int valid_environment_assignment(const char *assignment) {
    const char *equals = strchr(assignment, '=');
    if (equals == NULL || equals == assignment) return 0;
    for (const char *cursor = assignment; cursor < equals; ++cursor) {
        int initial = cursor == assignment;
        int letter = (*cursor >= 'A' && *cursor <= 'Z') || (*cursor >= 'a' && *cursor <= 'z');
        int digit = *cursor >= '0' && *cursor <= '9';
        if (!(letter || *cursor == '_' || (!initial && digit))) return 0;
    }
    return 1;
}

static void apply_environment_assignment(const char *assignment) {
    const char *equals = strchr(assignment, '=');
    char *name = strndup(assignment, (size_t)(equals - assignment));
    if (name == NULL) fail_errno(EX_OSERR, "allocate environment name");
    if (setenv(name, equals + 1, 1) != 0) {
        free(name);
        fail_errno(EX_OSERR, "set child environment");
    }
    free(name);
}

static void resolve_from_original_path(
    const char *command,
    const char *original_path,
    char resolved[PATH_MAX]
) {
    if (command == NULL || command[0] == '\0' || strchr(command, '/') != NULL) {
        fail(EX_USAGE, "service and client commands must be bare names resolved through CONTINUUM_ORIGINAL_PATH");
    }
    if (original_path == NULL || original_path[0] == '\0') {
        fail(EX_CONFIG, "CONTINUUM_ORIGINAL_PATH is missing");
    }

    const char *cursor = original_path;
    for (;;) {
        const char *separator = strchr(cursor, ':');
        size_t directory_length = separator == NULL ? strlen(cursor) : (size_t)(separator - cursor);
        if (directory_length == 0 || cursor[0] != '/') {
            fail(EX_CONFIG, "CONTINUUM_ORIGINAL_PATH must contain only nonempty absolute directories");
        }
        char candidate[PATH_MAX];
        if (directory_length + 1 + strlen(command) + 1 <= sizeof(candidate)) {
            memcpy(candidate, cursor, directory_length);
            candidate[directory_length] = '/';
            strcpy(candidate + directory_length + 1, command);
            if (access(candidate, X_OK) == 0 && realpath(candidate, resolved) != NULL) return;
        }
        if (separator == NULL) break;
        cursor = separator + 1;
        if (*cursor == '\0') {
            fail(EX_CONFIG, "CONTINUUM_ORIGINAL_PATH must contain only nonempty absolute directories");
        }
    }
    fprintf(stderr, "ContinuumManagedExec: command not found in CONTINUUM_ORIGINAL_PATH: %s\n", command);
    exit(EX_NOINPUT);
}

static void parse_tcp_endpoint(const char *value, readiness_endpoint *endpoint) {
    const char *host_start = value;
    const char *host_end = NULL;
    const char *port = NULL;
    if (value[0] == '[') {
        host_start = value + 1;
        host_end = strchr(host_start, ']');
        if (host_end == NULL || host_end[1] != ':') fail(EX_USAGE, "invalid --ready-tcp HOST:PORT");
        port = host_end + 2;
    } else {
        port = strrchr(value, ':');
        if (port == NULL) fail(EX_USAGE, "invalid --ready-tcp HOST:PORT");
        host_end = port;
        port += 1;
    }
    if (host_end == host_start || port[0] == '\0') fail(EX_USAGE, "invalid --ready-tcp HOST:PORT");
    char *end = NULL;
    long number = strtol(port, &end, 10);
    if (*end != '\0' || number < 1 || number > 65535) fail(EX_USAGE, "invalid --ready-tcp port");

    char *host = strndup(host_start, (size_t)(host_end - host_start));
    if (host == NULL) fail_errno(EX_OSERR, "allocate readiness host");
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = IPPROTO_TCP
    };
    int error = getaddrinfo(host, port, &hints, &endpoint->tcp_addresses);
    free(host);
    if (error != 0) {
        fprintf(stderr, "ContinuumManagedExec: resolve readiness endpoint: %s\n", gai_strerror(error));
        exit(EX_USAGE);
    }
    endpoint->kind = READINESS_TCP;
}

static void parse_unix_endpoint(const char *value, readiness_endpoint *endpoint) {
    size_t length = strlen(value);
    if (value[0] != '/' || length >= sizeof(endpoint->unix_address.sun_path)) {
        fail(EX_USAGE, "--ready-unix requires an absolute socket path that fits sockaddr_un");
    }
    memset(&endpoint->unix_address, 0, sizeof(endpoint->unix_address));
    endpoint->unix_address.sun_family = AF_UNIX;
    memcpy(endpoint->unix_address.sun_path, value, length + 1);
    endpoint->unix_length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + length + 1);
    endpoint->kind = READINESS_UNIX;
}

static int connect_with_timeout(
    int descriptor,
    const struct sockaddr *address,
    socklen_t length,
    int timeout
) {
    int flags = fcntl(descriptor, F_GETFL, 0);
    if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) != 0) return 0;
    if (connect(descriptor, address, length) == 0) return 1;
    if (errno != EINPROGRESS) return 0;
    struct pollfd event = { .fd = descriptor, .events = POLLOUT };
    int result;
    do result = poll(&event, 1, timeout); while (result < 0 && errno == EINTR && received_signal == 0);
    int socket_error = 0;
    socklen_t error_length = sizeof(socket_error);
    return result > 0 && getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &socket_error, &error_length) == 0 &&
           socket_error == 0;
}

static int endpoint_is_live(const readiness_endpoint *endpoint, int timeout) {
    if (endpoint->kind == READINESS_UNIX) {
        int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
        if (descriptor < 0) return 0;
        int live = connect_with_timeout(
            descriptor,
            (const struct sockaddr *)&endpoint->unix_address,
            endpoint->unix_length,
            timeout
        );
        close(descriptor);
        return live;
    }
    for (const struct addrinfo *address = endpoint->tcp_addresses; address != NULL; address = address->ai_next) {
        int descriptor = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (descriptor < 0) continue;
        int live = connect_with_timeout(
            descriptor,
            address->ai_addr,
            (socklen_t)address->ai_addrlen,
            timeout
        );
        close(descriptor);
        if (live) return 1;
    }
    return 0;
}

static supervised_child spawn_supervised(const char *executable, char *const arguments[]) {
    posix_spawnattr_t attributes = NULL;
    int error = posix_spawnattr_init(&attributes);
    sigset_t defaults;
    sigemptyset(&defaults);
    sigaddset(&defaults, SIGPIPE);
    if (error == 0) {
        error = posix_spawnattr_setflags(
            &attributes,
            POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGDEF
        );
    }
    if (error == 0) error = posix_spawnattr_setpgroup(&attributes, 0);
    if (error == 0) error = posix_spawnattr_setsigdefault(&attributes, &defaults);
    pid_t process = 0;
    if (error == 0) error = posix_spawn(&process, executable, NULL, &attributes, arguments, environ);
    if (attributes != NULL) posix_spawnattr_destroy(&attributes);
    if (error != 0) errno = error;
    return (supervised_child){ .process = error == 0 ? process : -1, .reaped = 0, .status = 0 };
}

static int reap_nonblocking(supervised_child *child) {
    if (child->process <= 0 || child->reaped) return 1;
    pid_t result;
    do result = waitpid(child->process, &child->status, WNOHANG); while (result < 0 && errno == EINTR);
    if (result == child->process || (result < 0 && errno == ECHILD)) child->reaped = 1;
    return child->reaped;
}

static int read_process_information(pid_t process, struct proc_bsdinfo *information) {
    int size = proc_pidinfo(
        process,
        PROC_PIDTBSDINFO,
        0,
        information,
        (int)sizeof(*information)
    );
    return size == sizeof(*information) && information->pbi_pid == (uint32_t)process;
}

static int read_process_identity(pid_t process, process_identity *identity) {
    struct proc_bsdinfo information;
    if (!read_process_information(process, &information)) return 0;
    *identity = (process_identity){
        .process = process,
        .start_seconds = information.pbi_start_tvsec,
        .start_microseconds = information.pbi_start_tvusec
    };
    return 1;
}

static int identity_is_live(const process_identity *identity) {
    process_identity current;
    return read_process_identity(identity->process, &current) &&
           current.start_seconds == identity->start_seconds &&
           current.start_microseconds == identity->start_microseconds;
}

static void forest_add_process(supervised_forest *forest, pid_t process) {
    if (process <= 0 || forest->count >= SUPERVISED_FOREST_CAPACITY) return;
    for (size_t index = 0; index < forest->count; ++index) {
        if (forest->entries[index].process == process) return;
    }
    process_identity identity;
    if (read_process_identity(process, &identity)) forest->entries[forest->count++] = identity;
}

static void forest_add_child(
    supervised_forest *forest,
    pid_t process,
    const process_identity *parent
) {
    if (process <= 0 || forest->count >= SUPERVISED_FOREST_CAPACITY) return;
    for (size_t index = 0; index < forest->count; ++index) {
        if (forest->entries[index].process == process) return;
    }
    if (!identity_is_live(parent)) return;
    struct proc_bsdinfo information;
    if (!read_process_information(process, &information) ||
        information.pbi_ppid != (uint32_t)parent->process ||
        !identity_is_live(parent)) return;
    forest->entries[forest->count++] = (process_identity){
        .process = process,
        .start_seconds = information.pbi_start_tvsec,
        .start_microseconds = information.pbi_start_tvusec
    };
}

static void forest_refresh(
    supervised_forest *forest,
    const supervised_child *left,
    const supervised_child *right
) {
    forest_add_process(forest, left->process);
    forest_add_process(forest, right->process);
    for (size_t index = 0; index < forest->count && forest->count < SUPERVISED_FOREST_CAPACITY; ++index) {
        if (!identity_is_live(&forest->entries[index])) continue;
        int capacity = proc_listchildpids(forest->entries[index].process, NULL, 0);
        if (capacity <= 0) continue;
        capacity += 16;
        pid_t *children = calloc((size_t)capacity, sizeof(pid_t));
        if (children == NULL) continue;
        int count = proc_listchildpids(
            forest->entries[index].process,
            children,
            capacity * (int)sizeof(pid_t)
        );
        for (int child = 0; child < count; ++child) {
            forest_add_child(forest, children[child], &forest->entries[index]);
        }
        free(children);
    }
}

static void forest_signal(supervised_forest *forest, int signal_number) {
    for (size_t index = forest->count; index > 0; --index) {
        process_identity *identity = &forest->entries[index - 1];
        if (identity_is_live(identity)) kill(identity->process, signal_number);
    }
}

static int forest_has_live_processes(const supervised_forest *forest) {
    for (size_t index = 0; index < forest->count; ++index) {
        if (identity_is_live(&forest->entries[index])) return 1;
    }
    return 0;
}

static void terminate_and_reap(
    supervised_child *left,
    supervised_child *right,
    supervised_forest *forest
) {
    supervised_child *children[] = { left, right };
    forest_refresh(forest, left, right);
    forest_signal(forest, SIGTERM);
    uint64_t deadline = monotonic_milliseconds() + 2000;
    while (monotonic_milliseconds() < deadline) {
        size_t previous_count = forest->count;
        forest_refresh(forest, left, right);
        for (size_t index = previous_count; index < forest->count; ++index) {
            if (identity_is_live(&forest->entries[index])) kill(forest->entries[index].process, SIGTERM);
        }
        int done = 1;
        for (size_t index = 0; index < 2; ++index) {
            if (!reap_nonblocking(children[index])) done = 0;
        }
        if (forest_has_live_processes(forest)) done = 0;
        if (done) return;
        sleep_milliseconds(20);
    }
    forest_refresh(forest, left, right);
    forest_signal(forest, SIGKILL);
    for (size_t index = 0; index < 2; ++index) {
        if (children[index]->process <= 0 || children[index]->reaped) continue;
        while (waitpid(children[index]->process, &children[index]->status, 0) < 0 && errno == EINTR) {}
        children[index]->reaped = 1;
    }
}

static int child_exit_code(const supervised_child *child) {
    if (WIFEXITED(child->status)) return WEXITSTATUS(child->status);
    if (WIFSIGNALED(child->status)) return 128 + WTERMSIG(child->status);
    return EX_SOFTWARE;
}

static int run_service_supervisor(int argc, char *argv[]) {
    readiness_endpoint endpoint = {0};
    const char *environment_assignments[128];
    size_t environment_count = 0;
    int index = 2;
    while (index < argc && strcmp(argv[index], "--") != 0) {
        if (strcmp(argv[index], "--env") == 0) {
            if (++index >= argc || !valid_environment_assignment(argv[index])) {
                fail(EX_USAGE, "--env requires KEY=VALUE with a valid environment name");
            }
            if (environment_count == sizeof(environment_assignments) / sizeof(environment_assignments[0])) {
                fail(EX_USAGE, "too many --env options");
            }
            environment_assignments[environment_count++] = argv[index++];
        } else if (strcmp(argv[index], "--ready-tcp") == 0) {
            if (endpoint.kind != READINESS_NONE || ++index >= argc) {
                fail(EX_USAGE, "exactly one readiness selector is required");
            }
            parse_tcp_endpoint(argv[index++], &endpoint);
        } else if (strcmp(argv[index], "--ready-unix") == 0) {
            if (endpoint.kind != READINESS_NONE || ++index >= argc) {
                fail(EX_USAGE, "exactly one readiness selector is required");
            }
            parse_unix_endpoint(argv[index++], &endpoint);
        } else {
            fail(EX_USAGE, "unknown continuum-with-service option");
        }
    }
    if (endpoint.kind == READINESS_NONE || index >= argc || strcmp(argv[index], "--") != 0) {
        fail(EX_USAGE, "usage: continuum-with-service [--env KEY=VALUE] (--ready-tcp HOST:PORT | --ready-unix PATH) -- SERVICE [ARGS...] ::: CLIENT [ARGS...]; SERVICE must remain in the foreground");
    }
    int service_index = ++index;
    int separator_index = -1;
    for (; index < argc; ++index) {
        if (strcmp(argv[index], ":::") == 0) {
            if (separator_index >= 0) fail(EX_USAGE, "continuum-with-service requires exactly one ::: separator");
            separator_index = index;
        }
    }
    if (separator_index <= service_index || separator_index + 1 >= argc) {
        fail(EX_USAGE, "continuum-with-service requires nonempty SERVICE and CLIENT commands");
    }

    const char *original_path = getenv("CONTINUUM_ORIGINAL_PATH");
    char service_source[PATH_MAX];
    char client_source[PATH_MAX];
    resolve_from_original_path(argv[service_index], original_path, service_source);
    resolve_from_original_path(argv[separator_index + 1], original_path, client_source);

    char service_managed[PATH_MAX];
    char client_managed[PATH_MAX];
    prepare_managed_executable(service_source, service_managed);
    prepare_managed_executable(client_source, client_managed);
    for (size_t assignment = 0; assignment < environment_count; ++assignment) {
        apply_environment_assignment(environment_assignments[assignment]);
    }

    if (endpoint_is_live(&endpoint, 150)) fail(EX_UNAVAILABLE, "readiness endpoint is already live");

    argv[separator_index] = NULL;
    char **service_arguments = &argv[service_index];
    char **client_arguments = &argv[separator_index + 1];

    struct sigaction action = {0};
    action.sa_handler = record_signal;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGHUP, &action, NULL);
    sigaction(SIGQUIT, &action, NULL);
    signal(SIGPIPE, SIG_IGN);

    supervised_child service = spawn_supervised(service_managed, service_arguments);
    supervised_child client = {0};
    supervised_forest forest = {0};
    if (service.process < 0) fail_errno(EX_OSERR, "launch managed service");
    forest_refresh(&forest, &service, &client);

    uint64_t readiness_deadline = monotonic_milliseconds() + 10000;
    while (!endpoint_is_live(&endpoint, 50)) {
        forest_refresh(&forest, &service, &client);
        if (reap_nonblocking(&service)) {
            terminate_and_reap(&service, &client, &forest);
            fail(EX_UNAVAILABLE, "service exited or daemonized before readiness; SERVICE must remain in the foreground");
        }
        if (received_signal != 0) {
            int signal_number = received_signal;
            terminate_and_reap(&service, &client, &forest);
            return 128 + signal_number;
        }
        if (monotonic_milliseconds() >= readiness_deadline) {
            terminate_and_reap(&service, &client, &forest);
            fail(EX_TEMPFAIL, "service did not become ready before the deadline");
        }
        sleep_milliseconds(25);
    }
    if (reap_nonblocking(&service)) {
        terminate_and_reap(&service, &client, &forest);
        fail(EX_UNAVAILABLE, "service exited or daemonized before readiness; SERVICE must remain in the foreground");
    }

    client = spawn_supervised(client_managed, client_arguments);
    if (client.process < 0) {
        int saved_errno = errno;
        terminate_and_reap(&service, &client, &forest);
        errno = saved_errno;
        fail_errno(EX_OSERR, "launch managed client");
    }
    forest_refresh(&forest, &service, &client);
    for (;;) {
        forest_refresh(&forest, &service, &client);
        if (reap_nonblocking(&client)) {
            int result = child_exit_code(&client);
            terminate_and_reap(&service, &client, &forest);
            if (endpoint.tcp_addresses != NULL) freeaddrinfo(endpoint.tcp_addresses);
            return result;
        }
        if (reap_nonblocking(&service)) {
            terminate_and_reap(&service, &client, &forest);
            fail(EX_UNAVAILABLE, "service exited while the client was running");
        }
        if (received_signal != 0) {
            int signal_number = received_signal;
            terminate_and_reap(&service, &client, &forest);
            return 128 + signal_number;
        }
        sleep_milliseconds(20);
    }
}

int main(int argc, char *argv[]) {
    if (argc >= 2 && strcmp(argv[1], "--continuum-with-service") == 0) {
        return run_service_supervisor(argc, argv);
    }
    if (argc < 2) fail(EX_USAGE, "usage: ContinuumManagedExec <Mach-O executable> [arguments ...]");

    char final_path[PATH_MAX];
    prepare_managed_executable(argv[1], final_path);
    execve(final_path, &argv[1], environ);
    fail_errno(EX_OSERR, "execute managed copy");
}
