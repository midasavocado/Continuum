#include <CommonCrypto/CommonDigest.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/types.h>
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

int main(int argc, char *argv[]) {
    if (argc < 2) fail(EX_USAGE, "usage: ContinuumManagedExec <Mach-O executable> [arguments ...]");

    uid_t owner = geteuid();
    struct stat path_information;
    if (lstat(argv[1], &path_information) != 0) fail_errno(EX_NOINPUT, "inspect source");
    if (!S_ISREG(path_information.st_mode) || path_information.st_uid != owner ||
        (path_information.st_mode & S_IXUSR) == 0) {
        fail(EX_NOPERM, "source must be a regular, owner-owned executable (symlinks are rejected)");
    }

    int source = open(argv[1], O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
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

    char final_path[PATH_MAX];
    if (snprintf(final_path, sizeof(final_path), "%s/Continuum/ManagedExecutables/%s/executable",
                 support_path, key) >= (int)sizeof(final_path)) {
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

    execve(final_path, &argv[1], environ);
    fail_errno(EX_OSERR, "execute managed copy");
}
