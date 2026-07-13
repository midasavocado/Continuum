#include "ContinuumBootstrap.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

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
    int descriptor = (int)descriptor_value;
    struct stat metadata;
    if (fstat(descriptor, &metadata) != 0
        || !S_ISREG(metadata.st_mode)
        || metadata.st_uid != geteuid()
        || metadata.st_nlink != 0
        || (metadata.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO))
            != (S_IRUSR | S_IWUSR)
        || metadata.st_size != 0
        || ftruncate(descriptor, 0) != 0
        || lseek(descriptor, 0, SEEK_SET) != 0) {
        close(descriptor);
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
    Dl_info image;
    memset(&image, 0, sizeof(image));
    if (dladdr((void *)copy_address, &image) == 0
        || image.dli_fbase == NULL) {
        close(descriptor);
        return;
    }
    uintptr_t image_base = (uintptr_t)image.dli_fbase;
    if (copy_address <= image_base) {
        close(descriptor);
        return;
    }

    char report[192];
    int length = snprintf(
        report,
        sizeof(report),
        "CONTINUUM_BOOTSTRAP_V2 %d 0x%llx 0x%llx\n",
        getpid(),
        (unsigned long long)image_base,
        (unsigned long long)copy_address
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
    const char *requested = getenv("CONTINUUM_BOOTSTRAP_STOP");
    if (requested == NULL || strcmp(requested, "1") != 0) {
        return;
    }
    continuum_bootstrap_report_copy_address();
    unsetenv("CONTINUUM_BOOTSTRAP_DESCRIPTOR_FD");
    unsetenv("CONTINUUM_BOOTSTRAP_STOP");
    (void)kill(getpid(), SIGSTOP);
}
