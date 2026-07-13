#include "ContinuumBootstrap.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/mach.h>
#include <pthread.h>
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

static int continuum_bootstrap_pthread_geometry(
    pthread_t thread,
    uint64_t *out_stack_base,
    uint64_t *out_stack_length,
    uint64_t *out_region_address,
    uint64_t *out_region_length
) {
    uintptr_t stack_top = (uintptr_t)pthread_get_stackaddr_np(thread);
    size_t stack_length = pthread_get_stacksize_np(thread);
    uintptr_t pthread_address = (uintptr_t)thread;
    if (stack_top == 0 || stack_length == 0 || stack_length > stack_top
        || pthread_address == 0 || out_stack_base == NULL
        || out_stack_length == NULL || out_region_address == NULL
        || out_region_length == NULL) {
        return EINVAL;
    }

    mach_vm_address_t region_address = pthread_address;
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
    uint64_t stack_base = stack_top - stack_length;
    uint64_t region_end = region_address + region_length;
    if (result != KERN_SUCCESS || region_length == 0
        || region_end < region_address || pthread_address < region_address
        || pthread_address >= region_end
        || (info.protection & (VM_PROT_READ | VM_PROT_WRITE))
            != (VM_PROT_READ | VM_PROT_WRITE)
        || stack_base < region_address
        || stack_top > region_end) {
        return EINVAL;
    }
    *out_stack_base = stack_base;
    *out_stack_length = stack_length;
    *out_region_address = region_address;
    *out_region_length = region_length;
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
        || requested_count == 0
        || requested_count > CONTINUUM_BOOTSTRAP_PTHREAD_LIMIT) {
        return EINVAL;
    }
    memset(report, 0, sizeof(*report));
    report->version = 2;
    report->requested_count = requested_count;

    for (uint32_t index = 0; index < requested_count; index += 1) {
        pthread_t thread = NULL;
        int result = pthread_create_suspended_np(
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

static int continuum_bootstrap_prepare_descriptors(
    int descriptor,
    uint32_t *out_restored_count
) {
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
    continuum_bootstrap_descriptor_record *records = NULL;
    int maximum_target = 63;
    if (plan_length > 0) {
        char *context = NULL;
        char *line = strtok_r(plan, "\n", &context);
        char trailing = '\0';
        if (line == NULL
            || sscanf(
                line,
                "CONTINUUM_FD_PLAN_V1 %u %c",
                &count,
                &trailing
            ) != 1
            || count > CONTINUUM_BOOTSTRAP_MAX_DESCRIPTORS) {
            free(plan);
            close(descriptor);
            return -1;
        }
        records = calloc(count, sizeof(*records));
        if (count > 0 && records == NULL) {
            free(plan);
            close(descriptor);
            return -1;
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
                free(plan);
                close(descriptor);
                return -1;
            }
            records[index].offset = offset;
            records[index].device = device;
            records[index].inode = inode;
            for (uint32_t prior = 0; prior < index; prior += 1) {
                if (records[prior].target_descriptor
                    == records[index].target_descriptor) {
                    free(records);
                    free(plan);
                    close(descriptor);
                    return -1;
                }
            }
            if (records[index].target_descriptor > maximum_target) {
                maximum_target = records[index].target_descriptor;
            }
        }
        if (strtok_r(NULL, "\n", &context) != NULL) {
            free(records);
            free(plan);
            close(descriptor);
            return -1;
        }
    }
    free(plan);

    if (maximum_target == INT_MAX) {
        free(records);
        close(descriptor);
        return -1;
    }
    int report_descriptor = fcntl(
        descriptor,
        F_DUPFD_CLOEXEC,
        maximum_target + 1
    );
    close(descriptor);
    if (report_descriptor < 0) {
        free(records);
        return -1;
    }

    for (uint32_t index = 0; index < count; index += 1) {
        int access_mode = records[index].open_flags & O_ACCMODE;
        if (access_mode != O_WRONLY && access_mode != O_RDWR) {
            free(records);
            close(report_descriptor);
            return -1;
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
            close(report_descriptor);
            return -1;
        }
        if (opened != records[index].target_descriptor) {
            close(opened);
        }
        *out_restored_count += 1;
    }
    free(records);
    if (ftruncate(report_descriptor, 0) != 0
        || lseek(report_descriptor, 0, SEEK_SET) != 0) {
        close(report_descriptor);
        return -1;
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
    int descriptor = continuum_bootstrap_prepare_descriptors(
        (int)descriptor_value,
        &restored_descriptor_count
    );
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
    const char *requested = getenv("CONTINUUM_BOOTSTRAP_STOP");
    if (requested == NULL || strcmp(requested, "1") != 0) {
        return;
    }
    continuum_bootstrap_report_copy_address();
    unsetenv("CONTINUUM_BOOTSTRAP_DESCRIPTOR_FD");
    unsetenv("CONTINUUM_BOOTSTRAP_STOP");
    (void)kill(getpid(), SIGSTOP);
}
