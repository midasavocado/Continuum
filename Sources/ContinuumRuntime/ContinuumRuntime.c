#include "ContinuumRuntime.h"

#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/thread_info.h>
#include <mach/vm_region.h>
#if defined(__arm64__)
#include <mach/arm/thread_status.h>
#endif
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define CONTINUUM_WRITE_CHUNK_SIZE (64U * 1024U * 1024U)
#define CONTINUUM_FNV_OFFSET UINT64_C(1469598103934665603)
#define CONTINUUM_FNV_PRIME UINT64_C(1099511628211)
#define CONTINUUM_RESUME_ATTEMPT_LIMIT 3U
#define CONTINUUM_DESTROY_RESUME_ATTEMPT_LIMIT 32U

typedef struct continuum_checkpoint {
    uint64_t identifier;
    uint8_t *bytes;
} continuum_checkpoint;

typedef struct continuum_remote_thread_entry {
    uint64_t identifier;
    uint32_t general_flavor;
    uint8_t *general_bytes;
    size_t general_length;
    uint32_t vector_flavor;
    uint8_t *vector_bytes;
    size_t vector_length;
} continuum_remote_thread_entry;

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
} continuum_remote_process_region;

struct continuum_tracked_region {
    uint8_t *address;
    size_t length;
    continuum_checkpoint *checkpoints;
    size_t checkpoint_count;
    size_t checkpoint_capacity;
    uint64_t next_identifier;
};

struct continuum_remote_session {
    mach_port_t task;
    int owns_task_port;
    int is_self;
    continuum_remote_identity identity;
    continuum_remote_region_descriptor registered_region;
    uint32_t owned_suspend_count;
    int has_registered_region;
};

struct continuum_remote_thread_snapshot {
    continuum_remote_thread_entry *entries;
    size_t count;
    uint64_t set_hash;
};

struct continuum_remote_process_snapshot {
    continuum_remote_identity identity;
    continuum_remote_process_region *regions;
    size_t region_count;
    continuum_remote_thread_snapshot *threads;
    continuum_remote_process_snapshot_info info;
};

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

static uint32_t continuum_canonical_share_mode(uint32_t share_mode) {
    return continuum_is_private_or_cow_share_mode(share_mode)
        ? UINT32_C(1)
        : share_mode;
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
    return continuum_identity_equal(&session->identity, &current)
        ? CONTINUUM_STATUS_OK
        : CONTINUUM_STATUS_PROCESS_IDENTITY_CHANGED;
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
    const uint8_t *source_bytes = source;
    size_t offset = 0;
    while (offset < length) {
        size_t remaining = length - offset;
        size_t chunk = remaining < CONTINUUM_WRITE_CHUNK_SIZE
            ? remaining
            : CONTINUUM_WRITE_CHUNK_SIZE;
        kern_return_t result = mach_vm_write(
            task,
            address + offset,
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
        memset(region, 0, sizeof(*region));
    }
    free(snapshot->regions);
    continuum_remote_thread_snapshot_destroy(snapshot->threads);
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

        const int eligible =
            (info.protection & (VM_PROT_READ | VM_PROT_WRITE))
                == (VM_PROT_READ | VM_PROT_WRITE)
            && continuum_is_private_or_cow_share_mode(info.share_mode);
        continuum_hash_u64(&snapshot->info.vm_layout_hash, address);
        continuum_hash_u64(&snapshot->info.vm_layout_hash, region_size);
        continuum_hash_u64(
            &snapshot->info.vm_layout_hash,
            (uint64_t)(uint32_t)info.protection
        );
        continuum_hash_u64(
            &snapshot->info.vm_layout_hash,
            (uint64_t)(uint32_t)info.max_protection
        );
        continuum_hash_u64(
            &snapshot->info.vm_layout_hash,
            (uint64_t)(uint32_t)info.inheritance
        );
        continuum_hash_u64(
            &snapshot->info.vm_layout_hash,
            continuum_canonical_share_mode(info.share_mode)
        );
        continuum_hash_u64(&snapshot->info.vm_layout_hash, info.user_tag);
        continuum_hash_u64(&snapshot->info.vm_layout_hash, (uint64_t)eligible);

        if (eligible) {
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

            mach_vm_address_t snapshot_address = 0;
            vm_prot_t current_protection = VM_PROT_NONE;
            vm_prot_t maximum_protection = VM_PROT_NONE;
            kern_return_t remap_result = mach_vm_remap(
                mach_task_self(),
                &snapshot_address,
                region_size,
                0,
                VM_FLAGS_ANYWHERE,
                session->task,
                address,
                TRUE,
                &current_protection,
                &maximum_protection,
                VM_INHERIT_NONE
            );
            if (remap_result != KERN_SUCCESS || snapshot_address == 0) {
                status = CONTINUUM_STATUS_MACH_ERROR;
                break;
            }
            remap_result = mach_vm_protect(
                mach_task_self(),
                snapshot_address,
                region_size,
                FALSE,
                VM_PROT_READ
            );
            if (remap_result != KERN_SUCCESS) {
                (void)mach_vm_deallocate(
                    mach_task_self(),
                    snapshot_address,
                    region_size
                );
                status = CONTINUUM_STATUS_MACH_ERROR;
                break;
            }
            region->bytes = (uint8_t *)(uintptr_t)snapshot_address;
            region->is_cow_mapping = 1;

            int *post_capture_dispositions = calloc(
                region->page_count,
                sizeof(*post_capture_dispositions)
            );
            if (post_capture_dispositions == NULL) {
                status = CONTINUUM_STATUS_OUT_OF_MEMORY;
                break;
            }
            status = continuum_query_page_dispositions(
                session->task,
                address,
                region_size,
                post_capture_dispositions,
                region->page_count
            );
            if (status == CONTINUUM_STATUS_OK) {
                for (size_t page = 0; page < region->page_count; page += 1) {
                    region->page_dispositions[page]
                        |= post_capture_dispositions[page];
                }
            }
            free(post_capture_dispositions);
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
        status = continuum_capture_thread_snapshot(
            session->task,
            &snapshot->threads
        );
    }
    if (status == CONTINUUM_STATUS_OK) {
        snapshot->info.thread_count = snapshot->threads->count;
        snapshot->info.thread_set_hash = snapshot->threads->set_hash;
    }
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
        if (region->bytes == NULL || region->length == 0) {
            continue;
        }
        (void)madvise(region->bytes, (size_t)region->length, MADV_WILLNEED);
        for (uint64_t offset = 0; offset < region->length; offset += page_size) {
            sink ^= region->bytes[offset];
        }
    }
    (void)sink;
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
    uint64_t *out_restored_count
) {
    if (task == MACH_PORT_NULL || snapshot == NULL || out_restored_count == NULL) {
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
    if ((size_t)thread_count != snapshot->count) {
        status = CONTINUUM_STATUS_THREAD_SET_CHANGED;
    } else if (thread_count > 0) {
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
        for (mach_msg_type_number_t index = 0; index < thread_count; index += 1) {
            if (entries[index].identifier != snapshot->entries[index].identifier) {
                status = CONTINUUM_STATUS_THREAD_SET_CHANGED;
                break;
            }
        }
    }

    for (mach_msg_type_number_t index = 0;
         status == CONTINUUM_STATUS_OK && index < thread_count;
         index += 1) {
        const continuum_remote_thread_entry *saved = &snapshot->entries[index];
        mach_msg_type_number_t vector_count =
            (mach_msg_type_number_t)(saved->vector_length / sizeof(natural_t));
        result = thread_set_state(
            entries[index].port,
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
            entries[index].port,
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
    if (current->region_count != saved->region_count
        || current->info.captured_region_count != saved->info.captured_region_count
        || current->info.captured_bytes != saved->info.captured_bytes
        || current->info.excluded_region_count != saved->info.excluded_region_count
        || current->info.excluded_bytes != saved->info.excluded_bytes
        || current->info.vm_layout_hash != saved->info.vm_layout_hash) {
        return CONTINUUM_STATUS_REGION_MAPPING_CHANGED;
    }
    if (current->info.thread_count != saved->info.thread_count
        || current->info.thread_set_hash != saved->info.thread_set_hash) {
        return CONTINUUM_STATUS_THREAD_SET_CHANGED;
    }
    for (size_t index = 0; index < saved->region_count; index += 1) {
        if (!continuum_process_region_metadata_equal(
                &current->regions[index],
                &saved->regions[index]
            )) {
            return CONTINUUM_STATUS_REGION_MAPPING_CHANGED;
        }
    }
    return CONTINUUM_STATUS_OK;
}

static continuum_status continuum_apply_process_snapshot(
    mach_port_t task,
    const continuum_remote_process_snapshot *snapshot,
    const continuum_remote_process_snapshot *current,
    continuum_remote_process_restore_report *out_report
) {
    if (task == MACH_PORT_NULL || snapshot == NULL || current == NULL
        || out_report == NULL || snapshot->region_count != current->region_count) {
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
            &current->regions[index];
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
            uint64_t written = 0;
            status = continuum_write_task_bytes(
                task,
                region->address + run_offset,
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
    if (status == CONTINUUM_STATUS_OK) {
        status = continuum_restore_thread_snapshot(
            task,
            snapshot->threads,
            &out_report->thread_states_restored
        );
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
    out_info->thread_identifier = entry->identifier;
    out_info->general_state_flavor = entry->general_flavor;
    out_info->general_state_length = entry->general_length;
    out_info->vector_state_flavor = entry->vector_flavor;
    out_info->vector_state_length = entry->vector_length;
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
    }
    return "unknown status";
}
