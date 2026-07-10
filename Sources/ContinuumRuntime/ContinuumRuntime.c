#include "ContinuumRuntime.h"

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct continuum_checkpoint {
    uint64_t identifier;
    uint8_t *bytes;
} continuum_checkpoint;

struct continuum_tracked_region {
    uint8_t *address;
    size_t length;
    continuum_checkpoint *checkpoints;
    size_t checkpoint_count;
    size_t checkpoint_capacity;
    uint64_t next_identifier;
};

static int continuum_add_u64(uint64_t left, uint64_t right, uint64_t *result) {
    if (UINT64_MAX - left < right) {
        return 0;
    }
    *result = left + right;
    return 1;
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

        if (UINT64_MAX - address < size) {
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
    memcpy(copy, region->address, region->length);

    uint64_t identifier = region->next_identifier;
    if (identifier == UINT64_MAX) {
        free(copy);
        return CONTINUUM_STATUS_RANGE_ERROR;
    }
    region->next_identifier += 1;

    continuum_checkpoint checkpoint = {
        .identifier = identifier,
        .bytes = copy
    };
    region->checkpoints[region->checkpoint_count] = checkpoint;
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
            memcpy(region->address, region->checkpoints[index].bytes, region->length);
            return CONTINUUM_STATUS_OK;
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
    }
    return "unknown status";
}
