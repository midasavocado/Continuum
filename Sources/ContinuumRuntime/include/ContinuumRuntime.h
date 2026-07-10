#ifndef CONTINUUM_RUNTIME_H
#define CONTINUUM_RUNTIME_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum continuum_status {
    CONTINUUM_STATUS_OK = 0,
    CONTINUUM_STATUS_INVALID_ARGUMENT = 1,
    CONTINUUM_STATUS_OUT_OF_MEMORY = 2,
    CONTINUUM_STATUS_MACH_ERROR = 3,
    CONTINUUM_STATUS_CHECKPOINT_NOT_FOUND = 4,
    CONTINUUM_STATUS_RANGE_ERROR = 5
} continuum_status;

typedef struct continuum_runtime_info {
    uint64_t page_size;
    uint64_t region_count;
    uint64_t readable_region_count;
    uint64_t writable_region_count;
    uint64_t executable_region_count;
    uint64_t virtual_bytes;
    uint64_t writable_bytes;
    uint64_t thread_count;
} continuum_runtime_info;

typedef struct continuum_tracked_region continuum_tracked_region;

continuum_status continuum_runtime_inspect_self(continuum_runtime_info *out_info);

continuum_status continuum_tracked_region_create(
    void *address,
    size_t length,
    continuum_tracked_region **out_region
);

continuum_status continuum_tracked_region_checkpoint(
    continuum_tracked_region *region,
    uint64_t *out_checkpoint_id
);

continuum_status continuum_tracked_region_restore(
    continuum_tracked_region *region,
    uint64_t checkpoint_id
);

size_t continuum_tracked_region_checkpoint_count(
    const continuum_tracked_region *region
);

void continuum_tracked_region_destroy(continuum_tracked_region *region);

const char *continuum_status_string(continuum_status status);

#ifdef __cplusplus
}
#endif

#endif
