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
    CONTINUUM_STATUS_RANGE_ERROR = 5,
    CONTINUUM_STATUS_ACCESS_DENIED = 6,
    CONTINUUM_STATUS_TARGET_EXITED = 7,
    CONTINUUM_STATUS_PROCESS_IDENTITY_CHANGED = 8,
    CONTINUUM_STATUS_REGION_UNMAPPED = 9,
    CONTINUUM_STATUS_REGION_PROTECTION_CHANGED = 10,
    CONTINUUM_STATUS_REGION_NOT_PRIVATE = 11,
    CONTINUUM_STATUS_THREAD_SET_CHANGED = 12,
    CONTINUUM_STATUS_SHORT_READ = 13,
    CONTINUUM_STATUS_SHORT_WRITE = 14,
    CONTINUUM_STATUS_VALIDATION_FAILED = 15,
    CONTINUUM_STATUS_ROLLBACK_FAILED = 16,
    CONTINUUM_STATUS_UNSUPPORTED_ARCHITECTURE = 17,
    CONTINUUM_STATUS_SUSPEND_FAILED = 18,
    CONTINUUM_STATUS_RESUME_FAILED = 19,
    CONTINUUM_STATUS_THREAD_STATE_FAILED = 20,
    CONTINUUM_STATUS_REGION_MAPPING_CHANGED = 21,
    CONTINUUM_STATUS_SNAPSHOT_BUDGET_EXCEEDED = 22,
    CONTINUUM_STATUS_THREAD_RESTORE_FAILED = 23
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
typedef struct continuum_remote_session continuum_remote_session;
typedef struct continuum_remote_thread_snapshot continuum_remote_thread_snapshot;
typedef struct continuum_remote_process_snapshot continuum_remote_process_snapshot;

typedef struct continuum_remote_identity {
    int32_t process_id;
    uint64_t start_seconds;
    uint64_t start_microseconds;
    uint64_t executable_device;
    uint64_t executable_inode;
} continuum_remote_identity;

typedef struct continuum_remote_region_descriptor {
    uint64_t address;
    uint64_t length;
    uint64_t mapping_address;
    uint64_t mapping_length;
    int32_t protection;
    int32_t maximum_protection;
    uint32_t share_mode;
    uint64_t thread_set_hash;
} continuum_remote_region_descriptor;

typedef struct continuum_owned_buffer {
    void *bytes;
    size_t length;
} continuum_owned_buffer;

typedef struct continuum_remote_restore_report {
    uint64_t bytes_written;
    uint8_t readback_verified;
    uint8_t rollback_attempted;
    uint8_t rollback_verified;
} continuum_remote_restore_report;

/// Coverage reported for a full-process hot snapshot. Only readable+writable
/// SM_PRIVATE/SM_COW mappings are captured; every other mapping is counted as
/// excluded so callers cannot mistake this for kernel or resource state.
typedef struct continuum_remote_process_snapshot_info {
    uint64_t captured_region_count;
    uint64_t captured_bytes;
    uint64_t excluded_region_count;
    uint64_t excluded_bytes;
    uint64_t thread_count;
    uint64_t vm_layout_hash;
    uint64_t thread_set_hash;
} continuum_remote_process_snapshot_info;

typedef struct continuum_remote_process_restore_report {
    uint64_t regions_written;
    uint64_t bytes_written;
    uint64_t thread_states_restored;
    uint8_t memory_readback_verified;
    uint8_t rollback_attempted;
    uint8_t rollback_verified;
} continuum_remote_process_restore_report;

typedef struct continuum_remote_process_region_info {
    uint64_t address;
    uint64_t length;
    int32_t protection;
    int32_t maximum_protection;
    int32_t inheritance;
    uint32_t share_mode;
    uint32_t user_tag;
} continuum_remote_process_region_info;

typedef struct continuum_remote_thread_state_info {
    uint64_t thread_identifier;
    uint32_t general_state_flavor;
    size_t general_state_length;
    uint32_t vector_state_flavor;
    size_t vector_state_length;
} continuum_remote_thread_state_info;

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

/// Opens a task-port-backed session and pins it to the PID's start time and
/// executable inode. External targets must permit task access; this API does
/// not attempt to bypass SIP or code-signing policy.
continuum_status continuum_remote_session_open(
    int32_t process_id,
    continuum_remote_session **out_session
);

continuum_status continuum_remote_session_identity(
    const continuum_remote_session *session,
    continuum_remote_identity *out_identity
);

/// Registers the only memory range capture and restore may touch. The range
/// must fit within one readable, writable SM_PRIVATE or SM_COW VM region.
continuum_status continuum_remote_session_register_region(
    continuum_remote_session *session,
    uint64_t address,
    uint64_t length
);

/// Suspends an external task, copies the registered bytes, captures thread
/// states as evidence, and resumes the task before returning. Thread states
/// are intentionally never restored by this v0 API.
continuum_status continuum_remote_session_capture(
    continuum_remote_session *session,
    continuum_remote_region_descriptor *out_descriptor,
    continuum_owned_buffer *out_bytes,
    continuum_remote_thread_snapshot **out_threads
);

/// Restores only the registered bytes. The function first captures an
/// emergency rollback copy, validates the process/region/thread-set identity,
/// writes, and reads back. It attempts and verifies rollback on write or
/// validation failure.
continuum_status continuum_remote_session_restore(
    continuum_remote_session *session,
    const continuum_remote_region_descriptor *descriptor,
    const void *bytes,
    size_t length,
    continuum_remote_restore_report *out_report
);

void continuum_remote_session_destroy(continuum_remote_session *session);

size_t continuum_remote_thread_snapshot_count(
    const continuum_remote_thread_snapshot *snapshot
);

continuum_status continuum_remote_thread_snapshot_info(
    const continuum_remote_thread_snapshot *snapshot,
    size_t index,
    continuum_remote_thread_state_info *out_info
);

continuum_status continuum_remote_thread_snapshot_copy_general_state(
    const continuum_remote_thread_snapshot *snapshot,
    size_t index,
    void *destination,
    size_t destination_capacity,
    size_t *out_required_length
);

continuum_status continuum_remote_thread_snapshot_copy_vector_state(
    const continuum_remote_thread_snapshot *snapshot,
    size_t index,
    void *destination,
    size_t destination_capacity,
    size_t *out_required_length
);

void continuum_remote_thread_snapshot_destroy(
    continuum_remote_thread_snapshot *snapshot
);

/// Captures every currently mapped readable+writable private/COW region plus
/// ARM64 general and vector thread state from an external task. The target is
/// suspended only for the coherent cut. This intentionally excludes file
/// descriptors, Mach message queues, sockets, WindowServer, GPU, devices, and
/// kernel state. A zero maximum is invalid; the budget prevents accidental
/// unbounded allocation when probing a large application.
continuum_status continuum_remote_session_capture_process(
    continuum_remote_session *session,
    uint64_t maximum_captured_bytes,
    continuum_remote_process_snapshot **out_snapshot,
    continuum_remote_process_snapshot_info *out_info
);

/// Restores a full-process hot snapshot into the exact still-running task.
/// Before writing, Continuum captures an in-memory safety snapshot. VM layout,
/// process identity, and thread identities must still match. Any failed write,
/// readback, or thread restore triggers a best-effort validated rollback.
continuum_status continuum_remote_session_restore_process(
    continuum_remote_session *session,
    const continuum_remote_process_snapshot *snapshot,
    continuum_remote_process_restore_report *out_report
);

void continuum_remote_process_snapshot_destroy(
    continuum_remote_process_snapshot *snapshot
);

size_t continuum_remote_process_snapshot_region_count(
    const continuum_remote_process_snapshot *snapshot
);

continuum_status continuum_remote_process_snapshot_region_info(
    const continuum_remote_process_snapshot *snapshot,
    size_t index,
    continuum_remote_process_region_info *out_info
);

void continuum_owned_buffer_destroy(continuum_owned_buffer *buffer);

const char *continuum_status_string(continuum_status status);

#ifdef __cplusplus
}
#endif

#endif
