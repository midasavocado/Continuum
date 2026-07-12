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
    CONTINUUM_STATUS_THREAD_RESTORE_FAILED = 23,
    CONTINUUM_STATUS_DESCRIPTOR_TABLE_CHANGED = 24,
    CONTINUUM_STATUS_MACH_NAMESPACE_CHANGED = 25,
    CONTINUUM_STATUS_UNSUPPORTED_DESCRIPTOR = 26,
    CONTINUUM_STATUS_PROCESS_TREE_CHANGED = 27
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
typedef struct continuum_remote_process_group_snapshot
    continuum_remote_process_group_snapshot;

/// Runs while every member of a process group remains coherently suspended.
/// The callback must not resume or mutate process topology. Returning a failure
/// aborts capture, resumes every task, and destroys the incomplete snapshot.
typedef continuum_status (*continuum_remote_resource_capture_callback)(
    const continuum_remote_process_group_snapshot *snapshot,
    void *context
);

/// Runs after memory/thread state has been applied but before any group member
/// resumes. A failure triggers the runtime's all-member memory rollback; the
/// callback owns rollback of any external resource bytes it changed.
typedef continuum_status (*continuum_remote_resource_restore_callback)(
    const continuum_remote_process_group_snapshot *snapshot,
    void *context
);

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

typedef struct continuum_remote_resource_fingerprint {
    uint64_t file_descriptor_count;
    uint64_t vnode_count;
    uint64_t socket_count;
    uint64_t pipe_count;
    uint64_t kqueue_count;
    uint64_t shared_memory_count;
    uint64_t semaphore_count;
    uint64_t guarded_descriptor_count;
    uint64_t unsupported_descriptor_count;
    uint64_t descriptor_table_hash;
    uint64_t mach_name_count;
    uint64_t mach_send_right_count;
    uint64_t mach_receive_right_count;
    uint64_t mach_send_once_right_count;
    uint64_t mach_port_set_count;
    uint64_t mach_dead_name_count;
    uint64_t mach_space_hash;
    uint64_t thread_count;
    uint64_t thread_set_hash;
} continuum_remote_resource_fingerprint;

typedef struct continuum_remote_process_group_snapshot_info {
    uint64_t process_count;
    uint64_t captured_region_count;
    uint64_t captured_bytes;
    uint64_t excluded_region_count;
    uint64_t excluded_bytes;
    uint64_t thread_count;
} continuum_remote_process_group_snapshot_info;

typedef struct continuum_remote_process_group_member_info {
    int32_t process_id;
    int32_t parent_process_id;
    uint64_t start_seconds;
    uint64_t start_microseconds;
    uint64_t executable_device;
    uint64_t executable_inode;
    uint64_t captured_region_count;
    uint64_t captured_bytes;
    uint64_t thread_count;
    uint64_t vm_layout_hash;
    uint64_t thread_set_hash;
    uint64_t file_descriptor_count;
    uint64_t descriptor_table_hash;
    uint64_t mach_name_count;
    uint64_t mach_space_hash;
} continuum_remote_process_group_member_info;

typedef struct continuum_remote_process_group_restore_report {
    uint64_t processes_restored;
    uint64_t regions_written;
    uint64_t bytes_written;
    uint64_t thread_states_restored;
    uint8_t memory_readback_verified;
    uint8_t rollback_attempted;
    uint8_t rollback_verified;
} continuum_remote_process_group_restore_report;

#define CONTINUUM_REMOTE_PATH_MAX 4096

typedef struct continuum_remote_writable_vnode_info {
    int32_t process_id;
    int32_t file_descriptor;
    uint32_t open_flags;
    int64_t offset;
    uint64_t device;
    uint64_t inode;
    uint64_t byte_count;
    uint32_t mode;
    char path[CONTINUUM_REMOTE_PATH_MAX];
} continuum_remote_writable_vnode_info;

typedef enum continuum_resource_change {
    CONTINUUM_RESOURCE_CHANGE_NONE = 0,
    CONTINUUM_RESOURCE_CHANGE_DESCRIPTOR_TABLE = 1 << 0,
    CONTINUUM_RESOURCE_CHANGE_MACH_SPACE = 1 << 1,
    CONTINUUM_RESOURCE_CHANGE_THREAD_SET = 1 << 2,
    CONTINUUM_RESOURCE_CHANGE_UNSUPPORTED_DESCRIPTOR = 1 << 3
} continuum_resource_change;

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

/// Captures a read-only kernel-resource fingerprint while an external target
/// is suspended. It inventories descriptor topology, vnode identity/offsets,
/// Mach right topology, and thread identities. It does not serialize resource
/// contents and therefore acts as a certification/restore guard, not a restore
/// mechanism by itself.
continuum_status continuum_remote_session_capture_resource_fingerprint(
    continuum_remote_session *session,
    continuum_remote_resource_fingerprint *out_fingerprint
);

uint32_t continuum_remote_resource_fingerprint_changes(
    const continuum_remote_resource_fingerprint *saved,
    const continuum_remote_resource_fingerprint *current
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

/// Captures the root process and every descendant as one coherent hot group.
/// Continuum discovers the tree, opens and pins every task, suspends the group
/// root-first, verifies membership again, then captures each process while all
/// members remain stopped. A membership race retries internally and otherwise
/// fails closed. The returned object owns the hot task sessions needed later.
continuum_status continuum_remote_process_group_capture(
    int32_t root_process_id,
    uint64_t maximum_captured_bytes,
    continuum_remote_process_group_snapshot **out_snapshot,
    continuum_remote_process_group_snapshot_info *out_info
);

/// Captures the process group and invokes `callback` during the same coherent
/// suspension cut. This is the integration point for file, IPC, window, GPU,
/// audio, and device checkpoint adapters.
continuum_status continuum_remote_process_group_capture_with_resources(
    int32_t root_process_id,
    uint64_t maximum_captured_bytes,
    continuum_remote_resource_capture_callback callback,
    void *callback_context,
    continuum_remote_process_group_snapshot **out_snapshot,
    continuum_remote_process_group_snapshot_info *out_info
);

/// Invokes a resource callback while the captured process group is coherently
/// suspended and its membership is unchanged. No process memory is modified.
continuum_status continuum_remote_process_group_with_suspended_resources(
    continuum_remote_process_group_snapshot *snapshot,
    continuum_remote_resource_capture_callback callback,
    void *callback_context
);

/// Restores a hot process group only while the exact original tasks, parent
/// relationships, VM layouts, resource fingerprints, and thread identities
/// remain present. All safety cuts validate before the first write. A partial
/// multi-process write rolls every touched member back before resuming them.
continuum_status continuum_remote_process_group_restore(
    continuum_remote_process_group_snapshot *snapshot,
    continuum_remote_process_group_restore_report *out_report
);

/// Restores memory/thread state and invokes `callback` before the group resumes.
/// A callback failure rolls process memory back to the pre-restore safety cut.
continuum_status continuum_remote_process_group_restore_with_resources(
    continuum_remote_process_group_snapshot *snapshot,
    continuum_remote_resource_restore_callback callback,
    void *callback_context,
    continuum_remote_process_group_restore_report *out_report
);

size_t continuum_remote_process_group_member_count(
    const continuum_remote_process_group_snapshot *snapshot
);

/// Verifies that every process captured by the live snapshot still refers to
/// the exact original process identity. This does not suspend or mutate it.
continuum_status continuum_remote_process_group_live_status(
    const continuum_remote_process_group_snapshot *snapshot
);

continuum_status continuum_remote_process_group_copy_member_info(
    const continuum_remote_process_group_snapshot *snapshot,
    size_t index,
    continuum_remote_process_group_member_info *out_info
);

/// Copies every regular vnode opened for writing by any captured group member.
/// A null `entries` with zero capacity returns the required count. Call only
/// from a coherent resource callback while the group is suspended.
continuum_status continuum_remote_process_group_copy_writable_vnodes(
    const continuum_remote_process_group_snapshot *snapshot,
    continuum_remote_writable_vnode_info *entries,
    size_t entry_capacity,
    size_t *out_entry_count
);

size_t continuum_remote_process_group_member_region_count(
    const continuum_remote_process_group_snapshot *snapshot,
    size_t member_index
);

continuum_status continuum_remote_process_group_copy_member_region_info(
    const continuum_remote_process_group_snapshot *snapshot,
    size_t member_index,
    size_t region_index,
    continuum_remote_process_region_info *out_info
);

/// Copies captured bytes from one process-tree region. A null destination with
/// zero capacity reports the required length without copying.
continuum_status continuum_remote_process_group_copy_member_region_bytes(
    const continuum_remote_process_group_snapshot *snapshot,
    size_t member_index,
    size_t region_index,
    void *destination,
    size_t destination_capacity,
    size_t *out_required_length
);

continuum_status continuum_remote_process_group_copy_member_region_bytes_range(
    const continuum_remote_process_group_snapshot *snapshot,
    size_t member_index,
    size_t region_index,
    uint64_t offset,
    void *destination,
    size_t length
);

size_t continuum_remote_process_group_member_thread_count(
    const continuum_remote_process_group_snapshot *snapshot,
    size_t member_index
);

continuum_status continuum_remote_process_group_copy_member_thread_info(
    const continuum_remote_process_group_snapshot *snapshot,
    size_t member_index,
    size_t thread_index,
    continuum_remote_thread_state_info *out_info
);

continuum_status continuum_remote_process_group_copy_member_thread_general_state(
    const continuum_remote_process_group_snapshot *snapshot,
    size_t member_index,
    size_t thread_index,
    void *destination,
    size_t destination_capacity,
    size_t *out_required_length
);

continuum_status continuum_remote_process_group_copy_member_thread_vector_state(
    const continuum_remote_process_group_snapshot *snapshot,
    size_t member_index,
    size_t thread_index,
    void *destination,
    size_t destination_capacity,
    size_t *out_required_length
);

void continuum_remote_process_group_snapshot_destroy(
    continuum_remote_process_group_snapshot *snapshot
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
