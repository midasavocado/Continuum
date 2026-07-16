#ifndef CONTINUUM_RUNTIME_H
#define CONTINUUM_RUNTIME_H

#include <stddef.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <termios.h>

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
    CONTINUUM_STATUS_PROCESS_TREE_CHANGED = 27,
    CONTINUUM_STATUS_SPAWN_FAILED = 28,
    CONTINUUM_STATUS_FILE_WRITER_CONFLICT = 29
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
typedef struct continuum_remote_descriptor_graph
    continuum_remote_descriptor_graph;

typedef struct continuum_bootstrap_identity {
    uint64_t image_base;
    uint64_t copy_address;
    uint64_t copy_offset;
    uint64_t pthread_prepare_address;
    uint64_t pthread_prepare_offset;
    uint64_t pty_safepoint_status_address;
    uint64_t pty_safepoint_status_offset;
    uint8_t image_uuid[16];
} continuum_bootstrap_identity;

typedef struct continuum_sha256_digest {
    uint8_t bytes[32];
} continuum_sha256_digest;

/// One launch-time descriptor relocation. The source descriptor belongs to
/// the Continuum controller; the target descriptor is the exact number the
/// replacement process must observe before its first instruction executes.
typedef struct continuum_spawn_descriptor_remap {
    int32_t source_descriptor;
    int32_t target_descriptor;
} continuum_spawn_descriptor_remap;

enum { CONTINUUM_SPAWN_DESCRIPTOR_REMAP_LIMIT = 256 };

typedef enum continuum_spawn_process_group_policy {
    CONTINUUM_SPAWN_PROCESS_GROUP_INHERIT = 0,
    CONTINUUM_SPAWN_PROCESS_GROUP_CREATE = 1,
    CONTINUUM_SPAWN_PROCESS_GROUP_JOIN = 2
} continuum_spawn_process_group_policy;

/// Kernel topology applied before the replacement executes target code.
/// A new session necessarily creates a process group led by the child, so
/// `create_session` requires `CONTINUUM_SPAWN_PROCESS_GROUP_CREATE`.
///
/// For the suspended-spawn APIs below, `controlling_terminal_descriptor` must
/// be -1. Darwin applies posix_spawn file actions before POSIX_SPAWN_SETSID, so
/// those calls fail closed with CONTINUUM_STATUS_UNSUPPORTED_DESCRIPTOR. The
/// brokered API accepts the field because its constructor calls `TIOCSCTTY`
/// after creating the replacement session.
typedef struct continuum_spawn_process_topology {
    uint32_t structure_size;
    uint32_t create_session;
    continuum_spawn_process_group_policy process_group_policy;
    int32_t process_group_id;
    int32_t controlling_terminal_descriptor;
} continuum_spawn_process_topology;

typedef struct continuum_brokered_process_spec {
    uint32_t structure_size;
    int32_t captured_process_id;
    int32_t captured_process_group_id;
    int32_t foreground_process_group_id;
    const char *executable_path;
    const char *const *arguments;
    const char *const *environment;
    const char *working_directory;
    const continuum_spawn_descriptor_remap *descriptor_remaps;
    size_t descriptor_remap_count;
    continuum_spawn_process_topology topology;
    uint8_t disable_aslr;
} continuum_brokered_process_spec;

typedef struct continuum_brokered_pair continuum_brokered_pair;

typedef enum continuum_brokered_process_role {
    CONTINUUM_BROKERED_PROCESS_ROOT = 1,
    CONTINUUM_BROKERED_PROCESS_CHILD = 2
} continuum_brokered_process_role;

/// Prepares a root and one direct child behind ContinuumBootstrap constructor
/// gates. The root creates its requested session before receiving a PTY slave,
/// establishes the controlling terminal, then launches the child itself. This
/// preserves real PPID/SID/PGID topology without executing target `main`.
///
/// A child JOIN policy may name the root's captured process identifier; it is
/// translated to the replacement root's process group. Descriptor sources are
/// transferred only through an inherited, unguessable socketpair capability.
continuum_status continuum_brokered_pair_prepare(
    const char *bootstrap_library_path,
    const continuum_brokered_process_spec *root,
    const continuum_brokered_process_spec *child,
    continuum_brokered_pair **out_pair
);

continuum_status continuum_brokered_pair_process_identifiers(
    const continuum_brokered_pair *pair,
    int32_t *out_root_process_id,
    int32_t *out_child_process_id
);

/// Moves the child and then the root from their constructor broker gates to
/// authenticated executable-entry stops. The child keeps its real root PPID;
/// the opaque capability authorizes Continuum to attach to that non-child PID.
/// Ownership remains with the caller on both success and failure. After a
/// successful transition, authorize each replacement session through
/// `continuum_brokered_pair_authorize_remote_session`, then either finish the
/// fully released pair or abort it.
continuum_status continuum_brokered_pair_advance_to_entry_stops(
    continuum_brokered_pair *pair,
    uint32_t timeout_milliseconds
);

/// Binds a stopped replacement session to the authenticated pair identity and
/// records whether its stop is controller-ptrace-owned (root) or a brokered
/// signal stop (child). This must precede remote reconstruction.
continuum_status continuum_brokered_pair_authorize_remote_session(
    continuum_brokered_pair *pair,
    continuum_remote_session *session,
    continuum_brokered_process_role role
);

/// Records a successful per-process remote-session release. `finish` refuses
/// to consume the pair until both exact replacement identities were released.
continuum_status continuum_brokered_pair_note_released_process(
    continuum_brokered_pair *pair,
    int32_t process_id
);

continuum_status continuum_brokered_pair_finish(
    continuum_brokered_pair *pair
);

/// Releases both constructor gates child-first. Ownership of the now-running
/// replacements transfers to the caller and the opaque pair is destroyed.
continuum_status continuum_brokered_pair_release(
    continuum_brokered_pair *pair
);

/// Aborts both gates, kills/reaps the direct child in the broker, then reaps
/// the root in the controller. The opaque pair is always destroyed.
continuum_status continuum_brokered_pair_abort(
    continuum_brokered_pair *pair,
    uint32_t timeout_milliseconds
);

/// Creates a clean replacement process from a captured launch contract and
/// leaves it kernel-suspended before any target instruction executes.
continuum_status continuum_spawn_process_suspended(
    const char *executable_path,
    const char *const arguments[],
    const char *const environment[],
    const char *working_directory,
    int32_t *out_process_id
);

/// Launches a direct child normally. `disable_aslr` applies Continuum's
/// deterministic address policy without stopping the child before main.
continuum_status continuum_spawn_process(
    const char *executable_path,
    const char *const arguments[],
    const char *const environment[],
    const char *working_directory,
    int disable_aslr,
    int32_t *out_process_id
);

/// Waits until a direct child enters a SIGSTOP gate without resuming it.
continuum_status continuum_wait_for_process_stop(
    int32_t process_id,
    uint32_t timeout_milliseconds
);

/// The descriptor remains open in the child despite
/// POSIX_SPAWN_CLOEXEC_DEFAULT. Continuum uses this for a private, unlinked
/// bootstrap handshake instead of trusting a pathname that another process
/// could replace.
continuum_status continuum_spawn_process_suspended_with_inherited_descriptor(
    const char *executable_path,
    const char *const arguments[],
    const char *const environment[],
    const char *working_directory,
    int32_t inherited_descriptor,
    int32_t *out_process_id
);

/// Inherits the private bootstrap descriptor and duplicates controller-owned
/// socket, pipe, or PTY descriptors onto their captured descriptor numbers.
/// Targets must be unique and must not collide with the bootstrap descriptor
/// or another remap's source descriptor.
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
);

/// Preserves normal macOS ASLR for a replacement captured from an app that
/// was not launched under Continuum's deterministic address-space policy.
continuum_status
continuum_spawn_process_suspended_with_inherited_descriptor_system_aslr(
    const char *executable_path,
    const char *const arguments[],
    const char *const environment[],
    const char *working_directory,
    int32_t inherited_descriptor,
    int32_t *out_process_id
);

/// System-ASLR form of the multi-descriptor suspended spawn contract.
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
);

/// Topology-aware form of the deterministic-ASLR suspended spawn contract.
/// Descriptor remaps remain exact and are installed before target code runs.
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
);

/// System-ASLR form of the topology-aware suspended spawn contract.
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
);

/// Loads ContinuumBootstrap locally and resolves its exact exported copy
/// symbol to a Mach-O UUID and image-relative offset.
continuum_status continuum_inspect_local_bootstrap_library(
    const char *library_path,
    continuum_bootstrap_identity *out_identity
);

/// Terminates and reaps a direct child, including a child currently stopped
/// under ptrace at Continuum's executable-entry boundary.
continuum_status continuum_terminate_direct_child(
    int32_t process_id,
    uint32_t timeout_milliseconds
);

/// Advances a direct child from the kernel's initial spawn stop to the
/// SIGSTOP raised by ContinuumBootstrap's dyld constructor. Success means the
/// loader finished mapping launch-time images and app main has not executed.
continuum_status continuum_advance_process_to_bootstrap_stop(
    int32_t process_id,
    uint32_t timeout_milliseconds
);

/// Advances a constructor-stopped direct child through dyld cleanup and stops
/// it on an ARM64 hardware breakpoint at its LC_MAIN entry. The executable's
/// first instruction has not run when this succeeds.
continuum_status continuum_advance_process_to_entry_stop(
    int32_t process_id,
    uint32_t timeout_milliseconds
);

/// Detaches from a direct child stopped at Continuum's executable-entry
/// boundary and lets it continue from its currently installed thread state.
continuum_status continuum_release_entry_stopped_child(
    int32_t process_id
);

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
    uint64_t observed_mapping_address;
    uint64_t observed_mapping_length;
    uint8_t readback_verified;
    uint8_t rollback_attempted;
    uint8_t rollback_verified;
    uint8_t max_protection_verified;
    uint32_t reconstruction_stage;
    int32_t mach_result;
    int32_t observed_protection;
    int32_t observed_maximum_protection;
    int32_t observed_inheritance;
    uint32_t observed_share_mode;
    uint32_t observed_user_tag;
    uint64_t observed_offset;
    uint16_t observed_flags;
    uint8_t observed_external_pager;
} continuum_remote_restore_report;

typedef struct continuum_remote_thread_reconstruction_report {
    uint64_t replacement_thread_identifier;
    uint64_t general_state_bytes;
    uint64_t vector_state_bytes;
    uint8_t general_state_verified;
    uint8_t vector_state_verified;
} continuum_remote_thread_reconstruction_report;
typedef struct continuum_remote_thread_reconstruction_input {
    uint64_t saved_thread_identifier;
    uint64_t thread_handle;
    uint64_t dispatch_queue_address;
    uint32_t general_state_flavor;
    const void *general_state;
    size_t general_state_length;
    uint32_t vector_state_flavor;
    const void *vector_state;
    size_t vector_state_length;
} continuum_remote_thread_reconstruction_input;

typedef struct continuum_remote_thread_set_reconstruction_report {
    uint64_t reconstructed_thread_count;
    uint64_t created_raw_thread_count;
    uint64_t general_state_bytes;
    uint64_t vector_state_bytes;
    uint64_t primary_replacement_thread_identifier;
    uint64_t validation_thread_index;
    uint64_t validation_address;
    uint32_t validation_kind;
    uint8_t all_states_verified;
    uint8_t rollback_attempted;
    uint8_t rollback_verified;
} continuum_remote_thread_set_reconstruction_report;

enum { CONTINUUM_REMOTE_PTHREAD_LIMIT = 64 };

typedef struct continuum_remote_pthread_bootstrap_report {
    uint32_t version;
    uint32_t requested_count;
    uint32_t created_count;
    int32_t error_code;
    uint64_t primary_pthread_address;
    uint64_t primary_thread_identifier;
    uint64_t primary_thread_handle;
    uint64_t primary_stack_base_address;
    uint64_t primary_stack_length;
    uint64_t primary_stack_region_address;
    uint64_t primary_stack_region_length;
    uint64_t primary_pthread_region_address;
    uint64_t primary_pthread_region_length;
    uint64_t pthread_addresses[CONTINUUM_REMOTE_PTHREAD_LIMIT];
    uint64_t thread_identifiers[CONTINUUM_REMOTE_PTHREAD_LIMIT];
    uint64_t thread_handles[CONTINUUM_REMOTE_PTHREAD_LIMIT];
    uint64_t stack_base_addresses[CONTINUUM_REMOTE_PTHREAD_LIMIT];
    uint64_t stack_lengths[CONTINUUM_REMOTE_PTHREAD_LIMIT];
    uint64_t stack_region_addresses[CONTINUUM_REMOTE_PTHREAD_LIMIT];
    uint64_t stack_region_lengths[CONTINUUM_REMOTE_PTHREAD_LIMIT];
    uint64_t pthread_region_addresses[CONTINUUM_REMOTE_PTHREAD_LIMIT];
    uint64_t pthread_region_lengths[CONTINUUM_REMOTE_PTHREAD_LIMIT];
} continuum_remote_pthread_bootstrap_report;

enum { CONTINUUM_PTHREAD_PLAN_LIMIT = CONTINUUM_REMOTE_PTHREAD_LIMIT + 1 };

typedef struct continuum_saved_pthread_geometry {
    uint64_t saved_thread_identifier;
    uint64_t pthread_address;
    uint64_t stack_pointer;
    uint64_t stack_region_address;
    uint64_t stack_region_length;
    uint64_t pthread_region_address;
    uint64_t pthread_region_length;
} continuum_saved_pthread_geometry;

typedef struct continuum_pthread_reconstruction_plan_entry {
    uint64_t saved_thread_identifier;
    uint64_t replacement_thread_identifier;
    uint64_t replacement_thread_handle;
    uint64_t pthread_address;
    uint64_t stack_copy_address;
    uint64_t stack_copy_length;
    uint64_t preserved_pthread_address;
    uint64_t preserved_pthread_length;
    uint8_t is_primary;
} continuum_pthread_reconstruction_plan_entry;

typedef struct continuum_pthread_reconstruction_plan {
    uint32_t entry_count;
    uint64_t primary_saved_thread_identifier;
    uint64_t stack_copy_bytes;
    uint64_t preserved_pthread_bytes;
    continuum_pthread_reconstruction_plan_entry
        entries[CONTINUUM_PTHREAD_PLAN_LIMIT];
} continuum_pthread_reconstruction_plan;


typedef enum continuum_reconstruction_stage {
    CONTINUUM_RECONSTRUCTION_STAGE_NONE = 0,
    CONTINUUM_RECONSTRUCTION_STAGE_DEALLOCATE = 1,
    CONTINUUM_RECONSTRUCTION_STAGE_ALLOCATE = 2,
    CONTINUUM_RECONSTRUCTION_STAGE_WRITE = 3,
    CONTINUUM_RECONSTRUCTION_STAGE_READBACK = 4,
    CONTINUUM_RECONSTRUCTION_STAGE_INHERIT = 5,
    CONTINUUM_RECONSTRUCTION_STAGE_PROTECT = 6,
    CONTINUUM_RECONSTRUCTION_STAGE_MAX_PROTECT = 7
} continuum_reconstruction_stage;

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
    continuum_sha256_digest immutable_layout_digest;
    uint64_t thread_set_hash;
} continuum_remote_process_snapshot_info;

typedef struct continuum_remote_process_layout_info {
    uint64_t region_count;
    uint64_t virtual_bytes;
    uint64_t layout_hash;
    continuum_sha256_digest immutable_layout_digest;
} continuum_remote_process_layout_info;

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
    uint8_t is_app_owned_state;
    uint8_t preserves_live_derived_graphics;
} continuum_remote_process_region_info;

typedef enum continuum_remote_thread_origin {
    CONTINUUM_REMOTE_THREAD_ORIGIN_UNKNOWN = 0,
    CONTINUUM_REMOTE_THREAD_ORIGIN_RAW_MACH = 1,
    CONTINUUM_REMOTE_THREAD_ORIGIN_PTHREAD = 2,
    CONTINUUM_REMOTE_THREAD_ORIGIN_WORKQUEUE = 3
} continuum_remote_thread_origin;

typedef struct continuum_remote_thread_state_info {
    uint64_t thread_identifier;
    uint64_t thread_handle;
    uint64_t pthread_object_address;
    uint64_t dispatch_queue_address;
    uint64_t stack_pointer;
    continuum_remote_thread_origin origin;
    uint32_t general_state_flavor;
    size_t general_state_length;
    uint32_t vector_state_flavor;
    size_t vector_state_length;
    uint8_t is_userspace_safepoint;
    uint8_t preserves_kernel_continuation;
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
    continuum_sha256_digest immutable_layout_digest;
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

#define CONTINUUM_REMOTE_SOCKET_ADDRESS_MAX 32

/// Stable metadata for one established IPv4 or IPv6 TCP descriptor. Address
/// bytes contain a native `sockaddr_in` or `sockaddr_in6`; opaque kernel socket
/// pointers are deliberately excluded so persisted records remain portable
/// across replacement processes.
typedef struct continuum_remote_tcp_endpoint_info {
    int32_t process_id;
    int32_t file_descriptor;
    int32_t domain;
    int32_t socket_type;
    int32_t protocol;
    int32_t tcp_state;
    uint32_t socket_state;
    uint32_t local_address_length;
    uint32_t remote_address_length;
    uint8_t receive_shutdown;
    uint8_t send_shutdown;
    uint8_t reserved[2];
    uint64_t receive_queue_bytes;
    uint64_t send_queue_bytes;
    uint8_t local_address[CONTINUUM_REMOTE_SOCKET_ADDRESS_MAX];
    uint8_t remote_address[CONTINUUM_REMOTE_SOCKET_ADDRESS_MAX];
} continuum_remote_tcp_endpoint_info;

typedef enum continuum_remote_descriptor_resource_kind {
    CONTINUUM_REMOTE_DESCRIPTOR_RESOURCE_SOCKET = 1,
    CONTINUUM_REMOTE_DESCRIPTOR_RESOURCE_PIPE = 2,
    CONTINUUM_REMOTE_DESCRIPTOR_RESOURCE_KQUEUE = 3
} continuum_remote_descriptor_resource_kind;

typedef struct continuum_remote_descriptor_handle_info {
    uint64_t resource_identity;
    int32_t process_id;
    int32_t file_descriptor;
    int32_t descriptor_flags;
    int32_t status_flags;
    continuum_remote_descriptor_resource_kind resource_kind;
} continuum_remote_descriptor_handle_info;

typedef enum continuum_remote_socket_kind {
    CONTINUUM_REMOTE_SOCKET_TCP_LISTENER = 1,
    CONTINUUM_REMOTE_SOCKET_TCP_CONNECTED = 2,
    CONTINUUM_REMOTE_SOCKET_UNIX_LISTENER = 3,
    CONTINUUM_REMOTE_SOCKET_UNIX_CONNECTED = 4
} continuum_remote_socket_kind;

#define CONTINUUM_REMOTE_DESCRIPTOR_ADDRESS_MAX 256

typedef struct continuum_remote_socket_resource_info {
    uint64_t resource_identity;
    uint64_t peer_identity;
    uint64_t listener_identity;
    continuum_remote_socket_kind kind;
    int32_t domain;
    int32_t socket_type;
    int32_t protocol;
    uint32_t socket_state;
    uint32_t local_address_length;
    uint32_t remote_address_length;
    uint8_t receive_shutdown;
    uint8_t send_shutdown;
    uint8_t reserved[2];
    uint64_t receive_queue_bytes;
    uint64_t send_queue_bytes;
    int32_t backlog;
    uint8_t local_address[CONTINUUM_REMOTE_DESCRIPTOR_ADDRESS_MAX];
    uint8_t remote_address[CONTINUUM_REMOTE_DESCRIPTOR_ADDRESS_MAX];
} continuum_remote_socket_resource_info;

typedef struct continuum_remote_pipe_resource_info {
    uint64_t resource_identity;
    uint64_t peer_identity;
    uint64_t capacity;
    uint64_t queued_bytes;
    uint32_t status;
} continuum_remote_pipe_resource_info;

typedef struct continuum_remote_kqueue_resource_info {
    uint64_t resource_identity;
    int32_t process_id;
    uint32_t state;
    uint64_t registration_start;
    uint64_t registration_count;
} continuum_remote_kqueue_resource_info;

typedef struct continuum_remote_kqueue_registration_info {
    uint64_t resource_identity;
    uint64_t ident;
    int16_t filter;
    uint16_t flags;
    uint32_t fflags;
    int64_t data;
    uint64_t udata;
    uint32_t qos;
    int64_t saved_data;
    uint32_t status;
} continuum_remote_kqueue_registration_info;

typedef enum continuum_remote_pty_role {
    CONTINUUM_REMOTE_PTY_ROLE_UNKNOWN = 0,
    CONTINUUM_REMOTE_PTY_ROLE_MASTER = 1,
    CONTINUUM_REMOTE_PTY_ROLE_SLAVE = 2
} continuum_remote_pty_role;

/// Stable userspace metadata for one descriptor backed by a real macOS PTY.
/// `alias_identity` groups descriptors for the same PTY endpoint across
/// captured processes; independent opens of that endpoint are intentionally
/// grouped because libproc cannot distinguish them from dup/inherited aliases.
/// It is not a reusable kernel object identifier. Queue counts are valid only
/// when their corresponding `*_known` byte is nonzero.
typedef struct continuum_remote_pty_descriptor_info {
    int32_t process_id;
    int32_t file_descriptor;
    uint32_t open_flags;
    continuum_remote_pty_role role;
    uint64_t device;
    uint64_t inode;
    uint64_t raw_device;
    uint32_t device_major;
    uint32_t device_minor;
    uint32_t tty_index;
    uint64_t alias_identity;
    uint64_t input_queue_bytes;
    uint64_t output_queue_bytes;
    uint8_t input_queue_known;
    uint8_t output_queue_known;
    uint8_t terminal_attributes_known;
    uint8_t window_size_known;
    struct termios terminal_attributes;
    struct winsize window_size;
} continuum_remote_pty_descriptor_info;

/// Whole-forest result from the in-process PTY safepoint handshake. `known`
/// is true only when every captured member published a current authenticated
/// report and every FIONREAD/TIOCOUTQ query succeeded. No queue payload is
/// read or consumed while producing this result.
typedef struct continuum_remote_pty_safepoint_status {
    uint64_t process_count;
    uint64_t pty_descriptor_count;
    uint8_t queue_state_known;
    uint8_t all_queues_zero;
} continuum_remote_pty_safepoint_status;

/// Recreates one closed, reverse-matched loopback TCP pair for later remapping
/// into replacement processes. Both captured processes must be absent and both
/// queues must have been empty. Exact saved ports are attempted first; TIME_WAIT
/// falls back to fresh loopback ports, so callers restoring observable socket
/// identity must virtualize getsockname/getpeername. Success transfers two
/// CLOEXEC descriptors to the caller in the same order as the endpoint records.
continuum_status continuum_recreate_closed_loopback_tcp_pair(
    const continuum_remote_tcp_endpoint_info *first_endpoint,
    const continuum_remote_tcp_endpoint_info *second_endpoint,
    int32_t *out_first_descriptor,
    int32_t *out_second_descriptor
);

/// Creates a fresh PTY master/slave pair from matching saved endpoint records.
/// Saved queued bytes are not replayed. Success transfers two owned CLOEXEC
/// descriptors to the caller, master first and slave second.
continuum_status continuum_recreate_closed_pty_pair(
    const continuum_remote_pty_descriptor_info *master_descriptor,
    const continuum_remote_pty_descriptor_info *slave_descriptor,
    int32_t *out_master_descriptor,
    int32_t *out_slave_descriptor
);

/// Recreates a PTY when the captured workload owns only slave descriptors and
/// its terminal emulator (the derived presentation process) owned the master.
/// The returned master stays controller-owned for attachment to a fresh UI.
continuum_status continuum_recreate_closed_pty_from_slave(
    const continuum_remote_pty_descriptor_info *slave_descriptor,
    int32_t *out_master_descriptor,
    int32_t *out_slave_descriptor
);

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

/// Hashes the complete leaf VM map without reading process memory. This is
/// used to prove deterministic replacement layouts before reconstruction.
continuum_status continuum_remote_session_inspect_process_layout(
    continuum_remote_session *session,
    continuum_remote_process_layout_info *out_info
);

/// Validates one exact existing mapping without mutating it. Rehydration uses
/// this narrower invariant for pointer-free tagged state instead of requiring
/// unrelated lazily loaded AppKit images to be identical.
continuum_status continuum_remote_session_region_matches(
    continuum_remote_session *session,
    const continuum_remote_process_region_info *region,
    uint8_t *out_matches
);

/// Reports whether an exact address range is entirely unmapped in a stopped
/// replacement. GUI rehydration uses this to distinguish a safe sparse-arena
/// hole from an incompatible live mapping before reconstruction.
continuum_status continuum_remote_session_range_is_unmapped(
    continuum_remote_session *session,
    uint64_t address,
    uint64_t length,
    uint8_t *out_is_unmapped
);

/// Recreates one private writable mapping inside a replacement child that is
/// still stopped before main. The child is disposable; failures never touch
/// the original process or any unrelated task.
continuum_status continuum_remote_session_reconstruct_region(
    continuum_remote_session *session,
    const continuum_remote_process_region_info *region,
    const void *bytes,
    size_t length,
    continuum_remote_restore_report *out_report
);

/// Allocates one saved mapping without materializing its complete contents in
/// the controller. Callers may then stream chunks with
/// continuum_remote_session_write_reconstructed_region before finalizing the
/// saved inheritance and access protections.
continuum_status continuum_remote_session_begin_reconstruct_region(
    continuum_remote_session *session,
    const continuum_remote_process_region_info *region,
    continuum_remote_restore_report *out_report
);

/// Registers the exact ContinuumBootstrap symbol after verifying its remote
/// Mach-O UUID, image-relative offset, load record, path, and executable map.
/// It is used only when XNU refuses an external Mach write to an otherwise
/// writable, non-overwritable mapping.
continuum_status continuum_remote_session_set_bootstrap_copy_identity(
    continuum_remote_session *session,
    const continuum_bootstrap_identity *identity,
    const char *expected_library_path
);

/// Calls the authenticated bootstrap inside a disposable entry-stopped child,
/// creates ordinary pthreads with one libpthread suspension each, and validates
/// their kernel identities and writable stack-allocation geometry. A failure
/// after remote execution is terminal for that disposable child.
continuum_status continuum_remote_session_prepare_suspended_pthreads(
    continuum_remote_session *session,
    uint32_t requested_count,
    continuum_remote_pthread_bootstrap_report *out_report
);

/// Requires exact primary/worker pthread and mapping addresses. It plans only
/// stack-byte transplantation and explicitly preserves live libpthread
/// metadata; callers must not interpret a successful plan as a complete
/// pthread/TSD restore.
continuum_status continuum_plan_exact_pthread_reconstruction(
    const continuum_saved_pthread_geometry *saved,
    size_t saved_count,
    const continuum_remote_pthread_bootstrap_report *replacement,
    continuum_pthread_reconstruction_plan *out_plan
);

/// Writes and immediately reads back bytes only within an exact stack-copy
/// range from a validated prepared-pthread plan. The runtime revalidates the
/// entry against the pthread set it created and refuses every byte of live
/// libpthread metadata.
continuum_status continuum_remote_session_write_prepared_pthread_stack(
    continuum_remote_session *session,
    const continuum_pthread_reconstruction_plan_entry *entry,
    uint64_t offset,
    const void *bytes,
    size_t length,
    continuum_remote_restore_report *out_report
);

/// Writes and immediately reads back one bounded range of a mapping prepared
/// by continuum_remote_session_begin_reconstruct_region.
continuum_status continuum_remote_session_write_reconstructed_region(
    continuum_remote_session *session,
    const continuum_remote_process_region_info *region,
    uint64_t offset,
    const void *bytes,
    size_t length,
    continuum_remote_restore_report *out_report
);

/// Applies the saved inheritance and current/max protection policy after all
/// chunks have been written. macOS may require the later in-process restorer
/// to narrow the maximum-protection ceiling.
continuum_status continuum_remote_session_finish_reconstruct_region(
    continuum_remote_session *session,
    const continuum_remote_process_region_info *region,
    continuum_remote_restore_report *out_report
);

/// Replaces the user-visible ARM64 and NEON state of the sole thread in a
/// direct-child replacement that remains stopped under Continuum. This is a
/// reconstruction proof only: it does not resume the process, recreate kernel
/// wait state, or claim that resource restoration is complete.
continuum_status continuum_remote_session_reconstruct_single_thread(
    continuum_remote_session *session,
    uint32_t general_state_flavor,
    const void *general_state,
    size_t general_state_length,
    uint32_t vector_state_flavor,
    const void *vector_state,
    size_t vector_state_length,
    continuum_remote_thread_reconstruction_report *out_report
);
/// Reconstructs a captured thread set whose sole pthread-compatible primary
/// matches the replacement entry thread's kernel TSD handle and whose remaining
/// members are deliberately raw Mach threads with no pthread or dispatch
/// identity. The disposable child remains task-suspended until
/// continuum_remote_session_release_entry_stopped_child commits it.
continuum_status continuum_remote_session_reconstruct_raw_thread_set(
    continuum_remote_session *session,
    const continuum_remote_thread_reconstruction_input *threads,
    size_t thread_count,
    continuum_remote_thread_set_reconstruction_report *out_report
);

/// Reconstructs a captured thread set after preparing an exact replacement
/// pthread set. Inputs with a nonzero thread handle must match one prepared
/// pthread exactly; inputs with both a zero handle and zero dispatch identity
/// are recreated as raw Mach threads. Every state write is read back, and a
/// failure restores all modified pthread states and terminates every raw thread
/// created by this call.
continuum_status continuum_remote_session_reconstruct_prepared_thread_set(
    continuum_remote_session *session,
    const continuum_remote_thread_reconstruction_input *threads,
    size_t thread_count,
    continuum_remote_thread_set_reconstruction_report *out_report
);

/// Detaches a reconstructed direct child from ptrace while its task suspension
/// still prevents any reconstructed thread from running, then releases exactly
/// the suspension owned by Continuum. This is the commit boundary for a thread
/// set reconstructed by either thread-set reconstruction function above.
continuum_status continuum_remote_session_release_entry_stopped_child(
    continuum_remote_session *session,
    int32_t process_id
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

/// Captures the union of every explicit root and all of their descendants as
/// one coherent hot group. Duplicate and overlapping roots are deduplicated;
/// members are captured with parents before children. PID 1, the caller, and
/// non-positive roots are rejected.
continuum_status continuum_remote_process_group_capture_roots(
    const int32_t root_process_ids[],
    size_t root_process_count,
    uint64_t maximum_captured_bytes,
    continuum_remote_process_group_snapshot **out_snapshot,
    continuum_remote_process_group_snapshot_info *out_info
);

/// Authenticates ContinuumBootstrap in every captured member by canonical
/// path and Mach-O UUID, then reads its image-relative PTY status export.
/// Every member must still be inside the userspace safepoint represented by
/// the snapshot. The authenticated report's pthread thread identifier must
/// occur exactly once in the captured thread set; released or stale
/// generations fail validation.
continuum_status continuum_remote_process_group_copy_pty_safepoint_status(
    const continuum_remote_process_group_snapshot *snapshot,
    const char *bootstrap_library_path,
    continuum_remote_pty_safepoint_status *out_status
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

/// Multi-root form of `continuum_remote_process_group_capture_with_resources`.
/// The callback runs only after the entire process forest is open, suspended,
/// and revalidated against a fresh process-table view.
continuum_status continuum_remote_process_group_capture_roots_with_resources(
    const int32_t root_process_ids[],
    size_t root_process_count,
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

/// Reports whether a live process loaded ContinuumBootstrap and created its
/// isolated app-state malloc zone. The controller uses this as a fail-closed
/// preflight before sending bootstrap-only safepoint signals.
continuum_status continuum_remote_process_has_app_state_zone(
    int32_t process_id,
    uint8_t *out_has_app_state_zone
);

/// Authenticates that `library_path` is loaded in the target by comparing its
/// canonical dyld image path and Mach-O UUID. Unlike malloc_get_all_zones,
/// this remains valid when the target has a privately slid shared region.
continuum_status continuum_remote_process_has_bootstrap(
    int32_t process_id,
    const char *library_path,
    uint8_t *out_has_bootstrap
);

continuum_status continuum_remote_process_group_copy_member_info(
    const continuum_remote_process_group_snapshot *snapshot,
    size_t index,
    continuum_remote_process_group_member_info *out_info
);

/// Copies the native KERN_PROCARGS2 payload for the captured member. The blob
/// contains argc, executable path, argv, and environment in launch order.
continuum_status continuum_remote_process_group_copy_member_procargs(
    const continuum_remote_process_group_snapshot *snapshot,
    size_t member_index,
    void *destination,
    size_t destination_capacity,
    size_t *out_required_length
);

continuum_status continuum_remote_process_group_copy_member_working_directory(
    const continuum_remote_process_group_snapshot *snapshot,
    size_t member_index,
    void *destination,
    size_t destination_capacity,
    size_t *out_required_length
);

/// Returns FILE_WRITER_CONFLICT when another visible process has the exact
/// regular vnode at `path` open for writing. `allowed_process_id` may identify
/// Continuum's stopped replacement. Access-denied inspection fails closed.
continuum_status continuum_find_writable_vnode_conflict(
    const char *path,
    int32_t allowed_process_id,
    int32_t *out_conflicting_process_id
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

/// Copies established IPv4/IPv6 TCP descriptors owned by captured members.
/// A null `entries` with zero capacity measures the required count. Call only
/// while the process forest is coherently suspended (for example from a
/// resource callback); this function observes but never reads or mutates queue
/// contents. Local peers can be paired by reverse-matching the two sockaddr
/// byte sequences.
continuum_status continuum_remote_process_group_copy_tcp_endpoints(
    const continuum_remote_process_group_snapshot *snapshot,
    continuum_remote_tcp_endpoint_info *entries,
    size_t entry_capacity,
    size_t *out_entry_count
);

/// Captures the socket, pipe, and ordinary fd-backed kqueue graph while the
/// process forest is coherently suspended. The opaque graph owns only copied
/// metadata; it never reads queue payloads or retains kernel object pointers.
/// Unsupported or ambiguous resources fail closed.
continuum_status continuum_remote_process_group_capture_descriptor_graph(
    const continuum_remote_process_group_snapshot *snapshot,
    continuum_remote_descriptor_graph **out_graph
);

size_t continuum_remote_descriptor_graph_handle_count(
    const continuum_remote_descriptor_graph *graph
);

size_t continuum_remote_descriptor_graph_socket_count(
    const continuum_remote_descriptor_graph *graph
);

size_t continuum_remote_descriptor_graph_pipe_count(
    const continuum_remote_descriptor_graph *graph
);

size_t continuum_remote_descriptor_graph_kqueue_count(
    const continuum_remote_descriptor_graph *graph
);

size_t continuum_remote_descriptor_graph_kqueue_registration_count(
    const continuum_remote_descriptor_graph *graph
);

continuum_status continuum_remote_descriptor_graph_copy_handles(
    const continuum_remote_descriptor_graph *graph,
    continuum_remote_descriptor_handle_info *entries,
    size_t entry_capacity
);

continuum_status continuum_remote_descriptor_graph_copy_sockets(
    const continuum_remote_descriptor_graph *graph,
    continuum_remote_socket_resource_info *entries,
    size_t entry_capacity
);

continuum_status continuum_remote_descriptor_graph_copy_pipes(
    const continuum_remote_descriptor_graph *graph,
    continuum_remote_pipe_resource_info *entries,
    size_t entry_capacity
);

continuum_status continuum_remote_descriptor_graph_copy_kqueues(
    const continuum_remote_descriptor_graph *graph,
    continuum_remote_kqueue_resource_info *entries,
    size_t entry_capacity
);

continuum_status continuum_remote_descriptor_graph_copy_kqueue_registrations(
    const continuum_remote_descriptor_graph *graph,
    continuum_remote_kqueue_registration_info *entries,
    size_t entry_capacity
);

void continuum_remote_descriptor_graph_destroy(
    continuum_remote_descriptor_graph *graph
);

/// Copies every descriptor backed by a real macOS PTY master or slave. A null
/// `entries` with zero capacity measures the required count. Call only while
/// the process forest is coherently suspended. This function never consumes
/// terminal data and marks queue counts unknown when they cannot be observed
/// without changing the captured descriptor graph.
continuum_status continuum_remote_process_group_copy_pty_descriptors(
    const continuum_remote_process_group_snapshot *snapshot,
    continuum_remote_pty_descriptor_info *entries,
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
