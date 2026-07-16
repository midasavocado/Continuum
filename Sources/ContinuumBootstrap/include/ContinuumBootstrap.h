#ifndef CONTINUUM_BOOTSTRAP_H
#define CONTINUUM_BOOTSTRAP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum { CONTINUUM_BOOTSTRAP_SAFEPOINT_REGISTER = 28 };
#define CONTINUUM_BOOTSTRAP_SAFEPOINT_MAGIC UINT64_C(0x434F4E5453414645)
#define CONTINUUM_BOOTSTRAP_APP_STATE_ZONE_NAME "ContinuumAppState"
#define CONTINUUM_BOOTSTRAP_PTY_STATUS_MAGIC UINT64_C(0x434F4E5450545951)
#define CONTINUUM_BOOTSTRAP_DESCRIPTOR_STATUS_MAGIC \
    UINT64_C(0x434F4E5446445354)

enum { CONTINUUM_BOOTSTRAP_DESCRIPTOR_STATUS_LIMIT = 1024 };

typedef enum continuum_bootstrap_descriptor_kind {
    CONTINUUM_BOOTSTRAP_DESCRIPTOR_SOCKET = 1,
    CONTINUUM_BOOTSTRAP_DESCRIPTOR_PIPE = 2,
    CONTINUUM_BOOTSTRAP_DESCRIPTOR_KQUEUE = 3
} continuum_bootstrap_descriptor_kind;

typedef struct continuum_bootstrap_descriptor_status_entry {
    int32_t file_descriptor;
    int32_t descriptor_flags;
    int32_t status_flags;
    uint32_t kind;
} continuum_bootstrap_descriptor_status_entry;

typedef struct continuum_bootstrap_descriptor_safepoint_status {
    uint64_t magic;
    uint32_t version;
    uint32_t structure_size;
    uint64_t generation;
    uint32_t descriptor_count;
    uint8_t overflow;
    uint8_t safepoint_active;
    uint8_t reserved[2];
    continuum_bootstrap_descriptor_status_entry
        descriptors[CONTINUUM_BOOTSTRAP_DESCRIPTOR_STATUS_LIMIT];
} continuum_bootstrap_descriptor_safepoint_status;

extern volatile continuum_bootstrap_descriptor_safepoint_status
    continuum_bootstrap_descriptor_safepoint_report;

typedef struct continuum_bootstrap_pty_safepoint_status {
    uint64_t magic;
    uint32_t version;
    uint32_t structure_size;
    uint64_t generation;
    uint64_t safepoint_thread_identifier;
    uint32_t pty_descriptor_count;
    uint8_t queue_state_known;
    uint8_t all_queues_zero;
    uint8_t safepoint_active;
    uint8_t reserved;
} continuum_bootstrap_pty_safepoint_status;

/// Published immediately before either the AppKit run-loop thread or the
/// generic CLI coordinator enters the safepoint spin. Queue depths are
/// observed with FIONREAD/TIOCOUTQ only; Continuum never consumes PTY payload
/// while producing this report.
extern volatile continuum_bootstrap_pty_safepoint_status
    continuum_bootstrap_pty_safepoint_report;

/// Runs on AppKit's main queue or the generic CLI coordinator until the
/// controller sends the release signal. x28 carries a marker so an external
/// capture can prove it stopped at this user-space continuation instead of
/// inside a Mach syscall.
void continuum_bootstrap_safepoint_spin(void);

/// Consumes one private, unlinked descriptor-plan file and applies it to the
/// current process. Success returns the owned report descriptor. V2 replay
/// validation failures return -2 so the pre-main constructor can exit before
/// exposing a partially reconstructed process; other failures return -1.
int continuum_bootstrap_apply_descriptor_plan(
    int descriptor,
    uint32_t *out_restored_count
);

/// Allocates durable model memory from Continuum's isolated app-state zone.
/// The general malloc interposer uses call-site ownership; this explicit entry
/// is also useful to adapters whose language runtime hides the app call site.
/// Cold GUI adapters must store pointer-free or self-relative data here; raw
/// pointers into a fresh AppKit process are intentionally not reconstructed.
void *continuum_bootstrap_allocate_app_state(size_t size);

/// Copies one reconstruction chunk with ordinary in-process stores, then
/// raises a debugger trap without returning. Continuum invokes this only while
/// its disposable replacement is stopped before the app's first instruction.
__attribute__((noreturn))
void continuum_bootstrap_copy_and_trap(
    void *destination,
    const void *source,
    size_t length
);

enum { CONTINUUM_BOOTSTRAP_PTHREAD_LIMIT = 64 };

typedef struct continuum_bootstrap_pthread_report {
    uint32_t version;
    uint32_t requested_count;
    uint32_t created_count;
    int32_t error_code;
    uint64_t primary_pthread_address;
    uint32_t primary_mach_thread_port;
    uint64_t primary_stack_base_address;
    uint64_t primary_stack_length;
    uint64_t primary_stack_region_address;
    uint64_t primary_stack_region_length;
    uint64_t primary_pthread_region_address;
    uint64_t primary_pthread_region_length;
    uint64_t pthread_addresses[CONTINUUM_BOOTSTRAP_PTHREAD_LIMIT];
    uint32_t mach_thread_ports[CONTINUUM_BOOTSTRAP_PTHREAD_LIMIT];
    uint64_t stack_base_addresses[CONTINUUM_BOOTSTRAP_PTHREAD_LIMIT];
    uint64_t stack_lengths[CONTINUUM_BOOTSTRAP_PTHREAD_LIMIT];
    uint64_t stack_region_addresses[CONTINUUM_BOOTSTRAP_PTHREAD_LIMIT];
    uint64_t stack_region_lengths[CONTINUUM_BOOTSTRAP_PTHREAD_LIMIT];
    uint64_t pthread_region_addresses[CONTINUUM_BOOTSTRAP_PTHREAD_LIMIT];
    uint64_t pthread_region_lengths[CONTINUUM_BOOTSTRAP_PTHREAD_LIMIT];
} continuum_bootstrap_pthread_report;

/// Creates ordinary pthreads with one libpthread suspension each. On partial
/// failure, every successfully created pthread remains suspended. The report
/// includes its pthread address, Mach name, usable stack, and containing
/// writable VM region; the owner must either release the threads or terminate
/// the disposable process.
int continuum_bootstrap_prepare_suspended_pthreads(
    continuum_bootstrap_pthread_report *report,
    size_t report_length,
    uint32_t requested_count
);

/// Prepares suspended pthreads and traps without returning so an external
/// controller can inspect the report while the disposable child is stopped.
__attribute__((noreturn))
void continuum_bootstrap_prepare_pthreads_and_trap(
    continuum_bootstrap_pthread_report *report,
    size_t report_length,
    uint32_t requested_count
);

#ifdef __cplusplus
}
#endif

#endif
