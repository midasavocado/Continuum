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

/// Runs on AppKit's main queue until the controller sends the release signal.
/// x28 carries a marker so an external capture can prove it stopped at this
/// user-space continuation instead of inside a Mach syscall.
void continuum_bootstrap_safepoint_spin(void);

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
