#ifndef CONTINUUM_BOOTSTRAP_H
#define CONTINUUM_BOOTSTRAP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

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
    uint64_t pthread_addresses[CONTINUUM_BOOTSTRAP_PTHREAD_LIMIT];
    uint32_t mach_thread_ports[CONTINUUM_BOOTSTRAP_PTHREAD_LIMIT];
} continuum_bootstrap_pthread_report;

/// Creates ordinary pthreads with one libpthread suspension each. On partial
/// failure, every successfully created pthread remains suspended and is
/// described by the report; the owner must either release them or terminate
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
