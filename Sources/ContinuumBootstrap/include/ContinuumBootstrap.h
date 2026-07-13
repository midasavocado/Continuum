#ifndef CONTINUUM_BOOTSTRAP_H
#define CONTINUUM_BOOTSTRAP_H

#include <stddef.h>

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

#ifdef __cplusplus
}
#endif

#endif
