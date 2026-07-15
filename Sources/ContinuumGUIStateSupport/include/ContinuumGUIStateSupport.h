#ifndef CONTINUUM_GUI_STATE_SUPPORT_H
#define CONTINUUM_GUI_STATE_SUPPORT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct continuum_gui_state {
    uint64_t magic;
    uint64_t counter;
} continuum_gui_state;

/// Ordinary application allocation used by the cold-restore acceptance app.
/// This target deliberately knows nothing about Continuum's bootstrap API.
continuum_gui_state *continuum_gui_state_create(
    uint64_t magic,
    uint64_t counter
);

/// Performs the same ordinary allocation from a temporary worker thread and
/// returns only after that worker has exited.
continuum_gui_state *continuum_gui_state_create_on_worker(
    uint64_t magic,
    uint64_t counter
);

/// Creates one app-defined Objective-C model object through the ordinary
/// allocation path and retains it for the lifetime of the proof process.
uintptr_t continuum_gui_object_state_create(
    uint64_t magic,
    uint64_t counter
);
uint64_t continuum_gui_object_state_magic(void);
uint64_t continuum_gui_object_state_counter(void);
void continuum_gui_object_state_add(uint64_t amount);

#ifdef __cplusplus
}
#endif

#endif
