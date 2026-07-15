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

#ifdef __cplusplus
}
#endif

#endif
