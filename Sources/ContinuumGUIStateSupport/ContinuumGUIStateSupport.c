#include "ContinuumGUIStateSupport.h"

#include <stdlib.h>

__attribute__((noinline))
continuum_gui_state *continuum_gui_state_create(
    uint64_t magic,
    uint64_t counter
) {
    continuum_gui_state *state = calloc(1, sizeof(*state));
    if (state != NULL) {
        state->magic = magic;
        state->counter = counter;
    }
    return state;
}
