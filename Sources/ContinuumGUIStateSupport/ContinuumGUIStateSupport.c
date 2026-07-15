#include "ContinuumGUIStateSupport.h"

#include <pthread.h>
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

typedef struct continuum_gui_worker_context {
    uint64_t magic;
    uint64_t counter;
    continuum_gui_state *state;
} continuum_gui_worker_context;

static void *continuum_gui_state_worker(void *raw_context) {
    continuum_gui_worker_context *context = raw_context;
    context->state = continuum_gui_state_create(
        context->magic,
        context->counter
    );
    return NULL;
}

__attribute__((noinline))
continuum_gui_state *continuum_gui_state_create_on_worker(
    uint64_t magic,
    uint64_t counter
) {
    continuum_gui_worker_context context = {
        .magic = magic,
        .counter = counter,
        .state = NULL,
    };
    pthread_t worker;
    if (pthread_create(
            &worker,
            NULL,
            continuum_gui_state_worker,
            &context
        ) != 0) {
        return NULL;
    }
    if (pthread_join(worker, NULL) != 0) {
        return NULL;
    }
    return context.state;
}
