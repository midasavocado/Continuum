#include "ContinuumBootstrap.h"

#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach/vm_statistics.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <malloc/malloc.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

static volatile sig_atomic_t continuum_safepoint_release = 0;
static volatile sig_atomic_t continuum_safepoint_requested = 0;
static volatile sig_atomic_t continuum_preservation_active = 0;
static volatile sig_atomic_t continuum_rehydrate_stop_requested = 0;
static volatile sig_atomic_t continuum_rehydrate_idle_boundaries = 0;
static CFRunLoopObserverRef continuum_safepoint_observer = NULL;
static malloc_zone_t *continuum_app_state_zone = NULL;
static uintptr_t continuum_main_text_start = 0;
static uintptr_t continuum_main_text_end = 0;
static volatile int continuum_allocator_interposition_active = 0;

enum {
    CONTINUUM_APP_STATE_ALLOCATION_LIMIT = 16384,
};

#define CONTINUUM_APP_STATE_ARENA_SIZE UINT64_C(0x10000000)
#define CONTINUUM_APP_STATE_METADATA_SIZE UINT64_C(0x00100000)
#define CONTINUUM_APP_STATE_METADATA_MAGIC UINT64_C(0x434F4E544D455441)
#define CONTINUUM_APP_STATE_METADATA_VERSION UINT32_C(1)

typedef struct continuum_app_state_allocation {
    mach_vm_address_t address;
    mach_vm_size_t mapping_length;
    size_t requested_size;
    uint8_t active;
} continuum_app_state_allocation;

typedef struct continuum_app_state_metadata {
    uint64_t magic;
    uint32_t version;
    uint32_t reserved;
    mach_vm_address_t arena_base;
    mach_vm_address_t mapping_cursor;
    mach_vm_address_t mapping_limit;
    uint64_t allocation_count;
    continuum_app_state_allocation allocations[
        CONTINUUM_APP_STATE_ALLOCATION_LIMIT
    ];
} continuum_app_state_metadata;

_Static_assert(
    sizeof(continuum_app_state_metadata) <= CONTINUUM_APP_STATE_METADATA_SIZE,
    "app-state allocator metadata exceeds its fixed mapping"
);

static continuum_app_state_metadata *continuum_app_state_metadata_header = NULL;
static pthread_mutex_t continuum_app_state_lock = PTHREAD_MUTEX_INITIALIZER;

static const mach_vm_address_t continuum_app_state_candidates[] = {
    UINT64_C(0x0000000140000000),
    UINT64_C(0x0000000150000000),
    UINT64_C(0x0000000160000000),
    UINT64_C(0x0000000170000000),
};

static int continuum_app_state_metadata_is_valid(void) {
    const continuum_app_state_metadata *metadata =
        continuum_app_state_metadata_header;
    if (metadata == NULL
        || metadata->magic != CONTINUUM_APP_STATE_METADATA_MAGIC
        || metadata->version != CONTINUUM_APP_STATE_METADATA_VERSION
        || metadata->allocation_count > CONTINUUM_APP_STATE_ALLOCATION_LIMIT) {
        return 0;
    }
    const mach_vm_address_t page_size = (mach_vm_address_t)getpagesize();
    for (size_t index = 0;
         index < sizeof(continuum_app_state_candidates)
            / sizeof(continuum_app_state_candidates[0]);
         index += 1) {
        const mach_vm_address_t base = continuum_app_state_candidates[index];
        const mach_vm_address_t metadata_address =
            base + CONTINUUM_APP_STATE_ARENA_SIZE
                - CONTINUUM_APP_STATE_METADATA_SIZE;
        const mach_vm_address_t mapping_limit = metadata_address - page_size;
        if (metadata->arena_base == base
            && metadata->mapping_limit == mapping_limit
            && metadata->mapping_cursor >= base
            && metadata->mapping_cursor <= mapping_limit) {
            return 1;
        }
    }
    return 0;
}

static size_t continuum_app_state_size(
    malloc_zone_t *zone,
    const void *pointer
) {
    (void)zone;
    if (pointer == NULL) {
        return 0;
    }
    size_t result = 0;
    pthread_mutex_lock(&continuum_app_state_lock);
    if (!continuum_app_state_metadata_is_valid()) {
        pthread_mutex_unlock(&continuum_app_state_lock);
        return 0;
    }
    for (size_t index = 0;
         index < continuum_app_state_metadata_header->allocation_count;
         index += 1) {
        const continuum_app_state_allocation *allocation =
            &continuum_app_state_metadata_header->allocations[index];
        if (allocation->active
            && allocation->address == (mach_vm_address_t)(uintptr_t)pointer) {
            result = allocation->requested_size;
            break;
        }
    }
    pthread_mutex_unlock(&continuum_app_state_lock);
    return result;
}

static void *continuum_app_state_memalign(
    malloc_zone_t *zone,
    size_t alignment,
    size_t size
) {
    (void)zone;
    if (alignment < sizeof(void *)
        || (alignment & (alignment - 1)) != 0) {
        return NULL;
    }
    const size_t requested_size = size == 0 ? 1 : size;
    const size_t page_size = (size_t)getpagesize();
    if (requested_size > SIZE_MAX - (page_size - 1)) {
        return NULL;
    }
    const mach_vm_size_t mapping_length =
        (mach_vm_size_t)((requested_size + page_size - 1)
            & ~(page_size - 1));
    if (mapping_length > UINT64_C(0x10000000)) {
        return NULL;
    }
    const mach_vm_size_t effective_alignment = alignment > page_size
        ? (mach_vm_size_t)alignment
        : (mach_vm_size_t)page_size;

    pthread_mutex_lock(&continuum_app_state_lock);
    mach_vm_address_t allocation_address = 0;
    if (continuum_app_state_metadata_header == NULL) {
        for (size_t index = 0;
             index < sizeof(continuum_app_state_candidates)
                / sizeof(continuum_app_state_candidates[0]);
             index += 1) {
            const mach_vm_address_t arena_base =
                continuum_app_state_candidates[index];
            if ((arena_base & (effective_alignment - 1)) != 0) {
                continue;
            }
            const mach_vm_address_t metadata_address =
                arena_base + CONTINUUM_APP_STATE_ARENA_SIZE
                    - CONTINUUM_APP_STATE_METADATA_SIZE;
            const mach_vm_address_t mapping_limit =
                metadata_address - (mach_vm_address_t)page_size;
            if (mapping_length > mapping_limit - arena_base) {
                continue;
            }

            mach_vm_address_t candidate = arena_base;
            kern_return_t result = mach_vm_map(
                mach_task_self(),
                &candidate,
                mapping_length,
                0,
                VM_FLAGS_FIXED
                    | VM_MAKE_TAG(VM_MEMORY_APPLICATION_SPECIFIC_1),
                MEMORY_OBJECT_NULL,
                0,
                FALSE,
                VM_PROT_READ | VM_PROT_WRITE,
                VM_PROT_READ | VM_PROT_WRITE,
                VM_INHERIT_NONE
            );
            if (result != KERN_SUCCESS || candidate != arena_base) {
                continue;
            }

            mach_vm_address_t metadata_candidate = metadata_address;
            result = mach_vm_map(
                mach_task_self(),
                &metadata_candidate,
                CONTINUUM_APP_STATE_METADATA_SIZE,
                0,
                VM_FLAGS_FIXED
                    | VM_MAKE_TAG(VM_MEMORY_APPLICATION_SPECIFIC_2),
                MEMORY_OBJECT_NULL,
                0,
                FALSE,
                VM_PROT_READ | VM_PROT_WRITE,
                VM_PROT_READ | VM_PROT_WRITE,
                VM_INHERIT_NONE
            );
            if (result != KERN_SUCCESS
                || metadata_candidate != metadata_address) {
                (void)mach_vm_deallocate(
                    mach_task_self(),
                    arena_base,
                    mapping_length
                );
                continue;
            }

            continuum_app_state_metadata_header =
                (continuum_app_state_metadata *)(uintptr_t)metadata_address;
            memset(
                continuum_app_state_metadata_header,
                0,
                sizeof(*continuum_app_state_metadata_header)
            );
            continuum_app_state_metadata_header->magic =
                CONTINUUM_APP_STATE_METADATA_MAGIC;
            continuum_app_state_metadata_header->version =
                CONTINUUM_APP_STATE_METADATA_VERSION;
            continuum_app_state_metadata_header->arena_base = arena_base;
            continuum_app_state_metadata_header->mapping_cursor = arena_base;
            continuum_app_state_metadata_header->mapping_limit = mapping_limit;
            allocation_address = arena_base;
            break;
        }
        if (continuum_app_state_metadata_header == NULL) {
            pthread_mutex_unlock(&continuum_app_state_lock);
            return NULL;
        }
    } else {
        if (!continuum_app_state_metadata_is_valid()
            || continuum_app_state_metadata_header->allocation_count
                >= CONTINUUM_APP_STATE_ALLOCATION_LIMIT) {
            pthread_mutex_unlock(&continuum_app_state_lock);
            return NULL;
        }
        const mach_vm_address_t mapping_cursor =
            continuum_app_state_metadata_header->mapping_cursor;
        const mach_vm_address_t mapping_limit =
            continuum_app_state_metadata_header->mapping_limit;
        const mach_vm_address_t aligned =
            (mapping_cursor + effective_alignment - 1)
                & ~(effective_alignment - 1);
        if (aligned < mapping_cursor
            || aligned >= mapping_limit
            || mapping_length > mapping_limit - aligned) {
            pthread_mutex_unlock(&continuum_app_state_lock);
            return NULL;
        }
        mach_vm_address_t candidate = aligned;
        kern_return_t result = mach_vm_map(
            mach_task_self(),
            &candidate,
            mapping_length,
            0,
            VM_FLAGS_FIXED | VM_MAKE_TAG(VM_MEMORY_APPLICATION_SPECIFIC_1),
            MEMORY_OBJECT_NULL,
            0,
            FALSE,
            VM_PROT_READ | VM_PROT_WRITE,
            VM_PROT_READ | VM_PROT_WRITE,
            VM_INHERIT_NONE
        );
        if (result != KERN_SUCCESS || candidate != aligned) {
            pthread_mutex_unlock(&continuum_app_state_lock);
            return NULL;
        }
        allocation_address = candidate;
    }

    continuum_app_state_allocation *allocation =
        &continuum_app_state_metadata_header->allocations[
            continuum_app_state_metadata_header->allocation_count
        ];
    allocation->address = allocation_address;
    allocation->mapping_length = mapping_length;
    allocation->requested_size = requested_size;
    allocation->active = 1;
    continuum_app_state_metadata_header->allocation_count += 1;
    const mach_vm_address_t allocation_end =
        allocation_address + mapping_length;
    continuum_app_state_metadata_header->mapping_cursor =
        allocation_end
                <= continuum_app_state_metadata_header->mapping_limit
                    - page_size
            ? allocation_end + page_size
            : continuum_app_state_metadata_header->mapping_limit;
    void *result = (void *)(uintptr_t)allocation->address;
    pthread_mutex_unlock(&continuum_app_state_lock);
    return result;
}

static void *continuum_app_state_malloc(malloc_zone_t *zone, size_t size) {
    return continuum_app_state_memalign(zone, sizeof(max_align_t), size);
}

static void *continuum_app_state_calloc(
    malloc_zone_t *zone,
    size_t count,
    size_t size
) {
    if (count != 0 && size > SIZE_MAX / count) {
        return NULL;
    }
    return continuum_app_state_malloc(zone, count * size);
}

static void *continuum_app_state_valloc(malloc_zone_t *zone, size_t size) {
    return continuum_app_state_memalign(zone, (size_t)getpagesize(), size);
}

static void continuum_app_state_free(malloc_zone_t *zone, void *pointer) {
    (void)zone;
    if (pointer == NULL) {
        return;
    }
    pthread_mutex_lock(&continuum_app_state_lock);
    if (!continuum_app_state_metadata_is_valid()) {
        pthread_mutex_unlock(&continuum_app_state_lock);
        return;
    }
    for (size_t index = 0;
         index < continuum_app_state_metadata_header->allocation_count;
         index += 1) {
        continuum_app_state_allocation *allocation =
            &continuum_app_state_metadata_header->allocations[index];
        if (!allocation->active
            || allocation->address != (mach_vm_address_t)(uintptr_t)pointer) {
            continue;
        }
        allocation->active = 0;
        (void)mach_vm_deallocate(
            mach_task_self(),
            allocation->address,
            allocation->mapping_length
        );
        break;
    }
    pthread_mutex_unlock(&continuum_app_state_lock);
}

static void *continuum_app_state_realloc(
    malloc_zone_t *zone,
    void *pointer,
    size_t size
) {
    if (pointer == NULL) {
        return continuum_app_state_malloc(zone, size);
    }
    if (size == 0) {
        continuum_app_state_free(zone, pointer);
        return NULL;
    }
    const size_t old_size = continuum_app_state_size(zone, pointer);
    if (old_size == 0) {
        return NULL;
    }
    void *replacement = continuum_app_state_malloc(zone, size);
    if (replacement == NULL) {
        return NULL;
    }
    memcpy(replacement, pointer, old_size < size ? old_size : size);
    continuum_app_state_free(zone, pointer);
    return replacement;
}

static void continuum_app_state_destroy(malloc_zone_t *zone) {
    (void)zone;
}

static void continuum_app_state_free_definite_size(
    malloc_zone_t *zone,
    void *pointer,
    size_t size
) {
    (void)size;
    continuum_app_state_free(zone, pointer);
}

static size_t continuum_app_state_pressure_relief(
    malloc_zone_t *zone,
    size_t goal
) {
    (void)zone;
    (void)goal;
    return 0;
}

static boolean_t continuum_app_state_claimed_address(
    malloc_zone_t *zone,
    void *pointer
) {
    return continuum_app_state_size(zone, pointer) > 0;
}

#define CONTINUUM_INTERPOSE(replacement, replacee) \
    __attribute__((used)) static struct { \
        const void *replacement; \
        const void *replacee; \
    } continuum_interpose_##replacee \
        __attribute__((section("__DATA,__interpose"))) = { \
            (const void *)(uintptr_t)&replacement, \
            (const void *)(uintptr_t)&replacee \
        }

static int continuum_address_is_in_main_text(uintptr_t address) {
    return continuum_main_text_start != 0
        && address >= continuum_main_text_start
        && address < continuum_main_text_end;
}

static int continuum_allocation_is_app_owned(uintptr_t return_address) {
#if __has_feature(ptrauth_calls)
    return_address = (uintptr_t)ptrauth_strip(
        (void *)return_address,
        ptrauth_key_return_address
    );
#endif
    return continuum_address_is_in_main_text(return_address);
}

static void *continuum_state_malloc(size_t size) {
    malloc_zone_t *default_zone = malloc_default_zone();
    malloc_zone_t *zone = default_zone;
    uintptr_t return_address = (uintptr_t)__builtin_return_address(0);
    if (pthread_main_np() != 0
        && continuum_app_state_zone != NULL
        && __sync_lock_test_and_set(
            &continuum_allocator_interposition_active,
            1
        ) == 0) {
        if (continuum_allocation_is_app_owned(return_address)) {
            zone = continuum_app_state_zone;
        }
        __sync_lock_release(&continuum_allocator_interposition_active);
    }
    void *result = malloc_zone_malloc(zone, size);
    return result == NULL && zone == continuum_app_state_zone
        ? malloc_zone_malloc(default_zone, size)
        : result;
}

static void *continuum_state_calloc(size_t count, size_t size) {
    malloc_zone_t *default_zone = malloc_default_zone();
    malloc_zone_t *zone = default_zone;
    uintptr_t return_address = (uintptr_t)__builtin_return_address(0);
    if (pthread_main_np() != 0
        && continuum_app_state_zone != NULL
        && __sync_lock_test_and_set(
            &continuum_allocator_interposition_active,
            1
        ) == 0) {
        if (continuum_allocation_is_app_owned(return_address)) {
            zone = continuum_app_state_zone;
        }
        __sync_lock_release(&continuum_allocator_interposition_active);
    }
    void *result = malloc_zone_calloc(zone, count, size);
    return result == NULL && zone == continuum_app_state_zone
        ? malloc_zone_calloc(default_zone, count, size)
        : result;
}

static void *continuum_state_typed_malloc(
    size_t size,
    malloc_type_id_t type_id
) {
    (void)type_id;
    malloc_zone_t *default_zone = malloc_default_zone();
    malloc_zone_t *zone = default_zone;
    uintptr_t return_address = (uintptr_t)__builtin_return_address(0);
    if (pthread_main_np() != 0
        && continuum_app_state_zone != NULL
        && __sync_lock_test_and_set(
            &continuum_allocator_interposition_active,
            1
        ) == 0) {
        if (continuum_allocation_is_app_owned(return_address)) {
            zone = continuum_app_state_zone;
        }
        __sync_lock_release(&continuum_allocator_interposition_active);
    }
    void *result = malloc_zone_malloc(zone, size);
    return result == NULL && zone == continuum_app_state_zone
        ? malloc_zone_malloc(default_zone, size)
        : result;
}

static void *continuum_state_typed_calloc(
    size_t count,
    size_t size,
    malloc_type_id_t type_id
) {
    (void)type_id;
    malloc_zone_t *default_zone = malloc_default_zone();
    malloc_zone_t *zone = default_zone;
    uintptr_t return_address = (uintptr_t)__builtin_return_address(0);
    if (pthread_main_np() != 0
        && continuum_app_state_zone != NULL
        && __sync_lock_test_and_set(
            &continuum_allocator_interposition_active,
            1
        ) == 0) {
        if (continuum_allocation_is_app_owned(return_address)) {
            zone = continuum_app_state_zone;
        }
        __sync_lock_release(&continuum_allocator_interposition_active);
    }
    void *result = malloc_zone_calloc(zone, count, size);
    return result == NULL && zone == continuum_app_state_zone
        ? malloc_zone_calloc(default_zone, count, size)
        : result;
}

CONTINUUM_INTERPOSE(continuum_state_malloc, malloc);
CONTINUUM_INTERPOSE(continuum_state_calloc, calloc);
CONTINUUM_INTERPOSE(continuum_state_typed_malloc, malloc_type_malloc);
CONTINUUM_INTERPOSE(continuum_state_typed_calloc, malloc_type_calloc);

static void continuum_prepare_app_state_zone(void) {
    const struct mach_header *header = NULL;
    uint32_t image_count = _dyld_image_count();
    for (uint32_t index = 0; index < image_count; index += 1) {
        const struct mach_header *candidate = _dyld_get_image_header(index);
        if (candidate != NULL && candidate->filetype == MH_EXECUTE) {
            header = candidate;
            break;
        }
    }
    if (header == NULL || header->magic != MH_MAGIC_64) {
        return;
    }
    const struct mach_header_64 *header64 =
        (const struct mach_header_64 *)header;
    const uint8_t *command_bytes = (const uint8_t *)(header64 + 1);
    const uint8_t *command_end = command_bytes + header64->sizeofcmds;
    const struct load_command *command =
        (const struct load_command *)command_bytes;
    for (uint32_t index = 0; index < header64->ncmds; index += 1) {
        const uint8_t *next = (const uint8_t *)command + command->cmdsize;
        if (command->cmdsize < sizeof(*command) || next > command_end) {
            return;
        }
        if (command->cmd == LC_SEGMENT_64
            && command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment =
                (const struct segment_command_64 *)command;
            if (strncmp(segment->segname, SEG_TEXT, sizeof(segment->segname))
                == 0
                && segment->vmsize > 0
                && (uintptr_t)header
                    <= UINTPTR_MAX - segment->vmsize) {
                continuum_main_text_start = (uintptr_t)header;
                continuum_main_text_end =
                    continuum_main_text_start + (uintptr_t)segment->vmsize;
            }
        }
        command = (const struct load_command *)next;
    }
    if (continuum_main_text_start == 0) {
        return;
    }
    continuum_app_state_zone = malloc_create_zone(0, 0);
    if (continuum_app_state_zone != NULL) {
        malloc_set_zone_name(
            continuum_app_state_zone,
            CONTINUUM_BOOTSTRAP_APP_STATE_ZONE_NAME
        );
        continuum_app_state_zone->size = continuum_app_state_size;
        continuum_app_state_zone->malloc = continuum_app_state_malloc;
        continuum_app_state_zone->calloc = continuum_app_state_calloc;
        continuum_app_state_zone->valloc = continuum_app_state_valloc;
        continuum_app_state_zone->free = continuum_app_state_free;
        continuum_app_state_zone->realloc = continuum_app_state_realloc;
        continuum_app_state_zone->destroy = continuum_app_state_destroy;
        continuum_app_state_zone->memalign = continuum_app_state_memalign;
        continuum_app_state_zone->free_definite_size =
            continuum_app_state_free_definite_size;
        continuum_app_state_zone->pressure_relief =
            continuum_app_state_pressure_relief;
        continuum_app_state_zone->claimed_address =
            continuum_app_state_claimed_address;
        continuum_app_state_zone->version = 10;
    }
}

__attribute__((visibility("default")))
void *continuum_bootstrap_allocate_app_state(size_t size) {
    return continuum_app_state_zone == NULL
        ? NULL
        : malloc_zone_malloc(continuum_app_state_zone, size);
}

static int continuum_should_preserve_receive_right(
    ipc_space_t task,
    mach_port_name_t name
) {
    if (!continuum_preservation_active || task != mach_task_self()
        || !MACH_PORT_VALID(name)) {
        return 0;
    }
    mach_port_type_t type = MACH_PORT_TYPE_NONE;
    return mach_port_type(task, name, &type) == KERN_SUCCESS
        && (type & MACH_PORT_TYPE_RECEIVE) != 0;
}

static int continuum_should_preserve_deallocatable_right(
    ipc_space_t task,
    mach_port_name_t name
) {
    if (!continuum_preservation_active || task != mach_task_self()
        || !MACH_PORT_VALID(name)) {
        return 0;
    }
    mach_port_type_t type = MACH_PORT_TYPE_NONE;
    return mach_port_type(task, name, &type) == KERN_SUCCESS
        && (type & (MACH_PORT_TYPE_SEND | MACH_PORT_TYPE_SEND_ONCE
            | MACH_PORT_TYPE_DEAD_NAME)) != 0;
}

static kern_return_t continuum_preserving_mach_port_destruct(
    ipc_space_t task,
    mach_port_name_t name,
    mach_port_delta_t send_right_delta,
    mach_port_context_t guard
) {
    if (continuum_should_preserve_receive_right(task, name)) {
        return KERN_SUCCESS;
    }
    return mach_port_destruct(task, name, send_right_delta, guard);
}

static kern_return_t continuum_preserving_mach_port_mod_refs(
    ipc_space_t task,
    mach_port_name_t name,
    mach_port_right_t right,
    mach_port_delta_t delta
) {
    if (delta < 0
        && (continuum_should_preserve_receive_right(task, name)
            || continuum_should_preserve_deallocatable_right(task, name))) {
        return KERN_SUCCESS;
    }
    return mach_port_mod_refs(task, name, right, delta);
}

static kern_return_t continuum_preserving_mach_port_deallocate(
    ipc_space_t task,
    mach_port_name_t name
) {
    if (continuum_should_preserve_deallocatable_right(task, name)) {
        return KERN_SUCCESS;
    }
    return mach_port_deallocate(task, name);
}

CONTINUUM_INTERPOSE(
    continuum_preserving_mach_port_destruct,
    mach_port_destruct
);
CONTINUUM_INTERPOSE(
    continuum_preserving_mach_port_mod_refs,
    mach_port_mod_refs
);
CONTINUUM_INTERPOSE(
    continuum_preserving_mach_port_deallocate,
    mach_port_deallocate
);

__attribute__((visibility("default"), noinline))
void continuum_bootstrap_safepoint_spin(void) {
    while (!continuum_safepoint_release) {
#if defined(__arm64__)
        const uint64_t marker = CONTINUUM_BOOTSTRAP_SAFEPOINT_MAGIC;
        __asm__ volatile("mov x28, %0" : : "r"(marker) : "x28", "memory");
#else
        __asm__ volatile("" : : : "memory");
#endif
    }
}

static void continuum_release_safepoint(int signal_number) {
    (void)signal_number;
    continuum_safepoint_release = 1;
}

static void continuum_request_safepoint(int signal_number) {
    (void)signal_number;
    continuum_safepoint_requested = 1;
}

static void continuum_run_loop_safepoint(
    CFRunLoopObserverRef observer,
    CFRunLoopActivity activity,
    void *context
) {
    (void)observer;
    (void)context;
    if (continuum_rehydrate_stop_requested
        && activity == kCFRunLoopBeforeWaiting) {
        continuum_rehydrate_idle_boundaries += 1;
        if (continuum_rehydrate_idle_boundaries >= 4) {
            continuum_rehydrate_stop_requested = 0;
            (void)kill(getpid(), SIGSTOP);
        }
    }
    if (continuum_safepoint_requested) {
        continuum_preservation_active = 1;
        continuum_safepoint_requested = 0;
        continuum_safepoint_release = 0;
        continuum_bootstrap_safepoint_spin();
        continuum_preservation_active = 0;
    }
}

static void continuum_bootstrap_enable_safepoints(void) {
    const char *requested = getenv("CONTINUUM_ENABLE_CHECKPOINT_SAFEPOINTS");
    if (requested == NULL || strcmp(requested, "1") != 0) {
        return;
    }

    (void)signal(SIGUSR1, continuum_release_safepoint);
    (void)signal(SIGUSR2, continuum_request_safepoint);
    CFRunLoopObserverContext context = {
        .version = 0,
        .info = NULL,
        .retain = NULL,
        .release = NULL,
        .copyDescription = NULL,
    };
    continuum_safepoint_observer = CFRunLoopObserverCreate(
        kCFAllocatorDefault,
        kCFRunLoopBeforeWaiting | kCFRunLoopAfterWaiting,
        true,
        0,
        continuum_run_loop_safepoint,
        &context
    );
    if (continuum_safepoint_observer != NULL) {
        CFRunLoopAddObserver(
            CFRunLoopGetMain(),
            continuum_safepoint_observer,
            kCFRunLoopCommonModes
        );
    }
}

__attribute__((visibility("default"), noinline, noreturn))
void continuum_bootstrap_copy_and_trap(
    void *destination,
    const void *source,
    size_t length
) {
    volatile uint8_t *destination_bytes = destination;
    const volatile uint8_t *source_bytes = source;
    for (size_t index = 0; index < length; index += 1) {
        destination_bytes[index] = source_bytes[index];
    }
    __builtin_debugtrap();
    __builtin_unreachable();
}

static int continuum_bootstrap_region(
    uintptr_t point,
    uint64_t *out_region_address,
    uint64_t *out_region_length
) {
    if (point == 0 || out_region_address == NULL
        || out_region_length == NULL) {
        return EINVAL;
    }

    mach_vm_address_t region_address = point;
    mach_vm_size_t region_length = 0;
    natural_t depth = 0;
    vm_region_submap_info_data_64_t info;
    kern_return_t result;
    for (;;) {
        memset(&info, 0, sizeof(info));
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        result = mach_vm_region_recurse(
            mach_task_self(),
            &region_address,
            &region_length,
            &depth,
            (vm_region_recurse_info_t)&info,
            &count
        );
        if (result != KERN_SUCCESS || !info.is_submap) {
            break;
        }
        depth += 1;
    }
    uint64_t region_end = region_address + region_length;
    if (result != KERN_SUCCESS || region_length == 0
        || region_end < region_address || point < region_address
        || point >= region_end
        || (info.protection & (VM_PROT_READ | VM_PROT_WRITE))
            != (VM_PROT_READ | VM_PROT_WRITE)) {
        return EINVAL;
    }
    *out_region_address = region_address;
    *out_region_length = region_length;
    return 0;
}

static int continuum_bootstrap_pthread_geometry(
    pthread_t thread,
    uint64_t *out_stack_base,
    uint64_t *out_stack_length,
    uint64_t *out_stack_region_address,
    uint64_t *out_stack_region_length,
    uint64_t *out_pthread_region_address,
    uint64_t *out_pthread_region_length
) {
    uintptr_t stack_top = (uintptr_t)pthread_get_stackaddr_np(thread);
    size_t stack_length = pthread_get_stacksize_np(thread);
    uintptr_t pthread_address = (uintptr_t)thread;
    if (stack_top == 0 || stack_length == 0 || stack_length > stack_top
        || pthread_address == 0 || out_stack_base == NULL
        || out_stack_length == NULL || out_stack_region_address == NULL
        || out_stack_region_length == NULL
        || out_pthread_region_address == NULL
        || out_pthread_region_length == NULL) {
        return EINVAL;
    }

    uint64_t stack_base = stack_top - stack_length;
    int result = continuum_bootstrap_region(
        stack_base,
        out_stack_region_address,
        out_stack_region_length
    );
    if (result != 0) {
        return result;
    }
    uint64_t stack_region_end =
        *out_stack_region_address + *out_stack_region_length;
    if (stack_region_end < *out_stack_region_address
        || stack_base < *out_stack_region_address
        || stack_top > stack_region_end) {
        return EINVAL;
    }
    result = continuum_bootstrap_region(
        pthread_address,
        out_pthread_region_address,
        out_pthread_region_length
    );
    if (result != 0) {
        return result;
    }
    *out_stack_base = stack_base;
    *out_stack_length = stack_length;
    return 0;
}

static void *continuum_bootstrap_placeholder_start(void *context) {
    return context;
}

int continuum_bootstrap_prepare_suspended_pthreads(
    continuum_bootstrap_pthread_report *report,
    size_t report_length,
    uint32_t requested_count
) {
    if (report == NULL || report_length < sizeof(*report)
        || requested_count > CONTINUUM_BOOTSTRAP_PTHREAD_LIMIT) {
        return EINVAL;
    }
    memset(report, 0, sizeof(*report));
    report->version = 3;
    report->requested_count = requested_count;

    pthread_t primary = pthread_self();
    report->primary_pthread_address = (uint64_t)(uintptr_t)primary;
    report->primary_mach_thread_port = pthread_mach_thread_np(primary);
    if (primary == NULL
        || !MACH_PORT_VALID(report->primary_mach_thread_port)) {
        report->error_code = EINVAL;
        return report->error_code;
    }
    int result = continuum_bootstrap_pthread_geometry(
        primary,
        &report->primary_stack_base_address,
        &report->primary_stack_length,
        &report->primary_stack_region_address,
        &report->primary_stack_region_length,
        &report->primary_pthread_region_address,
        &report->primary_pthread_region_length
    );
    if (result != 0) {
        report->error_code = result;
        return report->error_code;
    }

    for (uint32_t index = 0; index < requested_count; index += 1) {
        pthread_t thread = NULL;
        result = pthread_create_suspended_np(
            &thread,
            NULL,
            continuum_bootstrap_placeholder_start,
            NULL
        );
        if (result != 0 || thread == NULL) {
            report->error_code = result == 0 ? EINVAL : result;
            return report->error_code;
        }
        report->pthread_addresses[index] = (uint64_t)(uintptr_t)thread;
        mach_port_t mach_thread = pthread_mach_thread_np(thread);
        report->mach_thread_ports[index] = mach_thread;
        report->created_count += 1;
        if (!MACH_PORT_VALID(mach_thread)) {
            report->error_code = EINVAL;
            return report->error_code;
        }
        result = continuum_bootstrap_pthread_geometry(
            thread,
            &report->stack_base_addresses[index],
            &report->stack_lengths[index],
            &report->stack_region_addresses[index],
            &report->stack_region_lengths[index],
            &report->pthread_region_addresses[index],
            &report->pthread_region_lengths[index]
        );
        if (result != 0) {
            report->error_code = result;
            return report->error_code;
        }
    }
    return 0;
}

__attribute__((visibility("default"), noinline, noreturn))
void continuum_bootstrap_prepare_pthreads_and_trap(
    continuum_bootstrap_pthread_report *report,
    size_t report_length,
    uint32_t requested_count
) {
    (void)continuum_bootstrap_prepare_suspended_pthreads(
        report,
        report_length,
        requested_count
    );
    __builtin_debugtrap();
    __builtin_unreachable();
}

static int continuum_bootstrap_write_all(
    int descriptor,
    const char *bytes,
    size_t length
) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(descriptor, bytes + offset, length - offset);
        if (written <= 0) {
            return 0;
        }
        offset += (size_t)written;
    }
    return 1;
}

enum {
    CONTINUUM_BOOTSTRAP_MAX_PLAN_BYTES = 1024 * 1024,
    CONTINUUM_BOOTSTRAP_MAX_DESCRIPTORS = 1024
};

typedef struct continuum_bootstrap_descriptor_record {
    int target_descriptor;
    uint32_t open_flags;
    int64_t offset;
    uint64_t device;
    uint64_t inode;
    uint32_t mode;
    char path[PATH_MAX];
} continuum_bootstrap_descriptor_record;

static int continuum_bootstrap_hex_value(char value) {
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

static int continuum_bootstrap_decode_path(
    const char *hex,
    char output[PATH_MAX]
) {
    size_t length = strlen(hex);
    if (length == 0 || (length % 2) != 0 || length / 2 >= PATH_MAX) {
        return 0;
    }
    for (size_t index = 0; index < length; index += 2) {
        int high = continuum_bootstrap_hex_value(hex[index]);
        int low = continuum_bootstrap_hex_value(hex[index + 1]);
        if (high < 0 || low < 0 || (high == 0 && low == 0)) {
            return 0;
        }
        output[index / 2] = (char)((high << 4) | low);
    }
    output[length / 2] = '\0';
    return output[0] == '/';
}

static int continuum_bootstrap_prepare_descriptors(
    int descriptor,
    uint32_t *out_restored_count
) {
    *out_restored_count = 0;
    struct stat metadata;
    if (fstat(descriptor, &metadata) != 0
        || !S_ISREG(metadata.st_mode)
        || metadata.st_uid != geteuid()
        || metadata.st_nlink != 0
        || (metadata.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO))
            != (S_IRUSR | S_IWUSR)
        || metadata.st_size < 0
        || metadata.st_size > CONTINUUM_BOOTSTRAP_MAX_PLAN_BYTES) {
        close(descriptor);
        return -1;
    }

    size_t plan_length = (size_t)metadata.st_size;
    char *plan = calloc(plan_length + 1, 1);
    if (plan == NULL) {
        close(descriptor);
        return -1;
    }
    if (plan_length > 0
        && pread(descriptor, plan, plan_length, 0) != (ssize_t)plan_length) {
        free(plan);
        close(descriptor);
        return -1;
    }

    uint32_t count = 0;
    continuum_bootstrap_descriptor_record *records = NULL;
    int maximum_target = 63;
    if (plan_length > 0) {
        char *context = NULL;
        char *line = strtok_r(plan, "\n", &context);
        char trailing = '\0';
        if (line == NULL
            || sscanf(
                line,
                "CONTINUUM_FD_PLAN_V1 %u %c",
                &count,
                &trailing
            ) != 1
            || count > CONTINUUM_BOOTSTRAP_MAX_DESCRIPTORS) {
            free(plan);
            close(descriptor);
            return -1;
        }
        records = calloc(count, sizeof(*records));
        if (count > 0 && records == NULL) {
            free(plan);
            close(descriptor);
            return -1;
        }
        for (uint32_t index = 0; index < count; index += 1) {
            line = strtok_r(NULL, "\n", &context);
            char path_hex[PATH_MAX * 2];
            long long offset = 0;
            unsigned long long device = 0;
            unsigned long long inode = 0;
            trailing = '\0';
            int parsed = line == NULL ? 0 : sscanf(
                line,
                "%d %u %lld %llu %llu %u %2046s %c",
                &records[index].target_descriptor,
                &records[index].open_flags,
                &offset,
                &device,
                &inode,
                &records[index].mode,
                path_hex,
                &trailing
            );
            if (parsed != 7 || records[index].target_descriptor < 0
                || offset < 0
                || !continuum_bootstrap_decode_path(
                    path_hex,
                    records[index].path
                )) {
                free(records);
                free(plan);
                close(descriptor);
                return -1;
            }
            records[index].offset = offset;
            records[index].device = device;
            records[index].inode = inode;
            for (uint32_t prior = 0; prior < index; prior += 1) {
                if (records[prior].target_descriptor
                    == records[index].target_descriptor) {
                    free(records);
                    free(plan);
                    close(descriptor);
                    return -1;
                }
            }
            if (records[index].target_descriptor > maximum_target) {
                maximum_target = records[index].target_descriptor;
            }
        }
        if (strtok_r(NULL, "\n", &context) != NULL) {
            free(records);
            free(plan);
            close(descriptor);
            return -1;
        }
    }
    free(plan);

    if (maximum_target == INT_MAX) {
        free(records);
        close(descriptor);
        return -1;
    }
    int report_descriptor = fcntl(
        descriptor,
        F_DUPFD_CLOEXEC,
        maximum_target + 1
    );
    close(descriptor);
    if (report_descriptor < 0) {
        free(records);
        return -1;
    }

    for (uint32_t index = 0; index < count; index += 1) {
        int access_mode = records[index].open_flags & O_ACCMODE;
        if (access_mode != O_WRONLY && access_mode != O_RDWR) {
            free(records);
            close(report_descriptor);
            return -1;
        }
        int safe_flags = access_mode | O_CLOEXEC | O_NOFOLLOW;
        if ((records[index].open_flags & O_APPEND) != 0) {
            safe_flags |= O_APPEND;
        }
        int opened = open(records[index].path, safe_flags);
        struct stat file_metadata;
        if (opened < 0 || fstat(opened, &file_metadata) != 0
            || !S_ISREG(file_metadata.st_mode)
            || (uint64_t)file_metadata.st_dev != records[index].device
            || (uint64_t)file_metadata.st_ino != records[index].inode
            || ((uint32_t)file_metadata.st_mode & (S_IFMT | 07777))
                != (records[index].mode & (S_IFMT | 07777))
            || lseek(opened, records[index].offset, SEEK_SET) < 0
            || (opened != records[index].target_descriptor
                && dup2(opened, records[index].target_descriptor) < 0)
            || fcntl(records[index].target_descriptor, F_SETFD, 0) != 0) {
            if (opened >= 0) {
                close(opened);
            }
            free(records);
            close(report_descriptor);
            return -1;
        }
        if (opened != records[index].target_descriptor) {
            close(opened);
        }
        *out_restored_count += 1;
    }
    free(records);
    if (ftruncate(report_descriptor, 0) != 0
        || lseek(report_descriptor, 0, SEEK_SET) != 0) {
        close(report_descriptor);
        return -1;
    }
    return report_descriptor;
}

static void continuum_bootstrap_report_copy_address(void) {
    const char *descriptor_text = getenv("CONTINUUM_BOOTSTRAP_DESCRIPTOR_FD");
    if (descriptor_text == NULL || descriptor_text[0] == '\0') {
        return;
    }
    errno = 0;
    char *end = NULL;
    long descriptor_value = strtol(descriptor_text, &end, 10);
    if (errno != 0 || end == descriptor_text || end == NULL || *end != '\0'
        || descriptor_value < 0 || descriptor_value > INT_MAX) {
        return;
    }
    uint32_t restored_descriptor_count = 0;
    int descriptor = continuum_bootstrap_prepare_descriptors(
        (int)descriptor_value,
        &restored_descriptor_count
    );
    if (descriptor < 0) {
        return;
    }

    uintptr_t copy_address =
        (uintptr_t)(void *)&continuum_bootstrap_copy_and_trap;
#if __has_feature(ptrauth_calls)
    copy_address = (uintptr_t)ptrauth_strip(
        (void *)copy_address,
        ptrauth_key_function_pointer
    );
#endif
    uintptr_t pthread_prepare_address =
        (uintptr_t)(void *)&continuum_bootstrap_prepare_pthreads_and_trap;
#if __has_feature(ptrauth_calls)
    pthread_prepare_address = (uintptr_t)ptrauth_strip(
        (void *)pthread_prepare_address,
        ptrauth_key_function_pointer
    );
#endif
    Dl_info image;
    memset(&image, 0, sizeof(image));
    if (dladdr((void *)copy_address, &image) == 0
        || image.dli_fbase == NULL) {
        close(descriptor);
        return;
    }
    uintptr_t image_base = (uintptr_t)image.dli_fbase;
    if (copy_address <= image_base
        || pthread_prepare_address <= image_base) {
        close(descriptor);
        return;
    }

    char report[192];
    int length = snprintf(
        report,
        sizeof(report),
        "CONTINUUM_BOOTSTRAP_V4 %d 0x%llx 0x%llx 0x%llx %u\n",
        getpid(),
        (unsigned long long)image_base,
        (unsigned long long)copy_address,
        (unsigned long long)pthread_prepare_address,
        restored_descriptor_count
    );
    if (length > 0 && (size_t)length < sizeof(report)
        && continuum_bootstrap_write_all(
            descriptor,
            report,
            (size_t)length
        )) {
        (void)fsync(descriptor);
    }
    close(descriptor);
}

/// dyld runs this after mapping the executable and its launch-time libraries,
/// but before entering application main. Continuum uses that narrow window to
/// replace the disposable process image without executing app code.
__attribute__((constructor))
static void continuum_bootstrap_stop_before_main(void) {
    continuum_prepare_app_state_zone();
    continuum_bootstrap_enable_safepoints();
    const char *rehydrate = getenv("CONTINUUM_BOOTSTRAP_REHYDRATE_STOP");
    if (rehydrate != NULL && strcmp(rehydrate, "1") == 0) {
        continuum_rehydrate_stop_requested = 1;
        continuum_rehydrate_idle_boundaries = 0;
        unsetenv("CONTINUUM_BOOTSTRAP_REHYDRATE_STOP");
    }
    const char *requested = getenv("CONTINUUM_BOOTSTRAP_STOP");
    if (requested == NULL || strcmp(requested, "1") != 0) {
        return;
    }
    continuum_bootstrap_report_copy_address();
    unsetenv("CONTINUUM_BOOTSTRAP_DESCRIPTOR_FD");
    unsetenv("CONTINUUM_BOOTSTRAP_STOP");
    (void)kill(getpid(), SIGSTOP);
}
