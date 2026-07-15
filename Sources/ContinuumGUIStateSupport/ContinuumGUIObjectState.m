#import "ContinuumGUIStateSupport.h"

#import <Foundation/Foundation.h>

@interface ContinuumGUIObjectState : NSObject {
@public
    uint64_t _magic;
    uint64_t _counter;
}
@end

@implementation ContinuumGUIObjectState
@end

static ContinuumGUIObjectState *continuum_gui_object_state;

uintptr_t continuum_gui_object_state_create(
    uint64_t magic,
    uint64_t counter
) {
    continuum_gui_object_state = [[ContinuumGUIObjectState alloc] init];
    if (continuum_gui_object_state == nil) {
        return 0;
    }
    continuum_gui_object_state->_magic = magic;
    continuum_gui_object_state->_counter = counter;
    return (uintptr_t)continuum_gui_object_state;
}

uint64_t continuum_gui_object_state_magic(void) {
    return continuum_gui_object_state == nil
        ? 0
        : continuum_gui_object_state->_magic;
}

uint64_t continuum_gui_object_state_counter(void) {
    return continuum_gui_object_state == nil
        ? 0
        : continuum_gui_object_state->_counter;
}

void continuum_gui_object_state_add(uint64_t amount) {
    if (continuum_gui_object_state != nil) {
        continuum_gui_object_state->_counter += amount;
    }
}
