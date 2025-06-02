#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <gui/elements.h>
#include <stdlib.h>
#include <string.h>

#include "apple_ble_read_state.h"
#include "apple_ble_hash_demo.h"

#define TAG "AirDox"

typedef enum {
    DemoAppleBleReadState,
    DemoAppleBleHashDemo,
    DemoCount
} DemoIndex;

typedef struct {
    const char* name;
    int32_t (*app_function)(void* p);
} Demo;

static const Demo demos[] = {
    {"Apple BLE Sniffer", apple_ble_read_state_app},
    {"AirDrop Doxxer", apple_ble_hash_demo_app},
};

typedef struct {
    FuriMessageQueue* input_queue;
    ViewPort* view_port;
    Gui* gui;
    
    DemoIndex selected_demo;
} AirDox;

static void draw_cb(Canvas* canvas, void* ctx) {
    AirDox* app = ctx;
    
    canvas_clear(canvas);
    canvas_set_color(canvas, ColorBlack);
    
    // Title
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 64, 2, AlignCenter, AlignTop, "AirDox");
    
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(canvas, 64, 12, AlignCenter, AlignTop, "Select Demo:");
    
    // Demo list
    int y = 26;
    for(size_t i = 0; i < DemoCount; i++) {
        if(i == app->selected_demo) {
            canvas_draw_box(canvas, 0, y - 2, 128, 11);
            canvas_set_color(canvas, ColorWhite);
        }
        
        canvas_draw_str_aligned(canvas, 64, y, AlignCenter, AlignTop, demos[i].name);
        
        if(i == app->selected_demo) {
            canvas_set_color(canvas, ColorBlack);
        }
        
        y += 12;
    }
    
    // Instructions
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(canvas, 64, 54, AlignCenter, AlignBottom, "OK to run, Back to exit");
}

static void input_cb(InputEvent* evt, void* ctx) {
    AirDox* app = ctx;
    furi_message_queue_put(app->input_queue, evt, 0);
}

int32_t air_dox_app(void* p) {
    UNUSED(p);
    
    AirDox* app = malloc(sizeof(AirDox));
    if(!app) {
        FURI_LOG_E(TAG, "Failed to allocate memory");
        return -1;
    }
    memset(app, 0, sizeof(AirDox));
    
    app->view_port = view_port_alloc();
    app->input_queue = furi_message_queue_alloc(8, sizeof(InputEvent));
    
    view_port_draw_callback_set(app->view_port, draw_cb, app);
    view_port_input_callback_set(app->view_port, input_cb, app);
    
    app->gui = furi_record_open(RECORD_GUI);
    gui_add_view_port(app->gui, app->view_port, GuiLayerFullscreen);
    
    InputEvent input;
    bool exit_loop = false;
    
    while(!exit_loop) {
        if(furi_message_queue_get(app->input_queue, &input, FuriWaitForever) == FuriStatusOk) {
            if(input.type == InputTypePress) {
                switch(input.key) {
                case InputKeyUp:
                    if(app->selected_demo > 0) {
                        app->selected_demo--;
                    }
                    break;
                case InputKeyDown:
                    if(app->selected_demo + 1 < DemoCount) {
                        app->selected_demo++;
                    }
                    break;
                case InputKeyOk:
                    // Run selected demo
                    if(app->selected_demo < DemoCount) {
                        view_port_enabled_set(app->view_port, false);
                        gui_remove_view_port(app->gui, app->view_port);
                        
                        // Run the demo
                        demos[app->selected_demo].app_function(NULL);
                        
                        // Restore our view
                        gui_add_view_port(app->gui, app->view_port, GuiLayerFullscreen);
                        view_port_enabled_set(app->view_port, true);
                    }
                    break;
                case InputKeyBack:
                    exit_loop = true;
                    break;
                default:
                    break;
                }
            }
            view_port_update(app->view_port);
        }
    }
    
    view_port_enabled_set(app->view_port, false);
    gui_remove_view_port(app->gui, app->view_port);
    furi_record_close(RECORD_GUI);
    view_port_free(app->view_port);
    furi_message_queue_free(app->input_queue);
    
    free(app);
    
    return 0;
}