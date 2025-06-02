#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <furi_hal_bt.h>
#include <stdint.h>
#include <stdlib.h>

#define TAG "Id Card"

typedef struct {
    FuriMessageQueue* input_queue;
    ViewPort*         view_port;
    Gui*              gui;

    bool     sniffer_active;
    bool     sniffer_started;
    uint32_t sniffer_packets;
    float    rssi;

    uint32_t loop_count;
    char     debug_msg[64];
} Id_card;

/* GAP-observation packet callback */
static void sniffer_packet_cb(
    const uint8_t* data,
    uint16_t       len,
    int8_t         rssi,
    void*          ctx) {

    UNUSED(data);
    UNUSED(len);

    Id_card* app = ctx;
    if(!app) return;

    app->sniffer_packets++;
    app->rssi = (float)rssi;
}

static void draw_cb(Canvas* canvas, void* ctx) {
    Id_card* app = ctx;

    canvas_clear(canvas);
    canvas_set_color(canvas, ColorBlack);

    /* Status line */
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 1, 2, AlignLeft, AlignTop, "BLE:");

    canvas_set_font(canvas, FontSecondary);
    const char* s =
        app->sniffer_started ? (app->sniffer_active ? "Sniffer: Active"
                                                    : "Sniffer: Started")
                             : "Sniffer: Inactive";
    canvas_draw_str_aligned(canvas, 30, 2, AlignLeft, AlignTop, s);

    char buf[32];
    snprintf(buf, sizeof(buf), "RSSI: %.1f dBm", (double)app->rssi);
    canvas_draw_str_aligned(canvas, 1, 14, AlignLeft, AlignTop, buf);

    snprintf(buf, sizeof(buf), "Packets: %lu", app->sniffer_packets);
    canvas_draw_str_aligned(canvas, 1, 26, AlignLeft, AlignTop, buf);

    canvas_draw_str_aligned(canvas, 1, 38, AlignLeft, AlignTop, app->debug_msg);
}

static void input_cb(InputEvent* evt, void* ctx) {
    Id_card* app = ctx;
    furi_message_queue_put(app->input_queue, evt, 0);
}

int32_t air_dox_app(void* p) {
    furi_delay_ms(7000);
    UNUSED(p);

    Id_card app = {0};

    app.view_port   = view_port_alloc();
    app.input_queue = furi_message_queue_alloc(8, sizeof(InputEvent));

    view_port_draw_callback_set(app.view_port, draw_cb, &app);
    view_port_input_callback_set(app.view_port, input_cb, &app);

    app.gui = furi_record_open("gui");
    gui_add_view_port(app.gui, app.view_port, GuiLayerFullscreen);

    snprintf(app.debug_msg, sizeof(app.debug_msg), "Starting sniffer...");
    FURI_LOG_I(TAG, "Initializing BLE sniffer");

    furi_hal_bt_reinit();
    furi_delay_ms(20);
    furi_hal_bt_stop_advertising();
    furi_delay_ms(20);

    if(furi_hal_bt_sniffer_start(sniffer_packet_cb, &app)) {
        app.sniffer_started = true;
        snprintf(app.debug_msg, sizeof(app.debug_msg), "Sniffer started");
        FURI_LOG_I(TAG, "Sniffer started");
    } else {
        snprintf(app.debug_msg, sizeof(app.debug_msg), "Failed to start sniffer");
        FURI_LOG_E(TAG, "Failed to start BLE sniffer");
    }

    InputEvent input;
    bool exit_loop = false;

    while(!exit_loop) {
        app.sniffer_active = furi_hal_bt_is_sniffer_active();
        app.loop_count++;

        furi_hal_bt_hci_user_evt_proc(); // drain FIFO to our callback

        if(furi_message_queue_get(app.input_queue, &input, 100) == FuriStatusOk) {
            switch(input.key) {
            case InputKeyLeft:
            case InputKeyRight:
            case InputKeyOk:
            case InputKeyUp:
            case InputKeyDown:
            case InputKeyBack:
                exit_loop = true;
                break;
            default:
                break;
            }
        }

        view_port_update(app.view_port);
    }

    if(app.sniffer_started) {
        furi_hal_bt_sniffer_stop();
        FURI_LOG_I(TAG, "Stopped BLE sniffer");
    }

    view_port_enabled_set(app.view_port, false);
    gui_remove_view_port(app.gui, app.view_port);
    furi_record_close("gui");
    view_port_free(app.view_port);

    return 0;
}
