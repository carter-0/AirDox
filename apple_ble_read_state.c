#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <furi_hal_bt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <storage/storage.h>
#include <furi_hal_crypto.h>

#define __FLIPPER__ 1
#include "picohash.h"
#include "apple_ble_read_state.h"

#define TAG "AppleBleReadState"

#define APPLE_COMPANY_ID 0x004C

// Apple BLE packet types
#define AIRPRINT_TYPE 0x03
#define AIRDROP_TYPE 0x05
#define HOMEKIT_TYPE 0x06
#define AIRPODS_TYPE 0x07
#define SIRI_TYPE 0x08
#define AIRPLAY_TYPE 0x09
#define NEARBY_TYPE 0x10
#define WATCH_C_TYPE 0x0b
#define HANDOFF_TYPE 0x0c
#define WIFI_SET_TYPE 0x0d
#define HOTSPOT_TYPE 0x0e
#define WIFI_JOIN_TYPE 0x0f

#define MAX_DEVICES 100
#define MAC_ADDR_LEN 18  // "XX:XX:XX:XX:XX:XX\0"

// Device states
static const char* phone_states[] = {
    [0x01] = "Disabled",
    [0x03] = "Idle", 
    [0x05] = "Music",
    [0x07] = "Lock screen",
    [0x09] = "Video",
    [0x0a] = "Home screen",
    [0x0b] = "Home screen",
    [0x0d] = "Driving",
    [0x0e] = "Incoming call",
    [0x11] = "Home screen",
    [0x13] = "Off",
    [0x17] = "Lock screen",
    [0x18] = "Off",
    [0x1a] = "Off",
    [0x1b] = "Home screen",
    [0x1c] = "Home screen",
    [0x23] = "Off",
    [0x47] = "Lock screen",
    [0x4b] = "Home screen",
    [0x4e] = "Outgoing call",
    [0x57] = "Lock screen",
    [0x5a] = "Off",
    [0x5b] = "Home screen",
    [0x5e] = "Outgoing call",
    [0x67] = "Lock screen",
    [0x6b] = "Home screen",
    [0x6e] = "Incoming call",
};

typedef struct {
    char mac[MAC_ADDR_LEN];
    char state[32];
    char device[32];
    char wifi[16];
    char os[16];
    char notes[64];
    int8_t rssi;
    uint32_t timestamp;
} AppleDevice;

typedef struct {
    FuriMessageQueue* input_queue;
    ViewPort*         view_port;
    Gui*              gui;

    bool     sniffer_active;
    bool     sniffer_started;
    uint32_t sniffer_packets;
    
    // Device list
    AppleDevice devices[MAX_DEVICES];
    size_t device_count;
    
    // Current scroll position
    size_t scroll_pos;
    
    uint32_t loop_count;
} AppleBleReadState;

/* Helper function to find a specific AD type in BLE advertisement data */
static const uint8_t* find_ad_type(const uint8_t* data, uint16_t len, uint8_t type, uint8_t* found_len) {
    uint16_t offset = 0;
    
    while(offset < len) {
        uint8_t ad_len = data[offset];
        if(ad_len == 0) break;
        
        if(offset + 1 + ad_len > len) break;
        
        uint8_t ad_type = data[offset + 1];
        if(ad_type == type) {
            *found_len = ad_len - 1; // Subtract 1 for the type byte
            return &data[offset + 2]; // Return pointer to data after type
        }
        
        offset += ad_len + 1;
    }
    
    return NULL;
}

/* Convert MAC address bytes to string */
static void mac_to_str(const uint8_t* mac, char* str) {
    snprintf(str, MAC_ADDR_LEN, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[5], mac[4], mac[3], mac[2], mac[1], mac[0]);
}

/* Find or add device */
static AppleDevice* find_or_add_device(AppleBleReadState* app, const uint8_t* mac, int8_t rssi) {
    char mac_str[MAC_ADDR_LEN];
    mac_to_str(mac, mac_str);
    
    // Find existing device
    for(size_t i = 0; i < app->device_count; i++) {
        if(strcmp(app->devices[i].mac, mac_str) == 0) {
            app->devices[i].rssi = rssi;
            app->devices[i].timestamp = furi_get_tick() / 1000;
            return &app->devices[i];
        }
    }
    
    // Add new device
    if(app->device_count < MAX_DEVICES) {
        AppleDevice* dev = &app->devices[app->device_count];
        strncpy(dev->mac, mac_str, MAC_ADDR_LEN - 1);
        dev->rssi = rssi;
        dev->timestamp = furi_get_tick() / 1000;
        strcpy(dev->state, "<unknown>");
        strcpy(dev->device, "<unknown>");
        strcpy(dev->wifi, "");
        strcpy(dev->os, "");
        strcpy(dev->notes, "");
        app->device_count++;
        return dev;
    }
    
    return NULL;
}

/* Parse OS/WiFi code */
static void parse_os_wifi_code(uint8_t code, const char* dev_type, char* os, char* wifi) {
    switch(code) {
        case 0x1c:
            strcpy(os, strcmp(dev_type, "MacBook") == 0 ? "Mac OS" : "iOS12");
            strcpy(wifi, "On");
            break;
        case 0x18:
            strcpy(os, strcmp(dev_type, "MacBook") == 0 ? "Mac OS" : "iOS12");
            strcpy(wifi, "Off");
            break;
        case 0x10:
            strcpy(os, "iOS11");
            strcpy(wifi, "<unknown>");
            break;
        case 0x1e:
            strcpy(os, "iOS13");
            strcpy(wifi, "On");
            break;
        case 0x1a:
            strcpy(os, "iOS13");
            strcpy(wifi, "Off");
            break;
        case 0x0e:
            strcpy(os, "iOS13");
            strcpy(wifi, "Connecting");
            break;
        case 0x0c:
            strcpy(os, "iOS12");
            strcpy(wifi, "On");
            break;
        case 0x04:
            strcpy(os, "iOS13");
            strcpy(wifi, "On");
            break;
        case 0x00:
            strcpy(os, "iOS10");
            strcpy(wifi, "<unknown>");
            break;
        case 0x09:
            strcpy(os, "Mac OS");
            strcpy(wifi, "<unknown>");
            break;
        case 0x14:
            strcpy(os, "Mac OS");
            strcpy(wifi, "On");
            break;
        case 0x98:
            strcpy(os, "WatchOS");
            strcpy(wifi, "<unknown>");
            break;
        default:
            strcpy(os, "");
            strcpy(wifi, "");
            break;
    }
}

/* Parse Nearby packet */
static void parse_nearby(AppleBleReadState* app, const uint8_t* mac, int8_t rssi, const uint8_t* data, uint8_t len) {
    if(len < 2) return;
    
    uint8_t status = data[0];
    uint8_t wifi_code = data[1];
    
    AppleDevice* dev = find_or_add_device(app, mac, rssi);
    if(!dev) return;
    
    // Update state
    if(status < sizeof(phone_states)/sizeof(phone_states[0]) && phone_states[status]) {
        strncpy(dev->state, phone_states[status], 31);
    }
    
    // Detect device type from header (simplified)
    if(strcmp(dev->device, "<unknown>") == 0) {
        strcpy(dev->device, "iPhone"); // Default, would need header analysis
    }
    
    // Update OS and WiFi
    parse_os_wifi_code(wifi_code, dev->device, dev->os, dev->wifi);
    
    if(strcmp(dev->os, "WatchOS") == 0) {
        strcpy(dev->device, "Watch");
    }
}

/* Parse AirPods packet */
static void parse_airpods(AppleBleReadState* app, const uint8_t* mac, int8_t rssi, const uint8_t* data, uint8_t len) {
    if(len < 9) return;
    
    AppleDevice* dev = find_or_add_device(app, mac, rssi);
    if(!dev) return;
    
    uint16_t model = (data[1] << 8) | data[2];
    uint8_t battery1 = data[4];
    
    // Device model
    switch(model) {
        case 0x0220: strcpy(dev->device, "AirPods"); break;
        case 0x0320: strcpy(dev->device, "Powerbeats3"); break;
        case 0x0520: strcpy(dev->device, "BeatsX"); break;
        case 0x0620: strcpy(dev->device, "Beats Solo3"); break;
        default: strcpy(dev->device, "AirPods"); break;
    }
    
    // Battery levels
    int bat_left = (battery1 >> 4) * 10;
    int bat_right = (battery1 & 0x0F) * 10;
    
    // State
    if(data[3] == 0x09) {
        strcpy(dev->state, "Case:Closed");
    } else {
        strcpy(dev->state, "Active");
    }
    
    // Notes with battery info
    snprintf(dev->notes, 63, "L:%d%% R:%d%%", bat_left, bat_right);
}

/* Parse Apple manufacturer specific data */
static bool parse_apple_data(const uint8_t* mfg_data, uint8_t len, AppleBleReadState* app, const uint8_t* mac, int8_t rssi) {
    if(len < 2) return false;
    
    // Check Apple company ID (little endian)
    uint16_t company_id = mfg_data[0] | (mfg_data[1] << 8);
    if(company_id != APPLE_COMPANY_ID) return false;
    
    // Parse Apple-specific data starting after company ID
    const uint8_t* apple_data = mfg_data + 2;
    uint8_t apple_len = len - 2;
    
    // Look for different packet types
    uint8_t offset = 0;
    while(offset < apple_len) {
        if(offset + 1 >= apple_len) break;
        
        uint8_t packet_type = apple_data[offset];
        uint8_t packet_len = apple_data[offset + 1];
        
        if(offset + 2 + packet_len > apple_len) break;
        
        const uint8_t* packet_data = &apple_data[offset + 2];
        
        switch(packet_type) {
            case NEARBY_TYPE:
                parse_nearby(app, mac, rssi, packet_data, packet_len);
                break;
                
            case AIRPODS_TYPE:
                parse_airpods(app, mac, rssi, packet_data, packet_len);
                break;
                
            case AIRDROP_TYPE:
                {
                    AppleDevice* dev = find_or_add_device(app, mac, rssi);
                    if(dev) {
                        strcpy(dev->state, "AirDrop");
                    }
                }
                break;
                
            case HANDOFF_TYPE:
                {
                    AppleDevice* dev = find_or_add_device(app, mac, rssi);
                    if(dev) {
                        strcpy(dev->state, "Idle");
                        strcpy(dev->device, "AppleWatch");
                    }
                }
                break;
                
            case WIFI_SET_TYPE:
                {
                    AppleDevice* dev = find_or_add_device(app, mac, rssi);
                    if(dev) {
                        strcpy(dev->state, "WiFi screen");
                    }
                }
                break;
                
            case HOMEKIT_TYPE:
                {
                    AppleDevice* dev = find_or_add_device(app, mac, rssi);
                    if(dev) {
                        strcpy(dev->state, "Homekit");
                        strcpy(dev->device, "Homekit");
                    }
                }
                break;
                
            case SIRI_TYPE:
                {
                    AppleDevice* dev = find_or_add_device(app, mac, rssi);
                    if(dev) {
                        strcpy(dev->state, "Siri");
                    }
                }
                break;
        }
        
        offset += 2 + packet_len;
    }
    
    return true;
}

/* GAP-observation packet callback */
static void sniffer_packet_cb(
    const uint8_t* data,
    uint16_t       len,
    int8_t         rssi,
    void*          ctx) {

    AppleBleReadState* app = ctx;
    if(!app) return;

    app->sniffer_packets++;
    
    // Extract MAC address from the BLE packet
    // In BLE packets, the MAC is typically at offset 2 after flags
    uint8_t mac[6] = {0};
    if(len >= 8) {
        // Try to find the MAC in the packet structure
        // This is simplified - actual extraction depends on packet format
        memcpy(mac, &data[2], 6);
    }
    
    // Find manufacturer specific data (AD type 0xFF)
    uint8_t mfg_len = 0;
    const uint8_t* mfg_data = find_ad_type(data, len, 0xFF, &mfg_len);
    
    if(mfg_data && mfg_len >= 2) {
        parse_apple_data(mfg_data, mfg_len, app, mac, rssi);
    }
}

/* Remove old devices */
static void remove_old_devices(AppleBleReadState* app) {
    uint32_t current_time = furi_get_tick() / 1000;
    size_t write_idx = 0;
    
    for(size_t i = 0; i < app->device_count; i++) {
        // Keep devices seen in last 15 seconds
        if(current_time - app->devices[i].timestamp < 15) {
            if(write_idx != i) {
                app->devices[write_idx] = app->devices[i];
            }
            write_idx++;
        }
    }
    
    app->device_count = write_idx;
}

static void draw_cb(Canvas* canvas, void* ctx) {
    AppleBleReadState* app = ctx;
    char buf[128];

    canvas_clear(canvas);
    canvas_set_color(canvas, ColorBlack);

    // Title bar
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 1, 2, AlignLeft, AlignTop, "BLE Sniffer");
    
    canvas_set_font(canvas, FontSecondary);
    snprintf(buf, sizeof(buf), "Devices: %zu", app->device_count);
    canvas_draw_str_aligned(canvas, 80, 2, AlignLeft, AlignTop, buf);

    // Column headers
    canvas_draw_str_aligned(canvas, 1, 12, AlignLeft, AlignTop, "State");
    canvas_draw_str_aligned(canvas, 50, 12, AlignLeft, AlignTop, "Device");
    canvas_draw_str_aligned(canvas, 90, 12, AlignLeft, AlignTop, "WiFi");
    
    // Device list
    int y = 22;
    size_t max_visible = 4; // Max devices that fit on screen
    
    for(size_t i = app->scroll_pos; i < app->device_count && i < app->scroll_pos + max_visible; i++) {
        AppleDevice* dev = &app->devices[i];
        
        // State (truncated)
        char state[16];
        strncpy(state, dev->state, 15);
        state[15] = '\0';
        canvas_draw_str_aligned(canvas, 1, y, AlignLeft, AlignTop, state);
        
        // Device type
        canvas_draw_str_aligned(canvas, 50, y, AlignLeft, AlignTop, dev->device);
        
        // WiFi status
        canvas_draw_str_aligned(canvas, 90, y, AlignLeft, AlignTop, dev->wifi);
        
        // RSSI on far right
        snprintf(buf, sizeof(buf), "%ddB", (int)dev->rssi);
        canvas_draw_str_aligned(canvas, 100, y, AlignLeft, AlignTop, buf);
        
        y += 10;
    }
    
    // Scroll indicator
    if(app->device_count > max_visible) {
        canvas_draw_str_aligned(canvas, 122, 30, AlignLeft, AlignTop, 
            app->scroll_pos > 0 ? "^" : " ");
        canvas_draw_str_aligned(canvas, 122, 50, AlignLeft, AlignTop, 
            app->scroll_pos + max_visible < app->device_count ? "v" : " ");
    }
}

static void input_cb(InputEvent* evt, void* ctx) {
    AppleBleReadState* app = ctx;
    furi_message_queue_put(app->input_queue, evt, 0);
}

int32_t apple_ble_read_state_app(void* p) {
    UNUSED(p);

    AppleBleReadState* app = malloc(sizeof(AppleBleReadState));
    if(!app) {
        FURI_LOG_E(TAG, "Failed to allocate memory");
        return -1;
    }
    memset(app, 0, sizeof(AppleBleReadState));

    app->view_port   = view_port_alloc();
    app->input_queue = furi_message_queue_alloc(8, sizeof(InputEvent));

    view_port_draw_callback_set(app->view_port, draw_cb, app);
    view_port_input_callback_set(app->view_port, input_cb, app);

    app->gui = furi_record_open("gui");
    gui_add_view_port(app->gui, app->view_port, GuiLayerFullscreen);

    FURI_LOG_I(TAG, "Initializing BLE sniffer");

    furi_hal_bt_lock_core2();
    furi_hal_bt_stop_advertising();
    furi_hal_bt_unlock_core2();

    furi_hal_bt_reinit();
    furi_delay_ms(500);

    if(furi_hal_bt_sniffer_start(sniffer_packet_cb, app)) {
        app->sniffer_started = true;
        FURI_LOG_I(TAG, "Sniffer started");
    } else {
        FURI_LOG_E(TAG, "Failed to start BLE sniffer");
    }

    InputEvent input;
    bool exit_loop = false;
    uint32_t last_cleanup = 0;

    while(!exit_loop) {
        app->sniffer_active = furi_hal_bt_is_sniffer_active();
        app->loop_count++;

        // Clean up old devices every second
        uint32_t now = furi_get_tick() / 1000;
        if(now - last_cleanup >= 1) {
            remove_old_devices(app);
            last_cleanup = now;
        }

        // Non-blocking check for input
        if(furi_message_queue_get(app->input_queue, &input, 0) == FuriStatusOk) {
            if(input.type == InputTypePress) {
                switch(input.key) {
                case InputKeyUp:
                    if(app->scroll_pos > 0) app->scroll_pos--;
                    break;
                case InputKeyDown:
                    if(app->scroll_pos + 4 < app->device_count) app->scroll_pos++;
                    break;
                case InputKeyOk:
                    // Clear all devices
                    app->device_count = 0;
                    app->scroll_pos = 0;
                    break;
                case InputKeyBack:
                    exit_loop = true;
                    break;
                default:
                    break;
                }
            }
        }

        // Small delay to prevent CPU hogging
        furi_delay_ms(10);

        view_port_update(app->view_port);
    }

    if(app->sniffer_started) {
        furi_hal_bt_sniffer_stop();
        FURI_LOG_I(TAG, "Stopped BLE sniffer");
    }

    view_port_enabled_set(app->view_port, false);
    gui_remove_view_port(app->gui, app->view_port);
    furi_record_close("gui");
    view_port_free(app->view_port);
    furi_message_queue_free(app->input_queue);
    
    free(app);

    return 0;
}