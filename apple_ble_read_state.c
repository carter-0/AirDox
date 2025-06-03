#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <furi_hal_bt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <storage/storage.h>
#include <furi_hal_crypto.h>
#include <furi_hal_light.h>

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
#define MAC_ADDR_LEN 18  // "XX:XX:XX:XX:XX:XX\0" for 6-byte MAC address

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
    [0x5b] = "Lock screen",
    [0x5e] = "Outgoing call",
    [0x67] = "Lock screen",
    [0x6b] = "Home screen",
    [0x6e] = "Incoming call",
};

typedef struct {
    char mac_addr[MAC_ADDR_LEN];
    char state[32];
    char device[32];
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
    int h_scroll_offset;  // Horizontal scroll offset in pixels
    
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
static void mac_addr_to_str(const uint8_t* mac_addr, char* str) {
    snprintf(str, MAC_ADDR_LEN, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac_addr[0], mac_addr[1], mac_addr[2], 
             mac_addr[3], mac_addr[4], mac_addr[5]);
}

/* Sort devices by RSSI using insertion sort (strongest first) */
static void sort_devices_by_rssi(AppleDevice* devices, size_t count) {
    for(size_t i = 1; i < count; i++) {
        AppleDevice temp = devices[i];
        size_t j = i;
        
        // Move elements with lower RSSI to the right
        while(j > 0 && devices[j-1].rssi < temp.rssi) {
            devices[j] = devices[j-1];
            j--;
        }
        
        devices[j] = temp;
    }
}

/* Find or add device by MAC address */
static AppleDevice* find_or_add_device(AppleBleReadState* app, const uint8_t* mac_addr, int8_t rssi) {
    char mac_addr_str[MAC_ADDR_LEN];
    mac_addr_to_str(mac_addr, mac_addr_str);
    
    // Find existing device
    for(size_t i = 0; i < app->device_count; i++) {
        if(strcmp(app->devices[i].mac_addr, mac_addr_str) == 0) {
            app->devices[i].rssi = rssi;
            app->devices[i].timestamp = furi_get_tick() / 1000;
            return &app->devices[i];
        }
    }
    
    // Add new device
    if(app->device_count < MAX_DEVICES) {
        AppleDevice* dev = &app->devices[app->device_count];
        strncpy(dev->mac_addr, mac_addr_str, MAC_ADDR_LEN - 1);
        dev->mac_addr[MAC_ADDR_LEN - 1] = '\0'; // Ensure null termination
        dev->rssi = rssi;
        dev->timestamp = furi_get_tick() / 1000;
        strcpy(dev->state, "<unknown>");
        strcpy(dev->device, "<\?\?\?>");
        strcpy(dev->notes, "");
        app->device_count++;
        return dev;
    }
    
    return NULL;
}


/* Parse Nearby packet */
static void parse_nearby(AppleBleReadState* app, const uint8_t* mac_addr, int8_t rssi, const uint8_t* data, uint8_t len) {
    if(len < 1) return; // Need at least status byte
    
    uint8_t status = data[0];
    
    AppleDevice* dev = find_or_add_device(app, mac_addr, rssi);
    if(!dev) return;
    
    // Update state
    if(status < sizeof(phone_states)/sizeof(phone_states[0]) && phone_states[status]) {
        strncpy(dev->state, phone_states[status], 31);
    }
    
    // Detect device type from header (simplified)
    if(strcmp(dev->device, "<\?\?\?>") == 0) {
        strcpy(dev->device, "iPhone"); // Default, would need header analysis
    }
}

/* Parse AirPods packet */
static void parse_airpods(AppleBleReadState* app, const uint8_t* mac_addr, int8_t rssi, const uint8_t* data, uint8_t len) {
    if(len < 9) return;
    
    AppleDevice* dev = find_or_add_device(app, mac_addr, rssi);
    if(!dev) return;
    
    uint16_t model = (data[1] << 8) | data[2];
    uint8_t battery1 = data[4];
    
    // Device model
    switch(model) {
        case 0x0220: strcpy(dev->device, "AirPods"); break;
        case 0x0320: strcpy(dev->device, "Beats3"); break;
        case 0x0520: strcpy(dev->device, "BeatsX"); break;
        case 0x0620: strcpy(dev->device, "Solo3"); break;
        default: strcpy(dev->device, "AirPods"); break;
    }
    
    // Battery levels - convert from 0-15 to 0-100%
    int bat_left = ((battery1 >> 4) * 100) / 15;
    int bat_right = ((battery1 & 0x0F) * 100) / 15;
    
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
static bool parse_apple_data(const uint8_t* mfg_data, uint8_t len, AppleBleReadState* app, const uint8_t* mac_addr, int8_t rssi) {
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
                parse_nearby(app, mac_addr, rssi, packet_data, packet_len);
                break;
                
            case AIRPODS_TYPE:
                parse_airpods(app, mac_addr, rssi, packet_data, packet_len);
                break;
                
            case AIRDROP_TYPE:
                {
                    AppleDevice* dev = find_or_add_device(app, mac_addr, rssi);
                    if(dev) {
                        strcpy(dev->state, "AirDrop");
                    }
                }
                break;
                
            case HANDOFF_TYPE:
                {
                    AppleDevice* dev = find_or_add_device(app, mac_addr, rssi);
                    if(dev) {
                        strcpy(dev->state, "Idle");
                        strcpy(dev->device, "Watch");
                    }
                }
                break;
                
            case WIFI_SET_TYPE:
                {
                    AppleDevice* dev = find_or_add_device(app, mac_addr, rssi);
                    if(dev) {
                        strcpy(dev->state, "WiFi screen");
                    }
                }
                break;
                
            case HOMEKIT_TYPE:
                {
                    AppleDevice* dev = find_or_add_device(app, mac_addr, rssi);
                    if(dev) {
                        strcpy(dev->state, "Homekit");
                        strcpy(dev->device, "Homekit");
                    }
                }
                break;
                
            case SIRI_TYPE:
                {
                    AppleDevice* dev = find_or_add_device(app, mac_addr, rssi);
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
    
    // LED flicker for packet received
    furi_hal_light_set(LightBlue, 0xFF);
    furi_delay_ms(25);
    furi_hal_light_set(LightBlue, 0x00);
    
    // Parse HCI event packet format based on firmware source:
    // data[0] = 0x04 (Event Packet)
    // data[1] = 0x3E (LE Meta Event)
    // data[2] = plen
    // data[3] = 0x02 (LE Advertising Report)
    // data[4] = num_reports
    // data[5] = event_type
    // data[6] = address_type
    // data[7..12] = MAC address (6 bytes)
    // data[13] = data_length
    // data[14..] = AD payload
    
    // Validate packet structure
    if(len < 14) return; // Minimum size for header + MAC
    if(data[0] != 0x04) return; // Not an HCI event packet
    if(data[1] != 0x3E) return; // Not LE Meta Event
    if(data[3] != 0x02) return; // Not LE Advertising Report
    
    uint8_t num_reports = data[4];
    if(num_reports < 1) return;
    
    // Extract MAC address (bytes 7-12)
    uint8_t mac[6];
    memcpy(mac, data + 7, 6);
    
    // Get AD data length and pointer
    uint8_t ad_len = data[13];
    if(len < 14 + ad_len) return; // Packet too short
    
    const uint8_t* ad_data = data + 14;
    
    // Find manufacturer specific data (AD type 0xFF)
    uint8_t mfg_len = 0;
    const uint8_t* mfg_data = find_ad_type(ad_data, ad_len, 0xFF, &mfg_len);
    
    if(mfg_data && mfg_len >= 2) {
        parse_apple_data(mfg_data, mfg_len, app, mac, rssi);
    }
}

/* Remove old devices and sort by RSSI */
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
    
    // Sort devices by RSSI (strongest first)
    if(app->device_count > 0) {
        sort_devices_by_rssi(app->devices, app->device_count);
    }
}

static void draw_cb(Canvas* canvas, void* ctx) {
    AppleBleReadState* app = ctx;
    char buf[128];

    canvas_clear(canvas);
    canvas_set_color(canvas, ColorBlack);

    // Title bar with device count and packet count
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 1, 2, AlignLeft, AlignTop, "BLE Scanner");
    
    canvas_set_font(canvas, FontSecondary);
    snprintf(buf, sizeof(buf), "D:%zu", app->device_count);  // Shorter format
    canvas_draw_str_aligned(canvas, 75, 2, AlignLeft, AlignTop, buf);
    
    // Add packet counter in P:1k format
    if(app->sniffer_packets >= 1000) {
        snprintf(buf, sizeof(buf), "P:%luk", app->sniffer_packets / 1000);
    } else {
        snprintf(buf, sizeof(buf), "P:%lu", app->sniffer_packets);
    }
    canvas_draw_str_aligned(canvas, 100, 2, AlignLeft, AlignTop, buf);

    // Define column positions with proper spacing
    int col_state = 0;    // State column
    int col_device = 45;  // Device column (reduced spacing)
    int col_dbm = 80;     // dBm column (moved left)
    int col_mac = 100;    // MAC Address column (moved right to avoid overlap)
    
    // Column headers - shifted by horizontal scroll
    int base_x = -app->h_scroll_offset;
    canvas_draw_str_aligned(canvas, base_x + col_state, 12, AlignLeft, AlignTop, "State");
    canvas_draw_str_aligned(canvas, base_x + col_device, 12, AlignLeft, AlignTop, "Device");
    canvas_draw_str_aligned(canvas, base_x + col_dbm, 12, AlignLeft, AlignTop, "dBm");
    canvas_draw_str_aligned(canvas, base_x + col_mac, 12, AlignLeft, AlignTop, "MAC Address");
    
    // Device list
    int y = 22;
    size_t max_visible = 5; // Show 5 devices with good spacing
    
    // Calculate visible devices accounting for those with notes
    size_t visible_count = 0;
    size_t current_index = app->scroll_pos;
    
    while(visible_count < max_visible && current_index < app->device_count && y < 64) {
        AppleDevice* dev = &app->devices[current_index];
        
        // State (truncated to fit in column width)
        char state[11];  // Max 10 chars + null
        if(strstr(dev->state, "Lock screen")) {
            strcpy(state, "Locked");
        } else if(strstr(dev->state, "Home screen")) {
            strcpy(state, "Home");
        } else if(strstr(dev->state, "Incoming call")) {
            strcpy(state, "Inc. Call");
        } else if(strstr(dev->state, "Outgoing call")) {
            strcpy(state, "Calling");
        } else if(strstr(dev->state, "WiFi screen")) {
            strcpy(state, "WiFi");
        } else if(strstr(dev->state, "Case:Closed")) {
            strcpy(state, "Case");
        } else if(strcmp(dev->state, "<unknown>") == 0) {
            strcpy(state, "Unknown");  // Shorter without brackets
        } else {
            strncpy(state, dev->state, 9);  // Reduced to 9 chars for safety
            state[9] = '\0';
        }
        canvas_draw_str_aligned(canvas, base_x + col_state, y, AlignLeft, AlignTop, state);
        
        // Device type (max 12 chars)
        char device[13];
        strncpy(device, dev->device, 12);
        device[12] = '\0';
        canvas_draw_str_aligned(canvas, base_x + col_device, y, AlignLeft, AlignTop, device);
        
        // RSSI (max 4 chars: -999)
        snprintf(buf, sizeof(buf), "%d", (int)dev->rssi);
        canvas_draw_str_aligned(canvas, base_x + col_dbm, y, AlignLeft, AlignTop, buf);
        
        // MAC Address (full display)
        canvas_draw_str_aligned(canvas, base_x + col_mac, y, AlignLeft, AlignTop, dev->mac_addr);
        
        // Show notes on second line if present (battery info for AirPods)
        if(strlen(dev->notes) > 0) {
            canvas_draw_str_aligned(canvas, base_x + col_state + 2, y + 8, AlignLeft, AlignTop, dev->notes);
            y += 8; // Extra space for notes
        }
        
        y += 10;
        visible_count++;
        current_index++;
    }
    
    // Vertical scroll indicators
    if(app->device_count > 0) {
        // Up arrow
        if(app->scroll_pos > 0) {
            canvas_draw_str_aligned(canvas, 122, 22, AlignLeft, AlignTop, "^");
        }
        // Down arrow - check if there are more devices to show
        if(current_index < app->device_count) {
            canvas_draw_str_aligned(canvas, 122, 55, AlignLeft, AlignTop, "v");
        }
    }
    
    // Horizontal scroll indicator
    if(app->h_scroll_offset > 0) {
        canvas_draw_str_aligned(canvas, 0, 32, AlignLeft, AlignTop, "<");
    }
    if(app->h_scroll_offset < 150) { // Max scroll offset to see full MAC addresses
        canvas_draw_str_aligned(canvas, 122, 32, AlignLeft, AlignTop, ">");
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
        if (!app->sniffer_active) {
            app->sniffer_active = furi_hal_bt_is_sniffer_active();
        }

        app->loop_count++;

        // Clean up old devices every second
        uint32_t now = furi_get_tick() / 1000;
        if(now - last_cleanup >= 1) {
            remove_old_devices(app);
            last_cleanup = now;
        }

        // Non-blocking check for input
        if(furi_message_queue_get(app->input_queue, &input, 0) == FuriStatusOk) {
            if(input.type == InputTypePress || input.type == InputTypeRepeat) {
                switch(input.key) {
                case InputKeyUp:
                    if(app->scroll_pos > 0) {
                        app->scroll_pos--;
                        view_port_update(app->view_port);
                    }
                    break;
                case InputKeyDown:
                    // Check if we can scroll down more
                    if(app->scroll_pos < app->device_count - 1) {
                        app->scroll_pos++;
                        view_port_update(app->view_port);
                    }
                    break;
                case InputKeyLeft:
                    if(app->h_scroll_offset > 0) {
                        app->h_scroll_offset -= 10;
                        if(app->h_scroll_offset < 0) app->h_scroll_offset = 0;
                        view_port_update(app->view_port);
                    }
                    break;
                case InputKeyRight:
                    if(app->h_scroll_offset < 150) { // Max scroll right to see full MAC address
                        app->h_scroll_offset += 10;
                        if(app->h_scroll_offset > 150) app->h_scroll_offset = 150;
                        view_port_update(app->view_port);
                    }
                    break;
                case InputKeyOk:
                    // Clear all devices
                    app->device_count = 0;
                    app->scroll_pos = 0;
                    app->h_scroll_offset = 0;
                    view_port_update(app->view_port);
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

        // Update view more frequently for real-time feel
        static uint32_t last_update = 0;
        uint32_t current_ms = furi_get_tick();
        if(current_ms - last_update >= 100) { // Update every 100ms (10 times per second)
            view_port_update(app->view_port);
            last_update = current_ms;
        }
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
