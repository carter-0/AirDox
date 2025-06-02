#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <furi_hal_bt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define TAG "AppleBleHashDemo"

#define APPLE_COMPANY_ID 0x004C
#define WIFI_JOIN_TYPE 0x0f
#define NEARBY_TYPE 0x10
#define MAX_HASHES 100

typedef struct {
    char mac_short[9];      // "XX:XX:XX\0" - last 3 octets
    uint8_t apple_id_hash[3];
    uint32_t timestamp;
    uint32_t seen_count;
} HashEntry;

typedef struct {
    FuriMessageQueue* input_queue;
    ViewPort* view_port;
    Gui* gui;
    
    HashEntry hashes[MAX_HASHES];
    size_t hash_count;
    size_t scroll_pos;
    
    bool sniffer_active;
    uint32_t packets_seen;
} AppleBleHashDemo;

/* Helper function to find a specific AD type in BLE advertisement data */
static const uint8_t* find_ad_type(const uint8_t* data, uint16_t len, uint8_t type, uint8_t* found_len) {
    uint16_t offset = 0;
    
    while(offset < len) {
        if(offset >= len) break;
        
        uint8_t ad_len = data[offset];
        
        if(ad_len == 0) break;
        
        if(offset + 1 + ad_len > len) break;
        
        uint8_t ad_type = data[offset + 1];
        
        if(ad_type == type) {
            *found_len = ad_len - 1;
            return &data[offset + 2];
        }
        
        offset += ad_len + 1;
    }
    
    return NULL;
}

/* Convert last 3 MAC bytes to short string */
static void mac_to_short_str(const uint8_t* mac, char* str) {
    snprintf(str, 9, "%02X:%02X:%02X", mac[3], mac[4], mac[5]);
}

/* Find or add hash entry */
static HashEntry* find_or_add_hash(AppleBleHashDemo* app, const uint8_t* mac, const uint8_t* apple_id_hash) {
    char mac_short[9];
    mac_to_short_str(mac, mac_short);
    
    // Find existing entry
    for(size_t i = 0; i < app->hash_count; i++) {
        if(strcmp(app->hashes[i].mac_short, mac_short) == 0 &&
           memcmp(app->hashes[i].apple_id_hash, apple_id_hash, 3) == 0) {
            app->hashes[i].timestamp = furi_get_tick() / 1000;
            app->hashes[i].seen_count++;
            return &app->hashes[i];
        }
    }
    
    // Add new entry
    if(app->hash_count < MAX_HASHES) {
        HashEntry* entry = &app->hashes[app->hash_count];
        strncpy(entry->mac_short, mac_short, 8);
        memcpy(entry->apple_id_hash, apple_id_hash, 3);
        entry->timestamp = furi_get_tick() / 1000;
        entry->seen_count = 1;
        app->hash_count++;
        return entry;
    }
    
    return NULL;
}

/* Parse Nearby packet (type 0x10) */
static void parse_nearby(AppleBleHashDemo* app, const uint8_t* mac, const uint8_t* data, uint8_t len) {
    // Nearby packet structure (based on Python reference):
    // 0: status (1 byte)
    // 1: wifi (1 byte) 
    // 2-4: authTag (3 bytes)
    // More data may follow...
    
    if(len < 5) return;
    
    // Extract a hash from the auth tag area (bytes 2-4)
    const uint8_t* hash_data = &data[2];
    
    find_or_add_hash(app, mac, hash_data);
}

/* Parse WiFi Join packet */
static void parse_wifi_join(AppleBleHashDemo* app, const uint8_t* mac, const uint8_t* data, uint8_t len) {
    // WiFi join packet structure:
    // 0: flags (1 byte)
    // 1: type (1 byte) - should be 0x08
    // 2-4: auth tag (3 bytes)
    // 5-7: sha(appleID) (3 bytes)
    // 8-10: sha(phone_nbr) (3 bytes)
    // 11-13: sha(email) (3 bytes)
    // 14-16: sha(SSID) (3 bytes)
    
    if(len < 8) return;
    
    uint8_t type = data[1];
    
    // Extract Apple ID hash - try multiple offsets
    const uint8_t* apple_id_hash = NULL;
    
    if(len >= 8 && type == 0x08) {
        apple_id_hash = &data[5]; // Standard offset
    } else if(len >= 5) {
        apple_id_hash = &data[2]; // Alternative offset
    } else {
        return;
    }
    
    find_or_add_hash(app, mac, apple_id_hash);
}

/* Parse Apple manufacturer specific data */
static void parse_apple_data(const uint8_t* mfg_data, uint8_t len, AppleBleHashDemo* app, const uint8_t* mac) {
    if(len < 2) return;
    
    uint16_t company_id = mfg_data[0] | (mfg_data[1] << 8);
    if(company_id != APPLE_COMPANY_ID) return;
    
    const uint8_t* apple_data = mfg_data + 2;
    uint8_t apple_len = len - 2;
    
    uint8_t offset = 0;
    while(offset < apple_len) {
        if(offset + 1 >= apple_len) break;
        
        uint8_t packet_type = apple_data[offset];
        uint8_t packet_len = apple_data[offset + 1];
        
        if(offset + 2 + packet_len > apple_len) break;
        
        const uint8_t* packet_data = &apple_data[offset + 2];
        
        if(packet_type == WIFI_JOIN_TYPE) {
            parse_wifi_join(app, mac, packet_data, packet_len);
        } else if(packet_type == NEARBY_TYPE) {
            parse_nearby(app, mac, packet_data, packet_len);
        }
        
        offset += 2 + packet_len;
    }
}

/* GAP-observation packet callback */
static void sniffer_packet_cb(const uint8_t* data, uint16_t len, int8_t rssi, void* ctx) {
    UNUSED(rssi);
    AppleBleHashDemo* app = ctx;
    if(!app) return;
    
    app->packets_seen++;
    
    // BLE packet structure for Flipper sniffer:
    // First 6 bytes are typically the advertising address (MAC)
    // Then comes the advertisement data payload
    if(len < 8) return; // Need minimum packet size
    
    uint8_t mac[6];
    memcpy(mac, data, 6);
    
    // Skip the first 6 bytes (MAC) and process advertisement data
    const uint8_t* ad_data = data + 6;
    uint16_t ad_len = len - 6;
    
    // Find manufacturer specific data in advertisement payload
    uint8_t mfg_len = 0;
    const uint8_t* mfg_data = find_ad_type(ad_data, ad_len, 0xFF, &mfg_len);
    
    if(mfg_data && mfg_len >= 2) {
        uint16_t company_id = mfg_data[0] | (mfg_data[1] << 8);
        
        if(company_id == APPLE_COMPANY_ID) {
            parse_apple_data(mfg_data, mfg_len, app, mac);
        }
    }
}

/* Remove old entries */
static void remove_old_entries(AppleBleHashDemo* app) {
    uint32_t current_time = furi_get_tick() / 1000;
    size_t write_idx = 0;
    
    for(size_t i = 0; i < app->hash_count; i++) {
        // Keep entries seen in last 60 seconds
        if(current_time - app->hashes[i].timestamp < 60) {
            if(write_idx != i) {
                app->hashes[write_idx] = app->hashes[i];
            }
            write_idx++;
        }
    }
    
    app->hash_count = write_idx;
}

static void draw_cb(Canvas* canvas, void* ctx) {
    AppleBleHashDemo* app = ctx;
    char buf[64];
    
    canvas_clear(canvas);
    canvas_set_color(canvas, ColorBlack);
    
    // Title
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 64, 2, AlignCenter, AlignTop, "BLE Hash Demo");
    
    canvas_set_font(canvas, FontSecondary);
    snprintf(buf, sizeof(buf), "Hashes: %zu  Pkts: %lu", app->hash_count, app->packets_seen);
    canvas_draw_str_aligned(canvas, 64, 12, AlignCenter, AlignTop, buf);
    
    // Column headers
    canvas_draw_str_aligned(canvas, 1, 22, AlignLeft, AlignTop, "MAC");
    canvas_draw_str_aligned(canvas, 50, 22, AlignLeft, AlignTop, "Apple ID Hash");
    canvas_draw_str_aligned(canvas, 110, 22, AlignLeft, AlignTop, "Seen");
    
    // Hash entries
    int y = 32;
    size_t max_visible = 3;
    
    for(size_t i = app->scroll_pos; i < app->hash_count && i < app->scroll_pos + max_visible; i++) {
        HashEntry* entry = &app->hashes[i];
        
        // MAC (truncated)
        canvas_draw_str_aligned(canvas, 1, y, AlignLeft, AlignTop, entry->mac_short);
        
        // Apple ID hash
        snprintf(buf, sizeof(buf), "%02X%02X%02X", 
                 entry->apple_id_hash[0], 
                 entry->apple_id_hash[1], 
                 entry->apple_id_hash[2]);
        canvas_draw_str_aligned(canvas, 50, y, AlignLeft, AlignTop, buf);
        
        // Seen count
        snprintf(buf, sizeof(buf), "%lu", entry->seen_count);
        canvas_draw_str_aligned(canvas, 110, y, AlignLeft, AlignTop, buf);
        
        y += 10;
    }
    
    // Scroll indicators
    if(app->hash_count > max_visible) {
        if(app->scroll_pos > 0) {
            canvas_draw_str_aligned(canvas, 122, 32, AlignLeft, AlignTop, "^");
        }
        if(app->scroll_pos + max_visible < app->hash_count) {
            canvas_draw_str_aligned(canvas, 122, 52, AlignLeft, AlignTop, "v");
        }
    }
}

static void input_cb(InputEvent* evt, void* ctx) {
    AppleBleHashDemo* app = ctx;
    furi_message_queue_put(app->input_queue, evt, 0);
}

int32_t apple_ble_hash_demo_app(void* p) {
    UNUSED(p);
    
    AppleBleHashDemo* app = malloc(sizeof(AppleBleHashDemo));
    if(!app) {
        FURI_LOG_E(TAG, "Failed to allocate memory");
        return -1;
    }
    memset(app, 0, sizeof(AppleBleHashDemo));
    
    app->view_port = view_port_alloc();
    app->input_queue = furi_message_queue_alloc(8, sizeof(InputEvent));
    
    view_port_draw_callback_set(app->view_port, draw_cb, app);
    view_port_input_callback_set(app->view_port, input_cb, app);
    
    app->gui = furi_record_open("gui");
    gui_add_view_port(app->gui, app->view_port, GuiLayerFullscreen);
    
    // Start sniffer quietly
    
    // Initialize BLE sniffer
    furi_hal_bt_lock_core2();
    furi_hal_bt_stop_advertising();
    furi_hal_bt_unlock_core2();
    
    furi_hal_bt_reinit();
    furi_delay_ms(500);
    
    if(furi_hal_bt_sniffer_start(sniffer_packet_cb, app)) {
        app->sniffer_active = true;
    }
    
    InputEvent input;
    bool exit_loop = false;
    uint32_t last_cleanup = 0;
    
    while(!exit_loop) {
        // Cleanup old entries periodically
        uint32_t now = furi_get_tick() / 1000;
        if(now - last_cleanup >= 5) {
            remove_old_entries(app);
            last_cleanup = now;
        }
        
        if(furi_message_queue_get(app->input_queue, &input, 10) == FuriStatusOk) {
            if(input.type == InputTypePress) {
                switch(input.key) {
                case InputKeyUp:
                    if(app->scroll_pos > 0) app->scroll_pos--;
                    break;
                case InputKeyDown:
                    if(app->scroll_pos + 3 < app->hash_count) app->scroll_pos++;
                    break;
                case InputKeyOk:
                    // Clear all hashes
                    app->hash_count = 0;
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
        
        view_port_update(app->view_port);
    }
    
    if(app->sniffer_active) {
        furi_hal_bt_sniffer_stop();
    }
    
    view_port_enabled_set(app->view_port, false);
    gui_remove_view_port(app->gui, app->view_port);
    furi_record_close("gui");
    view_port_free(app->view_port);
    furi_message_queue_free(app->input_queue);
    
    free(app);
    
    return 0;
}