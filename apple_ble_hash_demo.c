#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <furi_hal_bt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <furi_hal_light.h>

#define TAG "AppleBleHashDemo"

#define APPLE_COMPANY_ID 0x004C
#define AIRDROP_TYPE 0x05
#define MAX_HASHES 100
#define MAX_LOG_LINES 10

typedef struct {
    char mac_short[9];      // "XX:XX:XX\0" - last 3 octets
    uint8_t apple_id_hash[2];
    uint8_t phone_hash[2]; 
    uint8_t email_hash[2];
    uint32_t timestamp;
    uint32_t seen_count;
} HashEntry;

typedef struct {
    char log_lines[MAX_LOG_LINES][64];
    int log_count;
    int log_start;
} LogBuffer;

typedef struct {
    FuriMessageQueue* input_queue;
    ViewPort* view_port;
    Gui* gui;
    
    HashEntry hashes[MAX_HASHES];
    size_t hash_count;
    size_t scroll_pos;
    
    LogBuffer log_buffer;
    
    bool sniffer_active;
    uint32_t packets_seen;
    uint32_t airdrop_packets_seen;
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
static HashEntry* find_or_add_hash(AppleBleHashDemo* app, const uint8_t* mac, const uint8_t* apple_id_hash, const uint8_t* phone_hash, const uint8_t* email_hash) {
    char mac_short[9];
    mac_to_short_str(mac, mac_short);
    
    // Find existing entry with same MAC and hashes
    for(size_t i = 0; i < app->hash_count; i++) {
        if(strcmp(app->hashes[i].mac_short, mac_short) == 0 &&
           memcmp(app->hashes[i].apple_id_hash, apple_id_hash, 2) == 0 &&
           memcmp(app->hashes[i].phone_hash, phone_hash, 2) == 0) {
            app->hashes[i].timestamp = furi_get_tick() / 1000;
            app->hashes[i].seen_count++;
            return &app->hashes[i];
        }
    }
    
    // Add new entry
    if(app->hash_count < MAX_HASHES) {
        HashEntry* entry = &app->hashes[app->hash_count];
        strncpy(entry->mac_short, mac_short, 8);
        entry->mac_short[8] = '\0';
        memcpy(entry->apple_id_hash, apple_id_hash, 2);
        memcpy(entry->phone_hash, phone_hash, 2);
        memcpy(entry->email_hash, email_hash, 2);
        entry->timestamp = furi_get_tick() / 1000;
        entry->seen_count = 1;
        app->hash_count++;
        return entry;
    }
    
    return NULL;
}

/* Add message to log buffer */
static void add_log_message(AppleBleHashDemo* app, const char* message) {
    int next_pos = (app->log_buffer.log_start + app->log_buffer.log_count) % MAX_LOG_LINES;
    
    if(app->log_buffer.log_count < MAX_LOG_LINES) {
        app->log_buffer.log_count++;
    } else {
        app->log_buffer.log_start = (app->log_buffer.log_start + 1) % MAX_LOG_LINES;
    }
    
    strncpy(app->log_buffer.log_lines[next_pos], message, 63);
    app->log_buffer.log_lines[next_pos][63] = '\0';
    
    FURI_LOG_I(TAG, "Added to screen log: %s (count=%d)", message, app->log_buffer.log_count);
    
    // Force screen update
    if(app->view_port) {
        view_port_update(app->view_port);
    }
}

/* Parse old AirDrop packet (type 0x05) */
static void parse_airdrop_old(AppleBleHashDemo* app, const uint8_t* mac, const uint8_t* data, uint8_t len) {
    // Old AirDrop packet structure (from Python reference):
    // 0-7: zeros (8 bytes)
    // 8: status (0x01) (1 byte)
    // 9-10: sha(AppleID) (2 bytes)
    // 11-12: sha(phone) (2 bytes)
    // 13-14: sha(email) (2 bytes)
    // 15-16: sha(email2) (2 bytes)
    // 17: zero (1 byte)
    
    FURI_LOG_I(TAG, "Parsing AirDrop payload (len=%d)", len);
    
    if(len < 18) {
        FURI_LOG_I(TAG, "AirDrop packet too short: %d bytes (need 18)", len);
        // But let's still try to extract what we can if we have at least 4 bytes
        if(len >= 4) {
            app->airdrop_packets_seen++;
            
            // Use whatever data we have
            uint8_t apple_id_hash[2] = {0};
            uint8_t phone_hash[2] = {0};
            uint8_t email_hash[2] = {0};
            
            if(len >= 2) {
                apple_id_hash[0] = data[0];
                apple_id_hash[1] = data[1];
            }
            if(len >= 4) {
                phone_hash[0] = data[2];
                phone_hash[1] = data[3];
            }
            if(len >= 6) {
                email_hash[0] = data[4];
                email_hash[1] = data[5];
            }
            
            find_or_add_hash(app, mac, apple_id_hash, phone_hash, email_hash);
            
            // Add to screen log
            char log_msg[64];
            snprintf(log_msg, sizeof(log_msg), "AirDrop: %02X:%02X:%02X A:%02X%02X P:%02X%02X",
                     mac[3], mac[4], mac[5],
                     apple_id_hash[0], apple_id_hash[1],
                     phone_hash[0], phone_hash[1]);
            add_log_message(app, log_msg);
        }
        return;
    }
    
    // Check the structure more flexibly
    FURI_LOG_I(TAG, "Checking AirDrop structure: data[8]=0x%02X (expect 0x01)", data[8]);
    
    // Check if it starts with zeros and has status 0x01 at position 8
    bool starts_with_zeros = true;
    for(int i = 0; i < 8; i++) {
        if(data[i] != 0x00) {
            starts_with_zeros = false;
            FURI_LOG_D(TAG, "Non-zero at position %d: 0x%02X", i, data[i]);
            break;
        }
    }
    
    if(!starts_with_zeros || data[8] != 0x01) {
        FURI_LOG_I(TAG, "AirDrop packet format mismatch - using flexible parsing");
        // Try flexible parsing - maybe the structure is different
        app->airdrop_packets_seen++;
        
        // Extract hashes from different positions
        const uint8_t* apple_id_hash = &data[0];  // Try start of packet
        const uint8_t* phone_hash = &data[2];
        const uint8_t* email_hash = &data[4];
        
        if(len >= 9) {
            apple_id_hash = &data[9];  // Standard position
            phone_hash = &data[11];
            email_hash = &data[13];
        }
        
        find_or_add_hash(app, mac, apple_id_hash, phone_hash, email_hash);
        
        // Add to screen log
        char log_msg[64];
        snprintf(log_msg, sizeof(log_msg), "AirDrop: %02X:%02X:%02X A:%02X%02X P:%02X%02X",
                 mac[3], mac[4], mac[5],
                 apple_id_hash[0], apple_id_hash[1],
                 phone_hash[0], phone_hash[1]);
        add_log_message(app, log_msg);
        return;
    }
    
    // Standard parsing for correctly formatted packets
    const uint8_t* apple_id_hash = &data[9];
    const uint8_t* phone_hash = &data[11];
    const uint8_t* email_hash = &data[13];
    
    app->airdrop_packets_seen++;
    
    find_or_add_hash(app, mac, apple_id_hash, phone_hash, email_hash);
    
    FURI_LOG_I(TAG, "AirDrop: MAC %02X:%02X:%02X, AppleID:%02X%02X Phone:%02X%02X Email:%02X%02X",
               mac[3], mac[4], mac[5],
               apple_id_hash[0], apple_id_hash[1],
               phone_hash[0], phone_hash[1], 
               email_hash[0], email_hash[1]);
    
    // Add to screen log
    char log_msg[64];
    snprintf(log_msg, sizeof(log_msg), "AirDrop: %02X:%02X:%02X A:%02X%02X P:%02X%02X",
             mac[3], mac[4], mac[5],
             apple_id_hash[0], apple_id_hash[1],
             phone_hash[0], phone_hash[1]);
    add_log_message(app, log_msg);
}

/* Parse BLE packet TLV structure */
static void parse_ble_packet_tlv(const uint8_t* data, uint8_t len, AppleBleHashDemo* app, const uint8_t* mac, const uint8_t* full_packet, uint16_t full_len) {
    uint8_t offset = 0;
    
    while(offset + 1 < len) {
        uint8_t type = data[offset];
        uint8_t type_len = data[offset + 1];
        
        if(offset + 2 + type_len > len) break;
        
        FURI_LOG_D(TAG, "TLV: type=0x%02X len=%d", type, type_len);
        
        if(type == AIRDROP_TYPE) {
            FURI_LOG_I(TAG, "Found old AirDrop packet (type 0x05)!");
            
            // Log the FULL raw packet here
            char hex_str[full_len * 3 + 1];
            size_t hex_offset = 0;
            for(uint16_t i = 0; i < full_len && hex_offset < sizeof(hex_str) - 3; i++) {
                hex_offset += snprintf(hex_str + hex_offset, sizeof(hex_str) - hex_offset, "%02X ", full_packet[i]);
            }
            FURI_LOG_I(TAG, "FULL RAW PACKET (len=%d): %s", full_len, hex_str);
            
            parse_airdrop_old(app, mac, &data[offset + 2], type_len);
        }
        
        offset += 2 + type_len;
    }
}

/* GAP-observation packet callback */
static void sniffer_packet_cb(const uint8_t* data, uint16_t len, int8_t rssi, void* ctx) {
    UNUSED(rssi);
    AppleBleHashDemo* app = ctx;
    if(!app) return;
    
    app->packets_seen++;
    
    // LED flicker for packet received
    furi_hal_light_set(LightGreen, 0xFF);
    furi_delay_ms(25);
    furi_hal_light_set(LightGreen, 0x00);
    
    // Log first few packets to understand structure
    static int debug_count = 0;
    if(debug_count < 5) {
        debug_count++;
        char hex_str[len * 3 + 1];
        size_t offset = 0;
        for(uint16_t i = 0; i < len && offset < sizeof(hex_str) - 3; i++) {
            offset += snprintf(hex_str + offset, sizeof(hex_str) - offset, "%02X ", data[i]);
        }
        FURI_LOG_I(TAG, "Debug packet %d (len=%d): %s", debug_count, len, hex_str);
    }
    
    // Parse BLE advertisement data looking for Apple manufacturer data
    uint8_t mac[6] = {0};
    const uint8_t* ad_data = data;
    uint16_t ad_len = len;
    
    // If packet starts with what looks like a MAC, skip it
    if(len > 6 && (data[0] != 0x02 && data[0] != 0x03)) {
        memcpy(mac, data, 6);
        ad_data = data + 6;
        ad_len = len - 6;
    }
    
    // Find manufacturer specific data (type 0xFF)
    uint8_t mfg_len = 0;
    const uint8_t* mfg_data = find_ad_type(ad_data, ad_len, 0xFF, &mfg_len);
    
    if(mfg_data && mfg_len >= 2) {
        uint16_t company_id = mfg_data[0] | (mfg_data[1] << 8);
        
        if(company_id == APPLE_COMPANY_ID) {
            FURI_LOG_D(TAG, "Apple packet found, mfg_len=%d", mfg_len);
            
            // Parse Apple TLV data after company ID
            if(mfg_len > 2) {
                parse_ble_packet_tlv(&mfg_data[2], mfg_len - 2, app, mac, data, len);
            }
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
    canvas_draw_str_aligned(canvas, 64, 2, AlignCenter, AlignTop, "AirDrop Sniffer");
    
    canvas_set_font(canvas, FontSecondary);
    snprintf(buf, sizeof(buf), "Pkts:%lu AirDrop:%lu Hashes:%zu", 
             app->packets_seen, app->airdrop_packets_seen, app->hash_count);
    canvas_draw_str_aligned(canvas, 64, 12, AlignCenter, AlignTop, buf);
    
    // Draw recent AirDrop packets log
    canvas_draw_str_aligned(canvas, 1, 22, AlignLeft, AlignTop, "Recent AirDrop packets:");
    
    int y = 32;
    for(int i = 0; i < app->log_buffer.log_count && i < 5; i++) {
        int log_idx = (app->log_buffer.log_start + app->log_buffer.log_count - 1 - i) % MAX_LOG_LINES;
        canvas_draw_str_aligned(canvas, 1, y, AlignLeft, AlignTop, app->log_buffer.log_lines[log_idx]);
        y += 8;
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
    
    // Start sniffer
    furi_hal_bt_lock_core2();
    furi_hal_bt_stop_advertising();
    furi_hal_bt_unlock_core2();
    
    furi_hal_bt_reinit();
    furi_delay_ms(500);
    
    if(furi_hal_bt_sniffer_start(sniffer_packet_cb, app)) {
        app->sniffer_active = true;
        FURI_LOG_I(TAG, "BLE sniffer started successfully");
    } else {
        FURI_LOG_E(TAG, "Failed to start BLE sniffer");
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
                case InputKeyOk:
                    // Clear log and hashes
                    app->hash_count = 0;
                    app->log_buffer.log_count = 0;
                    app->log_buffer.log_start = 0;
                    app->airdrop_packets_seen = 0;
                    break;
                case InputKeyBack:
                    exit_loop = true;
                    break;
                default:
                    break;
                }
            }
        }

        furi_delay_ms(10);
        
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