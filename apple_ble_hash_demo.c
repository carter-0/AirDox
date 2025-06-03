#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <furi_hal_bt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <furi_hal_light.h>
#include <dialogs/dialogs.h>
#include <storage/storage.h>
#include <toolbox/stream/buffered_file_stream.h>
#include "tiny_e164.h"
#include "picohash.h"
#include "apple_ble_hash_demo.h"

#define TAG "AppleBleHashDemo"
#define MAX_PHONE_NUMBERS 1000

/* Hash database implementation */
int phone_hash_db_init(phone_hash_db_t* db) {
    if(!db) return -1;
    
    db->entries = NULL;
    db->count = 0;
    db->capacity = 0;
    return 0;
}

void phone_hash_db_free(phone_hash_db_t* db) {
    if(db && db->entries) {
        free(db->entries);
        db->entries = NULL;
        db->count = 0;
        db->capacity = 0;
    }
}

const char* phone_hash_db_lookup(phone_hash_db_t* db, const uint8_t hash[2]) {
    if(!db || !db->entries) return NULL;
    
    for(size_t i = 0; i < db->count; i++) {
        if(db->entries[i].hash[0] == hash[0] && db->entries[i].hash[1] == hash[1]) {
            return db->entries[i].phone;
        }
    }
    return NULL;
}

void phone_hash_db_add_entry(phone_hash_db_t* db, const uint8_t hash[2], const char* phone) {
    if(!db || !phone) return;
    
    // Check if we need to grow the array
    if(db->count >= db->capacity) {
        size_t new_capacity = db->capacity == 0 ? 100 : db->capacity * 2;
        if(new_capacity > MAX_PHONE_NUMBERS) new_capacity = MAX_PHONE_NUMBERS;
        
        phone_hash_lookup_t* new_entries = realloc(db->entries, sizeof(phone_hash_lookup_t) * new_capacity);
        if(!new_entries) {
            FURI_LOG_E(TAG, "Failed to grow hash database");
            return;
        }
        
        db->entries = new_entries;
        db->capacity = new_capacity;
    }
    
    // Add the entry
    if(db->count < db->capacity) {
        db->entries[db->count].hash[0] = hash[0];
        db->entries[db->count].hash[1] = hash[1];
        strncpy(db->entries[db->count].phone, phone, 16);
        db->entries[db->count].phone[16] = '\0';
        db->count++;
    }
}

#define APPLE_COMPANY_ID 0x004C
#define AIRDROP_TYPE 0x05
#define MAX_HASHES 100
#define MAX_LOG_LINES 10
#define MAX_EXTRACTED_HASHES 8  // Maximum number of 2-byte hashes we can extract from one packet

typedef struct {
    uint8_t extracted_hashes[MAX_EXTRACTED_HASHES][2];  // All extracted 2-byte sequences
    uint8_t num_extracted_hashes;                       // Number of hashes extracted
    uint32_t timestamp;
    uint32_t seen_count;
    char matched_phone[17];  // Store matched phone number if found
    char packet_data[32];    // Truncated packet data for display
    int8_t rssi;
} HashEntry;

typedef struct {
    char log_lines[MAX_LOG_LINES][64];
    int log_count;
    int log_start;
} LogBuffer;

typedef enum {
    AppStateConfig,
    AppStateLoading,
    AppStateSniffer
} AppState;

typedef struct {
    phone_e164_t phone;
    uint8_t hash[2];
} PhoneHashEntry;

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
    uint32_t matches_found;  // Track successful matches
    
    AppState state;
    bool use_brute_force;
    char brute_force_file[256];
    int config_selection;  // 0 = continue without, 1 = select file
    
    // Phone number storage for brute force
    phone_e164_t* phone_numbers;
    size_t phone_numbers_count;
    size_t phone_numbers_capacity;
    
    // Hash lookup database
    phone_hash_db_t hash_db;
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

/* Format packet data for display (truncated) */
static void format_packet_data(const uint8_t* data, uint16_t len, char* str, size_t str_len) {
    size_t bytes_to_show = (len > 15) ? 15 : len;
    size_t pos = 0;
    
    for(size_t i = 0; i < bytes_to_show && pos < str_len - 3; i++) {
        pos += snprintf(str + pos, str_len - pos, "%02X", data[i]);
        if(i < bytes_to_show - 1 && pos < str_len - 3) {
            str[pos++] = ' ';
        }
    }
    
    if(len > 15 && pos < str_len - 4) {
        strcpy(str + pos, "...");
    }
    
    str[str_len - 1] = '\0';
}

/* Helper function to compare two hash arrays for similarity */
static bool hash_arrays_similar(const uint8_t hashes1[][2], uint8_t count1, const uint8_t hashes2[][2], uint8_t count2) {
    if(count1 == 0 || count2 == 0) return false;
    
    // Check if any hash from first array matches any hash from second array
    for(uint8_t i = 0; i < count1; i++) {
        for(uint8_t j = 0; j < count2; j++) {
            if(memcmp(hashes1[i], hashes2[j], 2) == 0) {
                return true;  // Found at least one matching hash
            }
        }
    }
    return false;
}

/* Find or add hash entry with multiple extracted hashes */
static HashEntry* find_or_add_hash_entry(AppleBleHashDemo* app, const uint8_t extracted_hashes[][2], uint8_t num_hashes, const uint8_t* packet_data, uint16_t packet_len, int8_t rssi) {
    // Find existing entry with similar hash set
    for(size_t i = 0; i < app->hash_count; i++) {
        if(hash_arrays_similar(app->hashes[i].extracted_hashes, app->hashes[i].num_extracted_hashes, 
                               extracted_hashes, num_hashes)) {
            app->hashes[i].timestamp = furi_get_tick() / 1000;
            app->hashes[i].seen_count++;
            app->hashes[i].rssi = rssi;  // Update RSSI
            return &app->hashes[i];
        }
    }
    
    // Add new entry
    if(app->hash_count < MAX_HASHES) {
        HashEntry* entry = &app->hashes[app->hash_count];
        
        // Copy all extracted hashes
        entry->num_extracted_hashes = (num_hashes > MAX_EXTRACTED_HASHES) ? MAX_EXTRACTED_HASHES : num_hashes;
        for(uint8_t i = 0; i < entry->num_extracted_hashes; i++) {
            memcpy(entry->extracted_hashes[i], extracted_hashes[i], 2);
        }
        
        entry->timestamp = furi_get_tick() / 1000;
        entry->seen_count = 1;
        entry->matched_phone[0] = '\0'; // Initialize as empty
        entry->rssi = rssi;
        
        // Format packet data for display
        format_packet_data(packet_data, packet_len, entry->packet_data, sizeof(entry->packet_data));
        
        app->hash_count++;
        return entry;
    }
    
    return NULL;
}

/* Add message to log buffer - simplified version for loading only */
static void add_log_message(AppleBleHashDemo* app, const char* message) {
    FURI_LOG_I(TAG, "Loading: %s", message);
    
    // Add to visible log buffer
    int idx = (app->log_buffer.log_start + app->log_buffer.log_count) % MAX_LOG_LINES;
    strncpy(app->log_buffer.log_lines[idx], message, 63);
    app->log_buffer.log_lines[idx][63] = '\0';
    
    if(app->log_buffer.log_count < MAX_LOG_LINES) {
        app->log_buffer.log_count++;
    } else {
        app->log_buffer.log_start = (app->log_buffer.log_start + 1) % MAX_LOG_LINES;
    }
    
    // Force screen update during loading
    if(app->view_port) {
        view_port_update(app->view_port);
    }
}

/* Compute phone hash like Apple does: sha256(phone_digits)[:4] */
static void compute_phone_hash(const char* phone_number, uint8_t* hash_out) {
    // Remove + from E164 format
    const char* digits = phone_number;
    if(*digits == '+') digits++;
    
    // Debug logging
    FURI_LOG_D(TAG, "compute_phone_hash: input='%s', digits='%s'", phone_number, digits);
    
    // Compute SHA256
    picohash_ctx_t ctx;
    picohash_init_sha256(&ctx);
    picohash_update(&ctx, digits, strlen(digits));
    
    uint8_t full_hash[PICOHASH_SHA256_DIGEST_LENGTH];
    picohash_final(&ctx, full_hash);
    
    // Take first 2 bytes (4 hex chars)
    hash_out[0] = full_hash[0];
    hash_out[1] = full_hash[1];
    
    FURI_LOG_D(TAG, "compute_phone_hash: result=%02X%02X", hash_out[0], hash_out[1]);
}


/* Load phone numbers from text file */
static void load_phone_numbers(AppleBleHashDemo* app) {
    if(!app->use_brute_force || strlen(app->brute_force_file) == 0) {
        return;
    }
    
    // Free existing phone numbers if any
    if(app->phone_numbers) {
        free(app->phone_numbers);
        app->phone_numbers = NULL;
        app->phone_numbers_count = 0;
        app->phone_numbers_capacity = 0;
    }
    
    // Free hash database
    phone_hash_db_free(&app->hash_db);
    
    Storage* storage = furi_record_open(RECORD_STORAGE);
    Stream* stream = buffered_file_stream_alloc(storage);
    
    if(!buffered_file_stream_open(stream, app->brute_force_file, FSAM_READ, FSOM_OPEN_EXISTING)) {
        FURI_LOG_E(TAG, "Failed to open brute force file: %s", app->brute_force_file);
        char log_msg[64];
        snprintf(log_msg, sizeof(log_msg), "Failed to open file!");
        add_log_message(app, log_msg);
        stream_free(stream);
        furi_record_close(RECORD_STORAGE);
        return;
    }
    
    // Show initial loading message
    add_log_message(app, "Opening file...");
    view_port_update(app->view_port);
    
    // Allocate initial array
    app->phone_numbers_capacity = 100;
    app->phone_numbers = malloc(sizeof(phone_e164_t) * app->phone_numbers_capacity);
    if(!app->phone_numbers) {
        FURI_LOG_E(TAG, "Failed to allocate memory for phone numbers");
        buffered_file_stream_close(stream);
        stream_free(stream);
        furi_record_close(RECORD_STORAGE);
        return;
    }
    
    add_log_message(app, "Reading phone numbers...");
    view_port_update(app->view_port);
    
    FuriString* line_buffer = furi_string_alloc();
    size_t lines_read = 0;
    size_t parse_failures = 0;
    
    while(stream_read_line(stream, line_buffer)) {
        lines_read++;
        
        const char* line_cstr = furi_string_get_cstr(line_buffer);
        
        // Skip empty lines
        if(furi_string_size(line_buffer) == 0) {
            continue;
        }
        
        // Try to parse the phone number
        phone_e164_t parsed_phone;
        if(phone_parse_e164(line_cstr, &parsed_phone) == 0) {
            // Successfully parsed
            if(app->phone_numbers_count >= app->phone_numbers_capacity) {
                // Grow array if needed
                if(app->phone_numbers_capacity < MAX_PHONE_NUMBERS) {
                    size_t new_capacity = app->phone_numbers_capacity * 2;
                    if(new_capacity > MAX_PHONE_NUMBERS) {
                        new_capacity = MAX_PHONE_NUMBERS;
                    }
                    phone_e164_t* new_array = realloc(app->phone_numbers, sizeof(phone_e164_t) * new_capacity);
                    if(new_array) {
                        app->phone_numbers = new_array;
                        app->phone_numbers_capacity = new_capacity;
                    } else {
                        FURI_LOG_W(TAG, "Failed to grow phone numbers array");
                        break;
                    }
                } else {
                    FURI_LOG_W(TAG, "Reached maximum phone numbers limit");
                    break;
                }
            }
            
            // Add to array
            app->phone_numbers[app->phone_numbers_count] = parsed_phone;
            app->phone_numbers_count++;
            
            FURI_LOG_D(TAG, "Loaded phone: %s (CC: %s, National: %s)", 
                       parsed_phone.e164, parsed_phone.cc, parsed_phone.national);
        } else {
            parse_failures++;
            FURI_LOG_D(TAG, "Failed to parse line %zu: %s", lines_read, line_cstr);
        }
    }
    
    furi_string_free(line_buffer);
    buffered_file_stream_close(stream);
    stream_free(stream);
    furi_record_close(RECORD_STORAGE);
    
    FURI_LOG_I(TAG, "Loaded %zu phone numbers from %zu lines (%zu parse failures)", 
               app->phone_numbers_count, lines_read, parse_failures);
    
    char log_msg[64];
    snprintf(log_msg, sizeof(log_msg), "Read %zu phone numbers", app->phone_numbers_count);
    add_log_message(app, log_msg);
    view_port_update(app->view_port);
    
    // Build hash lookup database
    if(app->phone_numbers_count > 0) {
        add_log_message(app, "Building hash database...");
        view_port_update(app->view_port);
        if(phone_hash_db_init(&app->hash_db) == 0) {
            for(size_t i = 0; i < app->phone_numbers_count; i++) {
                uint8_t hash[2];
                compute_phone_hash(app->phone_numbers[i].e164, hash);
                phone_hash_db_add_entry(&app->hash_db, hash, app->phone_numbers[i].e164);
            }
            FURI_LOG_I(TAG, "Built hash lookup database with %zu entries", app->hash_db.count);
        } else {
            FURI_LOG_E(TAG, "Failed to initialize hash database");
        }
    }
    
    // Show loading status with progress updates
    snprintf(log_msg, sizeof(log_msg), "Loaded %zu phone numbers", app->phone_numbers_count);
    add_log_message(app, log_msg);
    view_port_update(app->view_port);
    
    // Show brief flash of samples
    if(app->hash_db.count > 0) {
        size_t samples_to_show = app->hash_db.count < 3 ? app->hash_db.count : 3;
        for(size_t i = 0; i < samples_to_show; i++) {
            snprintf(log_msg, sizeof(log_msg), "%s → %02X%02X", 
                     app->hash_db.entries[i].phone,
                     app->hash_db.entries[i].hash[0], 
                     app->hash_db.entries[i].hash[1]);
            add_log_message(app, log_msg);
            view_port_update(app->view_port);
        }
        
        // Wait longer to show the loading status
        furi_delay_ms(2500);
        
        // Clear the log buffer to start fresh
        app->log_buffer.log_count = 0;
        app->log_buffer.log_start = 0;
    }
}

/* Helper function to sort hashes alphabetically */
static void sort_hashes_alphabetically(uint8_t hashes[][2], uint8_t count) {
    for(uint8_t i = 1; i < count; i++) {
        uint8_t temp[2];
        memcpy(temp, hashes[i], 2);
        uint8_t j = i;
        
        // Compare as big-endian 16-bit values for alphabetical ordering
        uint16_t temp_val = (temp[0] << 8) | temp[1];
        while(j > 0) {
            uint16_t prev_val = (hashes[j-1][0] << 8) | hashes[j-1][1];
            if(prev_val <= temp_val) break;
            memcpy(hashes[j], hashes[j-1], 2);
            j--;
        }
        memcpy(hashes[j], temp, 2);
    }
}

/* Parse old AirDrop packet (type 0x05) from full raw packet - now extracts ALL possible hashes */
static void parse_airdrop_old_from_full_packet(AppleBleHashDemo* app, const uint8_t* mac __attribute__((unused)), const uint8_t* full_packet, uint16_t full_len, int8_t rssi) {
    app->airdrop_packets_seen++;
    
    // Find the AD payload start (after HCI header)
    if(full_len < 14) return;
    uint8_t ad_len = full_packet[13];
    if(full_len < 14 + ad_len) return;
    
    // Find manufacturer data in AD payload
    const uint8_t* ad_data = full_packet + 14;
    uint8_t mfg_len = 0;
    const uint8_t* mfg_data = find_ad_type(ad_data, ad_len, 0xFF, &mfg_len);
    
    if(!mfg_data || mfg_len < 2) return;
    
    // Check Apple company ID
    uint16_t company_id = mfg_data[0] | (mfg_data[1] << 8);
    if(company_id != APPLE_COMPANY_ID) return;
    
    // The AirDrop data starts after company ID
    const uint8_t* apple_data = mfg_data + 2;
    uint8_t apple_len = mfg_len - 2;
    
    // Find AirDrop type 0x05 in Apple TLV structure
    uint8_t offset = 0;
    while(offset + 1 < apple_len) {
        uint8_t type = apple_data[offset];
        uint8_t type_len = apple_data[offset + 1];
        
        if(offset + 2 + type_len > apple_len) break;
        
        if(type == AIRDROP_TYPE) {
            // Found AirDrop packet
            const uint8_t* airdrop_data = apple_data + offset + 2;
            
            // Log full packet for debugging
            char packet_hex[256];
            char* hex_ptr = packet_hex;
            for(uint8_t i = 0; i < full_len && i < 120; i++) {
                hex_ptr += snprintf(hex_ptr, 4, "%02X ", full_packet[i]);
            }
            if(full_len > 120) {
                snprintf(hex_ptr, 4, "...");
            }
            FURI_LOG_I(TAG, "Full packet (%d bytes): %s", full_len, packet_hex);
            
            // Extract ALL possible 2-byte sequences from the hash section
            // Based on your analysis, we know the hash section starts after the initial structure
            uint8_t extracted_hashes[MAX_EXTRACTED_HASHES][2];
            uint8_t num_extracted = 0;
            const char* matched_phone = NULL;
            
            if(type_len >= 15) {  // Minimum required for AirDrop structure
                // Skip the known structure: 8 zeros + 1 status + 2 AppleID = 11 bytes
                // The hash section starts at position 11 and continues for remaining bytes
                uint8_t hash_section_start = 11;
                
                // Extract all possible 2-byte sequences from the hash section
                for(uint8_t pos = hash_section_start; pos + 1 < type_len && num_extracted < MAX_EXTRACTED_HASHES; pos += 2) {
                    extracted_hashes[num_extracted][0] = airdrop_data[pos];
                    extracted_hashes[num_extracted][1] = airdrop_data[pos + 1];
                    num_extracted++;
                }
                
                // Sort the extracted hashes alphabetically
                sort_hashes_alphabetically(extracted_hashes, num_extracted);
                
                // If we have a brute force database, try to match any of the extracted hashes
                if(app->use_brute_force && app->hash_db.count > 0) {
                    for(uint8_t i = 0; i < num_extracted; i++) {
                        matched_phone = phone_hash_db_lookup(&app->hash_db, extracted_hashes[i]);
                        if(matched_phone) {
                            FURI_LOG_I(TAG, "MATCH FOUND! Hash %02X%02X -> Phone: %s", 
                                      extracted_hashes[i][0], extracted_hashes[i][1], matched_phone);
                            break;  // Found a match, stop looking
                        }
                    }
                }
                
                // Log all extracted hashes for debugging
                char hash_log[128];
                char* log_ptr = hash_log;
                log_ptr += snprintf(log_ptr, sizeof(hash_log), "Extracted hashes: ");
                for(uint8_t i = 0; i < num_extracted; i++) {
                    log_ptr += snprintf(log_ptr, sizeof(hash_log) - (log_ptr - hash_log), 
                                       "%02X%02X ", extracted_hashes[i][0], extracted_hashes[i][1]);
                }
                FURI_LOG_I(TAG, "%s", hash_log);
            }
            
            // Create or update hash entry with all extracted hashes
            if(num_extracted > 0) {
                HashEntry* entry = find_or_add_hash_entry(app, extracted_hashes, num_extracted, full_packet, full_len, rssi);
                
                // If we found a match, store the matched phone
                if(matched_phone && entry) {
                    strncpy(entry->matched_phone, matched_phone, 16);
                    entry->matched_phone[16] = '\0';
                    app->matches_found++;
                    
                    // Flash LED for match
                    furi_hal_light_set(LightRed, 0xFF);
                    furi_delay_ms(100);
                    furi_hal_light_set(LightRed, 0x00);
                }
            }
            
            return;  // Found and processed AirDrop packet
        }
        
        offset += 2 + type_len;
    }
}


/* Parse BLE packet TLV structure */
static void parse_ble_packet_tlv(const uint8_t* data, uint8_t len, AppleBleHashDemo* app, const uint8_t* mac, const uint8_t* full_packet, uint16_t full_len, int8_t rssi) {
    uint8_t offset = 0;
    
    while(offset + 1 < len) {
        uint8_t type = data[offset];
        uint8_t type_len = data[offset + 1];
        
        if(offset + 2 + type_len > len) break;
        
        if(type == AIRDROP_TYPE) {
            parse_airdrop_old_from_full_packet(app, mac, full_packet, full_len, rssi);
        }
        
        offset += 2 + type_len;
    }
}

/* GAP-observation packet callback */
static void sniffer_packet_cb(const uint8_t* data, uint16_t len, int8_t rssi, void* ctx) {
    AppleBleHashDemo* app = ctx;
    if(!app) return;
    
    app->packets_seen++;
    
    // LED flicker for packet received
    furi_hal_light_set(LightGreen, 0xFF);
    furi_delay_ms(25);
    furi_hal_light_set(LightGreen, 0x00);
    
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
    
    // Find manufacturer specific data (type 0xFF)
    uint8_t mfg_len = 0;
    const uint8_t* mfg_data = find_ad_type(ad_data, ad_len, 0xFF, &mfg_len);
    
    if(mfg_data && mfg_len >= 2) {
        uint16_t company_id = mfg_data[0] | (mfg_data[1] << 8);
        
        if(company_id == APPLE_COMPANY_ID) {
            FURI_LOG_D(TAG, "Apple packet found, mfg_len=%d", mfg_len);
            
            // Parse Apple TLV data after company ID
            if(mfg_len > 2) {
                parse_ble_packet_tlv(&mfg_data[2], mfg_len - 2, app, mac, data, len, rssi);
            }
        }
    }
}

/* Remove old entries */
static void remove_old_entries(AppleBleHashDemo* app) {
    uint32_t current_time = furi_get_tick() / 1000;
    size_t write_idx = 0;
    
    for(size_t i = 0; i < app->hash_count; i++) {
        // Keep entries that are either:
        // 1. Matched phones (permanent)
        // 2. Unmatched hashes seen in last 60 seconds
        bool is_matched = strlen(app->hashes[i].matched_phone) > 0;
        bool is_recent = (current_time - app->hashes[i].timestamp < 60);
        
        if(is_matched || is_recent) {
            if(write_idx != i) {
                app->hashes[write_idx] = app->hashes[i];
            }
            write_idx++;
        }
    }
    
    app->hash_count = write_idx;
}


static void draw_config_screen(Canvas* canvas, AppleBleHashDemo* app) {
    canvas_clear(canvas);
    canvas_set_color(canvas, ColorBlack);
    
    // Header with icon-like decoration
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 64, 3, AlignCenter, AlignTop, "AirDrop Hash Demo");
    
    // Draw divider line
    canvas_draw_line(canvas, 10, 14, 118, 14);
    
    // Configuration options
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(canvas, 64, 20, AlignCenter, AlignTop, "Configuration");
    
    // Option 1: Continue without brute force
    canvas_draw_rframe(canvas, 8, 30, 112, 13, 3);
    if(app->config_selection == 0) {
        canvas_draw_rbox(canvas, 9, 31, 110, 11, 2);
        canvas_set_color(canvas, ColorWhite);
    }
    canvas_draw_str_aligned(canvas, 64, 33, AlignCenter, AlignTop, "Show Phone Hashes Only");
    canvas_set_color(canvas, ColorBlack);
    
    // Option 2: Select brute force file
    canvas_draw_rframe(canvas, 8, 46, 112, 13, 3);
    if(app->config_selection == 1) {
        canvas_draw_rbox(canvas, 9, 47, 110, 11, 2);
        canvas_set_color(canvas, ColorWhite);
    }
    canvas_draw_str_aligned(canvas, 64, 49, AlignCenter, AlignTop, "Select Brute Force File");
    canvas_set_color(canvas, ColorBlack);
}

/* Sort hash entries by timestamp (most recent first) */
static void sort_hashes_by_timestamp(HashEntry* hashes, size_t count) {
    for(size_t i = 1; i < count; i++) {
        HashEntry temp = hashes[i];
        size_t j = i;
        
        // Move older entries to the right
        while(j > 0 && hashes[j-1].timestamp < temp.timestamp) {
            hashes[j] = hashes[j-1];
            j--;
        }
        
        hashes[j] = temp;
    }
}

static void draw_sniffer_screen(Canvas* canvas, AppleBleHashDemo* app) {
    char buf[128];
    
    canvas_clear(canvas);
    canvas_set_color(canvas, ColorBlack);
    
    // Title bar with hash count and packet count
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 1, 2, AlignLeft, AlignTop, "AirDox Sniffer");
    
    canvas_set_font(canvas, FontSecondary);
    
    // Add packet counter in P:1k format
    if(app->packets_seen >= 1000) {
        snprintf(buf, sizeof(buf), "P:%luk", app->packets_seen / 1000);
    } else {
        snprintf(buf, sizeof(buf), "P:%lu", app->packets_seen);
    }
    canvas_draw_str_aligned(canvas, 100, 2, AlignLeft, AlignTop, buf);
    
    // Add matches counter if brute force is enabled
    if(app->use_brute_force) {
        snprintf(buf, sizeof(buf), "M:%lu", app->matches_found);
        canvas_draw_str_aligned(canvas, 75, 2, AlignLeft, AlignTop, buf);
        // Adjust packet counter position when matches shown
        if(app->packets_seen >= 1000) {
            snprintf(buf, sizeof(buf), "P:%luk", app->packets_seen / 1000);
        } else {
            snprintf(buf, sizeof(buf), "P:%lu", app->packets_seen);
        }
        canvas_draw_str_aligned(canvas, 100, 2, AlignLeft, AlignTop, buf);
    }
    
    // Define column positions
    int col_phone = 0;     // Phone/Hash column
    int col_count = 80;    // Count column
    int col_rssi = 105;    // RSSI column
    
    // Column headers
    canvas_draw_str_aligned(canvas, col_phone, 12, AlignLeft, AlignTop, "Phone/Hash");
    canvas_draw_str_aligned(canvas, col_count, 12, AlignLeft, AlignTop, "Num");
    canvas_draw_str_aligned(canvas, col_rssi, 12, AlignLeft, AlignTop, "dBm");
    
    // Sort hashes by timestamp (most recent first)
    if(app->hash_count > 0) {
        sort_hashes_by_timestamp(app->hashes, app->hash_count);
    }
    
    // Hash list
    int y = 22;
    size_t max_visible = 5; // Show 5 hashes with good spacing
    
    size_t visible_count = 0;
    size_t current_index = app->scroll_pos;
    
    while(visible_count < max_visible && current_index < app->hash_count && y < 64) {
        HashEntry* entry = &app->hashes[current_index];
        
        // Phone number or hash display
        if(strlen(entry->matched_phone) > 0) {
            // Show matched phone number (truncated if needed)
            char phone_display[20];
            strncpy(phone_display, entry->matched_phone, 19);
            phone_display[19] = '\0';
            canvas_draw_str_aligned(canvas, col_phone, y, AlignLeft, AlignTop, phone_display);
        } else {
            // Show all extracted hashes (sorted alphabetically)
            char hash_display[32];
            char* hash_ptr = hash_display;
            
            for(uint8_t i = 0; i < entry->num_extracted_hashes && hash_ptr < hash_display + sizeof(hash_display) - 5; i++) {
                hash_ptr += snprintf(hash_ptr, hash_display + sizeof(hash_display) - hash_ptr, 
                                   "%02X%02X", entry->extracted_hashes[i][0], entry->extracted_hashes[i][1]);
                // Add space between hashes except for the last one
                if(i < entry->num_extracted_hashes - 1 && hash_ptr < hash_display + sizeof(hash_display) - 2) {
                    *hash_ptr++ = ' ';
                }
            }
            *hash_ptr = '\0';
            
            canvas_draw_str_aligned(canvas, col_phone, y, AlignLeft, AlignTop, hash_display);
        }
        
        // Count
        snprintf(buf, sizeof(buf), "%lu", entry->seen_count);
        canvas_draw_str_aligned(canvas, col_count, y, AlignLeft, AlignTop, buf);
        
        // RSSI
        snprintf(buf, sizeof(buf), "%d", (int)entry->rssi);
        canvas_draw_str_aligned(canvas, col_rssi, y, AlignLeft, AlignTop, buf);
        
        y += 10;
        visible_count++;
        current_index++;
    }
    
    // Vertical scroll indicators
    if(app->hash_count > 0) {
        // Up arrow
        if(app->scroll_pos > 0) {
            canvas_draw_str_aligned(canvas, 122, 22, AlignLeft, AlignTop, "^");
        }
        // Down arrow - check if there are more hashes to show
        if(current_index < app->hash_count) {
            canvas_draw_str_aligned(canvas, 122, 55, AlignLeft, AlignTop, "v");
        }
    }
}

static void draw_cb(Canvas* canvas, void* ctx) {
    AppleBleHashDemo* app = ctx;
    
    if(app->state == AppStateConfig) {
        draw_config_screen(canvas, app);
    } else if(app->state == AppStateLoading) {
        // Show loading screen
        canvas_clear(canvas);
        canvas_set_color(canvas, ColorBlack);
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str_aligned(canvas, 64, 3, AlignCenter, AlignTop, "Loading Phone Numbers");
        
        canvas_set_font(canvas, FontSecondary);
        int y = 25; // Start lower on the screen
        int max_visible_lines = 4; // Show 4 lines instead of 5
        
        // Auto-scroll to show the most recent messages
        int start_line = 0;
        if(app->log_buffer.log_count > max_visible_lines) {
            start_line = app->log_buffer.log_count - max_visible_lines;
        }
        
        for(int i = 0; i < max_visible_lines && i < app->log_buffer.log_count && y < 56; i++) {
            int idx = (app->log_buffer.log_start + start_line + i) % MAX_LOG_LINES;
            canvas_draw_str(canvas, 2, y, app->log_buffer.log_lines[idx]);
            y += 10;
        }
    } else {
        draw_sniffer_screen(canvas, app);
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
    app->state = AppStateConfig;  // Start in config state
    app->config_selection = 0;     // Default to "continue without"
    
    view_port_draw_callback_set(app->view_port, draw_cb, app);
    view_port_input_callback_set(app->view_port, input_cb, app);
    
    app->gui = furi_record_open("gui");
    gui_add_view_port(app->gui, app->view_port, GuiLayerFullscreen);
    
    InputEvent input;
    bool exit_loop = false;
    uint32_t last_cleanup = 0;
    
    while(!exit_loop) {
        // Handle loading state
        if(app->state == AppStateLoading) {
            // Update the screen first to show loading
            view_port_update(app->view_port);
            furi_delay_ms(50); // Small delay to ensure screen updates
            
            // Load phone numbers from file
            load_phone_numbers(app);
            
            // Transition to sniffer state after loading
            app->state = AppStateSniffer;
            
            // Start sniffer
            furi_hal_bt_lock_core2();
            furi_hal_bt_stop_advertising();
            furi_hal_bt_unlock_core2();
            
            furi_hal_bt_reinit();
            furi_delay_ms(500);
            
            if(furi_hal_bt_sniffer_start(sniffer_packet_cb, app)) {
                app->sniffer_active = true;
                FURI_LOG_I(TAG, "BLE sniffer started with brute force file");
            } else {
                FURI_LOG_E(TAG, "Failed to start BLE sniffer");
            }
        }
        
        // Cleanup old entries periodically (only in sniffer mode)
        if(app->state == AppStateSniffer) {
            uint32_t now = furi_get_tick() / 1000;
            if(now - last_cleanup >= 5) {
                remove_old_entries(app);
                last_cleanup = now;
            }
        }
        
        if(furi_message_queue_get(app->input_queue, &input, 10) == FuriStatusOk) {
            if(input.type == InputTypePress) {
                if(app->state == AppStateConfig) {
                    // Handle config screen input
                    switch(input.key) {
                    case InputKeyUp:
                        if(app->config_selection > 0) app->config_selection--;
                        break;
                    case InputKeyDown:
                        if(app->config_selection < 1) app->config_selection++;
                        break;
                    case InputKeyOk:
                        // Handle selection
                        if(app->config_selection == 0) {
                            // Continue without brute force
                            app->use_brute_force = false;
                            app->state = AppStateSniffer;
                            
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
                        } else {
                            // Open file browser for .txt selection
                            DialogsApp* dialogs = furi_record_open(RECORD_DIALOGS);
                            DialogsFileBrowserOptions browser_options;
                            dialog_file_browser_set_basic_options(&browser_options, ".txt", NULL);
                            browser_options.base_path = "/ext";
                            browser_options.hide_ext = false;
                            
                            FuriString* selected_path = furi_string_alloc();
                            
                            bool file_selected = dialog_file_browser_show(
                                dialogs,
                                selected_path,
                                selected_path,
                                &browser_options);
                            
                            furi_record_close(RECORD_DIALOGS);
                            
                            if(file_selected) {
                                // File was selected
                                strncpy(app->brute_force_file, furi_string_get_cstr(selected_path), sizeof(app->brute_force_file) - 1);
                                app->brute_force_file[sizeof(app->brute_force_file) - 1] = '\0';
                                app->use_brute_force = true;
                                app->state = AppStateLoading;
                                
                                FURI_LOG_I(TAG, "Selected brute force file: %s", app->brute_force_file);
                                
                                // Don't load immediately - let the loading screen show first
                            } else {
                                // User cancelled file selection - stay on config screen
                                FURI_LOG_I(TAG, "File selection cancelled");
                            }
                            
                            furi_string_free(selected_path);
                        }
                        break;
                    case InputKeyBack:
                        exit_loop = true;
                        break;
                    default:
                        break;
                    }
                } else {
                    // Handle sniffer screen input
                    switch(input.key) {
                    case InputKeyUp:
                        if(app->scroll_pos > 0) {
                            app->scroll_pos--;
                        }
                        break;
                    case InputKeyDown:
                        // Check if we can scroll down more
                        if(app->scroll_pos < app->hash_count - 1) {
                            app->scroll_pos++;
                        }
                        break;
                    case InputKeyOk:
                        // Clear only non-matched hashes
                        size_t write_idx = 0;
                        for(size_t i = 0; i < app->hash_count; i++) {
                            // Keep matched entries
                            if(strlen(app->hashes[i].matched_phone) > 0) {
                                if(write_idx != i) {
                                    app->hashes[write_idx] = app->hashes[i];
                                }
                                write_idx++;
                            }
                        }
                        app->hash_count = write_idx;
                        if(app->scroll_pos >= app->hash_count && app->hash_count > 0) {
                            app->scroll_pos = app->hash_count - 1;
                        }
                        // Reset packet counters but not matches
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
    
    // Free phone numbers if allocated
    if(app->phone_numbers) {
        free(app->phone_numbers);
    }
    
    // Free hash database
    phone_hash_db_free(&app->hash_db);
    
    free(app);
    
    return 0;
}