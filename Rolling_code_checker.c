// rolling_code_checker.c
// Rolling Code vs Fixed Code detector
// GUI style: black background, white frame, BigNumbers title (matches IR Raw)
//
// RX pipeline: SubGhzWorker + SubGhzReceiver, run against subghz_protocol_registry.
// Verdicts come from Flipper's own protocol classification (protocol->type,
// Static/Dynamic) rather than a raw-byte guess. Two-press capture flow
// ("Sig 1 / Sig 2") confirms the same protocol decodes on both presses and
// compares payload hashes between them.

#include <furi.h>
#include <furi/core/string.h>
#include <gui/gui.h>
#include <gui/view_port.h>
#include <notification/notification.h>
#include <notification/notification_messages.h>
#include <subghz/subghz_worker.h>
#include <subghz/receiver.h>
#include <subghz/environment.h>
#include <subghz/registry.h>
#include <subghz/protocols/base.h>
#include <subghz/devices/devices.h>
#include <subghz/devices/preset.h>
#include <subghz/devices/cc1101_int/cc1101_int_interconnect.h>
#include <storage/storage.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define TAG "RCC"

#define SETTINGS_DIR  EXT_PATH("apps_data/rolling_code_checker")
#define SETTINGS_PATH EXT_PATH("apps_data/rolling_code_checker/settings.txt")

extern const SubGhzProtocolRegistry subghz_protocol_registry;

// ============================================================================
// CONSTANTS
// ============================================================================

#define CAPTURE_TIMEOUT_MS  8000  // 8 s to press remote
#define AUTO_FREQ_DWELL_MS  800   // time to listen on each auto freq
#define TIMER_PERIOD_MS     40    // ~25 Hz UI refresh

#define DEFAULT_FREQ_HZ 433920000U

static const uint32_t kFreqPresets[] = {
    300000000U,
    315000000U,
    390000000U,
    418000000U,
    430500000U,
    433920000U,
    868350000U,
    915000000U,
};
#define FREQ_PRESET_COUNT (sizeof(kFreqPresets) / sizeof(kFreqPresets[0]))

// ============================================================================
// TYPES
// ============================================================================

typedef enum {
    SceneMenu,
    SceneFreqSelect,
    SceneCapture1,
    SceneCapture2,
    SceneComparing,
    SceneResult,
    SceneAutoFreq,
    SceneSettings,
    SceneAbout,
} Scene;

typedef enum {
    VerdictNone,
    VerdictFixed,
    VerdictRolling,
    VerdictAmbiguous,
    VerdictTimeout,
    VerdictNoDevice,
    VerdictFreqBlocked,
} Verdict;

// Main menu items
typedef enum {
    MenuCompare = 0,
    MenuAutoFreq,
    MenuFreqSelect,
    MenuSettings,
    MenuRadioToggle,
    MenuAbout,
    MenuCount,
} MenuSel;

// Capture engine mode — mutually exclusive, persisted to SD card
typedef enum {
    ModeDecoder = 0,  // full protocol decode
    ModeBinRaw,       // decode known protocols; unmatched signals fall back to BinRAW
    ModeReadRawOnly,  // no decode — raw pulse timing capture and compare
} CaptureMode;

#define RAW_MAX_SAMPLES  512
#define RAW_MIN_SAMPLES  20    // need at least this many transitions to count as a real signal
#define RAW_SILENCE_MS   150   // this much quiet after the last edge = end of this press

// Two independent captures are rarely index-aligned — one stray edge at the
// start of either shifts everything after it. We search a range of offsets
// and keep the best-scoring alignment. Throttled to a few offsets per timer
// tick so the search runs over ~2s instead of one big blocking pass.
#define RAW_COMPARE_MAX_OFFSET      110
#define RAW_COMPARE_TOTAL_OFFSETS   (RAW_COMPARE_MAX_OFFSET * 2 + 1)
#define RAW_COMPARE_OFFSETS_PER_TICK 4

// Squelch: ignore pulses unless RSSI is above this. The CC1101's OOK
// envelope detector reports noise-triggered toggles even with no carrier
// present, so without a floor we'd capture static as if it were a signal.
#define RAW_RSSI_SQUELCH_DBM  -90.0f

typedef struct {
    bool     valid;
    int32_t  timing[RAW_MAX_SAMPLES]; // + = high-level duration, - = low-level duration (matches RAW_Data sign convention)
    uint16_t count;
    uint32_t last_edge_tick;
} RawCapture;

// Result of a single capture attempt (one button press)
typedef struct {
    bool    valid;   // did we get a recognized protocol?
    char    name[24]; // protocol name, e.g. "Princeton"
    uint8_t type;      // SubGhzProtocolType (Static/Dynamic/RAW)
    uint8_t hash;       // per-decode payload hash from the protocol's own get_hash_data
} CaptureResult;

typedef struct {
    // Core state
    Scene    scene;
    Scene    prev_scene;
    bool     running;

    // Radio
    uint32_t frequency;
    bool     use_external;
    char     radio_name[24];
    const SubGhzDevice* device;
    const SubGhzDevice* began_device; // device we currently hold begin() on
    bool     rx_active;               // true while subghz_devices_start_async_rx is active

    // Sub-GHz decode pipeline
    SubGhzEnvironment* environment;
    SubGhzReceiver*    receiver;
    SubGhzWorker*      worker;

    // Capture
    CaptureResult cap1;
    CaptureResult cap2;
    RawCapture    raw1;
    RawCapture    raw2;
    float         last_rssi; // polled each tick while capturing in raw mode
    bool    armed;
    uint32_t deadline;

    // Settings
    CaptureMode mode;
    uint8_t     settings_sel;

    // Raw-mode alignment search ("Comparing...") state
    int16_t  compare_offset;
    uint16_t compare_done;
    float    compare_best_score;
    uint8_t  compare_progress;

    // Set from the SubGhzWorker thread's decode callback, consumed on the
    // timer thread. subghz_worker_stop() must never be called from inside
    // the decode callback — it runs on the worker's own thread, which can't
    // stop/join itself.
    volatile bool pending_finish;
    volatile bool pending_auto_found;
    char auto_found_msg[48];

    // Result
    Verdict  verdict;
    float    confidence;

    // Menu
    uint8_t  menu_sel;

    // Freq select
    uint8_t  freq_sel;

    // Auto freq
    uint32_t auto_idx;
    uint32_t auto_deadline;
    bool     auto_found;

    // Ticker for animated dots
    uint32_t tick;

    // Status banner (timed)
    char     status[48];
    uint32_t status_until;

    // FURI
    Gui*              gui;
    ViewPort*         view_port;
    NotificationApp*  notifications;
    FuriTimer*        timer;
} App;

// ============================================================================
// HELPERS
// ============================================================================

static void app_redraw(App* app) {
    if(app && app->view_port) view_port_update(app->view_port);
}

static void set_status(App* app, const char* text, uint32_t ms) {
    snprintf(app->status, sizeof(app->status), "%s", text ? text : "");
    app->status_until = furi_get_tick() + furi_ms_to_ticks(ms);
}

static bool status_alive(App* app) {
    if(!app->status[0]) return false;
    return (int32_t)(app->status_until - furi_get_tick()) > 0;
}

static void freq_str(uint32_t hz, char* out, size_t sz) {
    uint32_t mhz = hz / 1000000U;
    uint32_t frac = (hz % 1000000U) / 10000U;
    snprintf(out, sz, "%lu.%02lu MHz", (unsigned long)mhz, (unsigned long)frac);
}

// ----------------------------------------------------------------------------
// Settings file (SD card, plain text):
//   Decoder=<ON/OFF>
//   BinRaw=<ON/OFF>
//   ReadRawOnly=<ON/OFF>
// Exactly one is ON at a time.
// ----------------------------------------------------------------------------
static void settings_load(App* app) {
    app->mode = ModeDecoder; // default

    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);

    if(storage_file_open(file, SETTINGS_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        char buf[128];
        uint16_t len = storage_file_read(file, buf, sizeof(buf) - 1);
        buf[len < sizeof(buf) ? len : sizeof(buf) - 1] = '\0';

        if(strstr(buf, "ReadRawOnly=ON")) {
            app->mode = ModeReadRawOnly;
        } else if(strstr(buf, "BinRaw=ON")) {
            app->mode = ModeBinRaw;
        } else {
            app->mode = ModeDecoder;
        }
    }

    storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
}

static void settings_save(App* app) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    storage_common_mkdir(storage, SETTINGS_DIR);

    File* file = storage_file_alloc(storage);
    if(storage_file_open(file, SETTINGS_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        char buf[128];
        int n = snprintf(
            buf,
            sizeof(buf),
            "Decoder=%s\nBinRaw=%s\nReadRawOnly=%s\n",
            app->mode == ModeDecoder ? "ON" : "OFF",
            app->mode == ModeBinRaw ? "ON" : "OFF",
            app->mode == ModeReadRawOnly ? "ON" : "OFF");
        storage_file_write(file, buf, n);
    }

    storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
}

// CC1101 hardware-valid bands (furi_hal_subghz_is_frequency_valid).
// Anything outside these ranges triggers furi_crash() at the device layer.
static bool freq_is_hardware_valid(uint32_t hz) {
    return ((hz >= 281000000U && hz <= 361000000U) ||
            (hz >= 378000000U && hz <= 481000000U) ||
            (hz >= 749000000U && hz <= 962000000U));
}

// ----------------------------------------------------------------------------
// Device power lifecycle. subghz_devices_get_by_name() only resolves a
// descriptor; begin()/end() actually power the CC1101 up/down and must
// bracket any use of the low-level start_async_rx/tx calls.
// ----------------------------------------------------------------------------
static void device_release(App* app) {
    if(app->began_device) {
        subghz_devices_end(app->began_device);
        app->began_device = NULL;
    }
}

static bool device_acquire(App* app, const SubGhzDevice* device) {
    if(app->began_device == device) return true; // already powered up
    device_release(app);
    if(!device) return false;
    subghz_devices_begin(device);
    app->began_device = device;
    return true;
}

// ============================================================================
// RX PIPELINE — SubGhzWorker feeds raw pulses into SubGhzReceiver for
// protocol matching, or (Read-Raw-Only mode) straight into our raw buffer.
// ============================================================================

static void raw_pair_callback(void* context, bool level, uint32_t duration);

static void subghz_rx_stop(App* app) {
    if(app->worker && subghz_worker_is_running(app->worker)) {
        subghz_worker_stop(app->worker);
    }
    if(app->rx_active && app->device) {
        subghz_devices_stop_async_rx(app->device);
    }
    app->rx_active = false;
}

static bool subghz_rx_start(App* app, uint32_t freq) {
    app->device = app->use_external
        ? subghz_devices_get_by_name("cc1101_ext")
        : subghz_devices_get_by_name(SUBGHZ_DEVICE_CC1101_INT_NAME);

    if(!app->device) {
        snprintf(app->radio_name, sizeof(app->radio_name), "No device");
        return false;
    }

    snprintf(app->radio_name, sizeof(app->radio_name), "%s",
             subghz_devices_get_name(app->device));

    // Must validate before touching hardware — an out-of-band frequency
    // triggers furi_crash() at the device layer.
    if(!freq_is_hardware_valid(freq)) {
        FURI_LOG_W(TAG, "Freq %lu outside CC1101 bands", (unsigned long)freq);
        return false;
    }

    subghz_rx_stop(app);

    if(!device_acquire(app, app->device)) {
        return false;
    }

    subghz_devices_reset(app->device);
    subghz_devices_load_preset(app->device, FuriHalSubGhzPresetOok650Async, NULL);
    app->frequency = subghz_devices_set_frequency(app->device, freq);

    if(app->mode == ModeReadRawOnly) {
        // No protocol decode — feed pulses straight into our own buffer.
        subghz_worker_set_pair_callback(app->worker, (SubGhzWorkerPairCallback)raw_pair_callback);
        subghz_worker_set_context(app->worker, app);
    } else {
        subghz_receiver_reset(app->receiver);
        uint32_t filter = SubGhzProtocolFlag_Decodable;
        if(app->mode == ModeBinRaw) {
            // Catch-all fallback for anything not matched by a named protocol.
            filter |= SubGhzProtocolFlag_BinRAW;
        }
        subghz_receiver_set_filter(app->receiver, filter);
        subghz_worker_set_pair_callback(app->worker, (SubGhzWorkerPairCallback)subghz_receiver_decode);
        subghz_worker_set_context(app->worker, app->receiver);
    }

    subghz_devices_start_async_rx(app->device, subghz_worker_rx_callback, app->worker);
    app->rx_active = true;

    subghz_worker_start(app->worker);
    return true;
}

// ============================================================================
// SCENE TRANSITIONS
// ============================================================================

static void go_menu(App* app) {
    subghz_rx_stop(app);
    app->scene = SceneMenu;
    app->armed = false;
}

static void reset_capture(App* app) {
    memset(&app->cap1, 0, sizeof(app->cap1));
    memset(&app->cap2, 0, sizeof(app->cap2));
    memset(&app->raw1, 0, sizeof(app->raw1));
    memset(&app->raw2, 0, sizeof(app->raw2));
    app->confidence = 0.0f;
    app->verdict = VerdictNone;
    app->armed = false;
}

static void start_compare(App* app) {
    reset_capture(app);

    if(!freq_is_hardware_valid(app->frequency)) {
        set_status(app, "Freq blocked — pick another", 2500);
        app->verdict = VerdictFreqBlocked;
        app->scene   = SceneResult;
        app_redraw(app);
        return;
    }

    if(!subghz_rx_start(app, app->frequency)) {
        set_status(app, "Radio start failed", 2000);
        app->verdict = VerdictFreqBlocked;
        app->scene   = SceneResult;
        app_redraw(app);
        return;
    }
    app->scene = SceneCapture1;
    set_status(app, "Press remote when armed", 2000);
    app_redraw(app);
}

static void start_auto_freq(App* app) {
    reset_capture(app);
    app->auto_idx   = 0;
    app->auto_found = false;

    // Find first hardware-valid preset to start on
    while(app->auto_idx < FREQ_PRESET_COUNT &&
          !freq_is_hardware_valid(kFreqPresets[app->auto_idx])) {
        app->auto_idx++;
    }

    if(app->auto_idx >= FREQ_PRESET_COUNT) {
        set_status(app, "No valid freqs for region", 2500);
        go_menu(app);
        app_redraw(app);
        return;
    }

    if(!subghz_rx_start(app, kFreqPresets[app->auto_idx])) {
        set_status(app, "No radio device", 2500);
        go_menu(app);
        app_redraw(app);
        return;
    }

    app->auto_deadline = furi_get_tick() + furi_ms_to_ticks(AUTO_FREQ_DWELL_MS);
    app->scene = SceneAutoFreq;
    app_redraw(app);
}

static void finish_result(App* app, Verdict v, float conf) {
    app->verdict    = v;
    app->confidence = conf;
    app->scene      = SceneResult;
    app->armed      = false;
    subghz_rx_stop(app);
    notification_message(app->notifications, &sequence_single_vibro);
    app_redraw(app);
}

// Compare the two captured presses and decide fixed vs. rolling.
static void finish_compare(App* app) {
    Verdict v;
    float conf;

    if(!app->cap1.valid || !app->cap2.valid) {
        v = VerdictAmbiguous;
        conf = 0.0f;
    } else if(strcmp(app->cap1.name, "BinRAW") == 0 && strcmp(app->cap2.name, "BinRAW") == 0) {
        // BinRAW has no inherent static/dynamic classification of its own —
        // compare payload hashes directly.
        v = (app->cap1.hash == app->cap2.hash) ? VerdictFixed : VerdictRolling;
        conf = 1.0f;
    } else if(strcmp(app->cap1.name, app->cap2.name) != 0) {
        // Different protocols on each press — fall back to the first
        // decode's own protocol-type classification.
        v = (app->cap1.type == SubGhzProtocolTypeDynamic) ? VerdictRolling : VerdictFixed;
        conf = 0.5f;
    } else if(app->cap1.type == SubGhzProtocolTypeDynamic) {
        // Known dynamic-code family (KeeLoq, Security+, Nice FloR-S, etc).
        v = VerdictRolling;
        conf = (app->cap1.hash != app->cap2.hash) ? 1.0f : 0.85f;
    } else {
        // Static-code family (Princeton, Came, Nice Flo, etc). Confirm the
        // payload actually matched between presses.
        v = (app->cap1.hash == app->cap2.hash) ? VerdictFixed : VerdictAmbiguous;
        conf = (app->cap1.hash == app->cap2.hash) ? 1.0f : 0.4f;
    }

    finish_result(app, v, conf);
}

// Timing similarity between two captures at a given alignment offset.
// Evaluated across a range of offsets by the Comparing scene; best-scoring
// offset wins.
static float raw_similarity_at_offset(const RawCapture* a, const RawCapture* b, int offset) {
    int start_a = offset < 0 ? -offset : 0;
    int start_b = offset > 0 ? offset : 0;
    int len_a = (int)a->count - start_a;
    int len_b = (int)b->count - start_b;
    int len = len_a < len_b ? len_a : len_b;
    if(len <= 0) return 0.0f;

    uint32_t close_loose = 0;
    uint32_t close_strict = 0;
    for(int i = 0; i < len; i++) {
        int32_t da = a->timing[start_a + i];
        int32_t db = b->timing[start_b + i];
        if((da < 0) != (db < 0)) continue; // level mismatch (high vs low)

        uint32_t ua = (uint32_t)(da < 0 ? -da : da);
        uint32_t ub = (uint32_t)(db < 0 ? -db : db);
        uint32_t base = ua > ub ? ua : ub;
        uint32_t diff = ua > ub ? ua - ub : ub - ua;
        if(base == 0) continue;
        float rel = (float)diff / (float)base;
        if(rel < 0.35f) close_loose++;   // roughly the same duration
        if(rel < 0.12f) close_strict++;  // very tightly matching duration
    }

    uint16_t mx = a->count > b->count ? a->count : b->count;
    float loose_score  = (float)close_loose / (float)len;
    float strict_score = (float)close_strict / (float)len;
    // Weight toward strict matches — rough agreement alone can be noise.
    float sample_score = loose_score * 0.3f + strict_score * 0.7f;
    float coverage_score = (float)len / (float)mx;
    return sample_score * 0.8f + coverage_score * 0.2f;
}

// Raw pulse capture for Read-Raw-Only mode. Runs on the SubGhzWorker
// thread — data fields only, no radio control (see decode callback below).
static void raw_pair_callback(void* context, bool level, uint32_t duration) {
    App* app = context;
    if(!app || !app->armed) return;
    if(app->scene != SceneCapture1 && app->scene != SceneCapture2) return;

    // Squelch — reject noise-triggered toggles when nothing is transmitting.
    if(app->last_rssi < RAW_RSSI_SQUELCH_DBM) return;

    RawCapture* rc = (app->scene == SceneCapture1) ? &app->raw1 : &app->raw2;
    if(rc->count < RAW_MAX_SAMPLES) {
        rc->timing[rc->count] = level ? (int32_t)duration : -(int32_t)duration;
        rc->count++;
    }
    rc->last_edge_tick = furi_get_tick();
}

// ============================================================================
// DECODE CALLBACK — fires on the SubGhzWorker thread when a pulse train
// matches a protocol in subghz_protocol_registry.
// ============================================================================

static void on_subghz_decode(SubGhzReceiver* receiver, SubGhzProtocolDecoderBase* decoder_base, void* context) {
    UNUSED(receiver);
    App* app = context;
    if(!app || !decoder_base || !decoder_base->protocol) return;

    const SubGhzProtocol* protocol = decoder_base->protocol;

    // Auto freq: any decode at all means there's a remote on this frequency.
    if(app->scene == SceneAutoFreq) {
        char fb[24];
        freq_str(app->frequency, fb, sizeof(fb));
        snprintf(app->auto_found_msg, sizeof(app->auto_found_msg), "%s on %s",
                 protocol->name ? protocol->name : "Signal", fb);
        app->pending_auto_found = true;
        return;
    }

    if((app->scene == SceneCapture1 || app->scene == SceneCapture2) && app->armed) {
        CaptureResult* slot = (app->scene == SceneCapture1) ? &app->cap1 : &app->cap2;

        snprintf(slot->name, sizeof(slot->name), "%s", protocol->name ? protocol->name : "?");
        slot->type = (uint8_t)protocol->type;
        slot->hash = 0;
        if(protocol->decoder && protocol->decoder->get_hash_data) {
            slot->hash = protocol->decoder->get_hash_data(decoder_base);
        }
        slot->valid = true;
        app->armed = false;

        notification_message(app->notifications, &sequence_single_vibro);

        if(app->scene == SceneCapture1) {
            app->scene    = SceneCapture2;
            app->deadline = furi_get_tick() + furi_ms_to_ticks(CAPTURE_TIMEOUT_MS);
            set_status(app, "Got sig 1 — arm for sig 2", 2000);
        } else {
            // Deferred to the timer thread — subghz_rx_stop() can't run
            // from inside this callback (see App.pending_finish above).
            app->pending_finish = true;
        }
        app_redraw(app);
    }
}

// ============================================================================
// TIMEOUTS
// ============================================================================

static void process_timeouts(App* app) {
    uint32_t now = furi_get_tick();

    if(app->scene == SceneComparing) {
        for(int i = 0; i < RAW_COMPARE_OFFSETS_PER_TICK && app->compare_offset <= RAW_COMPARE_MAX_OFFSET; i++) {
            float score = raw_similarity_at_offset(&app->raw1, &app->raw2, app->compare_offset);
            if(score > app->compare_best_score) app->compare_best_score = score;
            app->compare_offset++;
            app->compare_done++;
        }
        app->compare_progress = (uint8_t)((app->compare_done * 100U) / RAW_COMPARE_TOTAL_OFFSETS);

        if(app->compare_offset > RAW_COMPARE_MAX_OFFSET) {
            float score = app->compare_best_score;
            Verdict v;
            if(score >= 0.90f)      v = VerdictFixed;
            else if(score <= 0.72f) v = VerdictRolling;
            else                    v = VerdictAmbiguous;
            finish_result(app, v, score);
        } else {
            app_redraw(app);
        }
        return;
    }

    if(app->pending_finish) {
        app->pending_finish = false;
        finish_compare(app);
        return;
    }

    if(app->pending_auto_found) {
        app->pending_auto_found = false;
        set_status(app, app->auto_found_msg, 3000);
        app->auto_found = true;
        subghz_rx_stop(app);
        app->scene = SceneMenu;
        notification_message(app->notifications, &sequence_single_vibro);
        app_redraw(app);
        return;
    }

    if((app->scene == SceneCapture1 || app->scene == SceneCapture2) && app->armed) {
        // Read-Raw-Only: no decode event marks end of a press, so use a
        // gap of silence after the last edge instead.
        if(app->mode == ModeReadRawOnly) {
            if(app->device) {
                app->last_rssi = subghz_devices_get_rssi(app->device);
            }
            RawCapture* rc = (app->scene == SceneCapture1) ? &app->raw1 : &app->raw2;
            if(rc->count >= RAW_MIN_SAMPLES &&
               (int32_t)(now - rc->last_edge_tick) > (int32_t)furi_ms_to_ticks(RAW_SILENCE_MS)) {
                rc->valid = true;
                app->armed = false;
                notification_message(app->notifications, &sequence_single_vibro);

                if(app->scene == SceneCapture1) {
                    app->scene    = SceneCapture2;
                    app->deadline = now + furi_ms_to_ticks(CAPTURE_TIMEOUT_MS);
                    set_status(app, "Got sig 1 — arm for sig 2", 2000);
                } else {
                    app->scene              = SceneComparing;
                    app->compare_offset     = -RAW_COMPARE_MAX_OFFSET;
                    app->compare_done       = 0;
                    app->compare_best_score = 0.0f;
                    app->compare_progress   = 0;
                }
                app_redraw(app);
                return;
            }
        }

        if((int32_t)(now - app->deadline) >= 0) {
            finish_result(app, VerdictTimeout, 0.0f);
        }
        return;
    }

    if(app->scene == SceneAutoFreq) {
        if((int32_t)(now - app->auto_deadline) >= 0) {
            subghz_rx_stop(app);
            app->auto_idx++;

            // Skip any hardware-invalid freqs — passing them to the device
            // layer would crash.
            while(app->auto_idx < FREQ_PRESET_COUNT &&
                  !freq_is_hardware_valid(kFreqPresets[app->auto_idx])) {
                app->auto_idx++;
            }

            if(app->auto_idx >= FREQ_PRESET_COUNT) {
                set_status(app, "No signal found", 2500);
                app->scene = SceneMenu;
                app_redraw(app);
                return;
            }

            if(!subghz_rx_start(app, kFreqPresets[app->auto_idx])) {
                // Couldn't start this one — skip it next tick
                app->auto_deadline = furi_get_tick(); // expire immediately
            } else {
                app->auto_deadline = furi_get_tick() + furi_ms_to_ticks(AUTO_FREQ_DWELL_MS);
            }
            app_redraw(app);
        }
    }
}

// ============================================================================
// TIMER — runs every 40ms
// ============================================================================

static void timer_cb(void* ctx) {
    App* app = ctx;
    if(!app) return;

    app->tick++;

    // Expire status banner
    if(app->status[0] && !status_alive(app)) app->status[0] = '\0';

    process_timeouts(app);
    app_redraw(app);
}

// ============================================================================
// DRAW HELPERS — IR Raw style: black bg, white frame, BigNumbers title
// ============================================================================

// Shared header: fills black, draws title in BigNumbers, draws content frame
static void draw_header(Canvas* canvas, const char* title) {
    canvas_set_color(canvas, ColorBlack);
    canvas_draw_box(canvas, 0, 0, 128, 64);

    canvas_set_color(canvas, ColorWhite);
    canvas_set_font(canvas, FontBigNumbers);
    canvas_draw_str_aligned(canvas, 64, 2, AlignCenter, AlignTop, title);

    canvas_draw_frame(canvas, 2, 20, 124, 33);
}

static void draw_footer(Canvas* canvas, const char* text) {
    canvas_set_font(canvas, FontSecondary);
    canvas_set_color(canvas, ColorWhite);
    canvas_draw_str_aligned(canvas, 64, 63, AlignCenter, AlignBottom, text);
}

// Animated dots string into buf (buf must be ≥20 bytes)
static void anim_dots(uint32_t tick, const char* prefix, char* buf, size_t sz) {
    uint32_t d = (tick / 6) % 4; // ~1 dot per 240ms at 40ms tick
    if(d == 0)      snprintf(buf, sz, "%s", prefix);
    else if(d == 1) snprintf(buf, sz, "%s .", prefix);
    else if(d == 2) snprintf(buf, sz, "%s . .", prefix);
    else            snprintf(buf, sz, "%s . . .", prefix);
}

// ============================================================================
// DRAW: MENU
// ============================================================================

static void draw_menu(App* app, Canvas* canvas) {
    draw_header(canvas, "RCC");

    canvas_set_font(canvas, FontPrimary);
    canvas_set_color(canvas, ColorWhite);

    static const char* labels[MenuCount] = {
        "Compare Signals",
        "Auto Find Freq",
        "Set Frequency",
        "Settings",
        "Toggle Radio",
        "About",
    };

    // 3 rows fit in the 33px frame (y=28, y=38, y=48)
    // Scroll so selected item is always visible
    int8_t start = (int8_t)app->menu_sel - 1;
    if(start < 0) start = 0;
    if(start > (int8_t)MenuCount - 3) start = (int8_t)MenuCount - 3;
    if(start < 0) start = 0;

    for(int i = 0; i < 3; i++) {
        int idx = start + i;
        if(idx >= MenuCount) break;
        uint8_t y = 31 + (uint8_t)(i * 10);
        bool sel = (idx == (int)app->menu_sel);

        if(sel) {
            canvas_draw_box(canvas, 3, y - 8, 122, 10);
            canvas_set_color(canvas, ColorBlack);
        } else {
            canvas_set_color(canvas, ColorWhite);
        }
        canvas_draw_str(canvas, 6, y, labels[idx]);
        canvas_set_color(canvas, ColorWhite);
    }

    // Status or freq info in footer
    if(status_alive(app)) {
        draw_footer(canvas, app->status);
    } else {
        char fb[24];
        freq_str(app->frequency, fb, sizeof(fb));
        char info[32];
        snprintf(info, sizeof(info), "%s  %s",
                 app->use_external ? "EXT" : "INT", fb);
        draw_footer(canvas, info);
    }
}

// ============================================================================
// DRAW: FREQ SELECT
// ============================================================================

static void draw_freq_select(App* app, Canvas* canvas) {
    draw_header(canvas, "Freq");

    canvas_set_color(canvas, ColorWhite);

    int8_t start = (int8_t)app->freq_sel - 1;
    if(start < 0) start = 0;
    if(start > (int8_t)FREQ_PRESET_COUNT - 4) start = (int8_t)FREQ_PRESET_COUNT - 4;
    if(start < 0) start = 0;

    for(int i = 0; i < 4; i++) {
        int idx = start + i;
        if(idx >= (int)FREQ_PRESET_COUNT) break;
        uint8_t y = 28 + (uint8_t)(i * 8);
        bool sel = (idx == (int)app->freq_sel);
        bool valid = freq_is_hardware_valid(kFreqPresets[idx]);

        char fb[24];
        freq_str(kFreqPresets[idx], fb, sizeof(fb));

        if(sel) {
            canvas_draw_box(canvas, 3, y - 7, 118, 8);
            canvas_set_color(canvas, ColorBlack);
            canvas_set_font(canvas, FontPrimary);
        } else {
            canvas_set_color(canvas, ColorWhite);
            canvas_set_font(canvas, FontSecondary);
        }

        // Show blocked indicator for region-locked freqs
        if(!valid) {
            char blocked[28];
            snprintf(blocked, sizeof(blocked), "%s [!]", fb);
            canvas_draw_str(canvas, 6, y, blocked);
        } else {
            canvas_draw_str(canvas, 6, y, fb);
        }
        canvas_set_color(canvas, ColorWhite);
    }

    // Scrollbar
    if(FREQ_PRESET_COUNT > 4) {
        uint8_t bh = 30;
        uint8_t by = 21 + (app->freq_sel * bh) / FREQ_PRESET_COUNT;
        uint8_t th = bh / FREQ_PRESET_COUNT + 3;
        canvas_draw_box(canvas, 124, by, 2, th);
    }

    draw_footer(canvas, "OK=Select  [!]=blocked");
}

// ============================================================================
// DRAW: SETTINGS
// ============================================================================

static void draw_settings(App* app, Canvas* canvas) {
    draw_header(canvas, "Config");

    canvas_set_font(canvas, FontPrimary);
    canvas_set_color(canvas, ColorWhite);

    static const char* labels[3] = {"Decoder", "Bin Raw", "Read Raw Only"};

    for(int i = 0; i < 3; i++) {
        uint8_t y = 31 + (uint8_t)(i * 10);
        bool sel = (i == app->settings_sel);
        bool active = ((CaptureMode)i == app->mode);

        if(sel) {
            canvas_draw_box(canvas, 3, y - 8, 122, 10);
            canvas_set_color(canvas, ColorBlack);
        } else {
            canvas_set_color(canvas, ColorWhite);
        }

        char line[28];
        snprintf(line, sizeof(line), "%s %s", active ? "[x]" : "[ ]", labels[i]);
        canvas_draw_str(canvas, 6, y, line);
        canvas_set_color(canvas, ColorWhite);
    }

    draw_footer(canvas, "OK=Enable  BACK=Menu");
}

// ============================================================================
// DRAW: CAPTURE 1 / 2
// ============================================================================

static void draw_capture(App* app, Canvas* canvas) {
    const char* title = (app->scene == SceneCapture1) ? "Sig 1" : "Sig 2";
    draw_header(canvas, title);

    canvas_set_font(canvas, FontPrimary);
    canvas_set_color(canvas, ColorWhite);

    if(app->armed) {
        char anim[24];
        anim_dots(app->tick, "> Listening", anim, sizeof(anim));
        canvas_draw_str(canvas, 6, 32, anim);

        canvas_set_font(canvas, FontSecondary);
        // Countdown bar
        uint32_t now = furi_get_tick();
        int32_t left_ms = (int32_t)furi_ms_to_ticks(CAPTURE_TIMEOUT_MS) -
                          (int32_t)(now - (app->deadline - furi_ms_to_ticks(CAPTURE_TIMEOUT_MS)));
        if(left_ms < 0) left_ms = 0;
        uint32_t bar_w = (uint32_t)((left_ms * 110) / (int32_t)furi_ms_to_ticks(CAPTURE_TIMEOUT_MS));
        if(bar_w > 110) bar_w = 110;
        canvas_draw_frame(canvas, 8, 40, 112, 5);
        if(bar_w > 0) canvas_draw_box(canvas, 9, 41, bar_w, 3);
        char ts[16];
        snprintf(ts, sizeof(ts), "%lus", (unsigned long)(left_ms / 1000));
        canvas_draw_str(canvas, 8, 51, ts);
    } else {
        canvas_draw_str(canvas, 6, 32, "  Ready");
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 6, 43, "Press remote to arm");
    }

    // Radio + step info
    canvas_set_font(canvas, FontSecondary);
    char radio[48];
    snprintf(radio, sizeof(radio), "%s  %s/%u",
             app->radio_name[0] ? app->radio_name : "?",
             app->scene == SceneCapture1 ? "1" : "2", 2U);
    draw_footer(canvas, radio);
}

// ============================================================================
// DRAW: COMPARING (Read-Raw-Only alignment search progress)
// ============================================================================

static void draw_comparing(App* app, Canvas* canvas) {
    draw_header(canvas, "Compare");

    canvas_set_color(canvas, ColorWhite);
    canvas_set_font(canvas, FontPrimary);

    char anim[24];
    anim_dots(app->tick, "Comparing", anim, sizeof(anim));
    canvas_draw_str(canvas, 6, 32, anim);

    canvas_set_font(canvas, FontSecondary);
    canvas_draw_frame(canvas, 8, 40, 112, 6);
    uint32_t fill = ((uint32_t)app->compare_progress * 110U) / 100U;
    if(fill > 110) fill = 110;
    if(fill > 0) canvas_draw_box(canvas, 9, 41, fill, 4);

    char pct[16];
    snprintf(pct, sizeof(pct), "%u%%", (unsigned)app->compare_progress);
    canvas_draw_str(canvas, 8, 51, pct);

    draw_footer(canvas, "Analyzing raw timing...");
}

// ============================================================================
// DRAW: AUTO FREQ
// ============================================================================

static void draw_auto_freq(App* app, Canvas* canvas) {
    draw_header(canvas, "Auto");

    canvas_set_color(canvas, ColorWhite);
    canvas_set_font(canvas, FontPrimary);

    char anim[28];
    char fb[18];
    freq_str(app->frequency, fb, sizeof(fb));
    char prefix[24];
    snprintf(prefix, sizeof(prefix), "> %.14s", fb);
    anim_dots(app->tick, prefix, anim, sizeof(anim));
    canvas_draw_str(canvas, 6, 32, anim);

    canvas_set_font(canvas, FontSecondary);
    char prog[24];
    snprintf(prog, sizeof(prog), "%lu/%lu freqs",
             (unsigned long)(app->auto_idx + 1),
             (unsigned long)FREQ_PRESET_COUNT);
    canvas_draw_str(canvas, 6, 44, prog);

    draw_footer(canvas, "Press remote  BACK=cancel");
}

// ============================================================================
// DRAW: RESULT
// ============================================================================

static void draw_result(App* app, Canvas* canvas) {
    draw_header(canvas, "Result");

    canvas_set_color(canvas, ColorWhite);
    canvas_set_font(canvas, FontPrimary);

    // Big verdict line — invert for emphasis
    const char* vtext;
    switch(app->verdict) {
    case VerdictFixed:      vtext = "FIXED CODE";    break;
    case VerdictRolling:    vtext = "ROLLING CODE";  break;
    case VerdictAmbiguous:  vtext = "AMBIGUOUS";     break;
    case VerdictTimeout:    vtext = "TIMEOUT";       break;
    case VerdictFreqBlocked: vtext = "FREQ BLOCKED"; break;
    case VerdictNoDevice:   vtext = "NO RADIO";      break;
    default:                vtext = "UNKNOWN";       break;
    }

    // Filled box for verdict
    canvas_draw_box(canvas, 3, 21, 122, 12);
    canvas_set_color(canvas, ColorBlack);
    canvas_draw_str_aligned(canvas, 64, 27, AlignCenter, AlignCenter, vtext);
    canvas_set_color(canvas, ColorWhite);

    canvas_set_font(canvas, FontSecondary);

    char proto_line[40];
    char conf_line[40];
    uint8_t pct = (uint8_t)(app->confidence * 100.0f);

    if(app->mode == ModeReadRawOnly) {
        snprintf(proto_line, sizeof(proto_line), "Raw samples: %u / %u",
                 app->raw1.count, app->raw2.count);
        snprintf(conf_line, sizeof(conf_line), "Confidence: %u%%", (unsigned)pct);
    } else {
        if(app->cap1.valid) {
            snprintf(proto_line, sizeof(proto_line), "Protocol: %s", app->cap1.name);
        } else {
            snprintf(proto_line, sizeof(proto_line), "Protocol: unrecognized");
        }
        snprintf(conf_line, sizeof(conf_line), "Confidence: %u%%  Hash %02X/%02X",
                 (unsigned)pct, app->cap1.hash, app->cap2.hash);
    }
    canvas_draw_str(canvas, 6, 40, proto_line);
    canvas_draw_str(canvas, 6, 50, conf_line);

    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(canvas, 4, 63, AlignLeft, AlignBottom, "BACK=Menu");
    canvas_draw_str_aligned(canvas, 124, 63, AlignRight, AlignBottom, "Re-scan >");
}

// ============================================================================
// DRAW: ABOUT
// ============================================================================

static void draw_about(Canvas* canvas) {
    canvas_set_color(canvas, ColorBlack);
    canvas_draw_box(canvas, 0, 0, 128, 64);

    canvas_set_font(canvas, FontPrimary);
    canvas_set_color(canvas, ColorWhite);
    canvas_draw_str_aligned(canvas, 64, 8, AlignCenter, AlignTop, "About");

    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(canvas, 64, 26, AlignCenter, AlignTop, "Rolling Code Checker");
    canvas_draw_str_aligned(canvas, 64, 36, AlignCenter, AlignTop, "made by @Gitredstar");
    canvas_draw_str_aligned(canvas, 64, 46, AlignCenter, AlignTop, "on youtube");

    canvas_draw_line(canvas, 2, 55, 126, 55);
    canvas_draw_str_aligned(canvas, 64, 63, AlignCenter, AlignBottom, "BACK to return");
}

// ============================================================================
// MASTER DRAW CALLBACK
// ============================================================================

static void draw_cb(Canvas* canvas, void* ctx) {
    App* app = ctx;
    if(!app) return;

    switch(app->scene) {
    case SceneMenu:       draw_menu(app, canvas);       break;
    case SceneFreqSelect: draw_freq_select(app, canvas); break;
    case SceneSettings:   draw_settings(app, canvas);    break;
    case SceneCapture1:
    case SceneCapture2:   draw_capture(app, canvas);    break;
    case SceneComparing:  draw_comparing(app, canvas);  break;
    case SceneAutoFreq:   draw_auto_freq(app, canvas);  break;
    case SceneResult:     draw_result(app, canvas);     break;
    case SceneAbout:      draw_about(canvas);            break;
    }
}

// ============================================================================
// INPUT CALLBACK
// ============================================================================

static void input_cb(InputEvent* ev, void* ctx) {
    App* app = ctx;
    if(!app || ev->type != InputTypePress) return;

    // --- MENU ---
    if(app->scene == SceneMenu) {
        if(ev->key == InputKeyBack) { app->running = false; return; }
        if(ev->key == InputKeyUp) {
            if(app->menu_sel == 0) app->menu_sel = MenuCount - 1;
            else app->menu_sel--;
            app_redraw(app);
            return;
        }
        if(ev->key == InputKeyDown) {
            app->menu_sel = (app->menu_sel + 1) % MenuCount;
            app_redraw(app);
            return;
        }
        if(ev->key == InputKeyOk) {
            switch(app->menu_sel) {
            case MenuCompare:    start_compare(app);                break;
            case MenuAutoFreq:   start_auto_freq(app);              break;
            case MenuFreqSelect:
                app->freq_sel = 0;
                // Pre-select the closest preset to current freq
                for(uint8_t i = 0; i < FREQ_PRESET_COUNT; i++) {
                    if(kFreqPresets[i] == app->frequency) { app->freq_sel = i; break; }
                }
                app->scene = SceneFreqSelect;
                app_redraw(app);
                break;
            case MenuRadioToggle:
                app->use_external = !app->use_external;
                // Releasing here forces the next capture to re-acquire
                // (begin) whichever device is selected.
                device_release(app);
                set_status(app, app->use_external ? "Radio: External" : "Radio: Internal", 1500);
                app_redraw(app);
                break;
            case MenuSettings:
                app->settings_sel = (uint8_t)app->mode;
                app->scene = SceneSettings;
                app_redraw(app);
                break;
            case MenuAbout:
                app->scene = SceneAbout;
                app_redraw(app);
                break;
            default: break;
            }
            return;
        }
        return;
    }

    // --- FREQ SELECT ---
    if(app->scene == SceneFreqSelect) {
        if(ev->key == InputKeyBack) { app->scene = SceneMenu; app_redraw(app); return; }
        if(ev->key == InputKeyUp) {
            if(app->freq_sel == 0) app->freq_sel = (uint8_t)(FREQ_PRESET_COUNT - 1);
            else app->freq_sel--;
            app_redraw(app);
            return;
        }
        if(ev->key == InputKeyDown) {
            app->freq_sel = (app->freq_sel + 1) % (uint8_t)FREQ_PRESET_COUNT;
            app_redraw(app);
            return;
        }
        if(ev->key == InputKeyOk) {
            uint32_t selected = kFreqPresets[app->freq_sel];
            if(!freq_is_hardware_valid(selected)) {
                set_status(app, "Freq blocked by region", 2000);
                app_redraw(app);
                return;
            }
            app->frequency = selected;
            char fb[24]; freq_str(app->frequency, fb, sizeof(fb));
            char msg[40]; snprintf(msg, sizeof(msg), "Freq: %s", fb);
            set_status(app, msg, 1800);
            app->scene = SceneMenu;
            app_redraw(app);
            return;
        }
        return;
    }

    // --- SETTINGS ---
    if(app->scene == SceneSettings) {
        if(ev->key == InputKeyBack) { app->scene = SceneMenu; app_redraw(app); return; }
        if(ev->key == InputKeyUp) {
            app->settings_sel = (app->settings_sel == 0) ? 2 : app->settings_sel - 1;
            app_redraw(app);
            return;
        }
        if(ev->key == InputKeyDown) {
            app->settings_sel = (app->settings_sel + 1) % 3;
            app_redraw(app);
            return;
        }
        if(ev->key == InputKeyOk) {
            app->mode = (CaptureMode)app->settings_sel;
            settings_save(app);
            const char* mode_name =
                app->mode == ModeDecoder ? "Decoder" :
                app->mode == ModeBinRaw  ? "Bin Raw" : "Read Raw Only";
            char msg[32];
            snprintf(msg, sizeof(msg), "Mode: %s", mode_name);
            set_status(app, msg, 1800);
            app_redraw(app);
            return;
        }
        return;
    }

    // --- CAPTURE 1 / 2 ---
    if(app->scene == SceneCapture1 || app->scene == SceneCapture2) {
        if(ev->key == InputKeyBack) {
            subghz_rx_stop(app);
            go_menu(app);
            app_redraw(app);
            return;
        }
        // OK arms the capture window.
        if(ev->key == InputKeyOk && !app->armed) {
            subghz_receiver_reset(app->receiver);
            app->last_rssi = -120.0f; // squelch closed until the next RSSI poll
            app->armed    = true;
            app->deadline = furi_get_tick() + furi_ms_to_ticks(CAPTURE_TIMEOUT_MS);
            notification_message(app->notifications, &sequence_single_vibro);
            app_redraw(app);
        }
        return;
    }

    // --- COMPARING ---
    if(app->scene == SceneComparing) {
        if(ev->key == InputKeyBack) {
            subghz_rx_stop(app);
            go_menu(app);
            app_redraw(app);
        }
        return;
    }

    // --- AUTO FREQ ---
    if(app->scene == SceneAutoFreq) {
        if(ev->key == InputKeyBack || ev->key == InputKeyOk) {
            subghz_rx_stop(app);
            go_menu(app);
            app_redraw(app);
        }
        return;
    }

    // --- RESULT ---
    if(app->scene == SceneResult) {
        if(ev->key == InputKeyBack || ev->key == InputKeyOk) {
            go_menu(app);
            app_redraw(app);
            return;
        }
        if(ev->key == InputKeyRight) {
            start_compare(app);
        }
        return;
    }

    // --- ABOUT ---
    if(app->scene == SceneAbout) {
        if(ev->key == InputKeyBack || ev->key == InputKeyOk) {
            app->scene = SceneMenu;
            app_redraw(app);
        }
        return;
    }
}

// ============================================================================
// CLEANUP
// ============================================================================

static void app_free(App* app) {
    if(!app) return;

    if(app->timer) {
        furi_timer_stop(app->timer);
        furi_timer_free(app->timer);
    }

    subghz_rx_stop(app);
    device_release(app);

    if(app->gui && app->view_port) {
        gui_remove_view_port(app->gui, app->view_port);
    }

    if(app->worker) {
        subghz_worker_free(app->worker);
    }
    if(app->receiver) {
        subghz_receiver_free(app->receiver);
    }
    if(app->environment) {
        subghz_environment_free(app->environment);
    }

    if(app->view_port) {
        view_port_free(app->view_port);
    }

    if(app->notifications) furi_record_close(RECORD_NOTIFICATION);
    if(app->gui)            furi_record_close(RECORD_GUI);

    subghz_devices_deinit();

    free(app);
}

// ============================================================================
// ENTRY POINT
// ============================================================================

int32_t rolling_code_checker_app(void* p) {
    UNUSED(p);

    subghz_devices_init();

    App* app = malloc(sizeof(App));
    if(!app) return 255;
    memset(app, 0, sizeof(App));

    app->scene     = SceneMenu;
    app->frequency = DEFAULT_FREQ_HZ;
    app->running   = true;
    app->menu_sel  = MenuCompare;

    app->notifications = furi_record_open(RECORD_NOTIFICATION);
    app->gui           = furi_record_open(RECORD_GUI);

    settings_load(app);

    // Set up the decode pipeline: environment (protocol registry) ->
    // receiver (matches pulses against every registered protocol) ->
    // worker (feeds raw CC1101 pulses into the receiver on its own thread).
    app->environment = subghz_environment_alloc();
    subghz_environment_set_protocol_registry(app->environment, (void*)&subghz_protocol_registry);

    app->receiver = subghz_receiver_alloc_init(app->environment);
    subghz_receiver_set_rx_callback(app->receiver, on_subghz_decode, app);
    subghz_receiver_set_filter(app->receiver, SubGhzProtocolFlag_Decodable);

    app->worker = subghz_worker_alloc();
    subghz_worker_set_overrun_callback(app->worker, (SubGhzWorkerOverrunCallback)subghz_receiver_reset);
    subghz_worker_set_pair_callback(app->worker, (SubGhzWorkerPairCallback)subghz_receiver_decode);
    subghz_worker_set_context(app->worker, app->receiver);

    if(!app->worker || !app->receiver || !app->environment) {
        app_free(app);
        return 255;
    }

    app->view_port = view_port_alloc();
    view_port_draw_callback_set(app->view_port, draw_cb, app);
    view_port_input_callback_set(app->view_port, input_cb, app);
    gui_add_view_port(app->gui, app->view_port, GuiLayerFullscreen);

    app->timer = furi_timer_alloc(timer_cb, FuriTimerTypePeriodic, app);
    furi_timer_start(app->timer, furi_ms_to_ticks(TIMER_PERIOD_MS));

    set_status(app, "Ready", 1500);
    app_redraw(app);

    while(app->running) {
        furi_delay_ms(50);
    }

    app_free(app);
    return 0;
}
