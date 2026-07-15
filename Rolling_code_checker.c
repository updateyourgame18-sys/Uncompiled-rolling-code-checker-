// rolling_code_checker.c
// Rolling Code vs Fixed Code detector
// GUI style: black background, white frame, BigNumbers title (matches IR Raw)
//
// RX pipeline: SubGhzWorker + SubGhzReceiver, run against subghz_protocol_registry.
// Verdicts come from Flipper's own protocol classification (protocol->type,
// Static/Dynamic) rather than a raw-byte guess. Capture flow takes N presses
// (configurable, 2-10) and checks whether the same protocol decodes each
// time with matching payload data.

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
#include <furi_hal_rtc.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define TAG "RCC"

#define SETTINGS_DIR       EXT_PATH("apps_data/rolling_code_checker")
#define SETTINGS_PATH       EXT_PATH("apps_data/rolling_code_checker/settings.txt")
#define WATCHDOG_REF_PATH   EXT_PATH("apps_data/rolling_code_checker/watchdog_ref.txt")
#define WATCHDOG_LOG_PATH   EXT_PATH("apps_data/rolling_code_checker/watchdog_log.txt")
#define IDENTIFIER_TABLE_PATH EXT_PATH("apps_data/rolling_code_checker/identifiers.txt")

extern const SubGhzProtocolRegistry subghz_protocol_registry;

// ============================================================================
// CONSTANTS
// ============================================================================

#define CAPTURE_TIMEOUT_MS  8000  // 8 s to press remote
#define TIMER_PERIOD_MS     40    // ~25 Hz UI refresh

#define DEFAULT_FREQ_HZ 433920000U

#define MIN_CAPTURES 2
#define MAX_CAPTURES 10

// Manual frequency picker — short curated list.
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

// Auto Find now shares the same preset list as manual Set Frequency
// (kFreqPresets, above), so the on-screen strip always matches what's
// actually being scanned/tuned.
#define AUTO_FREQ_DWELL_MS  150 // per-frequency RSSI dwell

// ============================================================================
// TYPES
// ============================================================================

typedef enum {
    SceneMenu,
    SceneFreqSelect,
    SceneCapturing,
    SceneComparing,
    SceneResult,
    SceneAutoFreq,
    SceneSettings,
    SceneAbout,
    SceneWatchdogMenu,
    SceneWatchdogLearn,
    SceneWatching,
    SceneWatchdogLog,
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
    MenuWatchdog,
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
    ModeIdentifier,   // raw capture + measured Te/edge-count signature lookup
} CaptureMode;
#define CAPTURE_MODE_COUNT 4

#define RAW_MAX_SAMPLES  512
#define RAW_MIN_SAMPLES  20    // need at least this many transitions to count as a real signal
#define RAW_SILENCE_MS   150   // this much quiet after the last edge = end of this press

// Two independent captures are rarely index-aligned — one stray edge at the
// start of either shifts everything after it. We search a range of offsets
// and keep the best-scoring alignment. This window stays wide regardless of
// how many captures were requested (shrinking it to keep total time down
// caused real matches to be missed at higher capture counts) — instead we
// scale how many offsets are processed per timer tick, so more captures
// take proportionally longer rather than getting less accurate.
#define RAW_COMPARE_MAX_OFFSET       90
#define RAW_COMPARE_TARGET_TICKS     55 // ~2.2s per-pair budget at the baseline (2 captures)

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

    // Capture — capture_count presses requested, capture_index tracks progress
    CaptureResult caps[MAX_CAPTURES];
    RawCapture*   raws;          // allocated for capture_count entries in raw mode
    uint8_t       capture_count;
    uint8_t       capture_index;
    float         last_rssi;     // polled each tick while armed
    float         meter_boost;   // signal-ball pulse envelope, decays each tick
    bool          armed;
    uint32_t      deadline;

    // Settings
    CaptureMode mode;
    uint8_t     settings_sel;

    // Raw-mode alignment search ("Comparing...") state — walks capture_count-1
    // pairs (each vs raws[0]), tracking the worst (minimum) best-alignment
    // score seen across all pairs.
    uint16_t compare_pair_idx;
    uint16_t compare_pair_count;
    int16_t  compare_offset;
    int16_t  compare_max_offset;
    uint16_t compare_offsets_per_tick; // scales up with more captures, keeps window wide
    uint16_t compare_done_total;
    uint16_t compare_total_all;
    float    compare_pair_best;
    float    compare_min_score;
    uint8_t  compare_progress;

    // Set from the SubGhzWorker thread's decode callback, consumed on the
    // timer thread. subghz_worker_stop() must never be called from inside
    // the decode callback — it runs on the worker's own thread, which can't
    // stop/join itself.
    volatile bool pending_finish;
    volatile bool pending_auto_found;
    volatile bool pending_watchdog_learned;
    volatile bool pending_watchdog_event;
    char auto_found_msg[48];
    char pending_watchdog_event_name[24];
    bool pending_watchdog_event_known;

    // Forces the decode pipeline (ignoring app->mode) for scenes that need
    // a protocol name/hash regardless of the user's Read-Raw/Identifier
    // setting — Watchdog learn/watch always need this.
    bool force_decode_mode;

    // Watchdog — a learned reference signature, continuous monitoring
    // against it, and a simple append-only event log on the SD card.
    bool     watch_has_ref;
    char     watch_ref_name[24];
    uint8_t  watch_ref_type;
    uint8_t  watch_ref_hash;
    uint32_t watch_freq;
    uint32_t watch_known_count;
    uint32_t watch_unknown_count;
    uint8_t  watchdog_menu_sel;
    char     log_lines[4][48];
    uint8_t  log_line_count;

    // Identifier — measured characteristics from a raw capture, checked
    // against a user-editable signature table on the SD card.
    uint32_t ident_te_us;
    uint16_t ident_edge_count;
    char     ident_match_name[24];
    bool     ident_has_match;

    // Result
    Verdict  verdict;
    float    confidence;

    // Menu
    uint8_t  menu_sel;

    // Freq select
    uint8_t  freq_sel;

    // Auto freq (RSSI sweep + manual left/right override)
    uint8_t  auto_preset_idx; // index into kFreqPresets currently tuned
    bool     auto_manual;     // true once Left/Right takes over from auto-hop
    uint32_t auto_deadline;
    uint32_t pre_scan_freq;   // restored on Back (cancel without locking)

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
//   Captures=<2-10>
// Exactly one mode is ON at a time.
// ----------------------------------------------------------------------------
static void settings_load(App* app) {
    app->mode = ModeDecoder;
    app->capture_count = MIN_CAPTURES;

    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);

    if(storage_file_open(file, SETTINGS_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        char buf[160];
        uint16_t len = storage_file_read(file, buf, sizeof(buf) - 1);
        buf[len < sizeof(buf) ? len : sizeof(buf) - 1] = '\0';

        if(strstr(buf, "Identifier=ON")) {
            app->mode = ModeIdentifier;
        } else if(strstr(buf, "ReadRawOnly=ON")) {
            app->mode = ModeReadRawOnly;
        } else if(strstr(buf, "BinRaw=ON")) {
            app->mode = ModeBinRaw;
        } else {
            app->mode = ModeDecoder;
        }

        char* p = strstr(buf, "Captures=");
        if(p) {
            int n = atoi(p + strlen("Captures="));
            if(n < MIN_CAPTURES) n = MIN_CAPTURES;
            if(n > MAX_CAPTURES) n = MAX_CAPTURES;
            app->capture_count = (uint8_t)n;
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
        char buf[192];
        int n = snprintf(
            buf,
            sizeof(buf),
            "Decoder=%s\nBinRaw=%s\nReadRawOnly=%s\nIdentifier=%s\nCaptures=%u\n",
            app->mode == ModeDecoder ? "ON" : "OFF",
            app->mode == ModeBinRaw ? "ON" : "OFF",
            app->mode == ModeReadRawOnly ? "ON" : "OFF",
            app->mode == ModeIdentifier ? "ON" : "OFF",
            (unsigned)app->capture_count);
        storage_file_write(file, buf, n);
    }

    storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
}

// ----------------------------------------------------------------------------
// Watchdog reference (SD card, plain text):
//   Name=<protocol name>
//   Type=<0/1/2>   (SubGhzProtocolType)
//   Hash=<0-255>
//   Freq=<Hz>
// ----------------------------------------------------------------------------
static void watchdog_load_ref(App* app) {
    app->watch_has_ref = false;
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);
    if(storage_file_open(file, WATCHDOG_REF_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        char buf[128];
        uint16_t len = storage_file_read(file, buf, sizeof(buf) - 1);
        buf[len < sizeof(buf) ? len : sizeof(buf) - 1] = '\0';

        char* p = strstr(buf, "Name=");
        if(p) {
            p += 5;
            char* end = strchr(p, '\n');
            size_t l = end ? (size_t)(end - p) : strlen(p);
            if(l >= sizeof(app->watch_ref_name)) l = sizeof(app->watch_ref_name) - 1;
            memcpy(app->watch_ref_name, p, l);
            app->watch_ref_name[l] = '\0';
            app->watch_has_ref = true;
        }
        p = strstr(buf, "Type=");
        if(p) app->watch_ref_type = (uint8_t)atoi(p + 5);
        p = strstr(buf, "Hash=");
        if(p) app->watch_ref_hash = (uint8_t)atoi(p + 5);
        p = strstr(buf, "Freq=");
        if(p) app->watch_freq = (uint32_t)atoi(p + 5);
    }
    storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
}

static void watchdog_save_ref(App* app) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    storage_common_mkdir(storage, SETTINGS_DIR);
    File* file = storage_file_alloc(storage);
    if(storage_file_open(file, WATCHDOG_REF_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        char buf[128];
        int n = snprintf(
            buf, sizeof(buf), "Name=%s\nType=%u\nHash=%u\nFreq=%lu\n",
            app->watch_ref_name, (unsigned)app->watch_ref_type,
            (unsigned)app->watch_ref_hash, (unsigned long)app->watch_freq);
        storage_file_write(file, buf, n);
    }
    storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
}

static void watchdog_log_event(bool known, const char* name) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    storage_common_mkdir(storage, SETTINGS_DIR);
    File* file = storage_file_alloc(storage);
    if(storage_file_open(file, WATCHDOG_LOG_PATH, FSAM_WRITE, FSOM_OPEN_APPEND)) {
        DateTime dt;
        furi_hal_rtc_get_datetime(&dt);
        char line[64];
        int n = snprintf(
            line, sizeof(line), "%04u-%02u-%02u %02u:%02u:%02u,%s,%s\n",
            dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second,
            known ? "KNOWN" : "UNKNOWN", name);
        storage_file_write(file, line, n);
    }
    storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
}

// Loads the last few lines of the watchdog log for the log-viewer screen.
// Seeks near the end of the file rather than reading it all, so this stays
// cheap regardless of how large the log has grown.
static void watchdog_log_load_recent(App* app) {
    app->log_line_count = 0;
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);
    if(storage_file_open(file, WATCHDOG_LOG_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        uint64_t size = storage_file_size(file);
        uint32_t seek_from = size > 1024 ? (uint32_t)(size - 1024) : 0;
        storage_file_seek(file, seek_from, true);

        char buf[1025];
        uint16_t len = storage_file_read(file, buf, sizeof(buf) - 1);
        buf[len] = '\0';

        uint8_t n = 0;
        char* p = buf;
        while(*p) {
            char* nl = strchr(p, '\n');
            if(nl) *nl = '\0';
            if(*p) {
                if(n < 4) {
                    snprintf(app->log_lines[n], sizeof(app->log_lines[n]), "%.47s", p);
                    n++;
                } else {
                    memmove(app->log_lines[0], app->log_lines[1], sizeof(app->log_lines[0]) * 3);
                    snprintf(app->log_lines[3], sizeof(app->log_lines[3]), "%.47s", p);
                }
            }
            if(!nl) break;
            p = nl + 1;
        }
        app->log_line_count = n;
    }
    storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
}

static void watchdog_log_clear(void) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    storage_common_remove(storage, WATCHDOG_LOG_PATH);
    furi_record_close(RECORD_STORAGE);
}

// ----------------------------------------------------------------------------
// Identifier — measured Te (shortest recurring pulse width) and edge count
// from a raw capture, checked against a user-editable signature table:
//   Name,MinTeUs,MaxTeUs,MinEdges,MaxEdges
// one entry per line. Ships empty — this app does not include or claim any
// built-in database of real-world protocol signatures.
// ----------------------------------------------------------------------------
static void identifier_measure(App* app, const RawCapture* rc) {
    app->ident_edge_count = rc->count;
    app->ident_te_us = 0;

    uint32_t min_dur = 0xFFFFFFFFU;
    for(uint16_t i = 0; i < rc->count; i++) {
        uint32_t d = (uint32_t)(rc->timing[i] < 0 ? -rc->timing[i] : rc->timing[i]);
        if(d > 20 && d < min_dur) min_dur = d; // ignore near-zero glitches
    }
    if(min_dur != 0xFFFFFFFFU) app->ident_te_us = min_dur;
}

static void identifier_lookup(App* app) {
    app->ident_has_match = false;
    app->ident_match_name[0] = '\0';

    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);
    if(storage_file_open(file, IDENTIFIER_TABLE_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        char buf[1025];
        uint16_t len = storage_file_read(file, buf, sizeof(buf) - 1);
        buf[len] = '\0';

        char* p = buf;
        while(*p && !app->ident_has_match) {
            char* nl = strchr(p, '\n');
            if(nl) *nl = '\0';

            char name[24] = {0};
            uint32_t min_te, max_te;
            uint32_t min_edges, max_edges;
            if(*p && sscanf(p, "%23[^,],%lu,%lu,%lu,%lu", name, &min_te, &max_te, &min_edges, &max_edges) == 5) {
                if(app->ident_te_us >= min_te && app->ident_te_us <= max_te &&
                   app->ident_edge_count >= min_edges && app->ident_edge_count <= max_edges) {
                    snprintf(app->ident_match_name, sizeof(app->ident_match_name), "%s", name);
                    app->ident_has_match = true;
                }
            }

            if(!nl) break;
            p = nl + 1;
        }
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
    furi_delay_ms(5); // let the CC1101 settle before reconfiguring — rapid
                       // back-to-back reset/reload cycles across scans can
                       // otherwise leave it in a half-initialized state
    subghz_devices_load_preset(app->device, FuriHalSubGhzPresetOok650Async, NULL);
    app->frequency = subghz_devices_set_frequency(app->device, freq);

    bool use_raw_pipeline = (app->mode == ModeReadRawOnly || app->mode == ModeIdentifier) && !app->force_decode_mode;

    if(use_raw_pipeline) {
        // No protocol decode — feed pulses straight into our own buffer.
        subghz_worker_set_pair_callback(app->worker, (SubGhzWorkerPairCallback)raw_pair_callback);
        subghz_worker_set_context(app->worker, app);
    } else {
        subghz_receiver_reset(app->receiver);
        uint32_t filter = SubGhzProtocolFlag_Decodable;
        if(app->mode == ModeBinRaw || app->force_decode_mode) {
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
    memset(app->caps, 0, sizeof(app->caps));

    if(app->raws) {
        free(app->raws);
        app->raws = NULL;
    }
    if(app->mode == ModeReadRawOnly || app->mode == ModeIdentifier) {
        app->raws = malloc(sizeof(RawCapture) * app->capture_count);
        if(app->raws) {
            memset(app->raws, 0, sizeof(RawCapture) * app->capture_count);
        }
    }

    app->capture_index = 0;
    app->confidence = 0.0f;
    app->verdict = VerdictNone;
    app->armed = false;
    app->meter_boost = 0.0f;
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

    if((app->mode == ModeReadRawOnly || app->mode == ModeIdentifier) && !app->raws) {
        set_status(app, "Out of memory", 2000);
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
    app->scene = SceneCapturing;
    set_status(app, "Press remote when armed", 2000);
    app_redraw(app);
}

// Continuous RSSI sweep across the preset list — same idea as the stock
// Frequency Analyzer. No decode needed, so no worker/receiver involved.
static void start_auto_freq(App* app) {
    reset_capture(app);

    app->pre_scan_freq = app->frequency;
    app->auto_manual   = false;

    // Uses the same short preset list as manual Set Frequency, so the
    // left/right strip on screen matches what's actually being scanned.
    app->auto_preset_idx = 0;
    for(uint8_t i = 0; i < FREQ_PRESET_COUNT; i++) {
        if(kFreqPresets[i] == app->frequency) { app->auto_preset_idx = i; break; }
    }

    // Reuse the same begin/reset/preset/start_async_rx sequence captures
    // use — proven stable — rather than driving the device state machine
    // by hand. The decode/raw pair callbacks both no-op outside of
    // SceneCapturing, so this is safe to use purely for its RSSI side effect.
    if(!subghz_rx_start(app, kFreqPresets[app->auto_preset_idx])) {
        set_status(app, "No radio device", 2500);
        go_menu(app);
        app_redraw(app);
        return;
    }

    app->auto_deadline = furi_get_tick() + furi_ms_to_ticks(AUTO_FREQ_DWELL_MS);
    app->scene = SceneAutoFreq;
    app_redraw(app);
}

static void start_watchdog_learn(App* app) {
    reset_capture(app);
    app->force_decode_mode = true;

    if(!freq_is_hardware_valid(app->frequency)) {
        set_status(app, "Freq blocked — pick another", 2500);
        app->force_decode_mode = false;
        return;
    }
    if(!subghz_rx_start(app, app->frequency)) {
        set_status(app, "Radio start failed", 2000);
        app->force_decode_mode = false;
        return;
    }

    app->scene = SceneWatchdogLearn;
    app_redraw(app);
}

static void start_watching(App* app) {
    if(!app->watch_has_ref) {
        set_status(app, "Learn a remote first!", 1800);
        return;
    }

    reset_capture(app);
    app->force_decode_mode = true;
    app->watch_known_count = 0;
    app->watch_unknown_count = 0;

    if(!subghz_rx_start(app, app->watch_freq)) {
        set_status(app, "Radio start failed", 2000);
        app->force_decode_mode = false;
        return;
    }

    app->scene = SceneWatching;
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

// Compare all captured presses and decide fixed vs. rolling.
static void finish_compare(App* app) {
    uint8_t n = app->capture_count;

    for(uint8_t i = 0; i < n; i++) {
        if(!app->caps[i].valid) {
            finish_result(app, VerdictAmbiguous, 0.0f);
            return;
        }
    }

    bool same_name = true;
    for(uint8_t i = 1; i < n; i++) {
        if(strcmp(app->caps[i].name, app->caps[0].name) != 0) {
            same_name = false;
            break;
        }
    }

    if(!same_name) {
        // Different protocols across presses — fall back to the first
        // decode's own protocol-type classification.
        Verdict v = (app->caps[0].type == SubGhzProtocolTypeDynamic) ? VerdictRolling : VerdictFixed;
        finish_result(app, v, 0.5f);
        return;
    }

    uint8_t matches = 0;
    for(uint8_t i = 1; i < n; i++) {
        if(app->caps[i].hash == app->caps[0].hash) matches++;
    }
    bool all_match = (matches == n - 1);
    float match_frac = (n > 1) ? (float)matches / (float)(n - 1) : 1.0f;
    bool is_binraw = (strcmp(app->caps[0].name, "BinRAW") == 0);

    if(is_binraw) {
        // BinRAW has no inherent static/dynamic classification of its own —
        // compare payload hashes directly.
        finish_result(app, all_match ? VerdictFixed : VerdictRolling, 1.0f);
    } else if(app->caps[0].type == SubGhzProtocolTypeDynamic) {
        // Known dynamic-code family (KeeLoq, Security+, Nice FloR-S, etc).
        finish_result(app, VerdictRolling, all_match ? 0.85f : 1.0f);
    } else {
        // Static-code family (Princeton, Came, Nice Flo, etc).
        finish_result(app, all_match ? VerdictFixed : VerdictAmbiguous,
                      all_match ? 1.0f : (0.4f + 0.5f * match_frac));
    }
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
    if(app->scene != SceneCapturing) return;
    if(!app->raws || app->capture_index >= app->capture_count) return;

    // Squelch — reject noise-triggered toggles when nothing is transmitting.
    if(app->last_rssi < RAW_RSSI_SQUELCH_DBM) return;

    RawCapture* rc = &app->raws[app->capture_index];
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

    if(app->scene == SceneWatchdogLearn && app->armed) {
        snprintf(app->watch_ref_name, sizeof(app->watch_ref_name), "%s", protocol->name ? protocol->name : "?");
        app->watch_ref_type = (uint8_t)protocol->type;
        app->watch_ref_hash = 0;
        if(protocol->decoder && protocol->decoder->get_hash_data) {
            app->watch_ref_hash = protocol->decoder->get_hash_data(decoder_base);
        }
        app->watch_freq = app->frequency;
        app->watch_has_ref = true;
        app->armed = false;
        app->meter_boost = 1.0f;
        notification_message(app->notifications, &sequence_single_vibro);
        // Deferred to the timer thread — same reason as pending_finish above.
        app->pending_watchdog_learned = true;
        app_redraw(app);
        return;
    }

    if(app->scene == SceneWatching) {
        bool is_known;
        uint8_t hash = 0;
        if(protocol->decoder && protocol->decoder->get_hash_data) {
            hash = protocol->decoder->get_hash_data(decoder_base);
        }
        bool name_match = protocol->name && strcmp(protocol->name, app->watch_ref_name) == 0;
        if(protocol->type == SubGhzProtocolTypeDynamic) {
            // Rolling codes legitimately change hash every press — protocol
            // family match is the best we can do here.
            is_known = name_match;
        } else {
            is_known = name_match && (hash == app->watch_ref_hash);
        }

        if(is_known) app->watch_known_count++; else app->watch_unknown_count++;
        app->meter_boost = 1.0f;
        notification_message(app->notifications, is_known ? &sequence_single_vibro : &sequence_double_vibro);

        // Logging is Storage I/O — defer it to the timer thread rather than
        // doing file writes from inside the worker thread's callback.
        app->pending_watchdog_event = true;
        app->pending_watchdog_event_known = is_known;
        snprintf(app->pending_watchdog_event_name, sizeof(app->pending_watchdog_event_name),
                 "%s", protocol->name ? protocol->name : "?");
        app_redraw(app);
        return;
    }

    if(app->scene == SceneCapturing && app->armed && app->capture_index < app->capture_count) {
        CaptureResult* slot = &app->caps[app->capture_index];

        snprintf(slot->name, sizeof(slot->name), "%s", protocol->name ? protocol->name : "?");
        slot->type = (uint8_t)protocol->type;
        slot->hash = 0;
        if(protocol->decoder && protocol->decoder->get_hash_data) {
            slot->hash = protocol->decoder->get_hash_data(decoder_base);
        }
        slot->valid = true;
        app->armed = false;
        app->meter_boost = 1.0f;

        notification_message(app->notifications, &sequence_single_vibro);

        app->capture_index++;
        if(app->capture_index < app->capture_count) {
            app->deadline = furi_get_tick() + furi_ms_to_ticks(CAPTURE_TIMEOUT_MS);
            char msg[32];
            snprintf(msg, sizeof(msg), "Got %u/%u — arm next", app->capture_index, app->capture_count);
            set_status(app, msg, 1800);
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

// Begin the alignment-search Comparing scene: capture_count-1 pairs, each
// vs raws[0], with the per-pair offset range scaled down as capture_count
// grows so total analysis time stays roughly constant.
static void start_comparing(App* app) {
    uint16_t pair_count = app->capture_count - 1;
    if(pair_count < 1) pair_count = 1;

    uint32_t total_offsets = (uint32_t)(RAW_COMPARE_MAX_OFFSET * 2 + 1) * pair_count;
    uint16_t per_tick = (uint16_t)(total_offsets / RAW_COMPARE_TARGET_TICKS);
    if(per_tick < 4) per_tick = 4; // floor so the baseline (2 captures) case isn't slower than before

    app->compare_pair_idx        = 0;
    app->compare_pair_count      = pair_count;
    app->compare_max_offset      = RAW_COMPARE_MAX_OFFSET;
    app->compare_offset          = -RAW_COMPARE_MAX_OFFSET;
    app->compare_offsets_per_tick = per_tick;
    app->compare_done_total      = 0;
    app->compare_total_all       = (uint16_t)(total_offsets > 0xFFFF ? 0xFFFF : total_offsets);
    app->compare_pair_best       = 0.0f;
    app->compare_min_score       = 1.0f;
    app->compare_progress        = 0;
    app->scene = SceneComparing;
}

static void process_timeouts(App* app) {
    uint32_t now = furi_get_tick();

    if(app->scene == SceneComparing) {
        for(int i = 0; i < app->compare_offsets_per_tick && app->compare_pair_idx < app->compare_pair_count; i++) {
            RawCapture* ref = &app->raws[0];
            RawCapture* cur = &app->raws[app->compare_pair_idx + 1];
            float score = raw_similarity_at_offset(ref, cur, app->compare_offset);
            if(score > app->compare_pair_best) app->compare_pair_best = score;

            app->compare_offset++;
            app->compare_done_total++;

            if(app->compare_offset > app->compare_max_offset) {
                if(app->compare_pair_best < app->compare_min_score) {
                    app->compare_min_score = app->compare_pair_best;
                }
                app->compare_pair_idx++;
                app->compare_offset = -app->compare_max_offset;
                app->compare_pair_best = 0.0f;
            }
        }

        app->compare_progress = app->compare_total_all
            ? (uint8_t)((app->compare_done_total * 100U) / app->compare_total_all)
            : 100;

        if(app->compare_pair_idx >= app->compare_pair_count) {
            float score = app->compare_min_score;
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

    if(app->pending_watchdog_learned) {
        app->pending_watchdog_learned = false;
        subghz_rx_stop(app);
        app->force_decode_mode = false;
        watchdog_save_ref(app);
        app->scene = SceneWatchdogMenu;
        char msg[40];
        snprintf(msg, sizeof(msg), "Learned: %s", app->watch_ref_name);
        set_status(app, msg, 2000);
        app_redraw(app);
        return;
    }

    if(app->pending_watchdog_event) {
        app->pending_watchdog_event = false;
        watchdog_log_event(app->pending_watchdog_event_known, app->pending_watchdog_event_name);
        // Watching continues indefinitely — no scene change, no radio stop.
    }

    if(app->pending_auto_found) {
        app->pending_auto_found = false;
        set_status(app, app->auto_found_msg, 3000);
        subghz_rx_stop(app);
        app->scene = SceneMenu;
        notification_message(app->notifications, &sequence_single_vibro);
        app_redraw(app);
        return;
    }

    if(app->scene == SceneCapturing && app->armed) {
        if(app->device) {
            app->last_rssi = subghz_devices_get_rssi(app->device);
            if(app->last_rssi > RAW_RSSI_SQUELCH_DBM) app->meter_boost = 1.0f;
        }

        // Read-Raw-Only / Identifier: no decode event marks end of a press,
        // so use a gap of silence after the last edge instead.
        if((app->mode == ModeReadRawOnly || app->mode == ModeIdentifier) && app->raws) {
            RawCapture* rc = &app->raws[app->capture_index];
            if(rc->count >= RAW_MIN_SAMPLES &&
               (int32_t)(now - rc->last_edge_tick) > (int32_t)furi_ms_to_ticks(RAW_SILENCE_MS)) {
                rc->valid = true;
                app->armed = false;
                notification_message(app->notifications, &sequence_single_vibro);

                app->capture_index++;
                if(app->capture_index < app->capture_count) {
                    app->deadline = now + furi_ms_to_ticks(CAPTURE_TIMEOUT_MS);
                    char msg[32];
                    snprintf(msg, sizeof(msg), "Got %u/%u — arm next", app->capture_index, app->capture_count);
                    set_status(app, msg, 1800);
                } else {
                    if(app->mode == ModeIdentifier) {
                        identifier_measure(app, &app->raws[0]);
                        identifier_lookup(app);
                    }
                    start_comparing(app);
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
        if(app->device) {
            app->last_rssi = subghz_devices_get_rssi(app->device);
            if(app->last_rssi > RAW_RSSI_SQUELCH_DBM) app->meter_boost = 1.0f;
        }

        // Auto-hop through the presets unless the user has grabbed manual
        // control with Left/Right.
        if(!app->auto_manual && (int32_t)(now - app->auto_deadline) >= 0) {
            app->auto_preset_idx = (app->auto_preset_idx + 1) % (uint8_t)FREQ_PRESET_COUNT;
            subghz_rx_start(app, kFreqPresets[app->auto_preset_idx]);
            app->auto_deadline = now + furi_ms_to_ticks(AUTO_FREQ_DWELL_MS);
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

    // Decay the signal-ball pulse envelope
    if(app->meter_boost > 0.0f) {
        app->meter_boost -= 0.15f;
        if(app->meter_boost < 0.0f) app->meter_boost = 0.0f;
    }

    process_timeouts(app);
    app_redraw(app);
}

// ============================================================================
// DRAW HELPERS — IR Raw style: black bg, white frame, BigNumbers title
// ============================================================================

// Shared header: fills black, draws title in BigNumbers, draws content frame
static void draw_header_h(Canvas* canvas, const char* title, uint8_t frame_height) {
    canvas_set_color(canvas, ColorBlack);
    canvas_draw_box(canvas, 0, 0, 128, 64);

    canvas_set_color(canvas, ColorWhite);
    canvas_set_font(canvas, FontBigNumbers);
    canvas_draw_str_aligned(canvas, 64, 2, AlignCenter, AlignTop, title);

    canvas_draw_frame(canvas, 2, 20, 124, frame_height);
}

static void draw_header(Canvas* canvas, const char* title) {
    draw_header_h(canvas, title, 33);
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

// Signal strength indicator: a small ball with spikes that grow with the
// boost envelope (pulses outward whenever a signal crosses squelch).
static void draw_signal_ball(Canvas* canvas, int cx, int cy, float boost) {
    // 6 petals, 60 degrees apart — a rounded spark rather than a spiky mine.
    static const float dirs[6][2] = {
        {1.0f, 0.0f},    {0.5f, 0.8660f},  {-0.5f, 0.8660f},
        {-1.0f, 0.0f},   {-0.5f, -0.8660f}, {0.5f, -0.8660f},
    };
    const int center_r = 2;
    const int petal_r = 2;
    int reach = 4 + (int)(boost * 4.0f);

    canvas_draw_disc(canvas, cx, cy, center_r);
    for(int i = 0; i < 6; i++) {
        int tipx = cx + (int)(dirs[i][0] * (float)reach);
        int tipy = cy + (int)(dirs[i][1] * (float)reach);
        canvas_draw_line(canvas, cx, cy, tipx, tipy);
        canvas_draw_disc(canvas, tipx, tipy, petal_r);
    }
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
        "Watchdog",
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

    if(status_alive(app)) draw_footer(canvas, app->status);
}

// ============================================================================
// DRAW: SETTINGS
// ============================================================================

#define SETTINGS_ROW_COUNT (CAPTURE_MODE_COUNT + 1) // 4 modes + Captures row

static void draw_settings(App* app, Canvas* canvas) {
    draw_header(canvas, "Config");

    canvas_set_color(canvas, ColorWhite);
    canvas_set_font(canvas, FontPrimary);

    static const char* mode_labels[CAPTURE_MODE_COUNT] = {"Decoder", "Bin Raw", "Read Raw Only", "Identifier"};

    int8_t start = (int8_t)app->settings_sel - 1;
    if(start < 0) start = 0;
    if(start > (int8_t)SETTINGS_ROW_COUNT - 3) start = (int8_t)SETTINGS_ROW_COUNT - 3;
    if(start < 0) start = 0;

    for(int i = 0; i < 3; i++) {
        int idx = start + i;
        if(idx >= SETTINGS_ROW_COUNT) break;
        uint8_t y = 29 + (uint8_t)(i * 10);
        bool sel = (idx == (int)app->settings_sel);

        char line[28];
        if(idx < CAPTURE_MODE_COUNT) {
            bool active = ((CaptureMode)idx == app->mode);
            snprintf(line, sizeof(line), "%s %s", active ? "[x]" : "[ ]", mode_labels[idx]);
        } else {
            snprintf(line, sizeof(line), "Captures [%u]", (unsigned)app->capture_count);
        }

        if(sel) {
            canvas_draw_box(canvas, 3, y - 8, 122, 10);
            canvas_set_color(canvas, ColorBlack);
        } else {
            canvas_set_color(canvas, ColorWhite);
        }
        canvas_draw_str(canvas, 6, y, line);
        canvas_set_color(canvas, ColorWhite);
    }

    // Feedback goes in the footer only — same pattern as the main menu —
    // so the rows never disappear or get covered.
    if(status_alive(app)) {
        draw_footer(canvas, app->status);
    }
}

// ============================================================================
// DRAW: CAPTURING
// ============================================================================

static void draw_capturing(App* app, Canvas* canvas) {
    char title[10];
    snprintf(title, sizeof(title), "Sig %u", (unsigned)(app->capture_index + 1));
    draw_header(canvas, title);

    canvas_set_font(canvas, FontPrimary);
    canvas_set_color(canvas, ColorWhite);

    if(app->armed) {
        char anim[24];
        anim_dots(app->tick, "> Listening", anim, sizeof(anim));
        canvas_draw_str(canvas, 6, 32, anim);

        canvas_set_font(canvas, FontSecondary);
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

    draw_signal_ball(canvas, 112, 27, app->meter_boost);

    canvas_set_font(canvas, FontSecondary);
    char radio[48];
    snprintf(radio, sizeof(radio), "%s  %u/%u",
             app->radio_name[0] ? app->radio_name : "?",
             (unsigned)(app->capture_index + 1), (unsigned)app->capture_count);
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
    draw_header_h(canvas, "Auto", 38);

    canvas_set_color(canvas, ColorWhite);
    canvas_set_font(canvas, FontSecondary);

    char rssi_line[24];
    snprintf(rssi_line, sizeof(rssi_line), "%d dBm", (int)app->last_rssi);
    canvas_draw_str_aligned(canvas, 64, 23, AlignCenter, AlignTop, rssi_line);

    draw_signal_ball(canvas, 64, 38, app->meter_boost);

    // Bottom strip — Left/Right steps through the same presets as
    // Set Frequency, and immediately re-tunes to whichever is shown.
    // Up hands control back to the automatic sweep.
    char fb[24];
    freq_str(kFreqPresets[app->auto_preset_idx], fb, sizeof(fb));
    char strip[32];
    snprintf(strip, sizeof(strip), "< %s >", fb);
    canvas_draw_str_aligned(canvas, 64, 49, AlignCenter, AlignTop, strip);

    if(status_alive(app)) draw_footer(canvas, app->status);
}

// ============================================================================
// DRAW: WATCHDOG MENU
// ============================================================================

static void draw_watchdog_menu(App* app, Canvas* canvas) {
    draw_header(canvas, "Watch");

    canvas_set_font(canvas, FontPrimary);
    canvas_set_color(canvas, ColorWhite);

    static const char* labels[4] = {"Start Watching", "Learn Remote", "View Log", "Clear Log"};

    for(int i = 0; i < 4; i++) {
        uint8_t y = 29 + (uint8_t)(i * 8);
        bool sel = (i == app->watchdog_menu_sel);
        if(sel) {
            canvas_draw_box(canvas, 3, y - 7, 122, 9);
            canvas_set_color(canvas, ColorBlack);
        } else {
            canvas_set_color(canvas, ColorWhite);
        }
        canvas_draw_str(canvas, 6, y, labels[i]);
        canvas_set_color(canvas, ColorWhite);
    }

    if(status_alive(app)) {
        draw_footer(canvas, app->status);
    } else if(app->watch_has_ref) {
        char line[32];
        snprintf(line, sizeof(line), "Ref: %s", app->watch_ref_name);
        draw_footer(canvas, line);
    } else {
        draw_footer(canvas, "No reference learned yet");
    }
}

// ============================================================================
// DRAW: WATCHDOG LEARN (single capture, reused arm/listen visuals)
// ============================================================================

static void draw_watchdog_learn(App* app, Canvas* canvas) {
    draw_header(canvas, "Learn");

    canvas_set_font(canvas, FontPrimary);
    canvas_set_color(canvas, ColorWhite);

    if(app->armed) {
        char anim[24];
        anim_dots(app->tick, "> Listening", anim, sizeof(anim));
        canvas_draw_str(canvas, 6, 32, anim);
    } else {
        canvas_draw_str(canvas, 6, 32, "  Ready");
    }

    draw_signal_ball(canvas, 112, 27, app->meter_boost);

    if(status_alive(app)) draw_footer(canvas, app->status);
}

// ============================================================================
// DRAW: WATCHING (continuous monitor)
// ============================================================================

static void draw_watching(App* app, Canvas* canvas) {
    draw_header(canvas, "Watch");

    canvas_set_color(canvas, ColorWhite);
    canvas_set_font(canvas, FontSecondary);

    char anim[28];
    anim_dots(app->tick, "> Watching", anim, sizeof(anim));
    canvas_draw_str(canvas, 6, 28, anim);

    char ref_line[32];
    snprintf(ref_line, sizeof(ref_line), "Ref: %s", app->watch_ref_name);
    canvas_draw_str(canvas, 6, 37, ref_line);

    char count_line[32];
    snprintf(count_line, sizeof(count_line), "Known:%lu Unknown:%lu",
             (unsigned long)app->watch_known_count, (unsigned long)app->watch_unknown_count);
    canvas_draw_str(canvas, 6, 46, count_line);

    draw_signal_ball(canvas, 112, 28, app->meter_boost);

    if(status_alive(app)) draw_footer(canvas, app->status);
}

// ============================================================================
// DRAW: WATCHDOG LOG
// ============================================================================

static void draw_watchdog_log(App* app, Canvas* canvas) {
    draw_header(canvas, "Log");

    canvas_set_color(canvas, ColorWhite);
    canvas_set_font(canvas, FontSecondary);

    if(app->log_line_count == 0) {
        canvas_draw_str_aligned(canvas, 64, 36, AlignCenter, AlignCenter, "No events logged yet");
    } else {
        for(uint8_t i = 0; i < app->log_line_count; i++) {
            canvas_draw_str(canvas, 4, 27 + (uint8_t)(i * 8), app->log_lines[i]);
        }
    }

    draw_footer(canvas, "Showing most recent");
}

// ============================================================================
// DRAW: RESULT
// ============================================================================

static void draw_result(App* app, Canvas* canvas) {
    draw_header(canvas, "Result");

    canvas_set_color(canvas, ColorWhite);
    canvas_set_font(canvas, FontPrimary);

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

    canvas_draw_box(canvas, 3, 21, 122, 12);
    canvas_set_color(canvas, ColorBlack);
    canvas_draw_str_aligned(canvas, 64, 27, AlignCenter, AlignCenter, vtext);
    canvas_set_color(canvas, ColorWhite);

    canvas_set_font(canvas, FontSecondary);

    char proto_line[40];
    char conf_line[40];
    uint8_t pct = (uint8_t)(app->confidence * 100.0f);

    if(app->mode == ModeIdentifier) {
        if(app->ident_has_match) {
            snprintf(proto_line, sizeof(proto_line), "Match: %s", app->ident_match_name);
        } else {
            snprintf(proto_line, sizeof(proto_line), "Te:%luus Edges:%u",
                     (unsigned long)app->ident_te_us, (unsigned)app->ident_edge_count);
        }
        snprintf(conf_line, sizeof(conf_line), "Confidence: %u%%", (unsigned)pct);
    } else if(app->mode == ModeReadRawOnly) {
        snprintf(proto_line, sizeof(proto_line), "Raw presses: %u", (unsigned)app->capture_count);
        snprintf(conf_line, sizeof(conf_line), "Confidence: %u%%", (unsigned)pct);
    } else {
        if(app->caps[0].valid) {
            snprintf(proto_line, sizeof(proto_line), "Protocol: %s", app->caps[0].name);
        } else {
            snprintf(proto_line, sizeof(proto_line), "Protocol: unrecognized");
        }
        snprintf(conf_line, sizeof(conf_line), "Confidence: %u%%  (%u presses)",
                 (unsigned)pct, (unsigned)app->capture_count);
    }
    canvas_draw_str(canvas, 6, 40, proto_line);
    canvas_draw_str(canvas, 6, 50, conf_line);

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
    case SceneMenu:          draw_menu(app, canvas);          break;
    case SceneFreqSelect:    draw_freq_select(app, canvas);   break;
    case SceneSettings:      draw_settings(app, canvas);      break;
    case SceneCapturing:     draw_capturing(app, canvas);     break;
    case SceneComparing:     draw_comparing(app, canvas);     break;
    case SceneAutoFreq:      draw_auto_freq(app, canvas);     break;
    case SceneResult:        draw_result(app, canvas);        break;
    case SceneAbout:         draw_about(canvas);              break;
    case SceneWatchdogMenu:  draw_watchdog_menu(app, canvas); break;
    case SceneWatchdogLearn: draw_watchdog_learn(app, canvas); break;
    case SceneWatching:      draw_watching(app, canvas);      break;
    case SceneWatchdogLog:   draw_watchdog_log(app, canvas);  break;
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
                for(uint8_t i = 0; i < FREQ_PRESET_COUNT; i++) {
                    if(kFreqPresets[i] == app->frequency) { app->freq_sel = i; break; }
                }
                app->scene = SceneFreqSelect;
                app_redraw(app);
                break;
            case MenuWatchdog:
                app->watchdog_menu_sel = 0;
                app->scene = SceneWatchdogMenu;
                app_redraw(app);
                break;
            case MenuRadioToggle:
                app->use_external = !app->use_external;
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
            app->settings_sel = (app->settings_sel == 0) ? (uint8_t)(SETTINGS_ROW_COUNT - 1) : app->settings_sel - 1;
            app_redraw(app);
            return;
        }
        if(ev->key == InputKeyDown) {
            app->settings_sel = (app->settings_sel + 1) % SETTINGS_ROW_COUNT;
            app_redraw(app);
            return;
        }

        if(app->settings_sel == CAPTURE_MODE_COUNT) {
            if(ev->key == InputKeyLeft) {
                if(app->capture_count <= MIN_CAPTURES) {
                    notification_message(app->notifications, &sequence_single_vibro);
                    set_status(app, "Minimum captures!", 1400);
                } else {
                    app->capture_count--;
                    settings_save(app);
                    char msg[24];
                    snprintf(msg, sizeof(msg), "Captures: %u", (unsigned)app->capture_count);
                    set_status(app, msg, 1200);
                }
                app_redraw(app);
                return;
            }
            if(ev->key == InputKeyRight) {
                if(app->capture_count >= MAX_CAPTURES) {
                    notification_message(app->notifications, &sequence_single_vibro);
                    set_status(app, "Maximum captures!", 1400);
                } else {
                    app->capture_count++;
                    settings_save(app);
                    char msg[24];
                    snprintf(msg, sizeof(msg), "Captures: %u", (unsigned)app->capture_count);
                    set_status(app, msg, 1200);
                }
                app_redraw(app);
                return;
            }
        }

        if(ev->key == InputKeyOk && app->settings_sel != CAPTURE_MODE_COUNT) {
            app->mode = (CaptureMode)app->settings_sel;
            settings_save(app);
            const char* mode_name =
                app->mode == ModeDecoder ? "Decoder" :
                app->mode == ModeBinRaw  ? "Bin Raw" :
                app->mode == ModeReadRawOnly ? "Read Raw Only" : "Identifier";
            char msg[32];
            snprintf(msg, sizeof(msg), "Mode: %s", mode_name);
            set_status(app, msg, 1800);
            app_redraw(app);
            return;
        }
        return;
    }

    // --- CAPTURING ---
    if(app->scene == SceneCapturing) {
        if(ev->key == InputKeyBack) {
            subghz_rx_stop(app);
            go_menu(app);
            app_redraw(app);
            return;
        }
        if(ev->key == InputKeyOk && !app->armed) {
            subghz_receiver_reset(app->receiver);
            // Read RSSI immediately rather than leaving a stale "squelch
            // closed" sentinel — a pulse arriving before the next 40ms
            // timer tick would otherwise get silently dropped even on a
            // strong signal, causing an intermittent empty capture.
            app->last_rssi = app->device ? subghz_devices_get_rssi(app->device) : -120.0f;
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
        if(ev->key == InputKeyBack) {
            app->frequency = app->pre_scan_freq;
            go_menu(app);
            app_redraw(app);
            return;
        }
        if(ev->key == InputKeyUp) {
            app->auto_manual = false;
            app->auto_deadline = furi_get_tick() + furi_ms_to_ticks(AUTO_FREQ_DWELL_MS);
            set_status(app, "Auto", 1000);
            app_redraw(app);
            return;
        }
        if(ev->key == InputKeyLeft) {
            app->auto_manual = true;
            app->auto_preset_idx = (app->auto_preset_idx == 0)
                ? (uint8_t)(FREQ_PRESET_COUNT - 1)
                : app->auto_preset_idx - 1;
            subghz_rx_start(app, kFreqPresets[app->auto_preset_idx]);
            app_redraw(app);
            return;
        }
        if(ev->key == InputKeyRight) {
            app->auto_manual = true;
            app->auto_preset_idx = (app->auto_preset_idx + 1) % (uint8_t)FREQ_PRESET_COUNT;
            subghz_rx_start(app, kFreqPresets[app->auto_preset_idx]);
            app_redraw(app);
            return;
        }
        if(ev->key == InputKeyOk) {
            app->frequency = kFreqPresets[app->auto_preset_idx];
            char fb[24]; freq_str(app->frequency, fb, sizeof(fb));
            char msg[40]; snprintf(msg, sizeof(msg), "Locked: %s", fb);
            set_status(app, msg, 2000);
            go_menu(app);
            app_redraw(app);
        }
        return;
    }

    // --- WATCHDOG MENU ---
    if(app->scene == SceneWatchdogMenu) {
        if(ev->key == InputKeyBack) { app->scene = SceneMenu; app_redraw(app); return; }
        if(ev->key == InputKeyUp) {
            app->watchdog_menu_sel = (app->watchdog_menu_sel == 0) ? 3 : app->watchdog_menu_sel - 1;
            app_redraw(app);
            return;
        }
        if(ev->key == InputKeyDown) {
            app->watchdog_menu_sel = (app->watchdog_menu_sel + 1) % 4;
            app_redraw(app);
            return;
        }
        if(ev->key == InputKeyOk) {
            switch(app->watchdog_menu_sel) {
            case 0: start_watching(app); break;
            case 1: start_watchdog_learn(app); break;
            case 2:
                watchdog_log_load_recent(app);
                app->scene = SceneWatchdogLog;
                app_redraw(app);
                break;
            case 3:
                watchdog_log_clear();
                app->log_line_count = 0;
                set_status(app, "Log cleared", 1500);
                app_redraw(app);
                break;
            default: break;
            }
        }
        return;
    }

    // --- WATCHDOG LEARN ---
    if(app->scene == SceneWatchdogLearn) {
        if(ev->key == InputKeyBack) {
            subghz_rx_stop(app);
            app->force_decode_mode = false;
            app->scene = SceneWatchdogMenu;
            app_redraw(app);
            return;
        }
        if(ev->key == InputKeyOk && !app->armed) {
            subghz_receiver_reset(app->receiver);
            app->last_rssi = app->device ? subghz_devices_get_rssi(app->device) : -120.0f;
            app->armed    = true;
            app->deadline = furi_get_tick() + furi_ms_to_ticks(CAPTURE_TIMEOUT_MS);
            notification_message(app->notifications, &sequence_single_vibro);
            app_redraw(app);
        }
        return;
    }

    // --- WATCHING ---
    if(app->scene == SceneWatching) {
        if(ev->key == InputKeyBack) {
            subghz_rx_stop(app);
            app->force_decode_mode = false;
            app->scene = SceneWatchdogMenu;
            app_redraw(app);
        }
        return;
    }

    // --- WATCHDOG LOG ---
    if(app->scene == SceneWatchdogLog) {
        if(ev->key == InputKeyBack || ev->key == InputKeyOk) {
            app->scene = SceneWatchdogMenu;
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
    if(app->raws) {
        free(app->raws);
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
    watchdog_load_ref(app);

    // Decode pipeline: environment (protocol registry) -> receiver (matches
    // pulses against every registered protocol) -> worker (feeds raw CC1101
    // pulses into the receiver on its own thread).
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
