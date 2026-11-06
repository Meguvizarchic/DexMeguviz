#ifndef DEXMEGUVIZ_PERSISTENT_CACHE_V1_H
#define DEXMEGUVIZ_PERSISTENT_CACHE_V1_H

/* Optional desktop-only extension: link the separately enabled
 * dmg_persistent_facts library together with the normal core. */
#include "dexmeguviz.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct dmg_persistent_cache_v1 dmg_persistent_cache_v1;
typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    const uint8_t* directory_utf8;
    uint64_t directory_length;
    /* Zero selects the documented default for each bound. */
    uint64_t max_file_bytes;
    uint64_t max_directory_bytes;
    uint32_t max_directory_entries;
    uint32_t max_records;
    uint32_t reserved;
} dmg_persistent_cache_options_v1;
typedef struct {
    uint64_t hits, misses, rebuilds, rejected, published, write_failures, bytes_read;
} dmg_persistent_cache_stats_v1;

/* The caller chooses and trusts the directory and its writers. This call may
 * create it. It never enables caching for other queries or modifies defaults. */
dmg_status dmg_persistent_cache_open_v1(dmg_engine* engine,
    const dmg_persistent_cache_options_v1* options,dmg_persistent_cache_v1** out,dmg_error* error);
void dmg_persistent_cache_retain_v1(dmg_persistent_cache_v1* cache);
void dmg_persistent_cache_release_v1(dmg_persistent_cache_v1* cache);
/* Closes admission immediately; already-admitted synchronous calls continue. */
dmg_status dmg_persistent_cache_close_v1(dmg_persistent_cache_v1* cache);
/* Thread-safe snapshot of this handle's counters; available after close. */
dmg_status dmg_persistent_cache_get_stats_v1(dmg_persistent_cache_v1* cache,
    dmg_persistent_cache_stats_v1* out,uint32_t out_size);
/* Synchronous only; caller retains all handles throughout the call. The cache,
 * snapshot and compiled query must belong to the same Engine. The returned
 * Result obeys the normal result lifetime and getters. */
dmg_status dmg_persistent_cache_execute_v1(dmg_persistent_cache_v1* cache,
    dmg_snapshot* snapshot,dmg_query* query,dmg_result** out,dmg_error* error);
#ifdef __cplusplus
}
#endif
#endif
