#pragma once
#include "dexmeguviz/fast_query_v1.h"
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <stdexcept>
#include <vector>

namespace native_apk_candidate {
struct FastFailure : std::runtime_error {
 dmg_status status; uint32_t rule; dmg_error detail;
 FastFailure(dmg_status s,uint32_t r,const dmg_error& d):std::runtime_error("fast scan failure"),status(s),rule(r),detail(d){}
};
struct Input { std::filesystem::path apk; std::u16string slot; bool allow_no_dex; };
struct Limits {
 uint32_t workers=1,max_inputs=1,max_sources_per_input=1,max_sources=1,max_entries_per_input=1;
 uint64_t max_archive_bytes_per_input=0,max_archive_bytes=0,max_dex_bytes_per_input=0,max_dex_bytes=0,max_one_dex_bytes=0;
 uint64_t max_inflight_dex_bytes=0,max_zip_metadata_bytes_per_reader=0,max_total_rows=0;
 bool digest_matched_sources=false;
};
struct Source { std::u16string slot; uint32_t input_index,central_index,ordinal; uint64_t size,compressed_size; uint32_t crc; };
struct ResultDeleter { void operator()(dmg_fast_results_v1* p) const {if(p)dmg_fast_results_release_v1(p);} };
struct Item { Source source; std::string matched_sha256; std::unique_ptr<dmg_fast_results_v1,ResultDeleter> result; };
struct InputSummary { std::u16string slot; uint32_t sources=0; uint64_t archive_bytes=0,dex_bytes=0,compressed_bytes=0; };
struct Response { std::vector<InputSummary> inputs; std::vector<Item> ordered; uint64_t archive_bytes=0,dex_bytes=0,compressed_bytes=0; };
// Caller guarantees immutable APKs and valid sorted DEX for the entire call.
// Plans remain alive for the whole synchronous call. Results own their data;
// this function returns only after all source-level calls succeed and workers join.
// Rule-level status, unknown rows and limits remain in each result and must be
// checked by the caller; a returned rule failure is not a negative result.
// A valid previously compiled plan handle is required even with no DEX sources.
// This experimental C++ candidate is not a stable ABI or a complete ZIP verifier.
Response scan(const std::vector<Input>&,const Limits&,const dmg_fast_plans_v1*,const dmg_fast_limits_v1&);
}
