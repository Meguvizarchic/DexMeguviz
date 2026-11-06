#pragma once
#include "dexmeguviz/dexmeguviz.h"
#include <string>
#include <string_view>
#include <exception>
namespace dmg_cli {
struct SqlOutputLimit final:std::exception {const char* what()const noexcept override{return "SQL JSON exceeds 8 MiB";}};
struct SqlFrontendOptions {
    uint64_t max_rows=10000,max_result_bytes=4u<<20,max_progress_intervals=10000;
    uint64_t source_prepare_us=0,sqlite_heap_bytes=128u<<20;
    bool metadata_identity_equality=false,metadata_identity_in=false;
};
struct SqlFrontendResult {std::string json;int exit_code=0;};
SqlFrontendResult execute_sql(dmg_snapshot* snapshot,std::string_view sql,
    std::string_view parameters_json,const SqlFrontendOptions& options);
}
