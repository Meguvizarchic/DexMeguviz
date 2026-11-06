#include "dexmeguviz/dexmeguviz.h"
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#define CHECK(x) do { if (!(x)) throw std::runtime_error("line " + std::to_string(__LINE__) + ": " #x); } while (0)

struct Observation { dmg_job_status terminal{}; std::vector<std::string> names; };
static Observation execute(dmg_engine* engine, dmg_snapshot* snapshot, uint32_t cap) {
    dmg_method_query options{}; options.struct_size=sizeof(options); options.abi_version=DMG_ABI_VERSION;
    options.intent=DMG_ENUMERATE; options.max_results=cap;
    dmg_error error{}; dmg_query* query=nullptr;
    CHECK(dmg_query_compile_methods(engine,&options,&query,&error)==DMG_OK);
    dmg_job_options job_options{sizeof(job_options),DMG_ABI_VERSION,4,2,0}; dmg_job* job=nullptr;
    CHECK(dmg_job_start(snapshot,query,&job_options,&job,&error)==DMG_OK);
    Observation out;
    for (unsigned tries=0; tries<100; ++tries) {
        dmg_batch* batch=nullptr; const auto next=dmg_job_next(job,100,&batch,&error);
        if(next==DMG_NOT_READY) continue;
        if(next==DMG_END_OF_STREAM) break;
        CHECK(next==DMG_OK && batch);
        dmg_result_info info{}; CHECK(dmg_batch_get_info(batch,&info)==DMG_OK);
        CHECK(info.coverage==DMG_COVERAGE_PARTIAL && info.decision==DMG_NOT_APPLICABLE);
        for(uint32_t i=0;i<info.candidates_count;++i){
            dmg_method_row row{}; CHECK(dmg_batch_get_method(batch,i,&row)==DMG_OK);
            CHECK(row.name_length==3 && row.method_index==out.names.size());
            std::string name; for(uint64_t j=0;j<row.name_length;++j) name.push_back(static_cast<char>(row.name[j]));
            CHECK(name == "m" + std::string(row.method_index<10 ? "0" : "") + std::to_string(row.method_index));
            out.names.push_back(name);
        }
        dmg_batch_release(batch);
    }
    CHECK(dmg_job_wait(job,2000,&out.terminal)==DMG_OK && out.terminal.terminal);
    dmg_job_release(job); dmg_query_release(query); return out;
}
int main(int argc,char** argv) { try {
    CHECK(argc==2); std::ifstream input(argv[1],std::ios::binary); CHECK(input.good());
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)),{});
    dmg_engine_options eo{sizeof(eo),DMG_ABI_VERSION,8u<<20,8u<<20,1u<<20,1,0};
    dmg_engine* engine=nullptr; dmg_error error{}; CHECK(dmg_engine_create(&eo,&engine,&error)==DMG_OK);
    const dmg_open_options oo{sizeof(oo),DMG_ABI_VERSION,0,"q10-test","slot",nullptr}; dmg_snapshot* snapshot=nullptr;
    CHECK(dmg_snapshot_open_copy_in(engine,bytes.data(),bytes.size(),&oo,&snapshot,&error)==DMG_OK);
    const auto first=execute(engine,snapshot,32); const auto& fail=first.terminal.outcome;
    CHECK(first.names.size()==32 && fail.execution_status==DMG_BUDGET_EXCEEDED && fail.coverage==DMG_COVERAGE_PARTIAL && fail.reason==DMG_RESULT_LIMIT);
    // Business decisions and negative-cache flag are simulated in this harness only.
    unsigned first_accepted=0; for(const auto& name:first.names) if(name=="m32") ++first_accepted;
    CHECK(first_accepted==0);
    bool negative_cache_allowed=fail.execution_status==DMG_OK && fail.coverage==DMG_COVERAGE_COMPLETE && first_accepted==0;
    CHECK(!negative_cache_allowed);
    const auto retry=execute(engine,snapshot,33); const auto& full=retry.terminal.outcome;
    CHECK(retry.names.size()==33 && retry.names.back()=="m32" && full.execution_status==DMG_OK && full.coverage==DMG_COVERAGE_COMPLETE);
    unsigned accepted=0; for(const auto& name:retry.names) if(name=="m32") ++accepted;
    CHECK(accepted==1);
    std::cout << "{\"first_rows\":32,\"first_status\":\"BudgetExceeded\",\"first_coverage\":\"Partial\",\"first_reason\":\"ResultLimit\",\"negative_cache_allowed\":false,\"retry_rows\":33,\"retry_status\":\"Complete\",\"retry_coverage\":\"Complete\",\"simulated_accepted\":\"m32\",\"simulated_unique\":true}" << std::endl;
    dmg_snapshot_release(snapshot); dmg_engine_release(engine); return 0;
} catch(const std::exception& e) { std::cerr << e.what() << std::endl; return 1; } }
