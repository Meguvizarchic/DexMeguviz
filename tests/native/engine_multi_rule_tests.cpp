#include "planner/engine_multi_rule.hpp"
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

using namespace dexmeguviz;
#define CHECK(x) do { if(!(x)) throw std::runtime_error("engine multi-rule line "+std::to_string(__LINE__)+": " #x); } while(0)
int main(int argc,char** argv){try{
    CHECK(argc==2);
    const auto path=std::filesystem::path(argv[1])/"generated/method_facts/method-uses.dex";
    std::ifstream input(path,std::ios::binary);CHECK(input.good());
    const std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(input),{}};
    dmg_engine_options options{};options.owned_bytes_limit=4u<<20;options.borrowed_bytes_limit=4u<<20;options.max_jobs=1;
    auto engine=std::make_shared<runtime::EngineState>(options);
    auto dataset=runtime::state<runtime::Dataset>(engine);
    auto source=runtime::state<runtime::Source>(engine);
    source->bytes.assign(bytes.begin(),bytes.end());
    source->facts=read_metadata(source->view(),&engine->fact_resource);
    dataset->sources.push_back(source);dataset->inputs.emplace_back(&engine->source_resource);
    auto query_state=runtime::state<runtime::QueryState>(engine);
    query_state->plan.emplace(query::compile(R"({"schema_version":1,"relation":"method_defs","where":{"name":"uses","using_strings":{"all":["used-string"]}}})",&engine->query_resource,&engine->scratch_resource));
    const std::array<planner::EngineRule,2> rules{{{"one",query_state,{}},{"two",query_state,{}}}};
    auto missing=runtime::state<runtime::QueryState>(engine);
    missing->plan.emplace(query::compile(R"({"schema_version":1,"relation":"method_defs","scope":{"slots":["absent"]},"where":{"name":"uses"}})",&engine->query_resource,&engine->scratch_resource));
    const std::array<planner::EngineRule,3> mixed{{{"missing",missing,{}},{"one",query_state,{}},{"two",query_state,{}}}};
    const auto baseline=engine->account.total();
    {
        auto batch=planner::execute_engine_multi(engine,dataset,rules,1u<<20,1000000);
        CHECK(batch.result&&batch.result->rules.size()==2);
        CHECK(batch.result->rules[0].code==planner::OutcomeCode::result_available);
        CHECK(batch.result->rules[1].code==planner::OutcomeCode::result_available);
        CHECK(batch.result->shared.cache_hits>0&&!batch.budget_retry);
        CHECK(batch.result->rules[0].result->rows.size()==batch.result->rules[1].result->rows.size());
        CHECK(engine->account.total()<baseline+(1u<<20)); // arena was freed
    }
    CHECK(engine->account.total()==baseline);
    {
        auto batch=planner::execute_engine_multi(engine,dataset,rules,8u<<20,1000000);
        CHECK(batch.arena_budget_unavailable&&batch.result&&batch.result->rules.size()==2);
        CHECK(batch.result->rules[0].code==planner::OutcomeCode::result_available);
        CHECK(batch.result->rules[1].code==planner::OutcomeCode::result_available);
        CHECK(batch.result->shared.cache_hits==0);
    }
    CHECK(engine->account.total()==baseline);
    // Reserve an unrelated, already-accounted allocation so that the scalar
    // run fits while a live optional arena can exhaust the Engine ledger.
    bool retried=false;
    for(uint64_t headroom:{1024u,2048u,4096u,8192u,16384u}){
        Charge occupied(engine->account,options.owned_bytes_limit-baseline-(1u<<20)-headroom,MemoryKind::control);
        struct Summary {planner::OutcomeCode code;uint64_t offset;uint32_t pc;uint64_t visited;size_t rows;};
        std::array<Summary,3> scalar{};
        {
            auto batch=planner::execute_engine_multi(engine,dataset,mixed,0,0);
            for(size_t i=0;i<scalar.size();++i){const auto& rule=batch.result->rules[i];
                scalar[i]={rule.code,rule.error_offset,rule.error_pc,rule.progress.visited,rule.result?rule.result->rows.size():0};}
            CHECK(scalar[0].code==planner::OutcomeCode::source_mismatch);
        }
        {
            auto batch=planner::execute_engine_multi(engine,dataset,mixed,1u<<20,1000000);
            if(batch.budget_retry){
                for(size_t i=0;i<scalar.size();++i){const auto& rule=batch.result->rules[i];const auto& expected=scalar[i];
                    CHECK(rule.code==expected.code&&rule.error_offset==expected.offset&&rule.error_pc==expected.pc&&rule.progress.visited==expected.visited);
                    CHECK((rule.result?rule.result->rows.size():0)==expected.rows);}
                CHECK(batch.result->shared.cache_hits==0);
                retried=true;
            }
        }
        if(retried)break;
    }
    CHECK(retried&&engine->account.total()==baseline);
    {
        auto empty=planner::execute_engine_multi(engine,dataset,{},8u<<20,1000000);
        CHECK(empty.result&&empty.result->rules.empty()&&!empty.arena_budget_unavailable);
        CHECK(engine->account.total()==baseline);
    }
    auto foreign=std::make_shared<runtime::EngineState>(options);
    auto foreign_query=runtime::state<runtime::QueryState>(foreign);
    foreign_query->plan.emplace(query::compile(R"({"schema_version":1,"relation":"method_defs"})",&foreign->query_resource,&foreign->scratch_resource));
    const std::array<planner::EngineRule,1> wrong{{{"wrong",foreign_query,{}}}};
    bool rejected=false;try{(void)planner::execute_engine_multi(engine,dataset,wrong,1024,100);}catch(const std::invalid_argument&){rejected=true;}
    CHECK(rejected&&engine->account.total()==baseline);
    std::cout<<"PASS engine-owned arena, reuse, lifetime, budget fallback and ownership checks\n";
    return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
