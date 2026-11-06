#include "planner/isolated_multi.hpp"
#include <array>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>
#include <vector>
using namespace dexmeguviz;
#define CHECK(x) do{if(!(x))throw std::runtime_error("isolated multi line "+std::to_string(__LINE__)+": " #x);}while(false)
int main(int argc,char** argv){try{
    CHECK(argc==2);std::ifstream input(std::filesystem::path(argv[1])/"generated/method_facts/method-uses.dex",std::ios::binary);
    CHECK(input.good());const std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(input),{}};
    dmg_engine_options engine{sizeof(engine),DMG_ABI_VERSION,16u<<20,8u<<20,8u<<20,2,0};
    std::array<dmg_source_spec,2> sources{{
        {sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,bytes.data(),bytes.size(),"a","raw",nullptr},
        {sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,bytes.data(),bytes.size(),"b","raw",nullptr}}};
    dmg_source_set_options options{sizeof(options),DMG_ABI_VERSION,"multi-test",1,16,8u<<20};
    auto session=planner::IsolatedMultiSession::open(&engine,sources.data(),sources.size(),&options);
    constexpr auto one=R"({"schema_version":1,"relation":"method_defs","where":{"name":"uses","using_strings":{"all":["used-string"]}}})";
    constexpr auto two=R"({"schema_version":1,"relation":"method_defs","where":{"name":{"op":"contains","value":"use"},"using_strings":{"all":["used-string"]}}})";
    session->add("one",one);session->add("two",two);
    session->add("join",R"({"schema_version":1,"relation":{"op":"join","on":"same_entity","left":{"op":"label","label":"L","input":{"op":"scan","relation":"method_defs","where":{"name":"uses"}}},"right":{"op":"label","label":"R","input":{"op":"scan","relation":"method_defs","where":{"name":"uses"}}}}})");
    session->add("group",R"({"schema_version":1,"relation":{"op":"group_by_owner","inputs":[{"op":"label","label":"member","input":{"op":"scan","relation":"method_defs","where":{"name":"uses"}}}],"min":1,"max":1,"required_roles":["member"]}})");
    const std::array<std::string_view,2> ids{"one","two"};
    auto baseline=session->owned_bytes();
    {
      auto scalar=session->execute(ids,0,0);auto shared=session->execute(ids,1u<<20,1000000);
      CHECK(scalar.size()==2&&shared.size()==2&&shared.profile().cache_hits>0&&!shared.retried());
      for(size_t i=0;i<2;++i){const auto a=scalar.summary(i);const auto b=shared.summary(i);
        CHECK(a.id==b.id&&a.code==planner::OutcomeCode::result_available&&b.code==a.code);
        CHECK(a.visited==b.visited&&a.total==b.total&&a.profile.work_units==b.profile.work_units);
        CHECK(a.result_available&&b.result_available&&a.rows==b.rows&&a.rows>0);
        for(size_t j=0;j<a.rows;++j){CHECK(scalar.row_key(i,j)==shared.row_key(i,j));
          CHECK(scalar.witness_count(i,j)==shared.witness_count(i,j));
          for(size_t k=0;k<scalar.witness_count(i,j);++k){const auto u=scalar.witness(i,j,k);const auto v=shared.witness(i,j,k);
            CHECK(u.kind==v.kind&&u.node==v.node&&u.matched==v.matched&&u.dex_pc==v.dex_pc&&u.reference_index==v.reference_index);}}
      }
      CHECK(shared.source_method_count(0)==shared.source_method_count(1));
      CHECK(shared.source(0).slot=="a" && shared.source(1).slot=="b");
      CHECK(shared.entity(shared.row_key(0,0)).name==u"uses");
      try{(void)shared.entity({0,UINT32_MAX,query::Relation::method_defs,UINT32_MAX});CHECK(false);}catch(const std::out_of_range&){}
      CHECK(session->owned_bytes()>baseline);
    }
    CHECK(session->owned_bytes()==baseline);
    {
      const std::array<std::string_view,2> graph_ids{"join","group"};
      auto graph=session->execute(graph_ids,1u<<20,1000000);
      CHECK(graph.size()==2 && graph.profile().cache_hits==0);
      for(size_t i=0;i<2;++i){const auto state=graph.summary(i);CHECK(state.code==planner::OutcomeCode::result_available&&state.graph_available&&state.graph_nodes>0&&state.rows>0);CHECK(graph.result_scope_count(i)==2);CHECK(graph.scope_source(i,0)==0&&graph.scope_source(i,1)==1);CHECK(graph.graph_node(i,0).complete);}
      CHECK(graph.binding_count(0,0)==4&&graph.link_count(0,0)==1);
      const auto binding=graph.binding(0,0,1);CHECK(graph.label(0,binding.label)=="L");
      CHECK(graph.entity(binding.entity).name==u"uses");CHECK(graph.link(0,0,0).left.source_index==graph.link(0,0,0).right.source_index);
    }
    CHECK(session->owned_bytes()==baseline);
    try{const std::array<std::string_view,2> repeated{"one","one"};(void)session->execute(repeated,0,0);CHECK(false);}catch(const std::invalid_argument&){}
    try{session->add("one",one);CHECK(false);}catch(const std::invalid_argument&){}
    try{session->add("invalid","{");CHECK(false);}catch(const planner::SessionError& e){CHECK(e.status==DMG_INVALID_ARGUMENT);}
    try{const std::array<std::string_view,1> missing{"missing"};(void)session->execute(missing,0,0);CHECK(false);}catch(const std::invalid_argument&){}
    CHECK(session->owned_bytes()==baseline);
    std::atomic<unsigned> failures=0;auto worker=[&]{try{for(int i=0;i<5;++i){auto b=session->execute(ids,1u<<20,1000000);if(b.size()!=2||b.summary(0).code!=planner::OutcomeCode::result_available)++failures;}}catch(...){++failures;}};
    std::thread a(worker),b(worker);a.join();b.join();CHECK(failures==0&&session->owned_bytes()==baseline);
    auto materialized_worker=[&]{try{for(int i=0;i<5;++i){auto results=session->execute_materialized(ids,1u<<20,1000000);dmg_relation_info info{};if(results.size()!=2||results.profile().cache_hits==0||results.at(0).relation_info(info)!=DMG_OK||info.candidates_count==0)++failures;}}catch(...){++failures;}};
    std::thread c(materialized_worker),d(materialized_worker);c.join();d.join();CHECK(failures==0&&session->owned_bytes()==baseline);
    {
        auto incomplete_options=options;incomplete_options.scope_complete=0;
        auto partial=planner::IsolatedMultiSession::open(&engine,sources.data(),sources.size(),&incomplete_options);
        partial->add("absent",R"({"schema_version":1,"relation":"method_defs","where":{"name":"not-present"},"intent":"exists"})");
        const std::array<std::string_view,1> absent{"absent"};auto output=partial->execute(absent,0,0);
        const auto state=output.summary(0);CHECK(state.code==planner::OutcomeCode::result_available&&state.result_available&&state.rows==0&&!state.scope_complete);
    }
    auto retained=session->execute(ids,1u<<20,1000000);session->close();
    try{(void)session->execute(ids,0,0);CHECK(false);}catch(const std::logic_error&){}
    session.reset();CHECK(retained.size()==2&&retained.summary(0).result_available&&retained.summary(0).rows>0);
    CHECK(retained.source_method_count(0)>0);
    std::cout<<"PASS private serial session, reference parity, source/result lifetime, budget and close\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}







