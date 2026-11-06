#include "facts/use_relations/use_scan.hpp"
#include "format/instructions/decoder.hpp"
#include "source/sha256.hpp"
#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory_resource>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using namespace dexmeguviz;
using namespace dexmeguviz::facts;
#define CHECK(x) do { if (!(x)) throw std::runtime_error("use scan check " + std::to_string(__LINE__) + ": " #x); } while (0)

struct Counted final : std::pmr::memory_resource {
    size_t current=0,peak=0,limit=std::numeric_limits<size_t>::max();
    void* do_allocate(size_t bytes,size_t alignment) override {
        if(bytes>limit-current)throw std::bad_alloc();
        auto* p=std::pmr::new_delete_resource()->allocate(bytes,alignment);current+=bytes;peak=std::max(peak,current);return p;
    }
    void do_deallocate(void* p,size_t bytes,size_t alignment) override {
        CHECK(current>=bytes);current-=bytes;std::pmr::new_delete_resource()->deallocate(p,bytes,alignment);
    }
    bool do_is_equal(const std::pmr::memory_resource& r)const noexcept override{return this==&r;}
};

static std::vector<uint8_t> load(const std::filesystem::path& path,const char* expected_sha){
    std::ifstream input(path,std::ios::binary);CHECK(input.good());
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)),{});CHECK(sha256<>(bytes)==expected_sha);return bytes;
}
static uint16_t unit(const std::vector<uint8_t>& bytes,uint32_t code,uint32_t pc){
    const size_t at=size_t(code)+16+size_t(pc)*2;CHECK(at<=bytes.size()&&bytes.size()-at>=2);
    return uint16_t(bytes[at])|(uint16_t(bytes[at+1])<<8);
}
static std::vector<uint8_t> empty_fixture(){
    // Header and map_list only; SHA-1 and Adler-32 independently sealed with Python.
    constexpr std::string_view hex="6465780a30333500be0b70d91d9c3f88730d0ed6caa377d4520465e7322d365a8c00000070000000785634120000000000000000700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c0000007000000002000000000000000100000000000000001000000100000070000000";
    auto digit=[](char c)->uint8_t{return c<='9'?uint8_t(c-'0'):uint8_t(c-'a'+10);};
    std::vector<uint8_t> bytes;bytes.reserve(hex.size()/2);
    for(size_t i=0;i<hex.size();i+=2)bytes.push_back(uint8_t((digit(hex[i])<<4)|digit(hex[i+1])));
    CHECK(bytes.size()==140&&sha256<>(bytes)=="e0aeaa1d698e1d1149ffdcf116e7b3e98b3a3097814e01718c80caaee147b7ae");
    return bytes;
}

struct Event {UseKind kind;uint32_t pc,index,extra;uint8_t opcode;TargetDomain domain;};
struct Fixture {const char* path;const char* sha;bool corrupt;std::vector<Event> events;};

static void check_event(const UseRecord& actual,const Event& expected,uint32_t source,const std::vector<uint8_t>& bytes){
    CHECK(actual.key.source_index==source&&actual.key.kind==expected.kind&&actual.key.caller_ordinal==2&&actual.key.dex_pc==expected.pc);
    CHECK(actual.caller_method_ref==3&&actual.code_offset==416&&actual.target_index==expected.index);
    CHECK(actual.extra_proto==expected.extra&&actual.opcode==expected.opcode&&actual.target_domain==expected.domain);
    CHECK((unit(bytes,actual.code_offset,expected.pc)&0xff)==expected.opcode);
    CHECK(unit(bytes,actual.code_offset,expected.pc+1)==expected.index);
    if(expected.opcode==0x1b)CHECK(unit(bytes,actual.code_offset,expected.pc+2)==0);
    if(expected.domain==TargetDomain::method_and_proto)CHECK(unit(bytes,actual.code_offset,expected.pc+3)==expected.extra);
}

int main(int argc,char** argv){try{
    CHECK(argc==2);const std::filesystem::path root(argv[1]);
    constexpr uint32_t none=UINT32_MAX;
    const std::vector<Fixture> fixtures{
        {"generated/method_facts/method-uses.dex","8262d2b338e54a7965111b4cec1ef9e628ada9795ad2f6a555d717a2ba9546bc",false,
         {{UseKind::string_use,0,10,none,0x1a,TargetDomain::string_value},{UseKind::invoke_site,2,4,none,0x71,TargetDomain::method_ref},{UseKind::field_use,5,0,none,0x60,TargetDomain::field_ref}}},
        {"generated/method_facts/invoke-domains-038.dex","ecf85d163c87d58f065335f0d932442be48b91b5efa3858e319a1c1cdf7313b0",false,
         {{UseKind::invoke_site,0,4,0,0xfa,TargetDomain::method_and_proto},{UseKind::invoke_site,4,0,none,0xfc,TargetDomain::call_site}}},
        {"generated/use_relations/two-invokes.dex","04656bbfe03c8b04e6f77d29b8cae8e7e06f18a038f85300658f8c691435648b",false,
         {{UseKind::invoke_site,0,4,none,0x71,TargetDomain::method_ref},{UseKind::invoke_site,3,4,none,0x71,TargetDomain::method_ref}}},
        {"generated/use_relations/field-read-write.dex","7558a8945c3a87f727de782d885c687539d839e460497f6d2e86c2a7c7f46e8d",false,
         {{UseKind::field_use,0,0,none,0x60,TargetDomain::field_ref},{UseKind::field_use,2,0,none,0x67,TargetDomain::field_ref}}},
        {"generated/use_relations/string-normal-jumbo.dex","65373dc14bb0b19b3fb4ae8fd236e83befbfee4b69b74e3a8d4a8b7db2637c04",false,
         {{UseKind::string_use,0,10,none,0x1a,TargetDomain::string_value},{UseKind::string_use,2,10,none,0x1b,TargetDomain::string_value}}},
        {"generated/use_relations/valid-then-corrupt.dex","4e0661d233cfc3eaf32aff66e615a1cacba822e768c3c3b4559f0f0abfc2c2be",true,{}}
    };
    Counted metadata_memory,scratch_memory;auto* previous=std::pmr::set_default_resource(std::pmr::null_memory_resource());unsigned checks=0;
    try{
        for(const auto& fixture:fixtures){
            const auto bytes=load(root/fixture.path,fixture.sha);
            {
                const auto metadata=read_metadata(bytes,&metadata_memory);
                CHECK(metadata.methods.size()==4&&metadata.methods[2].method_index==3&&metadata.methods[2].code_offset==416);
                CHECK(metadata.strings[7]==u"only-in-pool"&&metadata.strings[10]==u"used-string");
                const auto saved=metadata_memory.current;
                for(const auto kind:{UseKind::string_use,UseKind::invoke_site,UseKind::field_use}){
                    UseScanProgress progress{};
                    if(fixture.corrupt){
                        bool returned=false,corrupt=false;
                        try{const auto result=collect_uses(bytes,metadata,3,kind,progress,&scratch_memory);returned=true;(void)result;}
                        catch(const instructions::DecodeError& error){
                            CHECK(error.code==instructions::DecodeCode::corrupt&&error.dex_pc==5&&error.dex_offset==442);corrupt=true;
                        }
                        CHECK(corrupt&&!returned&&scratch_memory.current==0);
                        CHECK(progress.total_methods==4&&progress.attempted_methods==3&&progress.visited_methods==2);
                        CHECK(progress.no_body_methods==1&&progress.decoded_methods==1&&progress.emitted_events==0&&progress.code_units==1);
                    }else{
                        std::vector<Event> expected;
                        for(const auto& event:fixture.events)if(event.kind==kind)expected.push_back(event);
                        {
                            const auto result=collect_uses(bytes,metadata,3,kind,progress,&scratch_memory);
                            CHECK(result.rows.get_allocator().resource()==&scratch_memory&&result.rows.size()==expected.size());
                            CHECK(progress.total_methods==4&&progress.attempted_methods==4&&progress.visited_methods==4);
                            CHECK(progress.no_body_methods==2&&progress.decoded_methods==2&&progress.emitted_events==expected.size());
                            CHECK(progress.code_units==9&&progress.validation_work>=9);
                            CHECK(progress.work_units==progress.attempted_methods+progress.validation_work+progress.emitted_events);
                            for(size_t i=0;i<expected.size();++i)check_event(result.rows[i],expected[i],3,bytes);
                            if(expected.size()==2){CHECK(result.rows[0].key.dex_pc!=result.rows[1].key.dex_pc);}
                        }
                        CHECK(scratch_memory.current==0);
                    }
                    CHECK(metadata_memory.current==saved);++checks;
                }
            }
            CHECK(metadata_memory.current==0&&scratch_memory.current==0);
        }

        const auto duplicate=load(root/"generated/use_relations/two-invokes.dex","04656bbfe03c8b04e6f77d29b8cae8e7e06f18a038f85300658f8c691435648b");
        {
            auto metadata=read_metadata(duplicate,&metadata_memory);const auto saved=metadata_memory.current;
            {
                UseScanProgress a{},b{};const auto left=collect_uses(duplicate,metadata,4,UseKind::invoke_site,a,&scratch_memory);
                const auto right=collect_uses(duplicate,metadata,5,UseKind::invoke_site,b,&scratch_memory);
                CHECK(left.rows.size()==2&&right.rows.size()==2);
                for(size_t i=0;i<2;++i){CHECK(left.rows[i].key.source_index==4&&right.rows[i].key.source_index==5);
                    CHECK(left.rows[i].key.caller_ordinal==right.rows[i].key.caller_ordinal&&left.rows[i].key.dex_pc==right.rows[i].key.dex_pc);
                    CHECK(left.rows[i].target_index==right.rows[i].target_index&&left.rows[i].key.kind==right.rows[i].key.kind);}
            }
            CHECK(scratch_memory.current==0);++checks;
            {
                UseScanLimits limits{};limits.max_records=1;UseScanProgress progress{};bool returned=false,limited=false;
                try{const auto result=collect_uses(duplicate,metadata,0,UseKind::invoke_site,progress,&scratch_memory,limits);returned=true;(void)result;}
                catch(const UseScanError& error){CHECK(error.code==UseScanError::Code::budget);limited=true;}
                CHECK(limited&&!returned&&progress.total_methods==4&&progress.attempted_methods==3&&progress.visited_methods==2);
                CHECK(progress.no_body_methods==1&&progress.decoded_methods==1&&progress.emitted_events==0&&progress.code_units==1&&scratch_memory.current==0);
            }++checks;
            for(const uint64_t budget:{1u,3u}){
                UseScanLimits limits{};limits.max_work=budget;UseScanProgress progress{};bool returned=false,limited=false;
                try{const auto result=collect_uses(duplicate,metadata,0,UseKind::invoke_site,progress,&scratch_memory,limits);returned=true;(void)result;}
                catch(const UseScanError& error){CHECK(error.code==UseScanError::Code::budget);limited=true;}
                CHECK(limited&&!returned&&progress.work_units==budget&&progress.attempted_methods==(budget==1?1u:2u));
                CHECK(progress.visited_methods==progress.attempted_methods&&progress.no_body_methods==1&&progress.emitted_events==0&&scratch_memory.current==0);
                CHECK(progress.decoded_methods==(budget==1?0u:1u)&&progress.code_units==(budget==1?0u:1u));++checks;
            }
            {
                UseScanLimits limits{};limits.max_work=4;UseScanProgress progress{};bool returned=false,limited=false;
                try{const auto result=collect_uses(duplicate,metadata,0,UseKind::invoke_site,progress,&scratch_memory,limits);returned=true;(void)result;}
                catch(const instructions::DecodeError& error){CHECK(error.code==instructions::DecodeCode::budget&&error.dex_pc==0);limited=true;}
                CHECK(limited&&!returned&&progress.attempted_methods==3&&progress.visited_methods==2&&progress.no_body_methods==1);
                CHECK(progress.decoded_methods==1&&progress.emitted_events==0&&progress.code_units==1&&scratch_memory.current==0);
            }++checks;
            {
                UseScanProgress progress{};unsigned calls=0;UseScanCancel cancel{[](void* p)noexcept{++*static_cast<unsigned*>(p);return true;},&calls};
                bool returned=false,cancelled=false;
                try{const auto result=collect_uses(duplicate,metadata,0,UseKind::invoke_site,progress,&scratch_memory,{},cancel);returned=true;(void)result;}
                catch(const UseScanError& error){CHECK(error.code==UseScanError::Code::cancelled);cancelled=true;}
                CHECK(cancelled&&!returned&&calls==1&&progress.attempted_methods==0&&progress.visited_methods==0&&scratch_memory.current==0);
            }++checks;
            {
                // nativeMethod costs 1, quiet costs 2, uses costs 1+8; its first append then costs 1.
                UseScanProgress progress{};
                UseScanCancel cancel{[](void* p)noexcept{const auto& state=*static_cast<const UseScanProgress*>(p);return state.attempted_methods==3&&state.work_units==13;},&progress};
                bool returned=false,cancelled=false;
                try{const auto result=collect_uses(duplicate,metadata,0,UseKind::invoke_site,progress,&scratch_memory,{},cancel);returned=true;(void)result;}
                catch(const UseScanError& error){CHECK(error.code==UseScanError::Code::cancelled);cancelled=true;}
                CHECK(cancelled&&!returned&&progress.total_methods==4&&progress.attempted_methods==3&&progress.visited_methods==2);
                CHECK(progress.no_body_methods==1&&progress.decoded_methods==1&&progress.emitted_events==0&&progress.code_units==1&&progress.work_units==13);
                CHECK(scratch_memory.current==0);
            }++checks;
            {
                bool found=false;
                for(unsigned limit=2;limit<32&&!found;++limit){
                    struct Cancellation {unsigned calls=0,limit=0;} state{0,limit};
                    UseScanCancel cancel{[](void* p)noexcept{auto& s=*static_cast<Cancellation*>(p);return ++s.calls>=s.limit;},&state};
                    UseScanProgress progress{};
                    try{(void)collect_uses(duplicate,metadata,0,UseKind::invoke_site,progress,&scratch_memory,{},cancel);}
                    catch(const instructions::DecodeError& error){
                        CHECK(error.code==instructions::DecodeCode::cancelled);
                        CHECK(progress.attempted_methods>progress.visited_methods&&progress.no_body_methods<=progress.visited_methods);found=true;
                    }
                    catch(const UseScanError& error){CHECK(error.code==UseScanError::Code::cancelled);}
                    CHECK(scratch_memory.current==0);
                }
                CHECK(found);
            }++checks;
            {
                scratch_memory.limit=0;UseScanProgress progress{};bool failed=false;
                try{(void)collect_uses(duplicate,metadata,0,UseKind::invoke_site,progress,&scratch_memory);}
                catch(const std::bad_alloc&){failed=true;}
                scratch_memory.limit=std::numeric_limits<size_t>::max();
                CHECK(failed&&progress.attempted_methods>progress.visited_methods&&progress.no_body_methods==1&&scratch_memory.current==0);
            }++checks;
            for(const auto invalid:{static_cast<UseKind>(3),static_cast<UseKind>(UINT32_MAX)}){
                UseScanProgress progress{};bool rejected=false;
                try{(void)collect_uses(duplicate,metadata,0,invalid,progress,&scratch_memory);}
                catch(const UseScanError& error){CHECK(error.code==UseScanError::Code::unsupported);rejected=true;}
                CHECK(rejected&&progress.attempted_methods==0&&progress.visited_methods==0&&scratch_memory.current==0);++checks;
            }
            for(unsigned which=0;which<3;++which){
                UseScanLimits limits{};if(which==0)limits.max_work=0;else if(which==1)limits.max_records=0;
                UseScanProgress progress{};bool rejected=false;
                try{(void)collect_uses(duplicate,metadata,0,UseKind::invoke_site,progress,which==2?nullptr:&scratch_memory,limits);}
                catch(const UseScanError& error){CHECK(error.code==UseScanError::Code::invalid);rejected=true;}
                CHECK(rejected&&progress.attempted_methods==0&&progress.visited_methods==0&&scratch_memory.current==0);++checks;
            }
            CHECK(metadata_memory.current==saved);
        }
        CHECK(metadata_memory.current==0&&scratch_memory.current==0);
        {
            const auto bytes=empty_fixture();auto empty=read_metadata(bytes,&metadata_memory);UseScanProgress progress{};
            {const auto result=collect_uses(bytes,empty,0,UseKind::invoke_site,progress,&scratch_memory);
             CHECK(result.rows.empty()&&progress.total_methods==0&&progress.attempted_methods==0&&progress.visited_methods==0&&progress.emitted_events==0);}
            CHECK(scratch_memory.current==0);
            bool rejected=false;try{(void)collect_uses(bytes,empty,0,static_cast<UseKind>(UINT32_MAX),progress,&scratch_memory);}
            catch(const UseScanError& error){CHECK(error.code==UseScanError::Code::unsupported);rejected=true;}CHECK(rejected&&scratch_memory.current==0);
        }++checks;
        CHECK(metadata_memory.current==0&&scratch_memory.current==0);
        {
            std::optional<UseScanResult> retained;
            {const auto bytes=load(root/"generated/use_relations/two-invokes.dex","04656bbfe03c8b04e6f77d29b8cae8e7e06f18a038f85300658f8c691435648b");
             auto metadata=read_metadata(bytes,&metadata_memory);UseScanProgress progress{};
             retained.emplace(collect_uses(bytes,metadata,9,UseKind::invoke_site,progress,&scratch_memory));
             CHECK(retained->rows.size()==2&&progress.emitted_events==2);}
            CHECK(metadata_memory.current==0&&retained->rows[1].key.source_index==9&&retained->rows[1].key.dex_pc==3&&retained->rows[1].target_index==4);
            retained.reset();CHECK(scratch_memory.current==0);
        }++checks;
    }catch(...){std::pmr::set_default_resource(previous);throw;}
    std::pmr::set_default_resource(previous);CHECK(metadata_memory.current==0&&scratch_memory.current==0);
    std::cout<<"PASS use scan: "<<checks<<" cases; stable source/caller/PC, typed target domains, full method validation, scope counters, budgets, cancellation, allocation rollback and value lifetime\n";
    return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
