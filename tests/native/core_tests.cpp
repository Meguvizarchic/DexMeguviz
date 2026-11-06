#include "dexmeguviz/dexmeguviz.h"
#include "source/sha256.hpp"
#include "execution/budget/account.hpp"
#include <atomic>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <new>
#include <stdexcept>
#include <string>
#include <vector>
#ifdef _MSC_VER
#include <crtdbg.h>
#endif

static std::atomic<int> allocation_countdown{-1};
static int active_fault_index=-1;
void* operator new(std::size_t n){
    int v=allocation_countdown.load();
    if(v>=0 && allocation_countdown.fetch_sub(1)==0) throw std::bad_alloc();
    if(void* p=std::malloc(n?n:1)) return p;
    throw std::bad_alloc();
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p,std::size_t) noexcept { std::free(p); }
void* operator new[](std::size_t n){return ::operator new(n);}
void operator delete[](void* p) noexcept {::operator delete(p);}
void operator delete[](void* p,std::size_t) noexcept {::operator delete(p);}
#define CHECK(x) do{if(!(x)) throw std::runtime_error(std::string("line ")+std::to_string(__LINE__)+": "+#x);}while(0)
static std::string hash(const std::string& s){return dexmeguviz::sha256({reinterpret_cast<const uint8_t*>(s.data()),s.size()});}
int main(int argc,char** argv){
    try{
#ifdef _MSC_VER
        _CrtSetReportMode(_CRT_ASSERT,_CRTDBG_MODE_FILE);
        _CrtSetReportFile(_CRT_ASSERT,_CRTDBG_FILE_STDERR);
        _set_abort_behavior(0,_WRITE_ABORT_MSG|_CALL_REPORTFAULT);
#endif
        std::cout << std::unitbuf;
        std::set_terminate([](){allocation_countdown=-1;std::cerr << "terminate during allocation fault index " << active_fault_index << '\n';std::_Exit(90);});
        CHECK(argc==2);
        std::cout << "checking SHA-256 vectors\n";
        CHECK(hash("")=="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        CHECK(hash("abc")=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        CHECK(hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")=="248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
        CHECK(hash(std::string(1000000,'a'))=="cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
        std::ifstream f(argv[1],std::ios::binary);CHECK(f.good());
        std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(f)),{});CHECK(!bytes.empty());
        std::cout << "checking source identity and query semantics\n";
        dmg_open_options options{sizeof(dmg_open_options),DMG_ABI_VERSION,DMG_MAX_SOURCE_BYTES,"native-test","a",nullptr};
        dmg_snapshot* s=nullptr;dmg_error error{};
        CHECK(dmg_snapshot_open_copy(bytes.data(),bytes.size(),&options,&s,&error)==DMG_OK);
        dmg_snapshot_info first{};CHECK(dmg_snapshot_get_info(s,&first)==DMG_OK);
        const std::string content=first.content_id,occurrence=first.occurrence_id;
        options.slot_key="b";dmg_snapshot* other=nullptr;
        CHECK(dmg_snapshot_open_copy(bytes.data(),bytes.size(),&options,&other,&error)==DMG_OK);
        dmg_snapshot_info second{};CHECK(dmg_snapshot_get_info(other,&second)==DMG_OK);
        CHECK(content==second.content_id && occurrence!=second.occurrence_id);
        dmg_snapshot_release(other);
        dmg_method_query q{};q.struct_size=sizeof(q);q.abi_version=DMG_ABI_VERSION;q.max_results=8;q.intent=DMG_UNIQUE;
        auto run=[&](){dmg_result* r=nullptr;CHECK(dmg_query_methods(s,&q,&r,&error)==DMG_OK);dmg_result_info info{};CHECK(dmg_result_get_info(r,&info)==DMG_OK);dmg_result_release(r);return info;};
        auto info=run();CHECK(info.decision==DMG_PROVEN_FALSE&&info.reason==DMG_AMBIGUOUS);
        q.max_results=1;info=run();CHECK(info.execution_status==DMG_BUDGET_EXCEEDED&&info.coverage==DMG_COVERAGE_PARTIAL&&info.decision==DMG_UNDETERMINED);
        q.max_results=8;q.flags_contains=0x8;info=run();CHECK(info.candidates_count==1&&info.decision==DMG_PROVEN_TRUE);
        q.flags_contains=0x408;info=run();CHECK(info.candidates_count==0&&info.reason==DMG_NO_MATCH);
        q.flags_contains=0;q.intent=DMG_EXISTS;info=run();CHECK(info.decision==DMG_PROVEN_TRUE&&info.candidates_count==1);
        q.intent=DMG_ENUMERATE;uint16_t locate[]={ 'l','o','c','a','t','e' };q.name_enabled=1;q.name=locate;q.name_length=6;
        info=run();CHECK(info.candidates_count==1&&info.coverage==DMG_COVERAGE_COMPLETE);
        dmg_snapshot_close(s);dmg_result* rejected=nullptr;CHECK(dmg_query_methods(s,&q,&rejected,&error)==DMG_CLOSED);dmg_snapshot_release(s);
        options.expected_sha256="incorrect";CHECK(dmg_snapshot_open_copy(bytes.data(),bytes.size(),&options,&s,&error)==DMG_SOURCE_MISMATCH&&s==nullptr);
        options.expected_sha256=nullptr;options.max_source_bytes=bytes.size()-1;
        CHECK(dmg_snapshot_open_copy(bytes.data(),bytes.size(),&options,&s,&error)==DMG_BUDGET_EXCEEDED&&s==nullptr);options.max_source_bytes=DMG_MAX_SOURCE_BYTES;
        std::cout << "checking all truncated prefixes\n";
        for(size_t n=0;n<bytes.size();++n){
            auto status=dmg_snapshot_open_copy(bytes.data(),n,&options,&s,&error);
            CHECK(status!=DMG_OK && s==nullptr);
        }
        std::cout << "core behavior checks passed\n";
#ifdef DMG_TEST_ALLOC_FAILURES
        std::cout << "checking allocation failure boundaries (dedicated fault target)\n";
        unsigned failed=0,success=0;
        for(int n=0;n<160;++n){
            active_fault_index=n;
            allocation_countdown=n;
            const auto status=dmg_snapshot_open_copy(bytes.data(),bytes.size(),&options,&s,&error);
            allocation_countdown=-1;
            CHECK(status==DMG_OUT_OF_MEMORY||status==DMG_OK);
            if(status==DMG_OK){++success;dmg_snapshot_release(s);}else{++failed;CHECK(s==nullptr);}
        }
        CHECK(failed>0&&success>0);
        std::cout<<"PASS native: SHA-256 vectors, identities, query cardinality/flags, ownership, "<<bytes.size()<<" truncations, "<<failed<<" allocation failures, "<<success<<" successful fault-loop opens\n";
        dmg_engine* engine=nullptr;CHECK(dmg_engine_create(nullptr,&engine,&error)==DMG_OK);
        dmg_engine_stats baseline{};CHECK(dmg_engine_get_stats(engine,&baseline)==DMG_OK);
        unsigned pmr_failed=0,pmr_success=0;
        for(int n=0;n<160;++n){
            dexmeguviz::test_fail_allocation_after(n);
            const auto status=dmg_snapshot_open_copy_in(engine,bytes.data(),bytes.size(),&options,&s,&error);
            dexmeguviz::test_fail_allocation_after(-1);
            CHECK(status==DMG_OUT_OF_MEMORY||status==DMG_OK);
            if(status==DMG_OK){++pmr_success;dmg_snapshot_release(s);}else{++pmr_failed;CHECK(s==nullptr);}
            dmg_engine_stats current{};CHECK(dmg_engine_get_stats(engine,&current)==DMG_OK);
            CHECK(current.owned_bytes==baseline.owned_bytes&&current.borrowed_bytes==0);
        }
        dmg_engine_release(engine);CHECK(pmr_failed>10&&pmr_success>0);
        std::cout<<"PASS PMR injection: "<<pmr_failed<<" failing allocation positions, "<<pmr_success<<" successful opens; exact baseline restored each time\n";
#else
        std::cout<<"PASS native: SHA-256 vectors, identities, query cardinality/flags, ownership, "<<bytes.size()<<" truncated prefixes; allocation faults run in the separate fault target\n";
#endif
        return 0;
    }catch(const std::exception& e){allocation_countdown=-1;std::cerr<<e.what()<<'\n';return 1;}
}
