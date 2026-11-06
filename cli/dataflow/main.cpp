#include "analysis/dataflow/dataflow.hpp"
#include <charconv>
#include <filesystem>
#include <fstream>
#include <iostream>

namespace {
class BoundedMemory final:public std::pmr::memory_resource {
    size_t used=0;static constexpr size_t limit=256u<<20;
    void* do_allocate(size_t bytes,size_t alignment)override{if(bytes>limit-used)throw std::bad_alloc{};auto p=std::pmr::new_delete_resource()->allocate(bytes,alignment);used+=bytes;return p;}
    void do_deallocate(void* p,size_t bytes,size_t alignment)override{std::pmr::new_delete_resource()->deallocate(p,bytes,alignment);used-=bytes;}
    bool do_is_equal(const std::pmr::memory_resource& r)const noexcept override{return this==&r;}
};
int run(const std::vector<std::filesystem::path>& args){
    if(args.size()<3||args.size()>6)throw std::runtime_error("usage: dexmeguviz_dataflow INPUT.dex ORDINAL [--conservative] [--opaque-invokes] [--exceptions]");
    const auto index=args[2].string();uint32_t ordinal=0;const auto parsed=std::from_chars(index.data(),index.data()+index.size(),ordinal);if(parsed.ec!=std::errc{}||parsed.ptr!=index.data()+index.size())throw std::runtime_error("invalid method ordinal");
    dexmeguviz::analysis::dataflow::Options options;options.max_uses=100000;
    for(size_t i=3;i<args.size();++i){const auto arg=args[i].string();if(arg=="--conservative")options.allow_conservative_registers=true;else if(arg=="--opaque-invokes")options.allow_opaque_invokes=true;else if(arg=="--exceptions")options.include_exception_edges=true;else throw std::runtime_error("unknown option");}
    const auto size=std::filesystem::file_size(args[1]);if(size>64u<<20)throw std::runtime_error("DEX input limit");std::vector<uint8_t> bytes(static_cast<size_t>(size));std::ifstream f(args[1],std::ios::binary);f.read(reinterpret_cast<char*>(bytes.data()),static_cast<std::streamsize>(bytes.size()));if(f.gcount()!=static_cast<std::streamsize>(bytes.size())||f.peek()!=std::char_traits<char>::eof())throw std::runtime_error("DEX read failed or changed");
    BoundedMemory memory;const auto metadata=dexmeguviz::read_metadata(bytes,&memory);const auto result=dexmeguviz::analysis::dataflow::analyze(bytes,metadata,ordinal,options,&memory);
    std::cout<<"{\"profile\":\"register-words-conservative-v1\",\"has_body\":"<<(result.has_body?"true":"false")<<",\"method_ordinal\":"<<ordinal<<",\"registers\":"<<result.registers<<",\"conservative_registers\":"<<(options.allow_conservative_registers?"true":"false")<<",\"opaque_invokes\":"<<(options.allow_opaque_invokes?"true":"false")<<",\"exception_edges_included\":"<<(result.exception_edges_included?"true":"false")<<",\"analysis_work\":"<<result.analysis_work<<",\"assumptions\":[\"register words, not runtime types\",\"no heap or alias model\",\"all structural paths retained\",\"handlers merge every instruction boundary\",\"unmodeled values are Unknown\"],\"uses\":[";
    bool comma=false;for(const auto& use:result.uses){if(comma)std::cout<<',';comma=true;std::cout<<"{\"pc\":"<<use.pc<<",\"register\":"<<use.register_index<<",\"operand\":"<<use.operand_index<<",\"definition_pc\":";if(use.definition_pc==UINT32_MAX)std::cout<<"null";else std::cout<<use.definition_pc;std::cout<<",\"constant_bits\":";if(use.constant_known)std::cout<<use.constant_bits;else std::cout<<"null";std::cout<<'}';}std::cout<<"]}\n";return 0;
}
}
#ifdef _WIN32
int wmain(int argc,wchar_t** argv){try{std::vector<std::filesystem::path> args;for(int i=0;i<argc;++i)args.emplace_back(argv[i]);return run(args);}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 2;}}
#else
int main(int argc,char** argv){try{std::vector<std::filesystem::path> args;for(int i=0;i<argc;++i)args.emplace_back(argv[i]);return run(args);}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 2;}}
#endif
