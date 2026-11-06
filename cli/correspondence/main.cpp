#include "analysis/correspondence/correspondence.hpp"
#include "execution/budget/account.hpp"
#include "source/sha256.hpp"
#include <charconv>
#include <fstream>
#include <iostream>

using namespace dexmeguviz;
namespace corr=dexmeguviz::analysis::correspondence;
std::pmr::vector<uint8_t> read(const char* path,std::pmr::memory_resource* memory){
    std::ifstream in(path,std::ios::binary|std::ios::ate);if(!in)throw std::runtime_error("cannot open input");
    const auto length=in.tellg();if(length<0||length>64*1024*1024)throw std::length_error("raw DEX input exceeds 64 MiB");
    std::pmr::vector<uint8_t> bytes(static_cast<size_t>(length),memory);in.seekg(0);if(!in.read(reinterpret_cast<char*>(bytes.data()),length))throw std::runtime_error("input read failed");return bytes;
}
int main(int argc,char** argv){
    try{
        if(argc!=4)throw std::invalid_argument("usage: dexmeguviz-correspondence reference.dex method-ordinal candidates.dex");
        uint32_t ordinal=0;const std::string_view argument(argv[2]);const auto parsed=std::from_chars(argument.data(),argument.data()+argument.size(),ordinal);if(parsed.ec!=std::errc{}||parsed.ptr!=argument.data()+argument.size())throw std::invalid_argument("invalid method ordinal");
        Account account(512ull*1024*1024,0);AccountResource memory(account,MemoryKind::scratch);
        const auto old_bytes=read(argv[1],&memory),new_bytes=read(argv[3],&memory);
        const auto old_facts=read_metadata(old_bytes,&memory),new_facts=read_metadata(new_bytes,&memory);
        if(new_facts.methods.size()>100000)throw std::length_error("candidate method count");
        const auto reference=corr::summarize(old_bytes,old_facts,ordinal,{},&memory);
        std::pmr::vector<corr::Summary> summaries(&memory);summaries.reserve(new_facts.methods.size());
        corr::Options options;uint64_t tokens=16'000'000,decode=64'000'000,graph=64'000'000,summary=64'000'000;
        for(uint32_t i=0;i<new_facts.methods.size();++i){options.max_tokens=static_cast<uint32_t>(std::min<uint64_t>(2'000'000,tokens));options.max_decode_work=std::min<uint64_t>(2'000'000,decode);options.max_graph_work=std::min<uint64_t>(8'000'000,graph);options.max_summary_work=std::min<uint64_t>(8'000'000,summary);auto item=corr::summarize(new_bytes,new_facts,i,options,&memory);tokens-=item.tokens.size();decode-=item.decode_work;graph-=item.graph_work;summary-=item.summary_work;summaries.push_back(std::move(item));}
        std::pmr::vector<corr::Candidate> candidates(&memory);for(uint32_t i=0;i<summaries.size();++i)candidates.push_back({0,i,&summaries[i]});
        const auto ordered=corr::rank(reference,candidates,100000,64'000'000,nullptr,nullptr,&memory);
        // Compute everything before writing a candidate; any failure emits no
        // successful partial JSON result. Output is static ranking only.
        const auto old_hash=sha256(old_bytes),new_hash=sha256(new_bytes);
        std::cout<<"{\"schema_version\":1,\"model\":\"register-structure-v1\",\"acceptance_proven\":false,\"reference_sha256\":\""<<old_hash<<"\",\"candidate_sha256\":\""<<new_hash<<"\",\"reference_method\":"<<ordinal<<",\"reference_digest\":\""<<reference.digest<<"\",\"candidates\":[";
        bool first=true;for(const auto& row:ordered){if(!first)std::cout<<',';first=false;const auto& item=summaries[row.method_ordinal];std::cout<<"{\"method_ordinal\":"<<row.method_ordinal<<",\"score\":"<<row.score<<",\"normalized_sequence\":"<<row.normalized_sequence<<",\"opcode_overlap\":"<<row.opcode_overlap<<",\"edge_overlap\":"<<row.edge_overlap<<",\"prototype_match\":"<<row.prototype_match<<",\"ordinary_flow_complete\":"<<(item.ordinary_flow_complete?"true":"false")<<",\"digest\":\""<<item.digest<<"\"}";}
        std::cout<<"]}\n";return std::cout?0:3;
    }catch(const std::exception& error){std::cerr<<"correspondence: "<<error.what()<<'\n';return 2;}
}
