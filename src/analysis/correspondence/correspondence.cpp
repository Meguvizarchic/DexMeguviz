#include "correspondence.hpp"
#include "source/sha256.hpp"
#include <algorithm>
#include <bit>
#include <limits>

namespace dexmeguviz::analysis::correspondence {
namespace {
using namespace instructions;
uint32_t narrow(size_t n){if(n>UINT32_MAX)throw std::length_error("reference directory too large");return static_cast<uint32_t>(n);}
bool between(uint8_t op,unsigned lo,unsigned hi){return op>=lo&&op<=hi;}
uint8_t canonical_opcode(uint8_t op){
    if(between(op,1,3))return 1;if(between(op,4,6))return 4;if(between(op,7,9))return 7;
    if(between(op,0x12,0x15))return 0x12;if(between(op,0x16,0x19))return 0x16;
    if(op==0x1b)return 0x1a;if(between(op,0x28,0x2a))return 0x28;
    if(op==0x25)return 0x24;if(between(op,0x74,0x78))return op-6;
    if(op==0xfb)return 0xfa;if(op==0xfd)return 0xfc;return op;
}
}
Summary summarize(std::span<const uint8_t> dex,const Facts& facts,uint32_t ordinal,const Options& options,std::pmr::memory_resource* memory){
    if(!memory)throw std::invalid_argument("null summary resource");
    if(ordinal>=facts.methods.size())throw std::out_of_range("method ordinal");
    Summary out(memory);const auto& method=facts.methods[ordinal];out.method_ordinal=ordinal;out.code_offset=method.code_offset;out.prototype=method.prototype;
    if(!method.code_offset)return out;
    DecodeInput input{dex,method.code_offset,facts.dex_version,{narrow(facts.strings.size()),narrow(facts.types.size()),narrow(facts.field_refs.size()),narrow(facts.method_refs.size()),narrow(facts.prototypes.size()),facts.call_site_count,facts.method_handle_count},method.code_end};
    cfg::Options graph_options;graph_options.include_exception_edges=true;graph_options.max_decode_work=options.max_decode_work;graph_options.max_graph_work=options.max_graph_work;graph_options.cancelled=options.cancelled;graph_options.cancel_context=options.cancel_context;
    const auto graph=cfg::build_checked(input,graph_options,memory);
    DecodeOptions decode_options;decode_options.demand_mask=Demand::numeric;decode_options.max_validation_work=options.max_decode_work-graph.decode_work;decode_options.cancelled=options.cancelled;decode_options.cancel_context=options.cancel_context;
    const auto decoded=decode(input,decode_options,memory);
    out.has_body=true;out.ordinary_flow_complete=graph.reachable_flow_complete;out.exception_regions=graph.has_exception_regions;
    out.decode_work=graph.decode_work+decoded.validation_work;out.graph_work=graph.graph_work;out.blocks=narrow(graph.blocks.size());out.edges=narrow(graph.edges.size());
    auto fail=[&](DecodeCode code,const char* message){throw DecodeError(code,method.code_offset,0,message);};
    auto charge=[&](uint64_t amount){if(options.cancelled&&options.cancelled(options.cancel_context))fail(DecodeCode::cancelled,"summary cancelled");if(amount>options.max_summary_work-out.summary_work)fail(DecodeCode::budget,"summary work limit");out.summary_work+=amount;};
    auto token=[&](uint32_t v){charge(1);if(out.tokens.size()>=options.max_tokens)fail(DecodeCode::budget,"summary token limit");out.tokens.push_back(v);};
    auto word=[&](uint32_t pc){const uint64_t at=uint64_t(method.code_offset)+16+uint64_t(pc)*2;if(at>dex.size()||dex.size()-at<2)fail(DecodeCode::corrupt,"instruction byte bound");return uint16_t(dex[at])|(uint16_t(dex[at+1])<<8);};
    const uint32_t registers=uint32_t(dex[method.code_offset])|(uint32_t(dex[method.code_offset+1])<<8),incoming=uint32_t(dex[method.code_offset+2])|(uint32_t(dex[method.code_offset+3])<<8);
    charge(registers);std::pmr::vector<uint32_t> names(registers,UINT32_MAX,memory);uint32_t next=incoming;
    for(uint32_t i=0;i<incoming;++i)names[registers-incoming+i]=i;
    token(Summary::version);token(incoming);token(out.blocks);token(out.edges);
    size_t block=0,literal=0;
    for(const auto& ins:decoded.instructions){
        charge(1);if(ins.payload_kind!=PayloadKind::none)continue;
        while(block<graph.blocks.size()&&graph.blocks[block].start_pc==ins.pc){token(0xffff0001u);token(narrow(block++));}
        const uint8_t op=ins.opcode;const uint32_t first=word(ins.pc),a8=first>>8,a=a8&15,b=a8>>4;const auto normalized=canonical_opcode(op);++out.instructions;++out.opcodes[normalized];token(0xffff0002u);token(normalized);
        auto reg=[&](uint32_t index,bool wide=false){const uint32_t count=wide?2:1;if(index>=registers||count>registers-index)fail(DecodeCode::corrupt,"register normalization bound");token(count);for(uint32_t i=0;i<count;++i){if(names[index+i]==UINT32_MAX)names[index+i]=next++;token(names[index+i]);}};
        if(op==1||op==4||op==7||op==0x21||between(op,0x7b,0x8f)||between(op,0xb0,0xcf)){
            bool aw=op==4,bw=op==4;
            if(between(op,0x7b,0x8f)){aw=op==0x7d||op==0x7e||op==0x80||op==0x81||op==0x83||op==0x86||op==0x88||op==0x89||op==0x8b;bw=op==0x7d||op==0x7e||op==0x80||between(op,0x84,0x86)||between(op,0x8a,0x8c);}
            if(between(op,0xb0,0xcf)){aw=between(op,0xbb,0xc5)||between(op,0xcb,0xcf);bw=between(op,0xbb,0xc2)||between(op,0xcb,0xcf);}reg(a,aw);reg(b,bw);
        }else if(op==2||op==5||op==8){reg(a8,op==5);reg(word(ins.pc+1),op==5);}
        else if(op==3||op==6||op==9){reg(word(ins.pc+1),op==6);reg(word(ins.pc+2),op==6);}
        else if(op==0x12)reg(a);
        else if(op==0x20||op==0x23||between(op,0x32,0x37)||between(op,0x52,0x5f)||between(op,0xd0,0xd7)){reg(a,op==0x53||op==0x5a);reg(b);}
        else if(between(op,0x2d,0x31)||between(op,0x44,0x51)||between(op,0x90,0xaf)){
            bool aw=op==0x45||op==0x4c,bw=between(op,0x2f,0x31),cw=bw;
            if(between(op,0x90,0xaf)){aw=bw=between(op,0x9b,0xa5)||between(op,0xab,0xaf);cw=between(op,0x9b,0xa2)||between(op,0xab,0xaf);}const auto operands=word(ins.pc+1);reg(a8,aw);reg(operands&255,bw);reg(operands>>8,cw);
        }else if(between(op,0xd8,0xe2)){reg(a8);reg(word(ins.pc+1)&255);}
        else if(op==0x24||op==0x25||between(op,0x6e,0x72)||between(op,0x74,0x78)||between(op,0xfa,0xfd)){
            const bool range=op==0x25||between(op,0x74,0x78)||op==0xfb||op==0xfd;const uint32_t count=range?a8:b;token(count);
            if(range){const auto begin=word(ins.pc+2);for(uint32_t i=0;i<count;++i)reg(begin+i);}
            else{const auto packed=word(ins.pc+2);const std::array<uint32_t,5> args{uint32_t(packed&15),uint32_t((packed>>4)&15),uint32_t((packed>>8)&15),uint32_t(packed>>12),a};for(uint32_t i=0;i<count;++i)reg(args[i]);}
        }else if(op!=0&&op!=0x0e&&!between(op,0x28,0x2a))reg(a8,op==0x0b||op==0x10||between(op,0x16,0x19)||op==0x61||op==0x68);
        while(literal<decoded.numeric_literals.size()&&decoded.numeric_literals[literal].pc==ins.pc){const auto& value=decoded.numeric_literals[literal++];token(0xffff0003u);token(value.width_bits);token(uint32_t(value.kind));token(uint32_t(value.bits));token(uint32_t(value.bits>>32));}
        token(0xffff0004u);
    }
    for(const auto& edge:graph.edges){const auto kind=static_cast<uint32_t>(edge.kind);if(kind>=out.edge_kinds.size())fail(DecodeCode::unsupported,"edge model");++out.edge_kinds[kind];token(0xffff0005u);token(edge.from_block);token(edge.to_block);token(kind);token(std::bit_cast<uint32_t>(edge.switch_key));token(edge.catch_type_index==UINT32_MAX?0:1);token(edge.catch_order);}
    std::pmr::vector<uint8_t> bytes(memory);if(out.tokens.size()>SIZE_MAX/4)fail(DecodeCode::budget,"summary byte overflow");charge(out.tokens.size());bytes.reserve(out.tokens.size()*4);
    for(auto value:out.tokens)for(unsigned shift=0;shift<32;shift+=8)bytes.push_back(uint8_t(value>>shift));out.digest=sha256<std::pmr::string>(bytes,memory);return out;
}
std::pmr::vector<Ranked> rank(const Summary& reference,std::span<const Candidate> candidates,uint32_t maximum,uint64_t max_work,bool (*cancelled)(void*)noexcept,void* context,std::pmr::memory_resource* memory){
    if(!memory||!reference.has_body)throw std::invalid_argument("ranking needs a body and memory resource");if(candidates.size()>maximum)throw std::length_error("candidate limit");
    uint64_t work=0;auto charge=[&](uint64_t n){if(cancelled&&cancelled(context))throw DecodeError(DecodeCode::cancelled,0,0,"ranking cancelled");if(n>max_work-work)throw DecodeError(DecodeCode::budget,0,0,"ranking work limit");work+=n;};
    std::pmr::vector<Ranked> out(memory);out.reserve(candidates.size());
    for(const auto& candidate:candidates){charge(1);if(!candidate.summary||candidate.method_ordinal!=candidate.summary->method_ordinal)throw std::invalid_argument("candidate summary identity");const auto& s=*candidate.summary;if(!s.has_body)continue;
        bool same=reference.tokens.size()==s.tokens.size();if(same)for(size_t i=0;i<s.tokens.size();++i){charge(1);if(reference.tokens[i]!=s.tokens[i]){same=false;break;}}
        auto overlap=[&](const auto& a,const auto& b){uint64_t common=0,total=0;for(size_t i=0;i<a.size();++i){charge(1);common+=std::min(a[i],b[i]);total+=std::max(a[i],b[i]);}return total?uint32_t(common*2000/total):2000u;};
        const auto opcode=overlap(reference.opcodes,s.opcodes),edge=overlap(reference.edge_kinds,s.edge_kinds);charge(reference.prototype.size()+s.prototype.size());const uint32_t proto=reference.prototype==s.prototype?500:0,sequence=same?5500:0;
        out.push_back({candidate.source_index,candidate.method_ordinal,sequence+opcode+edge+proto,sequence,opcode,edge,proto,same});
    }
    std::sort(out.begin(),out.end(),[&](const Ranked& a,const Ranked& b){charge(1);if(a.score!=b.score)return a.score>b.score;if(a.source_index!=b.source_index)return a.source_index<b.source_index;return a.method_ordinal<b.method_ordinal;});return out;
}
}
