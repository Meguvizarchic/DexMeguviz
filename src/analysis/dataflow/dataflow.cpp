#include "dataflow.hpp"
#include <bit>
#include <deque>
#include <limits>
#include <stdexcept>

namespace dexmeguviz::analysis::dataflow {
namespace {
using namespace instructions;
[[noreturn]] void fail(const DecodeInput& input, DecodeCode code, uint32_t pc, const char* message) {
    throw DecodeError(code,uint64_t(input.code_offset)+16+uint64_t(pc)*2,pc,message);
}
uint32_t narrow(size_t n) {
    if(n>UINT32_MAX)throw std::length_error("metadata reference table exceeds uint32");
    return static_cast<uint32_t>(n);
}
struct Cell { uint32_t bits=0, definition=no_single_definition; bool known=false; };
bool merge(Cell& target,const Cell& incoming) {
    bool changed=false;
    if(target.known&&(!incoming.known||target.bits!=incoming.bits)){target.known=false;target.bits=0;changed=true;}
    if(target.definition!=no_single_definition&&target.definition!=incoming.definition){target.definition=no_single_definition;changed=true;}
    return changed;
}
Cell arithmetic(unsigned operation,Cell left,Cell right,uint32_t pc) {
    Cell out;out.definition=pc;
    if(!left.known||!right.known)return out;
    const uint32_t a=left.bits,b=right.bits;uint32_t value=0;
    switch(operation){
    case 0:value=a+b;break;
    case 1:value=a-b;break;
    case 2:value=uint32_t(uint64_t(a)*uint64_t(b));break;
    case 3:case 4:{
        const int64_t x=std::bit_cast<int32_t>(a),y=std::bit_cast<int32_t>(b);
        if(y==0)return out;
        value=uint32_t(operation==3?x/y:x%y);break;
    }
    case 5:value=a&b;break;case 6:value=a|b;break;case 7:value=a^b;break;
    case 8:value=a<<(b&31u);break;
    case 9:{const uint32_t n=b&31u;value=n?(a>>n)|((a&0x80000000u)?(UINT32_MAX<<(32u-n)):0u):a;break;}
    case 10:value=a>>(b&31u);break;
    default:throw std::logic_error("invalid integer operation");
    }
    out.known=true;out.bits=value;return out;
}
}

Result analyze_checked(const DecodeInput& input,const Options& options,std::pmr::memory_resource* resource) {
    if(!resource)throw std::invalid_argument("dataflow memory resource is null");
    if(options.include_exception_edges&&!options.allow_conservative_registers)fail(input,DecodeCode::unsupported,0,"exception dataflow requires conservative register mode");
    cfg::Options graph_options;graph_options.max_decode_work=options.max_decode_work;graph_options.max_graph_work=options.max_graph_work;
    graph_options.include_exception_edges=options.include_exception_edges;
    graph_options.cancelled=options.cancelled;graph_options.cancel_context=options.cancel_context;
    auto graph=cfg::build_checked(input,graph_options,resource);
    if(!graph.reachable_flow_complete)fail(input,DecodeCode::unsupported,0,"dataflow requires complete ordinary flow");
    DecodeOptions decode_options;decode_options.max_validation_work=options.max_decode_work-graph.decode_work;
    decode_options.cancelled=options.cancelled;decode_options.cancel_context=options.cancel_context;
    auto decoded=decode(input,decode_options,resource);
    Result result(resource);result.has_body=true;result.conservative_registers=options.allow_conservative_registers;result.exception_edges_included=graph.exception_edges_included;result.decode_work=graph.decode_work+decoded.validation_work;result.graph_work=graph.graph_work;
    const uint64_t header=input.code_offset;
    result.registers=uint32_t(input.dex[header])|(uint32_t(input.dex[header+1])<<8);
    const uint64_t cells=uint64_t(result.registers)*graph.blocks.size();
    const uint64_t temporary_cells=graph.exception_edges_included?uint64_t(result.registers)*2:0;
    if(cells>options.max_state_cells||temporary_cells>options.max_state_cells-cells||cells>std::numeric_limits<size_t>::max())fail(input,DecodeCode::budget,0,"dataflow state cell limit exceeded");
    auto cancel=[&](uint32_t pc){if(options.cancelled&&options.cancelled(options.cancel_context))fail(input,DecodeCode::cancelled,pc,"dataflow cancelled");};
    auto charge=[&](uint64_t n,uint32_t pc){if(n>options.max_analysis_work-result.analysis_work)fail(input,DecodeCode::budget,pc,"dataflow work limit exceeded");result.analysis_work+=n;};
    charge(cells+decoded.code_units,0);
    std::pmr::vector<Cell> states(static_cast<size_t>(cells),Cell{},resource);
    std::pmr::vector<uint8_t> seen(graph.blocks.size(),0,resource),queued(graph.blocks.size(),0,resource);
    std::pmr::vector<uint32_t> index(decoded.code_units,cfg::no_target,resource);
    for(uint32_t i=0;i<decoded.instructions.size();++i)index[decoded.instructions[i].pc]=i;
    std::pmr::deque<uint32_t> queue(resource);seen[0]=1;queued[0]=1;queue.push_back(0);
    const uint64_t start=uint64_t(input.code_offset)+16;
    auto word=[&](uint32_t pc)->uint16_t {const uint64_t p=start+uint64_t(pc)*2;return uint16_t(input.dex[p])|(uint16_t(input.dex[p+1])<<8);};
    auto process=[&](uint32_t block_index,std::pmr::vector<Cell>& values,bool collect,std::pmr::vector<Cell>* exceptional=nullptr){
        const auto& block=graph.blocks[block_index];
        uint32_t ins=index[block.start_pc];
        while(ins<decoded.instructions.size()&&decoded.instructions[ins].pc<block.end_pc){
            const auto& item=decoded.instructions[ins++];const auto pc=item.pc;const auto op=item.opcode;const uint16_t w=word(pc);
            cancel(pc);charge(1,pc);
            auto use=[&](uint32_t reg,uint32_t operand)->Cell {
                if(reg>=values.size())fail(input,DecodeCode::corrupt,pc,"dataflow register exceeds checked register count");
                const auto value=values[reg];
                if(collect){
                    charge(1,pc);if(result.uses.size()>=options.max_uses)fail(input,DecodeCode::budget,pc,"dataflow use limit exceeded");
                    result.uses.push_back({pc,reg,operand,value.definition,value.bits,value.known});
                }
                return value;
            };
            auto write=[&](uint32_t reg,Cell value){if(reg>=values.size())fail(input,DecodeCode::corrupt,pc,"dataflow destination exceeds checked register count");value.definition=pc;values[reg]=value;};
            auto transfer=[&](){
            const uint32_t aa=w>>8,a=(w>>8)&15u,b=(w>>12)&15u;
            if(op==0x00||op==0x0e||(op>=0x28&&op<=0x2a))return;
            if((op>=0x6e&&op<=0x72)||(op>=0x74&&op<=0x78)||(op>=0xfa&&op<=0xfd)){
                if(!options.allow_opaque_invokes)fail(input,DecodeCode::unsupported,pc,"opaque invokes require explicit opt-in");
                const bool range=(op>=0x74&&op<=0x78)||op==0xfb||op==0xfd;
                const uint32_t count=range?aa:b;
                if(range){
                    const uint32_t first=word(pc+2);
                    for(uint32_t i=0;i<count;++i){cancel(pc);charge(1,pc);(void)use(first+i,i);}
                }else{
                    const uint16_t packed=word(pc+2);
                    const uint32_t regs[5]={uint32_t(packed&15u),uint32_t((packed>>4)&15u),uint32_t((packed>>8)&15u),uint32_t(packed>>12),a};
                    for(uint32_t i=0;i<count;++i){cancel(pc);charge(1,pc);(void)use(regs[i],i);}
                }
                return;
            }
            if(op>=0x0a&&op<=0x0c){
                if(!options.allow_opaque_invokes&&!options.allow_conservative_registers)fail(input,DecodeCode::unsupported,pc,"opaque results require explicit opt-in");
                write(aa,Cell{});if(op==0x0b)write(aa+1,Cell{});return;
            }
            if(op==0x0f||op==0x2b||op==0x2c||(op>=0x38&&op<=0x3d)){(void)use(aa,0);return;}
            if(op>=0x32&&op<=0x37){(void)use(a,0);(void)use(b,1);return;}
            if(op==0x01){write(a,use(b,0));return;}
            if(op==0x02){write(aa,use(word(pc+1),0));return;}
            if(op==0x03){write(word(pc+1),use(word(pc+2),0));return;}
            if(op==0x12){const int32_t v=(b&8u)?int32_t(b)-16:int32_t(b);write(a,Cell{uint32_t(v),pc,true});return;}
            if(op==0x13){write(aa,Cell{uint32_t(std::bit_cast<int16_t>(word(pc+1))),pc,true});return;}
            if(op==0x14){const uint32_t bits=uint32_t(word(pc+1))|(uint32_t(word(pc+2))<<16);write(aa,Cell{bits,pc,true});return;}
            if(op==0x15){write(aa,Cell{uint32_t(word(pc+1))<<16,pc,true});return;}
            if(op>=0x90&&op<=0x9a){const auto operands=word(pc+1);const Cell left=use(operands&255u,0),right=use(operands>>8,1);write(aa,arithmetic(op-0x90,left,right,pc));return;}
            if(op>=0xb0&&op<=0xba){const Cell left=use(a,0),right=use(b,1);write(a,arithmetic(op-0xb0,left,right,pc));return;}
            if(op>=0xd0&&op<=0xd7){const Cell left=use(b,0),literal{uint32_t(std::bit_cast<int16_t>(word(pc+1))),no_single_definition,true};const unsigned k=op-0xd0;write(a,k==1?arithmetic(1,literal,left,pc):arithmetic(k,left,literal,pc));return;}
            if(op>=0xd8&&op<=0xe2){const uint16_t operands=word(pc+1);const Cell left=use(operands&255u,0),literal{uint32_t(std::bit_cast<int8_t>(uint8_t(operands>>8))),no_single_definition,true};const unsigned k=op-0xd8;write(aa,k==1?arithmetic(1,literal,left,pc):arithmetic(k,left,literal,pc));return;}
            if(options.allow_conservative_registers){
                auto words=[&](uint32_t reg,uint32_t count,uint32_t first){for(uint32_t i=0;i<count;++i)(void)use(reg+i,first+i);};
                auto unknown=[&](uint32_t reg,uint32_t count){for(uint32_t i=0;i<count;++i)write(reg+i,Cell{});};
                if(op>=0x04&&op<=0x09){
                    const bool wide=op<=0x06;const auto form=wide?op-0x04:op-0x07;
                    const uint32_t dest=form==0?a:form==1?aa:word(pc+1),source=form==0?b:form==1?word(pc+1):word(pc+2);
                    const auto low=use(source,0);Cell high;if(wide)high=use(source+1,1);write(dest,low);if(wide)write(dest+1,high);return;
                }
                if(op==0x0d){write(aa,Cell{});return;}
                if(op==0x10||op==0x11){words(aa,op==0x10?2:1,0);return;}
                if(op>=0x16&&op<=0x19){
                    uint64_t bits=0;
                    if(op==0x16)bits=static_cast<uint64_t>(static_cast<int64_t>(std::bit_cast<int16_t>(word(pc+1))));
                    else if(op==0x17){const uint32_t value=uint32_t(word(pc+1))|(uint32_t(word(pc+2))<<16);bits=static_cast<uint64_t>(static_cast<int64_t>(std::bit_cast<int32_t>(value)));}
                    else if(op==0x18)bits=uint64_t(word(pc+1))|(uint64_t(word(pc+2))<<16)|(uint64_t(word(pc+3))<<32)|(uint64_t(word(pc+4))<<48);
                    else bits=uint64_t(word(pc+1))<<48;
                    write(aa,Cell{static_cast<uint32_t>(bits),pc,true});write(aa+1,Cell{static_cast<uint32_t>(bits>>32),pc,true});return;
                }
                if(op==0x1a||op==0x1b||op==0x1c||op==0x22||op==0xfe||op==0xff){unknown(aa,1);return;}
                if(op==0x1d||op==0x1e||op==0x1f||op==0x26||op==0x27){words(aa,1,0);return;}
                if(op==0x20||op==0x21||op==0x23){words(b,1,0);unknown(a,1);return;}
                if(op==0x24||op==0x25){
                    const bool range=op==0x25;const uint32_t count=range?aa:b;
                    if(range){const uint32_t first=word(pc+2);for(uint32_t i=0;i<count;++i){cancel(pc);charge(1,pc);(void)use(first+i,i);}}
                    else{const auto packed=word(pc+2);const uint32_t regs[5]={uint32_t(packed&15u),uint32_t((packed>>4)&15u),uint32_t((packed>>8)&15u),uint32_t(packed>>12),a};for(uint32_t i=0;i<count;++i)(void)use(regs[i],i);}return;
                }
                if(op>=0x2d&&op<=0x31){const auto operands=word(pc+1);const uint32_t width=op<=0x2e?1:2;words(operands&255u,width,0);words(operands>>8,width,width);unknown(aa,1);return;}
                if(op>=0x44&&op<=0x51){
                    const auto operands=word(pc+1);const bool put=op>=0x4b,wide=op==0x45||op==0x4c;
                    uint32_t operand=0;if(put){words(aa,wide?2:1,operand);operand+=wide?2:1;}
                    words(operands&255u,1,operand++);words(operands>>8,1,operand);if(!put)unknown(aa,wide?2:1);return;
                }
                if(op>=0x52&&op<=0x6d){
                    const bool instance=op<=0x5f,put=instance?op>=0x59:op>=0x67;
                    const bool wide=op==0x53||op==0x5a||op==0x61||op==0x68;const uint32_t reg=instance?a:aa;
                    if(put){words(reg,wide?2:1,0);if(instance)words(b,1,wide?2:1);}
                    else{if(instance)words(b,1,0);unknown(reg,wide?2:1);}return;
                }
                if(op>=0x7b&&op<=0x8f){
                    if(op==0x7b||op==0x7c||op>=0x8d){auto value=use(b,0);if(value.known){
                        if(op==0x7b)value.bits=0u-value.bits;else if(op==0x7c)value.bits=~value.bits;
                        else if(op==0x8d)value.bits=static_cast<uint32_t>(static_cast<int32_t>(std::bit_cast<int8_t>(static_cast<uint8_t>(value.bits))));
                        else if(op==0x8e)value.bits&=0xffffu;
                        else value.bits=static_cast<uint32_t>(static_cast<int32_t>(std::bit_cast<int16_t>(static_cast<uint16_t>(value.bits))));
                    }write(a,value);return;}
                    const bool source_wide=op==0x7d||op==0x7e||op==0x80||(op>=0x84&&op<=0x86)||(op>=0x8a&&op<=0x8c);
                    const bool dest_wide=op==0x7d||op==0x7e||op==0x80||op==0x81||op==0x83||op==0x86||op==0x88||op==0x89||op==0x8b;
                    words(b,source_wide?2:1,0);unknown(a,dest_wide?2:1);return;
                }
                if(op>=0x9b&&op<=0xaf){
                    const auto operands=word(pc+1);const bool wide=op<=0xa5||op>=0xab;const uint32_t left_width=wide?2:1,right_width=(op>=0xa3&&op<=0xa5)?1:left_width;
                    words(operands&255u,left_width,0);words(operands>>8,right_width,left_width);unknown(aa,left_width);return;
                }
                if(op>=0xbb&&op<=0xcf){
                    const bool wide=op<=0xc5||op>=0xcb;const uint32_t left_width=wide?2:1,right_width=(op>=0xc3&&op<=0xc5)?1:left_width;
                    words(a,left_width,0);words(b,right_width,left_width);unknown(a,left_width);return;
                }
            }
            fail(input,DecodeCode::unsupported,pc,"dataflow instruction is not modeled");
            };
            transfer();
            if(exceptional){
                // Join entry and every instruction boundary. This deliberately
                // overapproximates throw points and never substitutes block end.
                for(uint32_t reg=0;reg<result.registers;++reg){charge(1,pc);merge((*exceptional)[reg],values[reg]);}
            }
        }
    };
    while(!queue.empty()){
        const uint32_t block=queue.front();queue.pop_front();queued[block]=0;cancel(graph.blocks[block].start_pc);
        const size_t offset=size_t(block)*result.registers;
        std::pmr::vector<Cell> values(resource);values.reserve(result.registers);
        for(uint32_t r=0;r<result.registers;++r)values.push_back(states[offset+r]);
        const auto& node=graph.blocks[block];bool handlers=false;
        for(uint32_t e=0;e<node.edge_count;++e)if(graph.edges[node.first_edge+e].kind==cfg::EdgeKind::exception_handler)handlers=true;
        std::pmr::vector<Cell> exceptional(resource);if(handlers){charge(result.registers,node.start_pc);exceptional=values;}
        charge(result.registers,graph.blocks[block].start_pc);process(block,values,false,handlers?&exceptional:nullptr);
        for(uint32_t e=0;e<node.edge_count;++e){
            charge(1,node.last_pc);
            const auto& edge=graph.edges[node.first_edge+e];const auto dest=edge.to_block;
            const auto& outgoing=edge.kind==cfg::EdgeKind::exception_handler?exceptional:values;
            if(dest==cfg::no_target)fail(input,DecodeCode::unsupported,node.last_pc,"dataflow requires a complete CFG");
            bool changed=false;const size_t target=size_t(dest)*result.registers;
            for(uint32_t r=0;r<result.registers;++r){charge(1,node.last_pc);if(!seen[dest])states[target+r]=outgoing[r];else changed=merge(states[target+r],outgoing[r])||changed;}
            if(!seen[dest]){seen[dest]=1;changed=true;}
            if(changed&&!queued[dest]){queued[dest]=1;queue.push_back(dest);}
        }
    }
    for(uint32_t block=0;block<graph.blocks.size();++block){
        if(!seen[block])continue;const size_t offset=size_t(block)*result.registers;
        std::pmr::vector<Cell> values(resource);values.reserve(result.registers);
        for(uint32_t r=0;r<result.registers;++r)values.push_back(states[offset+r]);
        charge(result.registers,graph.blocks[block].start_pc);process(block,values,true);
    }
    return result;
}

Result analyze(std::span<const uint8_t> dex,const Facts& metadata,uint32_t ordinal,const Options& options,std::pmr::memory_resource* resource) {
    if(!resource)throw std::invalid_argument("dataflow memory resource is null");
    if(ordinal>=metadata.methods.size())throw std::out_of_range("method ordinal exceeds definition directory");
    const auto& method=metadata.methods[ordinal];if(!method.code_offset)return Result(resource);
    const DecodeInput input{dex,method.code_offset,metadata.dex_version,
        {narrow(metadata.strings.size()),narrow(metadata.types.size()),narrow(metadata.field_refs.size()),narrow(metadata.method_refs.size()),
         narrow(metadata.prototypes.size()),metadata.call_site_count,metadata.method_handle_count},method.code_end};
    return analyze_checked(input,options,resource);
}
}
