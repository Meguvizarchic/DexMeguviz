#pragma once
#include <algorithm>
#include <cstdint>
#include <exception>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>
#include "format/instructions/decoder.hpp"
#include "query/reflection_flags.hpp"

// Experimental candidate-only reader. It is not a DEX verifier; caller owns
// immutable bytes and must not infer absence or integrity from this prefilter.
namespace dexmeguviz::fast {
struct LimitError : std::runtime_error { explicit LimitError(const char* message):std::runtime_error(message){} };
struct UnsupportedError : std::runtime_error { explicit UnsupportedError(const char* message):std::runtime_error(message){} };
struct Row { uint32_t ref, flags, declaration, code; auto key() const { return std::tie(ref,flags,declaration,code); } };
struct Table { uint32_t size, offset, width; };
enum class TextOp { any, exact, prefix, contains };
struct TextFilter {
    TextOp op=TextOp::any;
    std::u16string text;
    bool matches(std::u16string_view v) const {
        switch(op) {
        case TextOp::any:return true;
        case TextOp::exact:return v==text;
        case TextOp::prefix:return v.starts_with(text);
        case TextOp::contains:return v.find(text)!=std::u16string_view::npos;
        }
        throw std::invalid_argument("unsupported text matcher");
    }
};
struct MethodFilter {
    TextFilter owner,name,prototype;
    bool return_enabled=false,parameters_enabled=false;
    std::u16string returned;
    std::vector<std::u16string> parameters;
    uint32_t flags_contains=0;
    bool flags_enabled=false,reflection_flags=false;
    uint32_t min_parameters=0,max_parameters=UINT32_MAX;
    size_t max_results=4096;
};
struct InvokePattern {
    TextFilter owner,name,returned;
    // -1 matches method-like references (normal and polymorphic), as QueryIR
    // does by default; 0 normal, 1 call-site, 2 polymorphic, 3 any kind.
    int reference_kind=-1;
    uint32_t min_parameters=0,max_parameters=UINT32_MAX;
    bool parameters_enabled=false;
    std::vector<std::u16string> parameters;
};
struct InvokeWitness { uint32_t pc,index,extra_proto;uint8_t opcode;instructions::ReferenceKind kind; };
struct StringWitness { uint32_t pc,index;uint8_t opcode; };
struct MatchedMethod {
    Row row;
    std::vector<InvokeWitness> witnesses;
    std::vector<StringWitness> string_witnesses;
    std::vector<InvokeWitness> all_invokes;
};
struct MethodDescription { std::u16string owner,name,prototype; };
struct QuerySpec {
    MethodFilter method;
    // AND between groups, OR within each group. Empty group is unsupported.
    std::vector<std::vector<InvokePattern>> invoke_all_any;
    std::vector<std::u16string> strings_all;
    bool capture_invokes=false;
};
struct RuleResult {
    std::vector<MatchedMethod> matches;
    uint64_t unknown_rows=0,visited_methods=0,decoded_methods=0;
    bool result_limit=false;
    std::exception_ptr error;
};
struct MultiResult {
    std::vector<RuleResult> rules;
    // Only the referenced metadata and selected bodies were inspected.
    // This is neither full DEX validation nor a complete source-set proof.
    bool selected_only=true;
};
struct Reader {
    std::span<const uint8_t> b;
    Table strings{}, types{}, protos{}, fields{},methods{}, classes{};
    uint32_t version=0,call_sites=0,method_handles=0;
    explicit Reader(std::span<const uint8_t> bytes):b(bytes) {
        require(0,112);
        if(b[0]!='d'||b[1]!='e'||b[2]!='x'||b[3]!='\n'||b[7]!=0||
           b[4]<'0'||b[4]>'9'||b[5]<'0'||b[5]>'9'||b[6]<'0'||b[6]>'9') fail("invalid DEX magic");
        if(b[4]!='0'||!((b[5]=='3'&&(b[6]=='5'||b[6]=='7'||b[6]=='8'||b[6]=='9'))||(b[5]=='4'&&b[6]=='0')))
            throw UnsupportedError("unsupported DEX version");
        if(u32(32)!=b.size()||u32(36)!=112||u32(40)!=0x12345678) fail("invalid header");
        version=uint32_t(b[4]-'0')*100+uint32_t(b[5]-'0')*10+uint32_t(b[6]-'0');
        strings=table(56,4); types=table(64,4); protos=table(72,12);fields=table(80,8);methods=table(88,8); classes=table(96,32);
        const auto map=u32(52);require(map,4);const auto count=u32(map);require(uint64_t(map)+4,uint64_t(count)*12);
        bool have_calls=false,have_handles=false;
        for(uint32_t i=0;i<count;++i){const auto at=uint64_t(map)+4+uint64_t(i)*12;const auto kind=u16(at);const auto n=u32(at+4),off=u32(at+8);
            if(kind==7){if(have_calls)fail("duplicate call site section");have_calls=true;call_sites=n;require(off,uint64_t(n)*4);}
            if(kind==8){if(have_handles)fail("duplicate method handle section");have_handles=true;method_handles=n;require(off,uint64_t(n)*8);}}
    }
    [[noreturn]] static void fail(const char* message) { throw std::runtime_error(message); }
    void require(uint64_t at,uint64_t n) const { if(at>b.size()||n>b.size()-at)fail("range"); }
    uint16_t u16(uint64_t at) const { require(at,2);return uint16_t(b[at])|uint16_t(uint16_t(b[at+1])<<8); }
    uint32_t u32(uint64_t at) const { require(at,4);return uint32_t(b[at])|(uint32_t(b[at+1])<<8)|(uint32_t(b[at+2])<<16)|(uint32_t(b[at+3])<<24); }
    uint32_t leb(uint64_t& at) const {
        uint32_t v=0;for(unsigned i=0;i<5;++i){require(at,1);uint32_t x=b[at++];if(i==4&&(x&0xf0))fail("uleb overflow");v|=(x&127u)<<(7*i);if(!(x&128))return v;}fail("unterminated uleb");
    }
    Table table(uint64_t header,uint32_t width) const {
        Table t{u32(header),u32(header+4),width};if((t.size==0)!=(t.offset==0))fail("table offset");require(t.offset,uint64_t(t.size)*width);return t;
    }
    std::u16string string(uint32_t index) const {
        if(index>=strings.size)fail("string index");uint64_t cursor=u32(uint64_t(strings.offset)+uint64_t(index)*4);const uint32_t count=leb(cursor);
        if(count>1048576||count>b.size()-cursor)fail("string size");std::u16string out;out.reserve(count);
        for(uint32_t i=0;i<count;++i){require(cursor,1);const uint32_t first=b[cursor++];uint32_t c;
            if(first>=1&&first<=0x7f)c=first;
            else if((first&0xe0)==0xc0){require(cursor,1);const uint32_t second=b[cursor++];if((second&0xc0)!=0x80)fail("mutf continuation");c=((first&31)<<6)|(second&63);if(c<128&&!(first==0xc0&&second==0x80))fail("mutf overlong");}
            else if((first&0xf0)==0xe0){require(cursor,2);const uint32_t second=b[cursor++],third=b[cursor++];if((second&0xc0)!=0x80||(third&0xc0)!=0x80)fail("mutf continuation");c=((first&15)<<12)|((second&63)<<6)|(third&63);if(c<2048)fail("mutf overlong");}
            else fail("mutf lead");out.push_back(static_cast<char16_t>(c));}
        require(cursor,1);if(b[cursor]!=0)fail("mutf terminator");return out;
    }
    uint32_t find_string(std::u16string_view value) const {
        uint32_t lo=0,hi=strings.size;while(lo<hi){uint32_t mid=lo+(hi-lo)/2;auto v=string(mid);if(v<value)lo=mid+1;else hi=mid;}
        return lo<strings.size&&string(lo)==value?lo:UINT32_MAX;
    }
    uint32_t find_type(std::u16string_view value) const {
        const auto string_index=find_string(value);if(string_index==UINT32_MAX)return UINT32_MAX;
        uint32_t lo=0,hi=types.size;while(lo<hi){uint32_t mid=lo+(hi-lo)/2;auto v=u32(uint64_t(types.offset)+uint64_t(mid)*4);if(v<string_index)lo=mid+1;else hi=mid;}
        return lo<types.size&&u32(uint64_t(types.offset)+uint64_t(lo)*4)==string_index?lo:UINT32_MAX;
    }
    std::u16string type_name(uint32_t id) const {if(id>=types.size)fail("type index");return string(u32(uint64_t(types.offset)+uint64_t(id)*4));}
    uint32_t parameter_count(uint32_t proto) const {
        if(proto>=protos.size)fail("prototype index");const auto at=uint64_t(protos.offset)+uint64_t(proto)*12;const auto list=u32(at+8);
        if(!list)return 0;require(list,4);const auto count=u32(list);require(uint64_t(list)+4,uint64_t(count)*2);return count;
    }
    std::u16string prototype_text(uint32_t proto, size_t max_units=1048576) const {
        if(proto>=protos.size)fail("prototype index");const auto at=uint64_t(protos.offset)+uint64_t(proto)*12;const auto list=u32(at+8);const auto count=parameter_count(proto);
        if(max_units<2)throw LimitError("prototype output limit");std::u16string out=u"(";
        const auto append=[&](std::u16string value){if(value.size()>max_units-out.size())throw LimitError("prototype output limit");out+=value;};
        for(uint32_t i=0;i<count;++i)append(type_name(u16(uint64_t(list)+4+uint64_t(i)*2)));
        if(out.size()>=max_units)throw LimitError("prototype output limit");out+=u")";append(type_name(u32(at+4)));return out;
    }
    MethodDescription describe_method(uint32_t ref, size_t max_units=1048576) const {
        if(ref>=methods.size)fail("method index");const auto at=uint64_t(methods.offset)+uint64_t(ref)*8;
        return {type_name(u16(at)),string(u32(at+4)),prototype_text(u16(at+2),max_units)};
    }
    bool invoke_matches(const InvokePattern& pattern,const instructions::InvokeSite& site) const {
        if(pattern.reference_kind < -1||pattern.reference_kind > 3)fail("unsupported reference kind");
        const int kind=site.reference_kind==instructions::ReferenceKind::method?0:site.reference_kind==instructions::ReferenceKind::call_site?1:2;
        if((pattern.reference_kind==-1&&kind==1)||(pattern.reference_kind>=0&&pattern.reference_kind!=3&&kind!=pattern.reference_kind))return false;
        if(kind==1)return pattern.owner.op==TextOp::any&&pattern.name.op==TextOp::any&&pattern.returned.op==TextOp::any&&!pattern.parameters_enabled&&!pattern.min_parameters&&pattern.max_parameters==UINT32_MAX;
        if(site.index>=methods.size)fail("invoked method index");const auto at=uint64_t(methods.offset)+uint64_t(site.index)*8;
        const uint32_t owner=u16(at),proto=u16(at+2),name_index=u32(at+4);if(proto>=protos.size)fail("invoked prototype index");
        if(!pattern.owner.matches(type_name(owner))||!pattern.name.matches(string(name_index)))return false;
        const auto pat=uint64_t(protos.offset)+uint64_t(proto)*12;const auto return_id=u32(pat+4),list=u32(pat+8);
        if(!pattern.returned.matches(type_name(return_id)))return false;const auto count=parameter_count(proto);
        if(count<pattern.min_parameters||count>pattern.max_parameters||(pattern.parameters_enabled&&count!=pattern.parameters.size()))return false;
        if(pattern.parameters_enabled)for(uint32_t i=0;i<count;++i)if(type_name(u16(uint64_t(list)+4+uint64_t(i)*2))!=pattern.parameters[i])return false;
        return true;
    }
    std::vector<InvokeWitness> all_calls(const Row& row) const {
        if(!row.code)return {};
        instructions::DecodeInput input{b,row.code,version,{strings.size,types.size,fields.size,methods.size,protos.size,call_sites,method_handles},0,false};
        instructions::DecodeOptions options;options.demand_mask=instructions::invokes;
        const auto decoded=instructions::decode(input,options);std::vector<InvokeWitness> out;out.reserve(decoded.invoke_sites.size());
        for(const auto& site:decoded.invoke_sites)out.push_back({site.pc,site.index,site.extra_proto,site.opcode,site.reference_kind});
        return out;
    }
    template<class Emit> void for_each(const MethodFilter& filter,Emit emit) const {
        if(filter.max_results==0)fail("result limit");
        const auto ret=filter.return_enabled?find_type(filter.returned):0;if(filter.return_enabled&&ret==UINT32_MAX)return;
        std::vector<uint32_t> wanted;if(filter.parameters_enabled)for(const auto& item:filter.parameters){auto id=find_type(item);if(id==UINT32_MAX)return;wanted.push_back(id);}
        std::vector<int8_t> proto_match(protos.size,-1);
        const auto matches=[&](uint32_t id){
            if(id>=protos.size)fail("prototype index");auto& memo=proto_match[id];if(memo>=0)return memo!=0;
            const uint64_t at=uint64_t(protos.offset)+uint64_t(id)*12;bool yes=!filter.return_enabled||u32(at+4)==ret;const uint32_t off=u32(at+8);
            if(filter.min_parameters||filter.max_parameters!=UINT32_MAX){const auto n=parameter_count(id);yes=yes&&n>=filter.min_parameters&&n<=filter.max_parameters;}
            if(filter.prototype.op!=TextOp::any)yes=yes&&filter.prototype.matches(prototype_text(id));
            if(filter.parameters_enabled){if(off==0)yes=yes&&wanted.empty();else {require(off,4);const uint32_t n=u32(off);require(uint64_t(off)+4,uint64_t(n)*2);yes=yes&&n==wanted.size();if(yes)for(uint32_t i=0;i<n;++i)if(u16(uint64_t(off)+4+uint64_t(i)*2)!=wanted[i]){yes=false;break;}}}
            memo=static_cast<int8_t>(yes);return yes;
        };
        for(uint32_t c=0;c<classes.size;++c){const uint64_t at=uint64_t(classes.offset)+uint64_t(c)*32;const uint32_t owner=u32(at),data=u32(at+24);auto name=type_name(owner);
            if(!filter.owner.matches(name)||data==0)continue;
            uint64_t cursor=data;uint32_t sizes[4];for(auto& n:sizes)n=leb(cursor);
            if(uint64_t(sizes[0])+sizes[1]+sizes[2]+sizes[3]>uint64_t(b.size()))fail("member counts");
            for(int g=0;g<4;++g){uint32_t prev=0;for(uint32_t i=0;i<sizes[g];++i){const uint64_t decl=cursor;const auto diff=leb(cursor);if(i&&diff==0)fail("duplicate member");if(diff>UINT32_MAX-prev)fail("member overflow");const auto id=prev+diff;prev=id;const auto flags=leb(cursor);
                if(g<2)continue;const auto code=leb(cursor);if(id>=methods.size)fail("method index");const auto method_at=uint64_t(methods.offset)+uint64_t(id)*8;if(u16(method_at)!=owner)fail("method owner mismatch");
                uint32_t projected=flags;if(filter.reflection_flags&&(filter.flags_enabled||filter.flags_contains)){const auto v=query::reflection_flags::project(flags,query::reflection_flags::Target::method);if(!v)fail("unknown reflection flags");projected=*v;}
                if((projected&filter.flags_contains)==filter.flags_contains&&
                   (filter.name.op==TextOp::any||filter.name.matches(string(u32(method_at+4))))&&matches(u16(method_at+2)))
                    emit(Row{id,flags,static_cast<uint32_t>(decl),code});
            }}
        }
    }
    std::vector<Row> scan(const MethodFilter& filter) const {
        std::vector<Row> out;
        for_each(filter,[&](Row row){if(out.size()>=filter.max_results)fail("result limit");out.push_back(row);});
        return out;
    }
    std::vector<Row> scan(std::u16string_view owner_prefix,std::u16string_view returned,const std::vector<std::u16string>& params) const {
        MethodFilter f;f.owner={TextOp::prefix,std::u16string(owner_prefix)};f.return_enabled=true;f.returned=returned;
        f.parameters_enabled=true;f.parameters=params;return scan(f);
    }
    // Candidate methods only: the caller must explicitly accept that untouched
    // methods and sections remain unchecked. Decode selected bodies once per
    // method and resolve only referenced symbols demanded by these predicates.
    std::vector<MatchedMethod> scan_invokes(const MethodFilter& filter,const std::vector<InvokePattern>& required) const {
        for(const auto& pattern:required){if(pattern.reference_kind < -1||pattern.reference_kind > 3)fail("unsupported reference kind");
            if(pattern.reference_kind==1&&(pattern.owner.op!=TextOp::any||pattern.name.op!=TextOp::any||pattern.returned.op!=TextOp::any||pattern.parameters_enabled||pattern.min_parameters||pattern.max_parameters!=UINT32_MAX))fail("call-site symbol match unsupported");}
        std::vector<MatchedMethod> out;
        for_each(filter,[&](const Row& row){if(row.code==0)return;
            instructions::DecodeInput input{b,row.code,version,{strings.size,types.size,fields.size,methods.size,protos.size,call_sites,method_handles},0,false};
            instructions::DecodeOptions options;options.demand_mask=instructions::invokes;
            const auto decoded=instructions::decode(input,options);
            std::vector<InvokeWitness> witness;bool all=true;
            for(const auto& pattern:required){bool found=false;
                for(const auto& site:decoded.invoke_sites){
                    const int kind=site.reference_kind==instructions::ReferenceKind::method?0:site.reference_kind==instructions::ReferenceKind::call_site?1:2;
                    if((pattern.reference_kind==-1&&kind==1)||(pattern.reference_kind>=0&&pattern.reference_kind!=3&&kind!=pattern.reference_kind))continue;
                    if(kind==1){if(pattern.owner.op!=TextOp::any||pattern.name.op!=TextOp::any||pattern.returned.op!=TextOp::any||pattern.parameters_enabled||pattern.min_parameters||pattern.max_parameters!=UINT32_MAX)continue;}
                    else {
                        if(site.index>=methods.size)fail("invoked method index");const auto at=uint64_t(methods.offset)+uint64_t(site.index)*8;
                        const uint32_t owner=u16(at),proto=u16(at+2),name_index=u32(at+4);if(proto>=protos.size)fail("invoked prototype index");
                        if(!pattern.owner.matches(type_name(owner))||!pattern.name.matches(string(name_index)))continue;
                        const auto pat=uint64_t(protos.offset)+uint64_t(proto)*12;const auto return_id=u32(pat+4),list=u32(pat+8);
                        if(!pattern.returned.matches(type_name(return_id)))continue;uint32_t n=0;if(list){require(list,4);n=u32(list);require(uint64_t(list)+4,uint64_t(n)*2);}
                        if(n<pattern.min_parameters||n>pattern.max_parameters||(pattern.parameters_enabled&&n!=pattern.parameters.size()))continue;
                        bool parameters_ok=true;if(pattern.parameters_enabled)for(uint32_t i=0;i<n;++i)if(type_name(u16(uint64_t(list)+4+uint64_t(i)*2))!=pattern.parameters[i]){parameters_ok=false;break;}
                        if(!parameters_ok)continue;
                    }
                    witness.push_back({site.pc,site.index,site.extra_proto,site.opcode,site.reference_kind});found=true;break;
                }
                if(!found){all=false;break;}
            }
            if(all){if(out.size()>=filter.max_results)fail("result limit");out.push_back({row,std::move(witness)});}
        });
        return out;
    }

    // Opt-in candidate scan, NOT a drop-in implementation of QueryIR budgets,
    // snapshots or coverage. For a malformed/unchecked source, callers must not
    // interpret zero candidates as proof of absence. A decoder/symbol error is
    // retained per affected rule; source table/class_data errors throw globally.
    MultiResult scan_multi(std::span<const QuerySpec> queries,uint64_t max_rows=UINT64_MAX,uint64_t max_calls=UINT64_MAX,
                           uint32_t max_code_units=1048576,uint32_t max_instructions=1048576) const {
        if(queries.empty()||queries.size()>64)fail("invalid query count");
        if(protos.size>65536)throw LimitError("prototype table limit");
        uint64_t allocated_rows=0,allocated_calls=0;
        struct Prepared {
            bool unavailable=false;
            uint32_t returned=0;
            std::vector<uint32_t> parameters,strings;
            std::vector<int8_t> proto_match;
        };
        MultiResult out;out.rules.resize(queries.size());std::vector<Prepared> prepared(queries.size());
        for(size_t i=0;i<queries.size();++i){const auto& q=queries[i];auto& p=prepared[i];
            if(!q.method.max_results||q.method.min_parameters>q.method.max_parameters)fail("invalid method limits");
            for(const auto& group:q.invoke_all_any){if(group.empty())fail("empty invoke group");for(const auto& item:group){
                if(item.reference_kind < -1||item.reference_kind > 3||item.min_parameters>item.max_parameters)fail("invalid invoke matcher");
                if(item.reference_kind==1&&(item.owner.op!=TextOp::any||item.name.op!=TextOp::any||item.returned.op!=TextOp::any||item.parameters_enabled||item.min_parameters||item.max_parameters!=UINT32_MAX))fail("call-site symbol match unsupported");}}
            if(q.method.return_enabled){p.returned=find_type(q.method.returned);if(p.returned==UINT32_MAX)p.unavailable=true;}
            if(q.method.parameters_enabled)for(const auto& item:q.method.parameters){const auto id=find_type(item);if(id==UINT32_MAX)p.unavailable=true;p.parameters.push_back(id);}
            for(const auto& item:q.strings_all){const auto id=find_string(item);if(id==UINT32_MAX)p.unavailable=true;p.strings.push_back(id);}
            p.proto_match.assign(protos.size,-1);
        }
        const auto proto_matches=[&](size_t lane,uint32_t id){
            if(id>=protos.size)fail("prototype index");auto& cached=prepared[lane].proto_match[id];if(cached>=0)return cached!=0;
            const auto& f=queries[lane].method;const auto& p=prepared[lane];const auto at=uint64_t(protos.offset)+uint64_t(id)*12;
            bool yes=!f.return_enabled||u32(at+4)==p.returned;const auto count=parameter_count(id);
            yes=yes&&count>=f.min_parameters&&count<=f.max_parameters;
            if(f.parameters_enabled){yes=yes&&count==p.parameters.size();if(yes){const auto list=u32(at+8);for(uint32_t j=0;j<count;++j)if(u16(uint64_t(list)+4+uint64_t(j)*2)!=p.parameters[j]){yes=false;break;}}}
            if(yes&&f.prototype.op!=TextOp::any)yes=f.prototype.matches(prototype_text(id));
            cached=static_cast<int8_t>(yes);return yes;
        };
        // Reuse per-lane flags across classes and methods. Wide queries may
        // visit millions of methods and must not allocate two vectors per row.
        std::vector<uint8_t> active(queries.size()),candidates(queries.size()),unknown(queries.size());
        for(uint32_t c=0;c<classes.size;++c){const auto at=uint64_t(classes.offset)+uint64_t(c)*32;const auto owner=u32(at),data=u32(at+24);const auto name=type_name(owner);
            std::fill(active.begin(),active.end(),0);bool any=false;
            for(size_t i=0;i<queries.size();++i)if(!prepared[i].unavailable&&!out.rules[i].error&&!out.rules[i].result_limit&&queries[i].method.owner.matches(name)){active[i]=1;any=true;}
            if(!any||!data)continue;
            uint64_t cursor=data;uint32_t sizes[4];for(auto& n:sizes)n=leb(cursor);
            if(uint64_t(sizes[0])+sizes[1]+sizes[2]+sizes[3]>uint64_t(b.size()))fail("member counts");
            for(int g=0;g<4;++g){uint32_t previous=0;for(uint32_t j=0;j<sizes[g];++j){
                const auto declaration=cursor;const auto delta=leb(cursor);if(j&&delta==0)fail("duplicate member");if(delta>UINT32_MAX-previous)fail("member overflow");
                const auto id=previous+delta;previous=id;const auto flags=leb(cursor);
                if(g<2){if(id>=fields.size)fail("field index");continue;}
                const auto code=leb(cursor);if(id>=methods.size)fail("method index");const auto method_at=uint64_t(methods.offset)+uint64_t(id)*8;
                if(u16(method_at)!=owner)fail("method owner mismatch");const auto proto=u16(method_at+2);const auto name_index=u32(method_at+4);
                const Row row{id,flags,static_cast<uint32_t>(declaration),code};std::fill(candidates.begin(),candidates.end(),0);std::fill(unknown.begin(),unknown.end(),0);
                uint32_t demand=0;
                for(size_t i=0;i<queries.size();++i)if(active[i]&&!out.rules[i].error&&!out.rules[i].result_limit){
                    auto& result=out.rules[i];++result.visited_methods;const auto& q=queries[i];const auto& f=q.method;
                    try {
                        if(!proto_matches(i,proto)||(f.name.op!=TextOp::any&&!f.name.matches(string(name_index))))continue;
                        uint32_t projected=flags;
                        if(f.reflection_flags&&(f.flags_enabled||f.flags_contains)){const auto value=query::reflection_flags::project(flags,query::reflection_flags::Target::method);
                            if(!value)unknown[i]=1;else projected=*value;}
                        if(!unknown[i]&&(projected&f.flags_contains)!=f.flags_contains)continue;
                        candidates[i]=1;if(!q.invoke_all_any.empty()||q.capture_invokes)demand|=instructions::invokes;if(!q.strings_all.empty())demand|=instructions::strings;
                    }catch(...){result.error=std::current_exception();}
                }
                instructions::DecodeResult decoded;bool have_body=false;std::exception_ptr decode_error;
                if(demand&&code){try {
                    instructions::DecodeInput input{b,code,version,{strings.size,types.size,fields.size,methods.size,protos.size,call_sites,method_handles},0,false};
                    instructions::DecodeOptions options;options.demand_mask=demand;options.max_code_units=max_code_units;options.max_instructions=max_instructions;decoded=instructions::decode(input,options);have_body=true;
                }catch(...){decode_error=std::current_exception();}}
                for(size_t i=0;i<queries.size();++i)if(candidates[i]&&!out.rules[i].error&&!out.rules[i].result_limit){
                    const auto& q=queries[i];auto& result=out.rules[i];const bool needs=!q.invoke_all_any.empty()||!q.strings_all.empty()||q.capture_invokes;
                    if(needs&&decode_error){result.error=decode_error;continue;}
                    if(needs&&code)++result.decoded_methods;
                    if((!q.invoke_all_any.empty()||!q.strings_all.empty())&&!have_body)continue;
                    try {
                        MatchedMethod match{row};bool yes=true;
                        for(const auto& group:q.invoke_all_any){bool found=false;
                            for(const auto& pattern:group){for(const auto& site:decoded.invoke_sites)if(invoke_matches(pattern,site)){
                                match.witnesses.push_back({site.pc,site.index,site.extra_proto,site.opcode,site.reference_kind});found=true;break;}
                                if(found)break;}
                            if(!found){yes=false;break;}
                        }
                        if(!yes)continue;
                        for(const auto id:prepared[i].strings){bool found=false;for(const auto& use:decoded.string_uses)if(use.string_index==id){match.string_witnesses.push_back({use.pc,use.string_index,use.opcode});found=true;break;}
                            if(!found){yes=false;break;}}
                        if(!yes)continue;
                        if(unknown[i]){++result.unknown_rows;continue;}
                        if(result.matches.size()>=q.method.max_results){result.result_limit=true;continue;}
                        if(allocated_rows>=max_rows)throw LimitError("fast row limit");
                        if(q.capture_invokes&&have_body){if(decoded.invoke_sites.size()>max_calls-allocated_calls)throw LimitError("fast call limit");
                            allocated_calls+=decoded.invoke_sites.size();for(const auto& site:decoded.invoke_sites)match.all_invokes.push_back({site.pc,site.index,site.extra_proto,site.opcode,site.reference_kind});}
                        ++allocated_rows;
                        result.matches.push_back(std::move(match));
                    }catch(const LimitError&){throw;}catch(...){result.error=std::current_exception();}
                }
            }}
        }
        return out;
    }
};

} // namespace dexmeguviz::fast
