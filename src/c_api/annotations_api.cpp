#include "runtime.hpp"
#include <algorithm>
#include <span>

using namespace dexmeguviz;
using namespace dexmeguviz::runtime;
namespace {
struct Element {
    uint32_t name_index=0,kind=0,arg=0,offset=0,length=0;
    std::pmr::vector<uint16_t> name;
    explicit Element(std::pmr::memory_resource* memory):name(memory){}
};
struct Annotation {
    uint32_t visibility=0,type_index=0,item_offset=0,offset=0,length=0;
    std::pmr::vector<uint16_t> descriptor;
    std::pmr::vector<Element> elements;
    explicit Annotation(std::pmr::memory_resource* memory):descriptor(memory),elements(memory){}
};
struct Area {uint64_t offset=0,end=0;bool present=false;};
class LimitedReader {
    std::span<const uint8_t> data;uint64_t used=0,limit,encoded_end=UINT64_MAX;const Control& control;
public:
    LimitedReader(std::span<const uint8_t> input,uint64_t max,const Control& c):data(input),limit(max),control(c){}
    void charge(uint64_t n=1){if(n>limit-used)throw query::Error(query::ErrorCode::budget,"annotation work limit");const auto before=used;used+=n;if((used>>8)!=(before>>8))control.check();}
    void begin_encoded(uint64_t at,uint64_t n){encoded_end=at+n;}
    void end_encoded()noexcept{encoded_end=UINT64_MAX;}
    uint64_t work()const noexcept{return used;}
    void range(uint64_t at,uint64_t n,uint64_t end)const{if(end>data.size()||at>end||n>end-at)throw ReadError(ReadCode::corrupt,at,"annotation range");}
    uint8_t byte(uint64_t& at,uint64_t end){if(at>=encoded_end)throw query::Error(query::ErrorCode::budget,"annotation encoded byte limit");charge();range(at,1,end);return data[at++];}
    uint32_t u32(uint64_t at,uint64_t end){uint32_t v=0;for(unsigned i=0;i<4;++i)v|=uint32_t(byte(at,end))<<(8*i);return v;}
    uint32_t uleb(uint64_t& at,uint64_t end){const auto start=at;uint32_t v=0;for(unsigned i=0;i<5;++i){auto b=byte(at,end);if(i==4&&(b&0xf0))throw ReadError(ReadCode::corrupt,start,"annotation ULEB overflow");v|=uint32_t(b&127)<<(7*i);if(!(b&128))return v;}throw ReadError(ReadCode::corrupt,start,"annotation ULEB length");}
    void copy(std::pmr::vector<uint16_t>& out,std::u16string_view text){charge(text.size());out.reserve(text.size());for(size_t i=0;i<text.size();++i){if((i&1023u)==0)control.check();out.push_back(static_cast<uint16_t>(text[i]));}}
};
void skip_value(LimitedReader& r,uint64_t& at,uint64_t end,const Facts& facts,unsigned depth){
    if(depth>=64)throw query::Error(query::ErrorCode::budget,"annotation nesting limit");
    const auto pos=at;const uint8_t tag=r.byte(at,end);const unsigned kind=tag&31u,arg=tag>>5;
    if(kind==0x1c||kind==0x1d){
        if(arg)throw ReadError(ReadCode::corrupt,pos,"annotation nested value arg");
        if(kind==0x1d&&r.uleb(at,end)>=facts.types.size())throw ReadError(ReadCode::corrupt,pos,"nested annotation type");
        const auto count=r.uleb(at,end);if(count>100000)throw query::Error(query::ErrorCode::budget,"annotation nested value count");
        uint32_t previous=0;bool have=false;
        for(uint32_t i=0;i<count;++i){if(kind==0x1d){const auto name=r.uleb(at,end);if(name>=facts.strings.size()||(have&&name<=previous))throw ReadError(ReadCode::corrupt,at,"annotation nested element name");previous=name;have=true;}skip_value(r,at,end,facts,depth+1);}return;
    }
    if(kind==0x1e||kind==0x1f){if((kind==0x1e&&arg)||(kind==0x1f&&arg>1))throw ReadError(ReadCode::corrupt,pos,"annotation simple value arg");return;}
    unsigned maximum=0;switch(kind){case 0x00:maximum=0;break;case 0x02:case 0x03:maximum=1;break;
      case 0x04:case 0x10:case 0x15:case 0x16:case 0x17:case 0x18:case 0x19:case 0x1a:case 0x1b:maximum=3;break;
      case 0x06:case 0x11:maximum=7;break;default:throw ReadError(ReadCode::corrupt,pos,"annotation value kind");}
    if(arg>maximum)throw ReadError(ReadCode::corrupt,pos,"annotation value width");
    uint64_t bits=0;for(unsigned i=0;i<=arg;++i)bits|=uint64_t(r.byte(at,end))<<(8*i);
    if(kind>=0x15&&kind<=0x1b){
        if((kind==0x15||kind==0x16)&&facts.dex_version<38)throw ReadError(ReadCode::corrupt,pos,"annotation method constant version");
        uint64_t bound=0;switch(kind){case 0x15:bound=facts.prototypes.size();break;case 0x16:bound=facts.method_handle_count;break;
          case 0x17:bound=facts.strings.size();break;case 0x18:bound=facts.types.size();break;
          case 0x19:case 0x1b:bound=facts.field_refs.size();break;case 0x1a:bound=facts.method_refs.size();break;}
        if(bits>=bound)throw ReadError(ReadCode::corrupt,pos,"annotation reference index");
    }
}
}
struct dmg_annotations_v1 {
    std::shared_ptr<EngineState> owner;std::shared_ptr<const Dataset> dataset;std::atomic<uint32_t> references{1};
    uint32_t source,kind,target,parameter;uint64_t work=0;
    std::pmr::vector<Annotation> items;
    dmg_annotations_v1(std::shared_ptr<EngineState> engine,std::shared_ptr<const Dataset> data,uint32_t s,uint32_t k,uint32_t t,uint32_t p)
      :owner(std::move(engine)),dataset(std::move(data)),source(s),kind(k),target(t),parameter(p),items(&owner->result_resource){}
};
namespace {struct AnnotationsDelete {void operator()(dmg_annotations_v1* p)const noexcept{if(p)destroy(p);}};}
extern "C" {
dmg_status dmg_snapshot_collect_annotations_v1(dmg_snapshot* snapshot,uint32_t source_index,uint32_t kind,uint32_t target,uint32_t parameter,
    const dmg_annotations_options_v1* options,dmg_annotations_v1** out,dmg_error* error){
    if(out)*out=nullptr;return guard([&]()->dmg_status{
        if(!snapshot||!options||!out||options->struct_size!=sizeof(*options)||options->abi_version!=DMG_ABI_VERSION||options->reserved||kind>DMG_ANNOTATION_PARAMETER||
           (kind!=DMG_ANNOTATION_PARAMETER&&parameter!=UINT32_MAX)||!options->max_records||options->max_records>100000||
           !options->max_work||options->max_work>100000000||!options->max_encoded_bytes||options->max_encoded_bytes>(64uLL<<20)||options->deadline_after_ms>86400000)return DMG_INVALID_ARGUMENT;
        if(snapshot->closed.load(std::memory_order_acquire))return DMG_CLOSED;admit(snapshot->owner);const auto dataset=snapshot->dataset;
        if(source_index>=dataset->sources.size())return DMG_INVALID_ARGUMENT;const auto& source=*dataset->sources[source_index];const auto& f=source.facts;
        if(f.dex_version==41)return DMG_UNSUPPORTED;
        uint32_t owner_type=UINT32_MAX;
        if(kind==DMG_ANNOTATION_CLASS){if(target>=f.types.size())return DMG_INVALID_ARGUMENT;owner_type=target;}
        else if(kind==DMG_ANNOTATION_FIELD){if(target>=f.field_refs.size())return DMG_INVALID_ARGUMENT;if(f.field_definition_by_ref[target]==UINT32_MAX)return DMG_UNSUPPORTED;owner_type=f.field_refs[target].owner;}
        else {if(target>=f.method_refs.size())return DMG_INVALID_ARGUMENT;if(f.method_definition_by_ref[target]==UINT32_MAX)return DMG_UNSUPPORTED;const auto& method=f.method_refs[target];owner_type=method.owner;if(kind==DMG_ANNOTATION_PARAMETER&&(method.type>=f.prototypes.size()||parameter>=f.prototypes[method.type].parameters.size()))return DMG_INVALID_ARGUMENT;}
        if(owner_type>=f.class_definition_by_type.size())return DMG_CORRUPT_INPUT;
        const auto class_index=f.class_definition_by_type[owner_type];if(class_index==UINT32_MAX)return DMG_UNSUPPORTED;
        if(class_index>=f.class_definitions.size())return DMG_INTERNAL_ERROR;
        Control control;if(options->deadline_after_ms)control.deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(options->deadline_after_ms);control.check();
        std::unique_ptr<dmg_annotations_v1,AnnotationsDelete> result(handle<dmg_annotations_v1>(snapshot->owner,dataset,source_index,kind,target,parameter));
        const auto bytes=source.view();LimitedReader r(bytes,options->max_work,control);const auto end=uint64_t(bytes.size());
        const auto dir=f.class_definitions[class_index].annotations_offset;
        if(dir){
            const auto map=r.u32(52,end),map_count=r.u32(map,end);if(!map_count||map_count>1000)throw ReadError(ReadCode::corrupt,map,"annotation map count");
            r.range(uint64_t(map)+4,uint64_t(map_count)*12,end);Area items,sets,lists,dirs;
            for(uint32_t i=0;i<map_count;++i){const uint64_t at=uint64_t(map)+4+uint64_t(i)*12;const auto low=r.u32(at,end);const auto type=low&0xffffu;const auto offset=r.u32(at+8,end);const auto next=i+1<map_count?r.u32(at+20,end):end;
                if((i&&offset==0)||next<=offset||next>end)throw ReadError(ReadCode::corrupt,at,"annotation map range");Area* a=type==0x2004?&items:type==0x1003?&sets:type==0x1002?&lists:type==0x2006?&dirs:nullptr;if(a){if(a->present)throw ReadError(ReadCode::corrupt,at,"duplicate annotation section");*a={offset,next,true};}}
            auto inside=[&](const Area& a,uint64_t at,uint64_t n){if(!a.present||at<a.offset)throw ReadError(ReadCode::corrupt,at,"annotation section missing");r.range(at,n,a.end);};
            inside(dirs,dir,16);uint32_t set=0;const uint32_t fields=r.u32(uint64_t(dir)+4,dirs.end),methods=r.u32(uint64_t(dir)+8,dirs.end),params=r.u32(uint64_t(dir)+12,dirs.end);
            const uint64_t total=uint64_t(fields)+methods+params;r.range(uint64_t(dir)+16,total*8,dirs.end);
            if(kind==DMG_ANNOTATION_CLASS)set=r.u32(dir,dirs.end);
            else {const uint64_t offset=uint64_t(dir)+16+(kind==DMG_ANNOTATION_FIELD?0:kind==DMG_ANNOTATION_METHOD?uint64_t(fields)*8:uint64_t(fields+uint64_t(methods))*8);const auto count=kind==DMG_ANNOTATION_FIELD?fields:kind==DMG_ANNOTATION_METHOD?methods:params;
                for(uint32_t i=0;i<count;++i){const auto at=offset+uint64_t(i)*8;if(r.u32(at,dirs.end)==target){set=r.u32(at+4,dirs.end);break;}}
                if(kind==DMG_ANNOTATION_PARAMETER&&set){inside(lists,set,4);const auto size=r.u32(set,lists.end);const auto& method=f.method_refs[target];if(size!=f.prototypes[method.type].parameters.size())throw ReadError(ReadCode::corrupt,set,"parameter annotation count mismatch");r.range(uint64_t(set)+4,uint64_t(size)*4,lists.end);set=r.u32(uint64_t(set)+4+uint64_t(parameter)*4,lists.end);}}
            if(set){inside(sets,set,4);const auto count=r.u32(set,sets.end);if(count>options->max_records)throw query::Error(query::ErrorCode::budget,"annotation count limit");r.range(uint64_t(set)+4,uint64_t(count)*4,sets.end);
                uint64_t records=0,encoded=0;result->items.reserve(count);
                for(uint32_t i=0;i<count;++i){const auto item=r.u32(uint64_t(set)+4+uint64_t(i)*4,sets.end);inside(items,item,1);uint64_t cursor=item;const auto visibility=r.byte(cursor,items.end);if(visibility>2)throw ReadError(ReadCode::corrupt,item,"annotation visibility");const uint64_t body=cursor;r.begin_encoded(body,options->max_encoded_bytes-encoded);const auto type=r.uleb(cursor,items.end);if(type>=f.types.size()||f.types[type]>=f.strings.size())throw ReadError(ReadCode::corrupt,item,"annotation type");const auto elements=r.uleb(cursor,items.end);
                    records+=uint64_t(elements)+1;if(records>options->max_records)throw query::Error(query::ErrorCode::budget,"annotation record limit");
                    result->items.emplace_back(&snapshot->owner->result_resource);auto& a=result->items.back();a.visibility=visibility;a.type_index=type;a.item_offset=item;a.offset=static_cast<uint32_t>(body);r.copy(a.descriptor,f.strings[f.types[type]]);a.elements.reserve(elements);uint32_t previous=0;bool have=false;
                    for(uint32_t j=0;j<elements;++j){const auto name=r.uleb(cursor,items.end);if(name>=f.strings.size()||(have&&name<=previous))throw ReadError(ReadCode::corrupt,cursor,"annotation element name");previous=name;have=true;const auto value_at=cursor;r.range(cursor,1,items.end);const auto tag=bytes[cursor];skip_value(r,cursor,items.end,f,0);
                        result->items.back().elements.emplace_back(&snapshot->owner->result_resource);auto& e=result->items.back().elements.back();e.name_index=name;e.kind=tag&31u;e.arg=tag>>5;e.offset=static_cast<uint32_t>(value_at);e.length=static_cast<uint32_t>(cursor-value_at);r.copy(e.name,f.strings[name]);}
                    a.length=static_cast<uint32_t>(cursor-body);encoded+=a.length;r.end_encoded();
                }
            }
        }
        control.check();result->work=r.work();*out=result.release();return DMG_OK;
    },error);
}
void dmg_annotations_retain_v1(dmg_annotations_v1* r){if(r)r->references.fetch_add(1,std::memory_order_relaxed);}
void dmg_annotations_release_v1(dmg_annotations_v1* r){if(r&&r->references.fetch_sub(1,std::memory_order_acq_rel)==1)destroy(r);}
dmg_status dmg_annotations_get_info_v1(const dmg_annotations_v1* r,dmg_annotations_info_v1* out,uint32_t size){if(!r||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;*out={r->source,r->kind,r->target,r->parameter,static_cast<uint32_t>(r->items.size()),r->work,r->dataset->snapshot_id.c_str()};return DMG_OK;}
dmg_status dmg_annotations_get_source_v1(const dmg_annotations_v1* r,dmg_source_info* out,uint32_t size){if(!r||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;return fill_source(*r->dataset,r->source,out);}
dmg_status dmg_annotations_get_item_v1(const dmg_annotations_v1* r,uint32_t i,dmg_annotation_item_v1* out,uint32_t size){if(!r||!out||size!=sizeof(*out)||i>=r->items.size())return DMG_INVALID_ARGUMENT;const auto& a=r->items[i];const auto bytes=r->dataset->sources[r->source]->view();*out={a.visibility,a.type_index,static_cast<uint32_t>(a.elements.size()),a.item_offset,a.offset,a.descriptor.data(),a.descriptor.size(),bytes.data()+a.offset,a.length};return DMG_OK;}
dmg_status dmg_annotations_get_element_v1(const dmg_annotations_v1* r,uint32_t i,uint32_t j,dmg_annotation_element_v1* out,uint32_t size){if(!r||!out||size!=sizeof(*out)||i>=r->items.size()||j>=r->items[i].elements.size())return DMG_INVALID_ARGUMENT;const auto& e=r->items[i].elements[j];const auto bytes=r->dataset->sources[r->source]->view();*out={e.name_index,e.kind,e.arg,e.offset,e.name.data(),e.name.size(),bytes.data()+e.offset,e.length};return DMG_OK;}
}
