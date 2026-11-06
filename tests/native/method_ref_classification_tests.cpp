#include "facts/symbols.hpp"
#include "facts/method_facts.hpp"
#include "execution/reference/entity.hpp"
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <vector>
using namespace dexmeguviz;
#define CHECK(x) do { if(!(x)) throw std::runtime_error("line "+std::to_string(__LINE__)+": " #x); } while(false)
static std::vector<uint8_t> read(const char* path) {std::ifstream in(path,std::ios::binary);CHECK(in.good());return {std::istreambuf_iterator<char>(in),{}};}
static uint32_t ref(const Facts& f,std::u16string_view owner,std::u16string_view name){
 for(uint32_t i=0;i<f.method_refs.size();++i){const auto& x=f.method_refs[i];if(f.strings[f.types[x.owner]]==owner&&f.strings[x.name]==name)return i;}
 throw std::runtime_error("missing fixture reference");
}
int main(int argc,char** argv){try{
 CHECK(argc==5);auto first=read(argv[1]),a=read(argv[2]),b=read(argv[3]);auto invalid_bytes=read(argv[4]);bool invalid_empty=false;try{(void)read_metadata(invalid_bytes);}catch(const ReadError& e){invalid_empty=e.code==ReadCode::corrupt;}CHECK(invalid_empty);auto f=read_metadata(first),left=read_metadata(a),right=read_metadata(b);
 using K=symbols::MethodRefLocalKind;const auto u=ref(f,u"Lfacts/Example;",u"uses"),q=ref(f,u"Lfacts/Example;",u"quiet"),n=ref(f,u"Lfacts/Example;",u"nativeMethod"),ab=ref(f,u"Lfacts/Example;",u"abstractMethod"),ext=ref(f,u"Ljava/lang/Object;",u"sink");
 CHECK(symbols::classify_method_ref(f,u).kind==K::local_with_body && symbols::classify_method_ref(f,q).kind==K::local_with_body);
 CHECK(symbols::classify_method_ref(f,n).kind==K::local_no_body && symbols::classify_method_ref(f,ab).kind==K::local_no_body);
 CHECK(symbols::classify_method_ref(f,ext).kind==K::no_local_definition && symbols::classify_method_ref(f,ext).definition_ordinal==symbols::no_index);
 CHECK(symbols::classify_method_ref(f,static_cast<uint32_t>(f.method_refs.size())).kind==K::invalid_reference);
 auto qq=facts::collect_method(first,f,symbols::classify_method_ref(f,q).definition_ordinal,instructions::strings);
 CHECK(qq.availability(instructions::strings)==facts::FactAvailability::checked && qq.string_uses.empty());
 CHECK(qq.availability(instructions::invokes)==facts::FactAvailability::not_requested);
 auto no=facts::collect_method(first,f,symbols::classify_method_ref(f,n).definition_ordinal,instructions::strings);
 CHECK(no.availability(instructions::strings)==facts::FactAvailability::no_body);
 unsigned polls=0;auto cancel=[](void* ctx) noexcept {++*static_cast<unsigned*>(ctx);return true;};bool cancelled=false;
 try{(void)facts::collect_method(first,f,symbols::classify_method_ref(f,u).definition_ordinal,instructions::strings,std::pmr::get_default_resource(),cancel,&polls);}
 catch(const instructions::DecodeError& e){cancelled=e.code==instructions::DecodeCode::cancelled;}
 CHECK(cancelled&&polls>0);bool budget=false;try{(void)facts::collect_method(first,f,symbols::classify_method_ref(f,u).definition_ordinal,instructions::strings,std::pmr::get_default_resource(),nullptr,nullptr,0);}
 catch(const instructions::DecodeError& e){budget=e.code==instructions::DecodeCode::budget;}CHECK(budget);
 const auto lref=ref(left,u"Lsample/Target;",u"sink"),rref=ref(right,u"Lsample/Target;",u"sink");
 CHECK(symbols::classify_method_ref(left,lref).kind==K::no_local_definition);const auto defined=symbols::classify_method_ref(right,rref);CHECK(defined.kind==K::local_with_body);
 CHECK(right.methods[defined.definition_ordinal].code_offset>0);
 const auto empty=facts::collect_method(b,right,defined.definition_ordinal,instructions::strings);CHECK(empty.has_body&&empty.instruction_checked&&empty.decoded_code_units==1&&empty.string_uses.empty()&&empty.availability(instructions::strings)==facts::FactAvailability::checked);
 reference::SourceView x{2,0,&left,a},duplicate{3,1,&left,a},y{4,2,&right,b};
 auto e1=reference::entity(x,query::Relation::method_refs,lref),e2=reference::entity(duplicate,query::Relation::method_refs,lref),e3=reference::entity(y,query::Relation::method_refs,rref);
 CHECK(e1.source_index==2&&e2.source_index==3&&e3.source_index==4&&!e1.definition_known&&!e2.definition_known&&e3.definition_known);
 CHECK(!e1.code_known&&!e2.code_known&&!e3.code_known&&e1.name==e3.name&&e1.owner==e3.owner&&e1.prototype==e3.prototype);
 auto ed=reference::entity(y,query::Relation::method_defs,defined.definition_ordinal);CHECK(ed.code_known&&ed.code_offset>0);
 auto save=f.method_definition_by_ref[u];f.method_definition_by_ref[u]=static_cast<uint32_t>(f.methods.size());CHECK(symbols::classify_method_ref(f,u).kind==K::invalid_metadata);
 bool rejected=false;reference::SourceView invalid{0,0,&f,first};try{(void)reference::entity(invalid,query::Relation::method_refs,u);}catch(const query::Error& e){rejected=e.code==query::ErrorCode::invalid;}CHECK(rejected);
 f.method_definition_by_ref[u]=save;const auto old=f.methods[save].method_index;f.methods[save].method_index=ext;CHECK(symbols::classify_method_ref(f,u).kind==K::invalid_metadata);f.methods[save].method_index=old;
 f.method_definition_by_ref.clear();CHECK(symbols::classify_method_ref(f,u).kind==K::invalid_metadata);
 std::cout<<"PASS source-local method reference classification and old entity semantics\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
