#include "facts/method_facts.hpp"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory_resource>
#include <stdexcept>
#include <string>
#include <vector>
using namespace dexmeguviz;using namespace dexmeguviz::instructions;
#define CHECK(x) do{if(!(x))throw std::runtime_error("line "+std::to_string(__LINE__)+": " #x);}while(0)
struct Tracker final:std::pmr::memory_resource{size_t live=0,calls=0,fail_at=SIZE_MAX;void* do_allocate(size_t n,size_t a)override{if(calls++==fail_at)throw std::bad_alloc();auto p=std::pmr::new_delete_resource()->allocate(n,a);live+=n;return p;}void do_deallocate(void*p,size_t n,size_t a)override{live-=n;std::pmr::new_delete_resource()->deallocate(p,n,a);}bool do_is_equal(const std::pmr::memory_resource& b)const noexcept override{return this==&b;}};
struct Stop{size_t at,seen=0;};static bool cancel(void*p)noexcept{auto& s=*static_cast<Stop*>(p);return s.seen++==s.at;}
static std::vector<uint8_t> read(const std::filesystem::path& p){std::ifstream f(p,std::ios::binary);CHECK(f.good());return {std::istreambuf_iterator<char>(f),{}};}
static uint32_t ordinal(const Facts& f,std::u16string_view name){for(uint32_t i=0;i<f.methods.size();++i)if(f.methods[i].name==name)return i;throw std::runtime_error("missing method");}
int main(int argc,char**argv){try{CHECK(argc==2);std::filesystem::path dir(argv[1]);
 for(const auto version:{"good-039.dex","good-040.dex"}){
  auto bytes=read(dir/version);auto facts=read_metadata(bytes);const auto method=ordinal(facts,u"uses");CHECK(facts.method_handle_count==1&&facts.prototypes.size()==1);Tracker mem;
  {auto got=facts::collect_method(bytes,facts,method,Demand::method_constants,&mem);CHECK(got.has_body&&got.instruction_checked&&got.decoded_code_units==8&&got.validation_work==11&&got.method_constants.size()==3&&got.availability(Demand::method_constants)==facts::FactAvailability::checked);
   for(const auto& v:got.method_constants)std::cout<<"EVENT "<<version<<" "<<v.pc<<" "<<v.index<<" "<<v.destination<<" "<<unsigned(v.opcode)<<" "<<unsigned(v.domain)<<"\n";
   CHECK(got.method_constants[0].pc==0&&got.method_constants[0].domain==ConstantDomain::method_handle&&got.method_constants[1].pc==2&&got.method_constants[1].domain==ConstantDomain::method_type&&got.method_constants[2].pc==4&&got.method_constants[2].domain==ConstantDomain::method_handle);
   CHECK(got.invoke_sites.empty()&&got.string_uses.empty()&&got.field_uses.empty()&&got.availability(Demand::invokes)==facts::FactAvailability::not_requested);}
  CHECK(mem.live==0);
  {auto no=facts::collect_method(bytes,facts,method,Demand::strings,&mem);CHECK(no.instruction_checked&&no.method_constants.empty()&&no.validation_work==8&&no.availability(Demand::method_constants)==facts::FactAvailability::not_requested);}CHECK(mem.live==0);
  for(auto name:{u"abstractMethod",u"nativeMethod"}){auto no=facts::collect_method(bytes,facts,ordinal(facts,name),Demand::method_constants,&mem);CHECK(!no.has_body&&!no.instruction_checked&&no.method_constants.empty()&&no.availability(Demand::method_constants)==facts::FactAvailability::no_body);}CHECK(mem.live==0);
  {bool limited=false;try{auto x=facts::collect_method(bytes,facts,method,Demand::method_constants,&mem,nullptr,nullptr,10);(void)x;}catch(const DecodeError&e){CHECK(e.code==DecodeCode::budget);limited=true;}CHECK(limited&&mem.live==0);auto exact=facts::collect_method(bytes,facts,method,Demand::method_constants,&mem,nullptr,nullptr,11);CHECK(exact.method_constants.size()==3);}CHECK(mem.live==0);
  Stop count{SIZE_MAX};{auto x=facts::collect_method(bytes,facts,method,Demand::method_constants,&mem,cancel,&count);CHECK(x.method_constants.size()==3);}CHECK(mem.live==0&&count.seen>0);
  for(size_t i=0;i<count.seen;++i){Tracker t;Stop state{i};bool stopped=false;try{auto x=facts::collect_method(bytes,facts,method,Demand::method_constants,&t,cancel,&state);(void)x;}catch(const DecodeError&e){CHECK(e.code==DecodeCode::cancelled);stopped=true;}CHECK(stopped&&t.live==0);}
  size_t attempts=0;for(size_t i=0;i<100;++i){Tracker t;t.fail_at=i;try{auto x=facts::collect_method(bytes,facts,method,Demand::method_constants,&t);CHECK(x.method_constants.size()==3);CHECK(t.live>0);attempts=i;break;}catch(const std::bad_alloc&){CHECK(t.live==0);}}CHECK(attempts>0);
  auto twin=read_metadata(bytes);auto a=facts::collect_method(bytes,facts,method,Demand::method_constants);auto b=facts::collect_method(bytes,twin,ordinal(twin,u"uses"),Demand::method_constants);CHECK(&facts!=&twin&&a.method_constants.size()==b.method_constants.size());
  DecodeInput cut{bytes,facts.methods[method].code_offset,facts.dex_version,{static_cast<uint32_t>(facts.strings.size()),static_cast<uint32_t>(facts.types.size()),static_cast<uint32_t>(facts.field_refs.size()),static_cast<uint32_t>(facts.method_refs.size()),static_cast<uint32_t>(facts.prototypes.size()),facts.call_site_count,facts.method_handle_count},uint64_t(facts.methods[method].code_offset)+19};DecodeOptions opt;opt.demand_mask=Demand::method_constants;bool truncated=false;try{(void)decode(cut,opt);}catch(const DecodeError&e){CHECK(e.code==DecodeCode::corrupt);truncated=true;}CHECK(truncated);
 }
 {auto bytes=read(dir/"nonzero-039.dex");auto facts=read_metadata(bytes);CHECK(facts.method_handle_count==2&&facts.prototypes.size()==2);Tracker memory;
  {auto got=facts::collect_method(bytes,facts,ordinal(facts,u"uses"),Demand::method_constants,&memory);CHECK(got.method_constants.size()==3&&got.validation_work==10);
   for(const auto& v:got.method_constants)std::cout<<"EVENT nonzero-039.dex "<<v.pc<<" "<<v.index<<" "<<v.destination<<" "<<unsigned(v.opcode)<<" "<<unsigned(v.domain)<<"\n";
   CHECK(got.method_constants[0].pc==0&&got.method_constants[0].index==1&&got.method_constants[0].destination==1&&got.method_constants[0].domain==ConstantDomain::method_handle);
   CHECK(got.method_constants[1].pc==2&&got.method_constants[1].index==1&&got.method_constants[1].destination==1&&got.method_constants[1].domain==ConstantDomain::method_type);
   CHECK(got.method_constants[2].pc==4&&got.method_constants[2].index==0&&got.method_constants[2].destination==0&&got.method_constants[2].domain==ConstantDomain::method_handle);}
  CHECK(memory.live==0);
 }
 for(const auto bad:{"old-038.dex","bad-handle.dex","bad-type.dex","bad-register.dex","late-opcode.dex","bad-handle-two.dex","bad-type-two.dex","bad-register-two.dex"}){auto bytes=read(dir/bad);auto facts=read_metadata(bytes);Tracker mem;bool failed=false;try{auto x=facts::collect_method(bytes,facts,ordinal(facts,u"uses"),Demand::method_constants,&mem);(void)x;}catch(const DecodeError&e){CHECK(e.code==(std::string(bad)=="old-038.dex"?DecodeCode::unsupported:DecodeCode::corrupt));failed=true;}CHECK(failed&&mem.live==0);}
 {auto bytes=read(dir/"good-039.dex");auto facts=read_metadata(bytes);Tracker mem;bool unsupported=false;try{(void)facts::collect_method(bytes,facts,ordinal(facts,u"uses"),256,&mem);}catch(const DecodeError&e){CHECK(e.code==DecodeCode::unsupported);unsupported=true;}CHECK(unsupported&&mem.live==0);}
 std::cout<<"PASS method constants, budget/cancel/alloc, no-body and checked errors\n";return 0;
}catch(const std::exception&e){std::cerr<<e.what()<<"\n";return 1;}}
