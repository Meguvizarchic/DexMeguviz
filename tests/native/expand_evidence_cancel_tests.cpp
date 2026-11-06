#include "c_api/runtime.hpp"
#include <atomic>
#include <iostream>
#include <limits>
#include <memory_resource>
#include <stdexcept>
#include <string>

using namespace dexmeguviz;
using namespace dexmeguviz::runtime;
#ifdef DMG_STANDALONE_EXPAND_CANCEL_TEST
namespace dexmeguviz::reference {
facts::UseKind use_kind(query::Relation){throw std::logic_error("unexpected use identity in isolated copy test");}
const facts::UseRecord& use_record(const Result&,const EntityKey&){throw std::logic_error("unexpected use record in isolated copy test");}
}
#endif
#define CHECK(x) do{if(!(x))throw std::runtime_error("expand evidence cancellation check "+std::to_string(__LINE__)+": " #x);}while(0)
struct Counter final:std::pmr::memory_resource{
 size_t used=0,limit=std::numeric_limits<size_t>::max();
 void* do_allocate(size_t n,size_t a)override{if(n>limit-used)throw std::bad_alloc();auto p=std::pmr::new_delete_resource()->allocate(n,a);used+=n;return p;}
 void do_deallocate(void* p,size_t n,size_t a)override{used-=n;std::pmr::new_delete_resource()->deallocate(p,n,a);}
 bool do_is_equal(const std::pmr::memory_resource& other)const noexcept override{return this==&other;}
};
struct Trigger {
 int value=0;static inline size_t copied=0,trip=0;static inline std::atomic<bool>* cancelled=nullptr;
 explicit Trigger(int v=0):value(v){}
 Trigger(const Trigger& other):value(other.value){tick();}
 Trigger& operator=(const Trigger& other){value=other.value;tick();return *this;}
 static void tick(){if(cancelled&&++copied==trip)cancelled->store(true,std::memory_order_release);}
};
int main(){try{
 Counter memory;
 {
  std::pmr::vector<Trigger> input(&memory),out(&memory);input.reserve(4096);
  for(int i=0;i<4096;++i)input.emplace_back(i);
  std::atomic<bool> cancelled{false};Control control;control.cancelled=&cancelled;
  Trigger::cancelled=&cancelled;Trigger::copied=0;Trigger::trip=1025;
  bool stopped=false;try{copy_expand_evidence(out,input,control);}catch(const Stop& e){CHECK(e.status==DMG_CANCELLED);stopped=true;}
  CHECK(stopped&&cancelled.load()&&out.size()==2048&&out.front().value==0&&out.back().value==2047);
  Trigger::cancelled=nullptr;cancelled=false;copy_expand_evidence(out,input,control);
  CHECK(out.size()==input.size());for(size_t i=0;i<input.size();++i)CHECK(out[i].value==input[i].value);
  Control expired;expired.deadline=std::chrono::steady_clock::now()-std::chrono::milliseconds(1);
  bool deadline=false;try{copy_expand_evidence(out,input,expired);}catch(const Stop& e){CHECK(e.status==DMG_DEADLINE_EXCEEDED);deadline=true;}CHECK(deadline&&out.size()==4096);
 }
 CHECK(memory.used==0);
 {
  std::pmr::vector<reference::Witness> input(&memory),out(&memory);input.resize(3000);
  const auto before=memory.used;memory.limit=before;bool exhausted=false;
  try{copy_expand_evidence(out,input,Control{});}catch(const std::bad_alloc&){exhausted=true;}
  CHECK(exhausted&&out.empty()&&memory.used==before);memory.limit=std::numeric_limits<size_t>::max();
 }
 CHECK(memory.used==0);
 {
  query::Plan legacy(&memory),expand(&memory);expand.contains_expand=true;
  reference::Candidate row(0,0,&memory);row.witnesses.resize(3000);row.witnesses[123].dex_pc=37;
  auto plain=row_evidence(legacy,row);auto grouped=row_evidence(expand,row);
  CHECK(plain.size()==3000&&plain.data()==row.witnesses.data()&&plain[123].dex_pc==37&&grouped.empty());
  reference::EntityView entity{};Control control;EntityData value(entity,&memory,control,0);
  Row legacy_row(std::move(value),&memory,plain);CHECK(legacy_row.witnesses.size()==3000&&legacy_row.witnesses[123].dex_pc==37);
  EntityData value2(entity,&memory,control,0);Row expand_row(std::move(value2),&memory,grouped);CHECK(expand_row.witnesses.empty());
 }
 CHECK(memory.used==0);
 {
  dmg_engine_options options{sizeof(options),DMG_ABI_VERSION,1u<<20,1u<<20,1u<<20,4,0};
  auto engine=std::make_shared<EngineState>(options);Dataset data(engine);reference::Result evaluated(&memory);reference::ExpandPath input(&memory);ExpandPathData out(input,&memory);
  input.seed_links.resize(2300);input.seed_witnesses.resize(2301);input.walk_witnesses.resize(2302);input.emit_witnesses.resize(2303);
  input.seed_links[1400].node=53;input.seed_witnesses[1401].dex_pc=54;input.walk_witnesses[1402].dex_pc=55;input.emit_witnesses[1403].dex_pc=56;
  expand_evidence(out,input,data,evaluated,&memory,Control{});
  CHECK(out.seed_links.size()==2300&&out.seed_witnesses.size()==2301&&out.walk_witnesses.size()==2302&&out.emit_witnesses.size()==2303);
  CHECK(out.seed_links[1400].node==53&&out.seed_witnesses[1401].dex_pc==54&&out.walk_witnesses[1402].dex_pc==55&&out.emit_witnesses[1403].dex_pc==56);
 }
 CHECK(memory.used==0);
 std::cout<<"PASS expand evidence: bounded mid-copy cancellation, deadline, allocation rollback, v5 grouped witnesses and v1-v4 row evidence\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
