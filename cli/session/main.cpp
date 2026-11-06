#include "resident_session.hpp"
#include "background_session.hpp"
#include "dexmeguviz/dexmeguviz.h"
#include "json.hpp"
#include "sqlite3.h"
#include <charconv>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using namespace dexmeguviz::desktop_sql;
namespace {
constexpr size_t max_line=65536, max_output=8u<<20, max_dex=32u<<20;
struct ProtocolError:std::runtime_error {using std::runtime_error::runtime_error;};
struct OutputLimit:std::runtime_error {OutputLimit():std::runtime_error("output limit") {}};
void require(bool v,const char* message){if(!v)throw ProtocolError(message);}
void append(std::string& out,std::string_view s){if(s.size()>max_output-out.size())throw OutputLimit();out.append(s);}
void keys(const dmg_cli::Json& j,std::initializer_list<std::u16string_view> allowed){
 require(j.kind==dmg_cli::Json::Kind::object,"object required");
 for(const auto& [key,value]:j.object){(void)value;bool ok=false;for(auto s:allowed)if(key==s){ok=true;break;}require(ok,"unexpected key");}
}
const dmg_cli::Json& required(const dmg_cli::Json& j,std::u16string_view key){auto i=j.object.find(std::u16string(key));require(i!=j.object.end(),"missing field");return i->second;}
const dmg_cli::Json* optional(const dmg_cli::Json& j,std::u16string_view key){auto i=j.object.find(std::u16string(key));return i==j.object.end()?nullptr:&i->second;}
uint64_t u64(const dmg_cli::Json& j){require(j.kind==dmg_cli::Json::Kind::number,"integer required");uint64_t v=0;auto [p,e]=std::from_chars(j.number.data(),j.number.data()+j.number.size(),v);require(e==std::errc{}&&p==j.number.data()+j.number.size(),"invalid unsigned integer");return v;}
int64_t i64(const dmg_cli::Json& j){require(j.kind==dmg_cli::Json::Kind::number,"integer required");int64_t v=0;auto [p,e]=std::from_chars(j.number.data(),j.number.data()+j.number.size(),v);require(e==std::errc{}&&p==j.number.data()+j.number.size(),"invalid signed integer");return v;}
uint64_t get_u64(const dmg_cli::Json& j,std::u16string_view key,uint64_t fallback){auto p=optional(j,key);return p?u64(*p):fallback;}
std::string utf8(std::u16string_view text){
 std::string out;out.reserve(text.size());
 for(size_t i=0;i<text.size();++i){uint32_t c=text[i];
  if(c>=0xd800&&c<=0xdbff){require(i+1<text.size()&&text[i+1]>=0xdc00&&text[i+1]<=0xdfff,"unpaired surrogate");c=0x10000+((c-0xd800)<<10)+(text[++i]-0xdc00);}
  else require(!(c>=0xdc00&&c<=0xdfff),"unpaired surrogate");
  if(c<0x80)out.push_back(static_cast<char>(c));else if(c<0x800){out.push_back(static_cast<char>(0xc0|(c>>6)));out.push_back(static_cast<char>(0x80|(c&63)));}
  else if(c<0x10000){out.push_back(static_cast<char>(0xe0|(c>>12)));out.push_back(static_cast<char>(0x80|((c>>6)&63)));out.push_back(static_cast<char>(0x80|(c&63)));}
  else{out.push_back(static_cast<char>(0xf0|(c>>18)));out.push_back(static_cast<char>(0x80|((c>>12)&63)));out.push_back(static_cast<char>(0x80|((c>>6)&63)));out.push_back(static_cast<char>(0x80|(c&63)));}}
 return out;
}
std::string text(const dmg_cli::Json& j){require(j.kind==dmg_cli::Json::Kind::string,"string required");return utf8(j.string);}
uint64_t identifier(const dmg_cli::Json& j){const auto x=text(j);require(!x.empty()&&x[0]>='1'&&x[0]<='9',"invalid task ID");uint64_t v=0;auto [p,e]=std::from_chars(x.data(),x.data()+x.size(),v);require(e==std::errc{}&&p==x.data()+x.size(),"invalid task ID");return v;}
int64_t integer_text(const dmg_cli::Json& j){const auto x=text(j);int64_t v=0;auto [p,e]=std::from_chars(x.data(),x.data()+x.size(),v);require(e==std::errc{}&&p==x.data()+x.size()&&std::to_string(v)==x,"invalid signed integer text");return v;}
std::string quoted_u64(uint64_t value){return "\""+std::to_string(value)+"\"";}
// Reserve the output buffer before state mutations; formatting these bounded
// responses uses no dynamic allocation after a task has been accepted.
void fill_response(std::string& out,std::string_view op,int status,const uint64_t* id=nullptr){
 out.clear();out.append("{\"op\":\"");out.append(op);out.append("\",\"status\":");
 char digits[32];auto status_end=std::to_chars(digits,digits+sizeof(digits),status);out.append(digits,status_end.ptr);
 if(id){out.append(",\"id\":\"");auto end=std::to_chars(digits,digits+sizeof(digits),*id);out.append(digits,end.ptr);out.push_back('\"');}out.push_back('}');
}
std::string response(std::string_view op,int status){return "{\"op\":"+dmg_cli::json_quote_ascii(op)+",\"status\":"+std::to_string(status)+"}";}
std::string response_id(std::string_view op,int status,uint64_t id){return "{\"op\":"+dmg_cli::json_quote_ascii(op)+",\"status\":"+std::to_string(status)+",\"id\":"+quoted_u64(id)+"}";}
// Validate UTF-8 incrementally and append directly under the response limit.
// JSON strings may contain NUL/control bytes only through escaped forms.
void append_json_utf8(std::string& out,std::string_view input){
 constexpr char hex[]="0123456789abcdef";append(out,"\"");
 for(size_t i=0;i<input.size();){
  const auto c=static_cast<uint8_t>(input[i]);
  if(c<0x80){
   if(c=='\"'||c=='\\'){char escaped[2]={'\\',static_cast<char>(c)};append(out,{escaped,2});}
   else if(c<0x20){char escaped[6]={'\\','u','0','0',hex[c>>4],hex[c&15]};append(out,{escaped,6});}
   else {append(out,input.substr(i,1));}
   ++i;continue;
  }
  uint32_t scalar=0,minimum=0;size_t count=0;
  if(c>=0xc2&&c<=0xdf){scalar=c&0x1f;minimum=0x80;count=2;}
  else if(c>=0xe0&&c<=0xef){scalar=c&0x0f;minimum=0x800;count=3;}
  else if(c>=0xf0&&c<=0xf4){scalar=c&0x07;minimum=0x10000;count=4;}
  else throw dmg_cli::JsonError("invalid UTF-8 in SQL result");
  if(count>input.size()-i)throw dmg_cli::JsonError("truncated UTF-8 in SQL result");
  for(size_t n=1;n<count;++n){const auto b=static_cast<uint8_t>(input[i+n]);if((b&0xc0)!=0x80)throw dmg_cli::JsonError("invalid UTF-8 in SQL result");scalar=(scalar<<6)|(b&63);}
  if(scalar<minimum||scalar>0x10ffff||(scalar>=0xd800&&scalar<=0xdfff))throw dmg_cli::JsonError("invalid Unicode scalar in SQL result");
  append(out,input.substr(i,count));i+=count;
 }
 append(out,"\"");
}
std::string blob_hex(std::string_view bytes){
 constexpr char digits[]="0123456789abcdef";std::string out;out.reserve(bytes.size()*2);
 for(unsigned char b:bytes){out.push_back(digits[b>>4]);out.push_back(digits[b&15]);}return out;
}
std::string parse_blob(const dmg_cli::Json& j){
 const auto hex=text(j);require(hex.size()%2==0,"blob_hex needs complete bytes");std::string out;out.reserve(hex.size()/2);
 auto nibble=[](char c)->unsigned{if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;throw ProtocolError("blob_hex must be lowercase hexadecimal");};
 for(size_t i=0;i<hex.size();i+=2)out.push_back(static_cast<char>((nibble(hex[i])<<4)|nibble(hex[i+1])));return out;
}
void append_profile_v1(std::string& out,const ResidentFinal& f){
 // This adapter producer and phase match the one-shot SQL envelope. A retained
 // terminal does not imply that prepare/step ran (for example queued cancel).
 append(out,",\"profile_v1\":{\"producer\":\"desktop-sql\",\"phase\":\"executed\",\"plan\":null,\"runtime\":{\"source_prepare_us\":null,\"session_open_us\":null,\"close_us\":null,\"query\":");
 if(!f.has_profile)append(out,"null");
 else {
  const auto& p=f.profile;
  append(out,"{\"sequence\":"+quoted_u64(p.sequence)+",\"elapsed_us\":"+quoted_u64(p.elapsed_us)+",\"prepare_us\":"+(p.prepare_attempted?quoted_u64(p.prepare_us):"null")+",\"first_step_us\":"+(p.first_step_observed?quoted_u64(p.first_step_us):"null"));
  append(out,",\"execution_status\":"+std::to_string(p.execution_status)+",\"first_step_status\":"+(p.first_step_observed?std::to_string(p.first_step_status):"null")+",\"prepare_attempted\":"+(p.prepare_attempted?"true":"false")+",\"prepared\":"+(p.prepared?"true":"false")+",\"first_step_observed\":"+(p.first_step_observed?"true":"false"));
  append(out,",\"progress_callbacks\":"+quoted_u64(p.progress_callbacks)+",\"rows_staged\":"+quoted_u64(p.rows_staged)+",\"rows_committed\":"+quoted_u64(p.rows_committed)+"}");
 }
 append(out,",\"statement_reuse\":");
 // These snapshots are collected after an observed SQL attempt. A queued
 // cancellation has no current reuse observation; its default fields are not measurements.
 if(!f.has_profile)append(out,"null");
 else append(out,"{\"prepare_attempts\":"+quoted_u64(f.reuse.prepare_attempts)+",\"cache_hits\":"+quoted_u64(f.reuse.cache_hits)+",\"automatic_reprepares\":"+quoted_u64(f.reuse.automatic_reprepares)+",\"estimated_retained_statement_bytes\":"+quoted_u64(f.reuse.retained_statement_bytes)+",\"cached\":"+(f.reuse.cached?"true":"false")+"}");
 append(out,",\"retained_index_bytes\":null,\"cancel_check_count\":null}}");
}
std::string final_json(const ResidentFinal& f){
 std::string out="{\"op\":\"final\",\"status\":0,\"id\":"+quoted_u64(f.id)+",\"execution_status\":"+std::to_string(f.execution_status);
 if(f.has_profile){const auto& p=f.profile;append(out,",\"profile\":{\"sequence\":"+quoted_u64(p.sequence)+",\"elapsed_us\":"+quoted_u64(p.elapsed_us)+",\"prepare_us\":"+quoted_u64(p.prepare_us)+",\"first_step_us\":"+quoted_u64(p.first_step_us)+",\"prepared\":"+(p.prepared?"true":"false")+",\"prepare_attempted\":"+(p.prepare_attempted?"true":"false")+",\"rows_committed\":"+quoted_u64(p.rows_committed)+"}");} else append(out,",\"profile\":null");
 append(out,",\"reuse\":{\"prepare_attempts\":"+quoted_u64(f.reuse.prepare_attempts)+",\"cache_hits\":"+quoted_u64(f.reuse.cache_hits)+",\"automatic_reprepares\":"+quoted_u64(f.reuse.automatic_reprepares)+",\"cached\":"+(f.reuse.cached?"true":"false")+"}");
 append_profile_v1(out,f);
 if(f.execution_status!=SQLITE_OK){append(out,",\"result\":null}");return out;}
 append(out,",\"result\":{\"snapshot_id\":"+dmg_cli::json_quote_ascii(f.result.snapshot_id)+",\"source_scope\":\""+(f.result.source_scope==SqlScopeCoverage::partial_source_scope?"partial":"declared_complete")+"\",\"input_count\":"+std::to_string(f.result.input_count)+",\"source_count\":"+std::to_string(f.result.source_count)+",\"rows\":[");
 bool first_row=true;for(const auto& row:f.result.rows){if(!first_row)append(out,",");first_row=false;append(out,"[");bool first=true;for(const auto& value:row){if(!first)append(out,",");first=false;
  if(value.kind==SqlValue::Kind::null)append(out,"null");else if(value.kind==SqlValue::Kind::integer)append(out,"{\"integer\":\""+std::to_string(value.integer)+"\"}");else if(value.kind==SqlValue::Kind::text)append_json_utf8(out,value.text);else if(value.kind==SqlValue::Kind::blob)append(out,"{\"blob_hex\":\""+blob_hex(value.text)+"\"}");else throw ProtocolError("unexpected result kind");}
  append(out,"]");}append(out,"]}}");return out;
}
std::string stats_json(const ResidentStats& s){return "{\"op\":\"stats\",\"status\":0,\"queued\":"+std::to_string(s.queued)+",\"terminal\":"+std::to_string(s.terminal)+",\"input_bytes\":"+quoted_u64(s.input_bytes)+",\"reserved_result_bytes\":"+quoted_u64(s.reserved_result_bytes)+",\"accepted\":"+quoted_u64(s.accepted)+",\"completed\":"+quoted_u64(s.completed)+",\"cancelled\":"+quoted_u64(s.cancelled)+",\"open_us\":"+quoted_u64(s.open_us)+",\"close_us\":"+quoted_u64(s.close_us)+",\"closed\":"+(s.closed?"true":"false")+"}";}
std::string stats_json(const BackgroundStats& s){return "{\"op\":\"stats\",\"status\":0,\"queued\":"+std::to_string(s.queued)+",\"running\":"+std::to_string(s.running)+",\"terminal\":"+std::to_string(s.terminal)+",\"input_bytes\":"+quoted_u64(s.input_bytes)+",\"reserved_result_bytes\":"+quoted_u64(s.reserved_result_bytes)+",\"accepted\":"+quoted_u64(s.accepted)+",\"completed\":"+quoted_u64(s.completed)+",\"interrupted\":"+quoted_u64(s.interrupted)+",\"stopping\":"+(s.stopping?"true":"false")+",\"closed\":"+(s.closed?"true":"false")+"}";}
bool emit(std::string_view s){std::cout.write(s.data(),static_cast<std::streamsize>(s.size()));std::cout.put('\n');std::cout.flush();return bool(std::cout);}
enum class Line { end, complete, oversized };
Line read_line(std::string& out){out.clear();bool oversized=false,any=false;for(;;){auto c=std::cin.get();if(c==std::char_traits<char>::eof())return any?(oversized?Line::oversized:Line::complete):Line::end;any=true;if(c=='\n')return oversized?Line::oversized:Line::complete;if(out.size()<max_line)out.push_back(static_cast<char>(c));else oversized=true;}}
std::vector<uint8_t> load_input(const std::filesystem::path& path,uint64_t limit){const auto size=std::filesystem::file_size(path);require(size>0&&size<=limit,"input size outside range");std::ifstream f(path,std::ios::binary);require(bool(f),"cannot open input");std::vector<uint8_t> b(static_cast<size_t>(size));f.read(reinterpret_cast<char*>(b.data()),static_cast<std::streamsize>(b.size()));require(f.gcount()==static_cast<std::streamsize>(b.size())&&f.peek()==std::char_traits<char>::eof(),"input changed or could not be read");return b;}
struct EngineGuard{dmg_engine* p=nullptr;~EngineGuard(){if(p)dmg_engine_release(p);}};
struct SnapshotGuard{dmg_snapshot* p=nullptr;~SnapshotGuard(){if(p)dmg_snapshot_release(p);}};
struct InputArgument{std::filesystem::path path;const char* role;bool allow_empty;};
struct StartOptions{std::vector<InputArgument> inputs;bool background=false,complete=false,identity_equality=false,identity_in=false;uint64_t max_input=max_dex,owned_budget=512u<<20,sqlite_heap=0;};
std::string path_utf8(const std::filesystem::path& p){const auto value=p.u8string();return {reinterpret_cast<const char*>(value.data()),value.size()};}
StartOptions parse_start(const std::vector<std::filesystem::path>& argv){
 StartOptions out;bool background_seen=false,scope_seen=false,input_seen=false,budget_seen=false,heap_seen=false;
 for(size_t i=1;i<argv.size();++i){const auto value=path_utf8(argv[i]);
  auto next=[&]()->const std::filesystem::path&{require(i+1<argv.size(),"missing startup option value");return argv[++i];};
  auto mib=[&](){const auto raw=path_utf8(next());uint64_t n=0;auto [end,error]=std::from_chars(raw.data(),raw.data()+raw.size(),n);require(error==std::errc{}&&end==raw.data()+raw.size()&&n>=1&&n<=4096,"MiB limit outside 1..4096");return n*(1u<<20);};
  if(value=="--background"){require(!background_seen,"duplicate background option");background_seen=true;out.background=true;}
  else if(value=="--scope-complete"||value=="--scope-incomplete"){require(!scope_seen,"duplicate scope option");scope_seen=true;out.complete=value=="--scope-complete";}
  else if(value=="--max-input-mib"){require(!input_seen,"duplicate input limit");input_seen=true;out.max_input=mib();}
  else if(value=="--budget-mib"){require(!budget_seen,"duplicate engine limit");budget_seen=true;out.owned_budget=mib();}
  else if(value=="--sqlite-heap-mib"){require(!heap_seen,"duplicate SQLite heap limit");heap_seen=true;out.sqlite_heap=mib();}
  else if(value=="--sql-identity-equality"){require(!out.identity_equality,"duplicate SQL identity equality");out.identity_equality=true;}
  else if(value=="--sql-identity-in"){require(!out.identity_in,"duplicate SQL identity IN");out.identity_in=true;}
  else if(value=="--source"||value=="--resource-source"){require(!out.inputs.empty()&&out.inputs.size()<64,"primary input required and at most 64 inputs");out.inputs.push_back({next(),value=="--resource-source"?"resource-split":"code-split",value=="--resource-source"});}
  else{require(!value.empty()&&value.rfind("--",0)!=0&&out.inputs.empty(),"unexpected startup argument");out.inputs.push_back({argv[i],"raw",false});}
 }
 require(!out.inputs.empty(),"input required");require(!out.identity_in||out.identity_equality,"SQL identity IN requires equality planning");return out;
}
int run(const StartOptions& args){
 const bool background=args.background;EngineGuard engine;SnapshotGuard snapshot;dmg_error error{};
 dmg_engine_options engine_options{};engine_options.struct_size=sizeof(engine_options);engine_options.abi_version=DMG_ABI_VERSION;engine_options.owned_bytes_limit=args.owned_budget;engine_options.max_source_bytes=args.max_input;engine_options.max_jobs=1;
 require(dmg_engine_create(&engine_options,&engine.p,&error)==DMG_OK,"engine creation failed");
 std::vector<std::vector<uint8_t>> buffers;std::vector<std::string> slots;std::vector<dmg_source_spec> specs;buffers.reserve(args.inputs.size());slots.reserve(args.inputs.size());specs.reserve(args.inputs.size());uint64_t total=0;
 for(size_t i=0;i<args.inputs.size();++i){const auto& input=args.inputs[i];buffers.push_back(load_input(input.path,args.max_input-total));total+=buffers.back().size();slots.push_back(i?"input:"+std::to_string(i)+":"+path_utf8(input.path):"main");
  dmg_source_spec spec{sizeof(spec),DMG_ABI_VERSION,DMG_INPUT_AUTO,input.allow_empty?1u:0u,buffers.back().data(),buffers.back().size(),slots.back().c_str(),input.role,nullptr};specs.push_back(spec);
 }
 dmg_source_set_options options{sizeof(options),DMG_ABI_VERSION,"resident-cli",args.complete?1u:0u,1024,args.max_input};
 require(dmg_snapshot_open_sources(engine.p,specs.data(),static_cast<uint32_t>(specs.size()),&options,&snapshot.p,&error)==DMG_OK,"snapshot open failed");buffers.clear();
 if(args.sqlite_heap)require(configure_private_sqlite_heap(args.sqlite_heap)==SQLITE_OK,"private SQLite heap configuration failed");
 std::unique_ptr<ResidentSession> session;std::unique_ptr<BackgroundSession> worker;
 const SqlPlanningOptions planning{args.identity_equality,args.identity_in};
 if(background)require(BackgroundSession::open(snapshot.p,{16,1u<<20,16u<<20,1u<<20},worker,planning)==SQLITE_OK,"background session open failed");
 else require(ResidentSession::open(snapshot.p,{16,1u<<20,16u<<20,1u<<20},session,planning)==SQLITE_OK,"session open failed");
 dmg_snapshot_release(snapshot.p);snapshot.p=nullptr;dmg_engine_release(engine.p);engine.p=nullptr;
 std::string ready="{\"op\":\"ready\",\"status\":0,\"schema_version\":1,\"source_scope\":\""+std::string(args.complete?"declared_complete":"partial")+"\""+(background?",\"mode\":\"background\"":"");
 if(args.identity_equality)ready+=",\"sql_planning\":{\"metadata_identity_equality\":true,\"metadata_identity_in\":"+std::string(args.identity_in?"true":"false")+"}";
 ready+="}";
 if(!emit(ready))return 3;
 std::string line;
 for(;;){auto state=read_line(line);if(state==Line::end){
   if(background)(void)worker->shutdown(false);
   const int rc=background?worker->close():session->close();
   if(rc!=SQLITE_OK){std::cerr<<"unacknowledged resident tasks at EOF\n";return 2;}return 0;}
  if(state==Line::oversized){if(!emit(response("error",SQLITE_TOOBIG)))return 3;continue;}
  try{
   auto j=dmg_cli::JsonReader(line).parse();require(j.kind==dmg_cli::Json::Kind::object,"object required");const auto op=text(required(j,u"op"));std::string out;out.reserve(256);
   if(op=="submit"){
    keys(j,{u"op",u"sql",u"params",u"max_rows",u"max_bytes",u"max_progress"});auto sql=text(required(j,u"sql"));std::vector<std::string> strings;std::vector<SqlParameter> values;
    if(auto params=optional(j,u"params")){require(params->kind==dmg_cli::Json::Kind::array&&params->array.size()<=256,"invalid parameters");strings.reserve(params->array.size());values.reserve(params->array.size());
     for(const auto& value:params->array){if(value.kind==dmg_cli::Json::Kind::null_value)values.push_back({});else if(value.kind==dmg_cli::Json::Kind::number)values.push_back({SqlParameter::Kind::integer,i64(value),{}});else if(value.kind==dmg_cli::Json::Kind::string){strings.push_back(text(value));values.push_back({SqlParameter::Kind::text,0,strings.back()});}else if(value.kind==dmg_cli::Json::Kind::object){keys(value,{u"integer",u"blob_hex"});require(value.object.size()==1,"parameter needs exactly one tag");if(const auto blob=optional(value,u"blob_hex")){strings.push_back(parse_blob(*blob));values.push_back({SqlParameter::Kind::blob,0,strings.back()});}else values.push_back({SqlParameter::Kind::integer,integer_text(required(value,u"integer")),{}});}else throw ProtocolError("unsupported parameter");}}
    auto rows=get_u64(j,u"max_rows",1000),limit=get_u64(j,u"max_bytes",1u<<20),progress=get_u64(j,u"max_progress",10000);require(limit<=1u<<20,"per-query result limit");uint64_t id=0;int rc=background?worker->submit(sql,values,rows,limit,progress,id):session->submit(sql,values,rows,limit,progress,id);fill_response(out,op,rc,rc==SQLITE_OK?&id:nullptr);
   }else if(op=="run"){keys(j,{u"op"});fill_response(out,op,background?SQLITE_MISUSE:session->run_next());}
   else if(op=="cancel"||op=="ack"||op=="final"){
    keys(j,{u"op",u"id"});auto id=identifier(required(j,u"id"));
    if(op=="cancel")fill_response(out,op,background?worker->cancel(id):session->cancel_queued(id),&id);
    else if(op=="ack")fill_response(out,op,background?worker->acknowledge(id):session->acknowledge(id),&id);
    else{ResidentFinal owned;const ResidentFinal* value=nullptr;int rc;
     if(background){rc=worker->final(id,owned);value=&owned;}else rc=session->final(id,value);
     if(rc!=SQLITE_OK)out=response_id(op,rc,id);else try{out=final_json(*value);}catch(const OutputLimit&){out=response_id(op,SQLITE_TOOBIG,id);}catch(const dmg_cli::JsonError&){out=response_id(op,SQLITE_MISMATCH,id);}}
   }else if(op=="stats"){keys(j,{u"op"});if(background){BackgroundStats stats;int rc=worker->stats(stats);out=rc==SQLITE_OK?stats_json(stats):response(op,rc);}else{ResidentStats stats;int rc=session->stats(stats);out=rc==SQLITE_OK?stats_json(stats):response(op,rc);}}
   else if(op=="shutdown" && background){keys(j,{u"op",u"cancel"});const auto& value=required(j,u"cancel");require(value.kind==dmg_cli::Json::Kind::boolean,"cancel must be boolean");fill_response(out,op,worker->shutdown(value.boolean));}
   else if(op=="close"){
    keys(j,{u"op"});const auto start=std::chrono::steady_clock::now();int rc=background?worker->close():session->close();fill_response(out,op,rc);
    if(rc==SQLITE_OK){uint64_t close_us=0;if(background){const auto elapsed=std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now()-start).count();if(elapsed>0)close_us=static_cast<uint64_t>(elapsed);}else{ResidentStats closed{};if(session->stats(closed)!=SQLITE_OK)return 3;close_us=closed.close_us;}
     // out was reserved before close; this bounded formatting cannot allocate.
     out.pop_back();out.append(",\"close_us\":\"");char digits[32];auto end=std::to_chars(digits,digits+sizeof(digits),close_us);out.append(digits,end.ptr);out.append("\"}");}
    if(!emit(out))return 3;if(rc==SQLITE_OK)return 0;continue;
   }
   else throw ProtocolError("unknown command");
   if(!emit(out))return 3;
  }catch(const std::bad_alloc&){if(!emit("{\"op\":\"error\",\"status\":7}"))return 3;}
   catch(const dmg_cli::JsonError&){if(!emit(response("error",SQLITE_MISUSE)))return 3;}
   catch(const ProtocolError&){if(!emit(response("error",SQLITE_MISUSE)))return 3;}
 }
}
}
int start(const std::vector<std::filesystem::path>& argv){
 try{if(argv.size()==2&&argv[1]==std::filesystem::path("--help")){std::cout<<"usage: dexmeguviz-sql-session [--background] INPUT [--source INPUT] [--resource-source APK] [--scope-complete|--scope-incomplete] [--max-input-mib N] [--budget-mib N] [--sqlite-heap-mib N] [--sql-identity-equality [--sql-identity-in]]\n";return 0;}return run(parse_start(argv));}
 catch(const std::exception& e){std::cerr<<"resident session startup failed: "<<e.what()<<'\n';return 2;}
}
#if defined(_WIN32)
int wmain(int argc,wchar_t** argv){try{std::vector<std::filesystem::path> args;for(int i=0;i<argc;++i)args.emplace_back(argv[i]);return start(args);}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 2;}}
#else
int main(int argc,char** argv){try{std::vector<std::filesystem::path> args;for(int i=0;i<argc;++i)args.emplace_back(argv[i]);return start(args);}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 2;}}
#endif
