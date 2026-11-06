#include "frontend.hpp"
#include "method_tables.hpp"
#include "json.hpp"
#include "sqlite3.h"
#include <charconv>
#include <chrono>
#include <sstream>
#include <streambuf>
#include <stdexcept>

namespace dmg_cli {
namespace {
using namespace dexmeguviz::desktop_sql;
using Clock=std::chrono::steady_clock;
uint64_t elapsed(Clock::time_point from){return std::chrono::duration_cast<std::chrono::microseconds>(Clock::now()-from).count();}
void require(bool value,const char* message){if(!value)throw JsonError(message);}
std::string utf8(std::u16string_view text){
    std::string out;out.reserve(text.size());
    for(size_t i=0;i<text.size();++i){uint32_t c=text[i];
        if(c>=0xd800&&c<=0xdbff){require(i+1<text.size()&&text[i+1]>=0xdc00&&text[i+1]<=0xdfff,"unpaired parameter surrogate");c=0x10000+((c-0xd800)<<10)+(text[++i]-0xdc00);}
        else require(c<0xdc00||c>0xdfff,"unpaired parameter surrogate");
        if(c<0x80)out.push_back(char(c));else if(c<0x800){out.push_back(char(0xc0|(c>>6)));out.push_back(char(0x80|(c&63)));}
        else if(c<0x10000){out.push_back(char(0xe0|(c>>12)));out.push_back(char(0x80|((c>>6)&63)));out.push_back(char(0x80|(c&63)));}
        else{out.push_back(char(0xf0|(c>>18)));out.push_back(char(0x80|((c>>12)&63)));out.push_back(char(0x80|((c>>6)&63)));out.push_back(char(0x80|(c&63)));}
    }return out;
}
int64_t integer(std::string_view text,bool canonical=false){int64_t value=0;auto [p,e]=std::from_chars(text.data(),text.data()+text.size(),value);require(e==std::errc{}&&p==text.data()+text.size(),"invalid int64 SQL parameter");if(canonical)require(std::to_string(value)==text,"noncanonical int64 parameter");return value;}
std::string unhex(const Json& item){require(item.kind==Json::Kind::string&&item.string.size()%2==0,"invalid BLOB tag");auto digit=[](char16_t c){if(c>=u'0'&&c<=u'9')return unsigned(c-u'0');if(c>=u'a'&&c<=u'f')return unsigned(c-u'a'+10);throw JsonError("BLOB requires lowercase hex");};std::string out;out.reserve(item.string.size()/2);for(size_t i=0;i<item.string.size();i+=2)out.push_back(char((digit(item.string[i])<<4)|digit(item.string[i+1])));return out;}
struct Params {std::vector<std::string> bytes;std::vector<SqlParameter> values;};
Params parameters(std::string_view json){
    Params out;if(json.empty())return out;auto parsed=JsonReader(json).parse();require(parsed.kind==Json::Kind::array&&parsed.array.size()<=256,"SQL parameters must be an array of at most 256 values");out.bytes.reserve(parsed.array.size());out.values.reserve(parsed.array.size());
    for(const auto& item:parsed.array){
        if(item.kind==Json::Kind::null_value)out.values.push_back({});
        else if(item.kind==Json::Kind::number)out.values.push_back({SqlParameter::Kind::integer,integer(item.number),{}});
        else if(item.kind==Json::Kind::string){out.bytes.push_back(utf8(item.string));out.values.push_back({SqlParameter::Kind::text,0,out.bytes.back()});}
        else if(item.kind==Json::Kind::object&&item.object.size()==1){const auto& [key,value]=*item.object.begin();
            if(key==u"integer"){require(value.kind==Json::Kind::string,"integer tag needs text");out.values.push_back({SqlParameter::Kind::integer,integer(utf8(value.string),true),{}});}
            else if(key==u"blob_hex"){out.bytes.push_back(unhex(value));out.values.push_back({SqlParameter::Kind::blob,0,out.bytes.back()});}
            else throw JsonError("unsupported SQL parameter tag");
        }else throw JsonError("unsupported SQL parameter value");
    }return out;
}
class Buffer:public std::streambuf {
public:std::string value;
protected:std::streamsize xsputn(const char* text,std::streamsize n)override{if(n<0||uint64_t(n)>(8u<<20)-value.size())throw SqlOutputLimit{};value.append(text,size_t(n));return n;}
    int_type overflow(int_type c)override{if(traits_type::eq_int_type(c,traits_type::eof()))return traits_type::not_eof(c);const char ch=traits_type::to_char_type(c);xsputn(&ch,1);return c;}
};
void quoted_text(std::ostream& out,std::string_view input){
    constexpr char hex[]="0123456789abcdef";out.put('"');
    for(size_t i=0;i<input.size();){const auto c=static_cast<uint8_t>(input[i]);
        if(c<0x80){if(c=='"'||c=='\\'){out.put('\\');out.put(char(c));}else if(c<0x20){const char escaped[]={'\\','u','0','0',hex[c>>4],hex[c&15]};out.write(escaped,6);}else out.put(char(c));++i;continue;}
        uint32_t scalar=0,minimum=0;size_t count=0;
        if(c>=0xc2&&c<=0xdf){scalar=c&31;minimum=0x80;count=2;}else if(c>=0xe0&&c<=0xef){scalar=c&15;minimum=0x800;count=3;}else if(c>=0xf0&&c<=0xf4){scalar=c&7;minimum=0x10000;count=4;}else throw JsonError("invalid UTF-8 in SQL result");
        require(count<=input.size()-i,"truncated UTF-8 in SQL result");for(size_t k=1;k<count;++k){const auto b=static_cast<uint8_t>(input[i+k]);require((b&0xc0)==0x80,"invalid UTF-8 continuation");scalar=(scalar<<6)|(b&63);}
        require(scalar>=minimum&&scalar<=0x10ffff&&(scalar<0xd800||scalar>0xdfff),"invalid Unicode scalar in SQL result");out.write(input.data()+i,static_cast<std::streamsize>(count));i+=count;
    }out.put('"');
}
void sql_value(std::ostream& out,const SqlValue& value){
    if(value.kind==SqlValue::Kind::null)out<<"null";
    else if(value.kind==SqlValue::Kind::integer)out<<"{\"integer\":\""<<value.integer<<"\"}";
    else if(value.kind==SqlValue::Kind::text)quoted_text(out,value.text);
    else if(value.kind==SqlValue::Kind::blob){constexpr char digits[]="0123456789abcdef";out<<"{\"blob_hex\":\"";for(unsigned char c:value.text)out<<digits[c>>4]<<digits[c&15];out<<"\"}";}
    else throw std::logic_error("SQL result kind");
}
int exit_for(int status){if(status==SQLITE_OK)return 0;if(status==SQLITE_NOMEM||status==SQLITE_TOOBIG||status==SQLITE_INTERRUPT||status==SQLITE_FULL)return 3;return status==SQLITE_INTERNAL?4:2;}
}
SqlFrontendResult execute_sql(dmg_snapshot* snapshot,std::string_view sql,std::string_view parameter_json,const SqlFrontendOptions& options){
    require(snapshot&&options.max_rows&&options.max_rows<=100000&&options.max_result_bytes&&options.max_result_bytes<=4u<<20&&options.max_progress_intervals&&options.max_progress_intervals<=1000000&&options.sqlite_heap_bytes&&options.sqlite_heap_bytes<=4096ull*(1u<<20),"SQL frontend limits");
    require(!options.metadata_identity_in||options.metadata_identity_equality,"SQL identity IN requires equality planning");
    const auto params=parameters(parameter_json);dmg_snapshot_overview source{};if(dmg_snapshot_get_overview(snapshot,&source)!=DMG_OK)throw std::runtime_error("snapshot overview");
    int rc=configure_private_sqlite_heap(options.sqlite_heap_bytes);std::unique_ptr<SqlSession> session;const auto open_started=Clock::now();
    if(rc==SQLITE_OK)rc=options.metadata_identity_equality?SqlSession::open_scoped_planned(snapshot,session,{}, {true,options.metadata_identity_in}):SqlSession::open_scoped(snapshot,session);const auto open_us=elapsed(open_started);
    SqlScopedResult result;SqlQueryProfile profile{};bool measured=false;uint64_t close_us=0;int close_status=SQLITE_OK;
    if(rc==SQLITE_OK){rc=session->enable_profiling(true);if(rc==SQLITE_OK)rc=session->query_scoped_bound(sql,params.values,options.max_rows,options.max_result_bytes,result,options.max_progress_intervals);measured=session->last_query_profile(profile)==SQLITE_OK;const auto start=Clock::now();close_status=session->close();close_us=elapsed(start);if(rc==SQLITE_OK&&close_status!=SQLITE_OK)rc=close_status;}
    Buffer buffer;std::ostream out(&buffer);out.exceptions(std::ios::badbit|std::ios::failbit);
    out<<"{\"schema_version\":1,\"command\":\"sql\",\"execution_status\":"<<json_quote_ascii(rc==SQLITE_OK?"Complete":"SQLiteError")<<",\"sqlite_status\":"<<rc<<",\"close_status\":"<<close_status
       <<",\"snapshot_id\":"<<json_quote_ascii(source.snapshot_id)<<",\"source_scope\":"<<json_quote_ascii(source.scope_complete?"declared_complete":"partial")<<",\"input_count\":"<<source.input_count<<",\"source_count\":"<<source.source_count;
    out<<",\"inputs\":[";for(uint32_t i=0;i<source.input_count;++i){dmg_input_info info{};if(dmg_snapshot_get_input_info(snapshot,i,&info)!=DMG_OK)throw std::runtime_error("input info");if(i)out<<',';out<<"{\"index\":"<<i<<",\"slot\":"<<json_quote_utf8(info.slot_key)<<",\"role\":"<<json_quote_utf8(info.role)<<",\"format\":"<<info.format<<",\"sha256\":"<<json_quote_ascii(info.source_sha256)<<",\"source_count\":"<<info.source_count<<'}';}out<<']';
    out<<",\"profile_v1\":{\"producer\":\"desktop-sql\",\"phase\":\"executed\",\"plan\":{\"sql_bytes\":"<<sql.size()<<",\"parameters\":"<<params.values.size()<<",\"max_rows\":"<<options.max_rows<<",\"max_result_bytes\":"<<options.max_result_bytes<<",\"max_progress_intervals\":"<<options.max_progress_intervals<<",\"sqlite_heap_limit_bytes\":"<<options.sqlite_heap_bytes;
    if(options.metadata_identity_equality)out<<",\"metadata_identity_equality\":true,\"metadata_identity_in\":"<<(options.metadata_identity_in?"true":"false");
    out<<"},\"runtime\":{\"source_prepare_us\":"<<options.source_prepare_us<<",\"session_open_us\":"<<open_us<<",\"close_us\":"<<close_us<<",\"query\":";
    if(!measured)out<<"null";else out<<"{\"elapsed_us\":"<<profile.elapsed_us<<",\"prepare_us\":"<<profile.prepare_us<<",\"first_step_us\":"<<profile.first_step_us<<",\"prepare_attempted\":"<<(profile.prepare_attempted?"true":"false")<<",\"prepared\":"<<(profile.prepared?"true":"false")<<",\"first_step_observed\":"<<(profile.first_step_observed?"true":"false")<<",\"progress_callbacks\":"<<profile.progress_callbacks<<",\"rows_staged\":"<<profile.rows_staged<<",\"rows_committed\":"<<profile.rows_committed<<'}';
    out<<"}},\"rows\":[";if(rc==SQLITE_OK)for(size_t i=0;i<result.rows.size();++i){if(i)out<<',';out<<'[';for(size_t j=0;j<result.rows[i].size();++j){if(j)out<<',';sql_value(out,result.rows[i][j]);}out<<']';}out<<"]}\n";
    return {std::move(buffer.value),exit_for(rc)};
}
}
