#include "method_tables.hpp"
#include "dexmeguviz/dexmeguviz.h"
#include "sqlite3.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
using namespace dexmeguviz::desktop_sql;
#define CHECK(x) do { if (!(x)) throw std::runtime_error("line " + std::to_string(__LINE__) + ": " #x); } while (false)
using Result=std::vector<std::vector<std::string>>;
std::vector<uint8_t> load(const std::filesystem::path& p) { std::ifstream in(p,std::ios::binary);CHECK(in.good());return {std::istreambuf_iterator<char>(in),{}}; }
Result read(SqlSession& s,std::string_view query) {
    SqlRows out; auto rc=s.query(query,std::nullopt,10000,1u<<20,out); if(rc!=SQLITE_OK)throw std::runtime_error("query rc "+std::to_string(rc)+": "+std::string(query));
    Result rows;for(const auto& row:out){std::vector<std::string> values;for(const auto& v:row){
        if(v.kind==SqlValue::Kind::null)values.emplace_back("N");else if(v.kind==SqlValue::Kind::integer)values.push_back("I"+std::to_string(v.integer));else values.push_back("T"+v.text);
    }rows.push_back(std::move(values));}return rows;
}
Result plain(sqlite3* db,const std::string& query) {
    sqlite3_stmt* st=nullptr;CHECK(sqlite3_prepare_v2(db,query.c_str(),-1,&st,nullptr)==SQLITE_OK);
    struct Guard{sqlite3_stmt* p;~Guard(){sqlite3_finalize(p);}}g{st};Result rows;int rc;
    while((rc=sqlite3_step(st))==SQLITE_ROW){std::vector<std::string> row;for(int c=0;c<sqlite3_column_count(st);++c){
        auto t=sqlite3_column_type(st,c);if(t==SQLITE_NULL)row.emplace_back("N");else if(t==SQLITE_INTEGER)row.push_back("I"+std::to_string(sqlite3_column_int64(st,c)));
        else {CHECK(t==SQLITE_TEXT);auto p=reinterpret_cast<const char*>(sqlite3_column_text(st,c));auto n=sqlite3_column_bytes(st,c);CHECK(p);row.push_back("T"+std::string(p,static_cast<size_t>(n)));}}
        rows.push_back(std::move(row));}CHECK(rc==SQLITE_DONE);return rows;
}
void insert(sqlite3* db,const std::string& sql,const std::vector<std::string>& row) {
    sqlite3_stmt* st=nullptr;CHECK(sqlite3_prepare_v2(db,sql.c_str(),-1,&st,nullptr)==SQLITE_OK);
    struct Guard{sqlite3_stmt* p;~Guard(){sqlite3_finalize(p);}}g{st};CHECK(sqlite3_bind_parameter_count(st)==int(row.size()));
    for(size_t i=0;i<row.size();++i){const auto& v=row[i];CHECK(!v.empty());int rc;
        if(v[0]=='N')rc=sqlite3_bind_null(st,int(i+1));else if(v[0]=='I')rc=sqlite3_bind_int64(st,int(i+1),std::stoll(v.substr(1)));
        else {CHECK(v[0]=='T');rc=sqlite3_bind_text(st,int(i+1),v.data()+1,int(v.size()-1),SQLITE_TRANSIENT);}CHECK(rc==SQLITE_OK);}
    CHECK(sqlite3_step(st)==SQLITE_DONE);
}
std::string integer(uint64_t x){return "I"+std::to_string(x);} std::string text(const char* p){CHECK(p);return "T"+std::string(p);}
std::string hex(const char* p){static const char digits[]="0123456789abcdef";std::string r="T";for(;*p;++p){auto c=static_cast<unsigned char>(*p);r+=digits[c>>4];r+=digits[c&15];}return r;}
void emit(const char* tag,const Result& rows){for(const auto& row:rows){std::cout<<tag;for(const auto& v:row)std::cout<<'\t'<<v;std::cout<<'\n';}}
int main(int argc,char** argv){try{
    CHECK(argc==2);const std::filesystem::path root(argv[1]);auto a=load(root/"raw-a.dex"),resource=load(root/"resource-only.apk"),apk=load(root/"reverse-deflate.apk");
    dmg_engine* e=nullptr;dmg_error error{};CHECK(dmg_engine_create(nullptr,&e,&error)==DMG_OK);struct EG{dmg_engine* p;~EG(){dmg_engine_release(p);}}eg{e};
    const char* sha="dd0e9527dda007481637b6b43393a8239635e85fa006b452092dcc064c3e456f";
    dmg_source_spec inputs[]{
      {sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,a.data(),a.size(),"base","baseRole",sha},
      {sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,a.data(),a.size(),"duplicate","splitRole",nullptr},
      {sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_APK,1,resource.data(),resource.size(),"resource","assets",nullptr},
      {sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_APK,0,apk.data(),apk.size(),"apk","code",nullptr}};
    dmg_source_set_options opts{sizeof(dmg_source_set_options),DMG_ABI_VERSION,"catalog",1,16,8u<<20};dmg_snapshot* snap=nullptr;
    CHECK(dmg_snapshot_open_sources(e,inputs,4,&opts,&snap,&error)==DMG_OK);struct SG{dmg_snapshot* p;~SG(){if(p)dmg_snapshot_release(p);}}sg{snap};
    dmg_snapshot_overview ov{};CHECK(dmg_snapshot_get_overview(snap,&ov)==DMG_OK);CHECK(ov.input_count==4&&ov.source_count==5&&ov.scope_complete==1);
    std::unique_ptr<SqlSession> session;CHECK(SqlSession::open(snap,session)==SQLITE_OK);
    sqlite3* db=nullptr;CHECK(sqlite3_open(":memory:",&db)==SQLITE_OK);struct DG{sqlite3* p;~DG(){sqlite3_close(p);}}dg{db};
    CHECK(sqlite3_exec(db,"CREATE TABLE snap(snapshot_id TEXT,namespace_key TEXT,namespace_hex TEXT,scope_complete INTEGER,input_count INTEGER,source_count INTEGER,input_bytes INTEGER,dex_bytes INTEGER,string_count INTEGER,type_count INTEGER,class_count INTEGER,method_ref_count INTEGER,method_definition_count INTEGER); CREATE TABLE inp(input_index INTEGER,format INTEGER,slot TEXT,role TEXT,slot_hex TEXT,role_hex TEXT,source_sha256 TEXT,content_id TEXT,input_bytes INTEGER,source_count INTEGER,allow_no_dex INTEGER,expected_digest_verified INTEGER,container_metadata_checked INTEGER); CREATE TABLE src(source_index INTEGER,input_index INTEGER,slot TEXT,role TEXT,slot_hex TEXT,role_hex TEXT,source_sha256 TEXT,content_id TEXT,occurrence_id TEXT,logical_dex_id TEXT,dex_bytes INTEGER,dex_version INTEGER,archive_sha256 TEXT,archive_entry_name TEXT,archive_entry_index INTEGER,crc_verified INTEGER,header_consistency_verified INTEGER,expected_digest_verified INTEGER)",nullptr,nullptr,nullptr)==SQLITE_OK);
    insert(db,"INSERT INTO snap VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",{text(ov.snapshot_id),"Tcatalog",hex("catalog"),integer(ov.scope_complete),integer(ov.input_count),integer(ov.source_count),integer(ov.input_bytes),integer(ov.dex_bytes),integer(ov.string_count),integer(ov.type_count),integer(ov.class_count),integer(ov.method_ref_count),integer(ov.method_def_count)});
    for(uint32_t i=0;i<ov.input_count;++i){dmg_input_info x{};CHECK(dmg_snapshot_get_input_info(snap,i,&x)==DMG_OK);
        insert(db,"INSERT INTO inp VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",{integer(i),integer(x.format),text(x.slot_key),text(x.role),hex(x.slot_key),hex(x.role),text(x.source_sha256),text(x.content_id),integer(x.input_bytes),integer(x.source_count),integer(x.allow_no_dex),integer(x.expected_digest_verified),integer(x.container_metadata_checked)});}
    for(uint32_t i=0;i<ov.source_count;++i){dmg_source_info x{};CHECK(dmg_snapshot_get_source_info(snap,i,&x)==DMG_OK);const bool archive=x.archive_entry_index!=UINT32_MAX;
        insert(db,"INSERT INTO src VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",{integer(i),integer(x.input_index),text(x.slot_key),text(x.role),hex(x.slot_key),hex(x.role),text(x.dex.source_sha256),text(x.dex.content_id),text(x.dex.occurrence_id),text(x.logical_dex_id),integer(x.dex.source_bytes),integer(x.dex.dex_version),archive?text(x.archive_sha256):"N",archive?text(x.archive_entry_name):"N",archive?integer(x.archive_entry_index):"N",integer(x.crc_verified),integer(x.header_consistency_verified),integer(x.expected_digest_verified)});}
    const std::vector<std::pair<std::string,std::string>> checks{
      {"SELECT * FROM dmg_snapshot","SELECT * FROM snap"},
      {"SELECT * FROM dmg_inputs ORDER BY input_index","SELECT * FROM inp ORDER BY input_index"},
      {"SELECT * FROM dmg_sources ORDER BY source_index","SELECT * FROM src ORDER BY source_index"},
      {"SELECT i.slot,s.archive_entry_name FROM dmg_inputs i LEFT JOIN dmg_sources s ON i.input_index=s.input_index ORDER BY i.input_index,s.source_index","SELECT i.slot,s.archive_entry_name FROM inp i LEFT JOIN src s ON i.input_index=s.input_index ORDER BY i.input_index,s.source_index"},
      {"SELECT input_index FROM dmg_inputs WHERE input_index IN (0,0,NULL,2) ORDER BY input_index DESC LIMIT 2","SELECT input_index FROM inp WHERE input_index IN (0,0,NULL,2) ORDER BY input_index DESC LIMIT 2"},
      {"SELECT count(*),sum(source_count),sum(archive_entry_index IS NULL) FROM dmg_inputs LEFT JOIN dmg_sources USING(input_index)","SELECT count(*),sum(source_count),sum(archive_entry_index IS NULL) FROM inp LEFT JOIN src USING(input_index)"},
      {"SELECT source_index,ordinal FROM dmg_sources JOIN dmg_method_defs USING(source_index) ORDER BY source_index,ordinal","SELECT source_index,ordinal FROM src JOIN (SELECT 0 AS source_index,0 AS ordinal UNION ALL SELECT 0,1 UNION ALL SELECT 1,0 UNION ALL SELECT 1,1 UNION ALL SELECT 2,0 UNION ALL SELECT 2,1 UNION ALL SELECT 3,0 UNION ALL SELECT 3,1 UNION ALL SELECT 4,0 UNION ALL SELECT 4,1) USING(source_index) ORDER BY source_index,ordinal"}};
    for(size_t i=0;i<checks.size();++i)CHECK(read(*session,checks[i].first)==plain(db,checks[i].second));
    CHECK(read(*session,"SELECT rowid,input_index FROM dmg_inputs ORDER BY rowid")==Result({{"I0","I0"},{"I1","I1"},{"I2","I2"},{"I3","I3"}}));
    CHECK(read(*session,"SELECT rowid,source_index FROM dmg_sources ORDER BY rowid")==Result({{"I0","I0"},{"I1","I1"},{"I2","I2"},{"I3","I3"},{"I4","I4"}}));
    auto plan=read(*session,"EXPLAIN QUERY PLAN SELECT slot FROM dmg_inputs ORDER BY slot DESC");bool ordered=false;for(const auto& row:plan)if(row.size()>3&&row[3].find("USE TEMP B-TREE")!=std::string::npos)ordered=true;CHECK(ordered);
    emit("SNAP",read(*session,"SELECT * FROM dmg_snapshot"));emit("INPUT",read(*session,"SELECT * FROM dmg_inputs ORDER BY input_index"));emit("SOURCE",read(*session,"SELECT * FROM dmg_sources ORDER BY source_index"));
    CHECK(session->close()==SQLITE_OK);
    // C source identity accepts arbitrary bytes. TEXT is guarded, hex remains lossless.
    const char invalid_slot[]{char(0xc0),char(0x80),0}, invalid_role[]{char(0xed),char(0xa0),char(0x80),0}, invalid_ns[]{char(0xff),0};
    dmg_source_spec invalid{sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,a.data(),a.size(),invalid_slot,invalid_role,nullptr};opts.source_namespace=invalid_ns;
    dmg_snapshot* bad=nullptr;CHECK(dmg_snapshot_open_sources(e,&invalid,1,&opts,&bad,&error)==DMG_OK);SG bad_guard{bad};std::unique_ptr<SqlSession> bad_session;CHECK(SqlSession::open(bad,bad_session)==SQLITE_OK);
    CHECK(read(*bad_session,"SELECT namespace_hex FROM dmg_snapshot")==Result({{"Tff"}}));
    CHECK(read(*bad_session,"SELECT slot_hex,role_hex FROM dmg_inputs")==Result({{"Tc080","Teda080"}}));
    SqlRows out{{SqlValue{SqlValue::Kind::text,0,"unchanged"}}};const auto saved=out;
    CHECK(bad_session->query("SELECT slot FROM dmg_inputs",std::nullopt,100,1u<<20,out)==SQLITE_MISMATCH&&out==saved);
    CHECK(bad_session->query("SELECT role FROM dmg_sources",std::nullopt,100,1u<<20,out)==SQLITE_MISMATCH&&out==saved);
    CHECK(bad_session->query("SELECT namespace_key FROM dmg_snapshot",std::nullopt,100,1u<<20,out)==SQLITE_MISMATCH&&out==saved);
    CHECK(read(*bad_session,"SELECT slot_hex,role_hex FROM dmg_sources")==Result({{"Tc080","Teda080"}}));
    CHECK(bad_session->close()==SQLITE_OK);
    // Exact UTF-8 values preserve BOM scalar and a supplementary character.
    const char unicode_slot[]{char(0xef),char(0xbb),char(0xbf),'s',0};
    const char unicode_role[]{char(0xef),char(0xbf),char(0xbe),char(0xf0),char(0x9f),char(0x98),char(0x80),0};
    dmg_source_spec unicode{sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,a.data(),a.size(),unicode_slot,unicode_role,nullptr};
    opts.source_namespace="catalog";dmg_snapshot* us=nullptr;CHECK(dmg_snapshot_open_sources(e,&unicode,1,&opts,&us,&error)==DMG_OK);SG ug{us};std::unique_ptr<SqlSession> unicode_session;CHECK(SqlSession::open(us,unicode_session)==SQLITE_OK);
    CHECK(read(*unicode_session,"SELECT slot,role,slot_hex,role_hex FROM dmg_inputs")==Result({{text(unicode_slot),text(unicode_role),"Tefbbbf73","Tefbfbef09f9880"}}));
    CHECK(unicode_session->close()==SQLITE_OK);
    // Invalid leading bytes, continuation, overlong sequences and out-of-range scalars reject only TEXT access.
    const std::vector<std::string> malformed{std::string("\x80",1),std::string("\xe2\x82",2),std::string("\xe2\x28\xa1",3),std::string("\xe0\x80\x80",3),std::string("\xf4\x90\x80\x80",4)};
    for(const auto& value:malformed){dmg_source_spec input{sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,a.data(),a.size(),value.c_str(),"r",nullptr};
        dmg_snapshot* item=nullptr;CHECK(dmg_snapshot_open_sources(e,&input,1,&opts,&item,&error)==DMG_OK);SG item_guard{item};std::unique_ptr<SqlSession> item_session;CHECK(SqlSession::open(item,item_session)==SQLITE_OK);
        CHECK(read(*item_session,"SELECT slot_hex FROM dmg_inputs")==Result({{hex(value.c_str())}}));
        CHECK(item_session->query("SELECT slot FROM dmg_inputs",std::nullopt,100,1u<<20,out)==SQLITE_MISMATCH&&out==saved);
        CHECK(item_session->close()==SQLITE_OK);}
    std::string long_slot(4096,'x');dmg_source_spec long_input{sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,a.data(),a.size(),long_slot.c_str(),"r",nullptr};
    dmg_snapshot* long_snap=nullptr;CHECK(dmg_snapshot_open_sources(e,&long_input,1,&opts,&long_snap,&error)==DMG_OK);SG long_guard{long_snap};std::unique_ptr<SqlSession> long_session;CHECK(SqlSession::open(long_snap,long_session)==SQLITE_OK);
    CHECK(long_session->query("SELECT slot FROM dmg_inputs",std::nullopt,100,1024,out)==SQLITE_TOOBIG&&out==saved);
    CHECK(long_session->query("SELECT slot_hex FROM dmg_inputs",std::nullopt,100,1024,out)==SQLITE_TOOBIG&&out==saved);CHECK(long_session->close()==SQLITE_OK);
    opts.source_namespace="catalog";opts.scope_complete=0;dmg_snapshot* incomplete=nullptr;CHECK(dmg_snapshot_open_sources(e,inputs,1,&opts,&incomplete,&error)==DMG_OK);SG ig{incomplete};std::unique_ptr<SqlSession> rejected;CHECK(SqlSession::open(incomplete,rejected)==SQLITE_MISUSE&&!rejected);
    opts.scope_complete=1;dmg_snapshot* empty=nullptr;CHECK(dmg_snapshot_open_sources(e,&inputs[2],1,&opts,&empty,&error)==DMG_OK);SG empty_guard{empty};std::unique_ptr<SqlSession> empty_session;CHECK(SqlSession::open(empty,empty_session)==SQLITE_OK);
    CHECK(read(*empty_session,"SELECT count(*) FROM dmg_inputs")==Result({{"I1"}}));CHECK(read(*empty_session,"SELECT count(*) FROM dmg_sources")==Result({{"I0"}}));CHECK(empty_session->close()==SQLITE_OK);
    std::cout<<"PASS source catalog: occurrence/input separation, resource-only, NULL, invalid UTF-8, ordinary SQLite\n";return 0;
}catch(const std::exception& x){std::cerr<<x.what()<<'\n';return 1;}}

