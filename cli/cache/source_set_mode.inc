// Desktop-only SourceSet adapter. Includes private runtime details intentionally;
// this is not a public ABI or a claim that snapshot source/loader is authenticated.
struct FileSourceSetInput {
    std::filesystem::path path;
    std::string slot,role,expected;
    uint32_t format=0;
    bool allow_no_dex=false;
    std::vector<uint8_t> bytes;
};
std::string utf8_ascii(const dmg_cli::Json& v,const char* label){
    if(v.kind!=dmg_cli::Json::Kind::string||v.string.empty()||v.string.size()>4096)throw std::runtime_error(std::string(label)+" requires bounded nonempty ASCII string");
    std::string out;out.reserve(v.string.size());for(auto c:v.string){if(c==0||c>127)throw std::runtime_error(std::string(label)+" requires non-NUL ASCII");out.push_back(static_cast<char>(c));}return out;
}
void known_keys(const dmg_cli::Json& v,std::initializer_list<std::u16string_view> keys){
    if(v.kind!=dmg_cli::Json::Kind::object)throw std::runtime_error("SourceSet object required");
    for(const auto& [key,_]:v.object)if(std::find(keys.begin(),keys.end(),std::u16string_view(key))==keys.end())throw std::runtime_error("unknown SourceSet field");
}
const dmg_cli::Json& required(const dmg_cli::Json& v,std::u16string_view k){auto p=field(v,k);if(!p)throw std::runtime_error("required SourceSet field missing");return *p;}
int run_sources(const std::vector<std::filesystem::path>& args){
    if(args.size()!=5)throw std::runtime_error("usage: dexmeguviz_cache_sources CACHE_DIR QUERY.json SYMBOL.json SOURCES.json");
    const auto query_data=file(args[2],65536),symbol_data=file(args[3],65536),source_data=file(args[4],65536);
    BoundedMemory memory;cache::PersistentFacts disk(args[1]);
    const auto plan=query::compile({reinterpret_cast<const char*>(query_data.data()),query_data.size()},&memory,&memory);
    const auto symbol_spec=dmg_cli::JsonReader({reinterpret_cast<const char*>(symbol_data.data()),symbol_data.size()}).parse();
    if(symbol_spec.kind!=dmg_cli::Json::Kind::object)throw std::runtime_error("symbol object required");
    const auto owner=symbol(symbol_spec,u"owner"),name=symbol(symbol_spec,u"name"),proto=symbol(symbol_spec,u"prototype");
    const auto model=ascii(symbol_spec,u"model","static-method-symbol-v1");
    if(field(symbol_spec,u"snapshot_id"))throw std::runtime_error("snapshot_id is obtained from the opened SourceSet; manual value prohibited");
    const auto input=dmg_cli::JsonReader({reinterpret_cast<const char*>(source_data.data()),source_data.size()}).parse();
    known_keys(input,{u"schema_version",u"namespace",u"scope_complete",u"inputs"});
    const auto& version=required(input,u"schema_version");if(version.kind!=dmg_cli::Json::Kind::number||version.number!="1")throw std::runtime_error("SourceSet schema version");
    const auto name_space=utf8_ascii(required(input,u"namespace"),"namespace");
    const auto& full=required(input,u"scope_complete");if(full.kind!=dmg_cli::Json::Kind::boolean)throw std::runtime_error("SourceSet scope_complete boolean required");
    if(auto p=field(symbol_spec,u"namespace"))if(utf8_ascii(*p,"namespace")!=name_space)throw std::runtime_error("symbol namespace mismatch");
    if(auto p=field(symbol_spec,u"complete"))if(p->kind!=dmg_cli::Json::Kind::boolean||p->boolean!=full.boolean)throw std::runtime_error("symbol scope mismatch");
    const auto& in=required(input,u"inputs");if(in.kind!=dmg_cli::Json::Kind::array||in.array.empty()||in.array.size()>8)throw std::runtime_error("SourceSet requires 1..8 inputs");
    std::vector<FileSourceSetInput> files;files.reserve(in.array.size());uint64_t total=0;
    for(size_t i=0;i<in.array.size();++i){const auto& item=in.array[i];known_keys(item,{u"path",u"slot",u"role",u"format",u"expected_sha256"});
        const auto& p=required(item,u"path");if(p.kind!=dmg_cli::Json::Kind::string||p.string.empty()||p.string.size()>4096||std::find(p.string.begin(),p.string.end(),u'\0')!=p.string.end())throw std::runtime_error("invalid input path");
        FileSourceSetInput f;f.path=std::filesystem::path(p.string);if(f.path.is_relative())f.path=args[4].parent_path()/f.path;f.path=f.path.lexically_normal();
        f.slot=utf8_ascii(required(item,u"slot"),"slot");f.role=utf8_ascii(required(item,u"role"),"role");const auto format=utf8_ascii(required(item,u"format"),"format");
        if(i==0?f.role!="base":(f.role!="code-split"&&f.role!="resource-split"))throw std::runtime_error("source role/order mismatch");
        f.allow_no_dex=f.role=="resource-split";
        if(format=="raw"){if(f.allow_no_dex)throw std::runtime_error("resource split must be APK");f.format=DMG_INPUT_RAW_DEX;}
        else if(format=="apk")f.format=DMG_INPUT_APK;else throw std::runtime_error("explicit raw or apk format required");
        if(auto e=field(item,u"expected_sha256")){f.expected=utf8_ascii(*e,"expected_sha256");if(f.expected.size()!=64||!std::all_of(f.expected.begin(),f.expected.end(),[](char c){return (c>='0'&&c<='9')||(c>='a'&&c<='f');}))throw std::runtime_error("invalid expected SHA256");}
        const auto remaining=static_cast<size_t>((128uLL<<20)-total);f.bytes=file(f.path,std::min<size_t>(64u<<20,remaining));total+=f.bytes.size();files.push_back(std::move(f));
    }
    dmg_engine_options eo{};eo.struct_size=sizeof(eo);eo.abi_version=DMG_ABI_VERSION;eo.owned_bytes_limit=512uLL<<20;eo.max_source_bytes=128uLL<<20;eo.max_jobs=1;
    dmg_engine* raw_engine=nullptr;dmg_error error{};auto status=dmg_engine_create(&eo,&raw_engine,&error);if(status!=DMG_OK)throw std::runtime_error("engine create status "+std::to_string(status));
    std::unique_ptr<dmg_engine,decltype(&dmg_engine_release)> engine(raw_engine,&dmg_engine_release);
    std::vector<dmg_source_spec> specs;specs.reserve(files.size());
    for(auto& f:files){dmg_source_spec s{};s.struct_size=sizeof(s);s.abi_version=DMG_ABI_VERSION;s.format=f.format;s.allow_no_dex=f.allow_no_dex?1:0;s.data=f.bytes.data();s.size=f.bytes.size();s.slot_key=f.slot.c_str();s.role=f.role.c_str();s.expected_sha256=f.expected.empty()?nullptr:f.expected.c_str();specs.push_back(s);}
    dmg_source_set_options opt{};opt.struct_size=sizeof(opt);opt.abi_version=DMG_ABI_VERSION;opt.source_namespace=name_space.c_str();opt.scope_complete=full.boolean?1:0;opt.max_sources=64;opt.max_total_dex_bytes=256uLL<<20;
    dmg_snapshot* raw_snapshot=nullptr;status=dmg_snapshot_open_sources(engine.get(),specs.data(),static_cast<uint32_t>(specs.size()),&opt,&raw_snapshot,&error);
    if(status!=DMG_OK)throw std::runtime_error("SourceSet open status "+std::to_string(status)+": "+error.message);
    std::unique_ptr<dmg_snapshot,decltype(&dmg_snapshot_release)> snapshot(raw_snapshot,&dmg_snapshot_release);
    // Single-threaded tool owns the open snapshot throughout resolution/execution.
    const auto dataset=snapshot->dataset;if(!dataset||dataset->snapshot_id.empty())throw std::runtime_error("missing opened snapshot identity");
    std::vector<reference::SourceView> views;std::vector<std::string_view> slots;std::vector<cache::ScopeSource> dependencies;
    views.reserve(dataset->sources.size());slots.reserve(dataset->inputs.size());dependencies.reserve(dataset->sources.size());
    for(const auto& input_record:dataset->inputs)slots.push_back(input_record.slot);
    for(uint32_t i=0;i<dataset->sources.size();++i){const auto& s=*dataset->sources[i];views.push_back({i,s.input_index,&s.facts,s.view()});dependencies.push_back({s.slot_key,s.role,s.view(),&s.facts});}
    const auto resolved=disk.resolve_method({dataset->namespace_key,model,dataset->scope_complete,dependencies,dataset->snapshot_id},owner,name,proto,&memory);const auto before=disk.statistics();
    reference::FactsCache local(views,&memory,0,&disk);reference::Progress progress{};const auto result=reference::execute({views,slots,dataset->scope_complete},plan,progress,&memory,{},{},&local);const auto after=disk.statistics();
    std::cout<<"{\"source_mode\":\"opened-sourceset\",\"snapshot_id\":\""<<dataset->snapshot_id<<"\",\"source_scope_authenticated\":false,\"scope_complete\":"<<(dataset->scope_complete?"true":"false")<<",\"input_count\":"<<dataset->inputs.size()<<",\"source_count\":"<<dataset->sources.size()<<",\"resolution_cache_hit\":"<<(resolved.cache_hit?"true":"false")<<",\"dependency_digest\":\""<<resolved.dependency_digest<<"\",\"definitions\":[";
    bool comma=false;for(auto d:resolved.definitions){if(comma)std::cout<<',';comma=true;std::cout<<"{\"source\":"<<d.source<<",\"ordinal\":"<<d.ordinal<<'}';}
    std::cout<<"],\"query_id\":\""<<plan.id<<"\",\"query_cache_hits\":"<<after.hits-before.hits<<",\"query_cache_rebuilds\":"<<after.rebuilds-before.rebuilds<<",\"work_units\":"<<progress.profile.work_units<<",\"candidates\":[";
    comma=false;for(const auto& row:result.rows){if(comma)std::cout<<',';comma=true;std::cout<<"{\"source\":"<<row.source_index<<",\"ordinal\":"<<row.method_ordinal<<",\"relation\":"<<static_cast<uint32_t>(row.relation)<<'}';}
    std::cout<<"],\"unknown_rows\":"<<progress.profile.unknown_rows<<",\"result_limit\":"<<(result.result_limit?"true":"false")<<",\"cache_rejected\":"<<after.rejected<<",\"cache_write_failures\":"<<after.write_failures<<"}\n";return 0;
}
