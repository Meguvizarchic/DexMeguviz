#include "dexmeguviz/dexmeguviz.h"
#include "json.hpp"
#ifdef DMG_CLI_SQL
#include "sql/frontend.hpp"
#endif
#include <charconv>
#include <chrono>
#include <algorithm>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <streambuf>
#include <string>
#include <string_view>
#include <vector>

namespace {
using dmg_cli::json_quote;
using dmg_cli::json_quote_ascii;

struct CliError : std::runtime_error {
    dmg_status status;
    uint64_t offset;
    CliError(dmg_status code, const std::string& message, uint64_t at = 0)
        : std::runtime_error(message), status(code), offset(at) {}
};
using Snapshot = std::unique_ptr<dmg_snapshot, decltype(&dmg_snapshot_release)>;
using Result = std::unique_ptr<dmg_result, decltype(&dmg_result_release)>;
using CompiledQuery = std::unique_ptr<dmg_query, decltype(&dmg_query_release)>;
using Engine = std::unique_ptr<dmg_engine, decltype(&dmg_engine_release)>;
constexpr uint64_t mebibyte = 1024u * 1024u;
struct SourceArgument {
    std::string path;
    const char* role = "code-split";
    bool allow_no_dex = false;
};
struct Arguments {
    std::string command;
    std::vector<SourceArgument> sources;
    std::string query_path,sql_path,params_path;
    uint64_t sql_max_rows=10000,sql_max_bytes=4u<<20,sql_max_progress=10000,sqlite_heap_bytes=128u<<20;
    std::string expected_sha256;
    uint64_t owned_budget = 512 * mebibyte;
    uint64_t max_input_bytes = 512 * mebibyte;
    bool scope_complete = true;
    bool dex_checksums = false;
    bool sql_identity_equality = false, sql_identity_in = false;
};
uint64_t parse_mib(std::string_view value) {
    if (value.empty()) throw CliError(DMG_INVALID_ARGUMENT, "MiB budget requires a positive decimal integer");
    uint64_t result = 0;
    constexpr uint64_t maximum = std::numeric_limits<uint64_t>::max() / mebibyte;
    for (const char c : value) {
        if (c < '0' || c > '9') throw CliError(DMG_INVALID_ARGUMENT, "MiB budget requires a positive decimal integer");
        const auto digit = static_cast<uint64_t>(c - '0');
        if (result > (maximum - digit) / 10)
            throw CliError(DMG_INVALID_ARGUMENT, "MiB budget overflows uint64 byte count");
        result = result * 10 + digit;
    }
    if (result == 0) throw CliError(DMG_INVALID_ARGUMENT, "MiB budget must be nonzero");
    return result * mebibyte;
}
uint64_t parse_count(std::string_view text,uint64_t maximum){uint64_t n=0;auto [end,error]=std::from_chars(text.data(),text.data()+text.size(),n);if(error!=std::errc{}||end!=text.data()+text.size()||!n||n>maximum)throw CliError(DMG_INVALID_ARGUMENT,"SQL limit outside supported range");return n;}
Arguments parse_arguments(int argc, char** argv) {
    if (argc < 2) throw CliError(DMG_INVALID_ARGUMENT, "Expected inspect/query INPUT or explain --query FILE; see --help");
    Arguments result;result.command=argv[1];const bool explain=result.command=="explain";
    if(!explain&&result.command!="inspect"&&result.command!="query"&&result.command!="sql")throw CliError(DMG_UNSUPPORTED,"Unsupported CLI command");
    if(!explain){if(argc<3||argv[2][0]=='\0')throw CliError(DMG_INVALID_ARGUMENT,"Input path required");result.sources.push_back({argv[2],"base",false});}
#ifndef DMG_CLI_SQL
    if(result.command=="sql")throw CliError(DMG_UNSUPPORTED,"SQL frontend requires a DMG_WITH_SQLITE build");
#endif
    bool sql_rows_seen=false,sql_bytes_seen=false,sql_progress_seen=false,sqlite_heap_seen=false;
    bool json_seen = false, budget_seen = false, input_limit_seen = false, incomplete_seen = false;
    for (int i = explain ? 2 : 3; i < argc; ++i) {
        const std::string_view option = argv[i];
        auto next = [&]() -> std::string {
            if (i+1 >= argc || argv[i+1][0] == '\0')
                throw CliError(DMG_INVALID_ARGUMENT, "Incomplete CLI option");
            return argv[++i];
        };
        if (option == "--json" && !json_seen) json_seen = true;
        else if (option == "--query" && result.query_path.empty()) result.query_path = next();
        else if (option == "--sql-file" && result.sql_path.empty()) result.sql_path = next();
        else if (option == "--params-file" && result.params_path.empty()) result.params_path = next();
        else if (option == "--sql-max-rows" && !sql_rows_seen){result.sql_max_rows=parse_count(next(),100000);sql_rows_seen=true;}
        else if (option == "--sql-max-bytes" && !sql_bytes_seen){result.sql_max_bytes=parse_count(next(),4u<<20);sql_bytes_seen=true;}
        else if (option == "--sql-max-progress" && !sql_progress_seen){result.sql_max_progress=parse_count(next(),1000000);sql_progress_seen=true;}
        else if (option == "--sqlite-heap-mib" && !sqlite_heap_seen){result.sqlite_heap_bytes=parse_count(next(),4096)*mebibyte;sqlite_heap_seen=true;}
        else if (option == "--sql-identity-equality" && !result.sql_identity_equality) result.sql_identity_equality=true;
        else if (option == "--sql-identity-in" && !result.sql_identity_in) result.sql_identity_in=true;
        else if (option == "--source" || option == "--resource-source") {
            if (result.sources.size() == 64)
                throw CliError(DMG_BUDGET_EXCEEDED, "CLI input source count exceeds 64");
            const bool resource = option == "--resource-source";
            result.sources.push_back({next(), resource ? "resource-split" : "code-split", resource});
        } else if (option == "--expected-sha256" && result.expected_sha256.empty()) {
            result.expected_sha256 = next();
            if (result.expected_sha256.size() != 64)
                throw CliError(DMG_INVALID_ARGUMENT, "Expected SHA-256 must contain exactly 64 hexadecimal digits");
            for (char& c : result.expected_sha256) {
                if (c >= 'A' && c <= 'F') c = static_cast<char>(c - 'A' + 'a');
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                    throw CliError(DMG_INVALID_ARGUMENT, "Expected SHA-256 contains a non-hexadecimal digit");
            }
        } else if (option == "--budget-mib" && !budget_seen) {
            result.owned_budget = parse_mib(next()); budget_seen = true;
        } else if (option == "--max-input-mib" && !input_limit_seen) {
            result.max_input_bytes = parse_mib(next()); input_limit_seen = true;
        } else if (option == "--dex-checksums" && !result.dex_checksums) {
            result.dex_checksums = true;
        } else if (option == "--scope-incomplete" && !incomplete_seen) {
            result.scope_complete = false; incomplete_seen = true;
        } else throw CliError(DMG_INVALID_ARGUMENT, "Unknown, duplicate, or incomplete CLI option");
    }
    if ((result.command == "query" || explain) != !result.query_path.empty())
        throw CliError(DMG_INVALID_ARGUMENT, "--query is required for query and explain commands");
    if(explain&&(!result.sources.empty()||input_limit_seen||incomplete_seen||result.dex_checksums||!result.expected_sha256.empty()))throw CliError(DMG_INVALID_ARGUMENT,"explain has no source or runtime scope options");
    if((result.command=="sql")!=!result.sql_path.empty())throw CliError(DMG_INVALID_ARGUMENT,"--sql-file is required only for sql");
    if(result.command!="sql"&&(!result.params_path.empty()||sql_rows_seen||sql_bytes_seen||sql_progress_seen||sqlite_heap_seen||result.sql_identity_equality||result.sql_identity_in))throw CliError(DMG_INVALID_ARGUMENT,"SQL-only option");
    if(result.sql_identity_in&&!result.sql_identity_equality)throw CliError(DMG_INVALID_ARGUMENT,"--sql-identity-in requires --sql-identity-equality");
    if(result.command=="sql"&&result.dex_checksums)throw CliError(DMG_INVALID_ARGUMENT,"use inspect for DEX header checksum diagnostics");
    return result;
}

class OutputBuffer : public std::streambuf {
public:
    static constexpr size_t maximum = 8u * 1024u * 1024u;
    const std::string& bytes() const { return bytes_; }
protected:
    std::streamsize xsputn(const char* data, std::streamsize count) override {
        if (count < 0 || static_cast<uint64_t>(count) > maximum - bytes_.size())
            throw CliError(DMG_BUDGET_EXCEEDED, "CLI JSON output exceeds 8 MiB");
        bytes_.append(data, static_cast<size_t>(count));
        return count;
    }
    int_type overflow(int_type ch) override {
        if (traits_type::eq_int_type(ch, traits_type::eof())) return traits_type::not_eof(ch);
        const char value = traits_type::to_char_type(ch);
        xsputn(&value, 1);
        return ch;
    }
private:
    std::string bytes_;
};

std::vector<uint8_t> read_file(const std::string& path, uint64_t maximum) {
    std::u8string path_utf8;
    path_utf8.reserve(path.size());
    for (const unsigned char byte : path) path_utf8.push_back(static_cast<char8_t>(byte));
    std::ifstream input(std::filesystem::path(path_utf8), std::ios::binary | std::ios::ate);
    if (!input) throw CliError(DMG_INVALID_ARGUMENT, "Cannot open input file");
    const auto end = input.tellg();
    if (end < 0) throw CliError(DMG_INVALID_ARGUMENT, "Cannot determine file size");
    const auto length = static_cast<uint64_t>(end);
    if (length > maximum || length > std::numeric_limits<size_t>::max() ||
        length > static_cast<uint64_t>(std::numeric_limits<std::streamsize>::max()))
        throw CliError(DMG_BUDGET_EXCEEDED, "Input exceeds explicit byte limit or addressable range");
    std::vector<uint8_t> bytes(static_cast<size_t>(length));
    input.seekg(0);
    if (length != 0 && !input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(length)))
        throw CliError(DMG_INVALID_ARGUMENT, "Input changed or could not be read completely");
    char extra;
    if (input.get(extra)) throw CliError(DMG_INVALID_ARGUMENT, "Input size changed while reading");
    if (input.bad()) throw CliError(DMG_INVALID_ARGUMENT, "Input read failed");
    return bytes;
}

std::string quote_units(const uint16_t* data, uint64_t size) {
    std::u16string value;
    value.reserve(static_cast<size_t>(size));
    for (uint64_t i = 0; i < size; ++i) value.push_back(static_cast<char16_t>(data[i]));
    return json_quote(value);
}
const char* coverage_name(uint32_t value) {
    return value == DMG_COVERAGE_COMPLETE ? "Complete" : "Partial";
}
const char* decision_name(uint32_t value) {
    switch (value) {
        case DMG_NOT_APPLICABLE: return "NotApplicable";
        case DMG_UNDETERMINED: return "Undetermined";
        case DMG_PROVEN_FALSE: return "ProvenFalse";
        case DMG_PROVEN_TRUE: return "ProvenTrue";
        default: return "Undetermined";
    }
}
const char* reason_name(uint32_t value) {
    switch (value) {
        case DMG_NO_MATCH: return "NoMatch";
        case DMG_AMBIGUOUS: return "Ambiguous";
        case DMG_WITNESS: return "Witness";
        case DMG_RESULT_LIMIT: return "ResultLimit";
        case DMG_SOURCE_SCOPE_INCOMPLETE: return "SourceScopeIncomplete";
        case DMG_UNKNOWN_ATTRIBUTE: return "UnknownAttribute";
        default: return "None";
    }
}
const char* execution_name(dmg_status value) {
    return value == DMG_OK ? "Complete" : dmg_status_name(value);
}
int exit_code(dmg_status status) {
    if (status == DMG_OK) return 0;
    if (status == DMG_BUDGET_EXCEEDED || status == DMG_OUT_OF_MEMORY ||
        status == DMG_CANCELLED || status == DMG_DEADLINE_EXCEEDED) return 3;
    if (status == DMG_INTERNAL_ERROR) return 4;
    return 2;
}
void metadata_counts(std::ostream& out, uint64_t strings, uint64_t types, uint64_t classes,
                     uint64_t refs, uint64_t definitions) {
    out << "{\"strings\":" << strings << ",\"types\":" << types
        << ",\"classes\":" << classes << ",\"method_refs\":" << refs
        << ",\"method_defs\":" << definitions << '}';
}
const char* format_name(uint32_t format) {
    if (format == DMG_INPUT_RAW_DEX) return "RawDex";
    if (format == DMG_INPUT_APK) return "Apk";
    throw CliError(DMG_INTERNAL_ERROR, "Snapshot contains an unresolved input format");
}
const char* relation_name(uint32_t relation) {
    switch(relation){
        case DMG_METHOD_DEFS:return "method_defs";case DMG_CLASS_DEFS:return "class_defs";
        case DMG_FIELD_DEFS:return "field_defs";case DMG_METHOD_REFS:return "method_refs";
        case DMG_FIELD_REFS:return "field_refs";case DMG_STRING_VALUES:return "string_values";
        case DMG_TYPE_REFS:return "type_refs";
        case DMG_STRING_USES:return "string_uses";case DMG_INVOKE_SITES:return "invoke_sites";case DMG_FIELD_USES:return "field_uses";case DMG_TYPE_USES:return "type_uses";
        default:throw CliError(DMG_INTERNAL_ERROR,"Result contains an unknown relation");
    }
}
void input_json(std::ostream& out, const dmg_input_info& input) {
    out << "{\"input_index\":" << input.input_index
        << ",\"format\":" << json_quote_ascii(format_name(input.format))
        << ",\"slot_key\":" << dmg_cli::json_quote_utf8(input.slot_key)
        << ",\"role\":" << json_quote_ascii(input.role)
        << ",\"source_sha256\":" << json_quote_ascii(input.source_sha256)
        << ",\"content_id\":" << json_quote_ascii(input.content_id)
        << ",\"input_bytes\":" << input.input_bytes
        << ",\"source_count\":" << input.source_count
        << ",\"allow_no_dex\":" << (input.allow_no_dex ? "true" : "false")
        << ",\"expected_digest_verified\":" << (input.expected_digest_verified ? "true" : "false")
        << ",\"container_metadata_checked\":" << (input.container_metadata_checked ? "true" : "false") << '}';
}
void source_json(std::ostream& out, const dmg_source_info& source,uint32_t relation) {
    const auto& dex = source.dex;
    out << "{\"source_index\":" << source.source_index
        << ",\"input_index\":" << source.input_index
        << ",\"slot_key\":" << dmg_cli::json_quote_utf8(source.slot_key)
        << ",\"role\":" << json_quote_ascii(source.role)
        << ",\"source_sha256\":" << json_quote_ascii(dex.source_sha256)
        << ",\"content_id\":" << json_quote_ascii(dex.content_id)
        << ",\"occurrence_id\":" << json_quote_ascii(dex.occurrence_id)
        << ",\"logical_dex_id\":" << json_quote_ascii(source.logical_dex_id)
        << ",\"snapshot_id\":" << json_quote_ascii(dex.snapshot_id)
        << ",\"dex_version\":" << dex.dex_version
        << ",\"source_bytes\":" << dex.source_bytes
        << ",\"archive_sha256\":" << json_quote_ascii(source.archive_sha256)
        << ",\"archive_entry_name\":" << dmg_cli::json_quote_utf8(source.archive_entry_name)
        << ",\"archive_entry_index\":";
    if (source.archive_entry_index == std::numeric_limits<uint32_t>::max()) out << "null";
    else out << source.archive_entry_index;
    out << ",\"crc_verified\":" << (source.crc_verified ? "true" : "false")
        << ",\"header_consistency_verified\":" << (source.header_consistency_verified ? "true" : "false")
        << ",\"expected_digest_verified\":" << (source.expected_digest_verified ? "true" : "false")
        << ",\"local_scope\":{\"relation\":" << json_quote_ascii(relation_name(relation)) << ",\"logical_header_offset\":0,";
    if(relation==DMG_METHOD_DEFS)out<<"\"method_index_domain\":\"logical_dex_id\"";
    else if(relation==DMG_STRING_USES||relation==DMG_INVOKE_SITES||relation==DMG_FIELD_USES||relation==DMG_TYPE_USES)out<<"\"local_index_domain\":\"logical_dex_id,relation,caller_ordinal,dex_pc\"";
    else out<<"\"local_index_domain\":\"logical_dex_id,relation\"";
    out<<"},\"counts\":";
    metadata_counts(out, dex.string_count, dex.type_count, dex.class_count, dex.method_ref_count, dex.method_def_count);
    out << '}';
}
void dataset_json(std::ostream& out, const dmg_snapshot_overview& overview,
                  const dmg_snapshot* snapshot, const dmg_result* result,uint32_t relation=DMG_METHOD_DEFS,bool use_query=false,
                  bool check_dex_checksums=false,uint64_t checksum_input_limit=0,const dmg_expand_info* expand=nullptr) {
    dmg_input_info first_input{};
    if (overview.input_count == 0 || (result ? dmg_result_get_input_info(result, 0, &first_input)
                                           : dmg_snapshot_get_input_info(snapshot, 0, &first_input)) != DMG_OK)
        throw CliError(DMG_INTERNAL_ERROR, "Snapshot input accessor failed");
    const bool single_raw = overview.input_count == 1 && overview.source_count == 1 && first_input.format == DMG_INPUT_RAW_DEX;
    if (single_raw) {
        dmg_source_info source{};
        if ((result ? dmg_result_get_source_info(result, 0, &source) : dmg_snapshot_get_source_info(snapshot, 0, &source)) != DMG_OK)
            throw CliError(DMG_INTERNAL_ERROR, "Snapshot source accessor failed");
        out << ",\"source_sha256\":" << json_quote_ascii(source.dex.source_sha256)
            << ",\"content_id\":" << json_quote_ascii(source.dex.content_id)
            << ",\"occurrence_id\":" << json_quote_ascii(source.dex.occurrence_id)
            << ",\"logical_dex_id\":" << json_quote_ascii(source.logical_dex_id)
            << ",\"dex_version\":" << source.dex.dex_version;
    } else {
        out << ",\"source_sha256\":null,\"content_id\":null,\"occurrence_id\":null,"
               "\"logical_dex_id\":null,\"dex_version\":null";
    }
    out << ",\"snapshot_id\":" << json_quote_ascii(overview.snapshot_id)
        << ",\"scope_complete\":" << (overview.scope_complete ? "true" : "false")
        << ",\"input_count\":" << overview.input_count << ",\"source_count\":" << overview.source_count
        << ",\"input_bytes\":" << overview.input_bytes << ",\"dex_bytes\":" << overview.dex_bytes
        << ",\"source_bytes\":" << overview.dex_bytes << ",\"inputs\":[";
    for (uint32_t index = 0; index < overview.input_count; ++index) {
        dmg_input_info input{};
        if ((result ? dmg_result_get_input_info(result, index, &input) : dmg_snapshot_get_input_info(snapshot, index, &input)) != DMG_OK)
            throw CliError(DMG_INTERNAL_ERROR, "Snapshot input accessor failed");
        if (index) out << ',';
        input_json(out, input);
    }
    out << "],\"sources\":[";
    for (uint32_t index = 0; index < overview.source_count; ++index) {
        dmg_source_info source{};
        if ((result ? dmg_result_get_source_info(result, index, &source) : dmg_snapshot_get_source_info(snapshot, index, &source)) != DMG_OK)
            throw CliError(DMG_INTERNAL_ERROR, "Snapshot source accessor failed");
        if (index) out << ',';
        source_json(out, source,relation);
    }
    out << ']';
    if(check_dex_checksums){
        constexpr char hex[]="0123456789abcdef";
        auto digest_hex=[&](const uint8_t* bytes){std::string value;value.reserve(40);for(size_t i=0;i<20;++i){value.push_back(hex[bytes[i]>>4]);value.push_back(hex[bytes[i]&15]);}return value;};
        out << ",\"dex_checksums\":[";
        for(uint32_t index=0;index<overview.source_count;++index){
            dmg_dex_checksums_v1 value{};
            const auto status=result?dmg_result_check_dex_checksums_v1(result,index,checksum_input_limit,&value,sizeof(value)):
                dmg_snapshot_check_dex_checksums_v1(snapshot,index,checksum_input_limit,&value,sizeof(value));
            if(status!=DMG_OK)throw CliError(status,"DEX checksum check failed");
            if(index)out<<',';
            out<<"{\"source_index\":"<<index<<",\"input_bytes\":"<<value.input_bytes
               <<",\"adler32_expected\":"<<value.adler32_expected<<",\"adler32_actual\":"<<value.adler32_actual
               <<",\"adler32_matches\":"<<(value.adler32_matches?"true":"false")
               <<",\"sha1_expected\":"<<json_quote_ascii(digest_hex(value.sha1_expected).c_str())
               <<",\"sha1_actual\":"<<json_quote_ascii(digest_hex(value.sha1_actual).c_str())
               <<",\"sha1_matches\":"<<(value.sha1_matches?"true":"false")<<'}';
        }
        out<<']';
    }
    dmg_query_profile validation_profile{};
    if(expand)validation_profile=expand->profile;
    else if(result&&dmg_result_get_profile(result,&validation_profile)!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Validation profile accessor failed");
    out << ",\"validation\":{\"metadata_scope\":\"header,id_tables,class_data,type_lists,code_item_bounds,class_topology\","
           "\"metadata_subset_checked\":true,\"instruction_stream\":"
        << json_quote_ascii(validation_profile.methods_decoded?"PerMethodChecked":"NotPerformed")
        << ",\"instruction_methods_checked\":"<<validation_profile.methods_decoded
        << ",\"control_flow\":\"NoCFGOrTypeVerification\",\"checksum\":\"SeePerLayer\",\"dex_checksum\":"
        << json_quote_ascii(check_dex_checksums?"PerSourceCompared":"NotVerified") << ','
        << "\"archive_checks\":\"PerInputAndSource\","
           "\"runtime_binding\":\"NotPerformed\",\"source_revision\":";
    out << json_quote_ascii(single_raw ? (first_input.expected_digest_verified ? "ExpectedDigestVerified" : "Unverified") : "PerInput");
    if(use_query)out<<",\"call_site_target_validation\":\"IndexBoundsOnly\",\"bootstrap\":\"NotParsed\"";
    out << '}';
}
void budget_json(std::ostream& out, const Arguments& args, uint64_t caller_input_peak, const dmg_engine* engine) {
    dmg_engine_stats stats{};
    if (dmg_engine_get_stats(engine, &stats) != DMG_OK)
        throw CliError(DMG_INTERNAL_ERROR, "Engine resource accessor failed");
    out << ",\"budgets\":{\"engine_owned_limit_bytes\":" << args.owned_budget
        << ",\"cli_input_buffer_limit_bytes\":" << args.max_input_bytes
        << ",\"max_single_input_bytes\":" << args.max_input_bytes
        << ",\"max_total_dex_bytes\":" << args.max_input_bytes
        << ",\"caller_input_peak_bytes\":" << caller_input_peak
        << ",\"caller_input_retained_bytes\":0,\"json_output_limit_bytes\":" << OutputBuffer::maximum
        << ",\"limits_process_rss\":false,\"engine_owned_bytes\":" << stats.owned_bytes
        << ",\"engine_peak_owned_bytes\":" << stats.peak_owned_bytes << '}';
}
const char* witness_kind(uint32_t kind){
    switch(kind){case DMG_WITNESS_TYPE_USE:return "type_use";case DMG_WITNESS_STRING:return "string_use";case DMG_WITNESS_INVOKE:return "invoke";case DMG_WITNESS_FIELD:return "field_use";
    case DMG_WITNESS_INHERITED:return "inherited";case DMG_WITNESS_NUMERIC:return "numeric_literal";case DMG_WITNESS_INSTRUCTION_SCOPE:return "instruction_scope";case DMG_WITNESS_NO_BODY:return "no_body";case DMG_WITNESS_STRING_POOL_ABSENCE:return "string_pool_absence";default:return "metadata";}
}
void nullable_id(std::ostream& out,uint32_t value){if(value==UINT32_MAX)out<<"null";else out<<value;}
uint32_t entity_projection(uint32_t relation){
    switch(relation){
        case DMG_METHOD_DEFS:case DMG_METHOD_REFS:return DMG_PROJECT_OWNER|DMG_PROJECT_NAME|DMG_PROJECT_PROTOTYPE;
        case DMG_FIELD_DEFS:case DMG_FIELD_REFS:return DMG_PROJECT_OWNER|DMG_PROJECT_NAME|DMG_PROJECT_TYPE;
        case DMG_CLASS_DEFS:case DMG_TYPE_REFS:return DMG_PROJECT_TYPE;
        case DMG_STRING_VALUES:return DMG_PROJECT_VALUE;
        default:throw CliError(DMG_INTERNAL_ERROR,"Unknown entity projection");
    }
}
void entity_text_json(std::ostream& out,const dmg_entity_row& row,uint32_t projection){
    if(projection&DMG_PROJECT_OWNER)out<<",\"owner\":"<<quote_units(row.owner,row.owner_length);
    if(projection&DMG_PROJECT_NAME)out<<",\"name\":"<<quote_units(row.name,row.name_length);
    if(projection&DMG_PROJECT_PROTOTYPE)out<<",\"prototype\":"<<quote_units(row.prototype,row.prototype_length);
    if(projection&DMG_PROJECT_TYPE)out<<",\"type_descriptor\":"<<quote_units(row.type_descriptor,row.type_descriptor_length);
    if(projection&DMG_PROJECT_VALUE)out<<",\"string_value\":"<<quote_units(row.string_value,row.string_value_length);
}
void entity_fields_json(std::ostream& out,const dmg_entity_row& row,bool include_source=false){
    out<<",\"relation\":"<<json_quote_ascii(relation_name(row.relation));
    if(include_source)out<<",\"source_index\":"<<row.source_index;
    out<<",\"local_index\":"<<row.local_index<<",\"reference_index\":";nullable_id(out,row.reference_index);
    out<<",\"record_offset\":";nullable_id(out,row.record_offset);
    out<<",\"has_local_definition\":"<<(row.definition_known?"true":"false")<<",\"definition_offset\":";
    if(row.definition_known)out<<row.definition_offset;else out<<"null";
    out<<",\"access_flags\":";if(row.flags_known)out<<row.access_flags;else out<<"null";
    out<<",\"code_offset\":";if(row.code_known)out<<row.code_offset;else out<<"null";
}
const char* operator_name(uint32_t op){
    switch(op){
        case DMG_REL_SCAN:return "scan";case DMG_REL_FILTER:return "filter";case DMG_REL_UNION:return "union";
        case DMG_REL_DISTINCT:return "distinct";case DMG_REL_LABEL:return "label";case DMG_REL_GROUP_BY_OWNER:return "group_by_owner";
        case DMG_REL_JOIN:return "join";case DMG_REL_SEMI_JOIN:return "semi_join";
        case DMG_REL_BOUNDED_EXPAND:return "bounded_expand";
        default:throw CliError(DMG_INTERNAL_ERROR,"Unknown relation operator");
    }
}
const char* join_key_name(uint32_t key){
    switch(key){case DMG_JOIN_SAME_ENTITY:return "same_entity";case DMG_JOIN_LOCAL_DEFINITION:return "local_definition";
        case DMG_JOIN_LOCAL_OWNER:return "local_owner";case DMG_JOIN_SYMBOL:return "symbol";
        case DMG_JOIN_CALLER:return "caller";case DMG_JOIN_TARGET_REF:return "target_ref";case DMG_JOIN_TARGET_SYMBOL:return "target_symbol";
        default:throw CliError(DMG_INTERNAL_ERROR,"Unknown join key");}
}
void path_json(std::ostream& out,const dmg_binding_path& path){
    if(path.length&&!path.sides)throw CliError(DMG_INTERNAL_ERROR,"Binding path has no storage");
    out<<'[';for(uint32_t i=0;i<path.length;++i){if(i)out<<',';
        if(path.sides[i]==DMG_PATH_LEFT)out<<"\"L\"";else if(path.sides[i]==DMG_PATH_RIGHT)out<<"\"R\"";
        else throw CliError(DMG_INTERNAL_ERROR,"Unknown binding path side");
    }out<<']';
}
void key_json(std::ostream& out,uint32_t relation,uint32_t source,uint32_t local){
    out<<"{\"relation\":"<<json_quote_ascii(relation_name(relation))<<",\"source_index\":"<<source<<",\"local_index\":"<<local<<'}';
}
bool use_relation(uint32_t relation){return relation==DMG_STRING_USES||relation==DMG_INVOKE_SITES||relation==DMG_FIELD_USES||relation==DMG_TYPE_USES;}
const char* target_domain_name(uint32_t domain){
    switch(domain){case DMG_TARGET_STRING_VALUE:return "string_value";case DMG_TARGET_FIELD_REF:return "field_ref";
    case DMG_TARGET_METHOD_REF:return "method_ref";case DMG_TARGET_METHOD_AND_PROTO:return "method_and_proto";
    case DMG_TARGET_CALL_SITE:return "call_site";case DMG_TARGET_TYPE_REF:return "type_ref";default:throw CliError(DMG_INTERNAL_ERROR,"Unknown use target domain");}
}
void key_json_v2(std::ostream& out,const dmg_value_identity_v2& key){
    if(use_relation(key.relation)==(key.dex_pc==UINT32_MAX))throw CliError(DMG_INTERNAL_ERROR,"Value identity has an invalid PC");
    out<<"{\"relation\":"<<json_quote_ascii(relation_name(key.relation))<<",\"source_index\":"<<key.source_index<<",\"local_index\":"<<key.local_index<<",\"dex_pc\":";
    nullable_id(out,key.dex_pc);out<<'}';
}
uint32_t value_relation(const dmg_value_row_v2& value){
    if(value.kind==DMG_VALUE_ENTITY){if(use_relation(value.entity.relation))throw CliError(DMG_INTERNAL_ERROR,"Entity value contains a use relation");return value.entity.relation;}
    if(value.kind==DMG_VALUE_USE){if(!use_relation(value.use.relation))throw CliError(DMG_INTERNAL_ERROR,"Use value has no use relation");return value.use.relation;}
    throw CliError(DMG_INTERNAL_ERROR,"Unknown tagged value kind");
}
uint32_t value_source(const dmg_value_row_v2& value){
    if(value.kind==DMG_VALUE_ENTITY)return value.entity.source_index;if(value.kind==DMG_VALUE_USE)return value.use.source_index;
    throw CliError(DMG_INTERNAL_ERROR,"Unknown tagged value kind");
}
uint32_t value_projection(const dmg_value_row_v2& value){
    return value.kind==DMG_VALUE_USE?(DMG_PROJECT_OWNER|DMG_PROJECT_NAME|DMG_PROJECT_PROTOTYPE):entity_projection(value_relation(value));
}
struct CliTarget {const uint16_t* data=nullptr;uint64_t size=0;};
dmg_status cli_value(const dmg_result* r,uint32_t row,dmg_value_row_v2* out,CliTarget& target){
    auto status=dmg_result_get_value_v2(r,row,out,sizeof(*out));if(status!=DMG_UNSUPPORTED)return status;
    dmg_value_row_v3 v{};status=dmg_result_get_value_v3(r,row,&v,sizeof(v));if(status==DMG_OK){*out=v.value;target={v.target_descriptor,v.target_descriptor_length};}return status;
}
dmg_status cli_binding(const dmg_result* r,uint32_t row,uint32_t index,dmg_binding_row_v2* out,CliTarget& target){
    auto status=dmg_result_get_binding_v2(r,row,index,out,sizeof(*out));if(status!=DMG_UNSUPPORTED)return status;
    dmg_binding_row_v3 v{};status=dmg_result_get_binding_v3(r,row,index,&v,sizeof(v));if(status==DMG_OK){out->label=v.label;out->value=v.value.value;target={v.value.target_descriptor,v.value.target_descriptor_length};}return status;
}
dmg_status cli_proof(const dmg_result* r,uint32_t row,uint32_t index,dmg_proof_binding_row_v2* out,CliTarget& target){
    auto status=dmg_result_get_proof_binding_v2(r,row,index,out,sizeof(*out));if(status!=DMG_UNSUPPORTED)return status;
    dmg_proof_binding_row_v3 v{};status=dmg_result_get_proof_binding_v3(r,row,index,&v,sizeof(v));if(status==DMG_OK){out->operator_node=v.operator_node;out->binding.label=v.binding.label;out->binding.value=v.binding.value.value;target={v.binding.value.target_descriptor,v.binding.value.target_descriptor_length};}return status;
}
void value_fields_json(std::ostream& out,const dmg_value_row_v2& value,bool include_source,uint32_t projection,bool first=false,CliTarget target={}){
    const auto relation=value_relation(value);
    out<<(first?"\"value_kind\":":",\"value_kind\":")<<json_quote_ascii(value.kind==DMG_VALUE_USE?"use":"entity");
    if(value.kind==DMG_VALUE_ENTITY){
        entity_fields_json(out,value.entity,include_source);out<<",\"dex_pc\":null";
        entity_text_json(out,value.entity,projection);return;
    }
    const auto& use=value.use;
    const bool domain_ok=(relation==DMG_STRING_USES&&use.target_domain==DMG_TARGET_STRING_VALUE)||
        (relation==DMG_FIELD_USES&&use.target_domain==DMG_TARGET_FIELD_REF)||
        (relation==DMG_TYPE_USES&&use.target_domain==DMG_TARGET_TYPE_REF)||
        (relation==DMG_INVOKE_SITES&&(use.target_domain==DMG_TARGET_METHOD_REF||use.target_domain==DMG_TARGET_METHOD_AND_PROTO||use.target_domain==DMG_TARGET_CALL_SITE));
    if(!domain_ok||use.dex_pc==UINT32_MAX||(use.target_domain==DMG_TARGET_METHOD_AND_PROTO)!=(use.extra_proto!=UINT32_MAX))
        throw CliError(DMG_INTERNAL_ERROR,"Use value has an inconsistent reference domain");
    out<<",\"relation\":"<<json_quote_ascii(relation_name(relation));if(include_source)out<<",\"source_index\":"<<use.source_index;
    out<<",\"local_index\":"<<use.caller_ordinal<<",\"caller_ordinal\":"<<use.caller_ordinal<<",\"caller_method_ref\":"<<use.caller_method_ref
       <<",\"dex_pc\":"<<use.dex_pc<<",\"opcode\":"<<use.opcode<<",\"code_offset\":"<<use.code_offset
       <<",\"instruction_offset\":"<<(uint64_t(use.code_offset)+16+uint64_t(use.dex_pc)*2)
       <<",\"target_domain\":"<<json_quote_ascii(target_domain_name(use.target_domain))<<",\"target_index\":"<<use.target_index<<",\"extra_proto\":";
    nullable_id(out,use.extra_proto);
    if(relation==DMG_TYPE_USES)out<<",\"target_descriptor\":"<<quote_units(target.data,target.size);
    if(projection&DMG_PROJECT_OWNER)out<<",\"caller_owner\":"<<quote_units(use.owner,use.owner_length);
    if(projection&DMG_PROJECT_NAME)out<<",\"caller_name\":"<<quote_units(use.name,use.name_length);
    if(projection&DMG_PROJECT_PROTOTYPE)out<<",\"caller_prototype\":"<<quote_units(use.prototype,use.prototype_length);
}
void graph_json(std::ostream& out,const dmg_result* result,const dmg_graph_info& graph){
    if(graph.unique_identity!=DMG_IDENTITY_ENTITY&&graph.unique_identity!=DMG_IDENTITY_TUPLE)
        throw CliError(DMG_INTERNAL_ERROR,"Unknown uniqueness identity");
    out<<",\"relation_profile\":{\"root_node\":"<<graph.root_node<<",\"unique_by\":"
       <<json_quote_ascii(graph.unique_identity==DMG_IDENTITY_ENTITY?"entity":"tuple")
       <<",\"identity_count\":"<<graph.identity_count<<",\"operators\":[";
    for(uint32_t i=0;i<graph.operator_count;++i){
        dmg_operator_profile profile{};
        if(dmg_result_get_operator_profile(result,i,&profile,sizeof(profile))!=DMG_OK)
            throw CliError(DMG_INTERNAL_ERROR,"Operator profile accessor failed");
        if(i)out<<',';
        out<<"{\"node_id\":"<<profile.node_id<<",\"op\":"<<json_quote_ascii(operator_name(profile.op))
           <<",\"input_rows\":"<<profile.input_rows<<",\"output_rows\":"<<profile.output_rows<<",\"unknown_rows\":"<<profile.unknown_rows
           <<",\"visited_rows\":"<<profile.visited_rows<<",\"total_rows\":"<<profile.total_rows<<",\"complete\":"<<(profile.complete?"true":"false")<<'}';
    }
    out<<"]}";
}
const char* scan_domain_name(uint32_t domain){
    switch(domain){case DMG_SCAN_DOMAIN_NONE:return "none";case DMG_SCAN_DOMAIN_ENTITY_RECORDS:return "entity_records";
    case DMG_SCAN_DOMAIN_METHOD_DEFS:return "method_defs";default:throw CliError(DMG_INTERNAL_ERROR,"Unknown operator scan domain");}
}
void graph_json_v2(std::ostream& out,const dmg_result* result,const dmg_graph_info& graph,bool expand=false){
    if(graph.unique_identity!=DMG_IDENTITY_ENTITY&&graph.unique_identity!=DMG_IDENTITY_TUPLE)
        throw CliError(DMG_INTERNAL_ERROR,"Unknown uniqueness identity");
    out<<",\"relation_profile\":{\"root_node\":"<<graph.root_node<<",\"unique_by\":"
       <<json_quote_ascii(graph.unique_identity==DMG_IDENTITY_ENTITY?"entity":"tuple")
       <<",\"identity_count\":"<<graph.identity_count<<",\"operators\":[";
    for(uint32_t i=0;i<graph.operator_count;++i){dmg_operator_profile_v2 profile{};
        if(([&]{if(expand)return dmg_result_get_expand_operator(result,i,&profile,sizeof(profile));auto x=dmg_result_get_operator_profile_v2(result,i,&profile,sizeof(profile));return x==DMG_UNSUPPORTED?dmg_result_get_operator_profile_v3(result,i,&profile,sizeof(profile)):x;})()!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Operator profile v2 accessor failed");
        if(i)out<<',';
        out<<"{\"node_id\":"<<profile.node_id<<",\"op\":"<<json_quote_ascii(operator_name(profile.op))
           <<",\"scan_domain\":"<<json_quote_ascii(scan_domain_name(profile.scan_domain))<<",\"input_rows\":"<<profile.input_rows
           <<",\"output_rows\":"<<profile.output_rows<<",\"unknown_rows\":"<<profile.unknown_rows<<",\"visited\":"<<profile.visited
           <<",\"total\":"<<profile.total<<",\"attempted_methods\":"<<profile.attempted_methods<<",\"no_body_methods\":"<<profile.no_body_methods
           <<",\"decoded_methods\":"<<profile.decoded_methods<<",\"events_collected\":"<<profile.events_collected<<",\"code_units\":"<<profile.code_units
           <<",\"complete\":"<<(profile.complete?"true":"false")<<'}';
    }out<<"]}";
}
void bindings_json(std::ostream& out,const dmg_result* result,uint32_t row){
    uint32_t count=0;
    if(dmg_result_get_binding_count(result,row,&count)!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Binding count accessor failed");
    out<<",\"bindings\":[";
    for(uint32_t i=0;i<count;++i){
        dmg_binding_row binding{};
        if(dmg_result_get_binding(result,row,i,&binding,sizeof(binding))!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Binding accessor failed");
        if(i)out<<',';out<<"{\"label\":";
        if(binding.label)out<<dmg_cli::json_quote_utf8(binding.label);else out<<"null";
        entity_fields_json(out,binding.entity,true);entity_text_json(out,binding.entity,entity_projection(binding.entity.relation));
        dmg_binding_path path{};if(dmg_result_get_binding_path(result,row,i,&path,sizeof(path))!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Binding path accessor failed");
        if(path.length){out<<",\"path\":";path_json(out,path);}out<<'}';
    }
    out<<']';
}
void bindings_json_v2(std::ostream& out,const dmg_result* result,uint32_t row){
    uint32_t count=0;if(dmg_result_get_binding_count(result,row,&count)!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Binding count accessor failed");
    out<<",\"bindings\":[";
    for(uint32_t i=0;i<count;++i){dmg_binding_row_v2 binding{};dmg_binding_path path{};CliTarget target;
        if(cli_binding(result,row,i,&binding,target)!=DMG_OK||dmg_result_get_binding_path(result,row,i,&path,sizeof(path))!=DMG_OK)
            throw CliError(DMG_INTERNAL_ERROR,"Binding v2 accessor failed");
        if(i)out<<',';out<<"{\"label\":";
        if(binding.label)out<<dmg_cli::json_quote_utf8(binding.label);else out<<"null";
        value_fields_json(out,binding.value,true,value_projection(binding.value),false,target);out<<",\"path\":";path_json(out,path);out<<'}';
    }out<<']';
}
void relation_proofs_json(std::ostream& out,const dmg_result* result,uint32_t row){
    uint32_t count=0;if(dmg_result_get_link_count(result,row,&count)!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Link count accessor failed");
    if(count){out<<",\"links\":[";for(uint32_t i=0;i<count;++i){dmg_relation_link link{};
        if(dmg_result_get_link(result,row,i,&link,sizeof(link))!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Link accessor failed");
        if(i)out<<',';out<<"{\"operator_node\":"<<link.node_id<<",\"key\":"<<json_quote_ascii(join_key_name(link.key))<<",\"left\":";
        key_json(out,link.left_relation,link.left_source,link.left_local);out<<",\"right\":";key_json(out,link.right_relation,link.right_source,link.right_local);out<<'}';
    }out<<']';}
    if(dmg_result_get_proof_binding_count(result,row,&count)!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Proof binding count accessor failed");
    if(count){out<<",\"proof_bindings\":[";for(uint32_t i=0;i<count;++i){dmg_proof_binding_row proof{};dmg_binding_path path{};
        if(dmg_result_get_proof_binding(result,row,i,&proof,sizeof(proof))!=DMG_OK||dmg_result_get_proof_binding_path(result,row,i,&path,sizeof(path))!=DMG_OK)
            throw CliError(DMG_INTERNAL_ERROR,"Proof binding accessor failed");
        if(i)out<<',';out<<"{\"operator_node\":"<<proof.operator_node<<",\"label\":";
        if(proof.binding.label)out<<dmg_cli::json_quote_utf8(proof.binding.label);else out<<"null";
        out<<",\"entity\":{\"source_index\":"<<proof.binding.entity.source_index;
        entity_fields_json(out,proof.binding.entity);entity_text_json(out,proof.binding.entity,entity_projection(proof.binding.entity.relation));
        out<<"},\"path\":";path_json(out,path);out<<'}';
    }out<<']';}
}
void relation_proofs_json_v2(std::ostream& out,const dmg_result* result,uint32_t row){
    uint32_t count=0;if(dmg_result_get_link_count(result,row,&count)!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Link count accessor failed");
    if(count){out<<",\"links\":[";for(uint32_t i=0;i<count;++i){dmg_relation_link_v2 link{};
        if(([&]{auto x=dmg_result_get_link_v2(result,row,i,&link,sizeof(link));return x==DMG_UNSUPPORTED?dmg_result_get_link_v3(result,row,i,&link,sizeof(link)):x;})()!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Link v2 accessor failed");
        if(i)out<<',';out<<"{\"operator_node\":"<<link.node_id<<",\"key\":"<<json_quote_ascii(join_key_name(link.key))<<",\"left\":";
        key_json_v2(out,link.left);out<<",\"right\":";key_json_v2(out,link.right);out<<'}';
    }out<<']';}
    if(dmg_result_get_proof_binding_count(result,row,&count)!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Proof binding count accessor failed");
    if(count){out<<",\"proof_bindings\":[";for(uint32_t i=0;i<count;++i){dmg_proof_binding_row_v2 proof{};dmg_binding_path path{};CliTarget target;
        if(cli_proof(result,row,i,&proof,target)!=DMG_OK||dmg_result_get_proof_binding_path(result,row,i,&path,sizeof(path))!=DMG_OK)
            throw CliError(DMG_INTERNAL_ERROR,"Proof binding v2 accessor failed");
        if(i)out<<',';out<<"{\"operator_node\":"<<proof.operator_node<<",\"label\":";
        if(proof.binding.label)out<<dmg_cli::json_quote_utf8(proof.binding.label);else out<<"null";
        out<<",\"value\":{";value_fields_json(out,proof.binding.value,true,value_projection(proof.binding.value),true,target);out<<"},\"path\":";path_json(out,path);out<<'}';
    }out<<']';}
}
dmg_query_info query_json_info(std::ostream& out,const dmg_result* result,uint64_t unknown_rows,const dmg_expand_info* expand=nullptr){
    dmg_query_info query{};dmg_query_info_v2 extended{};dmg_query_profile profile{};
    const auto info_status=dmg_result_get_query_info(result,&query);bool has_extended=false;
    if(info_status==DMG_UNSUPPORTED){if(dmg_result_get_query_info_v2(result,&extended,sizeof(extended))!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Query diagnostics accessor failed");query=extended.legacy;has_extended=true;}
    else if(info_status!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Query diagnostics accessor failed");
    if(expand)profile=expand->profile;else if(dmg_result_get_profile(result,&profile)!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Query diagnostics accessor failed");
    out<<",\"query_id\":"<<json_quote_ascii(query.query_id)<<",\"query\":{\"node_count\":"<<query.node_count
       <<",\"required_capabilities\":"<<query.required_capabilities<<",\"demand_mask\":"<<query.demand_mask
       <<",\"projection_mask\":"<<query.projection_mask<<",\"intent\":"<<query.intent<<",\"max_results\":"<<query.max_results<<",\"max_work\":"<<query.max_work;
    if(has_extended)out<<",\"extended_capabilities\":"<<json_quote_ascii(extended.extended_capabilities);out<<'}';
    out<<",\"query_scope\":{\"explicit\":"<<(query.explicit_scope?"true":"false")<<",\"complete\":"<<(profile.scope_complete?"true":"false")<<",\"sources\":[";
    for(uint32_t i=0;i<profile.scope_source_count;++i){uint32_t index=0;if(dmg_result_get_scope_source(result,i,&index)!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Query scope accessor failed");if(i)out<<',';out<<index;}
    out<<"]},\"query_profile\":{\"work_units\":"<<profile.work_units<<",\"fact_requests\":"<<profile.fact_requests
       <<",\"methods_decoded\":"<<profile.methods_decoded<<",\"code_units\":"<<profile.code_units<<",\"string_pool_lookups\":"<<profile.string_pool_lookups
       <<",\"invoke_sites\":"<<profile.invoke_sites<<",\"field_uses\":"<<profile.field_uses<<",\"declared_fields\":"<<profile.declared_fields
       <<",\"matches_seen\":"<<profile.matches_seen<<",\"sort_comparisons\":"<<profile.sort_comparisons<<",\"unknown_rows\":"<<unknown_rows
       <<",\"order_verified\":"<<(profile.order_verified?"true":"false")<<'}';
    out<<",\"profile_v1\":{\"producer\":\"native-query\",\"phase\":\"executed\",\"plan\":{\"query_id\":"<<json_quote_ascii(query.query_id)<<",\"demand_mask\":"<<query.demand_mask<<",\"required_capabilities\":"<<query.required_capabilities
       ;if(has_extended)out<<",\"extended_capabilities\":"<<json_quote_ascii(extended.extended_capabilities);
    out<<"},\"runtime\":{\"logical_work_units\":"<<profile.work_units<<",\"fact_requests\":"<<profile.fact_requests<<",\"methods_decoded\":"<<profile.methods_decoded<<",\"code_units\":"<<profile.code_units
       <<",\"scope_complete\":"<<(profile.scope_complete?"true":"false")<<",\"unknown_rows\":"<<unknown_rows<<",\"retained_index_bytes\":null,\"cancel_check_count\":null,\"reverse_index_events\":";
    if(!expand)out<<"null";else{out<<'[';for(uint32_t i=0;i<expand->expand_profile_count;++i){dmg_expand_profile value{};if(dmg_result_get_expand_profile(result,i,&value,sizeof(value))!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"expand profile accessor");if(i)out<<',';out<<"{\"node_id\":"<<value.node_id<<",\"built\":"<<value.reverse_builds<<",\"reused\":"<<value.reverse_reuses<<'}';}out<<']';}
    out<<"}}";return query;
}
void expand_key_json(std::ostream& out,const dmg_value_identity_v2& key){if(key.source_index==UINT32_MAX)out<<"null";else key_json_v2(out,key);}
void expand_binding_json(std::ostream& out,const dmg_expand_binding& binding){
    out<<"{\"label\":";if(binding.label)out<<dmg_cli::json_quote_utf8(binding.label);else out<<"null";
    out<<",\"value\":{";value_fields_json(out,binding.value,true,value_projection(binding.value),true);out<<"},\"path\":";path_json(out,binding.path);out<<'}';
}
void expand_hop_json(std::ostream& out,const dmg_expand_hop& hop){
    out<<"{\"caller\":";expand_key_json(out,hop.caller);out<<",\"resolved\":";expand_key_json(out,hop.resolved);
    out<<",\"dex_pc\":"<<hop.dex_pc<<",\"code_offset\":"<<hop.code_offset<<",\"opcode\":"<<hop.opcode
       <<",\"target_method_ref\":"<<hop.target_method_ref<<",\"candidate_count\":"<<hop.candidate_count
       <<",\"resolution_complete\":"<<(hop.resolution_complete?"true":"false")<<",\"target_symbol\":{\"source_index\":"<<hop.target_symbol.source_index;
    entity_fields_json(out,hop.target_symbol);entity_text_json(out,hop.target_symbol,entity_projection(hop.target_symbol.relation));out<<"}}";
}
void expand_witness_json(std::ostream& out,const dmg_relation_witness_v2& item){
    const auto& w=item.witness;out<<"{\"kind\":"<<json_quote_ascii(witness_kind(w.kind))<<",\"node_id\":"<<w.node_id
       <<",\"matched\":"<<(w.matched==DMG_MATCH_UNKNOWN?"null":w.matched==DMG_MATCH_TRUE?"true":"false")<<",\"dex_pc\":";
    nullable_id(out,w.dex_pc);out<<",\"opcode\":";if(w.dex_pc==UINT32_MAX)out<<"null";else out<<w.opcode;
    out<<",\"reference_index\":";nullable_id(out,w.reference_index);out<<",\"reference_kind\":"<<w.reference_kind<<",\"extra_proto\":";
    nullable_id(out,w.extra_proto);out<<",\"code_units\":"<<w.code_units<<",\"operator_node\":"<<item.operator_node<<",\"entity\":";
    expand_key_json(out,item.entity);out<<'}';
}
template<class GetLink,class GetProof,class GetWitness>void expand_proofs_json(std::ostream& out,uint32_t links,uint32_t proofs,uint32_t seed,uint32_t walk,uint32_t emit,GetLink get_link,GetProof get_proof,GetWitness get_witness){
    out<<",\"seed_links\":[";for(uint32_t i=0;i<links;++i){dmg_relation_link_v2 x{};if(get_link(i,&x)!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Expand seed link accessor failed");
        if(i)out<<',';out<<"{\"operator_node\":"<<x.node_id<<",\"key\":"<<json_quote_ascii(join_key_name(x.key))<<",\"left\":";expand_key_json(out,x.left);out<<",\"right\":";expand_key_json(out,x.right);out<<'}';}out<<']';
    out<<",\"seed_proofs\":[";for(uint32_t i=0;i<proofs;++i){dmg_expand_proof x{};if(get_proof(i,&x)!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Expand seed proof accessor failed");
        if(i)out<<',';out<<"{\"operator_node\":"<<x.operator_node<<",\"binding\":";expand_binding_json(out,x.binding);out<<'}';}out<<']';
    const uint32_t counts[]={seed,walk,emit};const char* names[]={"seed_witnesses","walk_witnesses","emit_witnesses"};
    for(uint32_t type=0;type<3;++type){out<<",\""<<names[type]<<"\":[";for(uint32_t i=0;i<counts[type];++i){dmg_relation_witness_v2 x{};
        if(get_witness(type,i,&x)!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Expand witness accessor failed");if(i)out<<',';expand_witness_json(out,x);}out<<']';}
}
void expand_row_evidence_json(std::ostream& out,const dmg_result* result,uint32_t row){
    dmg_expand_row_evidence_info n{};if(dmg_result_get_expand_row_evidence_info(result,row,&n,sizeof(n))!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Expand row evidence accessor failed");
    out<<",\"bindings\":[";for(uint32_t i=0;i<n.binding_count;++i){dmg_expand_binding b{};if(dmg_result_get_expand_row_binding(result,row,i,&b,sizeof(b))!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Expand row binding accessor failed");if(i)out<<',';expand_binding_json(out,b);}out<<']';
    out<<",\"links\":[";for(uint32_t i=0;i<n.link_count;++i){dmg_relation_link_v2 x{};if(dmg_result_get_expand_row_link(result,row,i,&x,sizeof(x))!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Expand row link accessor failed");if(i)out<<',';out<<"{\"operator_node\":"<<x.node_id<<",\"key\":"<<json_quote_ascii(join_key_name(x.key))<<",\"left\":";expand_key_json(out,x.left);out<<",\"right\":";expand_key_json(out,x.right);out<<'}';}out<<']';
    out<<",\"proof_bindings\":[";for(uint32_t i=0;i<n.proof_count;++i){dmg_expand_proof x{};if(dmg_result_get_expand_row_proof(result,row,i,&x,sizeof(x))!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Expand row proof accessor failed");if(i)out<<',';out<<"{\"operator_node\":"<<x.operator_node<<",\"binding\":";expand_binding_json(out,x.binding);out<<'}';}out<<']';
    out<<",\"witnesses\":[";for(uint32_t i=0;i<n.witness_count;++i){dmg_relation_witness_v2 x{};if(dmg_result_get_expand_row_witness(result,row,i,&x,sizeof(x))!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Expand row witness accessor failed");if(i)out<<',';expand_witness_json(out,x);}out<<']';
}
void expand_paths_json(std::ostream& out,const dmg_result* result,uint32_t row){
    uint32_t count=0;if(dmg_result_get_expand_path_count(result,row,&count)!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Expand path count accessor failed");out<<",\"paths\":[";
    for(uint32_t i=0;i<count;++i){dmg_expand_path_info p{};if(dmg_result_get_expand_path(result,row,i,&p,sizeof(p))!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Expand path accessor failed");
        if(i)out<<',';out<<"{\"operator_node\":"<<p.node_id<<",\"uncertain\":"<<(p.uncertain?"true":"false")<<",\"seed\":";expand_key_json(out,p.seed);
        out<<",\"endpoint\":";expand_key_json(out,p.endpoint);out<<",\"seed_bindings\":[";
        for(uint32_t j=0;j<p.seed_binding_count;++j){dmg_expand_binding b{};if(dmg_result_get_expand_path_binding(result,row,i,j,&b,sizeof(b))!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Expand binding accessor failed");if(j)out<<',';expand_binding_json(out,b);}out<<"],\"hops\":[";
        for(uint32_t j=0;j<p.hop_count;++j){dmg_expand_hop h{};if(dmg_result_get_expand_path_hop(result,row,i,j,&h,sizeof(h))!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Expand hop accessor failed");if(j)out<<',';expand_hop_json(out,h);}out<<']';
        expand_proofs_json(out,p.seed_link_count,p.seed_proof_count,p.seed_witness_count,p.walk_witness_count,p.emit_witness_count,
            [&](uint32_t j,dmg_relation_link_v2* x){return dmg_result_get_expand_path_seed_link(result,row,i,j,x,sizeof(*x));},
            [&](uint32_t j,dmg_expand_proof* x){return dmg_result_get_expand_path_seed_proof(result,row,i,j,x,sizeof(*x));},
            [&](uint32_t t,uint32_t j,dmg_relation_witness_v2* x){return dmg_result_get_expand_path_witness(result,row,i,t,j,x,sizeof(*x));});out<<'}';
    }out<<']';
}
const char* frontier_reason(uint32_t reason){switch(reason){case DMG_EXPAND_UNRESOLVED:return "unresolved";case DMG_EXPAND_INCOMPLETE:return "incomplete";case DMG_EXPAND_UNKNOWN_WALK:return "unknown_walk";case DMG_EXPAND_UNKNOWN_EMIT:return "unknown_emit";default:throw CliError(DMG_INTERNAL_ERROR,"Unknown frontier reason");}}
void expand_frontiers_json(std::ostream& out,const dmg_result* result,const dmg_expand_info& info){
    out<<",\"frontiers\":[";for(uint32_t i=0;i<info.frontier_count;++i){dmg_expand_frontier f{};if(dmg_result_get_expand_frontier(result,i,&f,sizeof(f))!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Expand frontier accessor failed");
        if(i)out<<',';out<<"{\"operator_node\":"<<f.node_id<<",\"depth\":"<<f.depth<<",\"reason\":"<<json_quote_ascii(frontier_reason(f.reason))<<",\"seed\":";expand_key_json(out,f.seed);
        out<<",\"current\":";expand_key_json(out,f.current);out<<",\"caller\":";expand_key_json(out,f.caller);out<<",\"dex_pc\":";nullable_id(out,f.dex_pc);out<<",\"target_method_ref\":";nullable_id(out,f.target_method_ref);
        out<<",\"target_symbol\":";if(!f.has_target_symbol)out<<"null";else{out<<"{\"source_index\":"<<f.target_symbol.source_index;entity_fields_json(out,f.target_symbol);entity_text_json(out,f.target_symbol,entity_projection(f.target_symbol.relation));out<<'}';}
        out<<",\"seed_bindings\":[";for(uint32_t j=0;j<f.seed_binding_count;++j){dmg_expand_binding b{};if(dmg_result_get_expand_frontier_binding(result,i,j,&b,sizeof(b))!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Expand frontier binding accessor failed");if(j)out<<',';expand_binding_json(out,b);}out<<"],\"prefix\":[";
        for(uint32_t j=0;j<f.prefix_count;++j){dmg_expand_hop h{};if(dmg_result_get_expand_frontier_hop(result,i,j,&h,sizeof(h))!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Expand frontier hop accessor failed");if(j)out<<',';expand_hop_json(out,h);}out<<']';
        expand_proofs_json(out,f.seed_link_count,f.seed_proof_count,f.seed_witness_count,f.walk_witness_count,f.emit_witness_count,
            [&](uint32_t j,dmg_relation_link_v2* x){return dmg_result_get_expand_frontier_seed_link(result,i,j,x,sizeof(*x));},
            [&](uint32_t j,dmg_expand_proof* x){return dmg_result_get_expand_frontier_seed_proof(result,i,j,x,sizeof(*x));},
            [&](uint32_t t,uint32_t j,dmg_relation_witness_v2* x){return dmg_result_get_expand_frontier_witness(result,i,t,j,x,sizeof(*x));});out<<'}';
    }out<<']';
    out<<",\"expand_profile\":[";for(uint32_t i=0;i<info.expand_profile_count;++i){dmg_expand_profile p{};if(dmg_result_get_expand_profile(result,i,&p,sizeof(p))!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Expand profile accessor failed");
        if(i)out<<',';out<<"{\"node_id\":"<<p.node_id<<",\"visited\":"<<p.visited<<",\"edges\":"<<p.edges<<",\"paths\":"<<p.paths<<",\"decoded_methods\":"<<p.decoded_methods<<",\"unresolved\":"<<p.unresolved<<",\"unknown_frontiers\":"<<p.unknown_frontiers<<",\"reverse_builds\":"<<p.reverse_builds<<",\"reverse_reuses\":"<<p.reverse_reuses<<'}';}out<<']';
}
void witnesses_json(std::ostream& out,const dmg_result* result,uint32_t row,bool relational=false,bool uses=false){
    uint32_t count=0;if(dmg_result_get_witness_count(result,row,&count)!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Witness count accessor failed");
    out<<",\"evidence\":[";
    for(uint32_t i=0;i<count;++i){dmg_witness witness{};dmg_relation_witness relation_witness{};dmg_relation_witness_v2 relation_witness_v2{};
        dmg_caller_field_relation_witness_v1 relation{};const auto rs=dmg_result_get_caller_field_relation_witness_v1(result,row,i,&relation,sizeof(relation));
        if(rs==DMG_OK){
            if(i)out<<',';out<<"{\"kind\":\"caller_field_relation\",\"node_id\":"<<relation.node_id<<",\"operator_node\":";nullable_id(out,relation.operator_node);
            out<<",\"caller_field_relation\":{\"item\":"<<relation.item_kind<<",\"status\":";nullable_id(out,relation.status);out<<",\"reason\":";nullable_id(out,relation.reason);
            out<<",\"source_index\":"<<relation.source_index<<",\"class_ordinal\":"<<relation.class_ordinal<<",\"path_index\":";nullable_id(out,relation.path_index);out<<",\"parent_index\":";nullable_id(out,relation.parent_index);out<<",\"edge_kind\":";nullable_id(out,relation.edge_kind);out<<",\"interface_index\":";nullable_id(out,relation.interface_index);
            out<<",\"target_source\":";nullable_id(out,relation.target_source);out<<",\"target_class\":";nullable_id(out,relation.target_class);out<<",\"target_field\":";nullable_id(out,relation.target_field);out<<",\"event_source\":";nullable_id(out,relation.event_source);out<<",\"event_caller\":";nullable_id(out,relation.event_caller);out<<",\"event_pc\":";nullable_id(out,relation.event_pc);out<<"}}";continue;
        }
        if(rs!=DMG_UNSUPPORTED)throw CliError(DMG_INTERNAL_ERROR,"Caller field relation witness accessor failed");
        dmg_class_annotation_flags_witness_v1 annotation{};const auto as=dmg_result_get_class_annotation_flags_witness_v1(result,row,i,&annotation,sizeof(annotation));
        if(as==DMG_OK){
            if(i)out<<',';out<<"{\"kind\":\"class_annotation_flags\",\"node_id\":"<<annotation.node_id<<",\"matched\":"<<(annotation.matched==DMG_MATCH_TRUE?"true":annotation.matched==DMG_MATCH_FALSE?"false":"null")<<",\"operator_node\":";nullable_id(out,annotation.operator_node);
            out<<",\"class_annotation_flags\":{\"source_index\":"<<annotation.source_index<<",\"class_ordinal\":"<<annotation.class_ordinal<<",\"source_kind\":"<<annotation.source_kind<<",\"directory_offset\":"<<annotation.directory_offset<<",\"set_offset\":"<<annotation.set_offset<<",\"item_offset\":"<<annotation.item_offset<<",\"value_offset\":"<<annotation.value_offset<<",\"raw_flags\":"<<annotation.raw_flags<<",\"encoded_flags\":"<<annotation.encoded_flags<<",\"projected_flags\":"<<annotation.projected_flags<<"}}";continue;
        }
        if(as!=DMG_UNSUPPORTED)throw CliError(DMG_INTERNAL_ERROR,"Class annotation flags witness accessor failed");
        dmg_field_declaration_witness_v1 field_declaration{};const auto ds=dmg_result_get_field_declaration_witness_v1(result,row,i,&field_declaration,sizeof(field_declaration));
        if(ds==DMG_OK){
            if(i)out<<',';out<<"{\"kind\":\"field_declaration\",\"node_id\":"<<field_declaration.node_id<<",\"matched\":true,\"operator_node\":";nullable_id(out,field_declaration.operator_node);
            out<<",\"field_declaration\":{\"item\":"<<field_declaration.item_kind<<",\"path\":"<<field_declaration.path_index<<",\"edge\":";nullable_id(out,field_declaration.edge_kind);
            out<<",\"interface_index\":";nullable_id(out,field_declaration.interface_index);
            out<<",\"detail\":"<<field_declaration.detail<<",\"source_index\":"<<field_declaration.source_index<<",\"relation\":"<<json_quote_ascii(relation_name(field_declaration.relation))<<",\"local_index\":"<<field_declaration.local_index<<"}}";continue;
        }
        if(ds!=DMG_UNSUPPORTED)throw CliError(DMG_INTERNAL_ERROR,"Field declaration witness accessor failed");
        dmg_interface_witness_v1 interface_proof{};auto fs=dmg_result_get_interface_resolved_witness_v1(result,row,i,&interface_proof,sizeof(interface_proof));const bool resolved_proof=fs==DMG_OK;if(fs==DMG_UNSUPPORTED)fs=dmg_result_get_interface_witness_v1(result,row,i,&interface_proof,sizeof(interface_proof));
        if(fs==DMG_OK){
            if(i)out<<',';out<<(resolved_proof?"{\"kind\":\"interface_resolved\",\"node_id\":" : "{\"kind\":\"interface_inherited\",\"node_id\":")<<interface_proof.node_id<<",\"matched\":"<<(interface_proof.matched==DMG_MATCH_TRUE?"true":interface_proof.matched==DMG_MATCH_FALSE?"false":"null")
                <<",\"operator_node\":";nullable_id(out,interface_proof.operator_node);
            out<<",\"interface\":{\"item\":"<<interface_proof.item_kind<<",\"branch\":";nullable_id(out,interface_proof.branch_index);
            out<<",\"node\":";nullable_id(out,interface_proof.node_index);out<<",\"aux\":";nullable_id(out,interface_proof.aux);
            out<<",\"detail\":"<<interface_proof.detail<<",\"source_index\":"<<interface_proof.source_index<<",\"relation\":"<<json_quote_ascii(relation_name(interface_proof.relation))<<",\"local_index\":"<<interface_proof.local_index<<"}}";continue;
        }
        if(fs!=DMG_UNSUPPORTED)throw CliError(DMG_INTERNAL_ERROR,"Interface witness accessor failed");
        dmg_numeric_witness_v1 numeric{};const auto ns=dmg_result_get_numeric_witness_v1(result,row,i,&numeric,sizeof(numeric));
        if(ns==DMG_OK){
            static constexpr char hex[]="0123456789abcdef";std::string bits(numeric.width_bits/4,'0');auto value=numeric.bits;
            for(size_t j=bits.size();j>0;--j){bits[j-1]=hex[value&15u];value>>=4;}
            if(i)out<<',';out<<"{\"kind\":\"numeric_literal\",\"node_id\":"<<numeric.node_id<<",\"matched\":"<<(numeric.matched==DMG_MATCH_TRUE?"true":numeric.matched==DMG_MATCH_FALSE?"false":"null")
                <<",\"dex_pc\":"<<numeric.dex_pc<<",\"opcode\":"<<numeric.opcode<<",\"code_units\":"<<numeric.code_units
                <<",\"width_bits\":"<<numeric.width_bits<<",\"literal_kind\":"<<json_quote_ascii(numeric.literal_kind==0?"constant":"arithmetic_operand")
                <<",\"bits\":"<<json_quote_ascii(bits)<<",\"operator_node\":";nullable_id(out,numeric.operator_node);
            out<<",\"entity\":{\"relation\":"<<json_quote_ascii(relation_name(numeric.relation))<<",\"source_index\":"<<numeric.source_index<<",\"local_index\":"<<numeric.local_index<<"}}";continue;
        }
        if(ns!=DMG_UNSUPPORTED)throw CliError(DMG_INTERNAL_ERROR,"Numeric witness accessor failed");
        if(uses){
            if(([&]{auto x=dmg_result_get_relation_witness_v2(result,row,i,&relation_witness_v2,sizeof(relation_witness_v2));return x==DMG_UNSUPPORTED?dmg_result_get_relation_witness_v3(result,row,i,&relation_witness_v2,sizeof(relation_witness_v2)):x;})()!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Relation witness v2 accessor failed");
            witness=relation_witness_v2.witness;
        }else if(relational){
            if(dmg_result_get_relation_witness(result,row,i,&relation_witness,sizeof(relation_witness))!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Relation witness accessor failed");
            witness=relation_witness.witness;
        }else {auto status=dmg_result_get_witness(result,row,i,&witness);if(status==DMG_UNSUPPORTED)status=dmg_result_get_method_witness_v1(result,row,i,&witness,sizeof(witness));if(status!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Witness accessor failed");}
        if(i)out<<',';out<<"{\"kind\":"<<json_quote_ascii(witness_kind(witness.kind))<<",\"node_id\":"<<witness.node_id<<",\"matched\":"<<(witness.matched==DMG_MATCH_UNKNOWN?"null":witness.matched==DMG_MATCH_TRUE?"true":"false")<<",\"dex_pc\":";
        nullable_id(out,witness.dex_pc);out<<",\"opcode\":";if(witness.dex_pc==UINT32_MAX)out<<"null";else out<<witness.opcode;
        out<<",\"reference_index\":";nullable_id(out,witness.reference_index);out<<",\"reference_kind\":";
        if(witness.kind==DMG_WITNESS_INVOKE)out<<json_quote_ascii(witness.reference_kind==1?"call_site":witness.reference_kind==2?"method_and_proto":"method");
        else if(witness.kind==DMG_WITNESS_STRING||witness.kind==DMG_WITNESS_STRING_POOL_ABSENCE)out<<"\"string\"";
        else if(witness.kind==DMG_WITNESS_FIELD)out<<"\"field\"";else if(witness.kind==DMG_WITNESS_TYPE_USE)out<<"\"type_ref\"";else out<<"null";
        out<<",\"extra_proto\":";nullable_id(out,witness.extra_proto);out<<",\"code_units\":"<<witness.code_units;
        if(witness.kind==DMG_WITNESS_TYPE_USE&&!uses){dmg_method_type_witness_v1 detail{};if(dmg_result_get_method_type_witness_v1(result,row,i,&detail,sizeof(detail))!=DMG_OK||detail.descriptor_length>1'048'576u)throw CliError(DMG_BUDGET_EXCEEDED,"Type witness descriptor limit");std::vector<uint16_t> text(static_cast<size_t>(detail.descriptor_length));if(dmg_result_copy_method_type_descriptor_v1(result,row,i,text.data(),text.size())!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Type witness descriptor accessor failed");out<<",\"target_descriptor\":"<<quote_units(text.data(),text.size())<<",\"source_index\":"<<detail.source_index<<",\"method_ordinal\":"<<detail.method_ordinal;}
        if(witness.kind==DMG_WITNESS_INHERITED){dmg_inherited_witness detail{};
            if(dmg_result_get_inherited_witness(result,row,i,&detail,sizeof(detail))!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Inherited witness accessor failed");
            out<<",\"inherited\":{\"item\":"<<detail.item_kind<<",\"path\":";nullable_id(out,detail.path_index);
            out<<",\"aux\":";nullable_id(out,detail.aux);out<<",\"branch\":";nullable_id(out,detail.branch_index);
            out<<",\"detail\":"<<detail.detail<<",\"source_index\":"<<detail.source_index<<",\"relation\":"<<json_quote_ascii(relation_name(detail.relation))<<",\"local_index\":"<<detail.local_index<<'}';}
        if(uses){out<<",\"operator_node\":"<<relation_witness_v2.operator_node<<",\"entity\":";key_json_v2(out,relation_witness_v2.entity);}
        else if(relational)out<<",\"operator_node\":"<<relation_witness.operator_node<<",\"entity\":{\"relation\":"
                         <<json_quote_ascii(relation_name(relation_witness.relation))<<",\"source_index\":"<<relation_witness.source_index
                         <<",\"local_index\":"<<relation_witness.local_index<<'}';
        out<<'}';
    }out<<']';
}
void error_json(dmg_status status, uint64_t offset, const std::string& message) {
    std::string quoted_message;
    bool invalid_utf8 = false;
    try { quoted_message = dmg_cli::json_quote_utf8(message); }
    catch (const dmg_cli::JsonError&) {
        quoted_message = "\"Diagnostic contains invalid UTF-8; see message_bytes_hex\"";
        invalid_utf8 = true;
    }
    std::cout << "{\"schema_version\":1,\"profile\":\"dex-query-method-v1\",\"execution_status\":"
              << json_quote_ascii(execution_name(status))
              << ",\"coverage\":\"Partial\",\"decision\":\"Undetermined\",\"reason\":\"None\","
                 "\"candidates\":[],\"error\":{\"offset\":" << offset
              << ",\"message\":" << quoted_message;
    if (invalid_utf8) {
        constexpr char hex[] = "0123456789abcdef";
        std::cout << ",\"message_bytes_hex\":\"";
        for (const unsigned char byte : message) std::cout << hex[byte >> 4] << hex[byte & 15];
        std::cout << '"';
    }
    std::cout << "}}\n";
    std::cerr << execution_name(status) << ": " << message << " (offset " << offset << ")\n";
}
void check(dmg_status status, const dmg_error& error) {
    if (status != DMG_OK) throw CliError(status, error.message, error.offset);
}
int commit_output(std::string_view output, int result) {
    std::cout.write(output.data(), static_cast<std::streamsize>(output.size()));
    std::cout.flush();
    if (!std::cout) {
        std::cerr << "InternalError: stdout write or flush failed\n";
        return 4;
    }
    return result;
}
#include "explain.inc"

int help() {
    return commit_output("DexMeguviz DEX/APK entity queries\n"
                 "  dexmeguviz inspect INPUT [--source PATH ...] [--resource-source PATH ...] --json\n"
                 "  dexmeguviz query INPUT --query QUERY.json [source options] --json\n"
                 "  Optional: --dex-checksums compares each DEX header checksum and SHA-1 (not authentication).\n"
                 "  dexmeguviz --help\n\n"
                 "Profiles: dex-query-method-v1, dex-query-entity-v2, dex-query-relational-v3, dex-query-use-v4, dex-query-expand-v5, dex-query-inherited-v6, dex-query-numeric-v7, dex-query-interface-v8, dex-query-use-stream-v9, dex-query-composite-v10, dex-query-interface-resolved-v11, dex-query-unique-one-v12, dex-query-reflection-flags-v13, dex-query-reflection-relational-v14, dex-query-reflection-method-uses-v15, dex-query-use-target-symbol-v16, dex-query-reflection-body-relational-v17, dex-query-inherited-target-symbol-v18, dex-query-field-declaration-v19, dex-query-reflection-class-annotations-v20, dex-query-type-uses-v21, dex-query-method-type-uses-v22, dex-query-opcode-sequence-v23, dex-query-class-annotation-static-v24, dex-query-class-annotation-string-static-v25.\n"
                 "  dexmeguviz explain --query FILE [--json] [--budget-mib N] (no source I/O).\n"
                 "  dexmeguviz sql INPUT --sql-file FILE [--params-file FILE] [source options] (SQLite opt-in build).\n"
                 "  SQL limits: --sql-max-rows N (<=100000), --sql-max-bytes N (<=4194304), --sql-max-progress N (<=1000000), --sqlite-heap-mib N (1..4096).\n"
                 "  SQL planning: --sql-identity-equality [--sql-identity-in] (experimental metadata identity pushdown).\n"
                 "Inputs: raw DEX 035/037/038/039/040 and stored/deflate APK.\n"
                 "Inputs are ordered: INPUT is base; --source appends code-split; --resource-source\n"
                 "appends resource-split and explicitly allows an archive without DEX entries.\n"
                 "Repeated paths keep distinct input slots. At most 64 inputs and 1024 DEX sources.\n"
                 "  --budget-mib N       Engine owned-memory limit (default 512 MiB).\n"
                 "  --max-input-mib N    Cumulative caller-input buffer limit and per-input limit;\n"
                 "                       also limits total decoded DEX bytes (default 512 MiB).\n"
                 "  --scope-incomplete   Declare that the supplied source scope is incomplete.\n"
                 "  --expected-sha256 H  Verify the primary INPUT against a 64-digit hexadecimal digest.\n"
                 "Query relations: method_defs, class_defs, field_defs, method_refs, field_refs,\n"
                 "string_values, type_refs; use scans: string_uses, invoke_sites, field_uses, type_uses.\n"
                 "Use scans require object relations and retain caller/PC/typed target identity.\n"
                 "Body predicates using_strings, using_types, invokes, field_access and numeric_bits require method_defs.\n"
                 "Missing local definition attributes remain unknown, including through not.\n"
                 "Text exact/contains/prefix uses UTF-16 units; ASCII folding is explicit.\n"
                 "Intents: enumerate (default), exists, unique, top_n; scope/projection/order supported.\n"
                 "Relation operators: scan, filter, union, distinct, label, group_by_owner, join, semi_join.\n"
                 "Use joins support caller, target_ref and explicitly enabled target_symbol keys.\n"
                 "Call-site target checks are index bounds only; bootstrap contents are not parsed.\n"
                 "Identity: entity or tuple; groups retain member labels and source occurrences.\n"
                 "Query <= 64 KiB; complete JSON output <= 8 MiB. Bounded expand requires explicit limits.\n"
                 "Input buffers and Engine allocations have separate limits; neither is a process RSS limit.\n"
                 "JSON output distinguishes coverage and decision. Exit 0=completed, 2=input/capability,\n"
                 "3=resource/cancel/deadline, 4=internal/output error. Complete is limited to declared scope.\n", 0);
}

int run(int argc, char** argv) {
    if (argc == 2 && std::string_view(argv[1]) == "--help") return help();
    const auto args = parse_arguments(argc, argv);
    const auto query_json = (args.command == "query" || args.command == "explain") ? read_file(args.query_path, 65536) : std::vector<uint8_t>{};
    const auto sql_bytes=args.command=="sql"?read_file(args.sql_path,65536):std::vector<uint8_t>{};
    const auto parameter_bytes=args.command=="sql"&&!args.params_path.empty()?read_file(args.params_path,65536):std::vector<uint8_t>{};
    const auto source_prepare_start=std::chrono::steady_clock::now();
    dmg_engine_options engine_options{};
    engine_options.struct_size = sizeof(engine_options); engine_options.abi_version = DMG_ABI_VERSION;
    engine_options.owned_bytes_limit = args.owned_budget;
    engine_options.max_source_bytes = args.max_input_bytes;
    engine_options.max_jobs = 1;
    dmg_engine* raw_engine = nullptr;
    dmg_error error{};
    check(dmg_engine_create(&engine_options, &raw_engine, &error), error);
    Engine engine(raw_engine, &dmg_engine_release);
    CompiledQuery query(nullptr, &dmg_query_release);
    if(args.command == "query" || args.command == "explain") {
        dmg_query* compiled = nullptr;
        check(dmg_query_compile_json(engine.get(),query_json.data(),query_json.size(),&compiled,&error),error);
        query.reset(compiled);
    }
    if(args.command=="explain"){
        OutputBuffer buffer;std::ostream out(&buffer);out.exceptions(std::ios::badbit|std::ios::failbit);
        explain_plan(out,query.get());return commit_output(buffer.bytes(),0);
    }
    std::vector<std::vector<uint8_t>> input_buffers;
    input_buffers.reserve(args.sources.size());
    uint64_t total_input = 0;
    for (const auto& source : args.sources) {
        input_buffers.push_back(read_file(source.path, args.max_input_bytes-total_input));
        total_input += input_buffers.back().size();
    }
    std::vector<std::string> slot_keys;
    std::vector<dmg_source_spec> specs;
    slot_keys.reserve(args.sources.size()); specs.reserve(args.sources.size());
    for (size_t index = 0; index < args.sources.size(); ++index) {
        slot_keys.push_back("input:" + std::to_string(index) + ":" + args.sources[index].path);
        dmg_source_spec source{};
        source.struct_size = sizeof(source); source.abi_version = DMG_ABI_VERSION;
        source.format = DMG_INPUT_AUTO;
        source.allow_no_dex = args.sources[index].allow_no_dex ? 1u : 0u;
        source.data = input_buffers[index].data(); source.size = input_buffers[index].size();
        source.slot_key = slot_keys[index].c_str(); source.role = args.sources[index].role;
        source.expected_sha256 = index == 0 && !args.expected_sha256.empty() ? args.expected_sha256.c_str() : nullptr;
        specs.push_back(source);
    }
    dmg_source_set_options options{};
    options.struct_size = sizeof(options); options.abi_version = DMG_ABI_VERSION;
    options.source_namespace = "cli-v1"; options.scope_complete = args.scope_complete ? 1u : 0u;
    options.max_sources = 1024; options.max_total_dex_bytes = args.max_input_bytes;
    dmg_snapshot* raw_snapshot = nullptr;
    check(dmg_snapshot_open_sources(engine.get(), specs.data(), static_cast<uint32_t>(specs.size()), &options, &raw_snapshot, &error), error);
    Snapshot snapshot(raw_snapshot, &dmg_snapshot_release);
    input_buffers.clear();
    dmg_snapshot_overview overview{};
    if (dmg_snapshot_get_overview(snapshot.get(), &overview) != DMG_OK)
        throw CliError(DMG_INTERNAL_ERROR, "Snapshot overview accessor failed");
#ifdef DMG_CLI_SQL
    if(args.command=="sql"){
        dmg_cli::SqlFrontendOptions sql_options;sql_options.max_rows=args.sql_max_rows;sql_options.max_result_bytes=args.sql_max_bytes;sql_options.max_progress_intervals=args.sql_max_progress;sql_options.sqlite_heap_bytes=args.sqlite_heap_bytes;sql_options.metadata_identity_equality=args.sql_identity_equality;sql_options.metadata_identity_in=args.sql_identity_in;
        sql_options.source_prepare_us=std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now()-source_prepare_start).count();
        const std::string sql(sql_bytes.begin(),sql_bytes.end()),parameters(parameter_bytes.begin(),parameter_bytes.end());
        try{auto result=dmg_cli::execute_sql(snapshot.get(),sql,parameters,sql_options);return commit_output(result.json,result.exit_code);}
        catch(const dmg_cli::SqlOutputLimit& error){throw CliError(DMG_BUDGET_EXCEEDED,error.what());}
    }
#endif
    OutputBuffer buffer;
    std::ostream out(&buffer);
    out.exceptions(std::ios::badbit | std::ios::failbit);
    if (args.command == "inspect") {
        out << "{\"schema_version\":1,\"profile\":\"dex-query-method-v1\",\"command\":\"inspect\","
               "\"execution_status\":\"Complete\",\"coverage\":"
            << json_quote_ascii(overview.scope_complete ? "Complete" : "Partial")
            << ",\"decision\":\"NotApplicable\",\"reason\":"
            << json_quote_ascii(overview.scope_complete ? "None" : "SourceScopeIncomplete");
        dataset_json(out, overview, snapshot.get(), nullptr,DMG_METHOD_DEFS,false,args.dex_checksums,args.max_input_bytes);
        budget_json(out, args, total_input, engine.get());
        out << ",\"counts\":";
        metadata_counts(out, overview.string_count, overview.type_count, overview.class_count,
                        overview.method_ref_count, overview.method_def_count);
        out << ",\"capabilities\":" << json_quote_ascii(dmg_capabilities()) << "}\n";
        return commit_output(buffer.bytes(), 0);
    }
    dmg_result* raw_result = nullptr;
    check(dmg_query_execute(snapshot.get(), query.get(), &raw_result, &error), error);
    Result result(raw_result, &dmg_result_release);
    dmg_expand_info expand_info{};const auto expand_status=dmg_result_get_expand_info(result.get(),&expand_info,sizeof(expand_info));
    if(expand_status==DMG_OK){
        if(dmg_result_get_overview(result.get(),&overview)!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Result overview accessor failed");
        const auto& outcome=expand_info.outcome;
        out<<"{\"schema_version\":1,\"profile\":\"dex-query-expand-v5\",\"command\":\"query\",\"execution_status\":"<<json_quote_ascii(execution_name(outcome.execution_status))
           <<",\"coverage\":"<<json_quote_ascii(coverage_name(outcome.coverage))<<",\"decision\":"<<json_quote_ascii(decision_name(outcome.decision))
           <<",\"reason\":"<<json_quote_ascii(reason_name(outcome.reason))<<",\"relation\":"<<json_quote_ascii(relation_name(outcome.relation))
           <<",\"counter_domain\":\"per_operator\",\"entity_visited\":"<<outcome.entity_visited<<",\"entity_total\":"<<outcome.entity_total
           <<",\"method_visited\":"<<outcome.method_visited<<",\"method_total\":"<<outcome.method_total<<",\"events_collected\":"<<outcome.events_collected<<",\"unknown_rows\":"<<outcome.unknown_rows;
        dataset_json(out,overview,nullptr,result.get(),outcome.relation,false,args.dex_checksums,args.max_input_bytes,&expand_info);budget_json(out,args,total_input,engine.get());
        const auto query_info=query_json_info(out,result.get(),outcome.unknown_rows,&expand_info);
        graph_json_v2(out,result.get(),expand_info.graph,true);expand_frontiers_json(out,result.get(),expand_info);
        out<<",\"candidates\":[";for(uint32_t i=0;i<outcome.candidates_count;++i){dmg_entity_row row{};dmg_source_info origin{};
            if(dmg_result_get_expand_endpoint(result.get(),i,&row,sizeof(row))!=DMG_OK||dmg_result_get_source_info(result.get(),row.source_index,&origin)!=DMG_OK)
                throw CliError(DMG_INTERNAL_ERROR,"Expand endpoint accessor failed");
            if(row.relation!=outcome.relation||row.source_index!=origin.source_index)throw CliError(DMG_INTERNAL_ERROR,"Expand endpoint identity mismatch");
            if(i)out<<',';out<<"{\"source_index\":"<<origin.source_index<<",\"input_index\":"<<origin.input_index
                <<",\"source_sha256\":"<<json_quote_ascii(origin.dex.source_sha256)<<",\"content_id\":"<<json_quote_ascii(origin.dex.content_id)
                <<",\"occurrence_id\":"<<json_quote_ascii(origin.dex.occurrence_id)<<",\"logical_dex_id\":"<<json_quote_ascii(origin.logical_dex_id)
                <<",\"snapshot_id\":"<<json_quote_ascii(origin.dex.snapshot_id);
            entity_fields_json(out,row);entity_text_json(out,row,query_info.projection_mask);expand_row_evidence_json(out,result.get(),i);expand_paths_json(out,result.get(),i);out<<'}';
        }out<<"]}\n";return commit_output(buffer.bytes(),exit_code(outcome.execution_status));
    }
    if(expand_status!=DMG_UNSUPPORTED)throw CliError(DMG_INTERNAL_ERROR,"Expand profile detection failed");
    dmg_relation_info outcome{};dmg_relation_info_v2 outcome_v2{};
    const auto info_status=dmg_result_get_relation_info(result.get(),&outcome,sizeof(outcome));
    const bool use_query=info_status==DMG_UNSUPPORTED;
    if(use_query){
        if(([&]{auto x=dmg_result_get_relation_info_v2(result.get(),&outcome_v2,sizeof(outcome_v2));return x==DMG_UNSUPPORTED?dmg_result_get_relation_info_v3(result.get(),&outcome_v2,sizeof(outcome_v2)):x;})()!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Result metadata v2 accessor failed");
        outcome.relation=outcome_v2.relation;outcome.execution_status=outcome_v2.execution_status;outcome.coverage=outcome_v2.coverage;
        outcome.decision=outcome_v2.decision;outcome.reason=outcome_v2.reason;outcome.candidates_count=outcome_v2.candidates_count;outcome.unknown_rows=outcome_v2.unknown_rows;
    }else if(info_status!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Result metadata accessor failed");
    if(dmg_result_get_overview(result.get(),&overview)!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Result overview accessor failed");
    dmg_graph_info graph{};
    const auto graph_status=dmg_result_get_graph_info(result.get(),&graph,sizeof(graph));
    if(graph_status!=DMG_OK&&graph_status!=DMG_UNSUPPORTED)throw CliError(DMG_INTERNAL_ERROR,"Relation graph accessor failed");
    const bool relational=graph_status==DMG_OK;
    if(use_query&&!relational)throw CliError(DMG_INTERNAL_ERROR,"Use query has no relation graph");
    const bool method_result=!relational&&outcome.relation==DMG_METHOD_DEFS;
    dmg_query_info numeric_profile{};const auto result_info_status=dmg_result_get_query_info(result.get(),&numeric_profile);
    if(result_info_status==DMG_UNSUPPORTED){dmg_query_info_v2 info{};if(dmg_result_get_query_info_v2(result.get(),&info,sizeof(info))!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Query info accessor failed");numeric_profile=info.legacy;}
    else if(result_info_status!=DMG_OK)throw CliError(DMG_INTERNAL_ERROR,"Query info accessor failed");
    const bool field_declaration_query=(numeric_profile.required_capabilities&134217728u)!=0;
    const bool interface_query=(numeric_profile.required_capabilities&65536u)!=0;
    const bool resolved_query=(numeric_profile.required_capabilities&524288u)!=0;
    const bool inherited_query=(numeric_profile.required_capabilities&16384u)!=0;
    const bool numeric_query=(numeric_profile.required_capabilities&32768u)!=0;
    const bool expand_capability=(numeric_profile.required_capabilities&8192u)!=0;
    const bool use_streaming_query=(numeric_profile.required_capabilities&131072u)!=0;
    const bool composite_query=(numeric_profile.required_capabilities&262144u)!=0;
    const bool unique_one_query=(numeric_profile.required_capabilities&1048576u)!=0;
    const bool reflection_query=(numeric_profile.required_capabilities&2097152u)!=0;
    const bool reflection_relational_query=(numeric_profile.required_capabilities&4194304u)!=0;
    const bool reflection_method_uses_query=(numeric_profile.required_capabilities&8388608u)!=0;
    const bool target_symbol_query=(numeric_profile.required_capabilities&16777216u)!=0;
    const bool reflection_body_relational_query=(numeric_profile.required_capabilities&33554432u)!=0;
    const bool inherited_target_symbol_query=(numeric_profile.required_capabilities&67108864u)!=0;
    const bool class_annotations_query=(numeric_profile.required_capabilities&536870912u)!=0;
    const bool class_annotation_query=numeric_profile.query_id&&std::string_view(numeric_profile.query_id).starts_with("query:v24:");
    const bool class_annotation_string_query=numeric_profile.query_id&&std::string_view(numeric_profile.query_id).starts_with("query:v25:");
    const bool method_type_query=numeric_profile.query_id&&std::string_view(numeric_profile.query_id).starts_with("query:v22:");
    const bool type_uses_query=(numeric_profile.required_capabilities&1073741824u)!=0;
    out << "{\"schema_version\":1,\"profile\":" << json_quote_ascii(class_annotation_string_query?"dex-query-class-annotation-string-static-v25":class_annotation_query?"dex-query-class-annotation-static-v24":expand_capability?"dex-query-expand-v5":method_type_query?"dex-query-method-type-uses-v22":type_uses_query?"dex-query-type-uses-v21":class_annotations_query?"dex-query-reflection-class-annotations-v20":field_declaration_query?"dex-query-field-declaration-v19":inherited_target_symbol_query?"dex-query-inherited-target-symbol-v18":reflection_body_relational_query?"dex-query-reflection-body-relational-v17":target_symbol_query?"dex-query-use-target-symbol-v16":reflection_method_uses_query?"dex-query-reflection-method-uses-v15":reflection_relational_query?"dex-query-reflection-relational-v14":reflection_query?"dex-query-reflection-flags-v13":unique_one_query?"dex-query-unique-one-v12":resolved_query?"dex-query-interface-resolved-v11":composite_query?"dex-query-composite-v10":use_streaming_query?"dex-query-use-stream-v9":interface_query?"dex-query-interface-v8":inherited_query?"dex-query-inherited-v6":numeric_query?"dex-query-numeric-v7":use_query?"dex-query-use-v4":relational?"dex-query-relational-v3":method_result?"dex-query-method-v1":"dex-query-entity-v2")
              << ",\"command\":\"query\",\"execution_status\":" << json_quote_ascii(execution_name(outcome.execution_status))
              << ",\"coverage\":" << json_quote_ascii(coverage_name(outcome.coverage))
              << ",\"decision\":" << json_quote_ascii(decision_name(outcome.decision))
              << ",\"reason\":" << json_quote_ascii(reason_name(outcome.reason));
    if(use_query){out<<",\"relation\":"<<json_quote_ascii(relation_name(outcome.relation))<<",\"counter_domain\":\"per_operator\""
        <<",\"entity_visited\":"<<outcome_v2.entity_visited<<",\"entity_total\":"<<outcome_v2.entity_total
        <<",\"method_visited\":"<<outcome_v2.method_visited<<",\"method_total\":"<<outcome_v2.method_total
        <<",\"events_collected\":"<<outcome_v2.events_collected<<",\"unknown_rows\":"<<outcome.unknown_rows;
    }else if(method_result)out<<",\"visited_methods\":"<<outcome.visited_rows<<",\"total_methods\":"<<outcome.total_rows;
    else out<<",\"relation\":"<<json_quote_ascii(relation_name(outcome.relation))
            <<",\"visited_rows\":"<<outcome.visited_rows<<",\"total_rows\":"<<outcome.total_rows<<",\"unknown_rows\":"<<outcome.unknown_rows;
    if(relational&&!use_query)out<<",\"counter_domain\":\"scan_records\"";
    dataset_json(out, overview, nullptr, result.get(),outcome.relation,use_query,args.dex_checksums,args.max_input_bytes);
    budget_json(out, args, total_input, engine.get());
    const auto query_info=query_json_info(out,result.get(),outcome.unknown_rows);
    if(use_query)graph_json_v2(out,result.get(),graph);else if(relational)graph_json(out,result.get(),graph);
    out << ",\"candidates\":[";
    for (uint32_t i = 0; i < outcome.candidates_count; ++i) {
        dmg_entity_row row{};dmg_value_row_v2 value{};CliTarget target;
        dmg_source_info origin{};
        if ((use_query?cli_value(result.get(),i,&value,target):dmg_result_get_entity(result.get(),i,&row,sizeof(row))) != DMG_OK || dmg_result_get_origin(result.get(), i, &origin) != DMG_OK)
            throw CliError(DMG_INTERNAL_ERROR, "Result row accessor failed");
        if((use_query?value_relation(value):row.relation)!=outcome.relation||(use_query?value_source(value):row.source_index)!=origin.source_index)
            throw CliError(DMG_INTERNAL_ERROR,"Result row identity does not match its relation or origin");
        if (i != 0) out << ',';
        out << "{\"source_index\":" << origin.source_index << ",\"input_index\":" << origin.input_index
                  << ",\"source_sha256\":" << json_quote_ascii(origin.dex.source_sha256)
                  << ",\"content_id\":" << json_quote_ascii(origin.dex.content_id)
                  << ",\"occurrence_id\":" << json_quote_ascii(origin.dex.occurrence_id)
                  << ",\"logical_dex_id\":" << json_quote_ascii(origin.logical_dex_id)
                  << ",\"snapshot_id\":" << json_quote_ascii(origin.dex.snapshot_id);
        if(use_query)value_fields_json(out,value,false,query_info.projection_mask,false,target);
        else if(method_result){
            if(!row.definition_known||!row.flags_known||!row.code_known)
                throw CliError(DMG_INTERNAL_ERROR,"Method definition is missing required attributes");
            out<<",\"method_index\":"<<row.reference_index<<",\"access_flags\":"<<row.access_flags
               <<",\"declaration_offset\":"<<row.definition_offset<<",\"code_offset\":"<<row.code_offset;
        }else entity_fields_json(out,row);
        if(!use_query)entity_text_json(out,row,query_info.projection_mask);
        if(use_query){bindings_json_v2(out,result.get(),i);relation_proofs_json_v2(out,result.get(),i);}
        else if(relational){bindings_json(out,result.get(),i);relation_proofs_json(out,result.get(),i);}
        witnesses_json(out,result.get(),i,relational,use_query);out<<'}';
    }
    out << "]}\n";
    return commit_output(buffer.bytes(), exit_code(outcome.execution_status));
}
}

int cli_main(int argc, char** argv) {
#ifdef SIGPIPE
    std::signal(SIGPIPE, SIG_IGN);
#endif
    try { return run(argc, argv); }
    catch (const CliError& error) { error_json(error.status, error.offset, error.what()); return exit_code(error.status); }
    catch (const dmg_cli::JsonError& error) { error_json(DMG_INVALID_ARGUMENT, 0, error.what()); return 2; }
    catch (const std::bad_alloc&) { error_json(DMG_OUT_OF_MEMORY, 0, "Allocation failed"); return 3; }
    catch (const std::exception&) { error_json(DMG_INTERNAL_ERROR, 0, "Unexpected CLI failure"); return 4; }
    catch (...) { error_json(DMG_INTERNAL_ERROR, 0, "Unknown CLI failure"); return 4; }
}

#if defined(_WIN32)
namespace {
std::string argument_utf8(std::wstring_view wide) {
    static_assert(sizeof(wchar_t) == sizeof(uint16_t));
    std::string encoded;
    encoded.reserve(wide.size());
    for (size_t index = 0; index < wide.size(); ++index) {
        uint32_t codepoint = static_cast<uint16_t>(wide[index]);
        if (codepoint >= 0xd800 && codepoint <= 0xdbff) {
            if (++index == wide.size()) throw CliError(DMG_INVALID_ARGUMENT, "Unpaired UTF-16 surrogate in command argument");
            const auto low = static_cast<uint16_t>(wide[index]);
            if (low < 0xdc00 || low > 0xdfff) throw CliError(DMG_INVALID_ARGUMENT, "Unpaired UTF-16 surrogate in command argument");
            codepoint = 0x10000 + ((codepoint - 0xd800) << 10) + (low - 0xdc00);
        } else if (codepoint >= 0xdc00 && codepoint <= 0xdfff) {
            throw CliError(DMG_INVALID_ARGUMENT, "Unpaired UTF-16 surrogate in command argument");
        }
        if (codepoint <= 0x7f) encoded.push_back(static_cast<char>(codepoint));
        else if (codepoint <= 0x7ff) {
            encoded.push_back(static_cast<char>(0xc0 | (codepoint >> 6)));
            encoded.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
        } else if (codepoint <= 0xffff) {
            encoded.push_back(static_cast<char>(0xe0 | (codepoint >> 12)));
            encoded.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
            encoded.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
        } else {
            encoded.push_back(static_cast<char>(0xf0 | (codepoint >> 18)));
            encoded.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3f)));
            encoded.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
            encoded.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
        }
    }
    return encoded;
}
}
int wmain(int argc, wchar_t** argv) {
    try {
        std::vector<std::string> strings;
        strings.reserve(static_cast<size_t>(argc));
        for (int index = 0; index < argc; ++index) strings.push_back(argument_utf8(argv[index]));
        std::vector<char*> arguments;
        arguments.reserve(strings.size());
        for (auto& value : strings) arguments.push_back(value.data());
        return cli_main(argc, arguments.data());
    } catch (const CliError& error) {
        error_json(error.status, error.offset, error.what());
        return exit_code(error.status);
    } catch (const std::bad_alloc&) {
        error_json(DMG_OUT_OF_MEMORY, 0, "Command argument allocation failed");
        return 3;
    } catch (...) {
        error_json(DMG_INTERNAL_ERROR, 0, "Command argument conversion failed");
        return 4;
    }
}
#else
int main(int argc, char** argv) { return cli_main(argc, argv); }
#endif
