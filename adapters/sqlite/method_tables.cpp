#include "method_tables.hpp"
#include "c_api/runtime.hpp"
#include "facts/use_relations/use_scan.hpp"
#include "private_sqlite.h"
#include "result_commit/cursor_quota.hpp"
#ifdef DMG_SQLITE_PROTO_TESTING
#include "../../tests/sql/session_probe.hpp"
#endif

#include <algorithm>
#include <chrono>
#include <charconv>
#include <limits>
#include <new>
#include <string_view>
#include <utility>

namespace dexmeguviz::desktop_sql {
namespace {
using Dataset = runtime::Dataset;
using Source = runtime::Source;
#ifdef DMG_SQLITE_PROTO_TESTING
thread_local bool in_site_cancel_callback = false;
thread_local int64_t utf8_failure_after = -1;
thread_local uint64_t utf8_successful_conversions = 0;
thread_local uint64_t utf8_allocation_attempts = 0;
thread_local uint64_t identity_integer_filters = 0;
thread_local uint64_t identity_rowid_filters = 0;
thread_local uint32_t identity_source_mask = 0;
thread_local uint64_t identity_in_filters = 0;
thread_local uint64_t identity_in_fallbacks = 0;
thread_local bool in_identity_in_cancel_callback = false;
thread_local uint32_t bind_success_count = 0;
thread_local int bind_failure_index = 0;
thread_local int bind_failure_code = 0;
thread_local int64_t row_copy_failure_after = -1;
#endif
static_assert(sizeof(char16_t) == 2, "SQLite UTF-16 text requires 16-bit code units");
constexpr const char* schema =
    "CREATE TABLE x(source_index INTEGER, ordinal INTEGER, reference_index INTEGER, "
    "definition_ordinal INTEGER, owner TEXT, name TEXT, prototype TEXT, "
    "access_flags INTEGER, declaration_offset INTEGER, code_offset INTEGER)";
constexpr const char* field_schema =
    "CREATE TABLE x(source_index INTEGER, ordinal INTEGER, reference_index INTEGER, "
    "definition_ordinal INTEGER, owner TEXT, name TEXT, type_descriptor TEXT, "
    "access_flags INTEGER, declaration_offset INTEGER)";
constexpr const char* type_schema =
    "CREATE TABLE x(source_index INTEGER, ordinal INTEGER, reference_index INTEGER, "
    "definition_ordinal INTEGER, descriptor TEXT, access_flags INTEGER, "
    "definition_offset INTEGER, superclass_descriptor TEXT)";
constexpr const char* string_schema =
    "CREATE TABLE x(source_index INTEGER, ordinal INTEGER, value TEXT)";
constexpr const char* string_data_schema =
    "CREATE TABLE x(source_index INTEGER, ordinal INTEGER, raw_mutf8 BLOB, utf16_length INTEGER)";
constexpr const char* input_schema =
    "CREATE TABLE x(input_index INTEGER, format INTEGER, slot TEXT, role TEXT, "
    "slot_hex TEXT, role_hex TEXT, source_sha256 TEXT, content_id TEXT, input_bytes INTEGER, "
    "source_count INTEGER, allow_no_dex INTEGER, expected_digest_verified INTEGER, container_metadata_checked INTEGER)";
constexpr const char* source_schema =
    "CREATE TABLE x(source_index INTEGER, input_index INTEGER, slot TEXT, role TEXT, slot_hex TEXT, role_hex TEXT, "
    "source_sha256 TEXT, content_id TEXT, occurrence_id TEXT, logical_dex_id TEXT, dex_bytes INTEGER, "
    "dex_version INTEGER, archive_sha256 TEXT, archive_entry_name TEXT, archive_entry_index INTEGER, "
    "crc_verified INTEGER, header_consistency_verified INTEGER, expected_digest_verified INTEGER)";
constexpr const char* snapshot_schema =
    "CREATE TABLE x(snapshot_id TEXT, namespace_key TEXT, namespace_hex TEXT, scope_complete INTEGER, "
    "input_count INTEGER, source_count INTEGER, input_bytes INTEGER, dex_bytes INTEGER, "
    "string_count INTEGER, type_count INTEGER, class_count INTEGER, method_ref_count INTEGER, method_definition_count INTEGER)";
constexpr const char* logical_schema =
    "CREATE TABLE x(logical_dex_id TEXT, content_id TEXT, source_sha256 TEXT, dex_bytes INTEGER, dex_version INTEGER, occurrence_count INTEGER)";
constexpr const char* use_schema =
    "CREATE TABLE x(source_index INTEGER, caller_ordinal INTEGER, caller_reference_index INTEGER, "
    "code_offset INTEGER, dex_pc INTEGER, opcode INTEGER, target_domain INTEGER, target_index INTEGER, extra_proto INTEGER)";
constexpr uint64_t max_site_work = 100'000'000;
constexpr uint32_t max_site_records = 100'000;
enum class Kind { inputs, sources, snapshot, refs, defs, field_refs, field_defs, type_refs, class_defs, string_values, string_uses, invoke_sites, field_uses, type_uses, logical_dex, string_data };
struct StatementSiteBudget {
    bool active = false;
    uint64_t remaining_work = 0, remaining_records = 0;
};
struct Auxiliary { std::shared_ptr<const Dataset> dataset; Kind kind; sqlite3_int64 rows; SqlSiteLimits site_limits; SqlCancel* cancel; StatementSiteBudget* statement_budget; bool identity_pushdown; bool identity_in; };
struct Table : sqlite3_vtab { std::vector<size_t> logical_sources; std::shared_ptr<const Dataset> dataset; Kind kind; sqlite3_int64 rows; SqlSiteLimits site_limits; SqlCancel* cancel; StatementSiteBudget* statement_budget; bool identity_pushdown; bool identity_in; };
struct Cursor : sqlite3_vtab_cursor {
    uint64_t projected_columns = UINT64_MAX;
    size_t source = 0, end_source = 0; uint32_t ordinal = 0, wanted_ordinal = 0; bool exact_ordinal = false;
    std::pmr::vector<uint32_t> source_keys, ordinal_keys;
    size_t ordinal_key_index = 0;
    bool source_in = false, ordinal_in = false;
    std::pmr::vector<facts::UseRecord> sites;
    explicit Cursor(std::pmr::memory_resource* memory) : source_keys(memory), ordinal_keys(memory), sites(memory) {}
};

bool is_catalog(Kind kind) noexcept {
    return kind == Kind::inputs || kind == Kind::sources || kind == Kind::snapshot || kind == Kind::logical_dex;
}
size_t catalog_count(const Table& table) noexcept {
    return table.kind == Kind::logical_dex ? table.logical_sources.size() : table.kind == Kind::inputs ? table.dataset->inputs.size() :
           table.kind == Kind::sources ? table.dataset->sources.size() : size_t{1};
}
bool is_site(Kind kind) noexcept {
    return kind == Kind::string_uses || kind == Kind::invoke_sites || kind == Kind::field_uses || kind == Kind::type_uses;
}

size_t count(const Source& source, Kind kind) noexcept {
    switch (kind) {
    case Kind::inputs: case Kind::sources: case Kind::snapshot: case Kind::logical_dex: return 0;
    case Kind::refs: return source.facts.method_refs.size();
    case Kind::defs: return source.facts.methods.size();
    case Kind::field_refs: return source.facts.field_refs.size();
    case Kind::field_defs: return source.facts.field_definitions.size();
    case Kind::type_refs: return source.facts.types.size();
    case Kind::class_defs: return source.facts.class_definitions.size();
    case Kind::string_values: case Kind::string_data: return source.facts.strings.size();
    case Kind::string_uses: case Kind::invoke_sites: case Kind::field_uses: case Kind::type_uses: return 0;
    }
    return 0;
}
void advance_empty(Cursor& cursor, const Table& table) noexcept {
    while (cursor.source < cursor.end_source &&
           ((cursor.source_in && !std::binary_search(cursor.source_keys.begin(), cursor.source_keys.end(), static_cast<uint32_t>(cursor.source))) ||
            cursor.ordinal >= count(*table.dataset->sources[cursor.source], table.kind))) {
        ++cursor.source;
        cursor.ordinal_key_index = 0;
        cursor.ordinal = cursor.exact_ordinal ? cursor.wanted_ordinal : cursor.ordinal_in ? cursor.ordinal_keys.front() : 0;
    }
}
int connect(sqlite3* db, void* context, int, const char* const*, sqlite3_vtab** out, char**) noexcept {
    const auto* aux = static_cast<const Auxiliary*>(context);
    const bool fields = aux->kind == Kind::field_refs || aux->kind == Kind::field_defs;
    const bool types = aux->kind == Kind::type_refs || aux->kind == Kind::class_defs;
    const char* definition = aux->kind == Kind::logical_dex ? logical_schema : aux->kind == Kind::inputs ? input_schema : aux->kind == Kind::sources ? source_schema :
        aux->kind == Kind::snapshot ? snapshot_schema : is_site(aux->kind) ? use_schema :
        aux->kind == Kind::string_values ? string_schema : aux->kind == Kind::string_data ? string_data_schema : types ? type_schema : fields ? field_schema : schema;
    const int rc = sqlite3_declare_vtab(db, definition);
    if (rc != SQLITE_OK) return rc;
    auto* table = new (std::nothrow) Table{};
    if (!table) return SQLITE_NOMEM;
    table->dataset = aux->dataset;
    table->kind = aux->kind;
    table->rows = aux->rows;
    table->site_limits = aux->site_limits;
    table->cancel = aux->cancel;
    table->statement_budget = aux->statement_budget;
    table->identity_pushdown = aux->identity_pushdown;
    table->identity_in = aux->identity_in;
    if (table->kind == Kind::logical_dex) {
        try {
            for (size_t i=0;i<table->dataset->sources.size();++i) {
                const auto& id=table->dataset->sources[i]->logical;
                if (std::none_of(table->logical_sources.begin(),table->logical_sources.end(),[&](size_t j){return table->dataset->sources[j]->logical==id;}))
                    table->logical_sources.push_back(i);
            }
            table->rows=static_cast<sqlite3_int64>(table->logical_sources.size());
        } catch (const std::bad_alloc&) { delete table; return SQLITE_NOMEM; }
          catch (...) { delete table; return SQLITE_ERROR; }
    }
    *out = table;
    return SQLITE_OK;
}
int disconnect(sqlite3_vtab* table) noexcept { delete static_cast<Table*>(table); return SQLITE_OK; }
int best_index(sqlite3_vtab* raw, sqlite3_index_info* info) noexcept {
    const auto* table = static_cast<const Table*>(raw);
    // Only opt-in metadata identity equality. A second opt-in permits
    // all-at-once IN; unselected IN may be passed as single-value probes.
    // Unusable constraints, omit and ordering remain SQLite's responsibility.
    info->idxNum = 0;
    if (table->identity_pushdown && !is_catalog(table->kind) && !is_site(table->kind)) {
        int chosen[2] = {-1, -1}; bool in[2] = {false, false};
        int chosen_rowid = -1;
        for (int i = 0; i < info->nConstraint; ++i) {
            const auto& c = info->aConstraint[i];
            if (c.usable && c.op == SQLITE_INDEX_CONSTRAINT_EQ && c.iColumn == -1 &&
                sqlite3_vtab_in(info, i, -1) == 0) { chosen_rowid = i; break; }
        }
        if (chosen_rowid >= 0) {
            info->aConstraintUsage[chosen_rowid].argvIndex = 1;
            info->idxNum = 16;
        } else {
        for (int i = 0; i < info->nConstraint; ++i) {
            const auto& c = info->aConstraint[i];
            if (c.usable && c.op == SQLITE_INDEX_CONSTRAINT_EQ && c.iColumn >= 0 && c.iColumn <= 1 && chosen[c.iColumn] < 0) {
                const bool all_at_once = sqlite3_vtab_in(info, i, -1) != 0;
                if (!all_at_once || table->identity_in) { chosen[c.iColumn] = i; in[c.iColumn] = all_at_once; }
            }
        }
        int arg = 1;
        for (int col = 0; col != 2; ++col) if (chosen[col] >= 0) {
            info->aConstraintUsage[chosen[col]].argvIndex = arg++;
            info->idxNum |= 1 << col;
            if (in[col]) { sqlite3_vtab_in(info, chosen[col], 1); info->idxNum |= 4 << col; }
        }
        }
    }
    // Include SQLite's declared projection in the access plan. It is not a
    // promise to consume residual expressions, sort order or LIMIT.
    info->idxStr=sqlite3_mprintf("columns:%llu",static_cast<unsigned long long>(info->colUsed));
    if(!info->idxStr)return SQLITE_NOMEM;
    info->needToFreeIdxStr=1;
    info->estimatedRows = table->rows;
    info->estimatedCost = static_cast<double>(std::max<sqlite3_int64>(1, table->rows));
    return SQLITE_OK;
}
int open(sqlite3_vtab* raw, sqlite3_vtab_cursor** out) noexcept {
    const auto& table = *static_cast<const Table*>(raw);
    auto* cursor = new (std::nothrow) Cursor{&table.dataset->engine->scratch_resource};
    if (!cursor) return SQLITE_NOMEM;
    *out = cursor;
    return SQLITE_OK;
}
int close(sqlite3_vtab_cursor* cursor) noexcept { delete static_cast<Cursor*>(cursor); return SQLITE_OK; }
// Retain only exact nonnegative integer identities. Other values can compare
// equal after SQLite affinity, so any such value requires an unfiltered scan.
// An overlong list also falls back; no RHS sqlite3_value outlives xFilter.
int read_identity_in(sqlite3_value* list, uint64_t upper, std::pmr::vector<uint32_t>& keys, bool& restricted, const SqlCancel* cancel) {
    constexpr size_t max_list_items = 4096;
    keys.clear(); restricted = true;
    sqlite3_value* value = nullptr;
    int rc = sqlite3_vtab_in_first(list, &value);
    size_t seen = 0;
    while (rc == SQLITE_OK && value) {
        ++seen;
        if ((seen == 1 || seen % 64 == 0) && cancel && cancel->requested) {
#ifdef DMG_SQLITE_PROTO_TESTING
            in_identity_in_cancel_callback = true;
#endif
            const bool interrupted=cancel->requested(cancel->context);
#ifdef DMG_SQLITE_PROTO_TESTING
            in_identity_in_cancel_callback = false;
#endif
            if (interrupted) return SQLITE_INTERRUPT;
        }
        if (seen > max_list_items) {
#ifdef DMG_SQLITE_PROTO_TESTING
            ++identity_in_fallbacks;
#endif
            keys.clear(); restricted = false; return SQLITE_OK;
        }
        const int type = sqlite3_value_type(value);
        if (type == SQLITE_INTEGER) {
            const auto v = sqlite3_value_int64(value);
            if (v >= 0 && static_cast<uint64_t>(v) < upper) keys.push_back(static_cast<uint32_t>(v));
        } else if (type != SQLITE_NULL) {
#ifdef DMG_SQLITE_PROTO_TESTING
            ++identity_in_fallbacks;
#endif
            keys.clear(); restricted = false; return SQLITE_OK;
        }
        rc = sqlite3_vtab_in_next(list, &value);
    }
    if (rc != SQLITE_DONE) return rc == SQLITE_OK ? SQLITE_ERROR : rc;
    std::sort(keys.begin(), keys.end());
    keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
    return SQLITE_OK;
}
int filter(sqlite3_vtab_cursor* raw, int number, const char* plan, int argc, sqlite3_value** argv) noexcept {
    auto& cursor = *static_cast<Cursor*>(raw);
    const auto& table = *static_cast<const Table*>(raw->pVtab);
    if (number < 0 || number > 16 || ((number & 16) && number != 16) ||
        ((number & 4) && !(number & 1)) || ((number & 8) && !(number & 2)) ||
        ((number & 12) && !table.identity_in) || argc != ((number & 1) != 0) + ((number & 2) != 0) + ((number & 16) != 0) ||
        (number && (!table.identity_pushdown || is_catalog(table.kind) || is_site(table.kind))) ||
        (argc && !argv)) return SQLITE_MISUSE;
    cursor.projected_columns=UINT64_MAX;
    if(plan){
        const std::string_view encoded(plan);
        if(!encoded.starts_with("columns:"))return SQLITE_MISUSE;
        const auto digits=encoded.substr(8);auto parsed=std::from_chars(digits.data(),digits.data()+digits.size(),cursor.projected_columns);
        if(parsed.ec!=std::errc{}||parsed.ptr!=digits.data()+digits.size())return SQLITE_MISUSE;
    }
    cursor.source = 0;
    cursor.ordinal = 0;
    cursor.end_source = table.dataset->sources.size();
    cursor.exact_ordinal = false;
    cursor.wanted_ordinal = 0;
    cursor.source_in = false; cursor.ordinal_in = false; cursor.ordinal_key_index = 0;
    cursor.source_keys.clear(); cursor.ordinal_keys.clear();
    int arg = 0;
    try {
    if (number & 16) {
        auto* value = argv[arg++];
        if (!value) return SQLITE_MISUSE;
        if (sqlite3_value_type(value) == SQLITE_INTEGER) {
#ifdef DMG_SQLITE_PROTO_TESTING
            ++identity_rowid_filters;
#endif
            const auto id = sqlite3_value_int64(value);
            if (id < 0) cursor.end_source = 0;
            else {
                const auto bits = static_cast<uint64_t>(id);
                const auto source = bits >> 32;
                if (source >= cursor.end_source) cursor.end_source = 0;
                else {
                    cursor.source = static_cast<size_t>(source);
                    cursor.end_source = cursor.source + 1;
                    cursor.exact_ordinal = true;
                    cursor.wanted_ordinal = static_cast<uint32_t>(bits);
                    cursor.ordinal = cursor.wanted_ordinal;
                }
            }
        }
    }
    if (number & 1) {
        auto* value = argv[arg++];
        if (!value) return SQLITE_MISUSE;
        if (number & 4) {
#ifdef DMG_SQLITE_PROTO_TESTING
            ++identity_in_filters;
#endif
            const int rc = read_identity_in(value, cursor.end_source, cursor.source_keys, cursor.source_in, table.cancel);
            if (rc != SQLITE_OK) return rc;
            if (cursor.source_in && cursor.source_keys.empty()) cursor.end_source = 0;
        } else if (sqlite3_value_type(value) == SQLITE_INTEGER) {
            const auto v = sqlite3_value_int64(value);
#ifdef DMG_SQLITE_PROTO_TESTING
            ++identity_integer_filters;
            if (v >= 0 && v < 32) identity_source_mask |= uint32_t{1} << static_cast<uint32_t>(v);
#endif
            if (v < 0 || static_cast<uint64_t>(v) >= cursor.end_source) cursor.end_source = 0;
            else { cursor.source = static_cast<size_t>(v); cursor.end_source = cursor.source + 1; }
        }
    }
    if (number & 2) {
        auto* value = argv[arg++];
        if (!value) return SQLITE_MISUSE;
        if (number & 8) {
#ifdef DMG_SQLITE_PROTO_TESTING
            ++identity_in_filters;
#endif
            const int rc = read_identity_in(value, UINT32_MAX, cursor.ordinal_keys, cursor.ordinal_in, table.cancel);
            if (rc != SQLITE_OK) return rc;
            if (cursor.ordinal_in && cursor.ordinal_keys.empty()) cursor.end_source = 0;
            else if (cursor.ordinal_in) cursor.ordinal = cursor.ordinal_keys.front();
        } else if (sqlite3_value_type(value) == SQLITE_INTEGER) {
            const auto v = sqlite3_value_int64(value);
            if (v < 0 || static_cast<uint64_t>(v) >= UINT32_MAX) cursor.end_source = 0;
            else { cursor.exact_ordinal = true; cursor.wanted_ordinal = static_cast<uint32_t>(v); cursor.ordinal = cursor.wanted_ordinal; }
        }
    }
    } catch (const std::bad_alloc&) { return SQLITE_NOMEM; }
      catch (...) { return SQLITE_ERROR; }
    if (is_site(table.kind)) {
        cursor.sites.clear();
        try {
            const auto kind = table.kind == Kind::string_uses ? facts::UseKind::string_use :
                              table.kind == Kind::invoke_sites ? facts::UseKind::invoke_site : table.kind == Kind::type_uses ? facts::UseKind::type_use : facts::UseKind::field_use;
            uint64_t work = 0;
            auto& statement = *table.statement_budget;
            if (!statement.active) return SQLITE_MISUSE;
            for (size_t i = 0; i < table.dataset->sources.size(); ++i) {
                if (work >= table.site_limits.max_work) { cursor.sites.clear(); return SQLITE_TOOBIG; }
                const auto& source = *table.dataset->sources[i];
                facts::UseScanProgress progress{};
                uint64_t remaining = table.site_limits.max_work - work;
                if (table.site_limits.max_statement_work) {
                    if (!statement.remaining_work) { cursor.sites.clear(); return SQLITE_TOOBIG; }
                    remaining = std::min(remaining, statement.remaining_work);
                }
                const facts::UseScanLimits limits{remaining, table.site_limits.max_records};
                const facts::UseScanCancel cancel{[](void* context) noexcept {
                    const auto& value=*static_cast<SqlCancel*>(context);
                    if (!value.requested) return false;
#ifdef DMG_SQLITE_PROTO_TESTING
                    in_site_cancel_callback = true;
                    const bool cancelled=value.requested(value.context);
                    in_site_cancel_callback = false;
                    return cancelled;
#else
                    return value.requested(value.context);
#endif
                }, table.cancel};
                auto result = facts::collect_uses(source.view(), source.facts, static_cast<uint32_t>(i),
                    kind, progress, &table.dataset->engine->scratch_resource, limits, cancel);
                if (progress.work_units > table.site_limits.max_work - work ||
                    progress.work_units > remaining ||
                    result.rows.size() > table.site_limits.max_records - cursor.sites.size() ||
                    (table.site_limits.max_statement_records && result.rows.size() > statement.remaining_records)) {
                    cursor.sites.clear(); return SQLITE_TOOBIG;
                }
                work += progress.work_units;
                if (table.site_limits.max_statement_work) statement.remaining_work -= progress.work_units;
                if (table.site_limits.max_statement_records) statement.remaining_records -= result.rows.size();
                cursor.sites.insert(cursor.sites.end(), result.rows.begin(), result.rows.end());
            }
            return SQLITE_OK;
        } catch (const facts::UseScanError& error) {
            cursor.sites.clear();
            switch (error.code) {
            case facts::UseScanError::Code::budget: return SQLITE_TOOBIG;
            case facts::UseScanError::Code::cancelled: return SQLITE_INTERRUPT;
            case facts::UseScanError::Code::unsupported: return SQLITE_MISMATCH;
            case facts::UseScanError::Code::invalid: return SQLITE_CORRUPT;
            }
            return SQLITE_ERROR;
        } catch (const instructions::DecodeError& error) {
            cursor.sites.clear();
            switch (error.code) {
            case instructions::DecodeCode::budget: return SQLITE_TOOBIG;
            case instructions::DecodeCode::cancelled: return SQLITE_INTERRUPT;
            case instructions::DecodeCode::unsupported: return SQLITE_MISMATCH;
            case instructions::DecodeCode::corrupt: return SQLITE_CORRUPT;
            }
            return SQLITE_ERROR;
        } catch (const std::bad_alloc&) { cursor.sites.clear(); return SQLITE_NOMEM; }
        catch (...) { cursor.sites.clear(); return SQLITE_ERROR; }
    }
    if (!is_catalog(table.kind)) advance_empty(cursor, table);
    return SQLITE_OK;
}
int next(sqlite3_vtab_cursor* raw) noexcept {
    auto& cursor = *static_cast<Cursor*>(raw);
    const auto& table = *static_cast<const Table*>(raw->pVtab);
    if (is_catalog(table.kind)) {
        if (cursor.source < catalog_count(table)) ++cursor.source;
    } else if (is_site(table.kind)) {
        if (cursor.ordinal < cursor.sites.size()) ++cursor.ordinal;
    } else if (cursor.source < cursor.end_source) {
        if (cursor.exact_ordinal) { ++cursor.source; cursor.ordinal = cursor.wanted_ordinal; }
        else if (cursor.ordinal_in) {
            if (++cursor.ordinal_key_index == cursor.ordinal_keys.size()) { ++cursor.source; cursor.ordinal_key_index = 0; }
            cursor.ordinal = cursor.ordinal_keys[cursor.ordinal_key_index];
        }
        else ++cursor.ordinal;
        advance_empty(cursor, table);
    }
    return SQLITE_OK;
}
int eof(sqlite3_vtab_cursor* raw) noexcept {
    const auto& cursor = *static_cast<const Cursor*>(raw);
    const auto& table = *static_cast<const Table*>(raw->pVtab);
    return is_catalog(table.kind) ? cursor.source >= catalog_count(table) :
        is_site(table.kind) ? cursor.ordinal >= cursor.sites.size() : cursor.source >= cursor.end_source;
}
int text16(sqlite3_context* context, std::u16string_view value) noexcept {
    // SQLite treats a leading UTF-16 BOM as metadata and may swap the rest.
    // Encode Unicode scalars to explicit-length UTF-8 instead. DEX permits
    // lone UTF-16 surrogates; SQLite text cannot represent them losslessly.
    size_t bytes=0;
    for (size_t i=0;i<value.size();++i) {
        uint32_t cp=value[i];
        if (cp>=0xd800 && cp<=0xdbff) {
            if (++i>=value.size() || value[i]<0xdc00 || value[i]>0xdfff) {
                sqlite3_result_error_code(context,SQLITE_MISMATCH); return SQLITE_MISMATCH;
            }
            cp=0x10000+((cp-0xd800)<<10)+(value[i]-0xdc00);
        } else if (cp>=0xdc00 && cp<=0xdfff) {
            sqlite3_result_error_code(context,SQLITE_MISMATCH); return SQLITE_MISMATCH;
        }
        const size_t add=cp<0x80?1:cp<0x800?2:cp<0x10000?3:4;
        if (bytes>size_t(std::numeric_limits<int>::max())-add) {
            sqlite3_result_error_toobig(context); return SQLITE_TOOBIG;
        }
        bytes+=add;
    }
    // The session sets SQLITE_LIMIT_LENGTH to its logical result byte budget.
    // Enforce it before creating the temporary UTF-8 copy, not only when
    // SQLite later copies the result. This is still not an Engine RSS ledger.
    const int limit=sqlite3_limit(sqlite3_context_db_handle(context),SQLITE_LIMIT_LENGTH,-1);
    if (limit<0 || bytes>static_cast<size_t>(limit)) {
        sqlite3_result_error_toobig(context); return SQLITE_TOOBIG;
    }
    try {
#ifdef DMG_SQLITE_PROTO_TESTING
        ++utf8_allocation_attempts;
        if (utf8_failure_after == 0) throw std::bad_alloc{};
        if (utf8_failure_after > 0) --utf8_failure_after;
#endif
        std::string out; out.reserve(bytes);
        for (size_t i=0;i<value.size();++i) {
            uint32_t cp=value[i];
            if (cp>=0xd800 && cp<=0xdbff) { const uint32_t low=value[++i]; cp=0x10000+((cp-0xd800)<<10)+(low-0xdc00); }
            if (cp<0x80) out.push_back(static_cast<char>(cp));
            else if (cp<0x800) { out.push_back(static_cast<char>(0xc0|(cp>>6))); out.push_back(static_cast<char>(0x80|(cp&63))); }
            else if (cp<0x10000) { out.push_back(static_cast<char>(0xe0|(cp>>12))); out.push_back(static_cast<char>(0x80|((cp>>6)&63))); out.push_back(static_cast<char>(0x80|(cp&63))); }
            else { out.push_back(static_cast<char>(0xf0|(cp>>18))); out.push_back(static_cast<char>(0x80|((cp>>12)&63))); out.push_back(static_cast<char>(0x80|((cp>>6)&63))); out.push_back(static_cast<char>(0x80|(cp&63))); }
        }
        sqlite3_result_text(context,out.empty()?"":out.data(),static_cast<int>(out.size()),SQLITE_TRANSIENT);
#ifdef DMG_SQLITE_PROTO_TESTING
        ++utf8_successful_conversions;
#endif
        return SQLITE_OK;
    } catch (const std::bad_alloc&) { sqlite3_result_error_nomem(context); return SQLITE_NOMEM; }
    catch (...) { sqlite3_result_error_toobig(context); return SQLITE_TOOBIG; }
}
// Source-set slot/role/namespace are bytes at the C API boundary, not guaranteed
// UTF-8. TEXT rejects invalid sequences; *_hex is a lossless ASCII alternative.
bool valid_utf8(std::string_view value) noexcept {
    for (size_t i=0;i<value.size();) {
        const auto a=static_cast<unsigned char>(value[i++]);
        if (a<0x80) continue;
        unsigned count=0; uint32_t cp=0, minimum=0;
        if (a>=0xc2 && a<=0xdf) {count=1;cp=a&31;minimum=0x80;}
        else if (a>=0xe0 && a<=0xef) {count=2;cp=a&15;minimum=0x800;}
        else if (a>=0xf0 && a<=0xf4) {count=3;cp=a&7;minimum=0x10000;}
        else return false;
        if (count>value.size()-i) return false;
        while (count--) {const auto b=static_cast<unsigned char>(value[i++]);if ((b&0xc0)!=0x80) return false;cp=(cp<<6)|(b&63);}
        if (cp<minimum || cp>0x10ffff || (cp>=0xd800 && cp<=0xdfff)) return false;
    }
    return true;
}
int text8(sqlite3_context* context, std::string_view value) noexcept {
    if (!valid_utf8(value)) {sqlite3_result_error_code(context,SQLITE_MISMATCH);return SQLITE_MISMATCH;}
    const auto limit=sqlite3_limit(sqlite3_context_db_handle(context),SQLITE_LIMIT_LENGTH,-1);
    if (limit<0 || value.size()>static_cast<size_t>(limit) || value.size()>static_cast<size_t>(std::numeric_limits<int>::max())) {
        sqlite3_result_error_toobig(context);return SQLITE_TOOBIG;
    }
    sqlite3_result_text(context,value.empty()?"":value.data(),static_cast<int>(value.size()),SQLITE_TRANSIENT);
    return SQLITE_OK;
}
int hex8(sqlite3_context* context, std::string_view value) noexcept {
    const auto limit=sqlite3_limit(sqlite3_context_db_handle(context),SQLITE_LIMIT_LENGTH,-1);
    if (limit<0 || value.size()>static_cast<size_t>(limit)/2 || value.size()>static_cast<size_t>(std::numeric_limits<int>::max())/2) {
        sqlite3_result_error_toobig(context);return SQLITE_TOOBIG;
    }
    try {
        static constexpr char hex[]="0123456789abcdef";
        std::string output;output.reserve(value.size()*2);
        for (const unsigned char byte : value) {output.push_back(hex[byte>>4]);output.push_back(hex[byte&15]);}
        sqlite3_result_text(context,output.empty()?"":output.data(),static_cast<int>(output.size()),SQLITE_TRANSIENT);
        return SQLITE_OK;
    } catch (const std::bad_alloc&) {sqlite3_result_error_nomem(context);return SQLITE_NOMEM;}
      catch (...) {sqlite3_result_error_toobig(context);return SQLITE_TOOBIG;}
}
// Return the original string_data payload, excluding its length and terminator.
// Source metadata already checked this item; repeat all byte bounds before use.
int raw_mutf8(sqlite3_context* context,const Source& source,uint32_t ordinal,const SqlCancel* cancel) noexcept {
    const auto bytes=source.view();
    auto u32=[&](size_t at,uint32_t& out){if(at>bytes.size()||bytes.size()-at<4)return false;out=uint32_t(bytes[at])|(uint32_t(bytes[at+1])<<8)|(uint32_t(bytes[at+2])<<16)|(uint32_t(bytes[at+3])<<24);return true;};
    uint32_t table=0,offset=0;
    if(!u32(60,table)||ordinal>=source.facts.strings.size())return SQLITE_CORRUPT;
    const uint64_t item=uint64_t(table)+uint64_t(ordinal)*4;
    if(item>bytes.size()||!u32(static_cast<size_t>(item),offset))return SQLITE_CORRUPT;
    size_t at=offset;bool end=false;
    for(unsigned i=0;i<5;++i){if(at>=bytes.size())return SQLITE_CORRUPT;const auto b=bytes[at++];if(!(b&128)){end=true;break;}}
    if(!end)return SQLITE_CORRUPT;
    const auto start=at;const int limit=sqlite3_limit(sqlite3_context_db_handle(context),SQLITE_LIMIT_LENGTH,-1);
    while(at<bytes.size()&&bytes[at]){
        if(limit<0||at-start>=static_cast<size_t>(limit))return SQLITE_TOOBIG;
        if(((at-start)&4095)==0&&cancel&&cancel->requested&&cancel->requested(cancel->context))return SQLITE_INTERRUPT;
        ++at;
    }
    if(at==bytes.size())return SQLITE_CORRUPT;
    sqlite3_result_blob(context,bytes.data()+start,static_cast<int>(at-start),SQLITE_TRANSIENT);return SQLITE_OK;
}
int column(sqlite3_vtab_cursor* raw, sqlite3_context* context, int index) noexcept {
    const auto& cursor = *static_cast<const Cursor*>(raw);
    const auto& table = *static_cast<const Table*>(raw->pVtab);
    if(index<0||index>=64||(cursor.projected_columns&(uint64_t{1}<<index))==0)return SQLITE_MISUSE;
    if (is_catalog(table.kind)) {
        const auto& dataset=*table.dataset;
        if (cursor.source >= catalog_count(table)) return SQLITE_MISUSE;
        if (table.kind == Kind::logical_dex) {
            const auto& s=*dataset.sources[table.logical_sources[cursor.source]];
            switch(index){
            case 0:return text8(context,s.logical);
            case 1:return text8(context,s.content);
            case 2:return text8(context,s.digest);
            case 3:sqlite3_result_int64(context,static_cast<sqlite3_int64>(s.view().size()));break;
            case 4:sqlite3_result_int64(context,s.facts.dex_version);break;
            case 5:{sqlite3_int64 n=0;for(const auto& item:dataset.sources)if(item->logical==s.logical)++n;sqlite3_result_int64(context,n);break;}
            default:return SQLITE_RANGE;
            }return SQLITE_OK;
        }
        if (table.kind == Kind::snapshot) {
            switch (index) {
            case 0: return text8(context,dataset.snapshot_id);
            case 1: return text8(context,dataset.namespace_key);
            case 2: return hex8(context,dataset.namespace_key);
            case 3: sqlite3_result_int64(context,dataset.scope_complete?1:0); break;
            case 4: sqlite3_result_int64(context,static_cast<sqlite3_int64>(dataset.inputs.size())); break;
            case 5: sqlite3_result_int64(context,static_cast<sqlite3_int64>(dataset.sources.size())); break;
            case 6: sqlite3_result_int64(context,static_cast<sqlite3_int64>(dataset.input_bytes)); break;
            case 7: sqlite3_result_int64(context,static_cast<sqlite3_int64>(dataset.dex_bytes)); break;
            case 8: sqlite3_result_int64(context,static_cast<sqlite3_int64>(dataset.strings)); break;
            case 9: sqlite3_result_int64(context,static_cast<sqlite3_int64>(dataset.types)); break;
            case 10: sqlite3_result_int64(context,static_cast<sqlite3_int64>(dataset.classes)); break;
            case 11: sqlite3_result_int64(context,static_cast<sqlite3_int64>(dataset.method_refs)); break;
            case 12: sqlite3_result_int64(context,static_cast<sqlite3_int64>(dataset.methods)); break;
            default: return SQLITE_RANGE;
            } return SQLITE_OK;
        }
        if (table.kind == Kind::inputs) {
            const auto& input=dataset.inputs[cursor.source];
            switch (index) {
            case 0: sqlite3_result_int64(context,static_cast<sqlite3_int64>(cursor.source)); break;
            case 1: sqlite3_result_int64(context,input.format); break;
            case 2: return text8(context,input.slot);
            case 3: return text8(context,input.role);
            case 4: return hex8(context,input.slot);
            case 5: return hex8(context,input.role);
            case 6: return text8(context,input.digest);
            case 7: return text8(context,input.content);
            case 8: sqlite3_result_int64(context,static_cast<sqlite3_int64>(input.bytes)); break;
            case 9: sqlite3_result_int64(context,input.source_count); break;
            case 10: sqlite3_result_int64(context,input.allow_no_dex?1:0); break;
            case 11: sqlite3_result_int64(context,input.expected_verified?1:0); break;
            case 12: sqlite3_result_int64(context,input.container_checked?1:0); break;
            default: return SQLITE_RANGE;
            } return SQLITE_OK;
        }
        const auto& source=*dataset.sources[cursor.source];
        switch (index) {
        case 0: sqlite3_result_int64(context,static_cast<sqlite3_int64>(cursor.source)); break;
        case 1: sqlite3_result_int64(context,source.input_index); break;
        case 2: return text8(context,source.slot_key);
        case 3: return text8(context,source.role);
        case 4: return hex8(context,source.slot_key);
        case 5: return hex8(context,source.role);
        case 6: return text8(context,source.digest);
        case 7: return text8(context,source.content);
        case 8: return text8(context,source.occurrence);
        case 9: return text8(context,source.logical);
        case 10: sqlite3_result_int64(context,static_cast<sqlite3_int64>(source.view().size())); break;
        case 11: sqlite3_result_int64(context,source.facts.dex_version); break;
        case 12: if(source.entry_index!=UINT32_MAX) return text8(context,source.archive_digest); sqlite3_result_null(context); break;
        case 13: if(source.entry_index!=UINT32_MAX) return text8(context,source.entry_name); sqlite3_result_null(context); break;
        case 14: if(source.entry_index!=UINT32_MAX) sqlite3_result_int64(context,source.entry_index); else sqlite3_result_null(context); break;
        case 15: sqlite3_result_int64(context,source.crc_verified?1:0); break;
        case 16: sqlite3_result_int64(context,source.header_verified?1:0); break;
        case 17: sqlite3_result_int64(context,source.expected_verified?1:0); break;
        default: return SQLITE_RANGE;
        } return SQLITE_OK;
    }
    if (is_site(table.kind)) {
        if (cursor.ordinal >= cursor.sites.size()) return SQLITE_MISUSE;
        const auto& site = cursor.sites[cursor.ordinal];
        switch (index) {
        case 0: sqlite3_result_int64(context, site.key.source_index); break;
        case 1: sqlite3_result_int64(context, site.key.caller_ordinal); break;
        case 2: sqlite3_result_int64(context, site.caller_method_ref); break;
        case 3: sqlite3_result_int64(context, site.code_offset); break;
        case 4: sqlite3_result_int64(context, site.key.dex_pc); break;
        case 5: sqlite3_result_int64(context, site.opcode); break;
        case 6: sqlite3_result_int64(context, static_cast<uint32_t>(site.target_domain)); break;
        case 7: sqlite3_result_int64(context, site.target_index); break;
        case 8: if (site.extra_proto == UINT32_MAX) sqlite3_result_null(context); else sqlite3_result_int64(context, site.extra_proto); break;
        default: return SQLITE_RANGE;
        }
        return SQLITE_OK;
    }
    if (cursor.source >= table.dataset->sources.size()) return SQLITE_MISUSE;
    const auto& source = *table.dataset->sources[cursor.source];
    const auto& f = source.facts;
    if (table.kind == Kind::string_values || table.kind == Kind::string_data) {
        switch (index) {
        case 0: sqlite3_result_int64(context, static_cast<sqlite3_int64>(cursor.source)); break;
        case 1: sqlite3_result_int64(context, cursor.ordinal); break;
        case 2: return table.kind == Kind::string_values ? text16(context, f.strings[cursor.ordinal]) : raw_mutf8(context,source,cursor.ordinal,table.cancel);
        case 3: if(table.kind != Kind::string_data)return SQLITE_RANGE;sqlite3_result_int64(context,static_cast<sqlite3_int64>(f.strings[cursor.ordinal].size()));break;
        default: return SQLITE_RANGE;
        }
        return SQLITE_OK;
    }
    if (table.kind == Kind::type_refs || table.kind == Kind::class_defs) {
        const auto ref_id = table.kind == Kind::type_refs ? cursor.ordinal : f.class_definitions[cursor.ordinal].type_id;
        const auto definition = table.kind == Kind::class_defs ? cursor.ordinal : f.class_definition_by_type[ref_id];
        switch (index) {
        case 0: sqlite3_result_int64(context, static_cast<sqlite3_int64>(cursor.source)); break;
        case 1: sqlite3_result_int64(context, cursor.ordinal); break;
        case 2: sqlite3_result_int64(context, ref_id); break;
        case 3: if (definition != UINT32_MAX) sqlite3_result_int64(context, definition); else sqlite3_result_null(context); break;
        case 4: return text16(context, f.strings[f.types[ref_id]]);
        case 5: if (definition != UINT32_MAX) sqlite3_result_int64(context, f.class_definitions[definition].access_flags); else sqlite3_result_null(context); break;
        case 6: if (definition != UINT32_MAX) sqlite3_result_int64(context, f.class_definitions[definition].definition_offset); else sqlite3_result_null(context); break;
        case 7: {
            if (definition == UINT32_MAX || f.class_definitions[definition].superclass_type == UINT32_MAX)
                sqlite3_result_null(context);
            else return text16(context, f.strings[f.types[f.class_definitions[definition].superclass_type]]);
            break;
        }
        default: return SQLITE_RANGE;
        }
        return SQLITE_OK;
    }
    if (table.kind == Kind::field_refs || table.kind == Kind::field_defs) {
        const auto ref_id = table.kind == Kind::field_refs ? cursor.ordinal : f.field_definitions[cursor.ordinal].field_ref_index;
        const auto definition = table.kind == Kind::field_defs ? cursor.ordinal : f.field_definition_by_ref[ref_id];
        const auto& ref = f.field_refs[ref_id];
        switch (index) {
        case 0: sqlite3_result_int64(context, static_cast<sqlite3_int64>(cursor.source)); break;
        case 1: sqlite3_result_int64(context, cursor.ordinal); break;
        case 2: sqlite3_result_int64(context, ref_id); break;
        case 3: if (definition != UINT32_MAX) sqlite3_result_int64(context, definition); else sqlite3_result_null(context); break;
        case 4: return text16(context, f.strings[f.types[ref.owner]]);
        case 5: return text16(context, f.strings[ref.name]);
        case 6: return text16(context, f.strings[f.types[ref.type]]);
        case 7: if (definition != UINT32_MAX) sqlite3_result_int64(context, f.field_definitions[definition].access_flags); else sqlite3_result_null(context); break;
        case 8: if (definition != UINT32_MAX) sqlite3_result_int64(context, f.field_definitions[definition].declaration_offset); else sqlite3_result_null(context); break;
        default: return SQLITE_RANGE;
        }
        return SQLITE_OK;
    }
    const auto ref_id = table.kind == Kind::refs ? cursor.ordinal : f.methods[cursor.ordinal].method_index;
    const auto definition = table.kind == Kind::defs ? cursor.ordinal : f.method_definition_by_ref[ref_id];
    const auto& ref = f.method_refs[ref_id];
    switch (index) {
    case 0: sqlite3_result_int64(context, static_cast<sqlite3_int64>(cursor.source)); break;
    case 1: sqlite3_result_int64(context, cursor.ordinal); break;
    case 2: sqlite3_result_int64(context, ref_id); break;
    case 3: if (definition != UINT32_MAX) sqlite3_result_int64(context, definition); else sqlite3_result_null(context); break;
    case 4: return text16(context, f.strings[f.types[ref.owner]]);
    case 5: return text16(context, f.strings[ref.name]);
    case 6: return text16(context, f.prototypes[ref.type].descriptor);
    case 7: if (definition != UINT32_MAX) sqlite3_result_int64(context, f.methods[definition].access_flags); else sqlite3_result_null(context); break;
    case 8: if (definition != UINT32_MAX) sqlite3_result_int64(context, f.methods[definition].declaration_offset); else sqlite3_result_null(context); break;
    case 9: if (table.kind == Kind::defs && f.methods[definition].code_offset != 0) sqlite3_result_int64(context, f.methods[definition].code_offset); else sqlite3_result_null(context); break;
    default: return SQLITE_RANGE;
    }
    return SQLITE_OK;
}
int rowid(sqlite3_vtab_cursor* raw, sqlite3_int64* value) noexcept {
    const auto& cursor = *static_cast<const Cursor*>(raw);
    const auto& table = *static_cast<const Table*>(raw->pVtab);
    if (is_catalog(table.kind)) {
        if (cursor.source >= catalog_count(table)) return SQLITE_MISUSE;
        *value=static_cast<sqlite3_int64>(cursor.source);return SQLITE_OK;
    }
    if (is_site(table.kind)) {
        if (cursor.ordinal >= cursor.sites.size()) return SQLITE_MISUSE;
        *value = static_cast<sqlite3_int64>(cursor.ordinal) + 1;
        return SQLITE_OK;
    }
    if (cursor.source >= table.dataset->sources.size()) return SQLITE_MISUSE;
    *value = (sqlite3_int64(cursor.source) << 32) | cursor.ordinal;
    return SQLITE_OK;
}
const sqlite3_module& module() {
    static const sqlite3_module value = [] {
        sqlite3_module m{};
        m.iVersion = 3;
        m.xConnect = connect; m.xBestIndex = best_index; m.xDisconnect = disconnect;
        m.xOpen = open; m.xClose = close; m.xFilter = filter; m.xNext = next;
        m.xEof = eof; m.xColumn = column; m.xRowid = rowid;
        return m;
    }();
    return value;
}
bool checked(const Dataset& data, sqlite3_int64& refs, sqlite3_int64& defs,
             sqlite3_int64& field_refs, sqlite3_int64& field_defs,
             sqlite3_int64& type_refs, sqlite3_int64& class_defs, sqlite3_int64& strings, bool allow_incomplete) noexcept {
    if ((!allow_incomplete && !data.scope_complete) || data.sources.size() > 1024 || data.inputs.size() > 64 ||
        data.input_bytes > uint64_t(std::numeric_limits<sqlite3_int64>::max()) ||
        data.dex_bytes > uint64_t(std::numeric_limits<sqlite3_int64>::max()) ||
        data.strings > uint64_t(std::numeric_limits<sqlite3_int64>::max()) ||
        data.types > uint64_t(std::numeric_limits<sqlite3_int64>::max()) ||
        data.classes > uint64_t(std::numeric_limits<sqlite3_int64>::max()) ||
        data.method_refs > uint64_t(std::numeric_limits<sqlite3_int64>::max()) ||
        data.methods > uint64_t(std::numeric_limits<sqlite3_int64>::max())) return false;
    for (const auto& input : data.inputs)
        if (input.bytes > uint64_t(std::numeric_limits<sqlite3_int64>::max())) return false;
    refs = defs = field_refs = field_defs = type_refs = class_defs = strings = 0;
    for (size_t i = 0; i < data.sources.size(); ++i) {
        const auto& source = data.sources[i];
        if (!source || source->engine != data.engine) return false;
        const auto& f = source->facts;
        if (f.method_refs.size() >= UINT32_MAX || f.methods.size() >= UINT32_MAX ||
            f.method_definition_by_ref.size() != f.method_refs.size() ||
            f.field_refs.size() >= UINT32_MAX || f.field_definitions.size() >= UINT32_MAX ||
            f.field_definition_by_ref.size() != f.field_refs.size() ||
            f.types.size() >= UINT32_MAX || f.class_definitions.size() >= UINT32_MAX || f.strings.size() >= UINT32_MAX ||
            f.class_definition_by_type.size() != f.types.size()) return false;
        if (uint64_t(f.method_refs.size()) > uint64_t(std::numeric_limits<sqlite3_int64>::max() - refs) ||
            uint64_t(f.methods.size()) > uint64_t(std::numeric_limits<sqlite3_int64>::max() - defs) ||
            uint64_t(f.field_refs.size()) > uint64_t(std::numeric_limits<sqlite3_int64>::max() - field_refs) ||
            uint64_t(f.field_definitions.size()) > uint64_t(std::numeric_limits<sqlite3_int64>::max() - field_defs) ||
            uint64_t(f.types.size()) > uint64_t(std::numeric_limits<sqlite3_int64>::max() - type_refs) ||
            uint64_t(f.class_definitions.size()) > uint64_t(std::numeric_limits<sqlite3_int64>::max() - class_defs) ||
            uint64_t(f.strings.size()) > uint64_t(std::numeric_limits<sqlite3_int64>::max() - strings)) return false;
        refs += static_cast<sqlite3_int64>(f.method_refs.size());
        defs += static_cast<sqlite3_int64>(f.methods.size());
        field_refs += static_cast<sqlite3_int64>(f.field_refs.size());
        field_defs += static_cast<sqlite3_int64>(f.field_definitions.size());
        type_refs += static_cast<sqlite3_int64>(f.types.size());
        class_defs += static_cast<sqlite3_int64>(f.class_definitions.size());
        strings += static_cast<sqlite3_int64>(f.strings.size());
        for (size_t j = 0; j < f.method_refs.size(); ++j) {
            const auto& ref = f.method_refs[j];
            if (ref.owner >= f.types.size() || f.types[ref.owner] >= f.strings.size() ||
                ref.name >= f.strings.size() || ref.type >= f.prototypes.size()) return false;
            const auto d = f.method_definition_by_ref[j];
            if (d != UINT32_MAX && (d >= f.methods.size() || f.methods[d].method_index != j)) return false;
        }
        for (size_t j = 0; j < f.methods.size(); ++j) {
            const auto ref = f.methods[j].method_index;
            if (ref >= f.method_refs.size() || f.method_definition_by_ref[ref] != j) return false;
        }
        for (size_t j = 0; j < f.field_refs.size(); ++j) {
            const auto& ref = f.field_refs[j];
            if (ref.owner >= f.types.size() || f.types[ref.owner] >= f.strings.size() ||
                ref.type >= f.types.size() || f.types[ref.type] >= f.strings.size() || ref.name >= f.strings.size()) return false;
            const auto d = f.field_definition_by_ref[j];
            if (d != UINT32_MAX && (d >= f.field_definitions.size() || f.field_definitions[d].field_ref_index != j)) return false;
        }
        for (size_t j = 0; j < f.field_definitions.size(); ++j) {
            const auto ref = f.field_definitions[j].field_ref_index;
            if (ref >= f.field_refs.size() || f.field_definition_by_ref[ref] != j) return false;
        }
        for (size_t j = 0; j < f.types.size(); ++j) {
            if (f.types[j] >= f.strings.size()) return false;
            const auto d = f.class_definition_by_type[j];
            if (d != UINT32_MAX && (d >= f.class_definitions.size() || f.class_definitions[d].type_id != j)) return false;
        }
        for (size_t j = 0; j < f.class_definitions.size(); ++j) {
            const auto& definition = f.class_definitions[j];
            if (definition.type_id >= f.types.size() || f.class_definition_by_type[definition.type_id] != j ||
                (definition.superclass_type != UINT32_MAX && definition.superclass_type >= f.types.size())) return false;
        }
    }
    return true;
}
}

namespace {
int register_tables(sqlite3* db, const std::shared_ptr<const Dataset>& dataset,
                    sqlite3_int64 refs, sqlite3_int64 defs, sqlite3_int64 field_refs,
                    sqlite3_int64 field_defs, sqlite3_int64 type_refs, sqlite3_int64 class_defs, sqlite3_int64 strings,
                    SqlSiteLimits site_limits, SqlCancel* cancel, StatementSiteBudget* statement_budget, bool identity_pushdown, bool identity_in) noexcept {
    auto destroy = [](void* ptr) { delete static_cast<Auxiliary*>(ptr); };
    struct Entry { const char* name; Kind kind; sqlite3_int64 rows; };
    for (const auto& entry : {Entry{"dmg_snapshot", Kind::snapshot, 1},
                              Entry{"dmg_inputs", Kind::inputs, static_cast<sqlite3_int64>(dataset->inputs.size())},
                              Entry{"dmg_sources", Kind::sources, static_cast<sqlite3_int64>(dataset->sources.size())},
                              Entry{"dmg_logical_dex", Kind::logical_dex, static_cast<sqlite3_int64>(dataset->sources.size())},
                              Entry{"dmg_method_refs", Kind::refs, refs},
                              Entry{"dmg_method_defs", Kind::defs, defs},
                              Entry{"dmg_field_refs", Kind::field_refs, field_refs},
                              Entry{"dmg_field_defs", Kind::field_defs, field_defs},
                              Entry{"dmg_type_refs", Kind::type_refs, type_refs},
                              Entry{"dmg_class_defs", Kind::class_defs, class_defs},
                              Entry{"dmg_string_values", Kind::string_values, strings},
                              Entry{"dmg_string_data", Kind::string_data, strings},
                              Entry{"dmg_string_uses", Kind::string_uses, max_site_records},
                              Entry{"dmg_invoke_sites", Kind::invoke_sites, max_site_records},
                              Entry{"dmg_field_uses", Kind::field_uses, max_site_records},
                              Entry{"dmg_type_uses", Kind::type_uses, max_site_records}}) {
        auto* auxiliary = new (std::nothrow) Auxiliary{dataset, entry.kind, entry.rows, site_limits, cancel, statement_budget, identity_pushdown, identity_in};
        if (!auxiliary) return SQLITE_NOMEM;
        const int rc = sqlite3_create_module_v2(db, entry.name, &module(), auxiliary, destroy);
        if (rc != SQLITE_OK) return rc;
    }
    return SQLITE_OK;
}
struct Statement {
    sqlite3_stmt* value = nullptr;
    ~Statement() { if (value) sqlite3_finalize(value); }
};
int safe_authorizer(void*, int action, const char*, const char* function, const char*, const char*) noexcept {
    switch (action) {
    case SQLITE_SELECT: case SQLITE_READ: case SQLITE_RECURSIVE:
        return SQLITE_OK;
    case SQLITE_FUNCTION:
        if (function && (!sqlite3_stricmp(function, "count") || !sqlite3_stricmp(function, "sum") ||
                         !sqlite3_stricmp(function, "like") || !sqlite3_stricmp(function, "zeroblob"))) return SQLITE_OK;
        return SQLITE_DENY;
    default:
        return SQLITE_DENY;
    }
}
void increment_saturated(uint64_t& value,uint64_t amount=1) noexcept {
    value = amount > UINT64_MAX - value ? UINT64_MAX : value + amount;
}
}

struct SqlSession::Impl {
    sqlite3* db = nullptr;
    std::shared_ptr<const Dataset> dataset;
    SqlCancel cancel{};
    SqlSiteLimits site_limits{};
    StatementSiteBudget statement_budget{};
    bool scoped = false;
    bool profile_enabled = false, profile_has_last = false;
    uint64_t profile_sequence = 0;
    SqlQueryProfile last_profile{};
    bool reuse_enabled = false;
    uint64_t reuse_max_bytes = 0, reuse_max_query_bytes = 0;
    sqlite3_stmt* reuse_statement = nullptr;
    std::string reuse_sql;
    SqlStatementReuseStats reuse_stats{};
#ifdef DMG_SQLITE_PROTO_TESTING
    sqlite3_stmt* held = nullptr;
    bool* close_returned = nullptr;
#endif
};

SqlSession::SqlSession(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
SqlSession::~SqlSession() {
    // The API never exposes statements and is single-threaded. If a misuse or
    // unexpected SQLite failure leaves the connection busy, retain both DB and
    // Dataset rather than releasing a borrowed lease inside SQLite's mutex.
    if (close() != SQLITE_OK) (void)impl_.release();
}
int configure_private_sqlite_heap(uint64_t limit_bytes) noexcept {
    if (!limit_bytes || limit_bytes > static_cast<uint64_t>(std::numeric_limits<sqlite3_int64>::max())) return SQLITE_MISUSE;
    return dmg_private_sqlite3_configure_heap_limit(static_cast<sqlite3_int64>(limit_bytes));
}
int private_sqlite_heap_stats(SqliteHeapStats& out) noexcept {
    sqlite3_int64 limit=0,used=0,peak=0;int configured=0,started=0;
    const int rc=dmg_private_sqlite3_heap_snapshot(&limit,&used,&peak,&configured,&started);
    if(rc!=SQLITE_OK)return rc;
    if(limit<0||used<0||peak<0||(configured!=0&&configured!=1)||(started!=0&&started!=1))return SQLITE_ERROR;
    const SqliteHeapStats pending{static_cast<uint64_t>(limit),static_cast<uint64_t>(used),static_cast<uint64_t>(peak),configured!=0,started!=0};
    out=pending;return SQLITE_OK;
}
int SqlSession::open(const dmg_snapshot* snapshot, std::unique_ptr<SqlSession>& out) noexcept {
    return open(snapshot,out,{});
}
int SqlSession::open(const dmg_snapshot* snapshot, std::unique_ptr<SqlSession>& out, SqlSiteLimits site_limits) noexcept {
    return open_impl(snapshot, out, site_limits, false, {});
}
int SqlSession::open_scoped(const dmg_snapshot* snapshot, std::unique_ptr<SqlSession>& out, SqlSiteLimits site_limits) noexcept {
    return open_impl(snapshot, out, site_limits, true, {});
}
int SqlSession::open_planned(const dmg_snapshot* snapshot, std::unique_ptr<SqlSession>& out, SqlSiteLimits site_limits, SqlPlanningOptions planning) noexcept {
    return open_impl(snapshot, out, site_limits, false, planning);
}
int SqlSession::open_scoped_planned(const dmg_snapshot* snapshot, std::unique_ptr<SqlSession>& out, SqlSiteLimits site_limits, SqlPlanningOptions planning) noexcept {
    return open_impl(snapshot, out, site_limits, true, planning);
}
int SqlSession::open_impl(const dmg_snapshot* snapshot, std::unique_ptr<SqlSession>& out, SqlSiteLimits site_limits, bool scoped, SqlPlanningOptions planning) noexcept {
    if (!snapshot || out || !site_limits.max_work || site_limits.max_work > max_site_work ||
        !site_limits.max_records || site_limits.max_records > max_site_records ||
        site_limits.max_statement_work > max_site_work || site_limits.max_statement_records > max_site_records ||
        (planning.metadata_identity_in && !planning.metadata_identity_equality)) return SQLITE_MISUSE;
    try {
        const auto engine = snapshot->owner;
        const auto dataset = snapshot->dataset;
        if (!engine || !dataset || dataset->engine != engine) return SQLITE_MISUSE;
        {
            std::lock_guard lock(engine->admission);
            if (engine->closed || snapshot->closed.load(std::memory_order_acquire)) return SQLITE_MISUSE;
        }
        // This adapter has direct byte readers outside reference::execute.
        // Their 041 logical-header bases have not been admitted as a profile.
        for (const auto& source : dataset->sources)
            if (source->facts.dex_version == 41) return SQLITE_MISMATCH;
        sqlite3_int64 refs = 0, defs = 0, field_refs = 0, field_defs = 0, type_refs = 0, class_defs = 0, strings = 0;
        if (!checked(*dataset, refs, defs, field_refs, field_defs, type_refs, class_defs, strings, scoped)) return SQLITE_MISUSE;
        auto candidate = std::unique_ptr<SqlSession>(new SqlSession(std::make_unique<Impl>()));
        candidate->impl_->dataset = dataset; // Hold before any SQLite callback can run.
        candidate->impl_->scoped = scoped;
        candidate->impl_->site_limits = site_limits;
        int rc = sqlite3_open_v2(":memory:", &candidate->impl_->db,
                                 SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr);
        if (rc != SQLITE_OK) return rc;
        rc = register_tables(candidate->impl_->db, dataset, refs, defs, field_refs, field_defs, type_refs, class_defs, strings, site_limits, &candidate->impl_->cancel, &candidate->impl_->statement_budget, planning.metadata_identity_equality, planning.metadata_identity_in);
        if (rc != SQLITE_OK) return rc;
        out = std::move(candidate);
        return SQLITE_OK;
    } catch (const std::bad_alloc&) { return SQLITE_NOMEM; }
    catch (...) { return SQLITE_ERROR; }
}
int SqlSession::close() noexcept {
    if (!impl_) return SQLITE_OK;
    if (impl_->reuse_statement) {
        const int finalized = sqlite3_finalize(impl_->reuse_statement);
        impl_->reuse_statement = nullptr;impl_->reuse_sql.clear();
        impl_->reuse_stats.cached=false;impl_->reuse_stats.retained_statement_bytes=0;
        if(finalized != SQLITE_OK) return finalized;
    }
    const int rc = impl_->db ? sqlite3_close(impl_->db) : SQLITE_OK;
#ifdef DMG_SQLITE_PROTO_TESTING
    if (impl_->close_returned) *impl_->close_returned = rc == SQLITE_OK;
#endif
    if (rc != SQLITE_OK) return rc;
    impl_->db = nullptr;
    // sqlite3_close has returned and its db mutex is no longer held.
    impl_->dataset.reset();
    return SQLITE_OK;
}
int SqlSession::enable_profiling(bool enabled) noexcept {
    if (!impl_ || !impl_->db) return SQLITE_MISUSE;
    if (impl_->profile_enabled != enabled) {
        impl_->profile_enabled = enabled;
        impl_->profile_has_last = false;
    }
    return SQLITE_OK;
}
int SqlSession::last_query_profile(SqlQueryProfile& out) const noexcept {
    if (!impl_ || !impl_->db) return SQLITE_MISUSE;
    if (!impl_->profile_enabled || !impl_->profile_has_last) return SQLITE_NOTFOUND;
    out = impl_->last_profile;return SQLITE_OK;
}
int SqlSession::enable_statement_reuse(uint64_t max_statement_bytes) noexcept {
    if(!impl_||!impl_->db||!impl_->scoped||impl_->reuse_enabled||!max_statement_bytes||max_statement_bytes>(16u<<20))return SQLITE_MISUSE;
    const int rc=sqlite3_set_authorizer(impl_->db,safe_authorizer,nullptr);
    if(rc!=SQLITE_OK)return rc;
    impl_->reuse_max_bytes=max_statement_bytes;impl_->reuse_enabled=true;return SQLITE_OK;
}
int SqlSession::statement_reuse_stats(SqlStatementReuseStats& out) const noexcept {
    if(!impl_||!impl_->db||!impl_->scoped)return SQLITE_MISUSE;
    if(!impl_->reuse_enabled)return SQLITE_NOTFOUND;
    out=impl_->reuse_stats;return SQLITE_OK;
}
int SqlSession::clear_statement_reuse_cache() noexcept {
    if (!impl_ || !impl_->db || !impl_->scoped || !impl_->reuse_enabled) return SQLITE_MISUSE;
    sqlite3_stmt* statement = impl_->reuse_statement;
    impl_->reuse_statement = nullptr;
    impl_->reuse_sql.clear();
    impl_->reuse_max_query_bytes = 0;
    impl_->reuse_stats.cached = false;
    impl_->reuse_stats.retained_statement_bytes = 0;
    return statement ? sqlite3_finalize(statement) : SQLITE_OK;
}
int SqlSession::configure_cursor_quota(uint32_t count,uint64_t bytes) noexcept {
    if(!impl_||!impl_->db||!impl_->scoped||cursor_attempted_||cursor_quota_||
       !count||count>1024||!bytes||bytes>(uint64_t(1)<<30))return SQLITE_MISUSE;
    try {cursor_quota_=std::make_shared<detail::CursorQuota>(count,bytes);return SQLITE_OK;}
    catch(const std::bad_alloc&){return SQLITE_NOMEM;}
    catch(...){return SQLITE_ERROR;}
}
int SqlSession::cursor_quota_stats(SqlCursorQuotaStats& out) const noexcept {
    if(!impl_||!impl_->db||!impl_->scoped)return SQLITE_MISUSE;
    if(!cursor_quota_)return SQLITE_NOTFOUND;
    const SqlCursorQuotaStats pending{cursor_quota_->max_cursors,cursor_quota_->live.load(std::memory_order_relaxed),
        cursor_quota_->max_bytes,cursor_quota_->bytes.load(std::memory_order_relaxed)};
    out=pending;return SQLITE_OK;
}
int SqlSession::query(std::string_view sql, std::optional<std::string_view> parameter,
                      uint64_t max_rows, uint64_t max_bytes, SqlRows& out,
                      uint64_t max_progress_intervals) noexcept {
    return query(sql,parameter,max_rows,max_bytes,out,max_progress_intervals,{});
}
int SqlSession::query(std::string_view sql, std::optional<std::string_view> parameter,
                      uint64_t max_rows, uint64_t max_bytes, SqlRows& out,
                      uint64_t max_progress_intervals, SqlCancel cancel) noexcept {
    if (impl_ && impl_->scoped) return SQLITE_MISUSE;
    return query_impl(sql, parameter, max_rows, max_bytes, out, max_progress_intervals, cancel);
}
int SqlSession::query_scoped(std::string_view sql, std::optional<std::string_view> parameter,
                             uint64_t max_rows, uint64_t max_bytes, SqlScopedResult& out,
                             uint64_t max_progress_intervals, SqlCancel cancel) noexcept {
    const SqlParameter single{SqlParameter::Kind::text, 0, parameter.value_or(std::string_view{})};
    return query_scoped_bound(sql, parameter ? std::span<const SqlParameter>(&single, 1) : std::span<const SqlParameter>{},
                              max_rows, max_bytes, out, max_progress_intervals, cancel);
}
int SqlSession::query_scoped_bound(std::string_view sql, std::span<const SqlParameter> parameters,
                                   uint64_t max_rows, uint64_t max_bytes, SqlScopedResult& out,
                                   uint64_t max_progress_intervals, SqlCancel cancel) noexcept {
    if (!impl_ || !impl_->db || !impl_->dataset || !impl_->scoped) return SQLITE_MISUSE;
    try {
        SqlScopedResult pending;
        const auto& dataset = *impl_->dataset;
        pending.snapshot_id.assign(dataset.snapshot_id.data(), dataset.snapshot_id.size());
        pending.source_scope = dataset.scope_complete ? SqlScopeCoverage::declared_complete_source_scope
                                                       : SqlScopeCoverage::partial_source_scope;
        pending.input_count = static_cast<uint32_t>(dataset.inputs.size());
        pending.source_count = static_cast<uint32_t>(dataset.sources.size());
        const int rc = query_bound_impl(sql, parameters, max_rows, max_bytes, pending.rows, max_progress_intervals, cancel);
        if (rc != SQLITE_OK) return rc;
        out.rows.swap(pending.rows);
        out.snapshot_id.swap(pending.snapshot_id);
        out.source_scope = pending.source_scope;
        out.input_count = pending.input_count;
        out.source_count = pending.source_count;
        return SQLITE_OK;
    } catch (const std::bad_alloc&) { return SQLITE_NOMEM; }
    catch (...) { return SQLITE_ERROR; }
}
int SqlSession::query_scoped_reused_bound(std::string_view sql, std::span<const SqlParameter> parameters,
                                         uint64_t max_rows, uint64_t max_bytes, SqlScopedResult& out,
                                         uint64_t max_progress_intervals, SqlCancel cancel) noexcept {
    if(!impl_||!impl_->db||!impl_->dataset||!impl_->scoped||!impl_->reuse_enabled)return SQLITE_MISUSE;
    try {
        SqlScopedResult pending;const auto& dataset=*impl_->dataset;
        pending.snapshot_id.assign(dataset.snapshot_id.data(),dataset.snapshot_id.size());
        pending.source_scope=dataset.scope_complete?SqlScopeCoverage::declared_complete_source_scope:SqlScopeCoverage::partial_source_scope;
        pending.input_count=static_cast<uint32_t>(dataset.inputs.size());pending.source_count=static_cast<uint32_t>(dataset.sources.size());
        const int rc=query_bound_impl(sql,parameters,max_rows,max_bytes,pending.rows,max_progress_intervals,cancel,nullptr,nullptr,nullptr,true);
        if(rc!=SQLITE_OK)return rc;
        out.rows.swap(pending.rows);out.snapshot_id.swap(pending.snapshot_id);out.source_scope=pending.source_scope;
        out.input_count=pending.input_count;out.source_count=pending.source_count;return SQLITE_OK;
    } catch(const std::bad_alloc&){return SQLITE_NOMEM;}catch(...){return SQLITE_ERROR;}
}
int SqlSession::query_provisional_scoped_bound(std::string_view sql, std::span<const SqlParameter> parameters,
                                                uint64_t max_rows, uint64_t max_bytes, SqlProvisionalSink sink,
                                                SqlProvisionalOutcome& terminal,
                                                uint64_t max_progress_intervals, SqlCancel cancel) noexcept {
    if (!impl_ || !impl_->db || !impl_->dataset || !impl_->scoped || !sink.on_row) return SQLITE_MISUSE;
    try {
        SqlProvisionalOutcome pending;
        const auto& dataset = *impl_->dataset;
        pending.scope.snapshot_id.assign(dataset.snapshot_id.data(), dataset.snapshot_id.size());
        pending.scope.source_scope = dataset.scope_complete ? SqlScopeCoverage::declared_complete_source_scope
                                                            : SqlScopeCoverage::partial_source_scope;
        pending.scope.input_count = static_cast<uint32_t>(dataset.inputs.size());
        pending.scope.source_count = static_cast<uint32_t>(dataset.sources.size());
        SqlRows unused;
        const int rc = query_bound_impl(sql, parameters, max_rows, max_bytes, unused, max_progress_intervals,
                                        cancel, &sink, &pending.scope, &pending.rows_emitted);
        pending.execution_status = rc;pending.terminal = true;
        terminal.scope.snapshot_id.swap(pending.scope.snapshot_id);
        terminal.scope.source_scope = pending.scope.source_scope;
        terminal.scope.input_count = pending.scope.input_count;
        terminal.scope.source_count = pending.scope.source_count;
        terminal.rows_emitted = pending.rows_emitted;
        terminal.execution_status = pending.execution_status;
        terminal.terminal = pending.terminal;
        return rc;
    } catch (const std::bad_alloc&) { return SQLITE_NOMEM; }
    catch (...) { return SQLITE_ERROR; }
}
int SqlSession::query_impl(std::string_view sql, std::optional<std::string_view> parameter,
                           uint64_t max_rows, uint64_t max_bytes, SqlRows& out,
                           uint64_t max_progress_intervals, SqlCancel cancel) noexcept {
    const SqlParameter single{SqlParameter::Kind::text, 0, parameter.value_or(std::string_view{})};
    return query_bound_impl(sql, parameter ? std::span<const SqlParameter>(&single, 1) : std::span<const SqlParameter>{},
                            max_rows, max_bytes, out, max_progress_intervals, cancel);
}
int SqlSession::query_bound_impl(std::string_view sql, std::span<const SqlParameter> parameters,
                                 uint64_t max_rows, uint64_t max_bytes, SqlRows& out,
                                 uint64_t max_progress_intervals, SqlCancel cancel,
                                 const SqlProvisionalSink* sink, const SqlProvisionalScope* scope,
                                 uint64_t* emitted, bool reuse) noexcept {
    if (!impl_ || !impl_->db || !impl_->profile_enabled)
        return query_bound_execute(sql, parameters, max_rows, max_bytes, out, max_progress_intervals, cancel, nullptr, sink, scope, emitted, reuse);
    using Clock = std::chrono::steady_clock;
    const auto start = Clock::now();SqlQueryProfile profile;
    if (impl_->profile_sequence != UINT64_MAX) ++impl_->profile_sequence;
    profile.sequence = impl_->profile_sequence;
    const int rc = query_bound_execute(sql, parameters, max_rows, max_bytes, out, max_progress_intervals, cancel, &profile, sink, scope, emitted, reuse);
    const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start).count();
    profile.elapsed_us = elapsed > 0 ? static_cast<uint64_t>(elapsed) : 0;
    profile.execution_status = rc;
    if (rc == SQLITE_OK) profile.rows_committed = sink ? *emitted : static_cast<uint64_t>(out.size());
    impl_->last_profile = profile;impl_->profile_has_last = true;
    return rc;
}
int SqlSession::query_bound_execute(std::string_view sql, std::span<const SqlParameter> parameters,
                                    uint64_t max_rows, uint64_t max_bytes, SqlRows& out,
                                    uint64_t max_progress_intervals, SqlCancel cancel, SqlQueryProfile* profile,
                                    const SqlProvisionalSink* sink, const SqlProvisionalScope* scope,
                                    uint64_t* emitted, bool reuse) noexcept {
    if (!impl_ || !impl_->db || sql.empty() || sql.size() > 65536 ||
        sql.find('\0') != std::string_view::npos || !max_rows || max_rows > 100000 ||
        !max_bytes || max_bytes > (8u << 20) || !max_progress_intervals ||
        max_progress_intervals > 1000000 || parameters.size() > 256 ||
        (sink && (!sink->on_row || !scope || !emitted)) || (reuse && (!impl_->reuse_enabled || sink))) return SQLITE_MISUSE;
    uint64_t bound_text_bytes = 0;
    for (const auto& value : parameters) {
        if ((value.kind == SqlParameter::Kind::text || value.kind == SqlParameter::Kind::blob)) {
            if (value.text.size() > max_bytes - bound_text_bytes ||
                value.text.size() > size_t(std::numeric_limits<int>::max())) return SQLITE_TOOBIG;
            bound_text_bytes += static_cast<uint64_t>(value.text.size());
        } else if (value.kind != SqlParameter::Kind::null && value.kind != SqlParameter::Kind::integer) {
            return SQLITE_MISUSE;
        }
    }
    if (cancel.requested && cancel.requested(cancel.context)) return SQLITE_INTERRUPT;
    try {
        struct ActiveSiteBudget {
            StatementSiteBudget& current;
            ActiveSiteBudget(StatementSiteBudget& slot, const SqlSiteLimits& limits) noexcept : current(slot) {
                current = {true, limits.max_statement_work, limits.max_statement_records};
            }
            ~ActiveSiteBudget() { current = {}; }
        } site_budget{impl_->statement_budget, impl_->site_limits};
        struct ActiveCancel {
            SqlCancel& current;
            ActiveCancel(SqlCancel& slot, SqlCancel value) noexcept : current(slot) { current=value; }
            ~ActiveCancel() { current={}; }
        } active{impl_->cancel,cancel};
        struct ProgressBudget { uint64_t remaining; SqlCancel cancel; SqlQueryProfile* profile; } budget{max_progress_intervals,cancel,profile};
        struct Limits {
            sqlite3* db;
            int previous_length;
            bool preserve_authorizer;
            ~Limits() {
                sqlite3_progress_handler(db, 0, nullptr, nullptr);
                if (!preserve_authorizer) sqlite3_set_authorizer(db, nullptr, nullptr);
                sqlite3_limit(db, SQLITE_LIMIT_LENGTH, previous_length);
            }
        } limits{impl_->db, sqlite3_limit(impl_->db, SQLITE_LIMIT_LENGTH, static_cast<int>(max_bytes)), impl_->reuse_enabled};
        const int authorization = impl_->reuse_enabled ? SQLITE_OK : sqlite3_set_authorizer(impl_->db,safe_authorizer,nullptr);
        if (authorization != SQLITE_OK) return authorization;
        sqlite3_progress_handler(impl_->db, 100, [](void* context) noexcept -> int {
            auto& state = *static_cast<ProgressBudget*>(context);
            if (state.profile && state.profile->progress_callbacks != UINT64_MAX) ++state.profile->progress_callbacks;
            if (state.cancel.requested && state.cancel.requested(state.cancel.context)) return 1;
            auto& remaining = state.remaining;
            if (!remaining) return 1;
            --remaining;
            return 0;
        }, &budget);
        Statement statement;
        const char* tail = nullptr;
        const auto prepare_start = profile ? std::chrono::steady_clock::now() : std::chrono::steady_clock::time_point{};
        const bool hit=reuse&&impl_->reuse_statement&&impl_->reuse_max_query_bytes==max_bytes&&impl_->reuse_sql==sql;
        int rc=SQLITE_OK;
        if(hit){
            statement.value=impl_->reuse_statement;impl_->reuse_statement=nullptr;impl_->reuse_sql.clear();
            impl_->reuse_stats.cached=false;impl_->reuse_stats.retained_statement_bytes=0;
            increment_saturated(impl_->reuse_stats.cache_hits);
        }else{
            if(reuse&&impl_->reuse_statement){
                rc=sqlite3_finalize(impl_->reuse_statement);impl_->reuse_statement=nullptr;impl_->reuse_sql.clear();
                impl_->reuse_stats.cached=false;impl_->reuse_stats.retained_statement_bytes=0;
                if(rc!=SQLITE_OK)return rc;
            }
            if (profile) profile->prepare_attempted = true;
            if(reuse)increment_saturated(impl_->reuse_stats.prepare_attempts);
            rc = sqlite3_prepare_v2(impl_->db, sql.data(), static_cast<int>(sql.size()), &statement.value, &tail);
            if (profile) {
                const auto value = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - prepare_start).count();
                profile->prepare_us = value > 0 ? static_cast<uint64_t>(value) : 0;
                profile->prepared = rc == SQLITE_OK && statement.value != nullptr;
            }
            if (rc != SQLITE_OK) return rc;
            if (!statement.value) return SQLITE_MISUSE;
            const char* end = sql.data() + sql.size();
            for (const char* p = tail; p < end; ++p)
                if (*p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') return SQLITE_MISUSE;
        }
        if(reuse)(void)sqlite3_stmt_status(statement.value,SQLITE_STMTSTATUS_REPREPARE,1);
        if (!sqlite3_stmt_readonly(statement.value)) return SQLITE_READONLY;
        const int bind_count = sqlite3_bind_parameter_count(statement.value);
        if (bind_count < 0 || static_cast<size_t>(bind_count) != parameters.size()) return SQLITE_RANGE;
        for (size_t i = 0; i < parameters.size(); ++i) {
            const auto& value = parameters[i];const int index = static_cast<int>(i + 1);
            if (value.kind == SqlParameter::Kind::null) rc = sqlite3_bind_null(statement.value, index);
            else if (value.kind == SqlParameter::Kind::integer) rc = sqlite3_bind_int64(statement.value, index, value.integer);
            else if (value.kind == SqlParameter::Kind::blob) rc = sqlite3_bind_blob(statement.value, index, value.text.empty()?"":value.text.data(), static_cast<int>(value.text.size()), SQLITE_TRANSIENT);
            else {
                const auto* p = value.text.empty() ? "" : value.text.data();
                rc = sqlite3_bind_text(statement.value, index, p, static_cast<int>(value.text.size()), SQLITE_TRANSIENT);
            }
#ifdef DMG_SQLITE_PROTO_TESTING
            if (rc == SQLITE_OK) ++bind_success_count;
            else { bind_failure_index = index; bind_failure_code = rc; }
#endif
            if (rc != SQLITE_OK) return rc;
        }
        const int columns = sqlite3_column_count(statement.value);
        if (columns < 1 || columns > 128) return SQLITE_TOOBIG;
        SqlRows rows;
        uint64_t used = 0, row_count = 0;
        const auto charge = [&](uint64_t amount) {
            if (amount > max_bytes - used) return false;
            used += amount;
            return true;
        };
        bool first_step = true;
        for (;;) {
            const auto step_start = profile && first_step ? std::chrono::steady_clock::now() : std::chrono::steady_clock::time_point{};
            rc = sqlite3_step(statement.value);
            if (profile && first_step) {
                const auto value = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - step_start).count();
                profile->first_step_us = value > 0 ? static_cast<uint64_t>(value) : 0;
                profile->first_step_status = rc;profile->first_step_observed = true;
            }
            first_step = false;
            if (rc != SQLITE_ROW) break;
            if (cancel.requested && cancel.requested(cancel.context)) return SQLITE_INTERRUPT;
            if (row_count >= max_rows || !charge(8 + uint64_t(columns) * 16)) return SQLITE_TOOBIG;
#ifdef DMG_SQLITE_PROTO_TESTING
            if (row_copy_failure_after == 0) throw std::bad_alloc();
            if (row_copy_failure_after > 0) --row_copy_failure_after;
#endif
            std::vector<SqlValue> row;
            row.reserve(static_cast<size_t>(columns));
            for (int i = 0; i < columns; ++i) {
                SqlValue value;
                const int type = sqlite3_column_type(statement.value, i);
                if (type == SQLITE_INTEGER) {
                    value.kind = SqlValue::Kind::integer;
                    value.integer = sqlite3_column_int64(statement.value, i);
                } else if (type == SQLITE_TEXT) {
                    const auto* bytes = reinterpret_cast<const char*>(sqlite3_column_text(statement.value, i));
                    const int length = sqlite3_column_bytes(statement.value, i);
                    if (!bytes) return SQLITE_NOMEM;
                    if (length < 0 || !charge(static_cast<uint64_t>(length))) return SQLITE_TOOBIG;
                    value.kind = SqlValue::Kind::text;
                    value.text.assign(bytes, static_cast<size_t>(length));
                } else if (type == SQLITE_BLOB) {
                    const auto* bytes = static_cast<const char*>(sqlite3_column_blob(statement.value, i));
                    const int length = sqlite3_column_bytes(statement.value, i);
                    if (length < 0 || !charge(static_cast<uint64_t>(length))) return SQLITE_TOOBIG;
                    if (!bytes && length != 0) return SQLITE_NOMEM;
                    value.kind = SqlValue::Kind::blob;
                    if (length) value.text.assign(bytes, static_cast<size_t>(length));
                } else if (type != SQLITE_NULL) return SQLITE_MISMATCH;
                row.push_back(std::move(value));
            }
            if (sink) {
                const auto index = row_count++;
                *emitted = row_count;
                if (profile) profile->rows_staged = row_count;
                if (sink->on_row(sink->context, index, *scope, row) != 0) return SQLITE_ABORT;
            } else {
                rows.push_back(std::move(row));++row_count;
                if (profile) profile->rows_staged = row_count;
            }
        }
        if (rc != SQLITE_DONE) return rc;
        if(reuse){
            const int reprepares=sqlite3_stmt_status(statement.value,SQLITE_STMTSTATUS_REPREPARE,1);
            if(reprepares<0)return SQLITE_ERROR;
            increment_saturated(impl_->reuse_stats.automatic_reprepares,static_cast<uint64_t>(reprepares));
            rc=sqlite3_reset(statement.value);if(rc!=SQLITE_OK)return rc;
            rc=sqlite3_clear_bindings(statement.value);if(rc!=SQLITE_OK)return rc;
            if(cancel.requested&&cancel.requested(cancel.context))return SQLITE_INTERRUPT;
            const int memory=sqlite3_stmt_status(statement.value,SQLITE_STMTSTATUS_MEMUSED,0);
            if(memory<0)return SQLITE_ERROR;
            if(static_cast<uint64_t>(memory)<=impl_->reuse_max_bytes){
                impl_->reuse_sql.assign(sql);impl_->reuse_max_query_bytes=max_bytes;
                impl_->reuse_statement=statement.value;statement.value=nullptr;
                impl_->reuse_stats.cached=true;impl_->reuse_stats.retained_statement_bytes=static_cast<uint64_t>(memory);
            }
        }
        if(statement.value){rc=sqlite3_finalize(statement.value);statement.value=nullptr;if(rc!=SQLITE_OK)return rc;}
        if (cancel.requested && cancel.requested(cancel.context)) {
            if(reuse&&impl_->reuse_statement){
                (void)sqlite3_finalize(impl_->reuse_statement);impl_->reuse_statement=nullptr;impl_->reuse_sql.clear();
                impl_->reuse_stats.cached=false;impl_->reuse_stats.retained_statement_bytes=0;
            }
            return SQLITE_INTERRUPT;
        }
        if (!sink) out.swap(rows); // Strict queries expose no row before successful finalize.
        return SQLITE_OK;
    } catch (const std::bad_alloc&) { return SQLITE_NOMEM; }
    catch (...) { return SQLITE_ERROR; }
}

#ifdef DMG_SQLITE_PROTO_TESTING
int SqlSessionProbe::configure_private_log(void (*callback)(void*,int,const char*) noexcept, void* context) noexcept {
    return dmg_private_sqlite3_test_config_log(callback, context);
}
int SqlSessionProbe::emit_private_log(SqlSession& session) noexcept {
    if (!session.impl_ || !session.impl_->db) return SQLITE_MISUSE;
    return dmg_private_sqlite3_test_exec(session.impl_->db, "SELECT sqlite_log(12345,'dmg-test-sentinel')");
}
bool SqlSessionProbe::private_default_vfs_is(const char* name) noexcept {
    return dmg_private_sqlite3_test_default_vfs_is(name) != 0;
}
bool SqlSessionProbe::in_site_cancel_callback() noexcept { return ::dexmeguviz::desktop_sql::in_site_cancel_callback; }
void SqlSessionProbe::fail_utf8_after(int64_t count) noexcept { utf8_failure_after=count; utf8_successful_conversions=0; utf8_allocation_attempts=0; }
void SqlSessionProbe::fail_row_copy_after(int64_t count) noexcept { row_copy_failure_after=count; }
uint64_t SqlSessionProbe::utf8_conversions() noexcept { return utf8_successful_conversions; }
uint64_t SqlSessionProbe::utf8_allocations() noexcept { return utf8_allocation_attempts; }
void SqlSessionProbe::reset_identity_filter_metrics() noexcept { identity_integer_filters=0; identity_rowid_filters=0; identity_source_mask=0; identity_in_filters=0; identity_in_fallbacks=0; }
uint64_t SqlSessionProbe::identity_filter_count() noexcept { return identity_integer_filters; }
uint64_t SqlSessionProbe::identity_rowid_filter_count() noexcept { return identity_rowid_filters; }
uint32_t SqlSessionProbe::identity_filter_source_mask() noexcept { return identity_source_mask; }
uint64_t SqlSessionProbe::identity_in_filter_count() noexcept { return identity_in_filters; }
uint64_t SqlSessionProbe::identity_in_fallback_count() noexcept { return identity_in_fallbacks; }
bool SqlSessionProbe::in_identity_in_callback() noexcept { return in_identity_in_cancel_callback; }
void SqlSessionProbe::fail_scratch_after(int64_t count) noexcept { dexmeguviz::test_fail_allocation_after(count); }
void SqlSessionProbe::reset_bind_observation() noexcept { ::dexmeguviz::desktop_sql::bind_success_count=0;::dexmeguviz::desktop_sql::bind_failure_index=0;::dexmeguviz::desktop_sql::bind_failure_code=0; }
uint32_t SqlSessionProbe::bind_success_count() noexcept { return ::dexmeguviz::desktop_sql::bind_success_count; }
int SqlSessionProbe::bind_failure_index() noexcept { return ::dexmeguviz::desktop_sql::bind_failure_index; }
int SqlSessionProbe::bind_failure_code() noexcept { return ::dexmeguviz::desktop_sql::bind_failure_code; }
void SqlSessionProbe::observe_close_return(SqlSession& session, bool* result) noexcept {
    session.impl_->close_returned = result;
}
int SqlSessionProbe::hold_statement(SqlSession& session) noexcept {
    if (!session.impl_ || !session.impl_->db || session.impl_->held) return SQLITE_MISUSE;
    int rc = sqlite3_prepare_v2(session.impl_->db, "SELECT name FROM dmg_method_refs", -1, &session.impl_->held, nullptr);
    if (rc != SQLITE_OK) return rc;
    rc = sqlite3_step(session.impl_->held);
    return rc == SQLITE_ROW ? SQLITE_OK : rc;
}
int SqlSessionProbe::release_statement(SqlSession& session) noexcept {
    if (!session.impl_ || !session.impl_->held) return SQLITE_MISUSE;
    const int rc = sqlite3_finalize(session.impl_->held);
    session.impl_->held = nullptr;
    return rc;
}
#endif
}


