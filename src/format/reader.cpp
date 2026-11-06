#include "format/dex_names.hpp"
#include "reader.hpp"
#include "checked_leb128.hpp"
#include "dex041/container.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <string_view>
#include <tuple>
#include <utility>

namespace dexmeguviz {
namespace {
constexpr uint64_t max_items = 1'000'000;
constexpr uint64_t max_string_units = 1'048'576;
constexpr uint64_t max_text_units = 16'777'216;
constexpr uint32_t no_index = 0xffffffffu;

struct Section {
    uint16_t type;
    uint32_t count;
    uint32_t offset;
    uint64_t end;
};
struct Table { uint32_t count; uint32_t offset; uint32_t width; };
struct TypeListItem { uint32_t offset; uint32_t count; };
struct CodeItem { uint32_t offset; uint16_t registers; uint16_t incoming; uint32_t units; uint32_t end; };
struct DebugInfoItem {
    uint32_t offset; uint32_t parameters; uint32_t max_register_plus_one; uint32_t max_register_at;
    uint64_t max_address; uint32_t max_address_at; uint32_t invalid_line_at;
};
struct CodeDebugItem { uint32_t code_offset; uint32_t debug_offset; uint32_t parameters; };
struct EncodedArrayItem { uint32_t offset; uint32_t count; std::array<uint8_t, 3> first_types{}; };
struct AnnotationItem { uint32_t offset; uint32_t type; };
struct AnnotationSet { uint32_t offset; };
struct AnnotationRefList { uint32_t offset; uint32_t count; };
struct AnnotationDirectory { uint32_t offset; uint32_t fields; uint32_t methods; uint32_t parameters; };
struct EncodedFrame { uint32_t remaining; bool annotation; uint32_t previous_name; bool has_name; };

class Reader {
public:
    explicit Reader(std::span<const uint8_t> input, std::pmr::memory_resource* resource, bool validate_debug_associations = false,uint32_t logical_header=UINT32_MAX,std::span<const dex041::Header> container_headers={})
        : bytes(input), resource(resource), facts(resource), sections(resource), strings(resource),
          types(resource), protos(resource), fields(resource), methods(resource),
          type_lists(resource), code_items(resource), encoded_arrays(resource), annotation_items(resource),
          annotation_sets(resource), annotation_ref_lists(resource), annotation_directories(resource), debug_items(resource),
          debug_associations(resource), code_debug_associations(resource), check_debug_associations(validate_debug_associations),experimental041(logical_header!=UINT32_MAX),header_offset(logical_header==UINT32_MAX?0:logical_header),headers(container_headers) {}

    Facts run() {
        header();
        read_strings();
        read_types();
        index_type_lists();
        read_protos();
        read_refs(fields, tables[3], false);
        read_refs(methods, tables[4], true);
        read_method_handles();
        index_encoded_arrays();
        index_annotations();
        read_call_sites();
        index_debug_info();
        index_code_items();
        definitions();
        facts.strings = std::move(strings);
        facts.types = std::move(types);
        facts.prototypes = std::move(protos);
        facts.method_refs = std::move(methods);
        facts.field_refs = std::move(fields);
        return std::move(facts);
    }

private:
    std::span<const uint8_t> bytes;
    std::pmr::memory_resource* resource;
    Facts facts;
    std::array<Table, 6> tables{};
    std::pmr::vector<Section> sections;
    std::pmr::vector<std::pmr::u16string> strings;
    std::pmr::vector<uint32_t> types;
    std::pmr::vector<Prototype> protos;
    std::pmr::vector<FieldReference> fields;
    std::pmr::vector<MethodReference> methods;
    std::pmr::vector<TypeListItem> type_lists;
    std::pmr::vector<CodeItem> code_items;
    std::pmr::vector<EncodedArrayItem> encoded_arrays;
    std::pmr::vector<AnnotationItem> annotation_items;
    std::pmr::vector<AnnotationSet> annotation_sets;
    std::pmr::vector<AnnotationRefList> annotation_ref_lists;
    std::pmr::vector<AnnotationDirectory> annotation_directories;
    std::pmr::vector<uint32_t> debug_items;
    std::pmr::vector<DebugInfoItem> debug_associations;
    std::pmr::vector<CodeDebugItem> code_debug_associations;
    bool check_debug_associations;
    bool experimental041;uint32_t header_offset;std::span<const dex041::Header> headers;
    uint64_t text_units = 0;
    uint64_t list_items = 0;
    uint32_t data_offset = 0;

    [[noreturn]] void fail(uint64_t at, const char* message) const {
        throw ReadError(ReadCode::corrupt, at, message);
    }
    [[noreturn]] void unsupported(uint64_t at, const char* message) const {
        throw ReadError(ReadCode::unsupported, at, message);
    }
    void range(uint64_t at, uint64_t count, uint64_t width, uint64_t end) const {
        if ((experimental041&&at<header_offset)||end > bytes.size() || at > end || width == 0 || count > (end - at) / width)
            fail(at, "range exceeds the containing section");
        if(experimental041&&count){
            const uint64_t stop=at+count*width;
            auto next=std::lower_bound(headers.begin(),headers.end(),at,[](const auto& h,uint64_t value){return uint64_t(h.offset)+120<=value;});
            for(;next!=headers.end()&&next->offset<stop;++next)if(next->offset!=header_offset)fail(at,"041 data overlaps another logical header");
        }

    }
    void range(uint64_t at, uint64_t count, uint64_t width = 1) const {
        range(at, count, width, bytes.size());
    }
    uint16_t u16(uint64_t at) const {
        range(at, 2);
        return static_cast<uint16_t>(uint16_t(bytes[at]) | (uint16_t(bytes[at + 1]) << 8));
    }
    uint32_t u32(uint64_t at) const {
        range(at, 4);
        return uint32_t(bytes[at]) | (uint32_t(bytes[at + 1]) << 8) |
               (uint32_t(bytes[at + 2]) << 16) | (uint32_t(bytes[at + 3]) << 24);
    }
    void charge_text(uint64_t units, uint64_t at) {
        if (units > max_text_units - text_units)
            throw ReadError(ReadCode::budget, at, "metadata text exceeds 16777216 UTF-16 units");
        text_units += units;
    }
    void charge_items(uint64_t count, uint64_t at) {
        if (count > max_items - list_items)
            throw ReadError(ReadCode::budget, at, "expanded metadata lists exceed 1000000 entries");
        list_items += count;
    }
    const Section* find(uint16_t type) const {
        const auto it = std::find_if(sections.begin(), sections.end(),
            [type](const Section& item) { return item.type == type; });
        return it == sections.end() ? nullptr : &*it;
    }
    const Section& section(uint16_t type, uint64_t at, uint64_t size = 1) const {
        const auto* item = find(type);
        if (!item || at < item->offset) fail(at, "offset does not reference the required mapped section");
        range(at, size, 1, item->end);
        return *item;
    }
    void index(uint32_t value, uint64_t count, uint64_t at) const {
        if (value >= count) fail(at, "table index out of range");
    }
    void aligned(uint64_t at) const {
        if (at % 4 != 0) fail(at, "required four-byte alignment is missing");
    }
    uint32_t uleb(uint64_t& cursor, uint64_t end) const {
        const auto begin=cursor;const auto value=detail::read_uleb32(bytes,cursor,end);range(begin,cursor-begin,1,end);return value;
    }
    void padding(uint64_t begin, uint64_t end) const {
        range(begin, end >= begin ? end - begin : std::numeric_limits<uint64_t>::max());
        if(experimental041)return;
        for (auto at = begin; at < end; ++at)
            if (bytes[at] != 0) fail(at, "nonzero alignment padding");
    }
    uint64_t align_item(uint64_t cursor, const Section& area) const {
        const uint64_t next = (cursor + 3) & ~uint64_t(3);
        if (next > area.end) fail(cursor, "aligned item starts outside the section");
        padding(cursor, next);
        return next;
    }
    void finish_section(const Section& area, uint64_t cursor) const {
        if(experimental041){if(cursor>area.end)fail(cursor,"041 section exceeds its mapped bound");return;}
        if (cursor > area.end) fail(cursor, "section count exceeds its mapped bound");
        // Between mapped sections, DEX allows a larger all-zero gap than the
        // minimum alignment padding. Item count and item starts were checked
        // by the caller; a nonzero residual cannot be hidden as padding.
        if (area.end == bytes.size() && cursor != area.end)
            fail(cursor, "section count leaves unaccounted item bytes");
        padding(cursor, area.end);
    }
    void finish_annotation_section(const Section& area, uint64_t cursor) const {
        if (cursor > area.end) fail(cursor, "annotation item exceeds its section");
        if(!experimental041)padding(cursor, area.end);
    }
    std::pair<uint32_t, uint32_t> layout(uint16_t type) const {
        switch (type) {
        case 0x0000: return {experimental041?120u:112u, 4};
        case 0x0001: case 0x0002: case 0x0007: return {4, 4};
        case 0x0003: return {12, 4};
        case 0x0004: case 0x0005: case 0x0008: return {8, 4};
        case 0x0006: return {32, 4};
        case 0x1000: case 0x1001: case 0x1002: case 0x1003: return {4, 4};
        case 0x2000: return {4, 1};
        case 0x2001: return {16, 4};
        case 0x2002: return {2, 1};
        case 0x2003: return {3, 1};
        case 0x2004: return {3, 1};
        case 0x2005: return {1, 1};
        case 0x2006: return {16, 4};
        case 0xf000: return {4, 1};
        default: return {0, 0};
        }
    }
    void header() {
        const uint64_t base=header_offset;
        if(!experimental041&&bytes.size()>=2&&bytes[0]=='P'&&bytes[1]=='K')unsupported(0,"APK/ZIP is not supported by raw metadata");
        if(!experimental041&&bytes.size()>=4&&bytes[0]=='c'&&bytes[1]=='d'&&bytes[2]=='e'&&bytes[3]=='x')unsupported(0,"compact DEX is not supported");
        range(base,8);
        if(bytes[base]!='d'||bytes[base+1]!='e'||bytes[base+2]!='x'||bytes[base+3]!='\n'||bytes[base+7]!=0)fail(base,"invalid DEX magic");
        uint32_t version=0;for(size_t i=4;i<7;++i){if(bytes[base+i]<'0'||bytes[base+i]>'9')fail(base+i,"invalid DEX version");version=version*10+bytes[base+i]-'0';}
        if(experimental041?version!=41:(version!=35&&version!=37&&version!=38&&version!=39&&version!=40))unsupported(base+4,"DEX version requires its explicit reader profile");
        const uint32_t header_size=experimental041?120:112;range(base,header_size);
        auto h32=[&](uint32_t at){return u32(base+at);};
        if(h32(40)==0x78563412)unsupported(base+40,"reverse-endian DEX is not supported");
        if(h32(40)!=0x12345678||h32(36)!=header_size)fail(base+36,"DEX endian/header size");
        if(experimental041){if(h32(112)!=bytes.size()||h32(116)!=base||h32(32)<120||h32(32)>bytes.size()-base)fail(base+32,"041 logical/container bounds");}
        else if(h32(32)!=bytes.size())fail(32,"DEX file_size does not match input");
        const auto link_size=h32(44),link_offset=h32(48);if((link_size==0)!=(link_offset==0))fail(base+44,"inconsistent link fields");
        if(link_size){range(link_offset,link_size);unsupported(base+44,"linked DEX is not supported");}
        if(experimental041)data_offset=header_offset+120;
        else{data_offset=h32(108);const auto data_size=h32(104);if(!data_size||data_offset<112)fail(104,"missing data section");aligned(data_offset);range(data_offset,data_size);if(uint64_t(data_offset)+data_size!=bytes.size())fail(104,"data section extent");}
        constexpr std::array<uint32_t, 6> widths{4, 4, 12, 8, 8, 32};
        uint64_t total = 0;
        for (size_t i = 0; i < tables.size(); ++i) {
            const uint64_t at = base + 56 + i * 8;
            tables[i] = {u32(at), u32(at + 4), widths[i]};
            const auto& t = tables[i];
            total += t.count;
            if (total > max_items) throw ReadError(ReadCode::budget, at, "header tables exceed 1000000 entries");
            if ((t.count == 0) != (t.offset == 0)) fail(at, "empty table must have a zero offset");
            if (t.count != 0) {
                aligned(t.offset);
                if (t.offset < base + header_size) fail(at + 4, "table overlaps the DEX header");
                range(t.offset, t.count, t.width, experimental041?bytes.size():data_offset);
            }
        }
        if (tables[1].count > 65535 || tables[2].count > 65535)
            fail(64, "type/prototype table exceeds the DEX 16-bit index limit");
        const auto map_offset = h32(52);
        aligned(map_offset);
        if (map_offset < data_offset) fail(52, "map is outside the data section");
        range(map_offset, 4);
        const auto map_count = u32(map_offset);
        if (map_count == 0 || map_count > 64) fail(map_offset, "invalid map entry count");
        range(uint64_t(map_offset) + 4, map_count, 12);
        sections.reserve(map_count);
        uint64_t mapped_items = 0;
        for (uint32_t i = 0; i < map_count; ++i) {
            const uint64_t at = uint64_t(map_offset) + 4 + uint64_t(i) * 12;
            const auto type = u16(at);
            const auto count = u32(at + 4), offset = u32(at + 8);
            const auto [minimum, alignment] = layout(type);
            if (minimum == 0) unsupported(at, "unrecognized DEX map item type");
            if ((type == 7 || type == 8) && version < 38) fail(at, "method handles/call sites require DEX 038 or newer");
            if (u16(at + 2) != 0 || count == 0) fail(at, "invalid map reserved field or count");
            if (find(type)) fail(at, "duplicate map item type");
            if (!sections.empty() && offset <= sections.back().offset) fail(at + 8, "map offsets are not strictly increasing");
            if (offset % alignment != 0) fail(at + 8, "misaligned map section");
            if (type >= 0x1000 && offset < data_offset) fail(at + 8, "data item is outside the data section");
            range(offset, count, minimum);
            mapped_items += count;
            if (mapped_items > max_items) throw ReadError(ReadCode::budget, at, "mapped items exceed 1000000 entries");
            sections.push_back({type, count, offset, bytes.size()});
        }
        for (size_t i = 0; i < sections.size(); ++i) {
            auto& item = sections[i];
            if (i + 1 < sections.size()) item.end = sections[i + 1].offset;
            range(item.offset, item.count, layout(item.type).first, item.end);
        }
        const auto* header_section = find(0);
        const auto* map_section = find(0x1000);
        if (!header_section || header_section->offset != header_offset || header_section->count != 1)
            fail(map_offset, "map must describe exactly the selected logical header");
        if (!map_section || map_section->offset != map_offset || map_section->count != 1)
            fail(map_offset, "map does not describe itself consistently");
        range(uint64_t(map_offset) + 4, map_count, 12, map_section->end);
        for (size_t i = 0; i < tables.size(); ++i) {
            const auto* item = find(static_cast<uint16_t>(i + 1));
            const auto& t = tables[i];
            if (t.count == 0) { if (item) fail(item->offset, "map describes an empty header table"); }
            else if (!item || item->offset != t.offset || item->count != t.count)
                fail(t.offset, "map and header table disagree");
        }
        facts.header_offset=header_offset;facts.logical_file_size=h32(32);facts.container_size=static_cast<uint32_t>(bytes.size());
        facts.dex_version = version;
        facts.string_count = tables[0].count;
        facts.type_count = tables[1].count;
        facts.class_count = tables[5].count;
        facts.method_ref_count = tables[4].count;
        if (const auto* call_sites = find(7)) facts.call_site_count = call_sites->count;
        if (const auto* handles = find(8)) facts.method_handle_count = handles->count;
    }
    void read_method_handles() {
        const auto* area = find(8);
        if (!area) return;
        for (uint32_t i = 0; i < area->count; ++i) {
            const uint64_t at = uint64_t(area->offset) + uint64_t(i) * 8;
            const auto kind = u16(at);
            const auto ref = u16(at + 4);
            if (kind > 8) fail(at, "invalid method handle type");
            index(ref, kind <= 3 ? fields.size() : methods.size(), at + 4);
        }
    }
    void encoded_values(uint64_t& cursor, uint64_t end, uint32_t count, bool top_annotation,
                        std::pmr::vector<EncodedFrame>& stack, std::pmr::vector<uint8_t>& annotation_name_validity,
                        std::array<uint8_t, 3>* first_types = nullptr) {
        constexpr size_t max_depth = 1024;
        stack.clear();
        stack.push_back({count, top_annotation, 0, false});
        uint32_t top_index = 0;
        while (!stack.empty()) {
            auto& frame = stack.back();
            if (!frame.remaining) { stack.pop_back(); continue; }
            if (frame.annotation) {
                const uint64_t at = cursor;
                const auto name = uleb(cursor, end);
                index(name, strings.size(), at);
                if (annotation_name_validity.empty()) annotation_name_validity.resize(strings.size(), 0);
                auto& validity = annotation_name_validity[name];
                if (validity == 0) validity = member_name(strings[name]) ? 1 : 2;
                if (validity == 2) fail(at, "invalid annotation element name");
                if (frame.has_name && name <= frame.previous_name)
                    fail(at, "annotation element names are not strictly ordered");
                frame.previous_name = name;
                frame.has_name = true;
            }
            --frame.remaining;
            const uint64_t at = cursor;
            range(cursor, 1, 1, end);
            const uint8_t tag = bytes[cursor++];
            const uint8_t value_type = tag & 0x1f, arg = tag >> 5;
            if (first_types && stack.size() == 1 && top_index < first_types->size())
                (*first_types)[top_index] = value_type;
            if (stack.size() == 1) ++top_index;
            uint8_t max_arg = 0;
            switch (value_type) {
            case 0x00: max_arg = 0; break;
            case 0x02: case 0x03: max_arg = 1; break;
            case 0x04: case 0x10: case 0x15: case 0x16: case 0x17:
            case 0x18: case 0x19: case 0x1a: case 0x1b: max_arg = 3; break;
            case 0x06: case 0x11: max_arg = 7; break;
            case 0x1e: if (arg != 0) fail(at, "invalid null value_arg"); continue;
            case 0x1f: if (arg > 1) fail(at, "invalid boolean value_arg"); continue;
            case 0x1c: case 0x1d: {
                if (arg != 0) fail(at, "invalid nested value_arg");
                if (stack.size() >= max_depth)
                    throw ReadError(ReadCode::budget, at, "encoded value nesting exceeds 1024 levels");
                const bool annotation = value_type == 0x1d;
                if (annotation) {
                    const uint64_t type_at = cursor;
                    const auto type_id = uleb(cursor, end);
                    index(type_id, types.size(), type_at);
                    if (type(type_id).empty() || type(type_id).front() != u'L')
                        fail(type_at, "annotation type must be a class");
                }
                const uint64_t count_at = cursor;
                const auto nested_count = uleb(cursor, end);
                charge_items(nested_count, count_at);
                stack.push_back({nested_count, annotation, 0, false});
                continue;
            }
            default: fail(at, "unknown encoded value type");
            }
            if (arg > max_arg) fail(at, "invalid encoded value_arg");
            if ((value_type == 0x15 || value_type == 0x16) && facts.dex_version < 38)
                fail(at, "method type and handle values require DEX 038 or newer");
            range(cursor, uint64_t(arg) + 1, 1, end);
            uint32_t reference = 0;
            if (value_type >= 0x15 && value_type <= 0x1b) {
                for (uint8_t byte = 0; byte <= arg; ++byte)
                    reference |= uint32_t(bytes[cursor + byte]) << (byte * 8);
                uint64_t bound = 0;
                switch (value_type) {
                case 0x15: bound = protos.size(); break;
                case 0x16: bound = facts.method_handle_count; break;
                case 0x17: bound = strings.size(); break;
                case 0x18: bound = types.size(); break;
                case 0x19: case 0x1b: bound = fields.size(); break;
                case 0x1a: bound = methods.size(); break;
                }
                index(reference, bound, at);
            }
            cursor += uint64_t(arg) + 1;
        }
    }
    void index_encoded_arrays() {
        const auto* area = find(0x2005);
        if (!area) return;
        std::pmr::vector<EncodedFrame> stack(resource);
        std::pmr::vector<uint8_t> annotation_name_validity(resource);
        encoded_arrays.reserve(area->count);
        uint64_t cursor = area->offset;
        for (uint32_t item = 0; item < area->count; ++item) {
            const uint64_t start = cursor;
            const auto count = uleb(cursor, area->end);
            charge_items(count, start);
            EncodedArrayItem array{static_cast<uint32_t>(start), count, {}};
            encoded_values(cursor, area->end, count, false, stack, annotation_name_validity, &array.first_types);
            encoded_arrays.push_back(array);
        }
        finish_section(*area, cursor);
    }
    const EncodedArrayItem& encoded_array(uint32_t offset) const {
        const auto found = std::lower_bound(encoded_arrays.begin(), encoded_arrays.end(), offset,
            [](const EncodedArrayItem& item, uint32_t key) { return item.offset < key; });
        if (found == encoded_arrays.end() || found->offset != offset)
            fail(offset, "offset does not reference an encoded array item start");
        return *found;
    }
    template <typename T>
    const T& annotation_at(const std::pmr::vector<T>& items, uint32_t offset) const {
        const auto found = std::lower_bound(items.begin(), items.end(), offset,
            [](const T& item, uint32_t key) { return item.offset < key; });
        if (found == items.end() || found->offset != offset)
            fail(offset, "annotation offset does not reference an item start");
        return *found;
    }
    void index_annotations() {
        if (const auto* area = find(0x2004)) {
            std::pmr::vector<EncodedFrame> stack(resource);
            std::pmr::vector<uint8_t> annotation_name_validity(resource);
            uint64_t cursor = area->offset;
            annotation_items.reserve(area->count);
            for (uint32_t i = 0; i < area->count; ++i) {
                const auto start = cursor;
                range(cursor, 1, 1, area->end);
                if (bytes[cursor++] > 2) fail(start, "invalid annotation visibility");
                const auto type_at = cursor;
                const auto type_id = uleb(cursor, area->end);
                index(type_id, types.size(), type_at);
                if (type(type_id).empty() || type(type_id).front() != u'L')
                    fail(type_at, "annotation type must be a class");
                const auto count_at = cursor;
                const auto count = uleb(cursor, area->end);
                charge_items(count, count_at);
                encoded_values(cursor, area->end, count, true, stack, annotation_name_validity);
                annotation_items.push_back({static_cast<uint32_t>(start), type_id});
            }
            finish_annotation_section(*area, cursor);
        }
        if (const auto* area = find(0x1003)) {
            uint64_t cursor = area->offset;
            annotation_sets.reserve(area->count);
            for (uint32_t i = 0; i < area->count; ++i) {
                cursor = align_item(cursor, *area);
                const auto start = cursor;
                range(cursor, 4, 1, area->end);
                const auto count = u32(cursor); cursor += 4;
                range(cursor, count, 4, area->end);
                charge_items(count, start);
                uint32_t previous = 0;
                for (uint32_t j = 0; j < count; ++j, cursor += 4) {
                    const auto& item = annotation_at(annotation_items, u32(cursor));
                    if (j && item.type <= previous) fail(cursor, "annotation types are not strictly ordered");
                    previous = item.type;
                }
                annotation_sets.push_back({static_cast<uint32_t>(start)});
            }
            finish_annotation_section(*area, cursor);
        }
        if (const auto* area = find(0x1002)) {
            uint64_t cursor = area->offset;
            annotation_ref_lists.reserve(area->count);
            for (uint32_t i = 0; i < area->count; ++i) {
                cursor = align_item(cursor, *area);
                const auto start = cursor;
                range(cursor, 4, 1, area->end);
                const auto count = u32(cursor); cursor += 4;
                range(cursor, count, 4, area->end);
                charge_items(count, start);
                for (uint32_t j = 0; j < count; ++j, cursor += 4) {
                    const auto offset = u32(cursor);
                    if (offset) (void)annotation_at(annotation_sets, offset);
                }
                annotation_ref_lists.push_back({static_cast<uint32_t>(start), count});
            }
            finish_annotation_section(*area, cursor);
        }
        if (const auto* area = find(0x2006)) {
            uint64_t cursor = area->offset;
            annotation_directories.reserve(area->count);
            for (uint32_t i = 0; i < area->count; ++i) {
                cursor = align_item(cursor, *area);
                const auto start = cursor;
                range(cursor, 16, 1, area->end);
                const auto class_set = u32(cursor);
                const std::array<uint32_t, 3> counts{u32(cursor + 4), u32(cursor + 8), u32(cursor + 12)};
                cursor += 16;
                const uint64_t total = uint64_t(counts[0]) + counts[1] + counts[2];
                range(cursor, total, 8, area->end);
                charge_items(total, start);
                if (class_set) (void)annotation_at(annotation_sets, class_set);
                for (size_t group = 0; group < counts.size(); ++group) {
                    uint32_t previous = 0;
                    for (uint32_t j = 0; j < counts[group]; ++j, cursor += 8) {
                        const auto id = u32(cursor), offset = u32(cursor + 4);
                        index(id, group == 0 ? fields.size() : methods.size(), cursor);
                        if (j && id <= previous) fail(cursor, "annotation members are not strictly ordered");
                        previous = id;
                        if (group == 2) (void)annotation_at(annotation_ref_lists, offset);
                        else (void)annotation_at(annotation_sets, offset);
                    }
                }
                annotation_directories.push_back({static_cast<uint32_t>(start), counts[0], counts[1], counts[2]});
            }
            finish_annotation_section(*area, cursor);
        }
    }
    void annotation_owners(uint32_t offset, uint32_t owner) {
        const auto& directory = annotation_at(annotation_directories, offset);
        const uint64_t total = uint64_t(directory.fields) + directory.methods + directory.parameters;
        charge_items(total, offset);
        uint64_t cursor = uint64_t(offset) + 16;
        for (uint32_t i = 0; i < directory.fields; ++i, cursor += 8)
            if (fields[u32(cursor)].owner != owner) fail(cursor, "field annotation owner mismatch");
        for (uint64_t i = 0; i < uint64_t(directory.methods) + directory.parameters; ++i, cursor += 8)
            if (methods[u32(cursor)].owner != owner) fail(cursor, "method annotation owner mismatch");
    }
    void static_value(uint64_t& cursor, uint64_t end, std::u16string_view field_type) const {
        const auto at = cursor;
        range(cursor, 1, 1, end);
        const auto tag = bytes[cursor++];
        const auto kind = uint8_t(tag & 0x1f), arg = uint8_t(tag >> 5);
        char16_t required = 0;
        switch (kind) {
        case 0x00: required = u'B'; break;
        case 0x02: required = u'S'; break;
        case 0x03: required = u'C'; break;
        case 0x04: required = u'I'; break;
        case 0x06: required = u'J'; break;
        case 0x10: required = u'F'; break;
        case 0x11: required = u'D'; break;
        case 0x1f: required = u'Z'; break;
        case 0x17: case 0x18: case 0x1e:
            if (field_type.empty() || (field_type.front() != u'L' && field_type.front() != u'['))
                fail(at, "static reference value requires a reference field");
            break;
        default: fail(at, "unsupported static field value kind");
        }
        if (required && (field_type.size() != 1 || field_type.front() != required))
            fail(at, "static field value type does not match field type");
        if (kind != 0x1e && kind != 0x1f) {
            range(cursor, uint64_t(arg) + 1, 1, end);
            cursor += uint64_t(arg) + 1;
        }
    }
    void read_call_sites() {
        const auto* area = find(7);
        if (!area) return;
        uint32_t previous = 0;
        for (uint32_t i = 0; i < area->count; ++i) {
            const uint64_t at = uint64_t(area->offset) + uint64_t(i) * 4;
            const auto offset = u32(at);
            if (i && offset < previous) fail(at, "call site offsets are not ascending");
            previous = offset;
            const auto& array = encoded_array(offset);
            if (array.count < 3 || array.first_types != std::array<uint8_t, 3>{0x16, 0x17, 0x15})
                fail(offset, "call site requires method handle, string and method type");
        }
    }
    void read_shared_strings(){
        const auto& table=tables[0];const auto* area_ptr=find(0x2002);
        if(!area_ptr){if(table.count)fail(table.offset,"missing shared string data");return;}
        const auto& area=*area_ptr;std::pmr::vector<uint32_t> offsets(resource);std::pmr::vector<std::pmr::u16string> values(resource);offsets.reserve(area.count);values.reserve(area.count);
        uint64_t cursor=area.offset;
        for(uint32_t i=0;i<area.count;++i){const uint64_t offset=cursor;
            const auto count = uleb(cursor, area.end);
            if (count > max_string_units) throw ReadError(ReadCode::budget, offset, "string exceeds 1048576 UTF-16 units");
            range(cursor, uint64_t(count) + 1, 1, area.end);
            charge_text(count, offset);
            std::pmr::u16string value(resource);
            value.reserve(count);
            for (uint32_t unit = 0; unit < count; ++unit) {
                range(cursor, 1, 1, area.end);
                const auto first = bytes[cursor++];
                uint16_t decoded = 0;
                if (first >= 1 && first <= 0x7f) decoded = first;
                else if ((first & 0xe0) == 0xc0) {
                    range(cursor, 1, 1, area.end);
                    const auto second = bytes[cursor++];
                    if ((second & 0xc0) != 0x80) fail(cursor - 1, "invalid MUTF-8 continuation byte");
                    decoded = static_cast<uint16_t>(((first & 0x1f) << 6) | (second & 0x3f));
                    if (decoded < 0x80 && !(first == 0xc0 && second == 0x80)) fail(cursor - 2, "overlong MUTF-8 encoding");
                } else if ((first & 0xf0) == 0xe0) {
                    range(cursor, 2, 1, area.end);
                    const auto second = bytes[cursor++], third = bytes[cursor++];
                    if ((second & 0xc0) != 0x80 || (third & 0xc0) != 0x80) fail(cursor - 2, "invalid MUTF-8 continuation byte");
                    decoded = static_cast<uint16_t>(((first & 0x0f) << 12) | ((second & 0x3f) << 6) | (third & 0x3f));
                    if (decoded < 0x800) fail(cursor - 3, "overlong MUTF-8 encoding");
                } else fail(cursor - 1, "invalid MUTF-8 lead byte or premature terminator");
                value.push_back(static_cast<char16_t>(decoded));
            }
            range(cursor, 1, 1, area.end);
            if (bytes[cursor++] != 0) fail(cursor - 1, "MUTF-8 UTF-16 length or terminator mismatch");
            offsets.push_back(static_cast<uint32_t>(offset));values.push_back(std::move(value));
        }
        strings.reserve(table.count);for(uint32_t i=0;i<table.count;++i){const auto offset=u32(uint64_t(table.offset)+i*4);const auto found=std::lower_bound(offsets.begin(),offsets.end(),offset);if(found==offsets.end()||*found!=offset)fail(offset,"shared string offset is not an item start");const auto& value=values[found-offsets.begin()];if(!strings.empty()&&strings.back()>=value)fail(offset,"string ID order");charge_text(value.size(),offset);strings.emplace_back(value);}
    }
    void read_strings() {
        if(experimental041){read_shared_strings();return;}
        const auto& table = tables[0];
        const auto* data = find(0x2002);
        if ((table.count != 0 && (!data || data->count != table.count)) || (table.count == 0 && data))
            fail(table.offset, "string data count does not match string IDs");
        strings.reserve(table.count);
        std::pmr::vector<std::pair<uint64_t, uint64_t>> ranges(resource);
        ranges.reserve(table.count);
        for (uint32_t i = 0; i < table.count; ++i) {
            const uint64_t offset = u32(uint64_t(table.offset) + uint64_t(i) * 4);
            const auto& area = section(0x2002, offset);
            uint64_t cursor = offset;
            const auto count = uleb(cursor, area.end);
            if (count > max_string_units) throw ReadError(ReadCode::budget, offset, "string exceeds 1048576 UTF-16 units");
            range(cursor, uint64_t(count) + 1, 1, area.end);
            charge_text(count, offset);
            std::pmr::u16string value(resource);
            value.reserve(count);
            for (uint32_t unit = 0; unit < count; ++unit) {
                range(cursor, 1, 1, area.end);
                const auto first = bytes[cursor++];
                uint16_t decoded = 0;
                if (first >= 1 && first <= 0x7f) decoded = first;
                else if ((first & 0xe0) == 0xc0) {
                    range(cursor, 1, 1, area.end);
                    const auto second = bytes[cursor++];
                    if ((second & 0xc0) != 0x80) fail(cursor - 1, "invalid MUTF-8 continuation byte");
                    decoded = static_cast<uint16_t>(((first & 0x1f) << 6) | (second & 0x3f));
                    if (decoded < 0x80 && !(first == 0xc0 && second == 0x80)) fail(cursor - 2, "overlong MUTF-8 encoding");
                } else if ((first & 0xf0) == 0xe0) {
                    range(cursor, 2, 1, area.end);
                    const auto second = bytes[cursor++], third = bytes[cursor++];
                    if ((second & 0xc0) != 0x80 || (third & 0xc0) != 0x80) fail(cursor - 2, "invalid MUTF-8 continuation byte");
                    decoded = static_cast<uint16_t>(((first & 0x0f) << 12) | ((second & 0x3f) << 6) | (third & 0x3f));
                    if (decoded < 0x800) fail(cursor - 3, "overlong MUTF-8 encoding");
                } else fail(cursor - 1, "invalid MUTF-8 lead byte or premature terminator");
                value.push_back(static_cast<char16_t>(decoded));
            }
            range(cursor, 1, 1, area.end);
            if (bytes[cursor++] != 0) fail(cursor - 1, "MUTF-8 UTF-16 length or terminator mismatch");
            if (!strings.empty() && strings.back() >= value) fail(offset, "string IDs are not strictly ordered by UTF-16 units");
            strings.push_back(std::move(value));
            ranges.emplace_back(offset, cursor);
        }
        std::sort(ranges.begin(), ranges.end());
        if (!ranges.empty() && ranges.front().first != data->offset)
            fail(ranges.front().first, "string IDs omit the first mapped string_data item");
        for (size_t i = 1; i < ranges.size(); ++i)
            if (ranges[i].first != ranges[i - 1].second)
                fail(ranges[i].first, "string_data item boundaries are not contiguous");
        if (data) finish_section(*data, ranges.back().second);
    }
    bool simple_name(std::u16string_view value) const {return dex_names::simple_name(value,facts.dex_version);}
    bool member_name(std::u16string_view value) const {return dex_names::member_name(value,facts.dex_version);}
    bool descriptor(std::u16string_view value) const {return dex_names::descriptor(value,facts.dex_version);}
    void read_types() {
        const auto& t = tables[1];
        types.reserve(t.count);
        for (uint32_t i = 0; i < t.count; ++i) {
            const uint64_t at = uint64_t(t.offset) + uint64_t(i) * 4;
            const auto string_index = u32(at);
            index(string_index, strings.size(), at);
            if (!types.empty() && types.back() >= string_index) fail(at, "type IDs are not strictly ordered");
            if (!descriptor(strings[string_index])) fail(at, "invalid type descriptor");
            types.push_back(string_index);
        }
    }
    const std::pmr::u16string& type(uint32_t id) const { return strings[types[id]]; }
    void index_type_lists() {
        const auto* area = find(0x1001);
        if (!area) return;
        type_lists.reserve(area->count);
        uint64_t cursor = area->offset;
        for (uint32_t item = 0; item < area->count; ++item) {
            cursor = align_item(cursor, *area);
            range(cursor, 4, 1, area->end);
            const auto count = u32(cursor);
            const auto offset = static_cast<uint32_t>(cursor);
            cursor += 4;
            range(cursor, count, 2, area->end);
            charge_items(count, offset);
            for (uint32_t i = 0; i < count; ++i) {
                const uint64_t at = cursor + uint64_t(i) * 2;
                const auto id = u16(at);
                index(id, types.size(), at);
                if (type(id) == u"V") fail(at, "void is not valid in a type list");
            }
            cursor += uint64_t(count) * 2;
            type_lists.push_back({offset, count});
        }
        finish_section(*area, cursor);
    }
    std::pmr::vector<uint16_t> type_list(uint32_t offset) {
        if (offset == 0) return std::pmr::vector<uint16_t>(resource);
        const auto found = std::lower_bound(type_lists.begin(), type_lists.end(), offset,
            [](const TypeListItem& item, uint32_t key) { return item.offset < key; });
        if (found == type_lists.end() || found->offset != offset)
            fail(offset, "type_list reference is not an indexed item start");
        const auto count = found->count;
        charge_items(count, offset);
        std::pmr::vector<uint16_t> result(resource);
        result.reserve(count);
        for (uint32_t i = 0; i < count; ++i) {
            const uint64_t at = uint64_t(offset) + 4 + uint64_t(i) * 2;
            const auto id = u16(at);
            index(id, types.size(), at);
            if (type(id) == u"V") fail(at, "void is not valid in a type list");
            result.push_back(id);
        }
        return result;
    }
    static char16_t short_type(const std::pmr::u16string& value) { return value[0] == u'[' ? u'L' : value[0]; }
    void append(std::pmr::u16string& target, std::u16string_view value, uint64_t at) {
        charge_text(value.size(), at);
        target.append(value);
    }
    void read_protos() {
        const auto& t = tables[2];
        protos.reserve(t.count);
        for (uint32_t i = 0; i < t.count; ++i) {
            const uint64_t at = uint64_t(t.offset) + uint64_t(i) * 12;
            const auto shorty = u32(at), result = u32(at + 4);
            index(shorty, strings.size(), at); index(result, types.size(), at + 4);
            Prototype p(resource);
            p.return_type = result;
            p.parameters = type_list(u32(at + 8));
            const auto& s = strings[shorty];
            if (s.size() != p.parameters.size() + 1 || s[0] != short_type(type(result))) fail(at, "shorty does not match the prototype");
            append(p.descriptor, u"(", at);
            for (size_t j = 0; j < p.parameters.size(); ++j) {
                const auto& parameter = type(p.parameters[j]);
                if (s[j + 1] != short_type(parameter)) fail(at, "shorty parameter mismatch");
                append(p.descriptor, parameter, at);
            }
            append(p.descriptor, u")", at); append(p.descriptor, type(result), at);
            if (!protos.empty()) {
                const auto& previous = protos.back();
                if (previous.return_type > p.return_type || (previous.return_type == p.return_type && previous.parameters >= p.parameters))
                    fail(at, "prototype IDs are not strictly ordered");
            }
            protos.push_back(std::move(p));
        }
    }
    template<class Ref> void read_refs(std::pmr::vector<Ref>& result, const Table& t, bool method) {
        result.reserve(t.count);
        for (uint32_t i = 0; i < t.count; ++i) {
            const uint64_t at = uint64_t(t.offset) + uint64_t(i) * 8;
            Ref ref{};
            ref.owner = u16(at); ref.type = u16(at + 2); ref.name = u32(at + 4);
            index(ref.owner, types.size(), at);
            index(ref.type, method ? protos.size() : types.size(), at + 2);
            index(ref.name, strings.size(), at + 4);
            const auto owner_kind = type(ref.owner)[0];
            if (owner_kind != u'L' && !(method && owner_kind == u'[')) fail(at, "member owner has an invalid type");
            if (!method && type(ref.type) == u"V") fail(at + 2, "field type cannot be void");
            const auto& name = strings[ref.name];
            if (!member_name(name)) fail(at + 4, "invalid member name");
            if (!result.empty()) {
                const auto& prev = result.back();
                if (std::tie(prev.owner, prev.name, prev.type) >= std::tie(ref.owner, ref.name, ref.type)) fail(at, "member IDs are not strictly ordered");
            }
            result.push_back(ref);
        }
    }
    void index_debug_info() {
        const auto* area = find(0x2003);
        if (!area) return;
        debug_items.reserve(area->count);
        if (check_debug_associations) debug_associations.reserve(area->count);
        uint64_t cursor = area->offset;
        auto optional_index = [&](uint64_t bound) {
            const auto at = cursor;
            const auto encoded = uleb(cursor, area->end);
            if (encoded) index(encoded - 1, bound, at);
        };
        for (uint32_t item = 0; item < area->count; ++item) {
            const auto start = cursor;
            debug_items.push_back(static_cast<uint32_t>(start));
            const auto line_at = cursor;
            const auto line_start = uleb(cursor, area->end);
            const auto parameters_at = cursor;
            const auto parameters = uleb(cursor, area->end);
            if (parameters > 65536) fail(parameters_at, "debug parameter count exceeds format limit");
            DebugInfoItem debug{static_cast<uint32_t>(start), parameters, 0, 0, 0, 0,
                                line_start == 0 ? static_cast<uint32_t>(line_at) : 0};
            // Every debug opcode is charged against max_items before its operand
            // is applied, bounding both accumulators well within 64-bit range.
            uint64_t address = 0;
            int64_t line = line_start;
            auto advance_address = [&](uint32_t amount, uint64_t at) {
                address += amount;
                if (address > debug.max_address) {
                    debug.max_address = address;
                    debug.max_address_at = static_cast<uint32_t>(at);
                }
            };
            auto advance_line = [&](int32_t amount, uint64_t at) {
                line += amount;
                if (line < 1 && debug.invalid_line_at == 0)
                    debug.invalid_line_at = static_cast<uint32_t>(at);
            };
            auto reg = [&]() {
                const auto at = cursor;
                const auto value = uleb(cursor, area->end);
                if (value >= 65536) fail(at, "debug register exceeds 16-bit range");
                if (check_debug_associations && value + 1 > debug.max_register_plus_one) {
                    debug.max_register_plus_one = value + 1;
                    debug.max_register_at = static_cast<uint32_t>(at);
                }
            };
            charge_items(parameters, parameters_at);
            for (uint32_t i = 0; i < parameters; ++i) optional_index(strings.size());
            for (;;) {
                const auto at = cursor;
                range(cursor, 1, 1, area->end);
                const auto opcode = bytes[cursor++];
                charge_items(1, at);
                if (opcode == 0) break;
                switch (opcode) {
                case 1: { const auto amount = uleb(cursor, area->end); if (check_debug_associations) advance_address(amount, at); break; }
                case 2: { const auto amount = detail::read_sleb32(bytes, cursor, area->end); if (check_debug_associations) advance_line(amount, at); break; }
                case 3: reg(); optional_index(strings.size()); optional_index(types.size()); break;
                case 4: reg(); optional_index(strings.size()); optional_index(types.size()); optional_index(strings.size()); break;
                case 5: case 6: reg(); break;
                case 7: case 8: break;
                case 9: optional_index(strings.size()); break;
                default:
                    if (check_debug_associations) {
                        const auto adjusted = uint32_t(opcode) - 0x0a;
                        advance_address(adjusted / 15, at);
                        advance_line(-4 + int32_t(adjusted % 15), at);
                    }
                    break; // special opcodes carry no operands
                }
            }
            if (check_debug_associations) debug_associations.push_back(debug);
        }
        padding(cursor, area->end);
    }
    const DebugInfoItem& debug_info(uint32_t offset, uint64_t reference_at) const {
        const auto found = std::lower_bound(debug_associations.begin(), debug_associations.end(), offset,
            [](const DebugInfoItem& item, uint32_t key) { return item.offset < key; });
        if (found == debug_associations.end() || found->offset != offset)
            fail(reference_at, "debug offset is not an indexed debug_info_item start");
        return *found;
    }
    void index_code_items() {
        const auto* area = find(0x2001);
        if (!area) return;
        code_items.reserve(area->count);
        uint64_t cursor = area->offset;
        for (uint32_t item = 0; item < area->count; ++item) {
            cursor = align_item(cursor, *area);
            range(cursor, 16, 1, area->end);
            const auto offset = static_cast<uint32_t>(cursor);
            const auto registers = u16(cursor), incoming = u16(cursor + 2), tries = u16(cursor + 6);
            const auto debug_offset = u32(cursor + 8), units = u32(cursor + 12);
            if (incoming > registers) fail(cursor, "incoming registers exceed total registers");
            if (debug_offset != 0 && !std::binary_search(debug_items.begin(), debug_items.end(), debug_offset))
                fail(cursor + 8, "debug offset is not an indexed debug_info_item start");
            uint32_t debug_parameters = 0;
            if (debug_offset != 0 && check_debug_associations) {
                const auto& debug = debug_info(debug_offset, cursor + 8);
                if (debug.max_register_plus_one > registers)
                    fail(debug.max_register_at, "debug register exceeds code register count");
                if (debug.max_address > units)
                    fail(debug.max_address_at, "debug address exceeds code instruction count");
                if (debug.invalid_line_at)
                    fail(debug.invalid_line_at, "debug line is less than one");
                debug_parameters = debug.parameters;
            }
            if (units == 0) fail(cursor + 12, "code item has an empty instruction array");
            cursor += 16;
            range(cursor, units, 2, area->end);
            cursor += uint64_t(units) * 2;
            if (tries != 0) {
                cursor = align_item(cursor, *area);
                const uint64_t try_start = cursor;
                range(cursor, tries, 8, area->end);
                cursor += uint64_t(tries) * 8;
                const uint64_t handler_base = cursor;
                const auto handler_count = uleb(cursor, area->end);
                if (handler_count == 0) fail(handler_base, "try blocks have no catch handlers");
                range(cursor, handler_count, 2, area->end);
                charge_items(handler_count, handler_base);
                std::pmr::vector<uint32_t> handler_offsets(resource);
                handler_offsets.reserve(handler_count);
                for (uint32_t h = 0; h < handler_count; ++h) {
                    handler_offsets.push_back(static_cast<uint32_t>(cursor - handler_base));
                    const uint64_t handler_at = cursor;
                    const auto signed_count = detail::read_sleb32(bytes, cursor, area->end);
                    const uint64_t typed_count = signed_count < 0 ? uint64_t(-int64_t(signed_count)) : uint64_t(signed_count);
                    range(cursor, typed_count, 2, area->end);
                    charge_items(typed_count, handler_at);
                    for (uint64_t c = 0; c < typed_count; ++c) {
                        const uint64_t pair_at = cursor;
                        const auto caught = uleb(cursor, area->end), address = uleb(cursor, area->end);
                        index(caught, types.size(), pair_at);
                        if (type(caught)[0] != u'L') fail(pair_at, "catch type must be a class");
                        if (address >= units) fail(pair_at, "catch handler address exceeds instruction array");
                    }
                    if (signed_count <= 0) {
                        const uint64_t catch_all_at = cursor;
                        if (uleb(cursor, area->end) >= units) fail(catch_all_at, "catch-all address exceeds instruction array");
                    }
                }
                uint64_t previous_end = 0;
                for (uint32_t t = 0; t < tries; ++t) {
                    const uint64_t at = try_start + uint64_t(t) * 8;
                    const auto start = u32(at);
                    const auto count = u16(at + 4), handler = u16(at + 6);
                    if (count == 0 || start >= units || count > uint64_t(units) - start || start < previous_end)
                        fail(at, "invalid or overlapping try block range");
                    previous_end = uint64_t(start) + count;
                    if (!std::binary_search(handler_offsets.begin(), handler_offsets.end(), handler))
                        fail(at + 6, "try block handler offset is not a handler item start");
                }
            }
            code_items.push_back({offset, registers, incoming, units, static_cast<uint32_t>(cursor)});
            if (debug_offset && check_debug_associations)
                code_debug_associations.push_back({offset, debug_offset, debug_parameters});
        }
        // A producer may pad the final code_item to its own four-byte alignment,
        // even when the next mapped section is only byte-aligned.
        if (cursor < area->end) {
            const uint64_t aligned = (cursor + 3) & ~uint64_t(3);
            if (aligned == area->end) {
                padding(cursor, aligned);
                cursor = aligned;
            }
        }
        finish_section(*area, cursor);
        // Opcode decoding and PC instruction-boundary validation remain separate capabilities.
    }
    uint32_t code(uint32_t offset, const Prototype& prototype, uint32_t flags) const {
        const auto found = std::lower_bound(code_items.begin(), code_items.end(), offset,
            [](const CodeItem& item, uint32_t key) { return item.offset < key; });
        if (found == code_items.end() || found->offset != offset)
            fail(offset, "code reference is not an indexed code_item start");
        uint64_t incoming = flags & 0x8 ? 0 : 1;
        for (const auto parameter : prototype.parameters) {
            const auto& name = type(parameter);
            incoming += name == u"J" || name == u"D" ? 2 : 1;
        }
        if (incoming != found->incoming) fail(offset + 2, "code ins_size does not match method parameters and receiver");
        if (check_debug_associations) {
            const auto debug = std::lower_bound(code_debug_associations.begin(), code_debug_associations.end(), offset,
                [](const CodeDebugItem& item, uint32_t key) { return item.code_offset < key; });
            if (debug != code_debug_associations.end() && debug->code_offset == offset &&
                debug->parameters != prototype.parameters.size())
                fail(debug->debug_offset, "debug parameter count does not match method prototype");
        }
        return found->end;
    }
    uint32_t next_index(uint64_t& cursor, uint64_t end, uint32_t previous, uint32_t position, size_t count) const {
        const auto at = cursor;
        const auto delta = uleb(cursor, end);
        if (position != 0 && delta == 0) fail(at, "duplicate index in a class_data sequence");
        const uint64_t value = uint64_t(previous) + delta;
        if (value >= count) fail(at, "class_data delta index is out of range");
        return static_cast<uint32_t>(value);
    }
    void definitions() {
        std::pmr::vector<uint32_t> class_positions(types.size(), no_index, resource);
        std::pmr::vector<uint8_t> declared_fields(fields.size(), 0, resource), declared_methods(methods.size(), 0, resource);
        std::pmr::vector<std::pair<uint64_t, uint64_t>> ranges(resource);
        const auto& t = tables[5];
        facts.class_definitions.reserve(t.count);
        facts.method_definition_by_ref.assign(methods.size(),no_index);
        facts.field_definition_by_ref.assign(fields.size(),no_index);
        for (uint32_t i = 0; i < t.count; ++i) {
            const uint64_t at = uint64_t(t.offset) + uint64_t(i) * 32;
            const auto owner = u32(at);
            index(owner, types.size(), at);
            if (type(owner)[0] != u'L' || class_positions[owner] != no_index)
                fail(at, "invalid or duplicate class definition");
            class_positions[owner] = i;
        }
        for (uint32_t i = 0; i < t.count; ++i) {
            const uint64_t at = uint64_t(t.offset) + uint64_t(i) * 32;
            const auto owner = u32(at), parent = u32(at + 8), source = u32(at + 16);
            index(owner, types.size(), at);
            if (parent != no_index) {
                index(parent, types.size(), at + 8);
                if (parent == owner || type(parent)[0] != u'L') fail(at + 8, "invalid superclass reference");
                if (class_positions[parent] != no_index && class_positions[parent] >= i)
                    fail(at + 8, "defined superclass must precede its subclass");
            }
            if (source != no_index) index(source, strings.size(), at + 16);
            auto interfaces = type_list(u32(at + 12));
            std::pmr::vector<uint16_t> checked_interfaces(interfaces, resource);
            std::sort(checked_interfaces.begin(), checked_interfaces.end());
            for (size_t j = 0; j < checked_interfaces.size(); ++j) {
                if (type(checked_interfaces[j])[0] != u'L' || checked_interfaces[j] == owner || (j && checked_interfaces[j - 1] >= checked_interfaces[j]))
                    fail(at + 12, "invalid or duplicate interface reference");
                if (class_positions[checked_interfaces[j]] != no_index && class_positions[checked_interfaces[j]] >= i)
                    fail(at + 12, "defined interface must precede its implementing class");
            }
            const auto annotations = u32(at + 20), data = u32(at + 24), values = u32(at + 28);
            if (annotations) annotation_owners(annotations, owner);
            const auto* initial_values = values ? &encoded_array(values) : nullptr;
            ClassDefinition definition(resource);
            definition.type_id = owner;
            definition.definition_offset = static_cast<uint32_t>(at);
            definition.access_flags = u32(at + 4);
            definition.superclass_type = parent;
            definition.class_data_offset = data;
            definition.annotations_offset = annotations;
            definition.static_values_offset = values;
            definition.interfaces = std::move(interfaces);
            facts.class_definitions.push_back(std::move(definition));
            if (!data) {
                if (initial_values && initial_values->count) fail(values, "static values exceed static field count");
                continue;
            }
            const auto& area = section(0x2000, data, 4);
            uint64_t cursor = data;
            std::array<uint32_t, 4> sizes{};
            for (auto& size : sizes) size = uleb(cursor, area.end);
            uint64_t value_cursor = 0, value_end = 0;
            if (initial_values) {
                if (initial_values->count > sizes[0]) fail(values, "static values exceed static field count");
                charge_items(initial_values->count, values);
                const auto& value_area = section(0x2005, values);
                value_cursor = values; value_end = value_area.end;
                (void)uleb(value_cursor, value_end);
            }
            if (uint64_t(sizes[0]) + sizes[1] > fields.size() || uint64_t(sizes[2]) + sizes[3] > methods.size())
                fail(data, "class_data member counts exceed reference tables");
            const uint64_t minimum = (uint64_t(sizes[0]) + sizes[1]) * 2 + (uint64_t(sizes[2]) + sizes[3]) * 3;
            range(cursor, minimum, 1, area.end);
            for (size_t group = 0; group < 4; ++group) {
                uint32_t previous = 0;
                for (uint32_t j = 0; j < sizes[group]; ++j) {
                    const auto declaration = cursor;
                    const bool method = group >= 2;
                    const auto id = next_index(cursor, area.end, previous, j, method ? methods.size() : fields.size());
                    previous = id;
                    const auto flags = uleb(cursor, area.end);
                    const MemberReference& ref = method ? static_cast<const MemberReference&>(methods[id]) : static_cast<const MemberReference&>(fields[id]);
                    auto& seen = method ? declared_methods[id] : declared_fields[id];
                    if (ref.owner != owner || seen) fail(declaration, "duplicate member definition or mismatched owner");
                    seen = 1;
                    if (!method) {
                        if (((flags & 0x8) != 0) != (group == 0)) fail(declaration, "static/instance field group mismatch");
                        if (group == 0 && initial_values && j < initial_values->count)
                            static_value(value_cursor, value_end, type(ref.type));
                        facts.field_definition_by_ref[id]=static_cast<uint32_t>(facts.field_definitions.size());
                        facts.field_definitions.push_back({id, flags, static_cast<uint32_t>(declaration), owner});
                        continue;
                    }
                    const auto code_offset = uleb(cursor, area.end);
                    const bool no_body = (flags & (0x100 | 0x400)) != 0;
                    if ((code_offset == 0) != no_body) fail(declaration, "code offset disagrees with native/abstract flags");
                    if ((flags & 0x500) == 0x500) fail(declaration, "method cannot be both native and abstract");
                    const bool direct = (flags & (0x2 | 0x8 | 0x10000)) != 0;
                    if (direct != (group == 2)) fail(declaration, "direct/virtual method group mismatch");
                    const auto& owner_name = type(ref.owner);
                    const auto& name = strings[ref.name];
                    const auto& signature = protos[ref.type];
                    const bool initializer = name == u"<init>" || name == u"<clinit>";
                    if (initializer != ((flags & 0x10000) != 0)) fail(declaration, "constructor flag disagrees with method name");
                    if (initializer) {
                        if (no_body || type(signature.return_type) != u"V") fail(declaration, "initializer must have code and return void");
                        if ((name == u"<clinit>") != ((flags & 0x8) != 0)) fail(declaration, "initializer static flag mismatch");
                        if (name == u"<clinit>" && !signature.parameters.empty()) fail(declaration, "class initializer must have no parameters");
                    }
                    if ((flags & 0x400) && (flags & (0x2 | 0x8 | 0x10 | 0x20 | 0x800)))
                        fail(declaration, "abstract method has incompatible access flags");
                    const auto code_end = code_offset ? code(code_offset, signature, flags) : 0;
                    const auto& prototype = protos[ref.type].descriptor;
                    facts.method_definition_by_ref[id]=static_cast<uint32_t>(facts.methods.size());
                    facts.methods.push_back({id, flags, static_cast<uint32_t>(declaration), code_offset,
                        owner_name, name, prototype, code_end});
                }
            }
            ranges.emplace_back(data, cursor);
        }
        std::sort(ranges.begin(), ranges.end());
        const auto* class_data = find(0x2000);
        if ((class_data && class_data->count != ranges.size()) || (!class_data && !ranges.empty()))
            fail(t.offset, "class_data map count does not match referenced definitions");
        if (!ranges.empty() && ranges.front().first != class_data->offset)
            fail(ranges.front().first, "class definitions omit the first mapped class_data item");
        for (size_t i = 1; i < ranges.size(); ++i)
            if (ranges[i].first != ranges[i - 1].second)
                fail(ranges[i].first, "class_data item boundaries are not contiguous");
        if (class_data) finish_section(*class_data, ranges.back().second);
        facts.class_definition_by_type=std::move(class_positions);
    }
};
}

Facts read_metadata(std::span<const uint8_t> bytes, std::pmr::memory_resource* resource) {
    try {
        return Reader(bytes, resource).run();
    } catch (const std::length_error&) {
        throw ReadError(ReadCode::budget, 0, "metadata container length exceeded");
    }
}
Facts read_metadata_with_debug_associations(std::span<const uint8_t> bytes, std::pmr::memory_resource* resource) {
    try {
        return Reader(bytes, resource, true).run();
    } catch (const std::length_error&) {
        throw ReadError(ReadCode::budget, 0, "metadata container length exceeded");
    }
}
Facts read_metadata_041(std::span<const uint8_t> bytes,uint32_t header,std::pmr::memory_resource* memory){
    try{const auto headers=dex041::enumerate(bytes,memory,1024);if(std::none_of(headers.begin(),headers.end(),[&](const auto& h){return h.offset==header;}))throw ReadError(ReadCode::corrupt,header,"not a logical header start");return Reader(bytes,memory,false,header,headers).run();}
    catch(const std::length_error&){throw ReadError(ReadCode::budget,header,"041 metadata length limit");}
}

}
