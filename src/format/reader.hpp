#pragma once
#include <cstdint>
#include <memory_resource>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace dexmeguviz {
enum class ReadCode { corrupt, unsupported, budget };
struct ReadError : std::runtime_error {
    ReadCode code;
    uint64_t offset;
    ReadError(ReadCode c, uint64_t at, const std::string& message)
        : std::runtime_error(message), code(c), offset(at) {}
};
struct Method {
    uint32_t method_index;
    uint32_t access_flags;
    uint32_t declaration_offset;
    uint32_t code_offset;
    // Views refer to this Facts object's stable owned string/prototype directories.
    std::u16string_view owner;
    std::u16string_view name;
    std::u16string_view prototype;
    uint32_t code_end = 0; // Exclusive checked code_item extent; zero for no body.
};
struct Prototype {
    explicit Prototype(std::pmr::memory_resource* resource = std::pmr::get_default_resource())
        : parameters(resource), descriptor(resource) {}
    uint32_t return_type = 0;
    std::pmr::vector<uint16_t> parameters;
    std::pmr::u16string descriptor;
};
struct MemberReference {
    uint16_t owner; // type_id
    uint16_t type;  // proto_id in MethodReference; type_id in FieldReference
    uint32_t name;  // string_id
};
struct MethodReference : MemberReference {};
struct FieldReference : MemberReference {};
struct ClassDefinition {
    explicit ClassDefinition(std::pmr::memory_resource* resource = std::pmr::get_default_resource()) : interfaces(resource) {}
    uint32_t type_id = 0;
    uint32_t definition_offset = 0;
    uint32_t access_flags = 0;
    uint32_t superclass_type = UINT32_MAX; // NO_INDEX denotes an absent superclass.
    uint32_t class_data_offset = 0;
    // Metadata offsets only: annotation/static-value contents are not parsed here.
    uint32_t annotations_offset = 0;
    uint32_t static_values_offset = 0;
    std::pmr::vector<uint16_t> interfaces; // Original type_list order is preserved.
};
struct FieldDefinition {
    uint32_t field_ref_index;
    uint32_t access_flags;
    uint32_t declaration_offset; // Start of encoded_field, before field_idx_diff.
    uint32_t owner_type;
};
struct Facts {
    explicit Facts(std::pmr::memory_resource* resource = std::pmr::get_default_resource())
        : methods(resource), strings(resource), types(resource), prototypes(resource),
          method_refs(resource), field_refs(resource), class_definitions(resource), field_definitions(resource),
          method_definition_by_ref(resource), field_definition_by_ref(resource), class_definition_by_type(resource) {}
    Facts(const Facts&) = delete;
    Facts& operator=(const Facts&) = delete;
    Facts(Facts&&) noexcept = default;
    Facts& operator=(Facts&& other) {
        if(this==&other)return *this;
        if(methods.get_allocator().resource()!=other.methods.get_allocator().resource())
            throw std::invalid_argument("Facts move assignment requires the same memory resource");
        header_offset=other.header_offset;logical_file_size=other.logical_file_size;container_size=other.container_size;
        dex_version=other.dex_version;string_count=other.string_count;type_count=other.type_count;
        class_count=other.class_count;method_ref_count=other.method_ref_count;
        call_site_count=other.call_site_count;method_handle_count=other.method_handle_count;
        methods=std::move(other.methods);strings=std::move(other.strings);types=std::move(other.types);
        prototypes=std::move(other.prototypes);method_refs=std::move(other.method_refs);field_refs=std::move(other.field_refs);
        class_definitions=std::move(other.class_definitions);field_definitions=std::move(other.field_definitions);
        method_definition_by_ref=std::move(other.method_definition_by_ref);field_definition_by_ref=std::move(other.field_definition_by_ref);
        class_definition_by_type=std::move(other.class_definition_by_type);
        return *this;
    }
    uint32_t header_offset=0,logical_file_size=0,container_size=0;
    uint32_t dex_version = 0;
    uint32_t string_count = 0;
    uint32_t type_count = 0;
    uint32_t class_count = 0;
    uint32_t method_ref_count = 0;
    uint32_t call_site_count = 0;
    uint32_t method_handle_count = 0;
    std::pmr::vector<Method> methods;
    // Directory indexes remain local to this logical DEX; references are not definitions.
    std::pmr::vector<std::pmr::u16string> strings;
    std::pmr::vector<uint32_t> types;
    std::pmr::vector<Prototype> prototypes;
    std::pmr::vector<MethodReference> method_refs;
    std::pmr::vector<FieldReference> field_refs;
    std::pmr::vector<ClassDefinition> class_definitions;
    std::pmr::vector<FieldDefinition> field_definitions;
    std::pmr::vector<uint32_t> method_definition_by_ref;
    std::pmr::vector<uint32_t> field_definition_by_ref;
    std::pmr::vector<uint32_t> class_definition_by_type;
};
// Metadata-only profile: checks the bytes it consumes, not opcode/CFG validity.
Facts read_metadata(std::span<const uint8_t> bytes,
    std::pmr::memory_resource* resource = std::pmr::get_default_resource());
// Optional internal check of debug/code/method associations; not an ART verifier.
Facts read_metadata_with_debug_associations(std::span<const uint8_t> bytes,
    std::pmr::memory_resource* resource = std::pmr::get_default_resource());
// Explicit experimental 041 only; bytes retain the entire physical container.
Facts read_metadata_041(std::span<const uint8_t> container,uint32_t header_offset,
    std::pmr::memory_resource* resource=std::pmr::get_default_resource());

}
