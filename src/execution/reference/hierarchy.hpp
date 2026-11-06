#pragma once
#include "format/reader.hpp"
#include <algorithm>
#include <limits>
#include <span>

// Static superclass graph over explicitly selected DEX occurrences. It is not
// Java field inheritance or runtime class resolution.
namespace dexmeguviz::hierarchy {
struct Source { uint32_t occurrence; const Facts* facts; };
struct ClassKey {
    uint32_t occurrence, ordinal;
    bool operator==(const ClassKey&) const = default;
};
enum class Link { root, observed_single, observed_ambiguous };
enum class Stop { no_superclass, missing_definition, incomplete_scope, cycle };
struct Path { ClassKey key; uint32_t parent; Link link; };
struct End { uint32_t path; Stop reason; };
struct Result {
    std::pmr::vector<Path> paths;
    std::pmr::vector<End> ends;
    explicit Result(std::pmr::memory_resource* r) : paths(r), ends(r) {}
};
// Internal typed cancellation is intentionally distinct from errors.
struct Cancelled {};
struct Budget {
    uint64_t remaining;
    bool (*cancelled)(void*) noexcept = nullptr;
    void* context = nullptr;
    void (*charge_external)(void*,uint64_t) = nullptr;
    void* external_context = nullptr;
    size_t max_nodes = 100000;
    void (*field_observed)(void*) = nullptr;
    void bound(size_t count) const {
        if(count>max_nodes) throw ReadError(ReadCode::budget,0,"hierarchy intermediate row limit exceeded");
    }
    void charge(uint64_t units = 1) {
        if(charge_external){charge_external(external_context,units);return;}
        if (cancelled && cancelled(context)) throw Cancelled{};
        if (units > remaining) throw ReadError(ReadCode::budget, 0, "hierarchy work budget exceeded");
        remaining -= units;
    }
};

// Caller supplies only sources in the query's actual resolution scope. When
// scope_complete is false, omitted definitions may exist, even if one or more
// candidates have been observed. Paths preserve source occurrence and branches.
inline Result resolve(std::span<const Source> sources, ClassKey root, bool scope_complete,
                      Budget& budget, std::pmr::memory_resource* resource) {
    if (!resource) throw std::invalid_argument("null hierarchy resource");
    for (size_t i = 0; i < sources.size(); ++i) {
        budget.charge();
        if (!sources[i].facts) throw std::invalid_argument("null hierarchy source");
        for (size_t j = 0; j < i; ++j) {
            budget.charge();
            if (sources[i].occurrence == sources[j].occurrence) throw std::invalid_argument("duplicate source occurrence");
        }
    }
    auto source_for = [&](uint32_t occurrence) -> const Facts& {
        for (const auto& source : sources) {
            budget.charge();
            if (source.occurrence == occurrence) return *source.facts;
        }
        throw std::invalid_argument("class occurrence outside scope");
    };
    auto descriptor = [](const Facts& f, uint32_t type) -> std::u16string_view {
        if (type >= f.types.size() || f.types[type] >= f.strings.size())
            throw std::invalid_argument("invalid hierarchy type index");
        return f.strings[f.types[type]];
    };
    const auto& start = source_for(root.occurrence);
    if (root.ordinal >= start.class_definitions.size()) throw std::invalid_argument("invalid root class ordinal");
    Result result(resource);
    budget.bound(1);result.paths.push_back({root, UINT32_MAX, Link::root});
    for (size_t current = 0; current < result.paths.size(); ++current) {
        budget.charge();
        bool terminal_cycle = false;
        for (const auto& end : result.ends) {
            budget.charge();
            if (end.path == current && end.reason == Stop::cycle) { terminal_cycle = true; break; }
        }
        if (terminal_cycle) continue;
        const auto path = result.paths[current];
        const auto& facts = source_for(path.key.occurrence);
        if (path.key.ordinal >= facts.class_definitions.size()) throw std::invalid_argument("invalid class ordinal");
        const auto parent_type = facts.class_definitions[path.key.ordinal].superclass_type;
        if (parent_type == UINT32_MAX) {
            budget.bound(result.ends.size()+1);result.ends.push_back({static_cast<uint32_t>(current), Stop::no_superclass});
            continue;
        }
        const auto wanted = descriptor(facts, parent_type);
        std::pmr::vector<ClassKey> candidates(resource);
        for (const auto& source : sources) {
            for (size_t i = 0; i < source.facts->class_definitions.size(); ++i) {
                budget.charge();
                const auto actual = descriptor(*source.facts, source.facts->class_definitions[i].type_id);
                bool equal = actual.size() == wanted.size();
                // Bound both work and cancellation latency even for enormous
                // descriptors, rather than calling an uninterruptible compare.
                for (size_t offset = 0; equal && offset < wanted.size();) {
                    const auto count = std::min<size_t>(256, wanted.size() - offset);
                    budget.charge(static_cast<uint64_t>(count));
                    equal = actual.substr(offset, count) == wanted.substr(offset, count);
                    offset += count;
                }
                if (equal) {
                    if (i >= UINT32_MAX) throw std::length_error("too many classes");
                    budget.bound(candidates.size()+1);candidates.push_back({source.occurrence, static_cast<uint32_t>(i)});
                }
            }
        }
        if (!scope_complete) {budget.bound(result.ends.size()+1);result.ends.push_back({static_cast<uint32_t>(current), Stop::incomplete_scope});}
        if (candidates.empty()) {
            budget.bound(result.ends.size()+1);result.ends.push_back({static_cast<uint32_t>(current), Stop::missing_definition});
            continue;
        }
        for (const auto candidate : candidates) {
            budget.charge();
            if (result.paths.size() >= UINT32_MAX) throw std::length_error("too many hierarchy paths");
            bool cycle = false;
            for (uint32_t at = static_cast<uint32_t>(current); at != UINT32_MAX; at = result.paths[at].parent) {
                budget.charge();
                if (result.paths[at].key == candidate) { cycle = true; break; }
            }
            const auto child = static_cast<uint32_t>(result.paths.size());
            budget.bound(result.paths.size()+1);result.paths.push_back({candidate, static_cast<uint32_t>(current), candidates.size() == 1 ? Link::observed_single : Link::observed_ambiguous});
            if (cycle) {budget.bound(result.ends.size()+1);result.ends.push_back({child, Stop::cycle});}
        }
    }
    return result;
}
}
