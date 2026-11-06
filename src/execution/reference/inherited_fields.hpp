#pragma once
#include "hierarchy.hpp"
#include <algorithm>
#include <cstdint>
#include <span>

// Source-scoped static superclass-field observations.
// It does not implement Java getFields or claim runtime classloader binding.
namespace dexmeguviz::hierarchy {
enum class FieldTruth { no, yes, unknown };
struct FieldKey { uint32_t occurrence, ordinal; bool operator==(const FieldKey&) const = default; };
struct FieldWitness { uint32_t end_index, path_index; FieldKey field; };
struct FieldBranch { uint32_t end_index, known_matches; bool incomplete; FieldTruth truth; };
struct FieldResult {
    std::pmr::vector<FieldBranch> branches;
    std::pmr::vector<FieldWitness> witnesses;
    FieldTruth truth = FieldTruth::unknown;
    explicit FieldResult(std::pmr::memory_resource* r) : branches(r), witnesses(r) {}
};
using FieldMatcher = bool(*)(void*, const Facts&, const FieldDefinition&);

// A callback must be pure for the duration of the call and is responsible for
// charging its own matcher work. All other loops and name comparisons below
// are charged against `budget`, which also checks cancellation.
inline FieldResult inherited_fields(std::span<const Source> sources, const Result& graph,
                                    uint32_t minimum, uint32_t maximum,
                                    FieldMatcher matcher, void* matcher_context,
                                    Budget& budget, std::pmr::memory_resource* resource) {
    if (!resource || !matcher || minimum > maximum || graph.paths.empty())
        throw std::invalid_argument("invalid inherited fields request");
    auto source_for = [&](uint32_t occurrence) -> const Facts& {
        for (const auto& source : sources) {
            budget.charge();
            if (source.occurrence == occurrence && source.facts) return *source.facts;
        }
        throw std::invalid_argument("field path source outside scope");
    };
    auto equal_name = [&](std::u16string_view a, std::u16string_view b) {
        budget.charge();
        if (a.size() != b.size()) return false;
        for (size_t at = 0; at < a.size();) {
            const auto n = std::min<size_t>(256, a.size() - at);
            budget.charge(n);
            if (a.substr(at, n) != b.substr(at, n)) return false;
            at += n;
        }
        return true;
    };
    FieldResult result(resource);
    bool saw_yes = false, saw_no = false, saw_unknown = false;
    for (size_t ei = 0; ei < graph.ends.size(); ++ei) {
        budget.charge();
        if (ei >= UINT32_MAX) throw std::length_error("too many field branches");
        const auto& end = graph.ends[ei];
        if (end.path >= graph.paths.size()) throw std::invalid_argument("invalid field path end");
        std::pmr::vector<uint32_t> chain(resource);
        for (uint32_t at = end.path; at != UINT32_MAX;) {
            budget.charge();
            if (at >= graph.paths.size() || chain.size() >= graph.paths.size())
                throw std::invalid_argument("invalid field path chain");
            chain.push_back(at);
            at = graph.paths[at].parent;
        }
        if (chain.back() != 0) throw std::invalid_argument("field path has wrong root");
        std::reverse(chain.begin(), chain.end());
        std::pmr::vector<std::u16string_view> hidden(resource);
        uint32_t known = 0;
        bool incomplete = end.reason != Stop::no_superclass;
        bool unstable_known = end.reason == Stop::cycle;
        for (size_t depth = 0; depth < chain.size(); ++depth) {
            budget.charge();
            const auto path_index = chain[depth];
            const auto key = graph.paths[path_index].key;
            const auto& facts = source_for(key.occurrence);
            if (key.ordinal >= facts.class_definitions.size()) throw std::invalid_argument("invalid field path class");
            const auto& cls = facts.class_definitions[key.ordinal];
            if (!cls.interfaces.empty()) {
                incomplete = true; // Interface fields are not resolved in this profile.
                unstable_known = true; // Interfaces can affect hiding/ambiguity.
            }
            std::pmr::vector<std::u16string_view> declared_here(resource);
            for (size_t fi = 0; fi < facts.field_definitions.size(); ++fi) {
                budget.charge();
                if(budget.field_observed)budget.field_observed(budget.external_context);
                if (fi >= UINT32_MAX) throw std::length_error("too many fields");
                const auto& field = facts.field_definitions[fi];
                if (field.owner_type != cls.type_id) continue;
                if (field.field_ref_index >= facts.field_refs.size()) throw std::invalid_argument("invalid field reference");
                const auto& ref = facts.field_refs[field.field_ref_index];
                if (ref.name >= facts.strings.size()) throw std::invalid_argument("invalid field name");
                const std::u16string_view name = facts.strings[ref.name];
                declared_here.push_back(name);
                if (depth == 0) continue; // Own declarations shadow, never count as inherited.
                bool obscured = false;
                for (const auto existing : hidden) if (equal_name(name, existing)) { obscured = true; break; }
                if (obscured || !matcher(matcher_context, facts, field)) continue;
                const auto access = field.access_flags & 7u;
                if (access == 2u) continue; // private
                if (access != 1u && access != 4u) {
                    incomplete = true;
                    if (access != 0u) unstable_known = true; // Contradictory access bits.
                    continue;
                }
                if (known == UINT32_MAX) throw std::length_error("too many inherited fields");
                ++known;
                budget.bound(result.witnesses.size()+1);result.witnesses.push_back({static_cast<uint32_t>(ei), path_index,
                                            {key.occurrence, static_cast<uint32_t>(fi)}});
            }
            // Delay insertion so two fields at the same depth with equal name
            // remain distinct; only nearer declarations hide an ancestor.
            hidden.insert(hidden.end(), declared_here.begin(), declared_here.end());
        }
        FieldTruth branch;
        if (minimum == 0 && maximum == UINT32_MAX) branch = FieldTruth::yes;
        else if (unstable_known) branch = FieldTruth::unknown;
        else if (known > maximum) branch = FieldTruth::no;
        else if (!incomplete) branch = known >= minimum ? FieldTruth::yes : FieldTruth::no;
        else if (known >= minimum && maximum == UINT32_MAX) branch = FieldTruth::yes;
        else branch = FieldTruth::unknown;
        budget.bound(result.branches.size()+1);result.branches.push_back({static_cast<uint32_t>(ei), known, incomplete, branch});
        saw_yes |= branch == FieldTruth::yes;
        saw_no |= branch == FieldTruth::no;
        saw_unknown |= branch == FieldTruth::unknown;
    }
    if (!result.branches.empty() && !saw_unknown && saw_yes != saw_no)
        result.truth = saw_yes ? FieldTruth::yes : FieldTruth::no;
    return result;
}
}
