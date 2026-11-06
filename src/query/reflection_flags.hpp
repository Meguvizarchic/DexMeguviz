#pragma once
#include <cstdint>
#include <optional>

namespace dexmeguviz::query::reflection_flags {
enum class Target { method, field, klass };

// A bounded transformation of DEX declaration bits using a pinned AOSP
// formula, not a claim about a ClassLoader-bound runtime object. Unknown is
// retained for flag encodings whose static meaning cannot be established.
inline std::optional<uint32_t> project(uint32_t raw, Target target, bool class_annotations_absent = false) noexcept {
    const uint32_t visibility = raw & 7u;
    if (visibility && (visibility & (visibility - 1u))) return std::nullopt;
    switch (target) {
    case Target::method: {
        constexpr uint32_t low_allowed = 0x1dffu;
        constexpr uint32_t high_allowed = 0x30000u; // constructor, declared-synchronized
        if ((raw & ~(low_allowed | high_allowed)) != 0) return std::nullopt;
        // Low-bit synchronized is legal in a DEX only for native methods.
        // Other encodings can carry hidden-API metadata rather than modifiers.
        if ((raw & 0x20u) && !(raw & 0x100u)) return std::nullopt;
        uint32_t flags = raw;
        if (flags & 0x400u) flags &= ~0x100u;
        flags &= ~0x20u;
        if (raw & 0x20000u) flags |= 0x20u;
        return flags & 0xffffu;
    }
    case Target::field:
        // Bit 0x20 and inverted visibility can encode hidden-API metadata.
        if ((raw & ~0x50dfu) != 0) return std::nullopt;
        return raw & 0xffffu;
    case Target::klass:
        // InnerClass.accessFlags is not yet parsed. Even unrelated annotation
        // directories are treated as unknown until their contents are checked.
        if (!class_annotations_absent || (raw & ~0x7611u) != 0) return std::nullopt;
        return raw & 0xffffu;
    }
    return std::nullopt;
}
}
