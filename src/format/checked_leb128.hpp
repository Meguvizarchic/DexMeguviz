#pragma once
#include "reader.hpp"
#include <bit>

namespace dexmeguviz::detail {
// Non-minimal encodings are accepted; encoded values must still fit 32 bits.
inline uint8_t leb_byte(std::span<const uint8_t> bytes, uint64_t& cursor, uint64_t end) {
    if (end > bytes.size() || cursor >= end)
        throw ReadError(ReadCode::corrupt, cursor, "truncated LEB128");
    return bytes[cursor++];
}

inline uint32_t read_uleb32(std::span<const uint8_t> bytes, uint64_t& cursor, uint64_t end) {
    const uint64_t start = cursor;
    uint32_t result = 0;
    for (unsigned i = 0; i != 5; ++i) {
        const auto value = leb_byte(bytes, cursor, end);
        if (i == 4 && (value & 0xf0) != 0)
            throw ReadError(ReadCode::corrupt, start, "ULEB128 exceeds 32 bits");
        result |= uint32_t(value & 0x7f) << (i * 7);
        if ((value & 0x80) == 0) return result;
    }
    throw ReadError(ReadCode::corrupt, start, "unterminated ULEB128");
}

inline int32_t read_sleb32(std::span<const uint8_t> bytes, uint64_t& cursor, uint64_t end) {
    const uint64_t start = cursor;
    uint32_t result = 0;
    for (unsigned i = 0; i != 5; ++i) {
        const auto value = leb_byte(bytes, cursor, end);
        if (i == 4 && (value > 0x7f || (value > 0x07 && value < 0x78)))
            throw ReadError(ReadCode::corrupt, start, "SLEB128 exceeds signed 32 bits");
        result |= uint32_t(value & 0x7f) << (i * 7);
        if ((value & 0x80) == 0) {
            const unsigned bits = (i + 1) * 7;
            if (bits < 32 && (value & 0x40) != 0) result |= ~uint32_t(0) << bits;
            return std::bit_cast<int32_t>(result);
        }
    }
    throw ReadError(ReadCode::corrupt, start, "unterminated SLEB128");
}
}
