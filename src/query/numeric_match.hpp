#pragma once
#include "format/instructions/decoder.hpp"
#include <array>
#include <cstdint>
#include <string_view>

namespace dexmeguviz::query::numeric {
// Fixed-width numeric literal matching, without signed or floating inference.
enum class Kind : uint32_t { either=0, constant=1, arithmetic_operand=2 };
struct Pattern {uint64_t bits=0; uint32_t width=0; Kind kind=Kind::either;};

// Exactly width/4 ASCII hex digits. Width and kind are explicit: no inferred
// signedness, floating type, padding, truncation or negative numeric conversion.
// A failed parse leaves out unchanged.
inline bool parse(uint32_t width,std::u16string_view hex,std::u16string_view selection,Pattern& out) noexcept {
    if((width!=32 && width!=64) || hex.size()!=width/4) return false;
    Kind kind;
    if(selection==u"either") kind=Kind::either;
    else if(selection==u"constant") kind=Kind::constant;
    else if(selection==u"arithmetic_operand") kind=Kind::arithmetic_operand;
    else return false;
    uint64_t bits=0;
    for(const char16_t c:hex){
        uint32_t digit;
        if(c>=u'0' && c<=u'9') digit=c-u'0';
        else if(c>=u'a' && c<=u'f') digit=c-u'a'+10;
        else if(c>=u'A' && c<=u'F') digit=c-u'A'+10;
        else return false;
        bits=(bits<<4)|digit;
    }
    out={bits,width,kind};return true;
}
inline bool matches(const Pattern& p,const instructions::NumericLiteral& literal) noexcept {
    using K=instructions::NumericKind;
    if(p.width!=literal.width_bits || p.bits!=literal.bits) return false;
    if(p.kind==Kind::either) return literal.kind==K::constant || literal.kind==K::arithmetic_operand;
    if(p.kind==Kind::constant) return literal.kind==K::constant;
    return p.kind==Kind::arithmetic_operand && literal.kind==K::arithmetic_operand;
}
// Fixed little-endian width(u32), kind(u32), bits(u64), matching project u32/u64
// encoding conventions. Parent AST must add a new node tag and versioned domain.
inline std::array<uint8_t,16> encode(const Pattern& p) noexcept {
    std::array<uint8_t,16> out{};
    for(unsigned i=0;i<4;++i)out[i]=uint8_t(p.width>>(8*i));
    const uint32_t kind=static_cast<uint32_t>(p.kind);
    for(unsigned i=0;i<4;++i)out[4+i]=uint8_t(kind>>(8*i));
    for(unsigned i=0;i<8;++i)out[8+i]=uint8_t(p.bits>>(8*i));
    return out;
}
}
