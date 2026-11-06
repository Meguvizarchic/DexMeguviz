#pragma once
#include <cstdint>
#include <map>
#include <memory_resource>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace dexmeguviz::query::json {
struct JsonError : std::runtime_error { using std::runtime_error::runtime_error; };
struct Json {
    enum class Kind { null_value, boolean, number, string, array, object };
    Kind kind = Kind::null_value;
    bool boolean = false;
    std::pmr::string number;
    std::pmr::u16string string;
    std::pmr::vector<Json> array;
    std::pmr::map<std::pmr::u16string, Json, std::less<>> object;
    explicit Json(std::pmr::memory_resource* memory) : number(memory), string(memory), array(memory), object(std::less<>{},memory) {}
    Json(const Json&)=delete;
    Json& operator=(const Json&)=delete;
    Json(Json&&)=default;
    Json& operator=(Json&&)=default;
};

class JsonReader {
public:
    explicit JsonReader(std::string_view input, std::pmr::memory_resource* memory) : input_(input), memory_(memory) {
        if (input.size() > 65536) throw JsonError("Query JSON exceeds 64 KiB");
    }
    Json parse() {
        Json result = value(0);
        whitespace();
        if (position_ != input_.size()) fail("Trailing JSON bytes");
        return result;
    }
private:
    std::string_view input_;
    std::pmr::memory_resource* memory_;
    size_t position_ = 0;
    size_t nodes_ = 0;

    [[noreturn]] void fail(const char* reason) const {
        throw JsonError(std::string(reason) + " at byte " + std::to_string(position_));
    }
    void whitespace() {
        while (position_ < input_.size()) {
            const char c = input_[position_];
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r') break;
            ++position_;
        }
    }
    bool take(char c) {
        if (position_ < input_.size() && input_[position_] == c) { ++position_; return true; }
        return false;
    }
    void require(char c) { if (!take(c)) fail("Unexpected JSON token"); }
    void literal(std::string_view expected) {
        if (input_.substr(position_, expected.size()) != expected) fail("Invalid JSON literal");
        position_ += expected.size();
    }
    static bool digit(char c) { return c >= '0' && c <= '9'; }
    uint16_t hex4() {
        if (input_.size() - position_ < 4) fail("Truncated Unicode escape");
        uint16_t value = 0;
        for (unsigned i = 0; i != 4; ++i) {
            const char c = input_[position_++];
            unsigned n;
            if (c >= '0' && c <= '9') n = static_cast<unsigned>(c - '0');
            else if (c >= 'a' && c <= 'f') n = static_cast<unsigned>(c - 'a') + 10;
            else if (c >= 'A' && c <= 'F') n = static_cast<unsigned>(c - 'A') + 10;
            else fail("Invalid Unicode escape");
            value = static_cast<uint16_t>((value << 4) | n);
        }
        return value;
    }
    std::pmr::u16string string() {
        require('"');
        std::pmr::u16string out(memory_);
        while (position_ < input_.size()) {
            const auto c = static_cast<uint8_t>(input_[position_++]);
            if (c == '"') return out;
            if (c < 0x20) fail("Unescaped control in JSON string");
            if (c == '\\') {
                if (position_ == input_.size()) fail("Truncated escape");
                switch (input_[position_++]) {
                    case '"': out.push_back(u'"'); break;
                    case '\\': out.push_back(u'\\'); break;
                    case '/': out.push_back(u'/'); break;
                    case 'b': out.push_back(u'\b'); break;
                    case 'f': out.push_back(u'\f'); break;
                    case 'n': out.push_back(u'\n'); break;
                    case 'r': out.push_back(u'\r'); break;
                    case 't': out.push_back(u'\t'); break;
                    case 'u': out.push_back(static_cast<char16_t>(hex4())); break;
                    default: fail("Unknown JSON escape");
                }
            } else if (c < 0x80) {
                out.push_back(static_cast<char16_t>(c));
            } else {
                uint32_t codepoint;
                uint32_t minimum;
                unsigned extra;
                if (c >= 0xc2 && c <= 0xdf) { codepoint = c & 0x1f; extra = 1; minimum = 0x80; }
                else if (c >= 0xe0 && c <= 0xef) { codepoint = c & 0x0f; extra = 2; minimum = 0x800; }
                else if (c >= 0xf0 && c <= 0xf4) { codepoint = c & 0x07; extra = 3; minimum = 0x10000; }
                else fail("Invalid UTF-8 leading byte");
                if (input_.size() - position_ < extra) fail("Truncated UTF-8");
                for (unsigned i = 0; i < extra; ++i) {
                    const auto continuation = static_cast<uint8_t>(input_[position_++]);
                    if ((continuation & 0xc0) != 0x80) fail("Invalid UTF-8 continuation");
                    codepoint = (codepoint << 6) | (continuation & 0x3f);
                }
                if (codepoint < minimum || codepoint > 0x10ffff || (codepoint >= 0xd800 && codepoint <= 0xdfff))
                    fail("Invalid UTF-8 scalar");
                if (codepoint <= 0xffff) out.push_back(static_cast<char16_t>(codepoint));
                else {
                    codepoint -= 0x10000;
                    out.push_back(static_cast<char16_t>(0xd800 + (codepoint >> 10)));
                    out.push_back(static_cast<char16_t>(0xdc00 + (codepoint & 0x3ff)));
                }
            }
        }
        fail("Unterminated JSON string");
    }
    Json value(unsigned depth) {
        if (depth > 32) fail("JSON nesting exceeds 32");
        if (++nodes_ > 16384) fail("JSON node count exceeds 16384");
        whitespace();
        if (position_ == input_.size()) fail("Missing JSON value");
        Json out(memory_);
        const char c = input_[position_];
        if (c == '{') {
            ++position_; out.kind = Json::Kind::object; whitespace();
            if (take('}')) return out;
            do {
                whitespace();
                if (position_ == input_.size() || input_[position_] != '"') fail("Object key must be a string");
                auto key = string(); whitespace(); require(':');
                auto child = value(depth + 1);
                if (!out.object.emplace(std::move(key), std::move(child)).second) fail("Duplicate JSON key");
                whitespace();
                if (take('}')) return out;
                require(',');
            } while (true);
        }
        if (c == '[') {
            ++position_; out.kind = Json::Kind::array; whitespace();
            if (take(']')) return out;
            do {
                out.array.push_back(value(depth + 1)); whitespace();
                if (take(']')) return out;
                require(',');
            } while (true);
        }
        if (c == '"') { out.kind = Json::Kind::string; out.string = string(); return out; }
        if (c == 'n') { literal("null"); return out; }
        if (c == 't') { literal("true"); out.kind = Json::Kind::boolean; out.boolean = true; return out; }
        if (c == 'f') { literal("false"); out.kind = Json::Kind::boolean; return out; }
        if (c == '-' || digit(c)) {
            out.kind = Json::Kind::number;
            const size_t start = position_;
            take('-');
            if (!take('0')) {
                if (position_ == input_.size() || input_[position_] < '1' || input_[position_] > '9') fail("Invalid JSON number");
                while (position_ < input_.size() && digit(input_[position_])) ++position_;
            }
            if (take('.')) {
                const auto fraction = position_;
                while (position_ < input_.size() && digit(input_[position_])) ++position_;
                if (fraction == position_) fail("Invalid JSON fraction");
            }
            if (take('e') || take('E')) {
                if (!take('+')) take('-');
                const auto exponent = position_;
                while (position_ < input_.size() && digit(input_[position_])) ++position_;
                if (exponent == position_) fail("Invalid JSON exponent");
            }
            out.number.assign(input_.substr(start, position_ - start));
            return out;
        }
        fail("Invalid JSON value");
    }
};


}
