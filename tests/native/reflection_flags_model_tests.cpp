#include "query/reflection_flags.hpp"
#include <cstdint>
#include <iostream>
#include <stdexcept>

using dexmeguviz::query::reflection_flags::project;
using dexmeguviz::query::reflection_flags::Target;

int main() {
    auto exact = [](uint32_t raw, Target target, uint32_t expected, bool no_annotations=false) {
        const auto actual=project(raw,target,no_annotations);
        if(!actual||*actual!=expected)throw std::runtime_error("unexpected projected flags");
    };
    auto unknown = [](uint32_t raw, Target target, bool no_annotations=false) {
        if(project(raw,target,no_annotations))throw std::runtime_error("ambiguous encoding must be Unknown");
    };
    exact(0x121,Target::method,0x101);       // native monitor bit is not declared synchronized
    exact(0x20121,Target::method,0x121);     // declared synchronized restores reflection bit
    exact(0x20001,Target::method,0x21);      // declared synchronized, non-native
    exact(0x501,Target::method,0x401);        // AOSP abstract runtime native-stub rule
    exact(0x10001,Target::method,0x1);       // DEX constructor bit is not a Java flag
    exact(0x19,Target::field,0x19);
    exact(0x601,Target::klass,0x601,true);
    unknown(0x1,Target::klass);               // class annotation contents are not known absent
    unknown(0x21,Target::method);            // hiddenapi-style/invalid non-native bit
    unknown(0x121|0x200,Target::method);     // hiddenapi-style/invalid native bit
    unknown(0x21,Target::field);             // hiddenapi-style field bit
    unknown(0x3,Target::field);              // inverted or malformed visibility
    unknown(0x10000001,Target::method);       // unmodelled runtime/vendor flag
    unknown(0x9,Target::klass,true);         // static class must use InnerClass annotations
    std::cout << "PASS static reflection flags model and Unknown encodings\n";
}
