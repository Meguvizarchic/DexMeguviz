#pragma once
#include "dexmeguviz/dexmeguviz.h"
#include <cstddef>
#include <cstdint>

// Internal bridge: fills an owned, engine-accounted buffer synchronously.
// The callback must not retain its pointer or call back into the engine.
namespace dexmeguviz::runtime {
using RawFill = bool (*)(void*, uint8_t*, size_t);
dmg_status open_android_raw_filled(dmg_engine*, uint64_t, const char*, RawFill, void*, dmg_snapshot**, dmg_error*) noexcept;
}
