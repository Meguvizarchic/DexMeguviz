#pragma once
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory_resource>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace dexmeguviz::archive {
enum class Status { corrupt_input, unsupported, budget_exceeded, cancelled, internal_error };
struct Error : std::exception {
    Status status;
    uint64_t offset;
    const char* message;
    Error(Status state, uint64_t at, const char* reason) noexcept
        : status(state), offset(at), message(reason) {}
    const char* what() const noexcept override { return message; }
};
struct Limits {
    uint64_t max_archive_bytes = 512ull * 1024 * 1024;
    uint64_t max_entries = 100000;
    uint64_t max_central_directory_bytes = 16ull * 1024 * 1024;
    uint64_t max_name_bytes = 65535;
    uint64_t max_total_name_bytes = 8ull * 1024 * 1024;
    uint64_t max_entry_output_bytes = 64ull * 1024 * 1024;
    uint64_t max_total_output_bytes = 256ull * 1024 * 1024;
    size_t chunk_bytes = 64 * 1024;
};
struct Cancel {
    bool (*requested)(void*) noexcept = nullptr;
    void* context = nullptr;
};
struct Selection {
    // Called after complete-name duplicate checks. Null selects all regular files.
    bool (*include)(void*, std::string_view, uint32_t) noexcept = nullptr;
    void* context = nullptr;
};
struct Entry {
    uint32_t index = 0;
    std::pmr::string name;
    std::pmr::vector<uint8_t> bytes;
    uint32_t crc32 = 0;
    bool header_consistency_verified = false;
    bool crc_verified = false;
    bool zip64 = false;
    explicit Entry(std::pmr::memory_resource* memory) : name(memory), bytes(memory) {}
};
// Input remains immutable for the duration of this synchronous call. Returned
// entries own their bytes; memory must outlive every returned PMR container.
// No result is returned after an incomplete extraction or failed final CRC.
std::pmr::vector<Entry> read(std::span<const uint8_t> input, const Limits& limits,
    std::pmr::memory_resource* memory, Cancel cancel = {}, Selection selection = {});
}
