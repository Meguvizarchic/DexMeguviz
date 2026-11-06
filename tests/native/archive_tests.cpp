#include "source/archive/archive.hpp"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <vector>

namespace ar = dexmeguviz::archive;
namespace {
size_t checks = 0;
void check(bool condition, const char* message) {
    ++checks;
    if (!condition) throw std::runtime_error(message);
}
std::vector<uint8_t> load(const std::filesystem::path& file) {
    std::ifstream stream(file, std::ios::binary);
    if (!stream) throw std::runtime_error("fixture unavailable");
    return {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
}
class Tracker : public std::pmr::memory_resource {
public:
    uint64_t live = 0, peak = 0, limit = 16 * 1024 * 1024;
    size_t attempts = 0, fail_at = static_cast<size_t>(-1);
    std::map<void*, std::pair<size_t,size_t>> blocks;
private:
    void* do_allocate(size_t size, size_t align) override {
        const auto attempt = attempts++;
        if (attempt == fail_at || size > limit-live) throw std::bad_alloc();
        void* pointer = std::pmr::new_delete_resource()->allocate(size, align);
        blocks.emplace(pointer, std::pair{size, align});
        live += size; peak = std::max(peak, live);
        return pointer;
    }
    void do_deallocate(void* pointer, size_t size, size_t align) override {
        const auto found = blocks.find(pointer);
        if (found == blocks.end() || found->second != std::pair{size, align}) std::terminate();
        blocks.erase(found); live -= size;
        std::pmr::new_delete_resource()->deallocate(pointer, size, align);
    }
    bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override { return this == &other; }
};
template<class Function>
void fails(ar::Status expected, Function action) {
    bool failed = false;
    try { action(); }
    catch (const ar::Error& error) { failed = true; check(error.status == expected, "unexpected archive failure status"); }
    check(failed, "expected archive failure was accepted");
}
struct Cancellation { size_t calls = 0; size_t cancel_at = 0; };
bool cancel(void* raw) noexcept {
    auto& value = *static_cast<Cancellation*>(raw);
    return value.calls++ >= value.cancel_at;
}
bool only_dex(void*, std::string_view name, uint32_t) noexcept {
    return name == "classes.dex" || name == "classes2.dex";
}
}
int main(int argc, char** argv) {
    try {
        if (argc != 3) throw std::runtime_error("usage: archive_tests FIXTURE_DIR MINIMAL_DEX");
        const std::filesystem::path root(argv[1]);
        const auto dex = load(argv[2]);
        for (const auto* fixture : {"stored.apk", "deflated.apk", "descriptor.apk", "local-zip64.apk", "zip64.apk", "zip64-descriptor.apk",
             "zipalign-padding-1.apk", "zipalign-padding-3.apk", "zipalign-padding-7.apk", "zipalign-after-extra.apk", "zipalign-after-zip64.apk"}) {
            Tracker memory;
            {
                const auto bytes = load(root / fixture);
                auto entries = ar::read(bytes, {}, &memory);
                check(entries.size() == 1, "one entry expected");
                check(entries[0].name == "classes.dex", "full filename mismatch");
                check(std::equal(entries[0].bytes.begin(), entries[0].bytes.end(), dex.begin(), dex.end()), "extracted bytes differ");
                check(entries[0].crc_verified && entries[0].header_consistency_verified, "verification flags not complete");
                check(memory.live > 0, "returned PMR data must remain accounted");
            }
            check(memory.live == 0 && memory.blocks.empty(), "successful extraction leaked");
        }
        {
            Tracker memory;
            {
                auto bytes = load(root / "multidex.apk");
                auto entries = ar::read(bytes, {}, &memory);
                check(entries.size() == 2 && entries[0].index == 0 && entries[1].index == 1, "multidex entry identity lost");
                auto moved = std::move(entries);
                bytes.clear();
                check(moved[0].bytes.size() == dex.size(), "output does not own bytes");
            }
            check(memory.live == 0, "multidex output leaked");
        }
        for (const auto* fixture : {"duplicate.apk", "duplicate-long.zip", "crc-mismatch.apk", "size-too-large.apk",
             "size-too-small.apk", "local-name-mismatch.apk", "embedded-nul.apk", "truncated.apk",
             "directory-offset-overflow.apk", "zip64-size-overflow.apk", "local-extra-nonzero-tail.apk", "central-extra-zero-tail.apk", "zip64-required-field-missing.apk"}) {
            Tracker memory;
            const auto bytes = load(root / fixture);
            fails(ar::Status::corrupt_input, [&] { (void)ar::read(bytes, {}, &memory); });
            check(memory.live == 0 && memory.blocks.empty(), "corrupt input leaked");
        }
        for (const auto* fixture : {"unsupported-method.apk", "encrypted.apk"}) {
            Tracker memory;
            const auto bytes = load(root / fixture);
            fails(ar::Status::unsupported, [&] { (void)ar::read(bytes, {}, &memory); });
            check(memory.live == 0, "unsupported input leaked");
        }
        {
            Tracker memory;
            {
                auto entries = ar::read(load(root / "long-name.zip"), {}, &memory);
                check(entries.size() == 2 && entries[0].name.size() == 607 && entries[1].name.size() == 608, "long full names truncated or falsely deduplicated");
                check(entries[0].bytes.size() == 4 && entries[1].bytes.size() == 8, "long-name payload mismatch");
            }
            check(memory.live == 0, "long names leaked");
        }
        {
            Tracker memory;
            {
                auto empty = ar::read(load(root / "empty.zip"), {}, &memory);
                check(empty.empty(), "empty archive mismatch");
                auto zero = ar::read(load(root / "zero-entry.zip"), {}, &memory);
                check(zero.size() == 1 && zero[0].bytes.empty() && zero[0].crc_verified, "empty entry did not verify");
            }
            check(memory.live == 0, "empty cases leaked");
        }
        const auto many = load(root / "many.apk");
        {
            Tracker memory;
            ar::Limits limits; limits.max_total_output_bytes = dex.size()*2;
            {
                auto selected = ar::read(many, limits, &memory, {}, {only_dex, nullptr});
                check(selected.size() == 2, "entry selection mismatch");
            }
            check(memory.live == 0, "selected result leaked");
        }
        for (int quota = 0; quota < 6; ++quota) {
            Tracker memory;
            ar::Limits limits;
            if (quota == 0) limits.max_archive_bytes = 1;
            if (quota == 1) limits.max_entries = 1;
            if (quota == 2) limits.max_central_directory_bytes = 1;
            if (quota == 3) limits.max_name_bytes = 2;
            if (quota == 4) limits.max_entry_output_bytes = dex.size()-1;
            if (quota == 5) limits.max_total_output_bytes = dex.size()*2;
            fails(ar::Status::budget_exceeded, [&] { (void)ar::read(many, limits, &memory); });
            check(memory.live == 0, "quota failure leaked");
        }
        size_t success_allocations = 0;
        {
            Tracker memory;
            { (void)ar::read(many, {}, &memory); success_allocations = memory.attempts; }
            check(memory.live == 0, "baseline allocation run leaked");
        }
        for (size_t fail = 0; fail < success_allocations; ++fail) {
            Tracker memory; memory.fail_at = fail;
            fails(ar::Status::budget_exceeded, [&] { (void)ar::read(many, {}, &memory); });
            check(memory.live == 0 && memory.blocks.empty(), "allocation failure leaked");
        }
        size_t checkpoints = 0;
        {
            Tracker memory;
            Cancellation state{0, static_cast<size_t>(-1)};
            { (void)ar::read(many, {}, &memory, {cancel, &state}); }
            checkpoints = state.calls;
            check(memory.live == 0, "cancellation baseline leaked");
        }
        for (size_t at = 0; at < checkpoints; ++at) {
            Tracker memory;
            Cancellation state{0, at};
            fails(ar::Status::cancelled, [&] { (void)ar::read(many, {}, &memory, {cancel, &state}); });
            check(memory.live == 0 && memory.blocks.empty(), "cancelled extraction leaked");
        }
        std::cout << "archive checks=" << checks << " allocation_fault_points=" << success_allocations
                  << " cancellation_points=" << checkpoints << "\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "archive test failed: " << error.what() << "\n";
        return 1;
    }
}
