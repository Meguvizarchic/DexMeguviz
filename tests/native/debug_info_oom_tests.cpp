#include "dexmeguviz/dexmeguviz.h"
#include "execution/budget/account.hpp"
#include <cstdint>
#include <cstring>
#include <exception>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#define CHECK(x) do { if (!(x)) throw std::runtime_error(std::string("line ") + std::to_string(__LINE__) + ": " #x); } while (0)

static bool same(const dmg_engine_stats& a, const dmg_engine_stats& b) {
    return a.owned_bytes == b.owned_bytes && a.source_bytes == b.source_bytes &&
        a.fact_bytes == b.fact_bytes && a.scratch_bytes == b.scratch_bytes &&
        a.query_bytes == b.query_bytes && a.result_bytes == b.result_bytes &&
        a.control_bytes == b.control_bytes && a.borrowed_bytes == b.borrowed_bytes &&
        a.active_jobs == b.active_jobs && a.admission_closed == b.admission_closed;
}

int main(int argc, char** argv) {
    try {
        CHECK(argc == 3);
        std::ifstream file(argv[1], std::ios::binary);
        CHECK(file.good());
        std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(file)), {});
        CHECK(bytes.size() > 525 && bytes[416] == 0xf4 && bytes[417] == 0x01 &&
              bytes[418] == 0 && bytes[419] == 0 && bytes[500] == 0x0a && bytes[524] == 0);
        dmg_error error{};
        dmg_engine* engine = nullptr;
        CHECK(dmg_engine_create(nullptr, &engine, &error) == DMG_OK && engine);
        dmg_engine_stats baseline{};
        CHECK(dmg_engine_get_stats(engine, &baseline) == DMG_OK);
        dmg_open_options options{sizeof(options), DMG_ABI_VERSION, DMG_MAX_SOURCE_BYTES, "debug-oom", "0", argv[2]};

        auto check_stats = [&]() {
            dmg_engine_stats now{};
            CHECK(dmg_engine_get_stats(engine, &now) == DMG_OK && same(now, baseline));
        };
        auto check_open = [&](dmg_snapshot* snapshot) {
            CHECK(snapshot);
            dmg_snapshot_info info{};
            CHECK(dmg_snapshot_get_info(snapshot, &info) == DMG_OK);
            CHECK(info.source_bytes == bytes.size() && info.source_sha256 && !std::strcmp(info.source_sha256, argv[2]));
            CHECK(info.dex_version == 35 && info.class_count == 1 && info.method_def_count == 2);
            dmg_snapshot_release(snapshot);
            check_stats();
        };

        // Prove that the checked fixture actually reaches debug-item start validation.
        std::vector<uint8_t> invalid = bytes;
        invalid[416] = 0xf5; // offset 501 is inside the item at 500.
        auto no_hash = options;
        no_hash.expected_sha256 = nullptr;
        dmg_snapshot* rejected = reinterpret_cast<dmg_snapshot*>(uintptr_t(1));
        CHECK(dmg_snapshot_open_copy_in(engine, invalid.data(), invalid.size(), &no_hash, &rejected, &error) == DMG_CORRUPT_INPUT);
        CHECK(rejected == nullptr && std::strstr(error.message, "debug offset") != nullptr);
        check_stats();

        uint32_t failures = 0;
        bool completed = false;
        for (int64_t position = 0; position < 2048; ++position) {
            dmg_snapshot* snapshot = reinterpret_cast<dmg_snapshot*>(uintptr_t(1));
            dexmeguviz::test_fail_allocation_after(position);
            const auto status = dmg_snapshot_open_copy_in(engine, bytes.data(), bytes.size(), &options, &snapshot, &error);
            dexmeguviz::test_fail_allocation_after(-1);
            if (status == DMG_OK) {
                check_open(snapshot);
                completed = true;
                break;
            }
            CHECK(status == DMG_OUT_OF_MEMORY && snapshot == nullptr);
            ++failures;
            check_stats();
            // A failed open must not poison the engine or retain any parser state.
            snapshot = nullptr;
            CHECK(dmg_snapshot_open_copy_in(engine, bytes.data(), bytes.size(), &options, &snapshot, &error) == DMG_OK);
            check_open(snapshot);
        }
        CHECK(completed && failures > 5);
        dmg_engine_release(engine);
        std::cout << "PASS debug-info PMR allocation: " << failures
                  << " failing positions; every retry restored the baseline\n";
        return 0;
    } catch (const std::exception& error) {
        dexmeguviz::test_fail_allocation_after(-1);
        std::cerr << error.what() << '\n';
        return 1;
    }
}
