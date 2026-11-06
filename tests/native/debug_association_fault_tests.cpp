#include "format/reader.hpp"
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory_resource>
#include <stdexcept>
#include <string>
#include <vector>

#define CHECK(x) do { if (!(x)) throw std::runtime_error(std::string("line ") + std::to_string(__LINE__) + ": " #x); } while (0)

class FaultResource final : public std::pmr::memory_resource {
public:
    explicit FaultResource(int64_t fail_after = -1) : fail_after_(fail_after) {}
    uint64_t calls = 0;
    uint64_t outstanding = 0;
private:
    int64_t fail_after_;
    void* do_allocate(size_t bytes, size_t alignment) override {
        if (fail_after_ >= 0 && static_cast<int64_t>(calls++) == fail_after_) throw std::bad_alloc();
        if (fail_after_ < 0) ++calls;
        void* result = std::pmr::new_delete_resource()->allocate(bytes, alignment);
        outstanding += bytes;
        return result;
    }
    void do_deallocate(void* p, size_t bytes, size_t alignment) override {
        if (bytes > outstanding) std::terminate();
        outstanding -= bytes;
        std::pmr::new_delete_resource()->deallocate(p, bytes, alignment);
    }
    bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override { return this == &other; }
};

int main(int argc, char** argv) {
    try {
        CHECK(argc == 2);
        std::ifstream input(argv[1], std::ios::binary);
        CHECK(input.good());
        std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)), {});
        CHECK(bytes.size() > 725 && bytes[644] == 0xcd && bytes[645] == 0x02 &&
              bytes[717] == 1 && bytes[718] == 2);

        FaultResource normal;
        { const auto facts = dexmeguviz::read_metadata(bytes, &normal); CHECK(facts.methods.size() == 4); }
        CHECK(normal.outstanding == 0);
        FaultResource checked;
        { const auto facts = dexmeguviz::read_metadata_with_debug_associations(bytes, &checked); CHECK(facts.methods.size() == 4); }
        CHECK(checked.outstanding == 0 && checked.calls > normal.calls);
        const auto total = checked.calls;
        CHECK(total > 5 && total < 2048);
        for (uint64_t position = 0; position < total; ++position) {
            FaultResource resource(static_cast<int64_t>(position));
            bool failed = false;
            try {
                const auto facts = dexmeguviz::read_metadata_with_debug_associations(bytes, &resource);
                (void)facts;
            } catch (const std::bad_alloc&) { failed = true; }
            CHECK(failed && resource.outstanding == 0);
        }
        std::cout << "PASS explicit debug association allocations: " << total
                  << " failures released; default calls=" << normal.calls << "\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
