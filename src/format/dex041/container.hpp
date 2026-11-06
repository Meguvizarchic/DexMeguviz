#pragma once
#include <cstdint>
#include <memory_resource>
#include <span>
#include <vector>
namespace dexmeguviz::dex041 {
struct Header {uint32_t offset,file_size,container_size;};
// Explicit experimental admission; byte offsets always use the physical span.
std::pmr::vector<Header> enumerate(std::span<const uint8_t> container,
    std::pmr::memory_resource* memory=std::pmr::get_default_resource(),uint32_t max_headers=64);
}
