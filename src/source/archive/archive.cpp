#include "archive.hpp"
#include "miniz.h"
#include <algorithm>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>
#include <utility>

namespace dexmeguviz::archive {
namespace {
constexpr uint32_t local_signature = 0x04034b50;
constexpr uint32_t central_signature = 0x02014b50;
constexpr uint32_t end_signature = 0x06054b50;
constexpr uint32_t zip64_signature = 0x06064b50;
constexpr uint32_t locator_signature = 0x07064b50;
constexpr uint32_t descriptor_signature = 0x08074b50;
constexpr uint32_t maximum32 = 0xffffffffu;

struct Context {
    std::span<const uint8_t> input;
    std::pmr::memory_resource* memory;
    Cancel cancel;
    bool failed = false;
    Status status = Status::internal_error;
    uint64_t failure_offset = 0;
    void record(Status reason, uint64_t at = 0) noexcept {
        if (!failed) { failed = true; status = reason; failure_offset = at; }
    }
    bool cancelled() noexcept {
        if (cancel.requested && cancel.requested(cancel.context)) {
            record(Status::cancelled);
            return true;
        }
        return false;
    }
    void checkpoint() {
        if (cancelled()) throw Error(Status::cancelled, 0, "archive operation cancelled");
    }
    [[noreturn]] void library_error(mz_zip_archive& zip) const {
        if (failed) throw Error(status, failure_offset, "archive callback failed");
        const auto code = mz_zip_get_last_error(&zip);
        if (code == MZ_ZIP_ALLOC_FAILED) throw Error(Status::budget_exceeded, 0, "archive allocation failed");
        if (code == MZ_ZIP_UNSUPPORTED_METHOD || code == MZ_ZIP_UNSUPPORTED_ENCRYPTION ||
            code == MZ_ZIP_UNSUPPORTED_FEATURE || code == MZ_ZIP_UNSUPPORTED_MULTIDISK ||
            code == MZ_ZIP_UNSUPPORTED_CDIR_SIZE)
            throw Error(Status::unsupported, 0, "unsupported archive feature");
        if (code == MZ_ZIP_INTERNAL_ERROR || code == MZ_ZIP_INVALID_PARAMETER)
            throw Error(Status::internal_error, 0, "archive backend failure");
        throw Error(Status::corrupt_input, 0, "archive metadata, deflate stream, size or CRC is invalid");
    }
};

struct alignas(std::max_align_t) Allocation {
    size_t requested;
    size_t allocated;
};
void* allocate(void* opaque, size_t items, size_t size) noexcept {
    auto& context = *static_cast<Context*>(opaque);
    if (context.cancelled()) return nullptr;
    if (size != 0 && items > (std::numeric_limits<size_t>::max() - sizeof(Allocation)) / size) {
        context.record(Status::budget_exceeded); return nullptr;
    }
    const size_t requested = items * size;
    const size_t total = sizeof(Allocation) + std::max(size_t{1}, requested);
    try {
        auto* header = static_cast<Allocation*>(context.memory->allocate(total, alignof(Allocation)));
        ::new (header) Allocation{requested, total};
        return header + 1;
    } catch (const std::bad_alloc&) { context.record(Status::budget_exceeded); }
    catch (...) { context.record(Status::internal_error); }
    return nullptr;
}
void deallocate(void* opaque, void* pointer) noexcept {
    if (!pointer) return;
    auto& context = *static_cast<Context*>(opaque);
    auto* header = static_cast<Allocation*>(pointer) - 1;
    const auto total = header->allocated;
    try { context.memory->deallocate(header, total, alignof(Allocation)); }
    catch (...) { context.record(Status::internal_error); }
}
void* reallocate(void* opaque, void* pointer, size_t items, size_t size) noexcept {
    if (!pointer) return allocate(opaque, items, size);
    if (items == 0 || size == 0) { deallocate(opaque, pointer); return nullptr; }
    void* replacement = allocate(opaque, items, size);
    if (!replacement) return nullptr;
    const auto old_size = (static_cast<Allocation*>(pointer) - 1)->requested;
    const auto new_size = (static_cast<Allocation*>(replacement) - 1)->requested;
    std::memcpy(replacement, pointer, std::min(old_size, new_size));
    deallocate(opaque, pointer);
    return replacement;
}
size_t read_callback(void* opaque, mz_uint64 at, void* output, size_t count) noexcept {
    auto& context = *static_cast<Context*>(opaque);
    if (context.cancelled()) return 0;
    if (at > context.input.size() || count > context.input.size() - at) {
        context.record(Status::corrupt_input, at); return 0;
    }
    if (count) std::memcpy(output, context.input.data() + static_cast<size_t>(at), count);
    return count;
}

class Bytes {
public:
    explicit Bytes(std::span<const uint8_t> input) : bytes(input) {}
    void range(uint64_t at, uint64_t count) const {
        if (at > bytes.size() || count > bytes.size() - at)
            throw Error(Status::corrupt_input, at, "archive range exceeds immutable input");
    }
    uint16_t u16(uint64_t at) const {
        range(at, 2); return uint16_t(bytes[at]) | (uint16_t(bytes[at + 1]) << 8);
    }
    uint32_t u32(uint64_t at) const {
        range(at, 4); return uint32_t(bytes[at]) | (uint32_t(bytes[at+1]) << 8) |
            (uint32_t(bytes[at+2]) << 16) | (uint32_t(bytes[at+3]) << 24);
    }
    uint64_t u64(uint64_t at) const { range(at, 8); return uint64_t(u32(at)) | (uint64_t(u32(at+4)) << 32); }
    std::string_view string(uint64_t at, size_t count) const {
        range(at, count); return {reinterpret_cast<const char*>(bytes.data() + static_cast<size_t>(at)), count};
    }
private:
    std::span<const uint8_t> bytes;
};
struct Directory { uint64_t offset; uint64_t size; uint64_t count; bool zip64; };
Directory preflight(Context& context, const Limits& limits) {
    if (context.input.size() > limits.max_archive_bytes)
        throw Error(Status::budget_exceeded, 0, "archive byte quota exceeded");
    if (context.input.size() < 22) throw Error(Status::corrupt_input, 0, "missing ZIP end record");
    const Bytes bytes(context.input);
    const uint64_t last = context.input.size() - 22;
    const uint64_t first = last > 65535 ? last - 65535 : 0;
    uint64_t end = last;
    bool found = false;
    for (;;) {
        if ((end & 1023) == 0) context.checkpoint();
        if (bytes.u32(end) == end_signature && uint64_t(bytes.u16(end + 20)) == last - end) { found = true; break; }
        if (end == first) break;
        --end;
    }
    if (!found) throw Error(Status::corrupt_input, last, "missing complete ZIP end record");
    if (bytes.u16(end + 4) != 0 || bytes.u16(end + 6) != 0)
        throw Error(Status::unsupported, end, "multi-disk archives are unsupported");
    Directory result{bytes.u32(end+16), bytes.u32(end+12), bytes.u16(end+10), false};
    if (bytes.u16(end+8) != result.count) throw Error(Status::unsupported, end, "split entry counts are unsupported");
    const bool sentinels = result.offset == maximum32 || result.size == maximum32 || result.count == 65535;
    const bool locator = end >= 20 && bytes.u32(end-20) == locator_signature;
    uint64_t directory_limit = end;
    if (locator) {
        if (bytes.u32(end-16) != 0 || bytes.u32(end-4) != 1)
            throw Error(Status::unsupported, end-20, "multi-disk ZIP64 is unsupported");
        const uint64_t at = bytes.u64(end-12);
        bytes.range(at, 56);
        if (at > end-20 || end-20-at < 12 || bytes.u32(at) != zip64_signature || bytes.u64(at+4) < 44 ||
            bytes.u64(at+4) > end-20-at-12)
            throw Error(Status::corrupt_input, at, "invalid ZIP64 end record");
        if (bytes.u32(at+16) != 0 || bytes.u32(at+20) != 0 || bytes.u64(at+24) != bytes.u64(at+32))
            throw Error(Status::unsupported, at, "multi-disk ZIP64 is unsupported");
        const Directory extended{bytes.u64(at+48), bytes.u64(at+40), bytes.u64(at+32), true};
        if ((result.offset != maximum32 && result.offset != extended.offset) ||
            (result.size != maximum32 && result.size != extended.size) ||
            (result.count != 65535 && result.count != extended.count))
            throw Error(Status::corrupt_input, at, "ZIP32 and ZIP64 end records disagree");
        result = extended; directory_limit = at;
    } else if (sentinels) throw Error(Status::corrupt_input, end, "ZIP64 locator is missing");
    if (result.count > limits.max_entries || result.size > limits.max_central_directory_bytes)
        throw Error(Status::budget_exceeded, result.offset, "archive directory quota exceeded");
    bytes.range(result.offset, result.size);
    if (result.offset > directory_limit || result.size > directory_limit - result.offset ||
        result.count > result.size / 46)
        throw Error(Status::corrupt_input, result.offset, "invalid central directory extent");
    return result;
}
struct Record {
    std::pmr::string name;
    uint64_t central_offset = 0;
    uint32_t index = 0;
    explicit Record(std::pmr::memory_resource* memory) : name(memory) {}
};
std::pmr::vector<Record> names(Context& context, const Directory& directory, const Limits& limits) {
    const Bytes bytes(context.input);
    std::pmr::vector<Record> records(context.memory);
    if (directory.count > std::numeric_limits<uint32_t>::max())
        throw Error(Status::unsupported, directory.offset, "ZIP64 entry count exceeds backend profile");
    records.reserve(static_cast<size_t>(directory.count));
    uint64_t cursor = directory.offset, total_names = 0;
    const uint64_t end = directory.offset + directory.size;
    for (uint64_t i = 0; i < directory.count; ++i) {
        context.checkpoint(); bytes.range(cursor, 46);
        if (cursor > end || end-cursor < 46 || bytes.u32(cursor) != central_signature)
            throw Error(Status::corrupt_input, cursor, "invalid central directory entry");
        const auto length = bytes.u16(cursor+28), extra = bytes.u16(cursor+30), comment = bytes.u16(cursor+32);
        const uint64_t size = uint64_t(46) + length + extra + comment;
        if (size > end-cursor) throw Error(Status::corrupt_input, cursor, "central entry exceeds directory");
        if (length == 0) throw Error(Status::corrupt_input, cursor, "empty archive filename");
        if (length > limits.max_name_bytes || length > limits.max_total_name_bytes-total_names)
            throw Error(Status::budget_exceeded, cursor, "archive filename quota exceeded");
        total_names += length;
        const auto name = bytes.string(cursor+46, length);
        if (name.find('\0') != std::string_view::npos)
            throw Error(Status::corrupt_input, cursor+46, "embedded NUL archive filename");
        records.emplace_back(context.memory);
        records.back().name.assign(name);
        records.back().index = static_cast<uint32_t>(i);
        records.back().central_offset = cursor;
        cursor += size;
    }
    if (cursor != end) throw Error(Status::unsupported, cursor, "extra central directory record is unsupported");
    std::pmr::vector<uint32_t> order(context.memory);
    order.reserve(records.size());
    for (uint32_t i = 0; i < records.size(); ++i) order.push_back(i);
    size_t comparisons = 0;
    std::sort(order.begin(), order.end(), [&](uint32_t a, uint32_t b) {
        if ((++comparisons & 1023) == 0) context.checkpoint();
        return records[a].name < records[b].name;
    });
    for (size_t i = 1; i < order.size(); ++i) {
        if ((i & 1023) == 0) context.checkpoint();
        if (records[order[i-1]].name == records[order[i]].name)
            throw Error(Status::corrupt_input, records[order[i]].central_offset, "duplicate complete archive filename");
    }
    return records;
}
struct Extended {
    uint64_t uncompressed, compressed, local;
    uint32_t disk;
    bool used = false;
};
Extended extended(const Bytes& bytes, uint64_t offset, uint64_t length, Extended values, bool local_zero_padding = false) {
    bytes.range(offset, length);
    const uint64_t end = offset+length;
    bool seen = false;
    const bool need_uncompressed = values.uncompressed == maximum32;
    const bool need_compressed = values.compressed == maximum32;
    const bool need_local = values.local == maximum32;
    const bool need_disk = values.disk == 65535;
    while (offset != end) {
        if (end-offset < 4) {
            // AOSP zipalign appends unstructured zero padding to the LFH extra field.
            const auto tail = bytes.string(offset, static_cast<size_t>(end-offset));
            if (local_zero_padding && std::all_of(tail.begin(), tail.end(), [](char value) { return value == 0; })) {
                offset = end;
                break;
            }
            throw Error(Status::corrupt_input, offset, "truncated ZIP extra field");
        }
        const auto kind = bytes.u16(offset), size = bytes.u16(offset+2);
        offset += 4;
        if (size > end-offset) throw Error(Status::corrupt_input, offset, "ZIP extra field exceeds header");
        if (kind == 1) {
            if (seen) throw Error(Status::corrupt_input, offset, "duplicate ZIP64 extra field");
            seen = true; values.used = true;
            uint64_t cursor = offset;
            auto next64 = [&]() {
                if (offset+size-cursor < 8) throw Error(Status::corrupt_input, cursor, "truncated ZIP64 field");
                const auto value = bytes.u64(cursor); cursor += 8; return value;
            };
            if (need_uncompressed) values.uncompressed = next64();
            if (need_compressed) values.compressed = next64();
            if (need_local) values.local = next64();
            if (need_disk) {
                if (offset+size-cursor < 4) throw Error(Status::corrupt_input, cursor, "truncated ZIP64 disk field");
                values.disk = bytes.u32(cursor);
            }
        }
        offset += size;
    }
    if ((need_uncompressed || need_compressed || need_local || need_disk) && !seen)
        throw Error(Status::corrupt_input, offset, "required ZIP64 extra field is missing");
    return values;
}
bool descriptor_matches(const Bytes& bytes, uint64_t at, uint64_t available, const mz_zip_archive_file_stat& stat, bool wide) {
    const uint64_t size = wide ? 20 : 12;
    if (available < size) return false;
    if (bytes.u32(at) != stat.m_crc32) return false;
    return wide ? bytes.u64(at+4) == stat.m_comp_size && bytes.u64(at+12) == stat.m_uncomp_size
                : bytes.u32(at+4) == stat.m_comp_size && bytes.u32(at+8) == stat.m_uncomp_size;
}
bool validate_headers(Context& context, const Directory& directory, const Record& record, const mz_zip_archive_file_stat& stat) {
    const Bytes bytes(context.input);
    const uint64_t central = record.central_offset;
    if (stat.m_central_dir_ofs != central-directory.offset || stat.m_file_index != record.index)
        throw Error(Status::internal_error, central, "backend entry identity disagrees with preflight");
    const uint16_t flags = bytes.u16(central+8), method = bytes.u16(central+10);
    if ((flags & ~(uint16_t{6} | uint16_t{8} | uint16_t{0x800})) != 0 || (method != 0 && method != 8))
        throw Error(Status::unsupported, central, "encrypted, patched or unsupported compression entry");
    const auto central_values = extended(bytes, central+46+record.name.size(), bytes.u16(central+30),
        {bytes.u32(central+24), bytes.u32(central+20), bytes.u32(central+42), bytes.u16(central+34)});
    if (central_values.disk != 0) throw Error(Status::unsupported, central, "entry belongs to another disk");
    if (central_values.uncompressed != stat.m_uncomp_size || central_values.compressed != stat.m_comp_size ||
        central_values.local != stat.m_local_header_ofs || flags != stat.m_bit_flag || method != stat.m_method)
        throw Error(Status::corrupt_input, central, "central metadata interpretation disagrees");
    const uint64_t local = stat.m_local_header_ofs;
    bytes.range(local, 30);
    if (local >= directory.offset || bytes.u32(local) != local_signature)
        throw Error(Status::corrupt_input, local, "invalid local header position/signature");
    const auto length = bytes.u16(local+26), extra_size = bytes.u16(local+28);
    const uint64_t header_size = uint64_t(30) + length + extra_size;
    bytes.range(local, header_size);
    if (header_size > directory.offset-local || bytes.u16(local+6) != flags || bytes.u16(local+8) != method ||
        length != record.name.size() || bytes.string(local+30, length) != record.name)
        throw Error(Status::corrupt_input, local, "local/central filename, flags or method disagree");
    const auto local_values = extended(bytes, local+30+length, extra_size,
        {bytes.u32(local+22), bytes.u32(local+18), 0, 0}, true);
    const bool with_descriptor = (flags & 8) != 0;
    const auto local_crc = bytes.u32(local+14);
    if ((!with_descriptor && (local_crc != stat.m_crc32 || local_values.compressed != stat.m_comp_size ||
                              local_values.uncompressed != stat.m_uncomp_size)) ||
        (with_descriptor && ((local_crc != 0 && local_crc != stat.m_crc32) ||
          (local_values.compressed != 0 && local_values.compressed != stat.m_comp_size) ||
          (local_values.uncompressed != 0 && local_values.uncompressed != stat.m_uncomp_size))))
        throw Error(Status::corrupt_input, local, "local/central CRC or sizes disagree");
    const uint64_t payload = local+header_size;
    if (stat.m_comp_size > directory.offset-payload)
        throw Error(Status::corrupt_input, payload, "entry payload overlaps central directory");
    const uint64_t payload_end = payload+stat.m_comp_size;
    const bool wide = central_values.used || local_values.used;
    if (with_descriptor) {
        const uint64_t at = payload_end;
        const uint64_t available = directory.offset-at;
        bool matches = descriptor_matches(bytes, at, available, stat, wide);
        if (!matches && available >= 4 && bytes.u32(at) == descriptor_signature)
            matches = descriptor_matches(bytes, at+4, available-4, stat, wide);
        if (!matches) throw Error(Status::corrupt_input, at, "data descriptor disagrees with central directory");
    }
    if (method == 0 && stat.m_comp_size != stat.m_uncomp_size)
        throw Error(Status::corrupt_input, payload, "stored entry has unequal sizes");
    context.checkpoint();
    return wide;
}
struct ArchiveOwner {
    mz_zip_archive value{};
    ~ArchiveOwner() { if (value.m_pState) mz_zip_reader_end(&value); }
};
struct IteratorOwner {
    mz_zip_reader_extract_iter_state* value = nullptr;
    ~IteratorOwner() { if (value) mz_zip_reader_extract_iter_free(value); }
};
}

std::pmr::vector<Entry> read(std::span<const uint8_t> input, const Limits& limits,
    std::pmr::memory_resource* memory, Cancel cancel, Selection selection) {
    if (!memory || limits.chunk_bytes == 0 || limits.chunk_bytes > 65536)
        throw Error(Status::internal_error, 0, "invalid archive memory resource or chunk configuration");
    Context context{input, memory, cancel};
    try {
        context.checkpoint();
        const auto directory = preflight(context, limits);
        auto records = names(context, directory, limits);
        ArchiveOwner owner;
        auto& zip = owner.value;
        zip.m_pAlloc = allocate; zip.m_pFree = deallocate; zip.m_pRealloc = reallocate;
        zip.m_pAlloc_opaque = &context; zip.m_pIO_opaque = &context; zip.m_pRead = read_callback;
        if (!mz_zip_reader_init(&zip, input.size(), MZ_ZIP_FLAG_DO_NOT_SORT_CENTRAL_DIRECTORY))
            context.library_error(zip);
        if (zip.m_total_files != directory.count || zip.m_central_directory_file_ofs != directory.offset)
            throw Error(Status::corrupt_input, directory.offset, "backend directory disagrees with bounded preflight");
        std::pmr::vector<Entry> result(memory);
        std::pmr::vector<uint8_t> chunk(memory);
        chunk.resize(limits.chunk_bytes);
        uint64_t total_output = 0;
        for (const auto& record : records) {
            context.checkpoint();
            mz_zip_archive_file_stat stat{};
            if (!mz_zip_reader_file_stat(&zip, record.index, &stat)) context.library_error(zip);
            const bool wide = validate_headers(context, directory, record, stat);
            const bool directory_name = !record.name.empty() && record.name.back() == '/';
            if (stat.m_is_directory && !directory_name)
                throw Error(Status::unsupported, record.central_offset, "directory without trailing slash is unsupported");
            if (directory_name) {
                if (stat.m_uncomp_size != 0) throw Error(Status::corrupt_input, record.central_offset, "directory carries file contents");
                continue;
            }
            if (selection.include && !selection.include(selection.context, record.name, record.index)) continue;
            if (stat.m_uncomp_size > limits.max_entry_output_bytes ||
                stat.m_uncomp_size > limits.max_total_output_bytes-total_output ||
                stat.m_uncomp_size > std::numeric_limits<size_t>::max())
                throw Error(Status::budget_exceeded, record.central_offset, "declared extraction output exceeds quota");
            Entry entry(memory);
            entry.index = record.index; entry.name = record.name;
            entry.crc32 = stat.m_crc32; entry.header_consistency_verified = true;
            entry.zip64 = directory.zip64 || wide;
            entry.bytes.reserve(static_cast<size_t>(stat.m_uncomp_size));
            IteratorOwner iterator{mz_zip_reader_extract_iter_new(&zip, record.index, 0)};
            if (!iterator.value) context.library_error(zip);
            for (;;) {
                context.checkpoint();
                const size_t count = mz_zip_reader_extract_iter_read(iterator.value, chunk.data(), chunk.size());
                if (context.failed) context.library_error(zip);
                if (count == 0) break;
                if (count > limits.max_entry_output_bytes-entry.bytes.size() ||
                    count > limits.max_total_output_bytes-total_output)
                    throw Error(Status::budget_exceeded, record.central_offset, "actual extraction output exceeds quota");
                if (entry.bytes.size() > stat.m_uncomp_size || count > stat.m_uncomp_size-entry.bytes.size())
                    throw Error(Status::corrupt_input, record.central_offset, "actual extraction exceeds declared size");
                entry.bytes.insert(entry.bytes.end(), chunk.begin(), chunk.begin()+count);
                total_output += count;
                context.checkpoint();
            }
            auto* final_iterator = std::exchange(iterator.value, nullptr);
            if (!mz_zip_reader_extract_iter_free(final_iterator)) context.library_error(zip);
            if (entry.bytes.size() != stat.m_uncomp_size)
                throw Error(Status::corrupt_input, record.central_offset, "extracted size differs from declared size");
            entry.crc_verified = true;
            result.push_back(std::move(entry));
        }
        context.checkpoint();
        if (!mz_zip_reader_end(&zip)) context.library_error(zip);
        if (context.failed) context.library_error(zip);
        return result;
    } catch (const std::bad_alloc&) {
        if (context.failed) throw Error(context.status, context.failure_offset, "archive resource callback failed");
        throw Error(Status::budget_exceeded, 0, "archive resource quota or allocation exhausted");
    } catch (const std::length_error&) {
        throw Error(Status::budget_exceeded, 0, "archive container capacity exceeded");
    }
}
}
