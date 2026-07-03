// Minimal, framework-agnostic parser for the length of an ESP-IDF application
// image. Used to locate the self-identity trailer when the image sits in a
// partition larger than itself (the on-flash path). Depends only on the public
// ESP image binary layout, not on any ESP-IDF header.
#pragma once

#include <cstddef>
#include <cstdint>

namespace ota_common {

// Random-access byte reader over an image (a partition, a file, a buffer).
struct IImageReader {
    virtual ~IImageReader() = default;
    // Read n bytes at offset into dst. Returns false on out-of-range or error.
    virtual bool read(size_t offset, uint8_t* dst, size_t n) const = 0;
};

// Reader over a contiguous in-memory buffer (host tests, mmap'd flash).
class BufferImageReader final : public IImageReader {
public:
    BufferImageReader(const uint8_t* data, size_t len) : data_(data), len_(len) {}
    bool read(size_t offset, uint8_t* dst, size_t n) const override;

private:
    const uint8_t* data_;
    size_t len_;
};

// Compute the byte length of the ESP application image at the start of the
// reader. Accounts for the 24-byte header, each segment, the checksum byte
// (16-byte aligned), and the optional appended SHA-256. Returns false if the
// magic byte is wrong or a read fails. On success out_len is the offset at
// which an appended trailer begins.
bool esp_image_length(const IImageReader& reader, uint32_t& out_len);

} // namespace ota_common
