#include "ota_common/esp_image.h"

#include <cstring>

namespace ota_common {

bool BufferImageReader::read(size_t offset, uint8_t *dst, size_t n) const {
  if (offset > len_ || n > len_ - offset)
    return false;
  std::memcpy(dst, data_ + offset, n);
  return true;
}

namespace {
constexpr uint8_t kEspImageMagic = 0xE9;
constexpr size_t kHeaderLen = 24;
constexpr size_t kSegHeaderLen = 8;
constexpr size_t kShaLen = 32;
constexpr size_t kSegmentCountOff = 1;
constexpr size_t kHashAppendedOff = 23; // last byte of the 24-byte header

uint32_t le32(const uint8_t *p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) |
         (static_cast<uint32_t>(p[3]) << 24);
}
} // namespace

bool esp_image_length(const IImageReader &reader, uint32_t &out_len) {
  uint8_t header[kHeaderLen];
  if (!reader.read(0, header, kHeaderLen))
    return false;
  if (header[0] != kEspImageMagic)
    return false;

  const uint8_t segment_count = header[kSegmentCountOff];
  const bool hash_appended = header[kHashAppendedOff] != 0;

  size_t len = kHeaderLen;
  for (uint8_t i = 0; i < segment_count; ++i) {
    uint8_t seg[kSegHeaderLen];
    if (!reader.read(len, seg, kSegHeaderLen))
      return false;
    const uint32_t data_len = le32(seg + 4); // [load_addr][data_len]
    len += kSegHeaderLen + data_len;
  }

  // One checksum byte, padded so the total is a multiple of 16.
  len += 15 - (len % 16);
  len += 1;
  if (hash_appended)
    len += kShaLen;

  out_len = static_cast<uint32_t>(len);
  return true;
}

} // namespace ota_common
