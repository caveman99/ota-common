#include "ota_common/trailer.h"

#include <cstring>

namespace ota_common {

uint32_t crc32_ieee(const uint8_t *data, size_t len) {
  uint32_t crc = 0xFFFFFFFFu;
  for (size_t i = 0; i < len; ++i) {
    crc ^= data[i];
    for (int b = 0; b < 8; ++b) {
      uint32_t mask = -(crc & 1u);
      crc = (crc >> 1) ^ (0xEDB88320u & mask);
    }
  }
  return crc ^ 0xFFFFFFFFu;
}

void trailer_finalize(OtaTrailer &t) {
  t.magic = kTrailerMagic;
  t.format = kTrailerFormat;
  const auto *bytes = reinterpret_cast<const uint8_t *>(&t);
  t.crc32 = crc32_ieee(bytes, sizeof(OtaTrailer) - sizeof(uint32_t));
}

bool trailer_is_valid(const OtaTrailer &t) {
  if (t.magic != kTrailerMagic)
    return false;
  if (t.format != kTrailerFormat)
    return false;
  const auto *bytes = reinterpret_cast<const uint8_t *>(&t);
  const uint32_t expect =
      crc32_ieee(bytes, sizeof(OtaTrailer) - sizeof(uint32_t));
  return expect == t.crc32;
}

bool trailer_from_image_tail(const uint8_t *image, size_t image_len,
                             OtaTrailer &out) {
  if (image == nullptr || image_len < sizeof(OtaTrailer))
    return false;
  std::memcpy(&out, image + image_len - sizeof(OtaTrailer), sizeof(OtaTrailer));
  return trailer_is_valid(out);
}

// Compare a fixed-width char field up to its first NUL within [0, N).
static bool field_equal(const char *a, const char *b, size_t n) {
  return std::strncmp(a, b, n) == 0;
}

bool trailer_identity_equal(const OtaTrailer &a, const OtaTrailer &b) {
  return field_equal(a.env, b.env, kEnvLen) &&
         field_equal(a.version, b.version, kVersionLen) &&
         field_equal(a.commit, b.commit, kCommitLen);
}

} // namespace ota_common
