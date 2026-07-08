#include "ota_common/xeddsa.h"

#include <cstring>

extern "C" {
// Implemented in the vendored TweetNaCl unity TU (src/vendor_tweetnacl.c).
int ota_xeddsa_verify_raw(const unsigned char *curve_pub,
                          const unsigned char *msg, unsigned long msg_len,
                          const unsigned char *sig);
}

namespace ota_common {

static void put_le32(uint8_t *p, uint32_t v) {
  p[0] = static_cast<uint8_t>(v);
  p[1] = static_cast<uint8_t>(v >> 8);
  p[2] = static_cast<uint8_t>(v >> 16);
  p[3] = static_cast<uint8_t>(v >> 24);
}

bool xeddsa_verify(const uint8_t curve_pub[32], uint32_t from, uint32_t id,
                   uint32_t portnum, const uint8_t *payload, size_t payload_len,
                   const uint8_t sig[64]) {
  if (payload == nullptr || payload_len > kXeddsaMaxPayload)
    return false;

  // buildSigningBuffer: [from][id][portnum] little-endian, then the payload.
  uint8_t buf[12 + kXeddsaMaxPayload];
  put_le32(buf + 0, from);
  put_le32(buf + 4, id);
  put_le32(buf + 8, portnum);
  std::memcpy(buf + 12, payload, payload_len);

  return ota_xeddsa_verify_raw(curve_pub, buf,
                               static_cast<unsigned long>(12 + payload_len),
                               sig) == 1;
}

} // namespace ota_common
