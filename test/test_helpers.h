// Small shared helpers for the host test suites. Placed in the test/ root so it
// is on the include path for every test program PlatformIO builds.
#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace ota_test {

// Parse a hex string into bytes.
inline std::vector<uint8_t> from_hex(const std::string &hex) {
  std::vector<uint8_t> out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    auto nyb = [](char c) -> int {
      if (c >= '0' && c <= '9')
        return c - '0';
      if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
      if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
      return 0;
    };
    out.push_back(static_cast<uint8_t>((nyb(hex[i]) << 4) | nyb(hex[i + 1])));
  }
  return out;
}

inline std::string to_hex(const uint8_t *data, size_t len) {
  static const char *d = "0123456789abcdef";
  std::string s;
  s.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    s.push_back(d[data[i] >> 4]);
    s.push_back(d[data[i] & 0xf]);
  }
  return s;
}

// A simple deterministic pseudo-random byte generator for building test images
// (no <random> dependency, reproducible across runs/platforms).
inline std::vector<uint8_t> prng_bytes(size_t n, uint32_t seed) {
  std::vector<uint8_t> v(n);
  uint32_t x = seed ? seed : 0x12345678u;
  for (size_t i = 0; i < n; ++i) {
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    v[i] = static_cast<uint8_t>(x >> 24);
  }
  return v;
}

} // namespace ota_test
