#include <unity.h>

#include <cstring>
#include <vector>

#include "ota_common/esp_image.h"
#include "ota_common/trailer.h"
#include "test_helpers.h"

using namespace ota_common;

void setUp() {}
void tearDown() {}

// Build a structurally valid ESP application image with the given segment data
// lengths, matching esptool's layout: 24-byte header, [8-byte seg hdr + data]*,
// 1 checksum byte padded to a 16-byte boundary, optional 32-byte SHA-256.
static std::vector<uint8_t>
make_esp_image(const std::vector<uint32_t> &seg_lens, bool hash_appended) {
  std::vector<uint8_t> img(24, 0);
  img[0] = 0xE9;                                  // magic
  img[1] = static_cast<uint8_t>(seg_lens.size()); // segment_count
  img[23] = hash_appended ? 1 : 0;                // hash_appended flag

  for (uint32_t dl : seg_lens) {
    uint8_t seg[8];
    std::memset(seg, 0, 8);
    // load_addr [0..4) left 0; data_len [4..8)
    seg[4] = static_cast<uint8_t>(dl & 0xff);
    seg[5] = static_cast<uint8_t>((dl >> 8) & 0xff);
    seg[6] = static_cast<uint8_t>((dl >> 16) & 0xff);
    seg[7] = static_cast<uint8_t>((dl >> 24) & 0xff);
    img.insert(img.end(), seg, seg + 8);
    auto data = ota_test::prng_bytes(dl, 0x2000 + dl);
    img.insert(img.end(), data.begin(), data.end());
  }

  // checksum byte, padded so total is a multiple of 16
  size_t pad = 15 - (img.size() % 16);
  img.insert(img.end(), pad, 0x00);
  img.push_back(0xEF); // checksum byte (value irrelevant to length parsing)

  if (hash_appended)
    img.insert(img.end(), 32, 0xAB);
  return img;
}

static void test_buffer_reader_bounds() {
  std::vector<uint8_t> data = {1, 2, 3, 4, 5};
  BufferImageReader r(data.data(), data.size());
  uint8_t buf[3];
  TEST_ASSERT_TRUE(r.read(0, buf, 3));
  TEST_ASSERT_TRUE(r.read(2, buf, 3));
  TEST_ASSERT_FALSE(r.read(3, buf, 3)); // would read past end
  TEST_ASSERT_FALSE(r.read(6, buf, 1)); // offset past end
}

static void test_image_length_no_hash() {
  auto img = make_esp_image({100, 200, 50}, /*hash_appended=*/false);
  BufferImageReader r(img.data(), img.size());
  uint32_t len = 0;
  TEST_ASSERT_TRUE(esp_image_length(r, len));
  TEST_ASSERT_EQUAL_UINT32(img.size(), len);
  TEST_ASSERT_EQUAL_UINT32(0, len % 16); // ends on a 16-byte boundary
}

static void test_image_length_with_hash() {
  auto img = make_esp_image({4096, 1234}, /*hash_appended=*/true);
  BufferImageReader r(img.data(), img.size());
  uint32_t len = 0;
  TEST_ASSERT_TRUE(esp_image_length(r, len));
  TEST_ASSERT_EQUAL_UINT32(img.size(), len);
}

static void test_bad_magic() {
  auto img = make_esp_image({100}, false);
  img[0] = 0x00;
  BufferImageReader r(img.data(), img.size());
  uint32_t len = 0;
  TEST_ASSERT_FALSE(esp_image_length(r, len));
}

// The whole point: locate an appended trailer in a partition-sized buffer.
static void test_locate_trailer_after_image() {
  auto img = make_esp_image({2048, 512}, true);
  uint32_t image_len = static_cast<uint32_t>(img.size());

  OtaTrailer t;
  std::memset(&t, 0, sizeof(t));
  std::strncpy(t.env, "heltec-v3", kEnvLen);
  std::strncpy(t.version, "2.8.0.54e0d8d", kVersionLen);
  std::strncpy(t.commit, "54e0d8d", kCommitLen);
  t.image_length = image_len;
  trailer_finalize(t);

  // Append the trailer, then pad out to a larger "partition" of 0xFF.
  std::vector<uint8_t> partition = img;
  const uint8_t *tb = reinterpret_cast<const uint8_t *>(&t);
  partition.insert(partition.end(), tb, tb + sizeof(OtaTrailer));
  partition.resize(partition.size() + 4096, 0xFF);

  BufferImageReader r(partition.data(), partition.size());
  uint32_t parsed_len = 0;
  TEST_ASSERT_TRUE(esp_image_length(r, parsed_len));
  TEST_ASSERT_EQUAL_UINT32(image_len, parsed_len);

  OtaTrailer got;
  TEST_ASSERT_TRUE(
      r.read(parsed_len, reinterpret_cast<uint8_t *>(&got), sizeof(got)));
  TEST_ASSERT_TRUE(trailer_is_valid(got));
  TEST_ASSERT_EQUAL_STRING("heltec-v3", got.env);
  TEST_ASSERT_EQUAL_STRING("2.8.0.54e0d8d", got.version);
}

int main() {
  UNITY_BEGIN();
  RUN_TEST(test_buffer_reader_bounds);
  RUN_TEST(test_image_length_no_hash);
  RUN_TEST(test_image_length_with_hash);
  RUN_TEST(test_bad_magic);
  RUN_TEST(test_locate_trailer_after_image);
  return UNITY_END();
}
