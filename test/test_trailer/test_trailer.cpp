#include <unity.h>

#include <cstring>
#include <vector>

#include "ota_common/trailer.h"
#include "test_helpers.h"

using namespace ota_common;

void setUp() {}
void tearDown() {}

static OtaTrailer make_trailer(const char* env, const char* version, const char* commit) {
    OtaTrailer t;
    std::memset(&t, 0, sizeof(t));
    std::strncpy(t.env, env, kEnvLen);
    std::strncpy(t.version, version, kVersionLen);
    std::strncpy(t.commit, commit, kCommitLen);
    std::strncpy(t.repo, "meshtastic/firmware", kRepoLen);
    t.hw_vendor = 9;
    t.image_length = 0x1000;
    trailer_finalize(t);
    return t;
}

static void test_layout_size() {
    TEST_ASSERT_EQUAL_UINT32(172, sizeof(OtaTrailer));
}

// Pin the CRC-32 to the canonical "123456789" check value so the C++ and
// Python (zlib.crc32) implementations are guaranteed to agree byte-for-byte.
static void test_crc32_known_vector() {
    const char* s = "123456789";
    TEST_ASSERT_EQUAL_HEX32(0xCBF43926u,
                            crc32_ieee(reinterpret_cast<const uint8_t*>(s), 9));
}

static void test_finalize_valid() {
    OtaTrailer t = make_trailer("heltec-v3", "2.8.0.54e0d8d", "54e0d8d");
    TEST_ASSERT_TRUE(trailer_is_valid(t));
    TEST_ASSERT_EQUAL_UINT32(kTrailerMagic, t.magic);
    TEST_ASSERT_EQUAL_UINT16(kTrailerFormat, t.format);
}

static void test_bad_magic() {
    OtaTrailer t = make_trailer("heltec-v3", "2.8.0.54e0d8d", "54e0d8d");
    t.magic = 0xDEADBEEF;
    TEST_ASSERT_FALSE(trailer_is_valid(t));
}

static void test_bad_format() {
    OtaTrailer t = make_trailer("heltec-v3", "2.8.0.54e0d8d", "54e0d8d");
    t.format = 99;
    TEST_ASSERT_FALSE(trailer_is_valid(t));
}

// Any tampered field must break the CRC.
static void test_crc_detects_tamper() {
    OtaTrailer t = make_trailer("heltec-v3", "2.8.0.54e0d8d", "54e0d8d");
    auto* bytes = reinterpret_cast<uint8_t*>(&t);
    for (size_t i = 8; i < sizeof(OtaTrailer) - sizeof(uint32_t); i += 17) {
        OtaTrailer copy = t;
        reinterpret_cast<uint8_t*>(&copy)[i] ^= 0x01;
        TEST_ASSERT_FALSE(trailer_is_valid(copy));
    }
    (void)bytes;
}

static void test_from_image_tail() {
    OtaTrailer t = make_trailer("tbeam", "2.8.0.abc1234", "abc1234");
    std::vector<uint8_t> image(4096 + sizeof(OtaTrailer), 0xAA);
    std::memcpy(image.data() + 4096, &t, sizeof(OtaTrailer));

    OtaTrailer got;
    TEST_ASSERT_TRUE(trailer_from_image_tail(image.data(), image.size(), got));
    TEST_ASSERT_EQUAL_STRING("tbeam", got.env);
    TEST_ASSERT_EQUAL_STRING("2.8.0.abc1234", got.version);
}

static void test_from_image_tail_too_small() {
    OtaTrailer got;
    std::vector<uint8_t> tiny(10, 0);
    TEST_ASSERT_FALSE(trailer_from_image_tail(tiny.data(), tiny.size(), got));
    TEST_ASSERT_FALSE(trailer_from_image_tail(nullptr, 0, got));
}

static void test_from_image_tail_corrupt() {
    OtaTrailer t = make_trailer("tbeam", "2.8.0.abc1234", "abc1234");
    std::vector<uint8_t> image(2048 + sizeof(OtaTrailer), 0);
    std::memcpy(image.data() + 2048, &t, sizeof(OtaTrailer));
    image.back() ^= 0xFF; // corrupt crc region
    OtaTrailer got;
    TEST_ASSERT_FALSE(trailer_from_image_tail(image.data(), image.size(), got));
}

static void test_identity_equal() {
    OtaTrailer a = make_trailer("heltec-v3", "2.8.0.54e0d8d", "54e0d8d");
    OtaTrailer b = make_trailer("heltec-v3", "2.8.0.54e0d8d", "54e0d8d");
    TEST_ASSERT_TRUE(trailer_identity_equal(a, b));
}

static void test_identity_differs() {
    OtaTrailer base = make_trailer("heltec-v3", "2.8.0.54e0d8d", "54e0d8d");
    TEST_ASSERT_FALSE(trailer_identity_equal(
        base, make_trailer("tbeam", "2.8.0.54e0d8d", "54e0d8d")));      // env
    TEST_ASSERT_FALSE(trailer_identity_equal(
        base, make_trailer("heltec-v3", "2.8.0.99999999", "54e0d8d"))); // version
    TEST_ASSERT_FALSE(trailer_identity_equal(
        base, make_trailer("heltec-v3", "2.8.0.54e0d8d", "0000000")));  // commit
}

// repo and hw_vendor are informational, not part of the identity gate.
static void test_identity_ignores_repo_vendor() {
    OtaTrailer a = make_trailer("heltec-v3", "2.8.0.54e0d8d", "54e0d8d");
    OtaTrailer b = make_trailer("heltec-v3", "2.8.0.54e0d8d", "54e0d8d");
    std::strncpy(b.repo, "fork/firmware", kRepoLen);
    b.hw_vendor = 42;
    trailer_finalize(b);
    TEST_ASSERT_TRUE(trailer_identity_equal(a, b));
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_layout_size);
    RUN_TEST(test_crc32_known_vector);
    RUN_TEST(test_finalize_valid);
    RUN_TEST(test_bad_magic);
    RUN_TEST(test_bad_format);
    RUN_TEST(test_crc_detects_tamper);
    RUN_TEST(test_from_image_tail);
    RUN_TEST(test_from_image_tail_too_small);
    RUN_TEST(test_from_image_tail_corrupt);
    RUN_TEST(test_identity_equal);
    RUN_TEST(test_identity_differs);
    RUN_TEST(test_identity_ignores_repo_vendor);
    return UNITY_END();
}
