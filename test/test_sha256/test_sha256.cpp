#include <unity.h>

#include <string>
#include <vector>

#include "ota_common/sha256.h"
#include "test_helpers.h"

using namespace ota_common;
using ota_test::from_hex;
using ota_test::to_hex;

void setUp() {}
void tearDown() {}

static std::string hash_str(const std::string& msg) {
    uint8_t out[kSha256Len];
    Sha256::hash(reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), out);
    return to_hex(out, kSha256Len);
}

static void test_empty() {
    TEST_ASSERT_EQUAL_STRING(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        hash_str("").c_str());
}

static void test_abc() {
    TEST_ASSERT_EQUAL_STRING(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        hash_str("abc").c_str());
}

static void test_448bit() {
    TEST_ASSERT_EQUAL_STRING(
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        hash_str("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").c_str());
}

// Crosses the 64-byte block boundary and the length-padding edge cases.
static void test_million_a() {
    Sha256 h;
    const std::vector<uint8_t> chunk(1000, 'a');
    for (int i = 0; i < 1000; ++i) h.update(chunk.data(), chunk.size());
    uint8_t out[kSha256Len];
    h.finish(out);
    TEST_ASSERT_EQUAL_STRING(
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        to_hex(out, kSha256Len).c_str());
}

// Incremental update in arbitrary chunk sizes must equal the one-shot hash.
static void test_incremental_equiv() {
    const std::vector<uint8_t> data = ota_test::prng_bytes(5000, 0xABCDEF01);
    uint8_t one_shot[kSha256Len];
    Sha256::hash(data.data(), data.size(), one_shot);

    for (size_t chunk : {1u, 3u, 31u, 32u, 33u, 64u, 65u, 127u, 200u}) {
        Sha256 h;
        for (size_t i = 0; i < data.size(); i += chunk) {
            size_t n = (i + chunk <= data.size()) ? chunk : data.size() - i;
            h.update(data.data() + i, n);
        }
        uint8_t got[kSha256Len];
        h.finish(got);
        TEST_ASSERT_EQUAL_MEMORY(one_shot, got, kSha256Len);
    }
}

// finish() exactly at the padding boundary (55, 56, 57 byte messages).
static void test_boundary_lengths() {
    for (size_t n = 50; n <= 70; ++n) {
        std::vector<uint8_t> msg(n, static_cast<uint8_t>(n));
        uint8_t a[kSha256Len], b[kSha256Len];
        Sha256::hash(msg.data(), n, a);
        Sha256 h;
        h.update(msg.data(), n);
        h.finish(b);
        TEST_ASSERT_EQUAL_MEMORY(a, b, kSha256Len);
    }
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_empty);
    RUN_TEST(test_abc);
    RUN_TEST(test_448bit);
    RUN_TEST(test_million_a);
    RUN_TEST(test_incremental_equiv);
    RUN_TEST(test_boundary_lengths);
    return UNITY_END();
}
