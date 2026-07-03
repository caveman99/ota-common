// Cross-language conformance: parse the packages and trailered images produced
// by the Python packager (tools/gen_fixtures.py) and confirm the C++ side reads
// every field identically. This is what guarantees the two implementations of
// the binary format stay in lockstep. Signature verification is exercised on
// the Python side (and on-device via mbedtls); here we validate structure,
// identity, the payload merkle root, and the full-image output hash.

#include <unity.h>

#include <cstdio>
#include <string>
#include <vector>

#include "ota_common/merkle.h"
#include "ota_common/package.h"
#include "ota_common/sha256.h"
#include "ota_common/trailer.h"

using namespace ota_common;

#ifndef OTA_FIXTURES_DIR
#define OTA_FIXTURES_DIR "test/fixtures"
#endif

void setUp() {}
void tearDown() {}

static std::vector<uint8_t> read_fixture(const char* name) {
    std::string path = std::string(OTA_FIXTURES_DIR) + "/" + name;
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) {
        // Fall back to a project-relative path if the absolute macro is unset.
        path = std::string("test/fixtures/") + name;
        f = std::fopen(path.c_str(), "rb");
    }
    TEST_ASSERT_NOT_NULL_MESSAGE(f, name);
    std::fseek(f, 0, SEEK_END);
    long n = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> buf(static_cast<size_t>(n));
    size_t got = std::fread(buf.data(), 1, buf.size(), f);
    std::fclose(f);
    TEST_ASSERT_EQUAL_UINT32(buf.size(), got);
    return buf;
}

static Hash256 root_over_payload(const ParsedPackage& pkg) {
    std::vector<Hash256> leaves;
    const uint32_t bs = pkg.manifest->block_size;
    for (uint32_t off = 0; off < pkg.payload_len; off += bs) {
        uint32_t n = (off + bs <= pkg.payload_len) ? bs : pkg.payload_len - static_cast<uint32_t>(off);
        leaves.push_back(hash_leaf(pkg.payload + off, n));
    }
    return merkle_root(leaves);
}

static void test_full_package() {
    auto buf = read_fixture("full_package.bin");
    ParsedPackage pkg;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(PackageError::Ok),
                          static_cast<int>(package_parse(buf.data(), buf.size(), pkg)));
    TEST_ASSERT_FALSE(manifest_is_delta(*pkg.manifest));
    TEST_ASSERT_EQUAL_STRING("heltec-v3", pkg.manifest->env);
    TEST_ASSERT_EQUAL_STRING("2.8.0.54e0d8d", pkg.manifest->base_version);
    TEST_ASSERT_EQUAL_STRING("54e0d8d", pkg.manifest->base_commit);

    // Full image: payload IS the output.
    TEST_ASSERT_EQUAL_UINT32(pkg.manifest->output_length, pkg.payload_len);

    // Merkle root recomputed in C++ must match the Python-written root.
    Hash256 root = root_over_payload(pkg);
    TEST_ASSERT_EQUAL_MEMORY(pkg.manifest->payload_merkle_root, root.bytes, kSha256Len);

    // Hard output gate: sha256(payload) == manifest output hash.
    uint8_t h[kSha256Len];
    Sha256::hash(pkg.payload, pkg.payload_len, h);
    TEST_ASSERT_EQUAL_MEMORY(pkg.manifest->output_sha256, h, kSha256Len);
}

static void test_delta_package() {
    auto buf = read_fixture("delta_package.bin");
    ParsedPackage pkg;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(PackageError::Ok),
                          static_cast<int>(package_parse(buf.data(), buf.size(), pkg)));
    TEST_ASSERT_TRUE(manifest_is_delta(*pkg.manifest));
    // Identity was lifted from the base image trailer by the packager.
    TEST_ASSERT_EQUAL_STRING("heltec-v3", pkg.manifest->env);
    TEST_ASSERT_EQUAL_STRING("2.8.0.54e0d8d", pkg.manifest->base_version);
    TEST_ASSERT_EQUAL_STRING("54e0d8d", pkg.manifest->base_commit);
    TEST_ASSERT_TRUE(pkg.manifest->output_length > 0);
    TEST_ASSERT_TRUE(pkg.payload_len < pkg.manifest->output_length); // delta < image

    Hash256 root = root_over_payload(pkg);
    TEST_ASSERT_EQUAL_MEMORY(pkg.manifest->payload_merkle_root, root.bytes, kSha256Len);
}

// The delta's expected base must match the base image's trailer (the soft gate
// would pass on the right device, fail on the wrong one).
static void test_identity_gate_against_base_trailer() {
    auto base = read_fixture("base_image.bin");
    OtaTrailer base_tr;
    TEST_ASSERT_TRUE(trailer_from_image_tail(base.data(), base.size(), base_tr));

    auto buf = read_fixture("delta_package.bin");
    ParsedPackage pkg;
    package_parse(buf.data(), buf.size(), pkg);
    TEST_ASSERT_TRUE(package_identity_matches(*pkg.manifest, base_tr));

    // The target trailer is a different build -> the delta must NOT match it.
    auto target = read_fixture("target_image.bin");
    OtaTrailer target_tr;
    TEST_ASSERT_TRUE(trailer_from_image_tail(target.data(), target.size(), target_tr));
    TEST_ASSERT_FALSE(package_identity_matches(*pkg.manifest, target_tr));
}

static void test_base_and_target_trailers() {
    auto base = read_fixture("base_image.bin");
    OtaTrailer t;
    TEST_ASSERT_TRUE(trailer_from_image_tail(base.data(), base.size(), t));
    TEST_ASSERT_EQUAL_STRING("heltec-v3", t.env);
    TEST_ASSERT_EQUAL_STRING("2.8.0.54e0d8d", t.version);
    TEST_ASSERT_EQUAL_STRING("54e0d8d", t.commit);
    TEST_ASSERT_EQUAL_STRING("meshtastic/firmware", t.repo);
    TEST_ASSERT_EQUAL_UINT32(9, t.hw_vendor);

    auto target = read_fixture("target_image.bin");
    OtaTrailer tt;
    TEST_ASSERT_TRUE(trailer_from_image_tail(target.data(), target.size(), tt));
    TEST_ASSERT_EQUAL_STRING("2.8.0.deadbee", tt.version);
    TEST_ASSERT_EQUAL_STRING("deadbee", tt.commit);
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_full_package);
    RUN_TEST(test_delta_package);
    RUN_TEST(test_identity_gate_against_base_trailer);
    RUN_TEST(test_base_and_target_trailers);
    return UNITY_END();
}
