#include <unity.h>

#include <cstring>
#include <vector>

#include "ota_common/merkle.h"
#include "ota_common/package.h"
#include "ota_common/trailer.h"
#include "test_helpers.h"

using namespace ota_common;

void setUp() {}
void tearDown() {}

// Verifier that accepts a fixed signature value -- stands in for Ed25519.
struct FakeVerifier : ISignatureVerifier {
    std::vector<uint8_t> good;
    bool verify(const uint8_t*, size_t, const uint8_t* sig, size_t sig_len) const override {
        return sig_len == good.size() && std::memcmp(sig, good.data(), sig_len) == 0;
    }
};

struct BuiltPackage {
    std::vector<uint8_t> bytes;
    Manifest manifest;
    std::vector<uint8_t> signature;
    std::vector<uint8_t> payload;
};

static Manifest make_manifest(const std::vector<uint8_t>& payload, uint32_t block_size,
                              const char* env, const char* ver, const char* commit) {
    Manifest m;
    std::memset(&m, 0, sizeof(m));
    m.magic = kManifestMagic;
    m.format = kManifestFormat;
    m.flags = kManifestFlagDelta;
    std::strncpy(m.env, env, kMEnvLen);
    std::strncpy(m.base_version, ver, kMVersionLen);
    std::strncpy(m.base_commit, commit, kMCommitLen);
    m.block_size = block_size;
    m.payload_length = static_cast<uint32_t>(payload.size());
    m.block_count = static_cast<uint32_t>((payload.size() + block_size - 1) / block_size);

    // Merkle root over payload blocks.
    std::vector<Hash256> leaves;
    for (size_t off = 0; off < payload.size(); off += block_size) {
        size_t n = (off + block_size <= payload.size()) ? block_size : payload.size() - off;
        leaves.push_back(hash_leaf(payload.data() + off, n));
    }
    Hash256 root = merkle_root(leaves);
    std::memcpy(m.payload_merkle_root, root.bytes, kSha256Len);

    m.output_length = static_cast<uint32_t>(payload.size());
    Sha256::hash(payload.data(), payload.size(), m.output_sha256);
    return m;
}

static BuiltPackage build_package(const Manifest& m, const std::vector<uint8_t>& payload,
                                  const std::vector<uint8_t>& sig) {
    BuiltPackage p;
    p.manifest = m;
    p.signature = sig;
    p.payload = payload;

    PackageHeader hdr;
    hdr.magic = kPackageMagic;
    hdr.format = kPackageFormat;
    hdr.flags = 0;
    hdr.manifest_length = sizeof(Manifest);
    hdr.signature_length = static_cast<uint32_t>(sig.size());

    auto append = [&](const void* d, size_t n) {
        const auto* b = reinterpret_cast<const uint8_t*>(d);
        p.bytes.insert(p.bytes.end(), b, b + n);
    };
    append(&hdr, sizeof(hdr));
    append(&m, sizeof(m));
    append(sig.data(), sig.size());
    append(payload.data(), payload.size());
    return p;
}

static void test_layout_sizes() {
    TEST_ASSERT_EQUAL_UINT32(16, sizeof(PackageHeader));
    TEST_ASSERT_EQUAL_UINT32(192, sizeof(Manifest));
}

static void test_parse_ok() {
    auto payload = ota_test::prng_bytes(3000, 0x55);
    auto sig = std::vector<uint8_t>(kEd25519SigLen, 0x7);
    Manifest m = make_manifest(payload, 1024, "heltec-v3", "2.8.0.54e0d8d", "54e0d8d");
    auto pkg = build_package(m, payload, sig);

    ParsedPackage parsed;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(PackageError::Ok),
                          static_cast<int>(package_parse(pkg.bytes.data(), pkg.bytes.size(), parsed)));
    TEST_ASSERT_EQUAL_UINT32(payload.size(), parsed.payload_len);
    TEST_ASSERT_EQUAL_UINT32(kEd25519SigLen, parsed.signature_len);
    TEST_ASSERT_TRUE(manifest_is_delta(*parsed.manifest));
    TEST_ASSERT_EQUAL_MEMORY(payload.data(), parsed.payload, payload.size());
}

static void test_parse_too_small() {
    std::vector<uint8_t> tiny(8, 0);
    ParsedPackage parsed;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(PackageError::TooSmall),
                          static_cast<int>(package_parse(tiny.data(), tiny.size(), parsed)));
}

static void test_parse_bad_magic() {
    auto payload = ota_test::prng_bytes(100, 1);
    auto sig = std::vector<uint8_t>(kEd25519SigLen, 0);
    auto pkg = build_package(make_manifest(payload, 64, "e", "v", "c"), payload, sig);
    reinterpret_cast<PackageHeader*>(pkg.bytes.data())->magic = 0xDEADBEEF;
    ParsedPackage parsed;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(PackageError::BadMagic),
                          static_cast<int>(package_parse(pkg.bytes.data(), pkg.bytes.size(), parsed)));
}

static void test_parse_payload_length_mismatch() {
    auto payload = ota_test::prng_bytes(500, 2);
    auto sig = std::vector<uint8_t>(kEd25519SigLen, 0);
    auto pkg = build_package(make_manifest(payload, 256, "e", "v", "c"), payload, sig);
    // Truncate one payload byte -> manifest.payload_length no longer matches.
    pkg.bytes.pop_back();
    ParsedPackage parsed;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(PackageError::LengthMismatch),
                          static_cast<int>(package_parse(pkg.bytes.data(), pkg.bytes.size(), parsed)));
}

static void test_parse_truncated_signature() {
    auto payload = ota_test::prng_bytes(100, 3);
    auto sig = std::vector<uint8_t>(kEd25519SigLen, 0);
    auto pkg = build_package(make_manifest(payload, 64, "e", "v", "c"), payload, sig);
    // Cut into the signature region.
    pkg.bytes.resize(sizeof(PackageHeader) + sizeof(Manifest) + 10);
    ParsedPackage parsed;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(PackageError::LengthMismatch),
                          static_cast<int>(package_parse(pkg.bytes.data(), pkg.bytes.size(), parsed)));
}

static void test_signature_verify() {
    auto payload = ota_test::prng_bytes(1000, 4);
    auto good = std::vector<uint8_t>(kEd25519SigLen, 0xAB);
    auto pkg = build_package(make_manifest(payload, 512, "e", "v", "c"), payload, good);
    ParsedPackage parsed;
    package_parse(pkg.bytes.data(), pkg.bytes.size(), parsed);

    FakeVerifier ok;
    ok.good = good;
    TEST_ASSERT_TRUE(package_verify_signature(parsed, ok));

    FakeVerifier bad;
    bad.good = std::vector<uint8_t>(kEd25519SigLen, 0xCD);
    TEST_ASSERT_FALSE(package_verify_signature(parsed, bad));
}

static void test_identity_gate() {
    auto payload = ota_test::prng_bytes(100, 5);
    auto sig = std::vector<uint8_t>(kEd25519SigLen, 0);
    Manifest m = make_manifest(payload, 64, "heltec-v3", "2.8.0.54e0d8d", "54e0d8d");

    OtaTrailer running;
    std::memset(&running, 0, sizeof(running));
    std::strncpy(running.env, "heltec-v3", kEnvLen);
    std::strncpy(running.version, "2.8.0.54e0d8d", kVersionLen);
    std::strncpy(running.commit, "54e0d8d", kCommitLen);
    trailer_finalize(running);
    TEST_ASSERT_TRUE(package_identity_matches(m, running));

    OtaTrailer other = running;
    std::strncpy(other.version, "2.8.0.deadbee", kVersionLen);
    trailer_finalize(other);
    TEST_ASSERT_FALSE(package_identity_matches(m, other));
}

// End-to-end: parse, verify signature, gate identity, then verify every payload
// block against the manifest's merkle root (the receive-time path).
static void test_end_to_end_block_verify() {
    const uint32_t bs = 1024;
    auto payload = ota_test::prng_bytes(4096 + 200, 0x99);
    auto sig = std::vector<uint8_t>(kEd25519SigLen, 0x11);
    Manifest m = make_manifest(payload, bs, "tbeam", "2.8.0.54e0d8d", "54e0d8d");
    auto pkg = build_package(m, payload, sig);

    ParsedPackage parsed;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(PackageError::Ok),
                          static_cast<int>(package_parse(pkg.bytes.data(), pkg.bytes.size(), parsed)));

    // Rebuild leaves to generate proofs (the seeder side would ship these).
    std::vector<Hash256> leaves;
    for (uint32_t off = 0; off < parsed.payload_len; off += bs) {
        uint32_t n = (off + bs <= parsed.payload_len) ? bs : parsed.payload_len - off;
        leaves.push_back(hash_leaf(parsed.payload + off, n));
    }
    Hash256 root;
    std::memcpy(root.bytes, parsed.manifest->payload_merkle_root, kSha256Len);

    const uint32_t count = parsed.manifest->block_count;
    TEST_ASSERT_EQUAL_UINT32(leaves.size(), count);
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t off = i * bs;
        uint32_t n = (off + bs <= parsed.payload_len) ? bs : parsed.payload_len - off;
        auto proof = merkle_proof(leaves, i);
        TEST_ASSERT_TRUE(merkle_verify_block(parsed.payload + off, n, i, count, proof, root));
    }
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_layout_sizes);
    RUN_TEST(test_parse_ok);
    RUN_TEST(test_parse_too_small);
    RUN_TEST(test_parse_bad_magic);
    RUN_TEST(test_parse_payload_length_mismatch);
    RUN_TEST(test_parse_truncated_signature);
    RUN_TEST(test_signature_verify);
    RUN_TEST(test_identity_gate);
    RUN_TEST(test_end_to_end_block_verify);
    return UNITY_END();
}
