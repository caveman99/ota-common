// Cross-language XEdDSA: verify a signature the Python `xeddsa` package
// produced (an independent Signal-XEdDSA implementation) with the vendored
// ota-common verifier. This proves the ota-common verify matches the scheme the
// admin device / firmware use, and closes the loop with
// tools/gen_xeddsa_fixtures.py.

#include <unity.h>

#include <cstdio>
#include <string>
#include <vector>

#include "ota_common/admin_key_verifier.h"
#include "ota_common/package.h"
#include "ota_common/xeddsa.h"

using namespace ota_common;

#ifndef OTA_FIXTURES_DIR
#define OTA_FIXTURES_DIR "test/fixtures"
#endif

void setUp() {}
void tearDown() {}

static std::vector<uint8_t> read_fixture(const char *name) {
  std::string path = std::string(OTA_FIXTURES_DIR) + "/" + name;
  std::FILE *f = std::fopen(path.c_str(), "rb");
  if (!f) {
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

// The Python-produced XEdDSA signature verifies with the ota-common verifier,
// under the fleet-wide OTA convention (from=0, id=0, portnum=79).
static void test_xeddsa_interop_ok() {
  auto pub = read_fixture("xeddsa_admin_pub.bin");
  auto payload = read_fixture("xeddsa_payload.bin");
  auto sig = read_fixture("xeddsa_sig.bin");
  TEST_ASSERT_EQUAL_UINT32(32, pub.size());
  TEST_ASSERT_EQUAL_UINT32(64, sig.size());

  TEST_ASSERT_TRUE(xeddsa_verify(pub.data(), 0, 0, kOtaPortnum, payload.data(),
                                 payload.size(), sig.data()));
}

static void test_tampered_payload_fails() {
  auto pub = read_fixture("xeddsa_admin_pub.bin");
  auto payload = read_fixture("xeddsa_payload.bin");
  auto sig = read_fixture("xeddsa_sig.bin");
  payload[10] ^= 0x01;
  TEST_ASSERT_FALSE(xeddsa_verify(pub.data(), 0, 0, kOtaPortnum, payload.data(),
                                  payload.size(), sig.data()));
}

static void test_tampered_signature_fails() {
  auto pub = read_fixture("xeddsa_admin_pub.bin");
  auto payload = read_fixture("xeddsa_payload.bin");
  auto sig = read_fixture("xeddsa_sig.bin");
  sig[5] ^= 0x80;
  TEST_ASSERT_FALSE(xeddsa_verify(pub.data(), 0, 0, kOtaPortnum, payload.data(),
                                  payload.size(), sig.data()));
}

// Wrong domain (different portnum) must fail -- the signature is bound to the
// OTA portnum via the signing buffer.
static void test_wrong_portnum_fails() {
  auto pub = read_fixture("xeddsa_admin_pub.bin");
  auto payload = read_fixture("xeddsa_payload.bin");
  auto sig = read_fixture("xeddsa_sig.bin");
  TEST_ASSERT_FALSE(xeddsa_verify(pub.data(), 0, 0, 6 /*ADMIN_APP*/,
                                  payload.data(), payload.size(), sig.data()));
}

// A different admin key must not verify.
static void test_wrong_key_fails() {
  auto other = read_fixture("xeddsa_other_pub.bin");
  auto payload = read_fixture("xeddsa_payload.bin");
  auto sig = read_fixture("xeddsa_sig.bin");
  TEST_ASSERT_FALSE(xeddsa_verify(other.data(), 0, 0, kOtaPortnum,
                                  payload.data(), payload.size(), sig.data()));
}

// AdminKeyVerifier accepts the manifest when ANY held admin key matches, and is
// fail-closed with no keys.
static void test_admin_key_verifier() {
  auto pub = read_fixture("xeddsa_admin_pub.bin");
  auto other = read_fixture("xeddsa_other_pub.bin");
  auto payload = read_fixture("xeddsa_payload.bin");
  auto sig = read_fixture("xeddsa_sig.bin");

  AdminKeyVerifier empty;
  TEST_ASSERT_FALSE(
      empty.verify(payload.data(), payload.size(), sig.data(), sig.size()));

  AdminKeyVerifier one;
  one.add_key(pub.data());
  TEST_ASSERT_TRUE(
      one.verify(payload.data(), payload.size(), sig.data(), sig.size()));

  // The right key present among others (order shouldn't matter).
  AdminKeyVerifier multi;
  multi.add_key(other.data());
  multi.add_key(pub.data());
  TEST_ASSERT_TRUE(
      multi.verify(payload.data(), payload.size(), sig.data(), sig.size()));

  // Only the wrong key -> reject.
  AdminKeyVerifier wrong;
  wrong.add_key(other.data());
  TEST_ASSERT_FALSE(
      wrong.verify(payload.data(), payload.size(), sig.data(), sig.size()));

  // Wrong signature length -> reject.
  TEST_ASSERT_FALSE(one.verify(payload.data(), payload.size(), sig.data(), 32));
}

// Full pipeline: a package built by the packager and signed by the reference
// signer (Meshtastic key model) is parsed and its manifest signature verified
// through package_verify_signature + AdminKeyVerifier -- exactly the on-device
// path (minus the transport).
static void test_signed_package_end_to_end() {
  auto pkg = read_fixture("signed_package.bin");
  auto admin_pub = read_fixture("signed_admin_pub.bin");

  ParsedPackage parsed;
  TEST_ASSERT_EQUAL_INT((int)PackageError::Ok,
                        (int)package_parse(pkg.data(), pkg.size(), parsed));

  AdminKeyVerifier verifier;
  verifier.add_key(admin_pub.data());
  TEST_ASSERT_TRUE(package_verify_signature(parsed, verifier));

  // Tamper the manifest -> signature must fail.
  auto tampered = pkg;
  tampered[16 + 40] ^= 0x01; // a byte inside the manifest
  ParsedPackage p2;
  package_parse(tampered.data(), tampered.size(), p2);
  TEST_ASSERT_FALSE(package_verify_signature(p2, verifier));

  // A verifier without the right key rejects.
  AdminKeyVerifier empty;
  TEST_ASSERT_FALSE(package_verify_signature(parsed, empty));
}

int main() {
  UNITY_BEGIN();
  RUN_TEST(test_xeddsa_interop_ok);
  RUN_TEST(test_signed_package_end_to_end);
  RUN_TEST(test_tampered_payload_fails);
  RUN_TEST(test_tampered_signature_fails);
  RUN_TEST(test_wrong_portnum_fails);
  RUN_TEST(test_wrong_key_fails);
  RUN_TEST(test_admin_key_verifier);
  return UNITY_END();
}
