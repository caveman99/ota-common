// Cross-language delta apply: the vendored detools C decoder reconstructs the
// target from the base using a delta the Python packager produced (heatshrink
// compressed). This is the end-to-end proof of the delta path and closes the
// loop with tools/gen_fixtures.py.

#include <unity.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "ota_common/detools_apply.h"
#include "ota_common/esp_image.h"
#include "ota_common/flash_target.h"
#include "ota_common/package.h"
#include "ota_common/sha256.h"
#include "ota_common/transport.h"

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

struct VecSink : IByteSink {
  std::vector<uint8_t> out;
  bool write(const uint8_t *d, size_t n) override {
    out.insert(out.end(), d, d + n);
    return true;
  }
};

// Accumulates the reconstructed image and runs the output-hash gate on commit,
// like InactiveSlotTarget.
struct FakeFlashTarget : IFlashTarget {
  std::vector<uint8_t> buf;
  uint8_t expected_sha[kSha256Len] = {0};
  bool committed = false;
  FlashStatus begin(uint32_t size, const Manifest &m) override {
    buf.assign(size, 0);
    std::memcpy(expected_sha, m.output_sha256, kSha256Len);
    return FlashStatus::Ok;
  }
  FlashStatus write(uint32_t off, const uint8_t *d, size_t n) override {
    if (off + n > buf.size())
      return FlashStatus::OutOfRange;
    std::memcpy(buf.data() + off, d, n);
    return FlashStatus::Ok;
  }
  FlashStatus commit() override {
    uint8_t h[kSha256Len];
    Sha256::hash(buf.data(), buf.size(), h);
    committed = std::memcmp(h, expected_sha, kSha256Len) == 0;
    return committed ? FlashStatus::Ok : FlashStatus::VerifyFailed;
  }
  void abort() override {}
};

static ParsedPackage parse(const std::vector<uint8_t> &pkg) {
  ParsedPackage p;
  TEST_ASSERT_EQUAL_INT((int)PackageError::Ok,
                        (int)package_parse(pkg.data(), pkg.size(), p));
  return p;
}

// apply(base, delta) == target, byte for byte.
static void test_delta_apply_matches_target() {
  auto base = read_fixture("base_image.bin");
  auto target = read_fixture("target_image.bin");
  auto deltaPkg = read_fixture("delta_package.bin");
  ParsedPackage pkg = parse(deltaPkg);
  TEST_ASSERT_TRUE(manifest_is_delta(*pkg.manifest));

  BufferImageReader base_reader(base.data(), base.size());
  VecSink sink;
  int out_size = detools_apply(base_reader, pkg.payload, pkg.payload_len, sink);

  TEST_ASSERT_TRUE_MESSAGE(out_size > 0, detools_apply_error_string(out_size));
  TEST_ASSERT_EQUAL_UINT32(target.size(), (uint32_t)out_size);
  TEST_ASSERT_EQUAL_UINT32(target.size(), sink.out.size());
  TEST_ASSERT_EQUAL_MEMORY(target.data(), sink.out.data(), target.size());
}

// The reconstructed image satisfies the manifest's hard output gate.
static void test_delta_output_hash_gate() {
  auto base = read_fixture("base_image.bin");
  auto deltaPkg = read_fixture("delta_package.bin");
  ParsedPackage pkg = parse(deltaPkg);

  BufferImageReader base_reader(base.data(), base.size());
  VecSink sink;
  int out_size = detools_apply(base_reader, pkg.payload, pkg.payload_len, sink);
  TEST_ASSERT_TRUE(out_size > 0);
  TEST_ASSERT_EQUAL_UINT32(pkg.manifest->output_length, (uint32_t)out_size);

  uint8_t h[kSha256Len];
  Sha256::hash(sink.out.data(), sink.out.size(), h);
  TEST_ASSERT_EQUAL_MEMORY(pkg.manifest->output_sha256, h, kSha256Len);
}

// Applying the delta against the WRONG base must not yield the target: either
// the decoder errors, or the output fails the hard hash gate. This is what
// makes a missing base-flash hash safe (the catch is at the output).
static void test_wrong_base_fails_output_gate() {
  auto target = read_fixture("target_image.bin");
  auto deltaPkg = read_fixture("delta_package.bin");
  ParsedPackage pkg = parse(deltaPkg);

  // A wrong base: the target image reused as the base.
  BufferImageReader wrong(target.data(), target.size());
  VecSink sink;
  int out_size = detools_apply(wrong, pkg.payload, pkg.payload_len, sink);

  bool matches_target =
      out_size > 0 && sink.out.size() == target.size() &&
      std::memcmp(sink.out.data(), target.data(), target.size()) == 0;
  TEST_ASSERT_FALSE(matches_target);

  if (out_size > 0) {
    uint8_t h[kSha256Len];
    Sha256::hash(sink.out.data(), sink.out.size(), h);
    TEST_ASSERT_NOT_EQUAL(
        0, std::memcmp(pkg.manifest->output_sha256, h, kSha256Len));
  }
}

// The separate-partition delta apply-path as a unit: decode the delta straight
// into an IFlashTarget via FlashTargetByteSink, then the target's commit gate
// passes.
static void test_delta_into_flash_target() {
  auto base = read_fixture("base_image.bin");
  auto target = read_fixture("target_image.bin");
  auto deltaPkg = read_fixture("delta_package.bin");
  ParsedPackage pkg = parse(deltaPkg);

  FakeFlashTarget flash;
  TEST_ASSERT_EQUAL_INT(
      (int)FlashStatus::Ok,
      (int)flash.begin(pkg.manifest->output_length, *pkg.manifest));

  BufferImageReader base_reader(base.data(), base.size());
  FlashTargetByteSink sink(flash);
  int out_size = detools_apply(base_reader, pkg.payload, pkg.payload_len, sink);
  TEST_ASSERT_TRUE(out_size > 0);
  TEST_ASSERT_EQUAL_UINT32(target.size(), sink.bytes_written());

  TEST_ASSERT_EQUAL_INT((int)FlashStatus::Ok, (int)flash.commit());
  TEST_ASSERT_TRUE(flash.committed);
  TEST_ASSERT_EQUAL_MEMORY(target.data(), flash.buf.data(), target.size());
}

// BufferBlockStore assembles the received delta blocks; the assembled bytes
// equal the payload and decode correctly. This is the transport->buffer half of
// the module's delta path.
static void test_buffer_store_assembles_delta() {
  auto base = read_fixture("base_image.bin");
  auto target = read_fixture("target_image.bin");
  auto deltaPkg = read_fixture("delta_package.bin");
  ParsedPackage pkg = parse(deltaPkg);

  const uint32_t bs = pkg.manifest->block_size;
  BufferBlockStore store;
  store.set_manifest(pkg.manifest);
  // Feed blocks out of order to exercise random-access assembly.
  const uint32_t n = pkg.manifest->block_count;
  for (uint32_t k = 0; k < n; ++k) {
    uint32_t i = (k * 7 + 3) % n; // scrambled order
    uint32_t off = i * bs;
    uint32_t len = (off + bs <= pkg.payload_len) ? bs : pkg.payload_len - off;
    store.put_block(i, pkg.payload + off, len);
  }
  TEST_ASSERT_EQUAL_UINT32(n, store.stored_count());
  TEST_ASSERT_EQUAL_UINT32(pkg.payload_len, store.size());
  TEST_ASSERT_EQUAL_MEMORY(pkg.payload, store.data(), pkg.payload_len);

  // The assembled buffer decodes to the target.
  BufferImageReader base_reader(base.data(), base.size());
  VecSink sink;
  int out_size = detools_apply(base_reader, store.data(), store.size(), sink);
  TEST_ASSERT_TRUE(out_size > 0);
  TEST_ASSERT_EQUAL_MEMORY(target.data(), sink.out.data(), target.size());
}

// ---- in-place apply --------------------------------------------------------

// Must match tools/gen_fixtures.py IN_PLACE_* constants.
static constexpr size_t kInPlaceMemorySize = 65536;

// RAM stand-in for the ota_0 flash region: read/write byte-addressable, erase
// sets 0xFF (like NOR flash). optionally fails after a write budget to simulate
// power loss mid-apply.
struct RamFlash : IFlashMem {
  std::vector<uint8_t> mem;
  int write_budget = -1; // <0 = unlimited
  int write_count = 0;
  explicit RamFlash(size_t size) : mem(size, 0xFF) {}
  int read(uintptr_t src, void *dst, size_t len) override {
    if (src + len > mem.size())
      return -1;
    std::memcpy(dst, mem.data() + src, len);
    return 0;
  }
  int write(uintptr_t dst, const void *src, size_t len) override {
    if (dst + len > mem.size())
      return -1;
    if (write_budget == 0)
      return -1; // simulated power loss
    if (write_budget > 0)
      --write_budget;
    ++write_count;
    std::memcpy(mem.data() + dst, src, len);
    return 0;
  }
  int erase(uintptr_t addr, size_t len) override {
    if (addr + len > mem.size())
      return -1;
    std::memset(mem.data() + addr, 0xFF, len);
    return 0;
  }
};

// Step journal persisted in RAM (survives across "reboots" in the resume test).
struct RamJournal : IStepJournal {
  int step = 0;
  int set_step(int s) override {
    step = s;
    return 0;
  }
  int get_step(int *s) override {
    *s = step;
    return 0;
  }
};

static RamFlash load_region(const std::vector<uint8_t> &base) {
  RamFlash f(kInPlaceMemorySize);
  std::memcpy(f.mem.data(), base.data(),
              base.size()); // from-image at the start
  return f;
}

// In-place patch reconstructs the target within the same flash region.
static void test_inplace_apply_matches_target() {
  auto base = read_fixture("base_image.bin");
  auto target = read_fixture("target_image.bin");
  auto patch = read_fixture("inplace_patch.bin");

  RamFlash flash = load_region(base);
  RamJournal journal;
  int out = detools_apply_in_place(flash, journal, patch.data(), patch.size());

  TEST_ASSERT_TRUE_MESSAGE(out > 0, detools_apply_error_string(out));
  TEST_ASSERT_EQUAL_UINT32(target.size(), (uint32_t)out);
  TEST_ASSERT_EQUAL_MEMORY(target.data(), flash.mem.data(), target.size());
}

// Power loss mid-apply, then resume: the journal persists the step, and a
// second apply over the same (partially patched) region completes to the
// target.
static void test_inplace_resume_after_interrupt() {
  auto base = read_fixture("base_image.bin");
  auto target = read_fixture("target_image.bin");
  auto patch = read_fixture("inplace_patch.bin");

  // Measure how many writes a full apply performs, so we can interrupt at the
  // midpoint (guaranteed mid-apply, after >= 1 segment/step is journaled).
  int total_writes = 0;
  {
    RamFlash count = load_region(base);
    RamJournal cj;
    int r = detools_apply_in_place(count, cj, patch.data(), patch.size());
    TEST_ASSERT_TRUE(r > 0);
    total_writes = count.write_count;
  }
  TEST_ASSERT_TRUE(total_writes >= 2);

  RamFlash flash = load_region(base);
  RamJournal journal; // survives the "reboot"

  // First leg: simulated power loss halfway through.
  flash.write_budget = total_writes / 2;
  int r1 = detools_apply_in_place(flash, journal, patch.data(), patch.size());
  TEST_ASSERT_TRUE(r1 < 0);           // interrupted
  TEST_ASSERT_TRUE(journal.step > 0); // a segment boundary was journaled

  // Second leg: fresh run, unlimited writes, SAME flash + journal -> resumes
  // from the journaled step and completes to the target.
  flash.write_budget = -1;
  int r2 = detools_apply_in_place(flash, journal, patch.data(), patch.size());
  TEST_ASSERT_TRUE_MESSAGE(r2 > 0, detools_apply_error_string(r2));
  TEST_ASSERT_EQUAL_UINT32(target.size(), (uint32_t)r2);
  TEST_ASSERT_EQUAL_MEMORY(target.data(), flash.mem.data(), target.size());
}

int main() {
  UNITY_BEGIN();
  RUN_TEST(test_delta_apply_matches_target);
  RUN_TEST(test_delta_output_hash_gate);
  RUN_TEST(test_wrong_base_fails_output_gate);
  RUN_TEST(test_delta_into_flash_target);
  RUN_TEST(test_buffer_store_assembles_delta);
  RUN_TEST(test_inplace_apply_matches_target);
  RUN_TEST(test_inplace_resume_after_interrupt);
  return UNITY_END();
}
