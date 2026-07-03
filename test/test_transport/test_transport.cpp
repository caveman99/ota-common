#include <unity.h>

#include <cstring>
#include <deque>
#include <functional>
#include <map>
#include <vector>

#include "ota_common/merkle.h"
#include "ota_common/package.h"
#include "ota_common/transport.h"
#include "test_helpers.h"

using namespace ota_common;

void setUp() {}
void tearDown() {}

// ---- helpers ---------------------------------------------------------------

// Verifier that accepts one fixed signature blob (stands in for Ed25519).
struct FakeVerifier : ISignatureVerifier {
    std::vector<uint8_t> good;
    bool ok = true;
    bool verify(const uint8_t*, size_t, const uint8_t* sig, size_t n) const override {
        if (!ok) return false;
        return n == good.size() && std::memcmp(sig, good.data(), n) == 0;
    }
};

// Build a full-image package buffer (payload == output image).
static std::vector<uint8_t> build_package(const std::vector<uint8_t>& payload, uint16_t block_size,
                                          const std::vector<uint8_t>& sig) {
    Manifest m;
    std::memset(&m, 0, sizeof(m));
    m.magic = kManifestMagic;
    m.format = kManifestFormat;
    m.flags = 0;
    std::strncpy(m.env, "heltec-v3", kMEnvLen);
    std::strncpy(m.base_version, "2.8.0.54e0d8d", kMVersionLen);
    std::strncpy(m.base_commit, "54e0d8d", kMCommitLen);
    m.block_size = block_size;
    m.payload_length = static_cast<uint32_t>(payload.size());
    m.block_count = static_cast<uint32_t>((payload.size() + block_size - 1) / block_size);

    std::vector<Hash256> leaves;
    for (size_t off = 0; off < payload.size(); off += block_size) {
        size_t n = (off + block_size <= payload.size()) ? block_size : payload.size() - off;
        leaves.push_back(hash_leaf(payload.data() + off, n));
    }
    Hash256 root = merkle_root(leaves);
    std::memcpy(m.payload_merkle_root, root.bytes, kSha256Len);
    m.output_length = static_cast<uint32_t>(payload.size());
    Sha256::hash(payload.data(), payload.size(), m.output_sha256);

    PackageHeader hdr{kPackageMagic, kPackageFormat, 0, sizeof(Manifest),
                      static_cast<uint32_t>(sig.size())};
    std::vector<uint8_t> buf;
    auto add = [&](const void* d, size_t n) {
        const auto* b = reinterpret_cast<const uint8_t*>(d);
        buf.insert(buf.end(), b, b + n);
    };
    add(&hdr, sizeof(hdr));
    add(&m, sizeof(m));
    add(sig.data(), sig.size());
    add(payload.data(), payload.size());
    return buf;
}

struct MemStore : IBlockStore {
    std::map<uint32_t, std::vector<uint8_t>> blocks;
    bool has_block(uint32_t i) const override { return blocks.find(i) != blocks.end(); }
    bool put_block(uint32_t i, const uint8_t* d, uint32_t n) override {
        blocks[i].assign(d, d + n);
        return true;
    }
    uint32_t stored_count() const override { return static_cast<uint32_t>(blocks.size()); }
    std::vector<uint8_t> assemble() const {
        std::vector<uint8_t> out;
        for (auto& kv : blocks) out.insert(out.end(), kv.second.begin(), kv.second.end());
        return out;
    }
};

struct Endpoint : IFrameOut {
    std::deque<std::vector<uint8_t>> outbox;
    void send_frame(const uint8_t* d, size_t n) override { outbox.emplace_back(d, d + n); }
};

// Stand-in for InactiveSlotTarget: accumulates the written image and runs the
// hard output-hash gate on commit, exactly like the real esp_ota sink.
struct FakeFlashTarget : IFlashTarget {
    std::vector<uint8_t> buf;
    uint8_t expected_sha[kSha256Len] = {0};
    bool committed = false;
    FlashStatus begin(uint32_t size, const Manifest& m) override {
        buf.assign(size, 0);
        std::memcpy(expected_sha, m.output_sha256, kSha256Len);
        return FlashStatus::Ok;
    }
    FlashStatus write(uint32_t off, const uint8_t* d, size_t n) override {
        if (off + n > buf.size()) return FlashStatus::OutOfRange;
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

// Pump frames between seeder and receiver until quiescent or the cap is hit.
// mutate(frame) is applied to each seeder->receiver frame (for fault injection).
static int pump(OtaSeeder& seeder, Endpoint& seederEp, OtaReceiver& receiver, Endpoint& recvEp,
                std::function<void(std::vector<uint8_t>&)> mutate = nullptr, int cap = 200000) {
    int delivered = 0;
    while (!seederEp.outbox.empty() || !recvEp.outbox.empty()) {
        if (--cap <= 0) break;
        if (!seederEp.outbox.empty()) {
            std::vector<uint8_t> f = std::move(seederEp.outbox.front());
            seederEp.outbox.pop_front();
            if (mutate) mutate(f);
            receiver.on_frame(f.data(), f.size());
            ++delivered;
        }
        if (!recvEp.outbox.empty()) {
            std::vector<uint8_t> f = std::move(recvEp.outbox.front());
            recvEp.outbox.pop_front();
            seeder.on_frame(f.data(), f.size());
            ++delivered;
        }
    }
    return delivered;
}

static std::vector<uint8_t> kSig(64, 0xA5);

// ---- codec unit tests ------------------------------------------------------

static void test_frame_header_roundtrip() {
    OtaFrameHeader h{OtaFrameType::Block, 7, 1234, 200, 1024};
    uint8_t buf[kFrameHeaderLen];
    frame_header_pack(h, buf);
    OtaFrameHeader g;
    TEST_ASSERT_TRUE(frame_header_unpack(buf, sizeof(buf), g));
    TEST_ASSERT_EQUAL_INT((int)OtaFrameType::Block, (int)g.type);
    TEST_ASSERT_EQUAL_UINT8(7, g.session);
    TEST_ASSERT_EQUAL_UINT16(1234, g.index);
    TEST_ASSERT_EQUAL_UINT16(200, g.off);
    TEST_ASSERT_EQUAL_UINT16(1024, g.total);
}

static void test_start_info_roundtrip() {
    OtaStartInfo s{1024, 50, 50000, 192, 64};
    std::vector<uint8_t> buf;
    start_info_pack(s, buf);
    OtaStartInfo g;
    TEST_ASSERT_TRUE(start_info_unpack(buf.data(), buf.size(), g));
    TEST_ASSERT_EQUAL_UINT16(1024, g.block_size);
    TEST_ASSERT_EQUAL_UINT16(50, g.block_count);
    TEST_ASSERT_EQUAL_UINT32(50000, g.payload_length);
    TEST_ASSERT_EQUAL_UINT16(192, g.manifest_len);
    TEST_ASSERT_EQUAL_UINT16(64, g.sig_len);
}

// ---- end-to-end ------------------------------------------------------------

static void run_transfer(const std::vector<uint8_t>& payload, uint16_t block_size, size_t frag,
                         MemStore& store) {
    auto pkg = build_package(payload, block_size, kSig);
    FakeVerifier v;
    v.good = kSig;
    Endpoint seederEp, recvEp;
    OtaSeeder seeder(pkg.data(), pkg.size(), seederEp, 3, frag);
    TEST_ASSERT_TRUE(seeder.valid());
    OtaReceiver receiver(store, recvEp, 3, &v);
    seeder.begin();
    pump(seeder, seederEp, receiver, recvEp);

    TEST_ASSERT_TRUE(receiver.manifest_ready());
    TEST_ASSERT_TRUE(receiver.complete());
    TEST_ASSERT_EQUAL_UINT32(receiver.blocks_total(), receiver.blocks_have());
    TEST_ASSERT_TRUE(seeder.done());
    auto got = store.assemble();
    TEST_ASSERT_EQUAL_UINT32(payload.size(), got.size());
    TEST_ASSERT_EQUAL_MEMORY(payload.data(), got.data(), payload.size());
}

static void test_end_to_end_basic() {
    auto payload = ota_test::prng_bytes(4096 + 250, 0x11);
    MemStore store;
    run_transfer(payload, 1024, 200, store);
}

// Tiny fragments stress the reassembly of manifest, blocks, and proofs.
static void test_tiny_fragments() {
    auto payload = ota_test::prng_bytes(3000, 0x22);
    MemStore store;
    run_transfer(payload, 256, 17, store);
}

// A payload that is an exact multiple of the block size (no short final block).
static void test_exact_multiple() {
    auto payload = ota_test::prng_bytes(1024 * 4, 0x33);
    MemStore store;
    run_transfer(payload, 1024, 200, store);
}

// Single block (single-leaf merkle tree -> empty proofs).
static void test_single_block() {
    auto payload = ota_test::prng_bytes(500, 0x44);
    MemStore store;
    run_transfer(payload, 1024, 200, store);
}

// ---- resume ----------------------------------------------------------------

static void test_resume_after_reboot() {
    auto payload = ota_test::prng_bytes(1024 * 8 + 100, 0x55);
    auto pkg = build_package(payload, 1024, kSig);
    FakeVerifier v;
    v.good = kSig;

    // First leg: stop the pump early so only some blocks are journaled.
    MemStore store;
    {
        Endpoint sEp, rEp;
        OtaSeeder seeder(pkg.data(), pkg.size(), sEp, 1, 200);
        OtaReceiver receiver(store, rEp, 1, &v);
        seeder.begin();
        pump(seeder, sEp, receiver, rEp, nullptr, /*cap=*/40); // truncated
    }
    const uint32_t partial = store.stored_count();
    TEST_ASSERT_TRUE(partial > 0);
    TEST_ASSERT_TRUE(partial < ((payload.size() + 1023) / 1024));

    // Second leg: a fresh receiver (simulated reboot) reuses the same store and
    // must only fetch the missing blocks. Count Block frames the seeder sends.
    std::map<uint16_t, int> blockSends;
    {
        Endpoint sEp, rEp;
        OtaSeeder seeder(pkg.data(), pkg.size(), sEp, 1, 200);
        OtaReceiver receiver(store, rEp, 1, &v);

        // Wrap delivery to observe Block frame indices.
        seeder.begin();
        int cap = 200000;
        while (!sEp.outbox.empty() || !rEp.outbox.empty()) {
            if (--cap <= 0) break;
            if (!sEp.outbox.empty()) {
                auto f = std::move(sEp.outbox.front());
                sEp.outbox.pop_front();
                OtaFrameHeader h;
                if (frame_header_unpack(f.data(), f.size(), h) && h.type == OtaFrameType::Block)
                    blockSends[h.index]++;
                receiver.on_frame(f.data(), f.size());
            }
            if (!rEp.outbox.empty()) {
                auto f = std::move(rEp.outbox.front());
                rEp.outbox.pop_front();
                seeder.on_frame(f.data(), f.size());
            }
        }
        TEST_ASSERT_TRUE(receiver.complete());
    }

    // Already-journaled blocks must never be re-sent on resume (asserted below
    // for block 0, which is always journaled first).
    auto got = store.assemble();
    TEST_ASSERT_EQUAL_MEMORY(payload.data(), got.data(), payload.size());
    // At least the first journaled block index should not have been refetched.
    TEST_ASSERT_EQUAL_INT(0, blockSends.count(0) ? blockSends[0] : 0);
}

// ---- corruption recovery ---------------------------------------------------

static void test_corruption_recovery() {
    auto payload = ota_test::prng_bytes(1024 * 5, 0x66);
    auto pkg = build_package(payload, 1024, kSig);
    FakeVerifier v;
    v.good = kSig;
    MemStore store;
    Endpoint sEp, rEp;
    OtaSeeder seeder(pkg.data(), pkg.size(), sEp, 9, 200);
    OtaReceiver receiver(store, rEp, 9, &v);

    // Corrupt the FIRST fragment of block index 2, exactly once.
    bool corrupted = false;
    auto mutate = [&](std::vector<uint8_t>& f) {
        OtaFrameHeader h;
        if (!frame_header_unpack(f.data(), f.size(), h)) return;
        if (!corrupted && h.type == OtaFrameType::Block && h.index == 2 && h.off == 0 &&
            f.size() > kFrameHeaderLen) {
            f[kFrameHeaderLen] ^= 0xFF; // flip a payload byte
            corrupted = true;
        }
    };

    seeder.begin();
    pump(seeder, sEp, receiver, rEp, mutate);

    TEST_ASSERT_TRUE(corrupted);          // the fault was actually injected
    TEST_ASSERT_TRUE(receiver.complete()); // and recovered from
    auto got = store.assemble();
    TEST_ASSERT_EQUAL_MEMORY(payload.data(), got.data(), payload.size());
}

// ---- signature rejection ---------------------------------------------------

static void test_bad_signature_aborts() {
    auto payload = ota_test::prng_bytes(2048, 0x77);
    auto pkg = build_package(payload, 1024, kSig);
    FakeVerifier v;
    v.good = kSig;
    v.ok = false; // reject every signature
    MemStore store;
    Endpoint sEp, rEp;
    OtaSeeder seeder(pkg.data(), pkg.size(), sEp, 2, 200);
    OtaReceiver receiver(store, rEp, 2, &v);
    seeder.begin();
    pump(seeder, sEp, receiver, rEp);

    TEST_ASSERT_TRUE(receiver.aborted());
    TEST_ASSERT_FALSE(receiver.complete());
    TEST_ASSERT_FALSE(receiver.manifest_ready());
    TEST_ASSERT_EQUAL_UINT32(0, store.stored_count());
}

// ---- geometry cross-check --------------------------------------------------

// A START whose geometry disagrees with the signed manifest must abort the
// session (the manifest is authoritative; START is an unsigned hint).
static void test_geometry_mismatch_aborts() {
    auto payload = ota_test::prng_bytes(2048, 0x88);
    auto pkg = build_package(payload, 1024, kSig);
    FakeVerifier v;
    v.good = kSig;
    MemStore store;
    Endpoint rEp;
    OtaReceiver receiver(store, rEp, 5, &v);

    // Hand-craft a START with the wrong block_count.
    OtaStartInfo bad{1024, 99 /*wrong*/, static_cast<uint32_t>(payload.size()), 192, 64};
    std::vector<uint8_t> body;
    start_info_pack(bad, body);
    std::vector<uint8_t> startFrame(kFrameHeaderLen + body.size());
    OtaFrameHeader sh{OtaFrameType::Start, 5, 0, 0, 0};
    frame_header_pack(sh, startFrame.data());
    std::memcpy(startFrame.data() + kFrameHeaderLen, body.data(), body.size());
    receiver.on_frame(startFrame.data(), startFrame.size());

    // Now feed the real manifest (single fragment, it fits): header(8)+manifest+sig.
    const size_t total = sizeof(Manifest) + kSig.size();
    std::vector<uint8_t> mf(kFrameHeaderLen + total);
    OtaFrameHeader mh{OtaFrameType::Manifest, 5, kIndexManifest, 0, static_cast<uint16_t>(total)};
    frame_header_pack(mh, mf.data());
    std::memcpy(mf.data() + kFrameHeaderLen, pkg.data() + sizeof(PackageHeader), total);
    receiver.on_frame(mf.data(), mf.size());

    TEST_ASSERT_TRUE(receiver.aborted());
    TEST_ASSERT_FALSE(receiver.manifest_ready());
}

// Full-image path: transport streams verified blocks straight into a flash
// target via FlashTargetBlockStore, and the target's commit gate passes. This
// mirrors how LoRaOtaABModule drives InactiveSlotTarget.
static void test_stream_to_flash_target() {
    auto payload = ota_test::prng_bytes(4096 + 300, 0x5151);
    auto pkg = build_package(payload, 1024, kSig);
    FakeVerifier v;
    v.good = kSig;

    FakeFlashTarget flash;
    FlashTargetBlockStore store(flash);
    Endpoint sEp, rEp;
    OtaSeeder seeder(pkg.data(), pkg.size(), sEp, 4, 200);
    OtaReceiver receiver(store, rEp, 4, &v);
    seeder.begin();

    // Pump, priming the store with the manifest the moment the receiver has it
    // (the firmware module does the same between mesh packets).
    int cap = 200000;
    bool primed = false;
    while (!sEp.outbox.empty() || !rEp.outbox.empty()) {
        if (--cap <= 0) break;
        if (!sEp.outbox.empty()) {
            auto f = std::move(sEp.outbox.front());
            sEp.outbox.pop_front();
            receiver.on_frame(f.data(), f.size());
            if (!primed && receiver.manifest_ready()) {
                store.set_manifest(&receiver.manifest());
                primed = true;
            }
        }
        if (!rEp.outbox.empty()) {
            auto f = std::move(rEp.outbox.front());
            rEp.outbox.pop_front();
            seeder.on_frame(f.data(), f.size());
        }
    }

    TEST_ASSERT_TRUE(receiver.complete());
    TEST_ASSERT_TRUE(store.began());
    TEST_ASSERT_EQUAL_UINT32(payload.size(), flash.buf.size());
    TEST_ASSERT_EQUAL_MEMORY(payload.data(), flash.buf.data(), payload.size());
    TEST_ASSERT_EQUAL_INT((int)FlashStatus::Ok, (int)store.commit());
    TEST_ASSERT_TRUE(flash.committed);
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_frame_header_roundtrip);
    RUN_TEST(test_stream_to_flash_target);
    RUN_TEST(test_start_info_roundtrip);
    RUN_TEST(test_end_to_end_basic);
    RUN_TEST(test_tiny_fragments);
    RUN_TEST(test_exact_multiple);
    RUN_TEST(test_single_block);
    RUN_TEST(test_resume_after_reboot);
    RUN_TEST(test_corruption_recovery);
    RUN_TEST(test_bad_signature_aborts);
    RUN_TEST(test_geometry_mismatch_aborts);
    return UNITY_END();
}
