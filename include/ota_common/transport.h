// Meshtastic-native point-to-point OTA transport. Pull-based, one seeder -> one
// target, single RF hop: no flooding, no relay, no routing. The logical units
// (manifest+signature, each payload block, each block's merkle proof) are split
// into fragments that fit one Meshtastic data payload (<=233 B). Each payload
// block is verified against the manifest merkle root as it completes, and
// verified blocks are journaled so the transfer resumes across reboot.
//
// Framework-agnostic: the radio is the caller's; this layer speaks in frames.
// The protocol is stop-and-wait per logical unit.
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <vector>

#include "ota_common/flash_target.h"
#include "ota_common/manifest.h"
#include "ota_common/merkle.h"
#include "ota_common/signature.h"

namespace ota_common {

// One Meshtastic data payload (meshtastic_Constants_DATA_PAYLOAD_LEN == 233);
// the OTA module lives under this ceiling.
inline constexpr size_t kMaxFramePayload = 233;
inline constexpr size_t kFrameHeaderLen = 8;
inline constexpr size_t kMaxFragment = kMaxFramePayload - kFrameHeaderLen; // 225

// index sentinel meaning "the manifest+signature unit" rather than a block.
inline constexpr uint16_t kIndexManifest = 0xFFFF;

enum class OtaFrameType : uint8_t {
    Start = 1,    // seeder->target: session geometry (a hint; manifest is authoritative)
    Manifest = 2, // seeder->target: manifest+signature fragment
    Block = 3,    // seeder->target: payload block fragment
    Proof = 4,    // seeder->target: merkle proof fragment for a block
    Request = 5,  // target->seeder: please send <index> (kIndexManifest or a block)
    Ack = 6,      // target->seeder: <index> verified
    Done = 7,     // target->seeder: all blocks verified
    Abort = 8,    // either side: session aborted
    Load = 9,        // client->relay: a chunk of the package to seed (OtaLoadInfo prefix)
    LoadCommit = 10, // client->relay: package upload complete, begin seeding
};

// 8-byte little-endian frame header. Field meaning is per-type; see the senders.
struct OtaFrameHeader {
    OtaFrameType type;
    uint8_t session; // single point-to-point session id, echoed by both sides
    uint16_t index;  // block index, or kIndexManifest
    uint16_t off;    // byte offset of this fragment within its logical unit
    uint16_t total;  // total byte length of the logical unit
};

void frame_header_pack(const OtaFrameHeader& h, uint8_t out[kFrameHeaderLen]);
bool frame_header_unpack(const uint8_t* in, size_t len, OtaFrameHeader& out);

// START payload (12 bytes): geometry hints, cross-checked against the manifest.
struct OtaStartInfo {
    uint16_t block_size;
    uint16_t block_count;
    uint32_t payload_length;
    uint16_t manifest_len;
    uint16_t sig_len;
};
void start_info_pack(const OtaStartInfo& s, std::vector<uint8_t>& out);
bool start_info_unpack(const uint8_t* in, size_t len, OtaStartInfo& out);

// LOAD payload prefix (8 bytes). A client streams the signed package to a relay
// node in Load frames (each carries this prefix followed by the chunk bytes);
// the relay assembles the buffer, then a LoadCommit frame makes it seed the
// package to the mesh. total_len is the whole package; offset is this chunk's
// position within it.
inline constexpr size_t kLoadInfoLen = 8;
struct OtaLoadInfo {
    uint32_t total_len;
    uint32_t offset;
};
void load_info_pack(const OtaLoadInfo& s, std::vector<uint8_t>& out);
bool load_info_unpack(const uint8_t* in, size_t len, OtaLoadInfo& out);

// Persistent verified-payload store. Doubles as the resume journal: has_block()
// reports what survived a reboot. Implementations write to a delta buffer
// (delta) or stream to flash (full image).
struct IBlockStore {
    virtual ~IBlockStore() = default;
    virtual bool has_block(uint32_t index) const = 0;
    virtual bool put_block(uint32_t index, const uint8_t* data, uint32_t len) = 0;
    virtual uint32_t stored_count() const = 0;
};

// Outgoing frame channel (the caller's radio, or a test loopback).
struct IFrameOut {
    virtual ~IFrameOut() = default;
    virtual void send_frame(const uint8_t* data, size_t len) = 0;
};

// Bridge for the full-image path (payload == output image): streams each
// verified payload block straight into an IFlashTarget. Writes are sequential
// (the transport requests the lowest missing block, so blocks arrive in order),
// and resume is RAM-only -- an interrupt restarts the transfer, which is safe
// when the destination is the inactive slot and the active slot is untouched. The delta path uses a buffering store + the detools decoder
// instead; this bridge is not used there.
//
// Usage: construct over the target; once the receiver has the manifest, call
// set_manifest(&receiver.manifest()); the first put_block lazily begins the
// target. After the transfer completes, call commit() to run the target's hard
// output-hash gate and activate.
class FlashTargetBlockStore final : public IBlockStore {
public:
    explicit FlashTargetBlockStore(IFlashTarget& target) : target_(target) {}

    // The signed manifest (held by the receiver) describing the output image.
    void set_manifest(const Manifest* manifest) { manifest_ = manifest; }

    bool has_block(uint32_t index) const override;
    bool put_block(uint32_t index, const uint8_t* data, uint32_t len) override;
    uint32_t stored_count() const override { return count_; }

    bool began() const { return began_; }
    FlashStatus commit() { return target_.commit(); }
    void abort() { target_.abort(); }

private:
    IFlashTarget& target_;
    const Manifest* manifest_ = nullptr;
    bool began_ = false;
    uint32_t block_size_ = 0;
    uint32_t block_count_ = 0;
    uint32_t next_ = 0; // lowest not-yet-written index (sequential)
    uint32_t count_ = 0;
    std::vector<bool> have_;
};

// Buffers verified payload blocks into one contiguous buffer. Used by the delta
// path: the received payload is a detools delta (tens of KB), assembled here and
// then decoded against the base into the flash target. Blocks may arrive in any
// order (random-access into the buffer); resume is RAM-only (restart on reboot).
class BufferBlockStore final : public IBlockStore {
public:
    void set_manifest(const Manifest* manifest) { manifest_ = manifest; }

    bool has_block(uint32_t index) const override;
    bool put_block(uint32_t index, const uint8_t* data, uint32_t len) override;
    uint32_t stored_count() const override { return count_; }

    const uint8_t* data() const { return buf_.data(); }
    size_t size() const { return buf_.size(); }

private:
    void ensure_geometry();
    const Manifest* manifest_ = nullptr;
    bool ready_ = false;
    uint32_t block_size_ = 0;
    uint32_t block_count_ = 0;
    uint32_t count_ = 0;
    std::vector<bool> have_;
    std::vector<uint8_t> buf_;
};

// Receiver-side FSM. Drives manifest receipt, per-block verification against the
// merkle root, journaling, and the pull/ACK requests back to the seeder.
class OtaReceiver {
public:
    // verifier is optional: when null the manifest signature is not checked here
    // (e.g. the caller verifies it separately, or a test omits crypto).
    OtaReceiver(IBlockStore& store, IFrameOut& out, uint8_t session,
                const ISignatureVerifier* verifier = nullptr);

    // Feed one received frame. Drives the state machine and may emit frames.
    void on_frame(const uint8_t* data, size_t len);

    // Kick the session if no START arrives (re-request manifest/next block).
    void poll();

    bool manifest_ready() const { return manifest_ready_; }
    const Manifest& manifest() const { return manifest_; }
    bool complete() const { return complete_; }
    bool aborted() const { return aborted_; }
    uint32_t blocks_total() const { return block_count_; }
    uint32_t blocks_have() const { return store_.stored_count(); }

private:
    struct Reassembler {
        std::vector<uint8_t> buf;
        uint16_t total = 0;
        uint32_t filled = 0;
        bool active = false;
        void reset(uint16_t total_len);
        // Accept an in-order fragment; returns true when the unit is complete.
        bool feed(uint16_t off, const uint8_t* data, size_t len);
    };

    void handle_start(const OtaFrameHeader& h, const uint8_t* p, size_t n);
    void handle_manifest(const OtaFrameHeader& h, const uint8_t* p, size_t n);
    void handle_block(const OtaFrameHeader& h, const uint8_t* p, size_t n);
    void handle_proof(const OtaFrameHeader& h, const uint8_t* p, size_t n);
    void try_finish_block(uint16_t index);
    void request(uint16_t index);
    void request_next();
    void send_simple(OtaFrameType type, uint16_t index);
    uint16_t next_needed_block() const;

    IBlockStore& store_;
    IFrameOut& out_;
    const ISignatureVerifier* verifier_;
    uint8_t session_;

    bool have_geometry_ = false;
    uint16_t block_size_ = 0;
    uint16_t block_count_ = 0;
    uint32_t payload_length_ = 0;
    uint16_t manifest_len_ = 0;
    uint16_t sig_len_ = 0;

    Reassembler manifest_re_;
    bool manifest_ready_ = false;
    Manifest manifest_{};
    Hash256 merkle_root_{};

    Reassembler block_re_;
    uint16_t block_in_flight_ = kIndexManifest;
    Reassembler proof_re_;
    uint16_t proof_in_flight_ = kIndexManifest;
    std::map<uint16_t, std::vector<Hash256>> proofs_;
    std::map<uint16_t, std::vector<uint8_t>> ready_blocks_; // complete, awaiting proof

    bool complete_ = false;
    bool aborted_ = false;
};

// Seeder-side: owns the package bytes and answers the receiver's requests.
class OtaSeeder {
public:
    OtaSeeder(const uint8_t* package, size_t package_len, IFrameOut& out, uint8_t session,
              size_t fragment_size = 200);

    bool valid() const { return valid_; }

    // Begin the session (emit START).
    void begin();
    // Feed a frame from the target (Request/Ack/Done/Abort).
    void on_frame(const uint8_t* data, size_t len);
    bool done() const { return done_; }

private:
    void send_manifest();
    void send_block(uint16_t index);
    void send_proof(uint16_t index);
    void emit(const OtaFrameHeader& h, const uint8_t* payload, size_t n);

    IFrameOut& out_;
    uint8_t session_;
    size_t frag_;
    bool valid_ = false;
    bool done_ = false;

    const Manifest* manifest_ = nullptr;
    const uint8_t* manifest_bytes_ = nullptr;
    const uint8_t* signature_ = nullptr;
    size_t sig_len_ = 0;
    const uint8_t* payload_ = nullptr;
    uint32_t payload_len_ = 0;
    uint16_t block_size_ = 0;
    uint16_t block_count_ = 0;
    std::vector<Hash256> leaves_;
};

} // namespace ota_common
