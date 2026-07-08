#include "ota_common/transport.h"

#include <cstring>

#include "ota_common/package.h"

namespace ota_common {

// ---- frame header / start info codecs --------------------------------------

static void put16(uint8_t *p, uint16_t v) {
  p[0] = static_cast<uint8_t>(v);
  p[1] = static_cast<uint8_t>(v >> 8);
}
static uint16_t get16(const uint8_t *p) {
  return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}
static void put32(uint8_t *p, uint32_t v) {
  for (int i = 0; i < 4; ++i)
    p[i] = static_cast<uint8_t>(v >> (8 * i));
}
static uint32_t get32(const uint8_t *p) {
  uint32_t v = 0;
  for (int i = 0; i < 4; ++i)
    v |= static_cast<uint32_t>(p[i]) << (8 * i);
  return v;
}

void frame_header_pack(const OtaFrameHeader &h, uint8_t out[kFrameHeaderLen]) {
  out[0] = static_cast<uint8_t>(h.type);
  out[1] = h.session;
  put16(out + 2, h.index);
  put16(out + 4, h.off);
  put16(out + 6, h.total);
}

bool frame_header_unpack(const uint8_t *in, size_t len, OtaFrameHeader &out) {
  if (in == nullptr || len < kFrameHeaderLen)
    return false;
  out.type = static_cast<OtaFrameType>(in[0]);
  out.session = in[1];
  out.index = get16(in + 2);
  out.off = get16(in + 4);
  out.total = get16(in + 6);
  return true;
}

void start_info_pack(const OtaStartInfo &s, std::vector<uint8_t> &out) {
  out.resize(12);
  put16(out.data() + 0, s.block_size);
  put16(out.data() + 2, s.block_count);
  put32(out.data() + 4, s.payload_length);
  put16(out.data() + 8, s.manifest_len);
  put16(out.data() + 10, s.sig_len);
}

bool start_info_unpack(const uint8_t *in, size_t len, OtaStartInfo &out) {
  if (in == nullptr || len < 12)
    return false;
  out.block_size = get16(in + 0);
  out.block_count = get16(in + 2);
  out.payload_length = get32(in + 4);
  out.manifest_len = get16(in + 8);
  out.sig_len = get16(in + 10);
  return true;
}

void load_info_pack(const OtaLoadInfo &s, std::vector<uint8_t> &out) {
  out.resize(kLoadInfoLen);
  put32(out.data() + 0, s.total_len);
  put32(out.data() + 4, s.offset);
}

bool load_info_unpack(const uint8_t *in, size_t len, OtaLoadInfo &out) {
  if (in == nullptr || len < kLoadInfoLen)
    return false;
  out.total_len = get32(in + 0);
  out.offset = get32(in + 4);
  return true;
}

// ---- Reassembler -----------------------------------------------------------

void OtaReceiver::Reassembler::reset(uint16_t total_len) {
  total = total_len;
  filled = 0;
  active = true;
  buf.assign(total_len, 0);
}

bool OtaReceiver::Reassembler::feed(uint16_t off, const uint8_t *data,
                                    size_t len) {
  if (!active)
    return false;
  if (off != filled)
    return false; // require in-order fragments
  if (off + len > total)
    return false; // overrun guard
  if (len)
    std::memcpy(buf.data() + off, data, len);
  filled += static_cast<uint32_t>(len);
  return filled >= total;
}

// ---- OtaReceiver -----------------------------------------------------------

OtaReceiver::OtaReceiver(IBlockStore &store, IFrameOut &out, uint8_t session,
                         const ISignatureVerifier *verifier)
    : store_(store), out_(out), verifier_(verifier), session_(session) {}

void OtaReceiver::send_simple(OtaFrameType type, uint16_t index) {
  OtaFrameHeader h{type, session_, index, 0, 0};
  uint8_t frame[kFrameHeaderLen];
  frame_header_pack(h, frame);
  out_.send_frame(frame, kFrameHeaderLen);
}

void OtaReceiver::request(uint16_t index) {
  send_simple(OtaFrameType::Request, index);
}

uint16_t OtaReceiver::next_needed_block() const {
  for (uint16_t i = 0; i < block_count_; ++i) {
    if (!store_.has_block(i))
      return i;
  }
  return kIndexManifest; // none missing
}

void OtaReceiver::request_next() {
  if (!manifest_ready_) {
    request(kIndexManifest);
    return;
  }
  uint16_t need = next_needed_block();
  if (need == kIndexManifest) {
    complete_ = true;
    send_simple(OtaFrameType::Done, 0);
    return;
  }
  request(need);
}

void OtaReceiver::on_frame(const uint8_t *data, size_t len) {
  OtaFrameHeader h;
  if (!frame_header_unpack(data, len, h))
    return;
  if (h.session != session_)
    return;
  if (aborted_ || complete_)
    return;

  const uint8_t *p = data + kFrameHeaderLen;
  size_t n = len - kFrameHeaderLen;

  switch (h.type) {
  case OtaFrameType::Start:
    handle_start(h, p, n);
    break;
  case OtaFrameType::Manifest:
    handle_manifest(h, p, n);
    break;
  case OtaFrameType::Block:
    handle_block(h, p, n);
    break;
  case OtaFrameType::Proof:
    handle_proof(h, p, n);
    break;
  case OtaFrameType::Abort:
    aborted_ = true;
    break;
  default:
    break; // Request/Ack/Done are not for the receiver
  }
}

void OtaReceiver::poll() {
  if (!aborted_ && !complete_)
    request_next();
}

void OtaReceiver::handle_start(const OtaFrameHeader &, const uint8_t *p,
                               size_t n) {
  OtaStartInfo s;
  if (!start_info_unpack(p, n, s))
    return;
  block_size_ = s.block_size;
  block_count_ = s.block_count;
  payload_length_ = s.payload_length;
  manifest_len_ = s.manifest_len;
  sig_len_ = s.sig_len;
  have_geometry_ = true;
  request_next();
}

void OtaReceiver::handle_manifest(const OtaFrameHeader &h, const uint8_t *p,
                                  size_t n) {
  if (manifest_ready_)
    return;
  if (h.off == 0)
    manifest_re_.reset(h.total);
  if (!manifest_re_.feed(h.off, p, n))
    return;

  // Complete: split into manifest bytes + signature.
  const std::vector<uint8_t> &buf = manifest_re_.buf;
  if (buf.size() < sizeof(Manifest)) {
    aborted_ = true;
    return;
  }
  const auto *m = reinterpret_cast<const Manifest *>(buf.data());
  if (m->magic != kManifestMagic || m->format != kManifestFormat) {
    aborted_ = true;
    return;
  }

  const size_t mlen = sizeof(Manifest);
  const uint8_t *sig = buf.data() + mlen;
  const size_t slen = buf.size() - mlen;
  if (verifier_ != nullptr) {
    if (!verifier_->verify(buf.data(), mlen, sig, slen)) {
      aborted_ = true; // bad signature: refuse the session
      return;
    }
  }

  // Cross-check the unsigned START geometry against the signed manifest.
  if (have_geometry_) {
    if (m->block_size != block_size_ || m->block_count != block_count_ ||
        m->payload_length != payload_length_) {
      aborted_ = true;
      return;
    }
  } else {
    block_size_ = static_cast<uint16_t>(m->block_size);
    block_count_ = static_cast<uint16_t>(m->block_count);
    payload_length_ = m->payload_length;
  }

  std::memcpy(&manifest_, m, sizeof(Manifest));
  std::memcpy(merkle_root_.bytes, m->payload_merkle_root, kSha256Len);
  manifest_ready_ = true;
  manifest_re_.active = false;
  request_next();
}

void OtaReceiver::handle_block(const OtaFrameHeader &h, const uint8_t *p,
                               size_t n) {
  if (!manifest_ready_)
    return; // need the root before trusting blocks
  if (store_.has_block(h.index))
    return; // already journaled

  if (h.off == 0 || block_in_flight_ != h.index) {
    block_re_.reset(h.total);
    block_in_flight_ = h.index;
  }
  if (!block_re_.feed(h.off, p, n))
    return;

  ready_blocks_[h.index] = block_re_.buf;
  block_re_.active = false;
  try_finish_block(h.index);
}

void OtaReceiver::handle_proof(const OtaFrameHeader &h, const uint8_t *p,
                               size_t n) {
  if (!manifest_ready_)
    return;
  if (store_.has_block(h.index))
    return;

  if (h.total == 0) {
    proofs_[h.index] = {}; // single-leaf tree: empty proof
    try_finish_block(h.index);
    return;
  }
  if (h.off == 0 || proof_in_flight_ != h.index) {
    proof_re_.reset(h.total);
    proof_in_flight_ = h.index;
  }
  if (!proof_re_.feed(h.off, p, n))
    return;

  const std::vector<uint8_t> &buf = proof_re_.buf;
  if (buf.size() % kSha256Len != 0) {
    proof_re_.active = false;
    return;
  }
  std::vector<Hash256> proof(buf.size() / kSha256Len);
  for (size_t i = 0; i < proof.size(); ++i) {
    std::memcpy(proof[i].bytes, buf.data() + i * kSha256Len, kSha256Len);
  }
  proofs_[h.index] = std::move(proof);
  proof_re_.active = false;
  try_finish_block(h.index);
}

void OtaReceiver::try_finish_block(uint16_t index) {
  auto bit = ready_blocks_.find(index);
  auto pit = proofs_.find(index);
  if (bit == ready_blocks_.end() || pit == proofs_.end())
    return;

  const std::vector<uint8_t> &block = bit->second;
  const bool ok = merkle_verify_block(block.data(), block.size(), index,
                                      block_count_, pit->second, merkle_root_);
  if (ok) {
    store_.put_block(index, block.data(), static_cast<uint32_t>(block.size()));
    send_simple(OtaFrameType::Ack, index);
  }
  // Whether verified or not, drop the working copies. A failed block is simply
  // re-requested by request_next(), and the seeder resends it.
  ready_blocks_.erase(index);
  proofs_.erase(index);
  request_next();
}

// ---- FlashTargetBlockStore -------------------------------------------------

bool FlashTargetBlockStore::has_block(uint32_t index) const {
  return index < have_.size() && have_[index];
}

bool FlashTargetBlockStore::put_block(uint32_t index, const uint8_t *data,
                                      uint32_t len) {
  if (manifest_ == nullptr)
    return false;

  if (!began_) {
    if (target_.begin(manifest_->output_length, *manifest_) != FlashStatus::Ok)
      return false;
    began_ = true;
    block_size_ = manifest_->block_size;
    block_count_ = manifest_->block_count;
    have_.assign(block_count_, false);
  }

  if (index < have_.size() && have_[index])
    return true; // idempotent
  if (index != next_)
    return false; // require sequential

  if (target_.write(index * block_size_, data, len) != FlashStatus::Ok)
    return false;
  have_[index] = true;
  ++next_;
  ++count_;
  return true;
}

// ---- BufferBlockStore ------------------------------------------------------

void BufferBlockStore::ensure_geometry() {
  if (ready_ || manifest_ == nullptr)
    return;
  block_size_ = manifest_->block_size;
  block_count_ = manifest_->block_count;
  buf_.assign(manifest_->payload_length, 0);
  have_.assign(block_count_, false);
  ready_ = true;
}

bool BufferBlockStore::has_block(uint32_t index) const {
  return index < have_.size() && have_[index];
}

bool BufferBlockStore::put_block(uint32_t index, const uint8_t *data,
                                 uint32_t len) {
  if (manifest_ == nullptr)
    return false;
  ensure_geometry();
  if (index >= block_count_)
    return false;
  if (have_[index])
    return true; // idempotent

  const uint32_t off = index * block_size_;
  if (off > buf_.size() || len > buf_.size() - off)
    return false;
  std::memcpy(buf_.data() + off, data, len);
  have_[index] = true;
  ++count_;
  return true;
}

// ---- OtaSeeder -------------------------------------------------------------

OtaSeeder::OtaSeeder(const uint8_t *package, size_t package_len, IFrameOut &out,
                     uint8_t session, size_t fragment_size)
    : out_(out), session_(session), frag_(fragment_size ? fragment_size : 1) {
  if (frag_ > kMaxFragment)
    frag_ = kMaxFragment;

  ParsedPackage pkg;
  if (package_parse(package, package_len, pkg) != PackageError::Ok)
    return;

  manifest_ = pkg.manifest;
  manifest_bytes_ = reinterpret_cast<const uint8_t *>(pkg.manifest);
  signature_ = pkg.signature;
  sig_len_ = pkg.signature_len;
  payload_ = pkg.payload;
  payload_len_ = static_cast<uint32_t>(pkg.payload_len);
  block_size_ = static_cast<uint16_t>(manifest_->block_size);
  block_count_ = static_cast<uint16_t>(manifest_->block_count);

  // Leaves for proof generation, recomputed from the payload.
  for (uint32_t off = 0; off < payload_len_; off += block_size_) {
    uint32_t len =
        (off + block_size_ <= payload_len_) ? block_size_ : payload_len_ - off;
    leaves_.push_back(hash_leaf(payload_ + off, len));
  }
  valid_ = true;
}

void OtaSeeder::emit(const OtaFrameHeader &h, const uint8_t *payload,
                     size_t n) {
  uint8_t frame[kMaxFramePayload];
  frame_header_pack(h, frame);
  if (n)
    std::memcpy(frame + kFrameHeaderLen, payload, n);
  out_.send_frame(frame, kFrameHeaderLen + n);
}

void OtaSeeder::begin() {
  if (!valid_)
    return;
  OtaStartInfo s{block_size_, block_count_, payload_len_,
                 static_cast<uint16_t>(sizeof(Manifest)),
                 static_cast<uint16_t>(sig_len_)};
  std::vector<uint8_t> body;
  start_info_pack(s, body);
  OtaFrameHeader h{OtaFrameType::Start, session_, 0, 0, 0};
  emit(h, body.data(), body.size());
}

void OtaSeeder::send_manifest() {
  // manifest bytes and signature are contiguous in the package buffer.
  const size_t mlen = sizeof(Manifest);
  const size_t total = mlen + sig_len_;
  for (size_t off = 0; off < total; off += frag_) {
    size_t n = (off + frag_ <= total) ? frag_ : total - off;
    OtaFrameHeader h{OtaFrameType::Manifest, session_, kIndexManifest,
                     static_cast<uint16_t>(off), static_cast<uint16_t>(total)};
    emit(h, manifest_bytes_ + off, n);
  }
}

void OtaSeeder::send_block(uint16_t index) {
  if (index >= block_count_)
    return;
  uint32_t base = static_cast<uint32_t>(index) * block_size_;
  uint32_t len =
      (base + block_size_ <= payload_len_) ? block_size_ : payload_len_ - base;
  for (uint32_t off = 0; off < len; off += frag_) {
    uint32_t n =
        (off + frag_ <= len) ? static_cast<uint32_t>(frag_) : len - off;
    OtaFrameHeader h{OtaFrameType::Block, session_, index,
                     static_cast<uint16_t>(off), static_cast<uint16_t>(len)};
    emit(h, payload_ + base + off, n);
  }
}

void OtaSeeder::send_proof(uint16_t index) {
  std::vector<Hash256> proof = merkle_proof(leaves_, index);
  const size_t total = proof.size() * kSha256Len;
  if (total == 0) {
    OtaFrameHeader h{OtaFrameType::Proof, session_, index, 0, 0};
    emit(h, nullptr, 0);
    return;
  }
  std::vector<uint8_t> bytes(total);
  for (size_t i = 0; i < proof.size(); ++i) {
    std::memcpy(bytes.data() + i * kSha256Len, proof[i].bytes, kSha256Len);
  }
  for (size_t off = 0; off < total; off += frag_) {
    size_t n = (off + frag_ <= total) ? frag_ : total - off;
    OtaFrameHeader h{OtaFrameType::Proof, session_, index,
                     static_cast<uint16_t>(off), static_cast<uint16_t>(total)};
    emit(h, bytes.data() + off, n);
  }
}

void OtaSeeder::on_frame(const uint8_t *data, size_t len) {
  if (!valid_)
    return;
  OtaFrameHeader h;
  if (!frame_header_unpack(data, len, h))
    return;
  if (h.session != session_)
    return;

  switch (h.type) {
  case OtaFrameType::Request:
    if (h.index == kIndexManifest) {
      send_manifest();
    } else {
      send_proof(h.index);
      send_block(h.index);
    }
    break;
  case OtaFrameType::Done:
    done_ = true;
    break;
  case OtaFrameType::Abort:
    done_ = true;
    break;
  default:
    break; // Ack is advisory in stop-and-wait
  }
}

} // namespace ota_common
