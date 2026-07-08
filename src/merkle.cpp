#include "ota_common/merkle.h"

#include <cstring>

namespace ota_common {

bool Hash256::operator==(const Hash256 &o) const {
  return std::memcmp(bytes, o.bytes, kSha256Len) == 0;
}

Hash256 hash_leaf(const uint8_t *block, size_t len) {
  Hash256 h;
  Sha256::hash(block, len, h.bytes);
  return h;
}

Hash256 hash_pair(const Hash256 &left, const Hash256 &right) {
  Sha256 s;
  s.update(left.bytes, kSha256Len);
  s.update(right.bytes, kSha256Len);
  Hash256 h;
  s.finish(h.bytes);
  return h;
}

// Reduce one level, promoting an unpaired trailing node.
static std::vector<Hash256> reduce_level(const std::vector<Hash256> &level) {
  std::vector<Hash256> next;
  next.reserve((level.size() + 1) / 2);
  size_t i = 0;
  for (; i + 1 < level.size(); i += 2) {
    next.push_back(hash_pair(level[i], level[i + 1]));
  }
  if (i < level.size())
    next.push_back(level[i]); // promote odd tail
  return next;
}

Hash256 merkle_root(const std::vector<Hash256> &leaves) {
  if (leaves.empty()) {
    Hash256 zero;
    std::memset(zero.bytes, 0, kSha256Len);
    return zero;
  }
  std::vector<Hash256> level = leaves;
  while (level.size() > 1)
    level = reduce_level(level);
  return level[0];
}

std::vector<Hash256> merkle_proof(const std::vector<Hash256> &leaves,
                                  size_t index) {
  std::vector<Hash256> proof;
  if (index >= leaves.size())
    return proof;

  std::vector<Hash256> level = leaves;
  size_t idx = index;
  while (level.size() > 1) {
    const bool idx_is_last_odd =
        (idx == level.size() - 1) && (level.size() % 2 == 1);
    if (!idx_is_last_odd) {
      const size_t sib = (idx % 2 == 0) ? idx + 1 : idx - 1;
      proof.push_back(level[sib]);
    }
    idx /= 2;
    level = reduce_level(level);
  }
  return proof;
}

bool merkle_verify(const Hash256 &leaf, size_t index, size_t leaf_count,
                   const std::vector<Hash256> &proof, const Hash256 &root) {
  if (leaf_count == 0 || index >= leaf_count)
    return false;

  Hash256 h = leaf;
  size_t idx = index;
  size_t count = leaf_count;
  size_t p = 0;
  while (count > 1) {
    const bool idx_is_last_odd = (idx == count - 1) && (count % 2 == 1);
    if (!idx_is_last_odd) {
      if (p >= proof.size())
        return false;
      const Hash256 &sib = proof[p++];
      h = (idx % 2 == 0) ? hash_pair(h, sib) : hash_pair(sib, h);
    }
    idx /= 2;
    count = (count + 1) / 2;
  }
  return p == proof.size() && h == root;
}

bool merkle_verify_block(const uint8_t *block, size_t block_len, size_t index,
                         size_t leaf_count, const std::vector<Hash256> &proof,
                         const Hash256 &root) {
  return merkle_verify(hash_leaf(block, block_len), index, leaf_count, proof,
                       root);
}

} // namespace ota_common
