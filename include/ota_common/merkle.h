// Merkle tree over fixed-size image blocks. The manifest carries the root; the
// transport delivers each 1 KB logical block with a proof so the receiver can
// verify and commit blocks independently and out of order.
//
// Conventions (the Python packager must match byte-for-byte):
//  - leaf[i]      = SHA-256(block_i bytes); the final block may be short.
//  - internal     = SHA-256(left || right).
//  - odd level    : the unpaired last node is PROMOTED unchanged to the next
//                   level (no self-duplication; avoids the CVE-2012-2459 class).
//  - a proof lists only real siblings, leaf -> root; promotion steps contribute
//    nothing. The verifier reconstructs tree shape from (index, leaf_count).
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "ota_common/sha256.h"

namespace ota_common {

struct Hash256 {
    uint8_t bytes[kSha256Len];
    bool operator==(const Hash256& o) const;
    bool operator!=(const Hash256& o) const { return !(*this == o); }
};

Hash256 hash_leaf(const uint8_t* block, size_t len);
Hash256 hash_pair(const Hash256& left, const Hash256& right);

// Compute the merkle root over an ordered list of leaf hashes. Empty input
// yields an all-zero hash.
Hash256 merkle_root(const std::vector<Hash256>& leaves);

// Build the proof (sibling hashes, leaf -> root) for leaf `index` of
// `leaf_count`. Promotion steps are omitted. Returns empty for a single leaf.
std::vector<Hash256> merkle_proof(const std::vector<Hash256>& leaves, size_t index);

// Verify that `leaf` at `index` within a tree of `leaf_count` leaves, folded
// with `proof`, reproduces `root`.
bool merkle_verify(const Hash256& leaf, size_t index, size_t leaf_count,
                   const std::vector<Hash256>& proof, const Hash256& root);

// Convenience: hash a block and verify it against the root in one call.
bool merkle_verify_block(const uint8_t* block, size_t block_len, size_t index,
                         size_t leaf_count, const std::vector<Hash256>& proof,
                         const Hash256& root);

} // namespace ota_common
