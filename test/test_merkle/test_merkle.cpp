#include <unity.h>

#include <vector>

#include "ota_common/merkle.h"
#include "test_helpers.h"

using namespace ota_common;

void setUp() {}
void tearDown() {}

// Build leaf hashes for `count` blocks of `block_size` bytes from a PRNG.
static std::vector<std::vector<uint8_t>> make_blocks(size_t count,
                                                     size_t block_size) {
  std::vector<std::vector<uint8_t>> blocks;
  for (size_t i = 0; i < count; ++i) {
    blocks.push_back(
        ota_test::prng_bytes(block_size, 0x1000 + static_cast<uint32_t>(i)));
  }
  return blocks;
}

static std::vector<Hash256>
leaves_of(const std::vector<std::vector<uint8_t>> &blocks) {
  std::vector<Hash256> leaves;
  for (const auto &b : blocks)
    leaves.push_back(hash_leaf(b.data(), b.size()));
  return leaves;
}

static void test_single_leaf() {
  auto blocks = make_blocks(1, 64);
  auto leaves = leaves_of(blocks);
  Hash256 root = merkle_root(leaves);
  TEST_ASSERT_TRUE(root == leaves[0]); // root of one leaf is the leaf
  auto proof = merkle_proof(leaves, 0);
  TEST_ASSERT_EQUAL_UINT32(0, proof.size());
  TEST_ASSERT_TRUE(merkle_verify(leaves[0], 0, 1, proof, root));
}

static void test_empty_root_is_zero() {
  std::vector<Hash256> empty;
  Hash256 root = merkle_root(empty);
  Hash256 zero;
  std::memset(zero.bytes, 0, kSha256Len);
  TEST_ASSERT_TRUE(root == zero);
}

// For every leaf count 1..33 and every index, the generated proof must verify
// and the block-based helper must agree. Exercises even and odd (promotion)
// levels at every depth.
static void test_all_indices_verify() {
  for (size_t count = 1; count <= 33; ++count) {
    auto blocks = make_blocks(count, 100);
    auto leaves = leaves_of(blocks);
    Hash256 root = merkle_root(leaves);
    for (size_t i = 0; i < count; ++i) {
      auto proof = merkle_proof(leaves, i);
      TEST_ASSERT_TRUE_MESSAGE(merkle_verify(leaves[i], i, count, proof, root),
                               "leaf proof must verify");
      TEST_ASSERT_TRUE_MESSAGE(merkle_verify_block(blocks[i].data(),
                                                   blocks[i].size(), i, count,
                                                   proof, root),
                               "block proof must verify");
    }
  }
}

static void test_wrong_block_fails() {
  auto blocks = make_blocks(7, 100);
  auto leaves = leaves_of(blocks);
  Hash256 root = merkle_root(leaves);
  auto proof = merkle_proof(leaves, 3);
  auto corrupt = blocks[3];
  corrupt[0] ^= 0x01;
  TEST_ASSERT_FALSE(
      merkle_verify_block(corrupt.data(), corrupt.size(), 3, 7, proof, root));
}

static void test_wrong_index_fails() {
  auto blocks = make_blocks(8, 100);
  auto leaves = leaves_of(blocks);
  Hash256 root = merkle_root(leaves);
  auto proof = merkle_proof(leaves, 2);
  // Correct leaf, correct proof, but claimed at the wrong index.
  TEST_ASSERT_FALSE(merkle_verify(leaves[2], 5, 8, proof, root));
}

static void test_tampered_proof_fails() {
  auto blocks = make_blocks(9, 100);
  auto leaves = leaves_of(blocks);
  Hash256 root = merkle_root(leaves);
  auto proof = merkle_proof(leaves, 4);
  TEST_ASSERT_TRUE(proof.size() > 0);
  proof[0].bytes[0] ^= 0xFF;
  TEST_ASSERT_FALSE(merkle_verify(leaves[4], 4, 9, proof, root));
}

static void test_extra_proof_element_fails() {
  auto blocks = make_blocks(4, 100);
  auto leaves = leaves_of(blocks);
  Hash256 root = merkle_root(leaves);
  auto proof = merkle_proof(leaves, 1);
  proof.push_back(leaves[0]); // surplus element
  TEST_ASSERT_FALSE(merkle_verify(leaves[1], 1, 4, proof, root));
}

static void test_short_proof_fails() {
  auto blocks = make_blocks(4, 100);
  auto leaves = leaves_of(blocks);
  Hash256 root = merkle_root(leaves);
  auto proof = merkle_proof(leaves, 1);
  TEST_ASSERT_TRUE(proof.size() >= 1);
  proof.pop_back();
  TEST_ASSERT_FALSE(merkle_verify(leaves[1], 1, 4, proof, root));
}

static void test_index_out_of_range() {
  auto blocks = make_blocks(4, 100);
  auto leaves = leaves_of(blocks);
  Hash256 root = merkle_root(leaves);
  auto proof = merkle_proof(leaves, 0);
  TEST_ASSERT_FALSE(
      merkle_verify(leaves[0], 4, 4, proof, root)); // index == count
  TEST_ASSERT_FALSE(merkle_verify(leaves[0], 0, 0, proof, root)); // empty tree
}

// Different last-block size (short final block) still verifies.
static void test_short_final_block() {
  std::vector<std::vector<uint8_t>> blocks = make_blocks(4, 1024);
  blocks.push_back(ota_test::prng_bytes(37, 0xBEEF)); // 5th, short block
  auto leaves = leaves_of(blocks);
  Hash256 root = merkle_root(leaves);
  auto proof = merkle_proof(leaves, 4);
  TEST_ASSERT_TRUE(merkle_verify_block(blocks[4].data(), blocks[4].size(), 4, 5,
                                       proof, root));
}

int main() {
  UNITY_BEGIN();
  RUN_TEST(test_single_leaf);
  RUN_TEST(test_empty_root_is_zero);
  RUN_TEST(test_all_indices_verify);
  RUN_TEST(test_wrong_block_fails);
  RUN_TEST(test_wrong_index_fails);
  RUN_TEST(test_tampered_proof_fails);
  RUN_TEST(test_extra_proof_element_fails);
  RUN_TEST(test_short_proof_fails);
  RUN_TEST(test_index_out_of_range);
  RUN_TEST(test_short_final_block);
  return UNITY_END();
}
