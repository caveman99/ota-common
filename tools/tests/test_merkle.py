"""Merkle parity with the C++ implementation: proofs verify for every index and
leaf count, tampering is caught, and the root is stable."""

from packager import merkle


def _blocks(count, size, seed=1):
    out = []
    x = seed
    for _ in range(count):
        b = bytearray(size)
        for i in range(size):
            x = (1103515245 * x + 12345) & 0xFFFFFFFF
            b[i] = (x >> 16) & 0xFF
        out.append(bytes(b))
    return out


def test_single_leaf_root_is_leaf():
    blocks = _blocks(1, 64)
    leaves = [merkle.hash_leaf(b) for b in blocks]
    assert merkle.merkle_root(leaves) == leaves[0]
    assert merkle.merkle_proof(leaves, 0) == []
    assert merkle.merkle_verify(leaves[0], 0, 1, [], merkle.merkle_root(leaves))


def test_empty_root_is_zero():
    assert merkle.merkle_root([]) == b"\x00" * 32


def test_all_indices_verify():
    for count in range(1, 34):
        blocks = _blocks(count, 100, seed=count)
        leaves = [merkle.hash_leaf(b) for b in blocks]
        root = merkle.merkle_root(leaves)
        for i in range(count):
            proof = merkle.merkle_proof(leaves, i)
            assert merkle.merkle_verify(leaves[i], i, count, proof, root)


def test_wrong_block_fails():
    blocks = _blocks(7, 100)
    leaves = [merkle.hash_leaf(b) for b in blocks]
    root = merkle.merkle_root(leaves)
    proof = merkle.merkle_proof(leaves, 3)
    bad = merkle.hash_leaf(blocks[3] + b"x")
    assert not merkle.merkle_verify(bad, 3, 7, proof, root)


def test_wrong_index_fails():
    blocks = _blocks(8, 100)
    leaves = [merkle.hash_leaf(b) for b in blocks]
    root = merkle.merkle_root(leaves)
    proof = merkle.merkle_proof(leaves, 2)
    assert not merkle.merkle_verify(leaves[2], 5, 8, proof, root)


def test_tampered_proof_fails():
    blocks = _blocks(9, 100)
    leaves = [merkle.hash_leaf(b) for b in blocks]
    root = merkle.merkle_root(leaves)
    proof = merkle.merkle_proof(leaves, 4)
    proof[0] = bytes([proof[0][0] ^ 0xFF]) + proof[0][1:]
    assert not merkle.merkle_verify(leaves[4], 4, 9, proof, root)


def test_root_is_deterministic():
    blocks = _blocks(5, 200)
    leaves = [merkle.hash_leaf(b) for b in blocks]
    assert merkle.merkle_root(leaves) == merkle.merkle_root(list(leaves))
