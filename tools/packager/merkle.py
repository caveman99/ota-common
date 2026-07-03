"""Merkle tree matching ota-common/src/merkle.cpp byte-for-byte.

Conventions:
  - leaf[i]  = SHA-256(block_i)
  - internal = SHA-256(left || right)
  - odd level: the unpaired trailing node is promoted unchanged.
  - a proof lists only real siblings, leaf -> root; promotion contributes none.
"""

from __future__ import annotations

import hashlib
from typing import List


def hash_leaf(block: bytes) -> bytes:
    return hashlib.sha256(block).digest()


def hash_pair(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(left + right).digest()


def _reduce(level: List[bytes]) -> List[bytes]:
    out: List[bytes] = []
    i = 0
    while i + 1 < len(level):
        out.append(hash_pair(level[i], level[i + 1]))
        i += 2
    if i < len(level):
        out.append(level[i])  # promote odd tail
    return out


def leaves_for(payload: bytes, block_size: int) -> List[bytes]:
    leaves = []
    for off in range(0, len(payload), block_size):
        leaves.append(hash_leaf(payload[off : off + block_size]))
    return leaves


def merkle_root(leaves: List[bytes]) -> bytes:
    if not leaves:
        return b"\x00" * 32
    level = list(leaves)
    while len(level) > 1:
        level = _reduce(level)
    return level[0]


def merkle_proof(leaves: List[bytes], index: int) -> List[bytes]:
    proof: List[bytes] = []
    if index >= len(leaves):
        return proof
    level = list(leaves)
    idx = index
    while len(level) > 1:
        is_last_odd = (idx == len(level) - 1) and (len(level) % 2 == 1)
        if not is_last_odd:
            sib = idx + 1 if idx % 2 == 0 else idx - 1
            proof.append(level[sib])
        idx //= 2
        level = _reduce(level)
    return proof


def merkle_verify(leaf: bytes, index: int, leaf_count: int, proof: List[bytes], root: bytes) -> bool:
    if leaf_count == 0 or index >= leaf_count:
        return False
    h = leaf
    idx = index
    count = leaf_count
    p = 0
    while count > 1:
        is_last_odd = (idx == count - 1) and (count % 2 == 1)
        if not is_last_odd:
            if p >= len(proof):
                return False
            sib = proof[p]
            p += 1
            h = hash_pair(h, sib) if idx % 2 == 0 else hash_pair(sib, h)
        idx //= 2
        count = (count + 1) // 2
    return p == len(proof) and h == root
