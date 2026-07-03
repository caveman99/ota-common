/*
 * Unity translation unit: vendored public-domain TweetNaCl plus an XEdDSA verify
 * built from its primitives. See third_party/tweetnacl/PROVENANCE.txt.
 *
 * ota_xeddsa_verify_raw converts a Curve25519 public key to Ed25519 via the RFC
 * 7748 birational map (matching CryptoEngine::curve_to_ed_pub) and then verifies
 * a standard Ed25519 signature (crypto_sign_open). This lets the bare-IDF Path A
 * loader and the host tests verify admin-key signatures without the firmware's
 * CryptoEngine.
 */
#include <string.h>

#include "../third_party/tweetnacl/tweetnacl.c"

/* Longest signed message this verifier accepts: the OTA signing buffer is a
 * 12-byte header + the 192-byte manifest = 204; 256 mirrors the firmware's
 * MAX_BLOCKSIZE with headroom. */
#define OTA_XEDDSA_MAX_MSG 256

/* randombytes is referenced only by key generation, which this project never
 * calls. Stub it; it must never be used to generate keys. */
void randombytes(unsigned char *p, unsigned long long n) {
    while (n--) {
        *p++ = 0;
    }
}

/* Verify an XEdDSA signature `sig` (64 bytes) over `msg` using the 32-byte
 * Curve25519 public key `curve_pub`. Returns 1 on success, 0 otherwise. */
int ota_xeddsa_verify_raw(const unsigned char *curve_pub, const unsigned char *msg,
                          unsigned long msg_len, const unsigned char *sig) {
    if (msg_len > OTA_XEDDSA_MAX_MSG) {
        return 0;
    }

    /* Curve25519 (Montgomery u) -> Ed25519 public key: y = (u-1)/(u+1), sign
     * bit cleared (XEdDSA normalizes the sign to zero). Uses TweetNaCl's field
     * ops, which are file-static and in scope via the include above. */
    gf u, one, um1, up1, up1inv, y;
    unsigned char ed_pub[32];
    unsigned int i;
    for (i = 0; i < 16; ++i) {
        one[i] = 0;
    }
    one[0] = 1;
    unpack25519(u, curve_pub);
    Z(um1, u, one);
    A(up1, u, one);
    inv25519(up1inv, up1);
    M(y, um1, up1inv);
    pack25519(ed_pub, y);
    ed_pub[31] &= 0x7f;

    /* Standard Ed25519 verify: crypto_sign_open checks a signed message
     * sm = sig || msg and recovers msg on success. */
    unsigned char sm[64 + OTA_XEDDSA_MAX_MSG];
    unsigned char recovered[64 + OTA_XEDDSA_MAX_MSG];
    unsigned long long recovered_len = 0;
    memcpy(sm, sig, 64);
    memcpy(sm + 64, msg, msg_len);
    if (crypto_sign_open(recovered, &recovered_len, sm, (unsigned long long)(64 + msg_len),
                         ed_pub) != 0) {
        return 0;
    }
    return recovered_len == msg_len ? 1 : 0;
}
