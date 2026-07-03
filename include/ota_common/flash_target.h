// The one platform-specific seam of the apply path. The detools decoder writes
// reconstructed image bytes through write(); the protocol/apply code above is
// identical for the in-place apply (CRLE -> ota_0) and the inactive-slot apply.
#pragma once

#include <cstddef>
#include <cstdint>

#include "ota_common/manifest.h"

namespace ota_common {

enum class FlashStatus { Ok, OutOfRange, WriteError, VerifyFailed, NotReady };

// Sink for the reconstructed output image. Implementations:
//   InPlaceCrleTarget:  detools in-place/CRLE into ota_0, forward journal for
//                       resume (boards with a single firmware slot).
//   InactiveSlotTarget: detools normal mode into the inactive slot,
//                       esp_ota_set_boot_partition + IDF rollback (A/B boards).
struct IFlashTarget {
    virtual ~IFlashTarget() = default;

    // Prepare to receive an image of expected_output_size, described by the
    // (already signature- and identity-verified) manifest.
    virtual FlashStatus begin(uint32_t expected_output_size, const Manifest& manifest) = 0;

    // Write len bytes of the reconstructed output at byte offset. Offsets may
    // be sequential (normal mode) or in-place; implementations handle their own
    // ordering constraints.
    virtual FlashStatus write(uint32_t offset, const uint8_t* bytes, size_t len) = 0;

    // Verify the reconstructed image hash against the manifest's hard output
    // gate, then activate (set boot partition / arm swap). Must not activate if
    // the hash does not match.
    virtual FlashStatus commit() = 0;

    // Abort an in-progress apply and release resources.
    virtual void abort() = 0;
};

} // namespace ota_common
