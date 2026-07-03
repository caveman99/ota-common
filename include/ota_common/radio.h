// Radio seam. The transport FSM speaks in whole frames; each consumer injects
// its own radio (RadioLib in the Path A loader, RadioInterface in Path B main
// firmware). No routing, no mesh: a single point-to-point OTA RF profile.
#pragma once

#include <cstddef>
#include <cstdint>

namespace ota_common {

// One OTA RF profile (the session preset, applied for the maintenance window
// then reverted). Frequency is explicit, independent of region/preset slot
// derivation; band is per-profile so 2.4 GHz SX128x boards work too.
struct RfProfile {
    float frequency_mhz; // explicit center, e.g. 869.525 (EU868 g3) or 2.4 GHz
    float bandwidth_khz; // e.g. 250 (EU Short Fast), 500 (US Short Turbo)
    uint8_t spreading_factor; // e.g. 7
    uint8_t coding_rate;      // 5 == 4:5
    int8_t tx_power_dbm;
    uint8_t sync_word;
    bool duty_cycle_limited;  // true under EU868 g3 10% rolling-hour
};

struct IRadio {
    virtual ~IRadio() = default;

    // Apply the OTA session profile (RAM-only, never persisted) and revert it.
    virtual bool apply_profile(const RfProfile& profile) = 0;
    virtual void revert_profile() = 0;

    // Send one frame. Returns false on transmit error / duty-cycle refusal.
    virtual bool send(const uint8_t* data, size_t len) = 0;

    // Poll for a received frame. Returns the number of bytes written to dst, 0
    // if none available, or a negative value on error. Non-blocking.
    virtual int receive(uint8_t* dst, size_t cap) = 0;
};

} // namespace ota_common
