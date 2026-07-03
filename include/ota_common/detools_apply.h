// Thin C++ wrapper over the vendored detools decoder. Reconstructs an output
// image from a random-access base (the current firmware) and a contiguous
// patch buffer (the received delta), writing the output sequentially to a sink.
// Decoder-only: the codec is never reimplemented here.
#pragma once

#include <cstddef>
#include <cstdint>

#include "ota_common/esp_image.h"    // IImageReader
#include "ota_common/flash_target.h" // IFlashTarget

namespace ota_common {

// Sequential output sink for the reconstructed image (a flash target, a buffer).
struct IByteSink {
    virtual ~IByteSink() = default;
    // Return false to abort the apply (e.g. flash write error).
    virtual bool write(const uint8_t* data, size_t len) = 0;
};

// Adapts an IFlashTarget into an IByteSink: the detools decoder writes the
// reconstructed image sequentially, forwarded to the target at a running offset.
// The caller must have already called target.begin(); after the apply, call
// target.commit() to run the hard output-hash gate and activate.
class FlashTargetByteSink final : public IByteSink {
public:
    explicit FlashTargetByteSink(IFlashTarget& target) : target_(target) {}
    bool write(const uint8_t* data, size_t len) override {
        if (target_.write(offset_, data, len) != FlashStatus::Ok) return false;
        offset_ += static_cast<uint32_t>(len);
        return true;
    }
    uint32_t bytes_written() const { return offset_; }

private:
    IFlashTarget& target_;
    uint32_t offset_ = 0;
};

// Apply `patch` (a full detools delta) against `base`, writing the reconstructed
// image to `sink`. Returns the output size in bytes on success, or a negative
// detools error code (see detools_apply_error_string). This is the Path B model
// (base and destination are different partitions).
int detools_apply(IImageReader& base, const uint8_t* patch, size_t patch_len, IByteSink& sink);

// ---- Path A: in-place delta apply ------------------------------------------
//
// Patches a single flash region against itself (base == destination == ota_0),
// which is what a 4 MB board must do (no spare slot). detools' in-place format
// processes the region in segments so a byte is only overwritten after it has
// been consumed; a step journal makes it resumable across reboot.

// Random-access flash memory (the ota_0 partition). Addresses are region-local
// byte offsets. Each call returns 0 on success or a negative value on error.
struct IFlashMem {
    virtual ~IFlashMem() = default;
    virtual int read(uintptr_t src, void* dst, size_t len) = 0;
    virtual int write(uintptr_t dst, const void* src, size_t len) = 0;
    virtual int erase(uintptr_t addr, size_t len) = 0;
};

// Forward-only resume journal: detools persists the current step here after each
// segment, and reads it back to resume. Persist it to flash/NVS so it survives a
// reboot; get_step must return 0 (start) when nothing was ever set.
struct IStepJournal {
    virtual ~IStepJournal() = default;
    virtual int set_step(int step) = 0;
    virtual int get_step(int* step) = 0;
};

// Apply an in-place detools patch to the flash region behind `mem`, journaling
// progress via `journal`. Returns the reconstructed (to) size on success, or a
// negative detools error code.
int detools_apply_in_place(IFlashMem& mem, IStepJournal& journal, const uint8_t* patch,
                           size_t patch_len);

// Human-readable string for a negative code returned by either apply function.
const char* detools_apply_error_string(int code);

} // namespace ota_common
