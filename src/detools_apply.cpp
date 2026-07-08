#include "ota_common/detools_apply.h"

#include <cstring>

// Same config as the vendored TU so the declarations match.
#define DETOOLS_CONFIG_FILE_IO 0
#define DETOOLS_CONFIG_COMPRESSION_LZMA 0
extern "C" {
#include "../third_party/detools/detools.h"
}

namespace ota_common {

namespace {

struct ApplyCtx {
  IImageReader *base;
  size_t base_pos;
  const uint8_t *patch;
  size_t patch_len;
  size_t patch_pos;
  IByteSink *sink;
};

// detools callbacks return 0 on success, negative on error.

int cb_from_read(void *arg, uint8_t *buf, size_t size) {
  auto *c = static_cast<ApplyCtx *>(arg);
  if (!c->base->read(c->base_pos, buf, size))
    return -DETOOLS_IO_FAILED;
  c->base_pos += size;
  return 0;
}

int cb_from_seek(void *arg, int offset) {
  auto *c = static_cast<ApplyCtx *>(arg);
  long p = static_cast<long>(c->base_pos) + offset; // offset is relative
  if (p < 0)
    return -DETOOLS_IO_FAILED;
  c->base_pos = static_cast<size_t>(p);
  return 0;
}

int cb_patch_read(void *arg, uint8_t *buf, size_t size) {
  auto *c = static_cast<ApplyCtx *>(arg);
  if (size > c->patch_len - c->patch_pos)
    return -DETOOLS_IO_FAILED;
  std::memcpy(buf, c->patch + c->patch_pos, size);
  c->patch_pos += size;
  return 0;
}

int cb_to_write(void *arg, const uint8_t *buf, size_t size) {
  auto *c = static_cast<ApplyCtx *>(arg);
  return c->sink->write(buf, size) ? 0 : -DETOOLS_IO_FAILED;
}

} // namespace

int detools_apply(IImageReader &base, const uint8_t *patch, size_t patch_len,
                  IByteSink &sink) {
  ApplyCtx ctx{&base, 0, patch, patch_len, 0, &sink};
  return detools_apply_patch_callbacks(
      cb_from_read, cb_from_seek, cb_patch_read, patch_len, cb_to_write, &ctx);
}

namespace {

struct InPlaceCtx {
  IFlashMem *mem;
  IStepJournal *journal;
  const uint8_t *patch;
  size_t patch_len;
  size_t patch_pos;
};

int cb_mem_read(void *arg, void *dst, uintptr_t src, size_t size) {
  auto *c = static_cast<InPlaceCtx *>(arg);
  return c->mem->read(src, dst, size);
}

int cb_mem_write(void *arg, uintptr_t dst, void *src, size_t size) {
  auto *c = static_cast<InPlaceCtx *>(arg);
  return c->mem->write(dst, src, size);
}

int cb_mem_erase(void *arg, uintptr_t addr, size_t size) {
  auto *c = static_cast<InPlaceCtx *>(arg);
  return c->mem->erase(addr, size);
}

int cb_step_set(void *arg, int step) {
  auto *c = static_cast<InPlaceCtx *>(arg);
  return c->journal->set_step(step);
}

int cb_step_get(void *arg, int *step) {
  auto *c = static_cast<InPlaceCtx *>(arg);
  return c->journal->get_step(step);
}

int cb_inplace_patch_read(void *arg, uint8_t *buf, size_t size) {
  auto *c = static_cast<InPlaceCtx *>(arg);
  if (size > c->patch_len - c->patch_pos)
    return -DETOOLS_IO_FAILED;
  std::memcpy(buf, c->patch + c->patch_pos, size);
  c->patch_pos += size;
  return 0;
}

} // namespace

int detools_apply_in_place(IFlashMem &mem, IStepJournal &journal,
                           const uint8_t *patch, size_t patch_len) {
  InPlaceCtx ctx{&mem, &journal, patch, patch_len, 0};
  return detools_apply_patch_in_place_callbacks(
      cb_mem_read, cb_mem_write, cb_mem_erase, cb_step_set, cb_step_get,
      cb_inplace_patch_read, patch_len, &ctx);
}

const char *detools_apply_error_string(int code) {
  return detools_error_as_string(code);
}

} // namespace ota_common
