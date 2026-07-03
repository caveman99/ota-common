/*
 * Unity translation unit: compiles the vendored detools decoder as part of
 * ota-common, with the config fixed here so no consumer needs special build
 * flags. Decoder-only usage:
 *   - FILE_IO off      (no stdio-file apply variants)
 *   - LZMA off         (avoids the external liblzma dependency)
 *   - NONE/CRLE/HEATSHRINK on (self-contained; heatshrink is vendored alongside)
 *
 * The detools sources are unmodified upstream (see third_party/detools/LICENSE).
 */
#define DETOOLS_CONFIG_FILE_IO 0
#define DETOOLS_CONFIG_COMPRESSION_LZMA 0

#include "../third_party/detools/detools.c"
