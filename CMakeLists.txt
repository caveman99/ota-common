# Self-registering ESP-IDF component for ota-common.
#
# This lets ota-common be consumed as an ESP-IDF component with no wrapper: add
# it as a git submodule under a consumer's components/ (the submodule checkout
# dir name becomes the component name, e.g. components/ota_common), or point
# EXTRA_COMPONENT_DIRS straight at this directory. The framework-agnostic sources
# are the same ones the host tests (platformio.ini / native) and the Arduino/
# PlatformIO library (library.json) build -- one source of truth, three manifests.
#
# Guard: only meaningful inside an ESP-IDF build. When ota-common is pulled into
# a PlatformIO build via lib_extra_dirs (LDF, library.json), this file is ignored
# by the LDF, so there is no double-registration.
if(NOT ESP_PLATFORM)
    return()
endif()

# .cpp core + the vendored detools/heatshrink/tweetnacl unity .c TUs (src/vendor_*.c).
# GLOB (not an explicit list) so adding a source needs no edit here; matches the
# thin wrapper this replaces. Re-run `idf.py reconfigure` after adding files.
file(GLOB OTA_COMMON_SRCS "${CMAKE_CURRENT_LIST_DIR}/src/*.cpp" "${CMAKE_CURRENT_LIST_DIR}/src/*.c")

idf_component_register(
    SRCS ${OTA_COMMON_SRCS}
    INCLUDE_DIRS "include"
)

# C++17, no exceptions/RTTI to keep the standalone loader small (640 KiB ceiling).
# PRIVATE: applies to ota-common's own TUs only, never a consumer's.
target_compile_options(${COMPONENT_LIB} PRIVATE -std=gnu++17 -fno-exceptions -fno-rtti)
