# ---------------------------------------
# This file is part of the wb_security project.
# ---------------------------------------

file(GLOB_RECURSE LIB_SRCS "*.c")

add_library(crypto_core STATIC ${LIB_SRCS})

target_include_directories(crypto_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(crypto_core PUBLIC secure_utils)