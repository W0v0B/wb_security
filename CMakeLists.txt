# ---------------------------------------
# This file is project wb_security
# ---------------------------------------

cmake_minimum_required(VERSION 3.10)

project(MyCryptoProject C)

add_subdirectory(utils/secure_memory)

add_subdirectory(src)
add_subdirectory(test)