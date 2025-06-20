# ---------------------------------------
# CMakeLists.txt for the test directory
# ---------------------------------------

add_executable(cipher_test main_app.c)

target_link_libraries(cipher_test PRIVATE crypto_core)