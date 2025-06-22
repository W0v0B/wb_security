
add_library(secure_utils STATIC wb_secure_utils.c)

target_include_directories(secure_utils PUBLIC
    ${PROJECT_SOURCE_DIR}/utils
)