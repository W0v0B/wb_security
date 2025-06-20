#ifndef WB_HASH_STRUCT_H
#define WB_HASH_STRUCT_H

#include "common/wb_type.h"

#define WB_HASH_CTX_MAGIC 0xDEADBEEF

typedef void* hash_handle_t;

// 算法类型枚举
typedef enum {
    WB_HASH_TYPE_SHA1,
    WB_HASH_TYPE_SHA224,
    WB_HASH_TYPE_SHA256,
    WB_HASH_TYPE_SHA384,
    WB_HASH_TYPE_SHA512,
    WB_HASH_TYPE_MAX,
    WB_HASH_TYPE_INVALID = 0xFF
} wb_hash_type_t;

typedef struct wb_hash_base_ctx_t wb_hash_base_ctx_t;
typedef void (*hash_compute_func_t)(void *ctx, const uint8_t *block);
typedef void (*hash_padding_func_t)(void *ctx);
typedef void (*hash_destroy_func_t)(void *ctx, uint8_t *digest);

struct wb_hash_base_ctx_t{
    uint32_t magic;
    wb_hash_type_t type;
    uint32_t block_size;
    uint32_t buffer_len;
    uint8_t *buffer_ptr;
    hash_compute_func_t compute_func;
    hash_padding_func_t padding_func;
    hash_destroy_func_t destroy_func;
};

#endif // WB_HASH_STRUCT_H