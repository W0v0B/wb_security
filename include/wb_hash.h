#ifndef WB_SHA1_H
#define WB_SHA1_H

#include "common/wb_common.h"

typedef enum {
    WB_HASH_TYPE_SHA1,
    WB_HASH_TYPE_SHA224,
    WB_HASH_TYPE_SHA256,
    WB_HASH_TYPE_SHA384,
    WB_HASH_TYPE_SHA512,
    WB_HASH_TYPE_MAX,
    WB_HASH_TYPE_INVALID = 0xFF
} wb_hash_type_t;

typedef void* hash_handle_t;

error_t wb_hash_start(hash_handle_t *ctx_handle, wb_hash_type_t type);

error_t wb_hash_update(hash_handle_t ctx_handle, const uint8_t *data, size_t data_len);

error_t wb_hash_finish(hash_handle_t ctx_handle, uint8_t *digest, size_t digest_len);

error_t wb_hash_transform(wb_hash_type_t type, const uint8_t *data, size_t data_len, uint8_t *digest, size_t digest_len);

error_t wb_hash_reset(hash_handle_t ctx_handle);

#endif // WB_SHA1_H