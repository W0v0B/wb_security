#ifndef WB_SHA1_H
#define WB_SHA1_H

#include "common/wb_common.h"

typedef enum {
    WB_HASH_TYPE_SHA1,
    WB_HASH_TYPE_SHA224,
    WB_HASH_TYPE_SHA256,
    WB_HASH_TYPE_SHA384,
    WB_HASH_TYPE_SHA512,
    WB_HASH_TYPE_BLAKE2S,
    WB_HASH_TYPE_BLAKE2B,
    WB_HASH_TYPE_MAX,
    WB_HASH_TYPE_INVALID = 0xFF
} wb_hash_type_t;

typedef void* hash_handle_t;

error_t wb_hash_start(hash_handle_t *ctx_handle, wb_hash_type_t type);

error_t wb_hash_update(hash_handle_t ctx_handle, const uint8_t *data, size_t data_len);

error_t wb_hash_finish(hash_handle_t ctx_handle, uint8_t *digest, size_t digest_len);

error_t wb_hash_transform(wb_hash_type_t type, const uint8_t *data, size_t data_len, uint8_t *digest, size_t digest_len);

error_t wb_hash_reset(hash_handle_t ctx_handle);

error_t wb_blake_set_key(hash_handle_t ctx_handle, const uint8_t *key, size_t key_len);

error_t wb_blake_set_digest_length(hash_handle_t *ctx_handle, size_t digest_len);

error_t wb_blake_reset(hash_handle_t *ctx_handle, const uint8_t *key, size_t key_len, size_t digest_len);

error_t wb_hash_blake_transform(wb_hash_type_t type, const uint8_t *data, size_t data_len,
    const uint8_t *key, size_t key_len, uint8_t *digest, size_t digest_len);

#endif // WB_SHA1_H