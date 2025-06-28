#include "wb_hash.h"
#include "hash_internal.h"

error_t wb_hash_start(hash_handle_t *ctx_handle, wb_hash_type_t type)
{
    error_t ret = WB_CRYPTO_INVALID_TYPE;

    switch (type) {
        case WB_HASH_TYPE_SHA1:
            ret = wb_sha1_internal_start(ctx_handle);
            break;
        case WB_HASH_TYPE_SHA224:
            ret = wb_sha224_internal_start(ctx_handle);
            break;
        case WB_HASH_TYPE_SHA256:
            ret = wb_sha256_internal_start(ctx_handle);
            break;
        case WB_HASH_TYPE_SHA384:
            ret = wb_sha384_internal_start(ctx_handle);
            break;
        case WB_HASH_TYPE_SHA512:
            ret = wb_sha512_internal_start(ctx_handle);
            break;
        case WB_HASH_TYPE_BLAKE2B:
            ret = wb_blake2b_internal_start(ctx_handle, 0);
            break;
        case WB_HASH_TYPE_MAX:
            WB_PRINTF("Invalid hash type: %x\n", type);
            return WB_HASH_ERROR(WB_CRYPTO_INVALID_TYPE);
        case WB_HASH_TYPE_INVALID:
            WB_PRINTF("Invalid hash type: %x\n", type);
            return WB_HASH_ERROR(WB_CRYPTO_INVALID_TYPE);
        default:
            WB_PRINTF("Unsupported hash type: %x\n", type);
            return WB_HASH_ERROR(WB_CRYPTO_INVALID_TYPE);
    }

    return ret == WB_CRYPTO_SUCCESS ? WB_CRYPTO_SUCCESS : WB_HASH_ERROR(ret);
}

error_t wb_hash_update(hash_handle_t ctx_handle, const uint8_t *data, size_t data_len)
{
    wb_hash_base_ctx_t *hash_ctx = (wb_hash_base_ctx_t *)ctx_handle;
    if (!is_valid_hash_ctx(hash_ctx)) {
        return WB_HASH_ERROR(WB_CRYPTO_CTX_INVALID);
    }
    WB_CHECK_EMPTY_RETURN(data, WB_HASH_ERROR(WB_CRYPTO_EMPTY_VALUE));

    error_t ret = WB_CRYPTO_SUCCESS;
    size_t process_len = data_len;
    uint32_t space_in_buffer = hash_ctx->block_size - hash_ctx->buffer_len;
    
    if (data_len > space_in_buffer) {
        ret = WB_MEMCPY_S(hash_ctx->buffer_ptr + hash_ctx->buffer_len, space_in_buffer, data, space_in_buffer);
        WB_CHECK_RET_RETURN(ret, WB_HASH_ERROR(WB_CRYPTO_MEMCPY_FAILED));
        hash_ctx->compute_func(hash_ctx, hash_ctx->buffer_ptr);
        process_len -= space_in_buffer;
        hash_ctx->buffer_len = 0;
    } else {
        ret = WB_MEMCPY_S(hash_ctx->buffer_ptr + hash_ctx->buffer_len, space_in_buffer, data, data_len);
        WB_CHECK_RET_RETURN(ret, WB_HASH_ERROR(WB_CRYPTO_MEMCPY_FAILED));
        hash_ctx->buffer_len += data_len;
        return WB_CRYPTO_SUCCESS;
    }

    while (process_len >= hash_ctx->block_size) {
        hash_ctx->compute_func(hash_ctx, data + (data_len - process_len));
        process_len -= hash_ctx->block_size;
    }
    if (process_len > 0) {
        ret = WB_MEMCPY_S(hash_ctx->buffer_ptr, hash_ctx->block_size, data + (data_len - process_len), process_len);
        WB_CHECK_RET_RETURN(ret, WB_HASH_ERROR(WB_CRYPTO_MEMCPY_FAILED));
        hash_ctx->buffer_len += process_len;
    }

    return WB_CRYPTO_SUCCESS;
}

error_t wb_hash_finish(hash_handle_t ctx_handle, uint8_t *digest, size_t digest_len)
{
    wb_hash_base_ctx_t *hash_ctx = (wb_hash_base_ctx_t *)ctx_handle;

    if (!is_valid_hash_ctx(hash_ctx)) {
        return WB_HASH_ERROR(WB_CRYPTO_CTX_INVALID);
    }
    WB_CHECK_EMPTY_RETURN(digest, WB_HASH_ERROR(WB_CRYPTO_EMPTY_VALUE));

    hash_ctx->padding_func(hash_ctx);
    hash_ctx->destroy_func(hash_ctx, digest, digest_len);

    return WB_CRYPTO_SUCCESS;
}

error_t wb_hash_reset(hash_handle_t ctx_handle)
{
    wb_hash_base_ctx_t *hash_ctx = (wb_hash_base_ctx_t *)ctx_handle;

    if (!is_valid_hash_ctx(hash_ctx)) {
        return WB_HASH_ERROR(WB_CRYPTO_CTX_INVALID);
    }
    if (hash_ctx->type > WB_HASH_TYPE_SHA512) {
        return WB_HASH_ERROR(WB_CRYPTO_INVALID_TYPE);
    }

    hash_ctx->reset_func(hash_ctx);
    return WB_CRYPTO_SUCCESS;
}

error_t wb_hash_transform(wb_hash_type_t type, const uint8_t *data, size_t data_len, uint8_t *digest, size_t digest_len)
{
    error_t ret = WB_CRYPTO_SUCCESS;
    hash_handle_t ctx_handle = NULL;

    ret = wb_hash_start(&ctx_handle, type);
    WB_CHECK_RET_RETURN(ret, ret);

    ret = wb_hash_update(ctx_handle, data, data_len);
    WB_CHECK_RET_RETURN(ret, ret);

    ret = wb_hash_finish(ctx_handle, digest, digest_len);
    WB_CHECK_RET_RETURN(ret, ret);

    return WB_CRYPTO_SUCCESS;
}

static error_t wb_blake2b_set_key(wb_hash_base_ctx_t *blake_ctx, const uint8_t *key, size_t key_len)
{
    error_t ret = WB_CRYPTO_SUCCESS;
    if (key_len > 64 || key_len == 0) {
        return WB_CRYPTO_INVALID_PARAM;
    }

    if (key != NULL && key_len > 0) {
        ret = WB_MEMCPY_S(blake_ctx->buffer_ptr, blake_ctx->block_size, key, key_len);
        blake_ctx->buffer_len = key_len;
    }
    return ret;
}

static error_t wb_blake2b_set_digest_length(hash_handle_t *ctx_handle, size_t digest_len)
{
    if (digest_len > 64 || digest_len == 0) {
        return WB_CRYPTO_INVALID_PARAM;
    }
    return wb_blake2b_internal_start((void **)ctx_handle, digest_len);
}

static error_t wb_blake2b_reset(wb_hash_base_ctx_t *blake_ctx, const uint8_t *key, size_t key_len, size_t digest_len)
{
    if (key_len > 64 || digest_len > 64 || digest_len == 0) {
        return WB_CRYPTO_INVALID_PARAM;
    }

    WB_MEMSET_S(blake_ctx->buffer_ptr, blake_ctx->block_size, 0, blake_ctx->block_size);
    if (key != NULL && key_len > 0) {
        WB_MEMCPY_S(blake_ctx->buffer_ptr, blake_ctx->block_size, key, key_len);
        blake_ctx->buffer_len = key_len;
        return wb_blake2b_internal_start((void **)blake_ctx, digest_len);
    } else {
        blake_ctx->buffer_len = 0;
        return wb_blake2b_internal_start((void **)blake_ctx, digest_len);
    }
}

error_t wb_blake_set_key(hash_handle_t ctx_handle, const uint8_t *key, size_t key_len)
{
    error_t ret = WB_CRYPTO_SUCCESS;
    wb_hash_base_ctx_t *blake_ctx = (wb_hash_base_ctx_t *)ctx_handle;

    WB_CHECK_EMPTY_RETURN(key, WB_HASH_ERROR(WB_CRYPTO_EMPTY_VALUE));
    
    switch (blake_ctx->type) {
        case WB_HASH_TYPE_BLAKE2B:
            ret = wb_blake2b_set_key(blake_ctx, key, key_len);
            break;
        default:
            return WB_HASH_ERROR(WB_CRYPTO_INVALID_TYPE);
    }

    return ret == WB_CRYPTO_SUCCESS ? WB_CRYPTO_SUCCESS : WB_HASH_ERROR(ret);
}

error_t wb_blake_set_digest_length(hash_handle_t *ctx_handle, size_t digest_len)
{
    wb_hash_base_ctx_t *blake_ctx = (wb_hash_base_ctx_t *)*ctx_handle;
    switch (blake_ctx->type) {
        case WB_HASH_TYPE_BLAKE2B:
            return wb_blake2b_set_digest_length(ctx_handle, digest_len);
        default:
            return WB_HASH_ERROR(WB_CRYPTO_INVALID_TYPE);
    }
}

error_t wb_blake_reset(hash_handle_t *ctx_handle, const uint8_t *key, size_t key_len, size_t digest_len)
{
    error_t ret = WB_CRYPTO_SUCCESS;
    wb_hash_base_ctx_t *blake_ctx = (wb_hash_base_ctx_t *)ctx_handle;
    
    switch (blake_ctx->type) {
        case WB_HASH_TYPE_BLAKE2B:
            ret = wb_blake2b_reset(blake_ctx, key, key_len, digest_len);
            break;
        default:
            return WB_HASH_ERROR(WB_CRYPTO_INVALID_TYPE);
    }

    return ret == WB_CRYPTO_SUCCESS ? WB_CRYPTO_SUCCESS : WB_HASH_ERROR(ret);
}

error_t wb_hash_blake_transform(wb_hash_type_t type, const uint8_t *data, size_t data_len,
    const uint8_t *key, size_t key_len, uint8_t *digest, size_t digest_len)
{
    if (type != WB_HASH_TYPE_BLAKE2B) {
        return WB_HASH_ERROR(WB_CRYPTO_INVALID_TYPE);
    }

    error_t ret = WB_CRYPTO_SUCCESS;
    hash_handle_t ctx_handle = NULL;

    ret = wb_hash_start(&ctx_handle, type);
    WB_CHECK_RET_RETURN(ret, ret);

    if (key != NULL && key_len > 0) {
        ret = wb_blake_set_key(ctx_handle, key, key_len);
        WB_CHECK_RET_RETURN(ret, ret);
    }

    ret = wb_blake_set_digest_length(&ctx_handle, digest_len);
    WB_CHECK_RET_RETURN(ret, ret);

    ret = wb_hash_update(ctx_handle, data, data_len);
    WB_CHECK_RET_RETURN(ret, ret);

    ret = wb_hash_finish(ctx_handle, digest, digest_len);
    WB_CHECK_RET_RETURN(ret, ret);

    return WB_CRYPTO_SUCCESS;
}