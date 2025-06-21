#include "wb_hash.h"
#include "hash_internal.h"

error_t wb_hash_start(hash_handle_t *ctx_handle, wb_hash_type_t type)
{
    error_t ret = WB_CRYPTO_INVALID_TYPE;

    switch (type) {
        case WB_HASH_TYPE_SHA1:
            ret = wb_sha1_internal_start(ctx_handle);
            break;
    }

    return ret == WB_CRYPTO_SUCCESS ? WB_CRYPTO_SUCCESS : WB_HASH_ERROR(ret);
}

error_t wb_hash_update(hash_handle_t ctx_handle, const uint8_t *data, size_t data_len)
{
    wb_hash_base_ctx_t *hash_ctx = (wb_hash_base_ctx_t *)ctx_handle;
    if (!is_valid_hash_ctx(hash_ctx)) {
        return WB_HASH_ERROR(WB_CRYPTO_CTX_INVALID);
    }
    WB_CHECK_EMPTY_RETURN(data, WB_HASH_ERROR(WB_CRYPTO_INVALID_ARG));

    size_t process_len = data_len;
    uint32_t space_in_buffer = hash_ctx->block_size - hash_ctx->buffer_len;
    
    if (data_len > space_in_buffer) {
        WB_MEMCPY(hash_ctx->buffer_ptr + hash_ctx->buffer_len, data, space_in_buffer);
        hash_ctx->compute_func(hash_ctx, hash_ctx->buffer_ptr);
        process_len -= space_in_buffer;
        hash_ctx->buffer_len = 0;
    } else {
        WB_MEMCPY(hash_ctx->buffer_ptr + hash_ctx->buffer_len, data, data_len);
        hash_ctx->buffer_len += data_len;
        return WB_CRYPTO_SUCCESS;
    }

    while (process_len >= hash_ctx->block_size) {
        hash_ctx->compute_func(hash_ctx, data + (data_len - process_len));
        process_len -= hash_ctx->block_size;
    }
    if (process_len > 0) {
        WB_MEMCPY(hash_ctx->buffer_ptr, data + (data_len - process_len), process_len);
        hash_ctx->buffer_len += process_len;
    }

    return WB_CRYPTO_SUCCESS;
}

error_t wb_hash_finish(hash_handle_t ctx_handle, uint8_t *digest)
{
    wb_hash_base_ctx_t *hash_ctx = (wb_hash_base_ctx_t *)ctx_handle;
    if (!is_valid_hash_ctx(hash_ctx)) {
        return WB_HASH_ERROR(WB_CRYPTO_CTX_INVALID);
    }
    WB_CHECK_EMPTY_RETURN(digest, WB_HASH_ERROR(WB_CRYPTO_INVALID_ARG));

    hash_ctx->padding_func(hash_ctx);
    hash_ctx->destroy_func(hash_ctx, digest);

    return WB_CRYPTO_SUCCESS;
}

error_t wb_hash_transform(wb_hash_type_t type, const uint8_t *data, size_t data_len, uint8_t *digest)
{
    error_t ret = WB_CRYPTO_SUCCESS;
    hash_handle_t ctx_handle = NULL;

    ret = wb_hash_start(&ctx_handle, type);
    if (ret != WB_CRYPTO_SUCCESS) {
        return ret;
    }

    ret = wb_hash_update(ctx_handle, data, data_len);
    if (ret != WB_CRYPTO_SUCCESS) {
        return ret;
    }

    ret = wb_hash_finish(ctx_handle, digest);
    if (ret != WB_CRYPTO_SUCCESS) {
        return ret;
    }

    return WB_CRYPTO_SUCCESS;
}

error_t wb_hash_reset(hash_handle_t ctx_handle)
{
    wb_hash_base_ctx_t *hash_ctx = (wb_hash_base_ctx_t *)ctx_handle;
    if (!is_valid_hash_ctx(hash_ctx)) {
        return WB_HASH_ERROR(WB_CRYPTO_CTX_INVALID);
    }

    hash_ctx->reset_func(hash_ctx);
    return WB_CRYPTO_SUCCESS;
}