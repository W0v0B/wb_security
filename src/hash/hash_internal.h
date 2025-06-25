#ifndef WB_HASH_INTERNAL_H
#define WB_HASH_INTERNAL_H

#include "wb_hash.h"

typedef struct wb_hash_base_ctx_t wb_hash_base_ctx_t;
typedef void (*hash_compute_func_t)(void *ctx, const uint8_t *block);
typedef void (*hash_padding_func_t)(void *ctx);
typedef void (*hash_destroy_func_t)(void *ctx, uint8_t *digest, size_t digest_len);
typedef void (*hash_reset_func_t)(void *ctx);

struct wb_hash_base_ctx_t{
    uintptr_t magic;
    wb_hash_type_t type;
    uint32_t block_size;
    uint32_t buffer_len;
    uint8_t *buffer_ptr;
    hash_compute_func_t compute_func;
    hash_padding_func_t padding_func;
    hash_destroy_func_t destroy_func;
    hash_reset_func_t reset_func;
};

#define WB_HASH_CTX_MAGIC 0xDEADBEEFU

error_t wb_sha1_internal_start(void **ctx_handle);

error_t wb_sha224_internal_start(void **ctx_handle);

error_t wb_sha256_internal_start(void **ctx_handle);

error_t wb_sha384_internal_start(void **ctx_handle);

error_t wb_sha512_internal_start(void **ctx_handle);

static inline bool is_valid_hash_ctx(const wb_hash_base_ctx_t *ctx)
{
    if (ctx == NULL) {
        WB_PRINTF("Hash context is NULL\n");
        return false;
    }
    if (ctx->magic != ((uintptr_t)ctx ^ ctx->type ^ WB_HASH_CTX_MAGIC)) {
        WB_PRINTF("Hash context magic mismatch: expected %lx, got %lx\n",
               (uintptr_t)ctx ^ ctx->type ^ WB_HASH_CTX_MAGIC, ctx->magic);
        return false;
    }
    if (ctx->type >= WB_HASH_TYPE_MAX || ctx->type < WB_HASH_TYPE_SHA1) {
        WB_PRINTF("Invalid hash type: %d\n", ctx->type);
        return false;
    }
    if (ctx->buffer_len > ctx->block_size) {
        WB_PRINTF("Buffer length exceeds block size: %u > %u\n", ctx->buffer_len, ctx->block_size);
        return false;
    }
    return true;
}

static inline uint32_t left_rotate32(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

static inline uint32_t right_rotate32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

static inline uint64_t left_rotate64(uint64_t x, uint32_t n) {
    return (x << n) | (x >> (64 - n));
}

static inline uint64_t right_rotate64(uint64_t x, uint32_t n) {
    return (x >> n) | (x << (64 - n));
}

static inline uint32_t bytes_to_uint32_be(const uint8_t *bytes) {
    return ((uint32_t)bytes[3]) |
           ((uint32_t)bytes[2] << 8) |
           ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[0] << 24);
}

static inline uint32_t bytes_to_uint32_le(const uint8_t *bytes) {
    return ((uint32_t)bytes[0]) |
           ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}

static inline uint64_t bytes_to_uint64_be(const uint8_t *bytes) {
    return ((uint64_t)bytes[0] << 56) |
           ((uint64_t)bytes[1] << 48) |
           ((uint64_t)bytes[2] << 40) |
           ((uint64_t)bytes[3] << 32) |
           ((uint64_t)bytes[4] << 24) |
           ((uint64_t)bytes[5] << 16) |
           ((uint64_t)bytes[6] << 8)  |
           ((uint64_t)bytes[7]);
}

static inline uint64_t bytes_to_uint64_le(const uint8_t *bytes) {
    return ((uint64_t)bytes[0]) |
           ((uint64_t)bytes[1] << 8) |
           ((uint64_t)bytes[2] << 16) |
           ((uint64_t)bytes[3] << 24) |
           ((uint64_t)bytes[4] << 32) |
           ((uint64_t)bytes[5] << 40) |
           ((uint64_t)bytes[6] << 48) |
           ((uint64_t)bytes[7] << 56);
}

static inline void wb_write_uint32_be(uint8_t *dest, uint32_t value)
{
    dest[0] = (uint8_t)(value >> 24);
    dest[1] = (uint8_t)(value >> 16);
    dest[2] = (uint8_t)(value >> 8);
    dest[3] = (uint8_t)(value);
}

static inline void wb_write_uint32_le(uint8_t *dest, uint32_t value)
{
    dest[0] = (uint8_t)(value);
    dest[1] = (uint8_t)(value >> 8);
    dest[2] = (uint8_t)(value >> 16);
    dest[3] = (uint8_t)(value >> 24);
}

static inline void wb_write_uint64_be(uint8_t *dest, uint64_t value)
{
    dest[0] = (uint8_t)(value >> 56);
    dest[1] = (uint8_t)(value >> 48);
    dest[2] = (uint8_t)(value >> 40);
    dest[3] = (uint8_t)(value >> 32);
    dest[4] = (uint8_t)(value >> 24);
    dest[5] = (uint8_t)(value >> 16);
    dest[6] = (uint8_t)(value >> 8);
    dest[7] = (uint8_t)(value);
}

static inline void wb_write_uint64_le(uint8_t *dest, uint64_t value)
{
    dest[0] = (uint8_t)(value);
    dest[1] = (uint8_t)(value >> 8);
    dest[2] = (uint8_t)(value >> 16);
    dest[3] = (uint8_t)(value >> 24);
    dest[4] = (uint8_t)(value >> 32);
    dest[5] = (uint8_t)(value >> 40);
    dest[6] = (uint8_t)(value >> 48);
    dest[7] = (uint8_t)(value >> 56);
}

#endif // WB_HASH_INTERNAL_H