#include "hash_internal.h"

#define SHA1_BLOCK_SIZE 64U
#define SHA1_TAIL_LEN 8U
#define SHA1_DIGEST_SIZE 20U

typedef struct {
    wb_hash_base_ctx_t base;
    uint8_t buffer[SHA1_BLOCK_SIZE];
    uint32_t state[5];
    uint64_t bit_count;
} wb_sha1_ctx_t;

static void wb_sha1_internal_compute(void *ctx, const uint8_t *block)
{
    wb_sha1_ctx_t *sha1_ctx = (wb_sha1_ctx_t *)ctx;
    uint32_t w[80];
    uint32_t a, b, c, d, e, temp;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = bytes_to_uint32_be(block + i * 4);
    }
    
    for (; i < 80; i++) {
        temp = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16];
        w[i] = left_rotate32(temp, 1);
    }

    a = sha1_ctx->state[0];
    b = sha1_ctx->state[1];
    c = sha1_ctx->state[2];
    d = sha1_ctx->state[3];
    e = sha1_ctx->state[4];

    for (i = 0; i < 20; i++) {
        temp = left_rotate32(a, 5) + ((b & c) | (~b & d)) + e + w[i] + 0x5A827999;
        e = d;
        d = c;
        c = left_rotate32(b, 30);
        b = a;
        a = temp;
    }
    for (; i < 40; i++) {
        temp = left_rotate32(a, 5) + (b ^ c ^ d) + e + w[i] + 0x6ED9EBA1;
        e = d;
        d = c;
        c = left_rotate32(b, 30);
        b = a;
        a = temp;
    }
    for (; i < 60; i++) {
        temp = left_rotate32(a, 5) + ((b & c) | (b & d) | (c & d)) + e + w[i] + 0x8F1BBCDC;
        e = d;
        d = c;
        c = left_rotate32(b, 30);
        b = a;
        a = temp;
    }
    for (; i < 80; i++) {
        temp = left_rotate32(a, 5) + (b ^ c ^ d) + e + w[i] + 0xCA62C1D6;
        e = d;
        d = c;
        c = left_rotate32(b, 30);
        b = a;
        a = temp;
    }
    sha1_ctx->state[0] += a;
    sha1_ctx->state[1] += b;
    sha1_ctx->state[2] += c;
    sha1_ctx->state[3] += d;
    sha1_ctx->state[4] += e;
    sha1_ctx->bit_count += SHA1_BLOCK_SIZE * 8;
}

static void wb_sha1_internal_padding(void *ctx)
{
    wb_sha1_ctx_t *sha1_ctx = (wb_sha1_ctx_t *)ctx;
    uint64_t total_bits = sha1_ctx->bit_count + (sha1_ctx->base.buffer_len * 8);
    sha1_ctx->buffer[sha1_ctx->base.buffer_len++] = 0x80;
    if (sha1_ctx->base.buffer_len > SHA1_BLOCK_SIZE - SHA1_TAIL_LEN) {
        WB_MEMSET_S(sha1_ctx->buffer + sha1_ctx->base.buffer_len, SHA1_BLOCK_SIZE - sha1_ctx->base.buffer_len,
            0, SHA1_BLOCK_SIZE - sha1_ctx->base.buffer_len);
        sha1_ctx->base.compute_func(ctx, sha1_ctx->buffer);
        sha1_ctx->base.buffer_len = 0;
    }
    WB_MEMSET_S(sha1_ctx->buffer + sha1_ctx->base.buffer_len, SHA1_BLOCK_SIZE - sha1_ctx->base.buffer_len, 
        0, SHA1_BLOCK_SIZE - SHA1_TAIL_LEN - sha1_ctx->base.buffer_len);
    wb_write_uint64_be(sha1_ctx->buffer + SHA1_BLOCK_SIZE - SHA1_TAIL_LEN, total_bits);
    sha1_ctx->base.compute_func(ctx, sha1_ctx->buffer);
}

static void wb_sha1_internal_destroy(void *ctx, uint8_t *digest, size_t digest_len)
{
    wb_sha1_ctx_t *sha1_ctx = (wb_sha1_ctx_t *)ctx;
    if (digest != NULL && digest_len >= SHA1_DIGEST_SIZE) {
        for (int i = 0; i < 5; i++) {
            wb_write_uint32_be(digest + i * 4, sha1_ctx->state[i]);
        }
    }
    WB_MEMSET_FREE_S(sha1_ctx, sizeof(wb_sha1_ctx_t), 0, sizeof(wb_sha1_ctx_t));
    WB_FREE(sha1_ctx);
    sha1_ctx = NULL;
}

static void wb_sha1_internal_reset(void *ctx)
{
    wb_sha1_ctx_t *sha1_ctx = (wb_sha1_ctx_t *)ctx;
    sha1_ctx->bit_count = 0;
    sha1_ctx->state[0] = 0x67452301U;
    sha1_ctx->state[1] = 0xEFCDAB89U;
    sha1_ctx->state[2] = 0x98BADCFEU;
    sha1_ctx->state[3] = 0x10325476U;
    sha1_ctx->state[4] = 0xC3D2E1F0U;
    sha1_ctx->base.buffer_len = 0;
    WB_MEMSET_S(sha1_ctx->buffer, SHA1_BLOCK_SIZE, 0, SHA1_BLOCK_SIZE);
}

error_t wb_sha1_internal_start(void **ctx_handle)
{
    wb_sha1_ctx_t *ctx = (wb_sha1_ctx_t *)WB_MALLOC(sizeof(wb_sha1_ctx_t));
    WB_CHECK_EMPTY_RETURN(ctx, WB_CRYPTO_MALLOC_FAIL);

    ctx->base.type = WB_HASH_TYPE_SHA1;
    ctx->base.block_size = SHA1_BLOCK_SIZE;
    ctx->base.buffer_ptr = ctx->buffer;
    ctx->base.compute_func = wb_sha1_internal_compute;
    ctx->base.padding_func = wb_sha1_internal_padding;
    ctx->base.destroy_func = wb_sha1_internal_destroy;
    ctx->base.reset_func = wb_sha1_internal_reset;

    ctx->base.reset_func(ctx);
    ctx->base.magic = (uintptr_t)ctx ^ ctx->base.type ^ WB_HASH_CTX_MAGIC;

    *ctx_handle = (void *)ctx;

    return WB_CRYPTO_SUCCESS;
}