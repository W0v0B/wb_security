#include "hash_internal.h"

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32
#define SHA256_TAIL_LEN 8

typedef struct {
    wb_hash_base_ctx_t base;
    uint8_t buffer[SHA256_BLOCK_SIZE];
    uint32_t state[8];
    uint64_t bit_count;
} wb_sha256_ctx_t;

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void wb_sha256_internal_compute(void *ctx, const uint8_t *block)
{
    wb_sha256_ctx_t *sha256_ctx = (wb_sha256_ctx_t *)ctx;
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h, temp1, temp2;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = bytes_to_uint32_be(block + i * 4);
    }
    
    for (; i < 64; i++) {
        temp1 = right_rotate(w[i-15], 7) ^ right_rotate(w[i-15], 18) ^ (w[i-15] >> 3);
        temp2 = right_rotate(w[i-2], 17) ^ right_rotate(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + temp1 + w[i-7] + temp2;
    }

    a = sha256_ctx->state[0];
    b = sha256_ctx->state[1];
    c = sha256_ctx->state[2];
    d = sha256_ctx->state[3];
    e = sha256_ctx->state[4];
    f = sha256_ctx->state[5];
    g = sha256_ctx->state[6];
    h = sha256_ctx->state[7];

    for (i = 0; i < 64; i++) {
        temp1 = h + (right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)) + ((e & f) ^ (~e & g)) + w[i] + K[i];
        temp2 = (right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    sha256_ctx->state[0] += a;
    sha256_ctx->state[1] += b;
    sha256_ctx->state[2] += c;
    sha256_ctx->state[3] += d;
    sha256_ctx->state[4] += e;
    sha256_ctx->state[5] += f;
    sha256_ctx->state[6] += g;
    sha256_ctx->state[7] += h;
    sha256_ctx->bit_count += SHA256_BLOCK_SIZE * 8;
}

static void wb_sha256_internal_padding(void *ctx)
{
    wb_sha256_ctx_t *sha256_ctx = (wb_sha256_ctx_t *)ctx;
    uint64_t total_bits = sha256_ctx->bit_count + (sha256_ctx->base.buffer_len * 8);
    sha256_ctx->buffer[sha256_ctx->base.buffer_len++] = 0x80;
    if (sha256_ctx->base.buffer_len > SHA256_BLOCK_SIZE - SHA256_TAIL_LEN) {
        WB_MEMSET_S(sha256_ctx->buffer + sha256_ctx->base.buffer_len, SHA256_BLOCK_SIZE - sha256_ctx->base.buffer_len,
            0, SHA256_BLOCK_SIZE - sha256_ctx->base.buffer_len);
        sha256_ctx->base.compute_func(ctx, sha256_ctx->buffer);
        sha256_ctx->base.buffer_len = 0;
    }
    WB_MEMSET_S(sha256_ctx->buffer + sha256_ctx->base.buffer_len, SHA256_BLOCK_SIZE - sha256_ctx->base.buffer_len, 
        0, SHA256_BLOCK_SIZE - SHA256_TAIL_LEN - sha256_ctx->base.buffer_len);
    wb_write_uint64_be(sha256_ctx->buffer + SHA256_BLOCK_SIZE - SHA256_TAIL_LEN, total_bits);
    sha256_ctx->base.compute_func(ctx, sha256_ctx->buffer);
}

static void wb_sha256_internal_destroy(void *ctx, uint8_t *digest)
{
    wb_sha256_ctx_t *sha256_ctx = (wb_sha256_ctx_t *)ctx;
    for (int i = 0; i < 8 && digest != NULL; i++) {
        wb_write_uint32_be(digest + i * 4, sha256_ctx->state[i]);
    }
    WB_MEMSET_S(sha256_ctx, sizeof(wb_sha256_ctx_t), 0, sizeof(wb_sha256_ctx_t));
    WB_FREE(sha256_ctx);
    sha256_ctx = NULL;
}

static void wb_sha256_internal_reset(void *ctx)
{
    wb_sha256_ctx_t *sha256_ctx = (wb_sha256_ctx_t *)ctx;
    sha256_ctx->bit_count = 0;
    sha256_ctx->state[0] = 0x6A09E667;
    sha256_ctx->state[1] = 0xBB67AE85;
    sha256_ctx->state[2] = 0x3C6EF372;
    sha256_ctx->state[3] = 0xA54FF53A;
    sha256_ctx->state[4] = 0x510E527F;
    sha256_ctx->state[5] = 0x9B05688C;
    sha256_ctx->state[6] = 0x1F83D9AB;
    sha256_ctx->state[7] = 0x5BE0CD19;
    sha256_ctx->base.buffer_len = 0;
    WB_MEMSET_S(sha256_ctx->buffer, SHA256_BLOCK_SIZE, 0, SHA256_BLOCK_SIZE);
}

error_t wb_sha256_internal_start(void **ctx_handle)
{
    wb_sha256_ctx_t *ctx = (wb_sha256_ctx_t *)WB_MALLOC(sizeof(wb_sha256_ctx_t));
    WB_CHECK_EMPTY_RETURN(ctx, WB_CRYPTO_MALLOC_FAIL);

    ctx->base.type = WB_HASH_TYPE_SHA256;
    ctx->base.block_size = SHA256_BLOCK_SIZE;
    ctx->base.buffer_ptr = ctx->buffer;
    ctx->base.buffer_len = 0;
    ctx->base.compute_func = wb_sha256_internal_compute;
    ctx->base.padding_func = wb_sha256_internal_padding;
    ctx->base.destroy_func = wb_sha256_internal_destroy;
    ctx->base.reset_func = wb_sha256_internal_reset;
    ctx->base.magic = (uintptr_t)ctx ^ ctx->base.type ^ WB_HASH_CTX_MAGIC;

    ctx->bit_count = 0;
    ctx->state[0] = 0x6A09E667;
    ctx->state[1] = 0xBB67AE85;
    ctx->state[2] = 0x3C6EF372;
    ctx->state[3] = 0xA54FF53A;
    ctx->state[4] = 0x510E527F;
    ctx->state[5] = 0x9B05688C;
    ctx->state[6] = 0x1F83D9AB;
    ctx->state[7] = 0x5BE0CD19;

    *ctx_handle = (void *)ctx;
    
    return WB_CRYPTO_SUCCESS;
}

static void wb_sha224_internal_destroy(void *ctx, uint8_t *digest)
{
    wb_sha256_ctx_t *sha256_ctx = (wb_sha256_ctx_t *)ctx;
    for (int i = 0; i < 7 && digest != NULL; i++) {
        wb_write_uint32_be(digest + i * 4, sha256_ctx->state[i]);
    }
    WB_MEMSET_S(sha256_ctx, sizeof(wb_sha256_ctx_t), 0, sizeof(wb_sha256_ctx_t));
    WB_FREE(sha256_ctx);
    sha256_ctx = NULL;
}

static void wb_sha224_internal_reset(void *ctx)
{
    wb_sha256_ctx_t *sha256_ctx = (wb_sha256_ctx_t *)ctx;
    sha256_ctx->bit_count = 0;
    sha256_ctx->state[0] = 0xC1059ED8;
    sha256_ctx->state[1] = 0x367CD507;
    sha256_ctx->state[2] = 0x3070DD17;
    sha256_ctx->state[3] = 0xF70E5939;
    sha256_ctx->state[4] = 0xFFC00B31;
    sha256_ctx->state[5] = 0x68581511;
    sha256_ctx->state[6] = 0x64F98FA7;
    sha256_ctx->state[7] = 0xBEFA4FA4;
    sha256_ctx->base.buffer_len = 0;
    WB_MEMSET_S(sha256_ctx->buffer, SHA256_BLOCK_SIZE, 0, SHA256_BLOCK_SIZE);
}

error_t wb_sha224_internal_start(void **ctx_handle)
{
    wb_sha256_ctx_t *ctx = (wb_sha256_ctx_t *)WB_MALLOC(sizeof(wb_sha256_ctx_t));
    WB_CHECK_EMPTY_RETURN(ctx, WB_CRYPTO_MALLOC_FAIL);

    ctx->base.type = WB_HASH_TYPE_SHA224;
    ctx->base.block_size = SHA256_BLOCK_SIZE;
    ctx->base.buffer_ptr = ctx->buffer;
    ctx->base.buffer_len = 0;
    ctx->base.compute_func = wb_sha256_internal_compute;
    ctx->base.padding_func = wb_sha256_internal_padding;
    ctx->base.destroy_func = wb_sha224_internal_destroy;
    ctx->base.reset_func = wb_sha224_internal_reset;
    ctx->base.magic = (uintptr_t)ctx ^ ctx->base.type ^ WB_HASH_CTX_MAGIC;

    ctx->bit_count = 0;
    ctx->state[0] = 0xC1059ED8;
    ctx->state[1] = 0x367CD507;
    ctx->state[2] = 0x3070DD17;
    ctx->state[3] = 0xF70E5939;
    ctx->state[4] = 0xFFC00B31;
    ctx->state[5] = 0x68581511;
    ctx->state[6] = 0x64F98FA7;
    ctx->state[7] = 0xBEFA4FA4;

    *ctx_handle = (void *)ctx;

    return WB_CRYPTO_SUCCESS;
}