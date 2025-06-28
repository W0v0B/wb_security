#include "hash_internal.h"

#define SHA256_BLOCK_SIZE 64U
#define SHA224_BLOCK_SIZE 64U
#define SHA256_TAIL_LEN 8U
#define SHA224_DIGEST_SIZE 28U
#define SHA256_DIGEST_SIZE 32U

typedef struct {
    wb_hash_base_ctx_t base;
    uint8_t buffer[SHA256_BLOCK_SIZE];
    uint32_t state[8];
    uint64_t bit_count;
} wb_sha256_ctx_t;

typedef wb_sha256_ctx_t wb_sha224_ctx_t;

static const uint32_t K[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
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
        temp1 = right_rotate32(w[i-15], 7) ^ right_rotate32(w[i-15], 18) ^ (w[i-15] >> 3);
        temp2 = right_rotate32(w[i-2], 17) ^ right_rotate32(w[i-2], 19) ^ (w[i-2] >> 10);
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
        temp1 = h + (right_rotate32(e, 6) ^ right_rotate32(e, 11) ^ right_rotate32(e, 25)) + ((e & f) ^ (~e & g)) + w[i] + K[i];
        temp2 = (right_rotate32(a, 2) ^ right_rotate32(a, 13) ^ right_rotate32(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
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

static void wb_sha256_internal_destroy(void *ctx, uint8_t *digest, size_t digest_len)
{
    wb_sha256_ctx_t *sha256_ctx = (wb_sha256_ctx_t *)ctx;
    if (digest != NULL && digest_len >= SHA256_DIGEST_SIZE) {
        for (int i = 0; i < 8; i++) {
            wb_write_uint32_be(digest + i * 4, sha256_ctx->state[i]);
        }
    }
    WB_MEMSET_FREE_S(sha256_ctx, sizeof(wb_sha256_ctx_t), 0, sizeof(wb_sha256_ctx_t));
    WB_FREE(sha256_ctx);
    sha256_ctx = NULL;
}

static void wb_sha256_internal_reset(void *ctx)
{
    wb_sha256_ctx_t *sha256_ctx = (wb_sha256_ctx_t *)ctx;
    sha256_ctx->bit_count = 0;
    sha256_ctx->state[0] = 0x6A09E667U;
    sha256_ctx->state[1] = 0xBB67AE85U;
    sha256_ctx->state[2] = 0x3C6EF372U;
    sha256_ctx->state[3] = 0xA54FF53AU;
    sha256_ctx->state[4] = 0x510E527FU;
    sha256_ctx->state[5] = 0x9B05688CU;
    sha256_ctx->state[6] = 0x1F83D9ABU;
    sha256_ctx->state[7] = 0x5BE0CD19U;
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
    ctx->base.compute_func = wb_sha256_internal_compute;
    ctx->base.padding_func = wb_sha256_internal_padding;
    ctx->base.destroy_func = wb_sha256_internal_destroy;
    ctx->base.reset_func = wb_sha256_internal_reset;
    
    ctx->base.reset_func(ctx);
    ctx->base.magic = (uintptr_t)ctx ^ ctx->base.type ^ WB_HASH_CTX_MAGIC;

    *ctx_handle = (void *)ctx;
    
    return WB_CRYPTO_SUCCESS;
}

static void wb_sha224_internal_destroy(void *ctx, uint8_t *digest, size_t digest_len)
{
    wb_sha224_ctx_t *sha224_ctx = (wb_sha224_ctx_t *)ctx;
    if (digest != NULL && digest_len >= SHA224_DIGEST_SIZE) {
        for (int i = 0; i < 7; i++) {
            wb_write_uint32_be(digest + i * 4, sha224_ctx->state[i]);
        }
    }
    WB_MEMSET_FREE_S(sha224_ctx, sizeof(wb_sha224_ctx_t), 0, sizeof(wb_sha224_ctx_t));
    WB_FREE(sha224_ctx);
    sha224_ctx = NULL;
}

static void wb_sha224_internal_reset(void *ctx)
{
    wb_sha224_ctx_t *sha224_ctx = (wb_sha224_ctx_t *)ctx;
    sha224_ctx->bit_count = 0;
    sha224_ctx->state[0] = 0xC1059ED8U;
    sha224_ctx->state[1] = 0x367CD507U;
    sha224_ctx->state[2] = 0x3070DD17U;
    sha224_ctx->state[3] = 0xF70E5939U;
    sha224_ctx->state[4] = 0xFFC00B31U;
    sha224_ctx->state[5] = 0x68581511U;
    sha224_ctx->state[6] = 0x64F98FA7U;
    sha224_ctx->state[7] = 0xBEFA4FA4U;
    sha224_ctx->base.buffer_len = 0;
    WB_MEMSET_S(sha224_ctx->buffer, SHA256_BLOCK_SIZE, 0, SHA256_BLOCK_SIZE);
}

error_t wb_sha224_internal_start(void **ctx_handle)
{
    wb_sha224_ctx_t *ctx = (wb_sha224_ctx_t *)WB_MALLOC(sizeof(wb_sha224_ctx_t));
    WB_CHECK_EMPTY_RETURN(ctx, WB_CRYPTO_MALLOC_FAIL);

    ctx->base.type = WB_HASH_TYPE_SHA224;
    ctx->base.block_size = SHA224_BLOCK_SIZE;
    ctx->base.buffer_ptr = ctx->buffer;
    ctx->base.compute_func = wb_sha256_internal_compute;
    ctx->base.padding_func = wb_sha256_internal_padding;
    ctx->base.destroy_func = wb_sha224_internal_destroy;
    ctx->base.reset_func = wb_sha224_internal_reset;

    ctx->base.reset_func(ctx);
    ctx->base.magic = (uintptr_t)ctx ^ ctx->base.type ^ WB_HASH_CTX_MAGIC;

    *ctx_handle = (void *)ctx;

    return WB_CRYPTO_SUCCESS;
}