#include "hash_internal.h"

#define BLAKE2B_BLOCK_SIZE 128U
#define BLAKE2B_TAIL_LEN 16U
#define BLAKE2B_MAX_DIGEST_SIZE 64U

typedef struct {
    wb_hash_base_ctx_t base;
    uint8_t buffer[BLAKE2B_BLOCK_SIZE];
    uint64_t state[8];
    uint64_t count[2];
    uint64_t flag[2];
} wb_blake2b_ctx_t;

static const uint64_t blake2b_iv[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const uint8_t blake2b_sigma[12][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
};

#define G(i, r, a, b, c, d) \
    do { \
        a = a + b + m[blake2b_sigma[i][2*r+0]]; \
        d = right_rotate64(d ^ a, 32); \
        c = c + d; \
        b = right_rotate64(b ^ c, 24); \
        a = a + b + m[blake2b_sigma[i][2*r+1]]; \
        d = right_rotate64(d ^ a, 16); \
        c = c + d; \
        b = right_rotate64(b ^ c, 63); \
    } while(0)

static void wb_blake2b_internal_compute(void *ctx, const uint8_t *block)
{
    wb_blake2b_ctx_t *blake2b_ctx = (wb_blake2b_ctx_t *)ctx;

    if (blake2b_ctx->flag[0] == 0) {
        blake2b_ctx->count[1] += BLAKE2B_BLOCK_SIZE;
        if (blake2b_ctx->count[1] < BLAKE2B_BLOCK_SIZE) {
            blake2b_ctx->count[0]++;
        }
    }

    int i;
    uint64_t m[16];
    uint64_t v[16];

    for (i = 0; i < 8; i++) {
        m[i] = bytes_to_uint64_le(block + i * sizeof(uint64_t));
        v[i] = blake2b_ctx->state[i];
    }

    for (; i < 16; i++) {
        m[i] = bytes_to_uint64_le(block + i * sizeof(uint64_t));
        v[i] = blake2b_iv[i - 8];
    }

    v[12] ^= blake2b_ctx->count[1];
    v[13] ^= blake2b_ctx->count[0];
    v[14] ^= blake2b_ctx->flag[0];
    v[15] ^= blake2b_ctx->flag[1];

    for (i = 0; i < 12; i++) {
        G(i, 0, v[0], v[4], v[8],  v[12]);
        G(i, 1, v[1], v[5], v[9],  v[13]);
        G(i, 2, v[2], v[6], v[10], v[14]);
        G(i, 3, v[3], v[7], v[11], v[15]);

        G(i, 4, v[0], v[5], v[10], v[15]);
        G(i, 5, v[1], v[6], v[11], v[12]);
        G(i, 6, v[2], v[7], v[8],  v[13]);
        G(i, 7, v[3], v[4], v[9],  v[14]);
    }

    for (i = 0; i < 8; i++) {
        blake2b_ctx->state[i] = blake2b_ctx->state[i] ^ v[i] ^ v[i + 8];
    }
}

static void wb_blake2b_internal_finish(void *ctx, uint8_t *digest, size_t digest_len)
{
    wb_blake2b_ctx_t *blake2b_ctx = (wb_blake2b_ctx_t *)ctx;
    uint8_t temp_digest[BLAKE2B_MAX_DIGEST_SIZE];

    blake2b_ctx->count[1] += blake2b_ctx->base.buffer_len;
    if (blake2b_ctx->count[1] < blake2b_ctx->base.buffer_len) {
        blake2b_ctx->count[0]++;
    }
    blake2b_ctx->flag[0] = 0xFFFFFFFFFFFFFFFFULL;
    (void)WB_MEMSET_S(blake2b_ctx->buffer + blake2b_ctx->base.buffer_len, BLAKE2B_BLOCK_SIZE - blake2b_ctx->base.buffer_len,
        0, BLAKE2B_BLOCK_SIZE - blake2b_ctx->base.buffer_len);
    blake2b_ctx->base.compute_func(ctx, blake2b_ctx->buffer);

    for (int i = 0; i < blake2b_ctx->base.digest_len / sizeof(uint64_t); i++) {
        wb_write_uint64_le(temp_digest + i * sizeof(uint64_t), blake2b_ctx->state[i]);
    }
    (void)WB_MEMCPY_S(digest, digest_len, temp_digest, blake2b_ctx->base.digest_len);
    (void)WB_MEMSET_FREE_S(temp_digest, BLAKE2B_MAX_DIGEST_SIZE, 0, BLAKE2B_MAX_DIGEST_SIZE);
}

static void wb_blake2b_internal_destroy(void *ctx)
{
    (void)WB_MEMSET_FREE_S(ctx, sizeof(wb_blake2b_ctx_t), 0, sizeof(wb_blake2b_ctx_t));
    free(ctx);
    ctx = NULL;
}

static void wb_blake2b_internal_reset(void *ctx)
{
    wb_blake2b_ctx_t *blake2b_ctx = (wb_blake2b_ctx_t *)ctx;
    uint64_t param_word = 0;
    blake2b_ctx->count[0] = 0;
    blake2b_ctx->count[1] = 0;
    blake2b_ctx->flag[0] = 0;
    blake2b_ctx->flag[1] = 0;

    param_word |= (uint64_t)(blake2b_ctx->base.digest_len);
    param_word |= ((uint64_t)(blake2b_ctx->base.buffer_len) << 8);
    param_word |= (1ULL << 16);
    param_word |= (1ULL << 24);

    blake2b_ctx->state[0] = blake2b_iv[0] ^ param_word;
    blake2b_ctx->state[1] = blake2b_iv[1];
    blake2b_ctx->state[2] = blake2b_iv[2];
    blake2b_ctx->state[3] = blake2b_iv[3];
    blake2b_ctx->state[4] = blake2b_iv[4];
    blake2b_ctx->state[5] = blake2b_iv[5];
    blake2b_ctx->state[6] = blake2b_iv[6];
    blake2b_ctx->state[7] = blake2b_iv[7];

    if (blake2b_ctx->base.buffer_len > 0) {
        (void)WB_MEMSET_S(blake2b_ctx->buffer + blake2b_ctx->base.buffer_len, BLAKE2B_BLOCK_SIZE - blake2b_ctx->base.buffer_len,
            0, BLAKE2B_BLOCK_SIZE - blake2b_ctx->base.buffer_len);
        blake2b_ctx->base.compute_func(ctx, blake2b_ctx->buffer);
    }
    blake2b_ctx->base.buffer_len = 0;
}

error_t wb_blake2b_internal_start(void **ctx_handle, size_t digest_len)
{
    if (digest_len != 0) {
        wb_blake2b_ctx_t *ctx = (wb_blake2b_ctx_t *)*ctx_handle;
        ctx->base.digest_len = (uint8_t)digest_len;
        ctx->base.reset_func(*ctx_handle);
        return WB_CRYPTO_SUCCESS;
    }
    wb_blake2b_ctx_t *ctx = (wb_blake2b_ctx_t *)malloc(sizeof(wb_blake2b_ctx_t));
    WB_CHECK_EMPTY_RETURN(ctx, WB_CRYPTO_MALLOC_FAIL);

    ctx->base.type = WB_HASH_TYPE_BLAKE2B;
    ctx->base.digest_len = 0;
    ctx->base.block_size = BLAKE2B_BLOCK_SIZE;
    ctx->base.buffer_ptr = ctx->buffer;
    ctx->base.buffer_len = 0;
    ctx->base.compute_func = wb_blake2b_internal_compute;
    ctx->base.finish_func = wb_blake2b_internal_finish;
    ctx->base.destroy_func = wb_blake2b_internal_destroy;
    ctx->base.reset_func = wb_blake2b_internal_reset;
    ctx->base.magic = (uintptr_t)ctx ^ ctx->base.type ^ WB_HASH_CTX_MAGIC;

    *ctx_handle = (void *)ctx;

    return WB_CRYPTO_SUCCESS;
}