#include "hash_internal.h"

#define SHA512_BLOCK_SIZE 128U
#define SHA384_BLOCK_SIZE 128U
#define SHA512_TAIL_LEN 16U
#define SHA384_DIGEST_SIZE 48U
#define SHA512_DIGEST_SIZE 64U

typedef struct {
    wb_hash_base_ctx_t base;
    uint8_t buffer[SHA512_BLOCK_SIZE];
    uint64_t state[8];
    uint64_t bit_count[2];
} wb_sha512_ctx_t;

typedef wb_sha512_ctx_t wb_sha384_ctx_t;

static const uint64_t K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static void wb_sha512_internal_compute(void *ctx, const uint8_t *block)
{
    wb_sha512_ctx_t *sha512_ctx = (wb_sha512_ctx_t *)ctx;
    uint64_t w[80];
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t temp1, temp2;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = bytes_to_uint64_be(block + i * 8);
    }

    for (; i < 80; ++i) {
        temp1 = right_rotate64(w[i - 15], 1) ^ right_rotate64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        temp2 = right_rotate64(w[i - 2], 19) ^ right_rotate64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + temp1 + w[i - 7] + temp2;
    }

    a = sha512_ctx->state[0];
    b = sha512_ctx->state[1];
    c = sha512_ctx->state[2];
    d = sha512_ctx->state[3];
    e = sha512_ctx->state[4];
    f = sha512_ctx->state[5];
    g = sha512_ctx->state[6];
    h = sha512_ctx->state[7];

    for (i = 0; i < 80; ++i) {
        temp1 = h + (right_rotate64(e, 14) ^ right_rotate64(e, 18) ^ right_rotate64(e, 41)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
        temp2 = (right_rotate64(a, 28) ^ right_rotate64(a, 34) ^ right_rotate64(a, 39)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    sha512_ctx->state[0] += a;
    sha512_ctx->state[1] += b;
    sha512_ctx->state[2] += c;
    sha512_ctx->state[3] += d;
    sha512_ctx->state[4] += e;
    sha512_ctx->state[5] += f;
    sha512_ctx->state[6] += g;
    sha512_ctx->state[7] += h;

    sha512_ctx->bit_count[1] += (uint64_t)(SHA512_BLOCK_SIZE * 8);
    if (sha512_ctx->bit_count[1] < (SHA512_BLOCK_SIZE * 8)) {
        sha512_ctx->bit_count[0]++;
    }
}

static void wb_sha512_internal_padding(void *ctx)
{
    wb_sha512_ctx_t *sha512_ctx = (wb_sha512_ctx_t *)ctx;
    sha512_ctx->bit_count[1] += (uint64_t)(sha512_ctx->base.buffer_len * 8);
    if (sha512_ctx->bit_count[1] < (sha512_ctx->base.buffer_len * 8)) {
        sha512_ctx->bit_count[0]++;
    }
    uint64_t total_bits[2] = { sha512_ctx->bit_count[0], sha512_ctx->bit_count[1] };
    sha512_ctx->buffer[sha512_ctx->base.buffer_len++] = 0x80;
    if (sha512_ctx->base.buffer_len > SHA512_BLOCK_SIZE - SHA512_TAIL_LEN) {
        (void)WB_MEMSET_S(sha512_ctx->buffer + sha512_ctx->base.buffer_len, SHA512_BLOCK_SIZE - sha512_ctx->base.buffer_len,
            0, SHA512_BLOCK_SIZE - sha512_ctx->base.buffer_len);
        sha512_ctx->base.compute_func(ctx, sha512_ctx->buffer);
        sha512_ctx->base.buffer_len = 0;
    }
    (void)WB_MEMSET_S(sha512_ctx->buffer + sha512_ctx->base.buffer_len, SHA512_BLOCK_SIZE - sha512_ctx->base.buffer_len,
        0, SHA512_BLOCK_SIZE - sha512_ctx->base.buffer_len - SHA512_TAIL_LEN);
    wb_write_uint64_be(sha512_ctx->buffer + SHA512_BLOCK_SIZE - SHA512_TAIL_LEN, total_bits[0]);
    wb_write_uint64_be(sha512_ctx->buffer + SHA512_BLOCK_SIZE - SHA512_TAIL_LEN + 8, total_bits[1]);
    sha512_ctx->base.compute_func(ctx, sha512_ctx->buffer);
}

static void wb_sha512_internal_destroy(void *ctx, uint8_t *digest, size_t digest_len)
{
    wb_sha512_ctx_t *sha512_ctx = (wb_sha512_ctx_t *)ctx;
    if (digest != NULL && digest_len >= SHA512_DIGEST_SIZE) {
        for (int i = 0; i < 8; i++) {
            wb_write_uint64_be(digest + i * 8, sha512_ctx->state[i]);
        }
    }
    (void)WB_MEMSET_FREE_S(sha512_ctx, sizeof(wb_sha512_ctx_t), 0, sizeof(wb_sha512_ctx_t));
    WB_FREE(sha512_ctx);
    sha512_ctx = NULL;
}

static void wb_sha512_internal_reset(void *ctx)
{
    wb_sha512_ctx_t *sha512_ctx = (wb_sha512_ctx_t *)ctx;
    sha512_ctx->bit_count[0] = 0;
    sha512_ctx->bit_count[1] = 0;
    sha512_ctx->state[0] = 0x6A09E667F3BCC908ULL;
    sha512_ctx->state[1] = 0xBB67AE8584CAA73BULL;
    sha512_ctx->state[2] = 0x3C6EF372FE94F82BULL;
    sha512_ctx->state[3] = 0xA54FF53A5F1D36F1ULL;
    sha512_ctx->state[4] = 0x510E527FADE682D1ULL;
    sha512_ctx->state[5] = 0x9B05688C2B3E6C1FULL;
    sha512_ctx->state[6] = 0x1F83D9ABFB41BD6BULL;
    sha512_ctx->state[7] = 0x5BE0CD19137E2179ULL;

    sha512_ctx->base.buffer_len = 0;
    (void)WB_MEMSET_S(sha512_ctx->buffer, SHA512_BLOCK_SIZE, 0, SHA512_BLOCK_SIZE);
}

error_t wb_sha512_internal_start(void **ctx_handle)
{
    wb_sha512_ctx_t *ctx = (wb_sha512_ctx_t *)WB_MALLOC(sizeof(wb_sha512_ctx_t));
    WB_CHECK_EMPTY_RETURN(ctx, WB_CRYPTO_MALLOC_FAIL);

    ctx->base.type = WB_HASH_TYPE_SHA512;
    ctx->base.block_size = SHA512_BLOCK_SIZE;
    ctx->base.buffer_ptr = ctx->buffer;
    ctx->base.compute_func = wb_sha512_internal_compute;
    ctx->base.padding_func = wb_sha512_internal_padding;
    ctx->base.destroy_func = wb_sha512_internal_destroy;
    ctx->base.reset_func = wb_sha512_internal_reset;

    ctx->base.reset_func(ctx);

    ctx->base.magic = (uintptr_t)ctx ^ ctx->base.type ^ WB_HASH_CTX_MAGIC;
    *ctx_handle = (void *)ctx;

    return WB_CRYPTO_SUCCESS;
}

static void wb_sha384_internal_destroy(void *ctx, uint8_t *digest, size_t digest_len)
{
    wb_sha384_ctx_t *sha384_ctx = (wb_sha384_ctx_t *)ctx;
    if (digest != NULL && digest_len >= SHA384_DIGEST_SIZE) {
        for (int i = 0; i < 6; i++) {
            wb_write_uint64_be(digest + i * 8, sha384_ctx->state[i]);
        }
    }
    (void)WB_MEMSET_FREE_S(sha384_ctx, sizeof(wb_sha384_ctx_t), 0, sizeof(wb_sha384_ctx_t));
    WB_FREE(sha384_ctx);
    sha384_ctx = NULL;
}

static void wb_sha384_internal_reset(void *ctx)
{
    wb_sha512_ctx_t *sha384_ctx = (wb_sha512_ctx_t *)ctx;
    sha384_ctx->bit_count[0] = 0;
    sha384_ctx->bit_count[1] = 0;
    sha384_ctx->state[0] = 0xCBBB9D5DC1059ED8ULL;
    sha384_ctx->state[1] = 0x629A292A367CD507ULL;
    sha384_ctx->state[2] = 0x9159015A3070DD17ULL;
    sha384_ctx->state[3] = 0x152FECD8F70E5939ULL;
    sha384_ctx->state[4] = 0x67332667FFC00B31ULL;
    sha384_ctx->state[5] = 0x8EB44A8768581511ULL;
    sha384_ctx->state[6] = 0xDB0C2E0D64F98FA7ULL;
    sha384_ctx->state[7] = 0x47B5481DBEFA4FA4ULL;

    sha384_ctx->base.buffer_len = 0;
    (void)WB_MEMSET_S(sha384_ctx->buffer, SHA512_BLOCK_SIZE, 0, SHA512_BLOCK_SIZE);
}

error_t wb_sha384_internal_start(void **ctx_handle)
{
    wb_sha512_ctx_t *ctx = (wb_sha512_ctx_t *)WB_MALLOC(sizeof(wb_sha512_ctx_t));
    WB_CHECK_EMPTY_RETURN(ctx, WB_CRYPTO_MALLOC_FAIL);

    ctx->base.type = WB_HASH_TYPE_SHA384;
    ctx->base.block_size = SHA384_BLOCK_SIZE;
    ctx->base.buffer_ptr = ctx->buffer;
    ctx->base.compute_func = wb_sha512_internal_compute;
    ctx->base.padding_func = wb_sha512_internal_padding;
    ctx->base.destroy_func = wb_sha384_internal_destroy;
    ctx->base.reset_func = wb_sha384_internal_reset;

    ctx->base.reset_func(ctx);

    ctx->base.magic = (uintptr_t)ctx ^ ctx->base.type ^ WB_HASH_CTX_MAGIC;
    *ctx_handle = (void *)ctx;

    return WB_CRYPTO_SUCCESS;
}