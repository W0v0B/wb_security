#include "hash_internal.h"

#define SHA1_BLOCK_SIZE 64
#define SHA1_DIGEST_SIZE 20

typedef struct {
    wb_hash_base_ctx_t base;
    uint8_t buffer[SHA1_BLOCK_SIZE];
    uint32_t state[5];
    uint64_t bit_count;
} wb_sha1_ctx_t;

static void wb_sha1_internal_compute(void *ctx, const uint8_t *block)
{

}

static void wb_sha1_internal_padding(void *ctx)
{
    
}

static void wb_sha1_internal_destroy(void *ctx, uint8_t *digest)
{
    
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
    ctx->base.magic = (uintptr_t)ctx ^ ctx->base.type ^ WB_HASH_CTX_MAGIC;

    ctx->bit_count = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;

    *ctx_handle = (void *)ctx;
    
    return WB_CRYPTO_SUCCESS;
}