#include "hash_internal.h"

#define SHA1_BLOCK_SIZE 64
#define SHA1_DIGEST_SIZE 20

typedef struct {
    wb_hash_base_ctx_t base;
    uint32_t state[5];
    uint8_t buffer[SHA1_BLOCK_SIZE];
} wb_sha1_ctx_t;

static void wb_sha1_internal_update(wb_hash_base_ctx_t *ctx, const uint8_t *data, size_t len)
{

}

static void wb_sha1_internal_finish(wb_hash_base_ctx_t *ctx, const uint8_t *data, uint8_t *hash)
{
    
}

error_t wb_sha1_internal_start(void **ctx_handle)
{
    wb_sha1_ctx_t *ctx = (wb_sha1_ctx_t *)WB_MALLOC(sizeof(wb_sha1_ctx_t));
    if (ctx == NULL) {
        return WB_ERROR(WB_CRYPTO_MODULE_HASH, WB_CRYPTO_MALLOC_FAIL);
    }

    ctx->base.type = WB_HASH_TYPE_SHA1;
    ctx->base.digest_size = SHA1_DIGEST_SIZE;
    ctx->base.bit_count = 0;
    ctx->base.update_func = wb_sha1_internal_update;
    ctx->base.finish_func = wb_sha1_internal_finish;

    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;

    *ctx_handle = (void *)ctx;
    
    return WB_CRYPTO_SUCCESS;
}