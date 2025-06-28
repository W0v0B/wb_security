#include <stdio.h>
#include <assert.h> 
#include "wb_hash.h"

int main() {
    error_t ret;
    hash_handle_t ctx_handle = NULL;
    const char *data = "abc";
    uint32_t data_len = strlen(data);
    const char *key = "key";
    uint32_t key_len = strlen(key);
    uint8_t digest[64];
    uint32_t digest_len = 64;

    printf("src data: ");
    for (int i = 0; i < strlen(data); i++) {
        printf("%c", data[i]);
    }
    printf("\n");

    printf("key data: ");
    for (int i = 0; i < strlen(key); i++) {
        printf("%c", key[i]);
    }
    printf("\n");

    ret = wb_hash_start(&ctx_handle, WB_HASH_TYPE_BLAKE2B);
    if (ret != WB_CRYPTO_SUCCESS) {
        printf("Failed to start BLAKE2B ret: %x\n", ret);
        return -1;
    }
    ret = wb_blake2b_set_key(ctx_handle, (const uint8_t *)key, key_len);
    if (ret != WB_CRYPTO_SUCCESS) {
        printf("Failed to BLAKE2B set key ret: %x\n", ret);
        return -1;
    }
    ret = wb_blake2b_set_digest_length(&ctx_handle, digest_len);
    if (ret != WB_CRYPTO_SUCCESS) {
        printf("Failed to BLAKE2B set digest length ret: %x\n", ret);
        return -1;
    }
    ret = wb_hash_update(ctx_handle, (const uint8_t *)data, data_len);
    if (ret != WB_CRYPTO_SUCCESS) {
        printf("Failed to update BLAKE2B ret: %x\n", ret);
        return -1;
    }
    ret = wb_hash_finish(ctx_handle, digest, digest_len);
    if (ret != WB_CRYPTO_SUCCESS) {
        printf("Failed to finish BLAKE2B ret: %x\n", ret);
        return -1;
    }

    printf("BLAKE2B Digest: ");
    for (int i = 0; i < digest_len; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    return 0;
}