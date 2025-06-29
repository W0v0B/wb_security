#include <stdio.h>
#include <assert.h> 
#include "wb_hash.h"

int main() {
    error_t ret;
    const char *data = "abc";
    uint32_t data_len = strlen(data);
    const char *key = "key";
    uint32_t key_len = strlen(key);
    uint8_t digest[64];
    uint32_t digest_len = 64;
    hash_handle_t ctx_handle = NULL;

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

    ret = wb_hash_transform(WB_HASH_TYPE_SHA1, (uint8_t *)data, strlen(data), digest, digest_len);
    if (ret != WB_CRYPTO_SUCCESS) {
        printf("Failed to transform sha1 ret: %x\n", ret);
        return -1;
    }

    printf("SHA1    Digest: ");
    for (int i = 0; i < 20; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    ret = wb_hash_transform(WB_HASH_TYPE_SHA224, (uint8_t *)data, strlen(data), digest, digest_len);
    if (ret != WB_CRYPTO_SUCCESS) {
        printf("Failed to transform sha224 ret: %x\n", ret);
        return -1;
    }

    printf("SHA224  Digest: ");
    for (int i = 0; i < 28; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    ret = wb_hash_transform(WB_HASH_TYPE_SHA256, (uint8_t *)data, strlen(data), digest, digest_len);
    if (ret != WB_CRYPTO_SUCCESS) {
        printf("Failed to transform sha256 ret: %x\n", ret);
        return -1;
    }

    printf("SHA256  Digest: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    ret = wb_hash_transform(WB_HASH_TYPE_SHA384, (uint8_t *)data, strlen(data), digest, digest_len);
    if (ret != WB_CRYPTO_SUCCESS) {
        printf("Failed to transform sha384 ret: %x\n", ret);
        return -1;
    }

    printf("SHA384  Digest: ");
    for (int i = 0; i < 48; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    ret = wb_hash_transform(WB_HASH_TYPE_SHA512, (uint8_t *)data, strlen(data), digest, digest_len);
    if (ret != WB_CRYPTO_SUCCESS) {
        printf("Failed to transform sha512 ret: %x\n", ret);
        return -1;
    }

    printf("SHA512  Digest: ");
    for (int i = 0; i < 64; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    ret = wb_hash_blake_transform(WB_HASH_TYPE_BLAKE2B, (const uint8_t *)data, data_len,
        (const uint8_t *)key, key_len, digest, digest_len);
    if (ret != WB_CRYPTO_SUCCESS) {
        printf("Error: %u\n", ret);
        return ret;
    }

    printf("BLAKE2B Digest: ");
    for (int i = 0; i < digest_len; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    printf("\n");
    printf("loop 3 hash\n");
    for (int i = 0; i < 3; i++) {
        ret = wb_hash_start(&ctx_handle, WB_HASH_TYPE_SHA256);
        if (ret != WB_CRYPTO_SUCCESS) {
            printf("Failed to start sha256 ret: %x\n", ret);
            return -1;
        }
        ret = wb_hash_update(ctx_handle, data, data_len);
        if (ret != WB_CRYPTO_SUCCESS) {
            printf("Failed to wb_hash_update sha256 ret: %x\n", ret);
            return -1;
        }
        ret = wb_hash_finish(ctx_handle, digest, digest_len);
        if (ret != WB_CRYPTO_SUCCESS) {
            printf("Failed to wb_hash_finish sha256 ret: %x\n", ret);
            return -1;
        }

        printf("sha256  Digest: ");
        for (int i = 0; i < 64; i++) {
            printf("%02x", digest[i]);
        }
        printf("\n");

        ret = wb_hash_reset(ctx_handle);
        if (ret != WB_CRYPTO_SUCCESS) {
            printf("Failed to wb_hash_reset sha256 ret: %x\n", ret);
            return -1;
        }

        ret = wb_hash_update(ctx_handle, data, data_len);
        if (ret != WB_CRYPTO_SUCCESS) {
            printf("Failed to wb_hash_update sha256 ret: %x\n", ret);
            return -1;
        }
        ret = wb_hash_finish(ctx_handle, digest, digest_len);
        if (ret != WB_CRYPTO_SUCCESS) {
            printf("Failed to wb_hash_finish sha256 ret: %x\n", ret);
            return -1;
        }

        printf("Reset   Digest: ");
        for (int i = 0; i < 64; i++) {
            printf("%02x", digest[i]);
        }
        printf("\n");

        ret = wb_hash_destroy(ctx_handle);
        if (ret != WB_CRYPTO_SUCCESS) {
            printf("Failed to wb_hash_destroy sha512 ret: %x\n", ret);
            return -1;
        }
    }

    printf("\n");
    printf("loop 3 BLAKE2B\n");
    for (int i = 0; i < 3; i++) {
        ret = wb_hash_start(&ctx_handle, WB_HASH_TYPE_BLAKE2B);
        if (ret != WB_CRYPTO_SUCCESS) {
            printf("Failed to start BLAKE2B ret: %x\n", ret);
            return -1;
        }
        ret = wb_blake_set_key(ctx_handle, key, key_len);
        if (ret != WB_CRYPTO_SUCCESS) {
            printf("Failed to wb_blake_set_key BLAKE2B ret: %x\n", ret);
            return -1;
        }
        ret = wb_blake_set_digest_length(&ctx_handle, digest_len);
        if (ret != WB_CRYPTO_SUCCESS) {
            printf("Failed to wb_hash_update BLAKE2B ret: %x\n", ret);
            return -1;
        }
        ret = wb_hash_update(ctx_handle, data, data_len);
        if (ret != WB_CRYPTO_SUCCESS) {
            printf("Failed to wb_hash_update BLAKE2B ret: %x\n", ret);
            return -1;
        }
        ret = wb_hash_finish(ctx_handle, digest, digest_len);
        if (ret != WB_CRYPTO_SUCCESS) {
            printf("Failed to wb_hash_finish BLAKE2B ret: %x\n", ret);
            return -1;
        }
        printf("BLAKE2B Digest: ");
        for (int i = 0; i < 64; i++) {
            printf("%02x", digest[i]);
        }
        printf("\n");

        ret = wb_blake_reset(&ctx_handle, key, key_len, 40);
        if (ret != WB_CRYPTO_SUCCESS) {
            printf("Failed to wb_hash_reset BLAKE2B ret: %x\n", ret);
            return -1;
        }
        ret = wb_hash_update(ctx_handle, data, data_len);
        if (ret != WB_CRYPTO_SUCCESS) {
            printf("Failed to Reset wb_hash_update BLAKE2B ret: %x\n", ret);
            return -1;
        }
        ret = wb_hash_finish(ctx_handle, digest, digest_len);
        if (ret != WB_CRYPTO_SUCCESS) {
            printf("Failed to Reset wb_hash_finish BLAKE2B ret: %x\n", ret);
            return -1;
        }

        printf("Reset   Digest: ");
        for (int i = 0; i < 64; i++) {
            printf("%02x", digest[i]);
        }
        printf("\n");

        ret = wb_hash_destroy(ctx_handle);
        if (ret != WB_CRYPTO_SUCCESS) {
            printf("Failed to wb_hash_destroy sha512 ret: %x\n", ret);
            return -1;
        }
    }

    return 0;
}