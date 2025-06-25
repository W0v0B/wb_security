#include <stdio.h>
#include <assert.h> 
#include "wb_hash.h"

int main() {
    error_t ret;
    const char *data = "abc";
    uint8_t digest[64];
    uint32_t digest_len = 64;

    printf("src data: ");
    for (int i = 0; i < strlen(data); i++) {
        printf("%c", data[i]);
    }
    printf("\n");

    ret = wb_hash_transform(WB_HASH_TYPE_SHA1, (uint8_t *)data, strlen(data), digest, digest_len);
    if (ret != WB_CRYPTO_SUCCESS) {
        printf("Failed to transform sha1 ret: %x\n", ret);
        return -1;
    }

    printf("SHA1   Digest: ");
    for (int i = 0; i < 20; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    ret = wb_hash_transform(WB_HASH_TYPE_SHA224, (uint8_t *)data, strlen(data), digest, digest_len);
    if (ret != WB_CRYPTO_SUCCESS) {
        printf("Failed to transform sha224 ret: %x\n", ret);
        return -1;
    }

    printf("SHA224 Digest: ");
    for (int i = 0; i < 28; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    ret = wb_hash_transform(WB_HASH_TYPE_SHA256, (uint8_t *)data, strlen(data), digest, digest_len);
    if (ret != WB_CRYPTO_SUCCESS) {
        printf("Failed to transform sha256 ret: %x\n", ret);
        return -1;
    }

    printf("SHA256 Digest: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    ret = wb_hash_transform(WB_HASH_TYPE_SHA384, (uint8_t *)data, strlen(data), digest, digest_len);
    if (ret != WB_CRYPTO_SUCCESS) {
        printf("Failed to transform sha384 ret: %x\n", ret);
        return -1;
    }

    printf("SHA384 Digest: ");
    for (int i = 0; i < 48; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    ret = wb_hash_transform(WB_HASH_TYPE_SHA512, (uint8_t *)data, strlen(data), digest, digest_len);
    if (ret != WB_CRYPTO_SUCCESS) {
        printf("Failed to transform sha512 ret: %x\n", ret);
        return -1;
    }

    printf("SHA512 Digest: ");
    for (int i = 0; i < 64; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    return 0;
}