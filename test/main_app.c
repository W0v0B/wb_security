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

    return 0;
}