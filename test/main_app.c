#include <stdio.h>
#include <assert.h> 
#include "wb_hash.h"

int main() {
    error_t ret;
    hash_handle_t ctx_handle;
    const uint8_t *data = "abc";
    uint8_t digest[20];

    ret = wb_hash_transform(WB_HASH_TYPE_SHA1, data, strlen(data), digest);
    if (ret != WB_CRYPTO_SUCCESS) {
        printf("Failed to transform hash ret: %x\n", ret);
        return -1;
    }

    printf("Digest: ");
    for (int i = 0; i < 20; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
    return 0;
}