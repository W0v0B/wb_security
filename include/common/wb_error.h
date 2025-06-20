#ifndef WB_ERROR_H
#define WB_ERROR_H

#include <errno.h>

/**
 * @brief 自定义错误类型
 */
typedef unsigned int error_t;

#define WB_CRYPTO_SUCCESS           0
#define WB_CRYPTO_ERROR             0xFFFFFFFF


// --- 错误码布局 ---
// | 31 | 30-24      | 23-0              |
// | 错误标志 | 模块ID | 具体错误码        |
#define WB_CRYPTO_ERR_FLAG        ((error_t)0x80000000)

#define WB_CRYPTO_MODULE_HASH     ((error_t)(0x01 << 24))
#define WB_CRYPTO_MODULE_SYMC     ((error_t)(0x02 << 24))
#define WB_CRYPTO_MODULE_RSA      ((error_t)(0x03 << 24))
#define WB_CRYPTO_MODULE_ECC      ((error_t)(0x04 << 24))

#define WB_CRYPTO_INVALID_ARG     ((error_t)(0x01))
#define WB_CRYPTO_EMPTY_VALUE     ((error_t)(0x02))
#define WB_CRYPTO_MALLOC_FAIL     ((error_t)(0x03))

#define WB_ERROR(module, code)    (WB_CRYPTO_ERR_FLAG | (module) | (code))
#define WB_HASH_ERROR(code)       (WB_CRYPTO_ERR_FLAG | WB_CRYPTO_MODULE_HASH | (code))
#define WB_SYMC_ERROR(code)       (WB_CRYPTO_ERR_FLAG | WB_CRYPTO_MODULE_SYMC | (code))
#define WB_RSA_ERROR(code)        (WB_CRYPTO_ERR_FLAG | WB_CRYPTO_MODULE_RSA | (code))
#define WB_ECC_ERROR(code)        (WB_CRYPTO_ERR_FLAG | WB_CRYPTO_MODULE_ECC | (code))

#endif // WB_ERROR_H