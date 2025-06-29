#ifndef WB_CONFIG_H
#define WB_CONFIG_H

#include <stdlib.h>
#include "secure_memory/wb_secure_utils.h"

#ifndef WB_USER_CONFIG

#define WB_MALLOC(size)                                 malloc(size)
#define WB_FREE(ptr)                                    free(ptr)
#define WB_CALLOC(num, size)                            calloc(num, size)
#define WB_MEMCPY(dest, src, size)                      memcpy(dest, src, size)
#define WB_MEMCPY_S(dest, destsz, src, count)           memcpy_s(dest, destsz, src, count)
#define WB_MEMSET(ptr, value, size)                     memset(ptr, value, size)
#define WB_MEMSET_S(ptr, size, value, count)            memset_s(ptr, size, value, count)
#define WB_MEMSET_FREE_S(ptr, size, value, count)       memset_free_s(ptr, size, value, count)

#endif // WB_USER_CONFIG

#define WB_PRINTF(fmt, ...) \
    do { \
        printf("[WB_LOG] " fmt, ##__VA_ARGS__); \
    } while(0)

#define WB_ERROR_PRINTF(fmt, ...) \
    do { \
        printf("[WB_ERROR] " fmt, ##__VA_ARGS__); \
    } while(0)

#define WB_CHECK_EMPTY_RETURN(ptr, err_code) \
    do { \
        if ((ptr) == NULL) { \
            WB_ERROR_PRINTF("[%s:%d] Check ptr Failed! ptr is NULL\n", __func__, __LINE__); \
            return (err_code); \
        } \
    } while(0)

#define WB_CHECK_EQ(val, expected) \
    do { \
        if ((val) != (expected)) { \
            WB_ERROR_PRINTF("%s WB_CHECK_EQ Failed! [%s:%d]\n", __func__, __FILE__, __LINE__); \
        } \
    } while(0)

#define WB_CHECK_NE(val, expected) \
    do { \
        if ((val) == (expected)) { \
            WB_ERROR_PRINTF("%s WB_CHECK_NE Failed! [%s:%d]\n", __func__, __FILE__, __LINE__); \
        } \
    } while(0)

#define WB_CHECK_GT(val, expected) \
    do { \
        if ((val) < (expected)) { \
            WB_ERROR_PRINTF("%s WB_CHECK_GT Failed! [%s:%d]\n", __func__, __FILE__, __LINE__); \
        } \
    } while(0)

#define WB_CHECK_LT(val, expected) \
    do { \
        if ((val) > (expected)) { \
            WB_ERROR_PRINTF("%s WB_CHECK_LT Failed! [%s:%d]\n", __func__, __FILE__, __LINE__); \
        } \
    } while(0)

#define WB_CHECK_EQ_RETURN(val, expected, err_code) \
    do { \
        if ((val) != (expected)) { \
            WB_ERROR_PRINTF("%s WB_CHECK_EQ Failed! [%s:%d] (ret = 0x%x)\n", __func__, __FILE__, __LINE__, (err_code)); \
            return (err_code); \
        } \
    } while(0)

#define WB_CHECK_NE_RETURN(val, expected, err_code) \
    do { \
        if ((val) == (expected)) { \
            WB_ERROR_PRINTF("%s WB_CHECK_NE Failed! [%s:%d] (ret = 0x%x)\n", __func__, __FILE__, __LINE__, (err_code)); \
            return (err_code); \
        } \
    } while(0)

#define WB_CHECK_GT_RETURN(val, expected, err_code) \
    do { \
        if ((val) < (expected)) { \
            WB_ERROR_PRINTF("%s WB_CHECK_GT Failed! [%s:%d] (ret = 0x%x)\n", __func__, __FILE__, __LINE__, (err_code)); \
            return (err_code); \
        } \
    } while(0)

#define WB_CHECK_LT_RETURN(val, expected, err_code) \
    do { \
        if ((val) > (expected)) { \
            WB_ERROR_PRINTF("%s WB_CHECK_LT Failed! [%s:%d] (ret = 0x%x)\n", __func__, __FILE__, __LINE__, (err_code)); \
            return (err_code); \
        } \
    } while(0)

#endif // WB_CONFIG_H