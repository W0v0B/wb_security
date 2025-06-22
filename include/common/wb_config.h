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

#endif // WB_USER_CONFIG

#define WB_PRINTF(fmt, ...) \
    do { \
        printf("[WB_LOG] " fmt, ##__VA_ARGS__); \
    } while(0)

#define WB_CHECK_EMPTY_RETURN(ptr, err_code) \
    do { \
        if ((ptr) == NULL) { \
            return (err_code); \
        } \
    } while(0)

#define WB_CHECK_RET(ret, err_code) \
    do { \
        if ((ret) != (0)) { \
            WB_PRINTF("[%s:%d] Check Failed! ret = 0x%x\n", __func__, __LINE__, (ret)); \
            return (err_code); \
        } \
    } while(0)

#endif // WB_CONFIG_H